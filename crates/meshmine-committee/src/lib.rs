//! Test-stage finalized-work committee sortition. The exact sortition is
//! deliberately release-gated pending protocol review.

use std::collections::{BTreeMap, BTreeSet};

use meshmine_codec::Encoder;
use meshmine_committee_risk::DeploymentRiskReport;
use meshmine_hns::{Hash256, blake2b_512, merkle_root};
use meshmine_share::{CommitteeRole, CommitteeRoster, ShareError};
use meshmine_types::{SignatureSet, U512, UnsignedObject, domain_hash};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use thiserror::Error;

const ELIGIBILITY_LEAF_DOMAIN: &str = "meshmine/eligibility-leaf/v2";
const ELIGIBILITY_SNAPSHOT_DOMAIN: &str = "meshmine/eligibility-snapshot/v2";
const COMMITTEE_SEED_DOMAIN: &str = "meshmine/committee-seed/v2";
const COMMITTEE_DRAW_DOMAIN: &str = "meshmine/committee-draw/v2";
const COMMITTEE_SELECTION_DOMAIN: &str = "meshmine/committee-selection/v2";
const ELIGIBILITY_FAULT_DOMAIN: &str = "meshmine/eligibility-fault/v2";
pub const MAX_ELIGIBILITY_LEAVES: usize = 1_000_000;
pub const MAX_ENTROPY_HASHES: usize = 1_024;
pub const MAX_COMMITTEE_MEMBERS: u16 = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EligibilityLeaf {
    pub operator_pubkey: [u8; 32],
    pub finalized_work: U512,
    pub eligible_role_mask: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EligibilitySnapshot {
    pub protocol_version: u16,
    pub network_id: u8,
    pub sequence: u64,
    pub source_start_height: u32,
    pub source_end_height: u32,
    pub finalized_at_height: u32,
    pub leaves: Vec<EligibilityLeaf>,
    pub eligibility_root: Hash256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionContext {
    pub epoch: u64,
    pub selection_anchor_height: u32,
    pub entropy_start_height: u32,
    pub delayed_hns_entropy: Vec<Hash256>,
    pub prior_threshold_beacon: Hash256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum BootstrapPhase {
    Static = 0,
    Hybrid = 1,
    Dynamic = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootstrapSchedule {
    pub hybrid_start_epoch: u64,
    pub dynamic_start_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectionPolicy {
    pub committee_size: u16,
    pub certificate_threshold: u16,
    pub opening_threshold: u16,
    pub minimum_lookback_blocks: u32,
    pub hybrid_static_seats: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedRoster {
    pub protocol_version: u16,
    pub network_id: u8,
    pub role: CommitteeRole,
    pub epoch: u64,
    pub phase: BootstrapPhase,
    pub certificate_threshold: u16,
    pub opening_threshold: u16,
    pub eligibility_snapshot_id: Hash256,
    pub eligibility_root: Hash256,
    pub selection_seed: Hash256,
    pub selection_transcript_hash: Hash256,
    pub members: Vec<[u8; 32]>,
    pub production_eligible: bool,
    pub production_risk_profile_commitment: Option<Hash256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRoster(SelectedRoster);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LivenessFailureEvidence {
    pub role: CommitteeRole,
    pub epoch: u64,
    pub missed_deadline_ms: u64,
    pub unavailable_members: BTreeSet<[u8; 32]>,
    pub transcript_root: Hash256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum EligibilityFaultKind {
    EarlyMaskReveal = 1,
    ReceiptDoubleSign = 2,
    AvailabilityFailure = 3,
    SettlementDoubleSign = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EligibilityFaultEvidence {
    pub member_pubkey: [u8; 32],
    pub role: CommitteeRole,
    pub kind: EligibilityFaultKind,
    pub observed_epoch: u64,
    pub exclusion_through_epoch: u64,
    pub evidence_root: Hash256,
}

#[derive(Clone, Debug, Default)]
pub struct EligibilityFaultLedger {
    faults: BTreeMap<([u8; 32], u8, EligibilityFaultKind), EligibilityFaultEvidence>,
}

#[derive(Clone, Debug)]
pub struct RotationController {
    active: VerifiedRoster,
    failures: Vec<LivenessFailureEvidence>,
}

#[derive(Debug, Error)]
pub enum CommitteeError {
    #[error("eligibility snapshot is empty, malformed, or contains duplicate operators")]
    InvalidEligibilitySnapshot,
    #[error("eligibility work total exceeds the 512-bit draw space")]
    EligibilityWeightOverflow,
    #[error("eligibility root has not met the required finalized lookback")]
    EligibilityNotDelayed,
    #[error(
        "entropy window is empty, predates eligibility, or extends beyond the selection anchor"
    )]
    InvalidEntropyWindow,
    #[error("bootstrap schedule or committee policy is invalid")]
    InvalidPolicy,
    #[error("not enough eligible operators for the requested role")]
    InsufficientEligibleOperators,
    #[error("candidate roster does not match deterministic selection")]
    RosterMismatch,
    #[error("certificate role or epoch does not match its roster")]
    CertificateContextMismatch,
    #[error("certificate verification failed: {0}")]
    Certificate(#[from] ShareError),
    #[error("dynamic mainnet release gate is not satisfied")]
    ProductionGate,
    #[error("liveness evidence or replacement epoch is invalid")]
    InvalidReplacement,
    #[error("replacement committee remains below its online certificate threshold")]
    ReplacementStillBlocked,
    #[error("selection counter overflow")]
    CounterOverflow,
    #[error("eligibility fault evidence is malformed or conflicts with its role")]
    InvalidFaultEvidence,
}

impl EligibilityFaultEvidence {
    pub fn evidence_id(&self) -> Hash256 {
        let mut encoder = Encoder::new();
        encoder.fixed(&self.member_pubkey);
        encoder.u8(role_code(self.role));
        encoder.u8(self.kind as u8);
        encoder.u64(self.observed_epoch);
        encoder.u64(self.exclusion_through_epoch);
        encoder.fixed(&self.evidence_root);
        domain_hash(ELIGIBILITY_FAULT_DOMAIN, encoder.as_bytes())
    }
}

impl EligibilityFaultLedger {
    pub fn record(&mut self, evidence: EligibilityFaultEvidence) -> Result<(), CommitteeError> {
        let correct_role = matches!(
            (evidence.kind, evidence.role),
            (EligibilityFaultKind::EarlyMaskReveal, CommitteeRole::Mask)
                | (
                    EligibilityFaultKind::ReceiptDoubleSign,
                    CommitteeRole::Receipt
                )
                | (
                    EligibilityFaultKind::AvailabilityFailure,
                    CommitteeRole::Availability
                )
                | (
                    EligibilityFaultKind::SettlementDoubleSign,
                    CommitteeRole::Settlement
                )
        );
        if !correct_role
            || evidence.exclusion_through_epoch < evidence.observed_epoch
            || evidence.evidence_root == [0; 32]
        {
            return Err(CommitteeError::InvalidFaultEvidence);
        }
        let key = (
            evidence.member_pubkey,
            role_code(evidence.role),
            evidence.kind,
        );
        match self.faults.get(&key) {
            Some(existing) if existing != &evidence => Err(CommitteeError::InvalidFaultEvidence),
            Some(_) => Ok(()),
            None => {
                self.faults.insert(key, evidence);
                Ok(())
            }
        }
    }

    /// Apply public fault exclusions before constructing the finalized
    /// eligibility snapshot. Clearing a role bit commits the exclusion into
    /// the resulting eligibility root; it does not confiscate HNS funds.
    pub fn apply(&self, leaves: &mut [EligibilityLeaf], epoch: u64) {
        for leaf in leaves {
            for evidence in self.faults.values() {
                if evidence.member_pubkey == leaf.operator_pubkey
                    && epoch >= evidence.observed_epoch
                    && epoch <= evidence.exclusion_through_epoch
                {
                    leaf.eligible_role_mask &= !role_bit(evidence.role);
                }
            }
        }
    }

    pub fn evidence_root(&self) -> Hash256 {
        merkle_root(
            &self
                .faults
                .values()
                .map(EligibilityFaultEvidence::evidence_id)
                .collect::<Vec<_>>(),
        )
    }
}

impl EligibilityLeaf {
    pub fn role_eligible(&self, role: CommitteeRole) -> bool {
        self.eligible_role_mask & role_bit(role) != 0
    }

    pub fn leaf_id(&self) -> Hash256 {
        let mut encoder = Encoder::new();
        encoder.fixed(&self.operator_pubkey);
        encoder.fixed(&self.finalized_work.0);
        encoder.u8(self.eligible_role_mask);
        domain_hash(ELIGIBILITY_LEAF_DOMAIN, encoder.as_bytes())
    }
}

impl EligibilitySnapshot {
    pub fn build(
        protocol_version: u16,
        network_id: u8,
        sequence: u64,
        source_start_height: u32,
        source_end_height: u32,
        finalized_at_height: u32,
        mut leaves: Vec<EligibilityLeaf>,
    ) -> Result<Self, CommitteeError> {
        if source_start_height > source_end_height || finalized_at_height < source_end_height {
            return Err(CommitteeError::InvalidEligibilitySnapshot);
        }
        leaves.sort_by_key(|leaf| leaf.operator_pubkey);
        validate_leaves(&leaves)?;
        let eligibility_root = merkle_root(
            &leaves
                .iter()
                .map(EligibilityLeaf::leaf_id)
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            protocol_version,
            network_id,
            sequence,
            source_start_height,
            source_end_height,
            finalized_at_height,
            leaves,
            eligibility_root,
        })
    }

    pub fn snapshot_id(&self) -> Hash256 {
        let mut encoder = Encoder::new();
        encoder.u16(self.protocol_version);
        encoder.u8(self.network_id);
        encoder.u64(self.sequence);
        encoder.u32(self.source_start_height);
        encoder.u32(self.source_end_height);
        encoder.u32(self.finalized_at_height);
        encoder.u64(self.leaves.len() as u64);
        encoder.fixed(&self.eligibility_root);
        domain_hash(ELIGIBILITY_SNAPSHOT_DOMAIN, encoder.as_bytes())
    }

    pub fn verify(&self) -> Result<(), CommitteeError> {
        let rebuilt = Self::build(
            self.protocol_version,
            self.network_id,
            self.sequence,
            self.source_start_height,
            self.source_end_height,
            self.finalized_at_height,
            self.leaves.clone(),
        )?;
        if rebuilt.leaves != self.leaves || rebuilt.eligibility_root != self.eligibility_root {
            return Err(CommitteeError::InvalidEligibilitySnapshot);
        }
        Ok(())
    }
}

impl BootstrapSchedule {
    pub fn phase(&self, epoch: u64) -> Result<BootstrapPhase, CommitteeError> {
        if self.hybrid_start_epoch == 0 || self.dynamic_start_epoch <= self.hybrid_start_epoch {
            return Err(CommitteeError::InvalidPolicy);
        }
        Ok(if epoch < self.hybrid_start_epoch {
            BootstrapPhase::Static
        } else if epoch < self.dynamic_start_epoch {
            BootstrapPhase::Hybrid
        } else {
            BootstrapPhase::Dynamic
        })
    }
}

impl SelectedRoster {
    pub fn selection_id(&self) -> Hash256 {
        let mut encoder = Encoder::new();
        encoder.u16(self.protocol_version);
        encoder.u8(self.network_id);
        encoder.u8(role_code(self.role));
        encoder.u64(self.epoch);
        encoder.u8(self.phase as u8);
        encoder.u16(self.certificate_threshold);
        encoder.u16(self.opening_threshold);
        encoder.fixed(&self.eligibility_snapshot_id);
        encoder.fixed(&self.eligibility_root);
        encoder.fixed(&self.selection_seed);
        encoder.fixed(&self.selection_transcript_hash);
        encoder.u64(self.members.len() as u64);
        for member in &self.members {
            encoder.fixed(member);
        }
        domain_hash(COMMITTEE_SELECTION_DOMAIN, encoder.as_bytes())
    }

    pub fn committee_id(&self) -> Hash256 {
        self.as_share_roster().id()
    }

    pub fn trust_notice(&self) -> &'static str {
        match self.phase {
            BootstrapPhase::Static => "static bootstrap committee: explicitly trusted",
            BootstrapPhase::Hybrid => "hybrid static and finalized-work committee",
            BootstrapPhase::Dynamic => "finalized-work committee: production remains release-gated",
        }
    }

    fn as_share_roster(&self) -> CommitteeRoster {
        CommitteeRoster {
            protocol_version: self.protocol_version,
            network_id: self.network_id,
            role: self.role,
            epoch: self.epoch,
            threshold: self.certificate_threshold,
            members: self.members.iter().copied().collect(),
        }
    }
}

impl VerifiedRoster {
    pub fn artifact(&self) -> &SelectedRoster {
        &self.0
    }

    pub fn into_artifact(self) -> SelectedRoster {
        self.0
    }

    pub fn verify_certificate<T: UnsignedObject>(
        &self,
        expected_role: CommitteeRole,
        expected_epoch: u64,
        signer_set: &SignatureSet,
        object: &T,
    ) -> Result<(), CommitteeError> {
        if self.0.role != expected_role || self.0.epoch != expected_epoch {
            return Err(CommitteeError::CertificateContextMismatch);
        }
        self.0.as_share_roster().verify(signer_set, object)?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn select_roster(
    snapshot: &EligibilitySnapshot,
    context: &SelectionContext,
    role: CommitteeRole,
    policy: SelectionPolicy,
    schedule: BootstrapSchedule,
    bootstrap_members: &[[u8; 32]],
) -> Result<VerifiedRoster, CommitteeError> {
    validate_selection_inputs(snapshot, context, policy, schedule, bootstrap_members)?;
    let phase = schedule.phase(context.epoch)?;
    let seed = if phase == BootstrapPhase::Static {
        bootstrap_seed(
            snapshot.protocol_version,
            snapshot.network_id,
            context.epoch,
            role,
            bootstrap_members,
        )
    } else {
        committee_seed(snapshot, context, role)
    };
    let mut selected = Vec::new();
    let mut draw_records = Vec::new();
    let mut bootstrap = bootstrap_members.to_vec();
    bootstrap.sort_unstable();
    bootstrap.dedup();

    match phase {
        BootstrapPhase::Static => selected.extend_from_slice(&bootstrap),
        BootstrapPhase::Hybrid => {
            selected.extend(
                bootstrap
                    .iter()
                    .take(usize::from(policy.hybrid_static_seats))
                    .copied(),
            );
            let (dynamic, dynamic_counters) = weighted_draw_without_replacement(
                snapshot,
                role,
                &seed,
                policy.committee_size - policy.hybrid_static_seats,
                &selected.iter().copied().collect(),
            )?;
            draw_records.extend(dynamic.iter().copied().zip(dynamic_counters));
            selected.extend(dynamic);
        }
        BootstrapPhase::Dynamic => {
            let (dynamic, dynamic_counters) = weighted_draw_without_replacement(
                snapshot,
                role,
                &seed,
                policy.committee_size,
                &BTreeSet::new(),
            )?;
            draw_records.extend(dynamic.iter().copied().zip(dynamic_counters));
            selected = dynamic;
        }
    }
    selected.sort_unstable();
    if selected.len() != usize::from(policy.committee_size)
        || selected.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(CommitteeError::InsufficientEligibleOperators);
    }
    let selection_transcript_hash = selection_transcript(&seed, phase, &selected, &draw_records);
    let (eligibility_snapshot_id, eligibility_root) = if phase == BootstrapPhase::Static {
        ([0; 32], [0; 32])
    } else {
        (snapshot.snapshot_id(), snapshot.eligibility_root)
    };
    Ok(VerifiedRoster(SelectedRoster {
        protocol_version: snapshot.protocol_version,
        network_id: snapshot.network_id,
        role,
        epoch: context.epoch,
        phase,
        certificate_threshold: policy.certificate_threshold,
        opening_threshold: policy.opening_threshold,
        eligibility_snapshot_id,
        eligibility_root,
        selection_seed: seed,
        selection_transcript_hash,
        members: selected,
        production_eligible: false,
        production_risk_profile_commitment: None,
    }))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_roster(
    candidate: &SelectedRoster,
    snapshot: &EligibilitySnapshot,
    context: &SelectionContext,
    role: CommitteeRole,
    policy: SelectionPolicy,
    schedule: BootstrapSchedule,
    bootstrap_members: &[[u8; 32]],
) -> Result<VerifiedRoster, CommitteeError> {
    let expected = select_roster(snapshot, context, role, policy, schedule, bootstrap_members)?;
    let mut normalized = candidate.clone();
    normalized.production_eligible = false;
    normalized.production_risk_profile_commitment = None;
    if normalized != *expected.artifact() {
        return Err(CommitteeError::RosterMismatch);
    }
    // Production authorization is participant-local release evidence, not an
    // assertion a remote candidate can import through deterministic roster
    // verification. Every verifier must run `authorize_production` itself.
    Ok(VerifiedRoster(normalized))
}

pub fn authorize_production(
    roster: VerifiedRoster,
    risk_report: &DeploymentRiskReport,
    explicit_review_release: bool,
) -> Result<VerifiedRoster, CommitteeError> {
    let role_name = match roster.0.role {
        CommitteeRole::Mask => "mask",
        CommitteeRole::Receipt => "receipt",
        CommitteeRole::Availability => "availability",
        CommitteeRole::Settlement => "settlement",
    };
    let Some(role_report) = risk_report.role(role_name) else {
        return Err(CommitteeError::ProductionGate);
    };
    if roster.0.phase != BootstrapPhase::Dynamic
        || roster.0.production_eligible
        || roster.0.production_risk_profile_commitment.is_some()
        || !risk_report.security_target_met()
        || !risk_report.liveness_target_met()
        || usize::from(role_report.committee_size) != roster.0.members.len()
        || role_report.certificate_threshold != roster.0.certificate_threshold
        || role_report.opening_threshold != roster.0.opening_threshold
        || !explicit_review_release
    {
        return Err(CommitteeError::ProductionGate);
    }
    let mut roster = roster.0;
    roster.production_eligible = true;
    roster.production_risk_profile_commitment = Some(risk_report.profile_commitment());
    Ok(VerifiedRoster(roster))
}

impl RotationController {
    pub fn new(active: VerifiedRoster) -> Self {
        Self {
            active,
            failures: Vec::new(),
        }
    }

    pub fn active(&self) -> &VerifiedRoster {
        &self.active
    }

    pub fn failures(&self) -> &[LivenessFailureEvidence] {
        &self.failures
    }

    pub fn replace_after_failure(
        &mut self,
        evidence: LivenessFailureEvidence,
        replacement: VerifiedRoster,
    ) -> Result<(), CommitteeError> {
        let active = self.active.artifact();
        let next = replacement.artifact();
        if evidence.role != active.role
            || evidence.epoch != active.epoch
            || evidence.missed_deadline_ms == 0
            || evidence.unavailable_members.is_empty()
            || next.role != active.role
            || next.epoch != active.epoch + 1
        {
            return Err(CommitteeError::InvalidReplacement);
        }
        let online = next
            .members
            .iter()
            .filter(|member| !evidence.unavailable_members.contains(*member))
            .count();
        if online < usize::from(next.certificate_threshold) {
            return Err(CommitteeError::ReplacementStillBlocked);
        }
        self.failures.push(evidence);
        self.active = replacement;
        Ok(())
    }
}

fn validate_selection_inputs(
    snapshot: &EligibilitySnapshot,
    context: &SelectionContext,
    policy: SelectionPolicy,
    schedule: BootstrapSchedule,
    bootstrap_members: &[[u8; 32]],
) -> Result<(), CommitteeError> {
    let phase = schedule.phase(context.epoch)?;
    if policy.committee_size == 0
        || policy.committee_size > MAX_COMMITTEE_MEMBERS
        || policy.certificate_threshold == 0
        || policy.certificate_threshold > policy.committee_size
        || policy.opening_threshold == 0
        || policy.opening_threshold > policy.committee_size
        || policy.hybrid_static_seats > policy.committee_size
        || (phase == BootstrapPhase::Static
            && bootstrap_members.len() != usize::from(policy.committee_size))
        || (phase == BootstrapPhase::Hybrid
            && bootstrap_members.len() < usize::from(policy.hybrid_static_seats))
    {
        return Err(CommitteeError::InvalidPolicy);
    }
    let mut canonical_bootstrap = bootstrap_members.to_vec();
    canonical_bootstrap.sort_unstable();
    canonical_bootstrap.dedup();
    if canonical_bootstrap.len() != bootstrap_members.len() {
        return Err(CommitteeError::InvalidPolicy);
    }
    if phase == BootstrapPhase::Static {
        return Ok(());
    }
    snapshot.verify()?;
    let delayed_at = snapshot
        .finalized_at_height
        .checked_add(policy.minimum_lookback_blocks)
        .ok_or(CommitteeError::EligibilityNotDelayed)?;
    if context.selection_anchor_height < delayed_at {
        return Err(CommitteeError::EligibilityNotDelayed);
    }
    let entropy_end = context
        .entropy_start_height
        .checked_add(
            u32::try_from(context.delayed_hns_entropy.len())
                .map_err(|_| CommitteeError::InvalidEntropyWindow)?,
        )
        .and_then(|height| height.checked_sub(1))
        .ok_or(CommitteeError::InvalidEntropyWindow)?;
    if context.delayed_hns_entropy.is_empty()
        || context.delayed_hns_entropy.len() > MAX_ENTROPY_HASHES
        || context.entropy_start_height <= snapshot.finalized_at_height
        || entropy_end > context.selection_anchor_height
    {
        return Err(CommitteeError::InvalidEntropyWindow);
    }
    Ok(())
}

fn committee_seed(
    snapshot: &EligibilitySnapshot,
    context: &SelectionContext,
    role: CommitteeRole,
) -> Hash256 {
    let mut encoder = Encoder::new();
    encoder.fixed(&snapshot.snapshot_id());
    encoder.fixed(&snapshot.eligibility_root);
    encoder.u32(context.entropy_start_height);
    encoder.u64(context.delayed_hns_entropy.len() as u64);
    for hash in &context.delayed_hns_entropy {
        encoder.fixed(hash);
    }
    encoder.fixed(&context.prior_threshold_beacon);
    encoder.bytes(role_tag(role));
    encoder.u64(context.epoch);
    domain_hash(COMMITTEE_SEED_DOMAIN, encoder.as_bytes())
}

fn bootstrap_seed(
    protocol_version: u16,
    network_id: u8,
    epoch: u64,
    role: CommitteeRole,
    bootstrap_members: &[[u8; 32]],
) -> Hash256 {
    let mut members = bootstrap_members.to_vec();
    members.sort_unstable();
    let mut encoder = Encoder::new();
    encoder.u16(protocol_version);
    encoder.u8(network_id);
    encoder.bytes(role_tag(role));
    encoder.u64(epoch);
    encoder.u64(members.len() as u64);
    for member in members {
        encoder.fixed(&member);
    }
    domain_hash(COMMITTEE_SEED_DOMAIN, encoder.as_bytes())
}

fn weighted_draw_without_replacement(
    snapshot: &EligibilitySnapshot,
    role: CommitteeRole,
    seed: &Hash256,
    count: u16,
    excluded: &BTreeSet<[u8; 32]>,
) -> Result<(Vec<[u8; 32]>, Vec<u64>), CommitteeError> {
    let mut candidates: Vec<_> = snapshot
        .leaves
        .iter()
        .filter(|leaf| leaf.role_eligible(role) && !excluded.contains(&leaf.operator_pubkey))
        .map(|leaf| {
            (
                leaf.operator_pubkey,
                BigUint::from_bytes_be(&leaf.finalized_work.0),
            )
        })
        .filter(|(_, weight)| !weight.is_zero())
        .collect();
    if candidates.len() < usize::from(count) {
        return Err(CommitteeError::InsufficientEligibleOperators);
    }
    let mut selected = Vec::with_capacity(usize::from(count));
    let mut counters = Vec::with_capacity(usize::from(count));
    for draw_index in 0..count {
        let total: BigUint = candidates.iter().map(|(_, weight)| weight).sum();
        if total.is_zero() || total.bits() > 512 {
            return Err(CommitteeError::EligibilityWeightOverflow);
        }
        let space = BigUint::one() << 512usize;
        let limit = (&space / &total) * &total;
        let mut counter = 0u64;
        let residue = loop {
            let mut encoder = Encoder::new();
            encoder.bytes(COMMITTEE_DRAW_DOMAIN.as_bytes());
            encoder.fixed(seed);
            encoder.u16(draw_index);
            encoder.u64(counter);
            let candidate = BigUint::from_bytes_be(&blake2b_512(&[encoder.as_bytes()]));
            if candidate < limit {
                break candidate % &total;
            }
            counter = counter
                .checked_add(1)
                .ok_or(CommitteeError::CounterOverflow)?;
        };
        let mut cumulative = BigUint::zero();
        let winner_index = candidates
            .iter()
            .position(|(_, weight)| {
                cumulative += weight;
                residue < cumulative
            })
            .ok_or(CommitteeError::EligibilityWeightOverflow)?;
        let (winner, _) = candidates.remove(winner_index);
        selected.push(winner);
        counters.push(counter);
    }
    Ok((selected, counters))
}

fn selection_transcript(
    seed: &Hash256,
    phase: BootstrapPhase,
    sorted_members: &[[u8; 32]],
    draw_records: &[([u8; 32], u64)],
) -> Hash256 {
    let mut encoder = Encoder::new();
    encoder.fixed(seed);
    encoder.u8(phase as u8);
    encoder.u64(draw_records.len() as u64);
    for (member, counter) in draw_records {
        encoder.fixed(member);
        encoder.u64(*counter);
    }
    encoder.u64(sorted_members.len() as u64);
    for member in sorted_members {
        encoder.fixed(member);
    }
    domain_hash(COMMITTEE_SELECTION_DOMAIN, encoder.as_bytes())
}

fn validate_leaves(leaves: &[EligibilityLeaf]) -> Result<(), CommitteeError> {
    if leaves.is_empty()
        || leaves.len() > MAX_ELIGIBILITY_LEAVES
        || leaves
            .windows(2)
            .any(|pair| pair[0].operator_pubkey >= pair[1].operator_pubkey)
        || leaves.iter().any(|leaf| {
            leaf.finalized_work.0.iter().all(|byte| *byte == 0)
                || leaf.eligible_role_mask == 0
                || leaf.eligible_role_mask & !0x0f != 0
        })
    {
        return Err(CommitteeError::InvalidEligibilitySnapshot);
    }
    Ok(())
}

fn role_code(role: CommitteeRole) -> u8 {
    role as u8
}

fn role_bit(role: CommitteeRole) -> u8 {
    1 << (role_code(role) - 1)
}

fn role_tag(role: CommitteeRole) -> &'static [u8] {
    match role {
        CommitteeRole::Mask => b"mask",
        CommitteeRole::Receipt => b"receipt",
        CommitteeRole::Availability => b"availability",
        CommitteeRole::Settlement => b"settlement",
    }
}

#[cfg(test)]
mod tests;
