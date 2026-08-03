//! Deterministic complete-session snapshots and fixed-count payout tickets.

mod recovery;

pub use recovery::*;

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::mem::size_of;

use meshmine_body::{CoinbaseOutputSkeleton, PayoutOutput};
use meshmine_codec::{CanonicalEncode, Encoder};
use meshmine_hns::{Hash256, blake2b_512, merkle_root};
use meshmine_storage::{DurableInvariantError, ProtocolJournal, ProtocolRecordKind};
use meshmine_types::{
    MaskSessionV2, PayoutBucketV2, PayoutPlanV2, PayoutSnapshotV2, ServiceBucketLeaf,
    SessionParentCertificateV2, SignatureSet, U512, UnsignedObject, WorkBucketLeaf, domain_hash,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use thiserror::Error;

const PLAN_SEED_DOMAIN: &str = "meshmine/payout-plan/v2";
const TICKET_DOMAIN: &str = "meshmine/payout-ticket/v2";
const TRANSCRIPT_DOMAIN: &str = "meshmine/payout-transcript/v2";
const SERVICE_CREDIT_DOMAIN: &str = "meshmine/service-credit/v2";
const SERVICE_ACTION_DOMAIN: &str = "meshmine/service-action/v2";

/// Default hard bounds for the in-memory suffix needed to construct future
/// complete-session PPLNS snapshots. Deployments may choose smaller bounds,
/// but exceeding a bound always fails closed instead of discarding work that a
/// future snapshot could still need.
pub const DEFAULT_MAX_RETAINED_SESSIONS: usize = 100_000;
pub const DEFAULT_MAX_RETAINED_BUCKET_CREDITS: usize = 1_000_000;
pub const DEFAULT_MAX_RETAINED_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BucketCredit {
    pub bucket: PayoutBucketV2,
    pub credit: U512,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosedSessionCredits {
    pub session_close_id: Hash256,
    pub close_anchor_height: u32,
    pub work: Vec<BucketCredit>,
    pub service: Vec<BucketCredit>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotAccumulatorLimits {
    pub max_retained_sessions: usize,
    pub max_retained_bucket_credits: usize,
    /// Maximum retained heap payload. This counts the capacities of the work
    /// and service credit vectors plus their nested address and signature byte
    /// vectors. `VecDeque` bookkeeping is bounded separately by
    /// `max_retained_sessions`.
    pub max_retained_payload_bytes: usize,
}

impl Default for SnapshotAccumulatorLimits {
    fn default() -> Self {
        Self {
            max_retained_sessions: DEFAULT_MAX_RETAINED_SESSIONS,
            max_retained_bucket_credits: DEFAULT_MAX_RETAINED_BUCKET_CREDITS,
            max_retained_payload_bytes: DEFAULT_MAX_RETAINED_PAYLOAD_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotAccumulatorStats {
    pub retained_sessions: usize,
    pub retained_bucket_credits: usize,
    pub retained_payload_bytes: usize,
}

/// Complete state needed to resume snapshot construction without replaying
/// pruned session history. Restoring re-applies the safe suffix-pruning rule
/// and the caller's current resource limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotAccumulatorCheckpoint {
    pub network_id: u8,
    pub next_sequence: u64,
    pub previous_snapshot_id: Hash256,
    pub snapshot_step_work: U512,
    pub pplns_window_work: U512,
    pub settlement_committee_id: Hash256,
    pub closed_sessions: Vec<ClosedSessionCredits>,
    pub new_work_since_snapshot: U512,
}

#[derive(Clone, Debug)]
pub struct SnapshotAccumulator {
    network_id: u8,
    next_sequence: u64,
    previous_snapshot_id: Hash256,
    snapshot_step_work: BigUint,
    pplns_window_work: BigUint,
    settlement_committee_id: Hash256,
    closed_sessions: VecDeque<ClosedSessionCredits>,
    new_work_since_snapshot: BigUint,
    retained_work: BigUint,
    retained_bucket_credits: usize,
    retained_payload_bytes: usize,
    limits: SnapshotAccumulatorLimits,
}

#[derive(Debug)]
struct RetentionProjection {
    prune_count: usize,
    retained_work: BigUint,
    retained_sessions: usize,
    retained_bucket_credits: usize,
    retained_payload_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayoutProfile {
    pub work_ticket_count: u16,
    pub service_ticket_count: u16,
    pub service_basis_points: u16,
    pub maximum_service_basis_points: u16,
    /// Smallest serialized ticket value permitted by deployment economics.
    pub minimum_ticket_value: u64,
    /// Deployment policy bound including mandatory and operator outputs.
    pub maximum_coinbase_outputs: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServiceRole {
    MaskSetup,
    MaskOpening,
    ReceiptBatch,
    AvailabilityChallenge,
    SettlementSignature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceCreditPolicy {
    pub maximum_per_event: BTreeMap<ServiceRole, U512>,
    pub maximum_per_role_per_snapshot: BTreeMap<ServiceRole, U512>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceCreditEvent {
    pub protocol_version: u16,
    pub network_id: u8,
    pub role: ServiceRole,
    /// ID of the externally observable setup, opening share, batch,
    /// retrieval challenge, or settlement signature being compensated.
    pub subject_id: Hash256,
    pub beneficiary_bucket_id: Hash256,
    pub observed_height: u32,
    pub credit: U512,
}

#[derive(Clone, Debug, Default)]
pub struct ServiceCreditLedger {
    observed_actions: HashSet<Hash256>,
    totals_by_role: BTreeMap<ServiceRole, BigUint>,
    credits: Vec<BucketCredit>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootstrapPayoutPolicy {
    pub final_bootstrap_height: u32,
    pub first_normal_height: u32,
    pub first_normal_session_close_id: Hash256,
    pub bootstrap_allocation_commitment: Hash256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayoutMode {
    Bootstrap { allocation_commitment: Hash256 },
    Normal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbasePayoutPlan {
    pub skeleton: CoinbaseOutputSkeleton,
    pub work_pool: u64,
    pub service_pool: u64,
    pub total_subsidy: u64,
    pub operator_fees: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlanPaymentTracker {
    eligible_sequences: BTreeSet<u64>,
    canonical_payments: Vec<(Hash256, Option<u64>)>,
    /// Exact membership index for `Some` entries in `canonical_payments`.
    paid_sequences: BTreeSet<u64>,
    /// Derived `eligible_sequences - paid_sequences` frontier.
    payable_sequences: BTreeSet<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntropyPlanTracker {
    plans: BTreeMap<Hash256, TrackedEntropyPlan>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CanonicalOverlayView {
    canonical_headers: BTreeMap<u32, Hash256>,
    parent_certificates: BTreeMap<Hash256, TrackedParentCertificate>,
    sessions: BTreeMap<Hash256, TrackedOverlaySession>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrackedParentCertificate {
    parent_height: u32,
    parent_hash: Hash256,
    canonical: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrackedOverlaySession {
    parent_certificate_id: Hash256,
    closed_for_reorg: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReorgEffects {
    pub invalidated_parent_certificates: BTreeSet<Hash256>,
    pub closed_sessions: BTreeSet<Hash256>,
    pub invalidated_plan_sequences: BTreeSet<u64>,
    pub retain_share_and_body_evidence: bool,
    pub recompute_current_payable_plan: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrackedEntropyPlan {
    sequence: u64,
    entropy_blocks: Vec<(u32, Hash256)>,
    canonical: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SettlementError {
    #[error("snapshot thresholds must be nonzero")]
    ZeroSnapshotThreshold,
    #[error("snapshot accumulator limits must be nonzero")]
    ZeroAccumulatorLimit,
    #[error("retained PPLNS session count exceeds its configured bound")]
    RetainedSessionLimit,
    #[error("retained PPLNS bucket-credit count exceeds its configured bound")]
    RetainedBucketCreditLimit,
    #[error("retained PPLNS payload bytes exceed their configured bound")]
    RetainedPayloadByteLimit,
    #[error("snapshot accumulator checkpoint is inconsistent")]
    InvalidAccumulatorCheckpoint,
    #[error("closed session has no work")]
    EmptySessionWork,
    #[error("bucket metadata conflicts for the same bucket ID")]
    ConflictingBucketMetadata,
    #[error("snapshot has no buckets for requested ticket class")]
    EmptyTicketClass,
    #[error("ticket class total weight is zero")]
    ZeroTicketWeight,
    #[error("entropy count does not fit u16")]
    EntropyCountOverflow,
    #[error("ticket entropy is not delayed beyond snapshot closure")]
    EntropyNotDelayed,
    #[error("payout profile has an invalid or unbounded service fraction")]
    InvalidServiceFraction,
    #[error("ticket count must be nonzero for a nonzero pool")]
    MissingTickets,
    #[error("ticket count does not match payout plan winners")]
    TicketCountMismatch,
    #[error("payout plan does not reference the supplied snapshot")]
    PlanSnapshotMismatch,
    #[error("payout plan winners or transcript do not match deterministic recomputation")]
    PlanVerificationMismatch,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    #[error("canonical disconnect does not match the current chain tip")]
    DisconnectMismatch,
    #[error("canonical HNS height is not the next tip or conflicts with the recorded hash")]
    CanonicalHeightConflict,
    #[error("parent certificate is not backed by the recorded canonical HNS chain")]
    NoncanonicalParentCertificate,
    #[error("mask session is not linked to a tracked canonical parent certificate")]
    NoncanonicalSessionParent,
    #[error("service credit role is missing an explicit cap")]
    MissingServiceCreditCap,
    #[error("service event credit exceeds its role's per-event cap")]
    ServiceEventCap,
    #[error("service credit exceeds its role's per-snapshot cap")]
    ServiceRoleCap,
    #[error("service event was already credited")]
    DuplicateServiceEvent,
    #[error("zero service credit is not certifiable")]
    ZeroServiceCredit,
    #[error("ticket value is below the deployment's economic minimum")]
    UneconomicTicket,
    #[error("coinbase output count exceeds deployment policy")]
    CoinbaseOutputPolicy,
    #[error("bootstrap-to-normal payout transition is invalid")]
    InvalidBootstrapTransition,
    #[error("normal payout mode requires the configured first finalized session")]
    NormalSnapshotUnavailable,
    #[error("durable settlement state failed: {0}")]
    Durable(#[from] DurableInvariantError),
}

impl ServiceCreditLedger {
    pub fn certify(
        &mut self,
        policy: &ServiceCreditPolicy,
        event: ServiceCreditEvent,
        bucket: PayoutBucketV2,
    ) -> Result<(), SettlementError> {
        if event.protocol_version != 2
            || event.network_id != bucket.network_id
            || event.beneficiary_bucket_id != bucket.object_id()
            || event.subject_id == [0; 32]
        {
            return Err(SettlementError::ConflictingBucketMetadata);
        }
        let action_id = event.action_id();
        let role = event.role;
        let amount = BigUint::from_bytes_be(&event.credit.0);
        if amount.is_zero() {
            return Err(SettlementError::ZeroServiceCredit);
        }
        let per_event = policy
            .maximum_per_event
            .get(&role)
            .map(|cap| BigUint::from_bytes_be(&cap.0))
            .ok_or(SettlementError::MissingServiceCreditCap)?;
        let per_snapshot = policy
            .maximum_per_role_per_snapshot
            .get(&role)
            .map(|cap| BigUint::from_bytes_be(&cap.0))
            .ok_or(SettlementError::MissingServiceCreditCap)?;
        if amount > per_event {
            return Err(SettlementError::ServiceEventCap);
        }
        if self.observed_actions.contains(&action_id) {
            return Err(SettlementError::DuplicateServiceEvent);
        }
        let next = self.totals_by_role.get(&role).cloned().unwrap_or_default() + &amount;
        if next > per_snapshot {
            return Err(SettlementError::ServiceRoleCap);
        }
        self.observed_actions.insert(action_id);
        self.totals_by_role.insert(role, next);
        self.credits.push(BucketCredit {
            bucket,
            credit: event.credit,
        });
        Ok(())
    }

    pub fn into_credits(self) -> Vec<BucketCredit> {
        self.credits
    }
}

impl ServiceCreditEvent {
    pub fn event_id(&self) -> Hash256 {
        let mut encoder = Encoder::new();
        encoder.u16(self.protocol_version);
        encoder.u8(self.network_id);
        encoder.u8(self.role as u8);
        encoder.fixed(&self.subject_id);
        encoder.fixed(&self.beneficiary_bucket_id);
        encoder.u32(self.observed_height);
        encoder.fixed(&self.credit.0);
        domain_hash(SERVICE_CREDIT_DOMAIN, encoder.as_bytes())
    }

    pub fn action_id(&self) -> Hash256 {
        let mut encoder = Encoder::new();
        encoder.u16(self.protocol_version);
        encoder.u8(self.network_id);
        encoder.u8(self.role as u8);
        encoder.fixed(&self.subject_id);
        domain_hash(SERVICE_ACTION_DOMAIN, encoder.as_bytes())
    }
}

impl BootstrapPayoutPolicy {
    pub fn payout_mode(
        &self,
        candidate_height: u32,
        first_finalized_session_close_id: Option<Hash256>,
    ) -> Result<PayoutMode, SettlementError> {
        if self.first_normal_height != self.final_bootstrap_height.saturating_add(1) {
            return Err(SettlementError::InvalidBootstrapTransition);
        }
        if candidate_height <= self.final_bootstrap_height {
            return Ok(PayoutMode::Bootstrap {
                allocation_commitment: self.bootstrap_allocation_commitment,
            });
        }
        if first_finalized_session_close_id != Some(self.first_normal_session_close_id) {
            return Err(SettlementError::NormalSnapshotUnavailable);
        }
        Ok(PayoutMode::Normal)
    }
}

impl SnapshotAccumulator {
    pub fn new(
        network_id: u8,
        first_sequence: u64,
        previous_snapshot_id: Hash256,
        snapshot_step_work: U512,
        pplns_window_work: U512,
        settlement_committee_id: Hash256,
    ) -> Result<Self, SettlementError> {
        Self::new_with_limits(
            network_id,
            first_sequence,
            previous_snapshot_id,
            snapshot_step_work,
            pplns_window_work,
            settlement_committee_id,
            SnapshotAccumulatorLimits::default(),
        )
    }

    pub fn new_with_limits(
        network_id: u8,
        first_sequence: u64,
        previous_snapshot_id: Hash256,
        snapshot_step_work: U512,
        pplns_window_work: U512,
        settlement_committee_id: Hash256,
        limits: SnapshotAccumulatorLimits,
    ) -> Result<Self, SettlementError> {
        let step = BigUint::from_bytes_be(&snapshot_step_work.0);
        let window = BigUint::from_bytes_be(&pplns_window_work.0);
        if step.is_zero() || window.is_zero() {
            return Err(SettlementError::ZeroSnapshotThreshold);
        }
        if limits.max_retained_sessions == 0
            || limits.max_retained_bucket_credits == 0
            || limits.max_retained_payload_bytes == 0
        {
            return Err(SettlementError::ZeroAccumulatorLimit);
        }
        Ok(Self {
            network_id,
            next_sequence: first_sequence,
            previous_snapshot_id,
            snapshot_step_work: step,
            pplns_window_work: window,
            settlement_committee_id,
            closed_sessions: VecDeque::new(),
            new_work_since_snapshot: BigUint::zero(),
            retained_work: BigUint::zero(),
            retained_bucket_credits: 0,
            retained_payload_bytes: 0,
            limits,
        })
    }

    pub fn stats(&self) -> SnapshotAccumulatorStats {
        SnapshotAccumulatorStats {
            retained_sessions: self.closed_sessions.len(),
            retained_bucket_credits: self.retained_bucket_credits,
            retained_payload_bytes: self.retained_payload_bytes,
        }
    }

    pub fn limits(&self) -> SnapshotAccumulatorLimits {
        self.limits
    }

    pub fn checkpoint(&self) -> Result<SnapshotAccumulatorCheckpoint, SettlementError> {
        if self.new_work_since_snapshot >= self.snapshot_step_work {
            return Err(SettlementError::InvalidAccumulatorCheckpoint);
        }
        Ok(SnapshotAccumulatorCheckpoint {
            network_id: self.network_id,
            next_sequence: self.next_sequence,
            previous_snapshot_id: self.previous_snapshot_id,
            snapshot_step_work: big_to_u512(&self.snapshot_step_work)?,
            pplns_window_work: big_to_u512(&self.pplns_window_work)?,
            settlement_committee_id: self.settlement_committee_id,
            closed_sessions: self.closed_sessions.iter().cloned().collect(),
            new_work_since_snapshot: big_to_u512(&self.new_work_since_snapshot)?,
        })
    }

    pub fn from_checkpoint(
        checkpoint: SnapshotAccumulatorCheckpoint,
        limits: SnapshotAccumulatorLimits,
    ) -> Result<Self, SettlementError> {
        let SnapshotAccumulatorCheckpoint {
            network_id,
            next_sequence,
            previous_snapshot_id,
            snapshot_step_work,
            pplns_window_work,
            settlement_committee_id,
            closed_sessions,
            new_work_since_snapshot,
        } = checkpoint;
        let mut accumulator = Self::new_with_limits(
            network_id,
            next_sequence,
            previous_snapshot_id,
            snapshot_step_work,
            pplns_window_work,
            settlement_committee_id,
            limits,
        )?;
        let new_work = BigUint::from_bytes_be(&new_work_since_snapshot.0);
        if new_work >= accumulator.snapshot_step_work
            || (closed_sessions.is_empty() && !new_work.is_zero())
        {
            return Err(SettlementError::InvalidAccumulatorCheckpoint);
        }

        for mut session in closed_sessions {
            compact_session_allocations(&mut session);
            let session_work = sum_credits(&session.work);
            if session_work.is_zero() {
                return Err(SettlementError::InvalidAccumulatorCheckpoint);
            }
            accumulator.retained_work += session_work;
            accumulator.retained_bucket_credits = accumulator
                .retained_bucket_credits
                .checked_add(session_bucket_credit_count(&session)?)
                .ok_or(SettlementError::ArithmeticOverflow)?;
            accumulator.retained_payload_bytes = accumulator
                .retained_payload_bytes
                .checked_add(session_payload_bytes(&session)?)
                .ok_or(SettlementError::ArithmeticOverflow)?;
            accumulator.closed_sessions.push_back(session);
        }
        accumulator.prune_retained_prefix();
        accumulator.ensure_limits()?;
        accumulator.new_work_since_snapshot = new_work;
        Ok(accumulator)
    }

    pub fn add_closed_session(
        &mut self,
        mut session: ClosedSessionCredits,
        signer_set: SignatureSet,
    ) -> Result<Option<PayoutSnapshotV2>, SettlementError> {
        compact_session_allocations(&mut session);
        let session_work = sum_credits(&session.work);
        if session_work.is_zero() {
            return Err(SettlementError::EmptySessionWork);
        }
        let projection = self.retention_projection(&session, &session_work)?;
        self.ensure_projection_within_limits(&projection)?;
        let prospective_new_work = &self.new_work_since_snapshot + &session_work;

        // Construct the result before changing the accumulator. Besides making
        // errors atomic, this permits durable callers to checkpoint every
        // successful state without inheriting a partially built snapshot.
        let snapshot = if prospective_new_work < self.snapshot_step_work {
            None
        } else {
            let next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or(SettlementError::ArithmeticOverflow)?;
            let mut selected = Vec::new();
            let mut window_work = BigUint::zero();
            for selected_session in self
                .closed_sessions
                .iter()
                .chain(std::iter::once(&session))
                .rev()
            {
                selected.push(selected_session);
                window_work += sum_credits(&selected_session.work);
                if window_work >= self.pplns_window_work {
                    break;
                }
            }
            selected.reverse();
            let work_buckets = aggregate_work(&selected)?;
            let service_buckets = aggregate_service(&selected)?;
            let close_ids: Vec<_> = selected
                .iter()
                .map(|selected_session| selected_session.session_close_id)
                .collect();
            let service_ids: Vec<_> = selected
                .iter()
                .filter(|selected_session| !selected_session.service.is_empty())
                .map(|selected_session| selected_session.session_close_id)
                .collect();
            let first = selected.first().expect("at least current session");
            let last = selected.last().expect("at least current session");
            let snapshot = PayoutSnapshotV2 {
                protocol_version: 2,
                network_id: self.network_id,
                snapshot_sequence: self.next_sequence,
                previous_snapshot_id: self.previous_snapshot_id,
                first_session_close_id: first.session_close_id,
                last_session_close_id: last.session_close_id,
                close_anchor_height: last.close_anchor_height,
                work_window_target: big_to_u512(&self.pplns_window_work)?,
                actual_work_in_window: big_to_u512(&window_work)?,
                work_buckets,
                service_buckets,
                share_set_root: merkle_root(&close_ids),
                service_set_root: merkle_root(&service_ids),
                settlement_committee_id: self.settlement_committee_id,
                signer_set,
            };
            debug_assert_eq!(next_sequence, self.next_sequence + 1);
            Some(snapshot)
        };

        self.closed_sessions.push_back(session);
        for _ in 0..projection.prune_count {
            let _ = self
                .closed_sessions
                .pop_front()
                .expect("retention projection only prunes existing sessions");
        }
        self.retained_work = projection.retained_work;
        self.retained_bucket_credits = projection.retained_bucket_credits;
        self.retained_payload_bytes = projection.retained_payload_bytes;
        if let Some(snapshot) = &snapshot {
            self.previous_snapshot_id = snapshot.object_id();
            self.next_sequence += 1;
            self.new_work_since_snapshot = BigUint::zero();
        } else {
            self.new_work_since_snapshot = prospective_new_work;
        }
        Ok(snapshot)
    }

    fn retention_projection(
        &self,
        session: &ClosedSessionCredits,
        session_work: &BigUint,
    ) -> Result<RetentionProjection, SettlementError> {
        let mut retained_work = &self.retained_work + session_work;
        let mut retained_sessions = self
            .closed_sessions
            .len()
            .checked_add(1)
            .ok_or(SettlementError::ArithmeticOverflow)?;
        let mut retained_bucket_credits = self
            .retained_bucket_credits
            .checked_add(session_bucket_credit_count(session)?)
            .ok_or(SettlementError::ArithmeticOverflow)?;
        let mut retained_payload_bytes = self
            .retained_payload_bytes
            .checked_add(session_payload_bytes(session)?)
            .ok_or(SettlementError::ArithmeticOverflow)?;
        let mut prune_count = 0;

        // A prefix is dead exactly when the remaining suffix already reaches
        // the work window. Equality is sufficient: reverse selection stops as
        // soon as it reaches the target and no future positive work can make an
        // older session relevant again.
        for old_session in &self.closed_sessions {
            let work_without_oldest = &retained_work - sum_credits(&old_session.work);
            if work_without_oldest < self.pplns_window_work {
                break;
            }
            retained_work = work_without_oldest;
            retained_sessions -= 1;
            retained_bucket_credits -= session_bucket_credit_count(old_session)?;
            retained_payload_bytes -= session_payload_bytes(old_session)?;
            prune_count += 1;
        }
        Ok(RetentionProjection {
            prune_count,
            retained_work,
            retained_sessions,
            retained_bucket_credits,
            retained_payload_bytes,
        })
    }

    fn prune_retained_prefix(&mut self) {
        while let Some(oldest) = self.closed_sessions.front() {
            let work_without_oldest = &self.retained_work - sum_credits(&oldest.work);
            if work_without_oldest < self.pplns_window_work {
                break;
            }
            self.retained_work = work_without_oldest;
            self.retained_bucket_credits -= oldest.work.len().saturating_add(oldest.service.len());
            self.retained_payload_bytes -= session_payload_bytes(oldest)
                .expect("retained payload size was validated while restoring");
            let _ = self.closed_sessions.pop_front();
        }
    }

    fn ensure_projection_within_limits(
        &self,
        projection: &RetentionProjection,
    ) -> Result<(), SettlementError> {
        ensure_retention_limits(
            self.limits,
            projection.retained_sessions,
            projection.retained_bucket_credits,
            projection.retained_payload_bytes,
        )
    }

    fn ensure_limits(&self) -> Result<(), SettlementError> {
        ensure_retention_limits(
            self.limits,
            self.closed_sessions.len(),
            self.retained_bucket_credits,
            self.retained_payload_bytes,
        )
    }

    /// Stage the accumulator mutation, persist a newly closed snapshot, then
    /// make the new state visible. A failed durable write leaves `self`
    /// unchanged and an identical retry is idempotent.
    pub fn add_closed_session_durable(
        &mut self,
        session: ClosedSessionCredits,
        signer_set: SignatureSet,
        journal: &ProtocolJournal<'_>,
    ) -> Result<Option<PayoutSnapshotV2>, SettlementError> {
        let mut staged = self.clone();
        let snapshot = staged.add_closed_session(session, signer_set)?;
        if let Some(snapshot) = &snapshot {
            let mut encoded = Encoder::new();
            snapshot.encode(&mut encoded);
            journal.persist(
                ProtocolRecordKind::PayoutSnapshot,
                &snapshot.object_id(),
                encoded.as_bytes(),
            )?;
        }
        *self = staged;
        Ok(snapshot)
    }
}

pub fn build_payout_plan(
    snapshot: &PayoutSnapshotV2,
    entropy_anchor_start: u32,
    entropy_hashes: Vec<Hash256>,
    prior_beacon: Hash256,
    profile: PayoutProfile,
    signer_set: SignatureSet,
) -> Result<PayoutPlanV2, SettlementError> {
    let snapshot_id = snapshot.object_id();
    build_payout_plan_with_snapshot_id(
        snapshot,
        snapshot_id,
        entropy_anchor_start,
        entropy_hashes,
        prior_beacon,
        profile,
        signer_set,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_payout_plan_with_snapshot_id(
    snapshot: &PayoutSnapshotV2,
    snapshot_id: Hash256,
    entropy_anchor_start: u32,
    entropy_hashes: Vec<Hash256>,
    prior_beacon: Hash256,
    profile: PayoutProfile,
    signer_set: SignatureSet,
) -> Result<PayoutPlanV2, SettlementError> {
    if entropy_hashes.is_empty() || entropy_anchor_start <= snapshot.close_anchor_height {
        return Err(SettlementError::EntropyNotDelayed);
    }
    let entropy_anchor_count =
        u16::try_from(entropy_hashes.len()).map_err(|_| SettlementError::EntropyCountOverflow)?;
    let mut seed_body = Encoder::new();
    seed_body.fixed(&snapshot_id);
    for hash in &entropy_hashes {
        seed_body.fixed(hash);
    }
    seed_body.fixed(&prior_beacon);
    let plan_seed = domain_hash(PLAN_SEED_DOMAIN, seed_body.as_bytes());
    let (work_winners, work_counters) = select_work_winners(
        &plan_seed,
        0,
        profile.work_ticket_count,
        &snapshot.work_buckets,
    )?;
    let (service_winners, service_counters) = if profile.service_ticket_count == 0 {
        (Vec::new(), Vec::new())
    } else {
        select_service_winners(
            &plan_seed,
            1,
            profile.service_ticket_count,
            &snapshot.service_buckets,
        )?
    };
    let mut transcript = Encoder::new();
    transcript.fixed(&plan_seed);
    transcript.varint(work_counters.len() as u64);
    for counter in work_counters {
        transcript.u64(counter);
    }
    transcript.varint(service_counters.len() as u64);
    for counter in service_counters {
        transcript.u64(counter);
    }
    for winner in &work_winners {
        transcript.fixed(winner);
    }
    for winner in &service_winners {
        transcript.fixed(winner);
    }
    Ok(PayoutPlanV2 {
        protocol_version: 2,
        network_id: snapshot.network_id,
        plan_sequence: snapshot.snapshot_sequence,
        snapshot_id,
        entropy_anchor_start,
        entropy_anchor_count,
        entropy_hashes,
        prior_beacon,
        plan_seed,
        work_ticket_count: profile.work_ticket_count,
        service_ticket_count: profile.service_ticket_count,
        work_winners,
        service_winners,
        selection_transcript_hash: domain_hash(TRANSCRIPT_DOMAIN, transcript.as_bytes()),
        signer_set,
    })
}

pub fn build_payout_plan_durable(
    snapshot: &PayoutSnapshotV2,
    entropy_anchor_start: u32,
    entropy_hashes: Vec<Hash256>,
    prior_beacon: Hash256,
    profile: PayoutProfile,
    signer_set: SignatureSet,
    journal: &ProtocolJournal<'_>,
) -> Result<PayoutPlanV2, SettlementError> {
    let plan = build_payout_plan(
        snapshot,
        entropy_anchor_start,
        entropy_hashes,
        prior_beacon,
        profile,
        signer_set,
    )?;
    let mut encoded = Encoder::new();
    plan.encode(&mut encoded);
    journal.persist(
        ProtocolRecordKind::PayoutPlan,
        &plan.object_id(),
        encoded.as_bytes(),
    )?;
    Ok(plan)
}

pub fn verify_payout_plan(
    snapshot: &PayoutSnapshotV2,
    plan: &PayoutPlanV2,
    profile: PayoutProfile,
) -> Result<(), SettlementError> {
    let snapshot_id = snapshot.object_id();
    if plan.snapshot_id != snapshot_id
        || plan.plan_sequence != snapshot.snapshot_sequence
        || usize::from(plan.entropy_anchor_count) != plan.entropy_hashes.len()
        || plan.work_ticket_count != profile.work_ticket_count
        || plan.service_ticket_count != profile.service_ticket_count
    {
        return Err(SettlementError::PlanSnapshotMismatch);
    }
    let expected = build_payout_plan_with_snapshot_id(
        snapshot,
        snapshot_id,
        plan.entropy_anchor_start,
        plan.entropy_hashes.clone(),
        plan.prior_beacon,
        profile,
        SignatureSet::empty_ed25519(),
    )?;
    if expected.unsigned_bytes() != plan.unsigned_bytes() {
        return Err(SettlementError::PlanVerificationMismatch);
    }
    Ok(())
}

pub fn build_coinbase_payouts(
    snapshot: &PayoutSnapshotV2,
    plan: &PayoutPlanV2,
    subsidy: u64,
    operator_fees: u64,
    mandatory_claim_airdrop_outputs: Vec<PayoutOutput>,
    operator_fee_destination: Option<(u8, Vec<u8>)>,
    profile: PayoutProfile,
) -> Result<CoinbasePayoutPlan, SettlementError> {
    if plan.snapshot_id != snapshot.object_id()
        || plan.plan_sequence != snapshot.snapshot_sequence
        || plan.work_ticket_count != profile.work_ticket_count
        || plan.service_ticket_count != profile.service_ticket_count
    {
        return Err(SettlementError::PlanSnapshotMismatch);
    }
    if profile.service_basis_points > profile.maximum_service_basis_points
        || profile.maximum_service_basis_points > 10_000
        || profile.maximum_coinbase_outputs == 0
    {
        return Err(SettlementError::InvalidServiceFraction);
    }
    if plan.work_winners.len() != usize::from(profile.work_ticket_count)
        || plan.service_winners.len() != usize::from(profile.service_ticket_count)
    {
        return Err(SettlementError::TicketCountMismatch);
    }
    let service_pool =
        ((u128::from(subsidy) * u128::from(profile.service_basis_points)) / 10_000) as u64;
    let work_pool = subsidy - service_pool;
    if work_pool > 0 && profile.work_ticket_count == 0 {
        return Err(SettlementError::MissingTickets);
    }
    if service_pool > 0 && profile.service_ticket_count == 0 {
        return Err(SettlementError::MissingTickets);
    }
    if (work_pool > 0
        && work_pool / u64::from(profile.work_ticket_count) < profile.minimum_ticket_value)
        || (service_pool > 0
            && service_pool / u64::from(profile.service_ticket_count)
                < profile.minimum_ticket_value)
    {
        return Err(SettlementError::UneconomicTicket);
    }
    let work_values = ticket_values(work_pool, profile.work_ticket_count);
    let service_values = ticket_values(service_pool, profile.service_ticket_count);
    let work_destinations = work_destination_map(&snapshot.work_buckets);
    let service_destinations = service_destination_map(&snapshot.service_buckets);
    let work = combine_winners(&plan.work_winners, &work_values, &work_destinations)?;
    let service = combine_winners(
        &plan.service_winners,
        &service_values,
        &service_destinations,
    )?;
    let first_winner = plan
        .work_winners
        .first()
        .ok_or(SettlementError::MissingTickets)?;
    let first_key = destination_key(
        work_destinations
            .get(first_winner)
            .ok_or(SettlementError::ConflictingBucketMetadata)?,
    );
    let first_work_or_fallback = work
        .get(&first_key)
        .cloned()
        .ok_or(SettlementError::ConflictingBucketMetadata)?;
    let remaining_work_outputs = work
        .into_iter()
        .filter_map(|(key, output)| (key != first_key).then_some(output))
        .collect();
    let service_outputs = service.into_values().collect();
    let operator_fee_output = match (operator_fees, operator_fee_destination) {
        (0, _) => None,
        (_, Some((version, hash))) => Some(PayoutOutput {
            hns_address_version: version,
            hns_address_hash: hash,
            value: operator_fees,
        }),
        (_, None) => return Err(SettlementError::ConflictingBucketMetadata),
    };
    let skeleton = CoinbaseOutputSkeleton {
        first_work_or_fallback,
        mandatory_claim_airdrop_outputs,
        remaining_work_outputs,
        service_outputs,
        operator_fee_output,
    };
    skeleton
        .validate_sorted()
        .map_err(|_| SettlementError::ConflictingBucketMetadata)?;
    if skeleton
        .ordered_outputs()
        .map_err(|_| SettlementError::ConflictingBucketMetadata)?
        .len()
        > usize::from(profile.maximum_coinbase_outputs)
    {
        return Err(SettlementError::CoinbaseOutputPolicy);
    }
    Ok(CoinbasePayoutPlan {
        skeleton,
        work_pool,
        service_pool,
        total_subsidy: subsidy,
        operator_fees,
    })
}

impl PlanPaymentTracker {
    pub fn add_eligible(&mut self, sequence: u64) {
        if self.eligible_sequences.insert(sequence) && !self.paid_sequences.contains(&sequence) {
            self.payable_sequences.insert(sequence);
        }
    }

    pub fn invalidate_eligible(&mut self, sequence: u64) {
        self.eligible_sequences.remove(&sequence);
        self.payable_sequences.remove(&sequence);
    }

    pub fn connect_block(
        &mut self,
        block_hash: Hash256,
        paid_plan: Option<u64>,
    ) -> Result<(), SettlementError> {
        if let Some(sequence) = paid_plan
            && Some(sequence) != self.current_payable()
        {
            return Err(SettlementError::TicketCountMismatch);
        }

        // All fallible validation precedes every mutation. A paid sequence is
        // necessarily the first eligible-but-unpaid sequence, so these two
        // derived-index updates cannot conflict with valid tracker state.
        self.canonical_payments.push((block_hash, paid_plan));
        if let Some(sequence) = paid_plan {
            let newly_paid = self.paid_sequences.insert(sequence);
            let was_payable = self.payable_sequences.remove(&sequence);
            debug_assert!(newly_paid && was_payable);
        }
        Ok(())
    }

    pub fn disconnect_tip(&mut self, block_hash: &Hash256) -> Result<(), SettlementError> {
        let Some((tip_hash, paid_plan)) = self.canonical_payments.last().copied() else {
            return Err(SettlementError::DisconnectMismatch);
        };
        if &tip_hash != block_hash {
            return Err(SettlementError::DisconnectMismatch);
        }

        self.canonical_payments.pop();
        if let Some(sequence) = paid_plan {
            let was_paid = self.paid_sequences.remove(&sequence);
            debug_assert!(was_paid);
            if self.eligible_sequences.contains(&sequence) {
                self.payable_sequences.insert(sequence);
            }
        }
        Ok(())
    }

    pub fn current_payable(&self) -> Option<u64> {
        self.payable_sequences.first().copied()
    }
}

impl EntropyPlanTracker {
    pub fn register(&mut self, plan: &PayoutPlanV2) -> Result<(), SettlementError> {
        if usize::from(plan.entropy_anchor_count) != plan.entropy_hashes.len()
            || plan.entropy_hashes.is_empty()
        {
            return Err(SettlementError::EntropyNotDelayed);
        }
        let mut entropy_blocks = Vec::with_capacity(plan.entropy_hashes.len());
        for (offset, hash) in plan.entropy_hashes.iter().enumerate() {
            let height = plan
                .entropy_anchor_start
                .checked_add(
                    u32::try_from(offset).map_err(|_| SettlementError::ArithmeticOverflow)?,
                )
                .ok_or(SettlementError::ArithmeticOverflow)?;
            entropy_blocks.push((height, *hash));
        }
        let tracked = TrackedEntropyPlan {
            sequence: plan.plan_sequence,
            entropy_blocks,
            canonical: true,
        };
        match self.plans.get_mut(&plan.object_id()) {
            Some(existing)
                if existing.sequence != tracked.sequence
                    || existing.entropy_blocks != tracked.entropy_blocks =>
            {
                Err(SettlementError::PlanVerificationMismatch)
            }
            Some(existing) => {
                // Callers must revalidate the exact plan against their current
                // HNS oracle before registering it again. This permits an HNS
                // branch to return to byte-identical entropy without making a
                // permanently invalidated plan unusable forever.
                existing.canonical = true;
                Ok(())
            }
            None => {
                self.plans.insert(plan.object_id(), tracked);
                Ok(())
            }
        }
    }

    /// Invalidate every plan whose delayed entropy committed to a disconnected
    /// HNS block. Replacement entropy produces a new plan; if HNS returns to
    /// the exact old entropy, a caller may revalidate and register the old plan.
    pub fn disconnect_entropy_block(&mut self, height: u32, hash: Hash256) -> BTreeSet<u64> {
        let mut invalidated = BTreeSet::new();
        for plan in self.plans.values_mut() {
            if plan.canonical && plan.entropy_blocks.contains(&(height, hash)) {
                plan.canonical = false;
                invalidated.insert(plan.sequence);
            }
        }
        invalidated
    }

    pub fn is_canonical(&self, plan_id: &Hash256) -> bool {
        self.plans.get(plan_id).is_some_and(|plan| plan.canonical)
    }
}

impl CanonicalOverlayView {
    /// Connect the same canonical HNS block to the overlay and payout views.
    /// The two mutations are kept together so plan-payment state cannot advance
    /// on a block the overlay did not record.
    pub fn connect_block(
        &mut self,
        height: u32,
        block_hash: Hash256,
        paid_plan: Option<u64>,
        payments: &mut PlanPaymentTracker,
    ) -> Result<(), SettlementError> {
        if let Some((tip_height, _)) = self.canonical_headers.last_key_value()
            && height != tip_height.saturating_add(1)
        {
            return Err(SettlementError::CanonicalHeightConflict);
        }
        if self
            .canonical_headers
            .get(&height)
            .is_some_and(|existing| existing != &block_hash)
        {
            return Err(SettlementError::CanonicalHeightConflict);
        }
        payments.connect_block(block_hash, paid_plan)?;
        self.canonical_headers.insert(height, block_hash);
        Ok(())
    }

    pub fn register_parent_certificate(
        &mut self,
        certificate: &SessionParentCertificateV2,
    ) -> Result<(), SettlementError> {
        if self.canonical_headers.get(&certificate.parent_height) != Some(&certificate.parent_hash)
        {
            return Err(SettlementError::NoncanonicalParentCertificate);
        }
        let certificate_id = certificate.object_id();
        let tracked = TrackedParentCertificate {
            parent_height: certificate.parent_height,
            parent_hash: certificate.parent_hash,
            canonical: true,
        };
        match self.parent_certificates.get(&certificate_id) {
            Some(existing) if existing != &tracked => {
                Err(SettlementError::NoncanonicalParentCertificate)
            }
            Some(_) => Ok(()),
            None => {
                self.parent_certificates.insert(certificate_id, tracked);
                Ok(())
            }
        }
    }

    pub fn register_session(&mut self, session: &MaskSessionV2) -> Result<(), SettlementError> {
        let parent = self
            .parent_certificates
            .get(&session.parent_certificate_id)
            .filter(|parent| parent.canonical && parent.parent_hash == session.parent_hash)
            .ok_or(SettlementError::NoncanonicalSessionParent)?;
        if self.canonical_headers.get(&parent.parent_height) != Some(&parent.parent_hash) {
            return Err(SettlementError::NoncanonicalSessionParent);
        }
        let session_id = session.object_id();
        let tracked = TrackedOverlaySession {
            parent_certificate_id: session.parent_certificate_id,
            closed_for_reorg: false,
        };
        match self.sessions.get(&session_id) {
            Some(existing) if existing != &tracked => {
                Err(SettlementError::NoncanonicalSessionParent)
            }
            Some(_) => Ok(()),
            None => {
                self.sessions.insert(session_id, tracked);
                Ok(())
            }
        }
    }

    /// Disconnect the canonical tip, roll back its plan payment, invalidate
    /// entropy plans that used it, invalidate parent certificates on the
    /// orphan, and deterministically close their sessions while retaining all
    /// evidence objects for audit.
    pub fn disconnect_tip(
        &mut self,
        height: u32,
        block_hash: Hash256,
        payments: &mut PlanPaymentTracker,
        entropy: &mut EntropyPlanTracker,
    ) -> Result<ReorgEffects, SettlementError> {
        if self.canonical_headers.last_key_value() != Some((&height, &block_hash)) {
            return Err(SettlementError::DisconnectMismatch);
        }
        payments.disconnect_tip(&block_hash)?;
        self.canonical_headers.remove(&height);

        let invalidated_plan_sequences = entropy.disconnect_entropy_block(height, block_hash);
        for sequence in &invalidated_plan_sequences {
            payments.invalidate_eligible(*sequence);
        }
        let invalidated_parent_certificates: BTreeSet<_> = self
            .parent_certificates
            .iter_mut()
            .filter_map(|(certificate_id, parent)| {
                if parent.canonical
                    && parent.parent_height == height
                    && parent.parent_hash == block_hash
                {
                    parent.canonical = false;
                    Some(*certificate_id)
                } else {
                    None
                }
            })
            .collect();
        let closed_sessions: BTreeSet<_> = self
            .sessions
            .iter_mut()
            .filter_map(|(session_id, session)| {
                if invalidated_parent_certificates.contains(&session.parent_certificate_id) {
                    session.closed_for_reorg = true;
                    Some(*session_id)
                } else {
                    None
                }
            })
            .collect();

        Ok(ReorgEffects {
            invalidated_parent_certificates,
            closed_sessions,
            invalidated_plan_sequences,
            retain_share_and_body_evidence: true,
            recompute_current_payable_plan: true,
        })
    }

    pub fn is_parent_canonical(&self, certificate_id: &Hash256) -> bool {
        self.parent_certificates
            .get(certificate_id)
            .is_some_and(|parent| parent.canonical)
    }

    pub fn session_closed_for_reorg(&self, session_id: &Hash256) -> bool {
        self.sessions
            .get(session_id)
            .is_some_and(|session| session.closed_for_reorg)
    }
}

fn select_work_winners(
    seed: &Hash256,
    class: u8,
    count: u16,
    buckets: &[WorkBucketLeaf],
) -> Result<(Vec<Hash256>, Vec<u64>), SettlementError> {
    let weighted: Vec<_> = buckets
        .iter()
        .map(|bucket| {
            (
                bucket.bucket_id,
                BigUint::from_bytes_be(&bucket.credited_work.0),
            )
        })
        .collect();
    select_weighted(seed, class, count, &weighted)
}

fn select_service_winners(
    seed: &Hash256,
    class: u8,
    count: u16,
    buckets: &[ServiceBucketLeaf],
) -> Result<(Vec<Hash256>, Vec<u64>), SettlementError> {
    let weighted: Vec<_> = buckets
        .iter()
        .map(|bucket| {
            (
                bucket.bucket_id,
                BigUint::from_bytes_be(&bucket.certified_service_credit.0),
            )
        })
        .collect();
    select_weighted(seed, class, count, &weighted)
}

fn select_weighted(
    seed: &Hash256,
    class: u8,
    count: u16,
    buckets: &[(Hash256, BigUint)],
) -> Result<(Vec<Hash256>, Vec<u64>), SettlementError> {
    if count == 0 {
        return Ok((Vec::new(), Vec::new()));
    }
    if buckets.is_empty() && count > 0 {
        return Err(SettlementError::EmptyTicketClass);
    }
    let total: BigUint = buckets.iter().map(|(_, weight)| weight).sum();
    if total.is_zero() && count > 0 {
        return Err(SettlementError::ZeroTicketWeight);
    }
    let space = BigUint::one() << 512usize;
    let limit = (&space / &total) * &total;
    let mut cumulative = Vec::with_capacity(buckets.len());
    let mut running = BigUint::zero();
    for (_, weight) in buckets {
        running += weight;
        cumulative.push(running.clone());
    }
    let mut winners = Vec::with_capacity(usize::from(count));
    let mut counters = Vec::with_capacity(usize::from(count));
    for ticket_index in 0..count {
        let mut counter = 0u64;
        let residue = loop {
            let mut candidate_input = Encoder::new();
            candidate_input.bytes(TICKET_DOMAIN.as_bytes());
            candidate_input.fixed(seed);
            candidate_input.u8(class);
            candidate_input.u16(ticket_index);
            candidate_input.u64(counter);
            let candidate = BigUint::from_bytes_be(&blake2b_512(&[candidate_input.as_bytes()]));
            if candidate < limit {
                break candidate % &total;
            }
            counter = counter
                .checked_add(1)
                .ok_or(SettlementError::ArithmeticOverflow)?;
        };
        let winner_index = cumulative.partition_point(|upper| residue >= *upper);
        let winner = buckets
            .get(winner_index)
            .map(|(bucket, _)| *bucket)
            .ok_or(SettlementError::ArithmeticOverflow)?;
        winners.push(winner);
        counters.push(counter);
    }
    Ok((winners, counters))
}

fn aggregate_work(
    sessions: &[&ClosedSessionCredits],
) -> Result<Vec<WorkBucketLeaf>, SettlementError> {
    let mut buckets: BTreeMap<Hash256, (PayoutBucketV2, BigUint)> = BTreeMap::new();
    for credit in sessions.iter().flat_map(|session| &session.work) {
        merge_credit(&mut buckets, credit)?;
    }
    buckets
        .into_iter()
        .map(|(bucket_id, (bucket, credit))| {
            Ok(WorkBucketLeaf {
                bucket_id,
                operator_pubkey: bucket.operator_pubkey,
                hns_address_version: bucket.hns_address_version,
                hns_address_hash: bucket.hns_address_hash,
                credited_work: big_to_u512(&credit)?,
            })
        })
        .collect()
}

fn aggregate_service(
    sessions: &[&ClosedSessionCredits],
) -> Result<Vec<ServiceBucketLeaf>, SettlementError> {
    let mut buckets: BTreeMap<Hash256, (PayoutBucketV2, BigUint)> = BTreeMap::new();
    for credit in sessions.iter().flat_map(|session| &session.service) {
        merge_credit(&mut buckets, credit)?;
    }
    buckets
        .into_iter()
        .map(|(bucket_id, (bucket, credit))| {
            Ok(ServiceBucketLeaf {
                bucket_id,
                operator_pubkey: bucket.operator_pubkey,
                hns_address_version: bucket.hns_address_version,
                hns_address_hash: bucket.hns_address_hash,
                certified_service_credit: big_to_u512(&credit)?,
            })
        })
        .collect()
}

fn merge_credit(
    buckets: &mut BTreeMap<Hash256, (PayoutBucketV2, BigUint)>,
    credit: &BucketCredit,
) -> Result<(), SettlementError> {
    let id = credit.bucket.object_id();
    let amount = BigUint::from_bytes_be(&credit.credit.0);
    match buckets.get_mut(&id) {
        Some((bucket, total)) => {
            if bucket.unsigned_bytes() != credit.bucket.unsigned_bytes() {
                return Err(SettlementError::ConflictingBucketMetadata);
            }
            *total += amount;
        }
        None => {
            buckets.insert(id, (credit.bucket.clone(), amount));
        }
    }
    Ok(())
}

fn sum_credits(credits: &[BucketCredit]) -> BigUint {
    credits
        .iter()
        .map(|credit| BigUint::from_bytes_be(&credit.credit.0))
        .sum()
}

fn compact_session_allocations(session: &mut ClosedSessionCredits) {
    session.work.shrink_to_fit();
    session.service.shrink_to_fit();
    for credit in session.work.iter_mut().chain(&mut session.service) {
        credit.bucket.hns_address_hash.shrink_to_fit();
        credit.bucket.signature.0.shrink_to_fit();
    }
}

fn session_bucket_credit_count(session: &ClosedSessionCredits) -> Result<usize, SettlementError> {
    session
        .work
        .len()
        .checked_add(session.service.len())
        .ok_or(SettlementError::ArithmeticOverflow)
}

fn session_payload_bytes(session: &ClosedSessionCredits) -> Result<usize, SettlementError> {
    let mut total = session
        .work
        .capacity()
        .checked_add(session.service.capacity())
        .and_then(|credits| credits.checked_mul(size_of::<BucketCredit>()))
        .ok_or(SettlementError::ArithmeticOverflow)?;
    for credit in session.work.iter().chain(&session.service) {
        total = total
            .checked_add(credit.bucket.hns_address_hash.capacity())
            .and_then(|bytes| bytes.checked_add(credit.bucket.signature.0.capacity()))
            .ok_or(SettlementError::ArithmeticOverflow)?;
    }
    Ok(total)
}

fn ensure_retention_limits(
    limits: SnapshotAccumulatorLimits,
    retained_sessions: usize,
    retained_bucket_credits: usize,
    retained_payload_bytes: usize,
) -> Result<(), SettlementError> {
    if retained_sessions > limits.max_retained_sessions {
        return Err(SettlementError::RetainedSessionLimit);
    }
    if retained_bucket_credits > limits.max_retained_bucket_credits {
        return Err(SettlementError::RetainedBucketCreditLimit);
    }
    if retained_payload_bytes > limits.max_retained_payload_bytes {
        return Err(SettlementError::RetainedPayloadByteLimit);
    }
    Ok(())
}

fn big_to_u512(value: &BigUint) -> Result<U512, SettlementError> {
    if value.bits() > 512 {
        return Err(SettlementError::ArithmeticOverflow);
    }
    let bytes = value.to_bytes_be();
    let mut output = [0; 64];
    output[64 - bytes.len()..].copy_from_slice(&bytes);
    Ok(U512(output))
}

fn ticket_values(pool: u64, count: u16) -> Vec<u64> {
    if count == 0 {
        return Vec::new();
    }
    let count_u64 = u64::from(count);
    let base = pool / count_u64;
    let remainder = pool % count_u64;
    (0..count_u64)
        .map(|index| base + u64::from(index < remainder))
        .collect()
}

fn work_destination_map(buckets: &[WorkBucketLeaf]) -> BTreeMap<Hash256, PayoutOutput> {
    buckets
        .iter()
        .map(|bucket| {
            (
                bucket.bucket_id,
                PayoutOutput {
                    hns_address_version: bucket.hns_address_version,
                    hns_address_hash: bucket.hns_address_hash.clone(),
                    value: 0,
                },
            )
        })
        .collect()
}

fn service_destination_map(buckets: &[ServiceBucketLeaf]) -> BTreeMap<Hash256, PayoutOutput> {
    buckets
        .iter()
        .map(|bucket| {
            (
                bucket.bucket_id,
                PayoutOutput {
                    hns_address_version: bucket.hns_address_version,
                    hns_address_hash: bucket.hns_address_hash.clone(),
                    value: 0,
                },
            )
        })
        .collect()
}

type DestinationKey = (u8, Vec<u8>);

fn destination_key(output: &PayoutOutput) -> DestinationKey {
    (output.hns_address_version, output.hns_address_hash.clone())
}

fn combine_winners(
    winners: &[Hash256],
    values: &[u64],
    destinations: &BTreeMap<Hash256, PayoutOutput>,
) -> Result<BTreeMap<DestinationKey, PayoutOutput>, SettlementError> {
    let mut outputs = BTreeMap::new();
    for (winner, value) in winners.iter().zip(values) {
        let output = destinations
            .get(winner)
            .cloned()
            .ok_or(SettlementError::ConflictingBucketMetadata)?;
        let key = destination_key(&output);
        let entry = outputs.entry(key).or_insert_with(|| output.clone());
        entry.value = entry
            .value
            .checked_add(*value)
            .ok_or(SettlementError::ArithmeticOverflow)?;
    }
    Ok(outputs)
}

#[cfg(test)]
mod tests;
