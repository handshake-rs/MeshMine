//! MM-0001 share validation, DAG dissemination, and authoritative receipts.

pub mod benchmark;

use std::collections::{BTreeSet, HashMap, HashSet};

use meshmine_codec::{CanonicalEncode, Encoder};
use meshmine_crypto::{CryptoError, verify_certificate, verify_object};
use meshmine_handoff::{
    CAPTURE_OUTCOME_ACCEPTED, GatewayCaptureEnvelopeV1, GatewayCaptureReceiptV1,
    GatewayContextManifestV1, HandoffError, prepare_capture_disposition, validate_capture_envelope,
    validate_context_manifest,
};
use meshmine_hns::{
    Hash256, MinerHeader, compact_to_target, derive_capture_parameters, merkle_root,
};
use meshmine_storage::{
    DurableInvariantError, DurableStore, JournalBatchOutcome, JournalBatchRecord, ProtocolJournal,
    ProtocolRecordKind,
};
use meshmine_types::{
    AssignmentV2, BlockBodyPackageV2, BodyAvailabilityCertificateV2, BodyErasureDescriptorV2,
    ED25519_SUITE, GATEWAY_HANDOFF_V1, GATEWAY_OBSERVATION_CORE_RECEIPT_TIME,
    GATEWAY_OBSERVATION_DELEGATED_SIGNED_TIME_V1, GatewayAssignmentV1, MAX_GATEWAY_CLOCK_SKEW_MS,
    MaskSessionV2, PayoutBucketV2, ReceiptBatchV2, SessionCloseV2, SessionParentCertificateV2,
    ShareV2, SignatureSet, U256, U512, UnsignedObject, domain_hash,
};
use num_bigint::{BigUint, Sign};
use num_traits::{One, Zero};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitteeRole {
    Mask = 1,
    Receipt = 2,
    Availability = 3,
    Settlement = 4,
}

/// Maximum member count accepted by the Core v2 committee verification
/// boundary. Static and dynamically selected rosters use the same bound.
pub const MAX_COMMITTEE_MEMBERS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteeRoster {
    pub protocol_version: u16,
    pub network_id: u8,
    pub role: CommitteeRole,
    pub epoch: u64,
    pub threshold: u16,
    pub members: BTreeSet<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedShare {
    pub share: ShareV2,
    pub share_id: Hash256,
    pub work_key: Hash256,
    pub credited_work: U512,
}

#[derive(Clone, Copy)]
pub struct ShareValidationContext<'a> {
    pub assignment: &'a AssignmentV2,
    pub session: &'a MaskSessionV2,
    pub parent_certificate: &'a SessionParentCertificateV2,
    pub body: &'a BlockBodyPackageV2,
    pub descriptor: &'a BodyErasureDescriptorV2,
    pub body_certificate: &'a BodyAvailabilityCertificateV2,
    pub payout_bucket: &'a PayoutBucketV2,
    pub mask_roster: &'a CommitteeRoster,
    pub availability_roster: &'a CommitteeRoster,
    pub settlement_roster: &'a CommitteeRoster,
    /// Local first-observation time. Receipt admission is allowed only while
    /// the certified session submission window is open.
    pub observed_ms: u64,
    /// Committee signatures do not replace the participant's independent
    /// local `HNS node` header and chainwork check.
    pub parent_oracle: &'a dyn ParentChainOracle,
}

#[derive(Clone, Copy)]
pub struct GatewayShareValidationContext<'a> {
    pub assignment: &'a GatewayAssignmentV1,
    pub context_manifest: &'a GatewayContextManifestV1,
    pub capture_envelope: &'a GatewayCaptureEnvelopeV1,
    pub session: &'a MaskSessionV2,
    pub parent_certificate: &'a SessionParentCertificateV2,
    pub body: &'a BlockBodyPackageV2,
    pub descriptor: &'a BodyErasureDescriptorV2,
    pub body_certificate: &'a BodyAvailabilityCertificateV2,
    pub payout_bucket: &'a PayoutBucketV2,
    pub mask_roster: &'a CommitteeRoster,
    pub availability_roster: &'a CommitteeRoster,
    pub settlement_roster: &'a CommitteeRoster,
    /// Local Core receive time. The handoff validator selects this value or
    /// the signed gateway observation time according to the assignment's
    /// immutable policy; callers cannot inject a preselected eligibility time.
    pub core_received_ms: u64,
    pub parent_oracle: &'a dyn ParentChainOracle,
}

#[derive(Clone, Copy)]
struct CommonShareValidationContext<'a> {
    session: &'a MaskSessionV2,
    parent_certificate: &'a SessionParentCertificateV2,
    body: &'a BlockBodyPackageV2,
    descriptor: &'a BodyErasureDescriptorV2,
    body_certificate: &'a BodyAvailabilityCertificateV2,
    payout_bucket: &'a PayoutBucketV2,
    mask_roster: &'a CommitteeRoster,
    availability_roster: &'a CommitteeRoster,
    settlement_roster: &'a CommitteeRoster,
    observed_ms: u64,
    parent_oracle: &'a dyn ParentChainOracle,
}

#[derive(Clone, Copy)]
enum AssignmentSignature<'a> {
    Exact(&'a AssignmentV2),
    Gateway(&'a GatewayAssignmentV1),
}

#[derive(Clone, Copy)]
struct AssignmentView<'a> {
    protocol_version: u16,
    network_id: u8,
    object_id: Hash256,
    session_id: Hash256,
    body_package_id: Hash256,
    body_certificate_id: Hash256,
    operator_pubkey: [u8; 32],
    payout_bucket_id: Hash256,
    ntime: u64,
    edge_target: U256,
    capture_target: U256,
    extra_nonce_authorized: bool,
    signed: AssignmentSignature<'a>,
}

pub trait ParentChainOracle {
    fn verify_header_and_chainwork(&self, certificate: &SessionParentCertificateV2) -> bool;
}

#[derive(Clone, Debug)]
struct DagNode {
    share: ValidatedShare,
    depth: u32,
    insertion: u64,
}

#[derive(Clone, Debug)]
pub struct ShareDag {
    session_id: Hash256,
    nodes: HashMap<Hash256, DagNode>,
    tips: BTreeSet<Hash256>,
    insertion: u64,
    max_parent_age: u64,
    max_depth: u32,
}

#[derive(Debug)]
pub struct ReceiptBuilder {
    protocol_version: u16,
    network_id: u8,
    session_id: Hash256,
    batch_sequence: u64,
    previous_batch_id: Hash256,
    previous_share_count: u64,
    previous_work: U512,
    accepted: HashMap<Hash256, ValidatedShare>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptEquivocationProof {
    pub session_id: Hash256,
    pub batch_sequence: u64,
    pub first_batch_id: Hash256,
    pub second_batch_id: Hash256,
    pub equivocating_signers: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptChainSummary {
    pub session_id: Hash256,
    pub final_batch_id: Hash256,
    pub accepted_share_ids: Vec<Hash256>,
    pub accepted_work_keys: Vec<Hash256>,
    pub total_credited_work: U512,
}

#[derive(Debug, Error)]
pub enum ShareError {
    #[error("object linkage mismatch: {0}")]
    Linkage(&'static str),
    #[error("gateway-to-Core handoff rejected the capture: {0}")]
    GatewayHandoff(#[from] HandoffError),
    #[error("invalid operator signature: {0}")]
    OperatorSignature(#[from] CryptoError),
    #[error("certificate does not meet its eligible committee threshold")]
    CertificateThreshold,
    #[error("committee roster size or threshold is invalid")]
    InvalidCommitteeRoster,
    #[error("certificate includes an ineligible signer")]
    IneligibleSigner,
    #[error("committee role or identity mismatch")]
    CommitteeMismatch,
    #[error("payout bucket was not active at assignment height")]
    InactivePayoutBucket,
    #[error("raw share hash mismatch")]
    RawShareHash,
    #[error("share does not meet capture target")]
    CaptureTarget,
    #[error("invalid compact HNS target")]
    InvalidNetworkTarget,
    #[error("duplicate credited work")]
    DuplicateWork,
    #[error("DAG parent is missing")]
    MissingParent,
    #[error("DAG parent belongs to another session")]
    CrossSessionParent,
    #[error("DAG parent is too old")]
    ParentTooOld,
    #[error("DAG maximum depth exceeded")]
    MaximumDepth,
    #[error("DAG share already exists")]
    DuplicateShare,
    #[error("receipt cumulative work overflow")]
    WorkOverflow,
    #[error("receipt batches are not a conflicting pair")]
    NotEquivocation,
    #[error("certified parent header or chainwork was rejected by the local HNS oracle")]
    ParentOracleRejected,
    #[error("session is not open for receipt submission at the local observation time")]
    SessionNotOpen,
    #[error("session capture target is inconsistent with the certified HNS bits and blind band")]
    InvalidCaptureProfile,
    #[error("durable receipt state failed: {0}")]
    Durable(#[from] DurableInvariantError),
    #[error("receipt batch chain sequence, cumulative value, or root is invalid")]
    InvalidReceiptChain,
    #[error("session close does not match its complete receipt chain")]
    InvalidSessionClose,
}

impl CommitteeRoster {
    /// Checks the structural invariants required before this roster can
    /// authorize a certificate.
    ///
    /// The fields remain public because roster IDs and role/epoch linkage are
    /// composed by several protocol crates. `verify` calls this method on
    /// every certificate, so constructing a roster directly cannot bypass the
    /// nonzero, attainable threshold or the bounded member count.
    pub fn validate(&self) -> Result<(), ShareError> {
        if self.members.is_empty()
            || self.members.len() > MAX_COMMITTEE_MEMBERS
            || self.threshold == 0
            || usize::from(self.threshold) > self.members.len()
        {
            return Err(ShareError::InvalidCommitteeRoster);
        }
        Ok(())
    }

    pub fn id(&self) -> Hash256 {
        let mut bytes = Vec::with_capacity(13 + self.members.len() * 32);
        bytes.extend_from_slice(&self.protocol_version.to_le_bytes());
        bytes.push(self.network_id);
        bytes.extend_from_slice(&(self.role as u16).to_le_bytes());
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.extend_from_slice(&self.threshold.to_le_bytes());
        for member in &self.members {
            bytes.extend_from_slice(member);
        }
        domain_hash("meshmine/committee-roster/v2", &bytes)
    }

    pub fn verify<T: UnsignedObject>(
        &self,
        signer_set: &SignatureSet,
        object: &T,
    ) -> Result<(), ShareError> {
        self.validate()?;
        verify_certificate(signer_set, self.network_id, object)?;
        if signer_set.signatures.len() < usize::from(self.threshold) {
            return Err(ShareError::CertificateThreshold);
        }
        if signer_set
            .signatures
            .iter()
            .any(|signature| !self.members.contains(&signature.signer_pubkey))
        {
            return Err(ShareError::IneligibleSigner);
        }
        Ok(())
    }
}

impl<'a> From<&'a ShareValidationContext<'a>> for CommonShareValidationContext<'a> {
    fn from(context: &'a ShareValidationContext<'a>) -> Self {
        Self {
            session: context.session,
            parent_certificate: context.parent_certificate,
            body: context.body,
            descriptor: context.descriptor,
            body_certificate: context.body_certificate,
            payout_bucket: context.payout_bucket,
            mask_roster: context.mask_roster,
            availability_roster: context.availability_roster,
            settlement_roster: context.settlement_roster,
            observed_ms: context.observed_ms,
            parent_oracle: context.parent_oracle,
        }
    }
}

impl<'a> GatewayShareValidationContext<'a> {
    fn common(&'a self, observed_ms: u64) -> CommonShareValidationContext<'a> {
        CommonShareValidationContext {
            session: self.session,
            parent_certificate: self.parent_certificate,
            body: self.body,
            descriptor: self.descriptor,
            body_certificate: self.body_certificate,
            payout_bucket: self.payout_bucket,
            mask_roster: self.mask_roster,
            availability_roster: self.availability_roster,
            settlement_roster: self.settlement_roster,
            observed_ms,
            parent_oracle: self.parent_oracle,
        }
    }
}

impl<'a> AssignmentView<'a> {
    fn exact(assignment: &'a AssignmentV2, extra_nonce: &[u8; 24]) -> Self {
        Self {
            protocol_version: assignment.protocol_version,
            network_id: assignment.network_id,
            object_id: assignment.object_id(),
            session_id: assignment.session_id,
            body_package_id: assignment.body_package_id,
            body_certificate_id: assignment.body_certificate_id,
            operator_pubkey: assignment.operator_pubkey,
            payout_bucket_id: assignment.payout_bucket_id,
            ntime: assignment.ntime,
            edge_target: assignment.edge_target,
            capture_target: assignment.capture_target,
            extra_nonce_authorized: assignment.extra_nonce == *extra_nonce,
            signed: AssignmentSignature::Exact(assignment),
        }
    }

    fn gateway(
        assignment: &'a GatewayAssignmentV1,
        extra_nonce: &[u8; 24],
    ) -> Result<Self, ShareError> {
        if assignment.core_protocol_version != meshmine_types::CORE_V2
            || assignment.handoff_version != GATEWAY_HANDOFF_V1
            || assignment.gateway_pubkey == [0; 32]
            || assignment.core_handoff_pubkey == [0; 32]
            || assignment.gateway_pubkey == assignment.core_handoff_pubkey
            || !matches!(
                assignment.observation_policy,
                GATEWAY_OBSERVATION_CORE_RECEIPT_TIME
                    | GATEWAY_OBSERVATION_DELEGATED_SIGNED_TIME_V1
            )
            || assignment.maximum_clock_skew_ms > MAX_GATEWAY_CLOCK_SKEW_MS
            || (assignment.observation_policy == GATEWAY_OBSERVATION_CORE_RECEIPT_TIME
                && assignment.maximum_clock_skew_ms != 0)
        {
            return Err(ShareError::Linkage(
                "gateway assignment version or handoff identities",
            ));
        }
        Ok(Self {
            protocol_version: assignment.core_protocol_version,
            network_id: assignment.network_id,
            object_id: assignment.object_id(),
            session_id: assignment.session_id,
            body_package_id: assignment.body_package_id,
            body_certificate_id: assignment.body_certificate_id,
            operator_pubkey: assignment.operator_pubkey,
            payout_bucket_id: assignment.payout_bucket_id,
            ntime: assignment.ntime,
            edge_target: assignment.edge_target,
            capture_target: assignment.capture_target,
            extra_nonce_authorized: assignment.accepts_extra_nonce(extra_nonce),
            signed: AssignmentSignature::Gateway(assignment),
        })
    }

    fn verify_signature(self) -> Result<(), ShareError> {
        match self.signed {
            AssignmentSignature::Exact(assignment) => Ok(verify_object(
                &self.operator_pubkey,
                ED25519_SUITE,
                &assignment.operator_signature,
                self.network_id,
                assignment,
            )?),
            AssignmentSignature::Gateway(assignment) => Ok(verify_object(
                &self.operator_pubkey,
                ED25519_SUITE,
                &assignment.operator_signature,
                self.network_id,
                assignment,
            )?),
        }
    }
}

pub fn validate_share(
    share: ShareV2,
    context: &ShareValidationContext<'_>,
) -> Result<ValidatedShare, ShareError> {
    let assignment = AssignmentView::exact(context.assignment, &share.extra_nonce);
    validate_share_with_assignment(
        share,
        assignment,
        &CommonShareValidationContext::from(context),
    )
}

pub fn validate_gateway_share(
    share: ShareV2,
    context: &GatewayShareValidationContext<'_>,
) -> Result<ValidatedShare, ShareError> {
    validate_context_manifest(context.context_manifest, context.core_received_ms)?;
    let observed_ms = validate_capture_envelope(
        context.context_manifest,
        context.assignment,
        context.capture_envelope,
        context.core_received_ms,
    )?;
    if context.capture_envelope.ntime != share.ntime
        || context.capture_envelope.extra_nonce != share.extra_nonce
        || context.capture_envelope.nonce != share.nonce
        || context.capture_envelope.raw_share_hash != share.raw_share_hash
        || share.local_telemetry_hash != Some(context.capture_envelope.object_id())
    {
        return Err(ShareError::Linkage("gateway capture envelope"));
    }
    let assignment = AssignmentView::gateway(context.assignment, &share.extra_nonce)?;
    validate_share_with_assignment(share, assignment, &context.common(observed_ms))
}

fn validate_share_with_assignment(
    share: ShareV2,
    assignment: AssignmentView<'_>,
    context: &CommonShareValidationContext<'_>,
) -> Result<ValidatedShare, ShareError> {
    let session = context.session;
    let body = context.body;

    if share.protocol_version != assignment.protocol_version
        || share.protocol_version != session.protocol_version
        || share.protocol_version != body.protocol_version
        || share.network_id != assignment.network_id
        || share.network_id != session.network_id
        || share.network_id != body.network_id
    {
        return Err(ShareError::Linkage("protocol version or network"));
    }
    if context.observed_ms < session.assignment_start_ms
        || context.observed_ms > session.submission_end_ms
        || session.assignment_start_ms > session.assignment_end_ms
        || session.assignment_end_ms > session.submission_end_ms
        || session.submission_end_ms > session.timed_open_after_ms
    {
        return Err(ShareError::SessionNotOpen);
    }
    share
        .validate_parents()
        .map_err(|_| ShareError::Linkage("DAG parent syntax"))?;

    if assignment.object_id != share.assignment_id {
        return Err(ShareError::Linkage("share assignment ID"));
    }
    if session.object_id() != share.session_id || assignment.session_id != share.session_id {
        return Err(ShareError::Linkage("share session ID"));
    }
    if body.object_id() != share.body_package_id
        || assignment.body_package_id != share.body_package_id
    {
        return Err(ShareError::Linkage("share body package ID"));
    }
    if context.descriptor.object_id() != context.body_certificate.descriptor_id
        || context.descriptor.body_package_id != body.object_id()
    {
        return Err(ShareError::Linkage("availability descriptor"));
    }
    if context.body_certificate.object_id() != assignment.body_certificate_id {
        return Err(ShareError::Linkage("body certificate ID"));
    }
    if context.parent_certificate.object_id() != session.parent_certificate_id
        || context.parent_certificate.parent_hash != session.parent_hash
        || context.parent_certificate.parent_hash != body.template_core.hns_parent_hash
        || context.parent_certificate.parent_height != body.template_core.hns_parent_height
    {
        return Err(ShareError::Linkage("certified HNS parent"));
    }
    if context.body_certificate.parent_hash != session.parent_hash
        || context.body_certificate.parent_height != context.parent_certificate.parent_height
        || context.body_certificate.consensus_validation_result_hash
            != body.consensus_validation_result_hash
    {
        return Err(ShareError::Linkage("body certificate context"));
    }
    if share.operator_pubkey != assignment.operator_pubkey
        || share.operator_pubkey != body.template_core.operator_pubkey
        || share.operator_pubkey != context.payout_bucket.operator_pubkey
        || share.payout_bucket_id != assignment.payout_bucket_id
        || share.payout_bucket_id != context.payout_bucket.object_id()
    {
        return Err(ShareError::Linkage("operator or payout bucket"));
    }
    verify_object(
        &share.operator_pubkey,
        ED25519_SUITE,
        &body.operator_signature,
        body.network_id,
        body,
    )?;
    assignment.verify_signature()?;
    verify_object(
        &share.operator_pubkey,
        ED25519_SUITE,
        &context.payout_bucket.signature,
        context.payout_bucket.network_id,
        context.payout_bucket,
    )?;
    verify_object(
        &share.operator_pubkey,
        ED25519_SUITE,
        &share.operator_signature,
        share.network_id,
        &share,
    )?;

    if context.mask_roster.role != CommitteeRole::Mask
        || context.mask_roster.id() != session.mask_committee_id
        || context.availability_roster.role != CommitteeRole::Availability
        || context.settlement_roster.role != CommitteeRole::Settlement
    {
        return Err(ShareError::CommitteeMismatch);
    }
    context.mask_roster.verify(&session.signer_set, session)?;
    context.availability_roster.verify(
        &context.body_certificate.signer_set,
        context.body_certificate,
    )?;
    context.settlement_roster.verify(
        &context.parent_certificate.signer_set,
        context.parent_certificate,
    )?;

    let assignment_height = body
        .template_core
        .hns_parent_height
        .checked_add(1)
        .ok_or(ShareError::Linkage("assignment height overflow"))?;
    if context.payout_bucket.activation_height > assignment_height
        || context
            .payout_bucket
            .retirement_height
            .is_some_and(|height| assignment_height >= height)
    {
        return Err(ShareError::InactivePayoutBucket);
    }
    if share.ntime != assignment.ntime
        || !assignment.extra_nonce_authorized
        || share.declared_target != session.capture_target
        || assignment.capture_target != session.capture_target
        || assignment.edge_target.0 < session.capture_target.0
        || session.accounting_target != session.capture_target
    {
        return Err(ShareError::Linkage(
            "assignment proof fields or baseline targets",
        ));
    }

    let expected_network_target = compact_target_u256(body.template_core.bits)?;
    let expected_capture =
        derive_capture_parameters(body.template_core.bits, session.blind_band_bits_d)
            .map_err(|_| ShareError::InvalidCaptureProfile)?;
    if session.hns_network_target != expected_network_target
        || session.hns_network_target.0 != expected_capture.network_target
        || session.leading_zero_prefix_q != expected_capture.leading_zero_prefix_q
        || session.capture_target.0 != expected_capture.capture_target
    {
        return Err(ShareError::InvalidCaptureProfile);
    }
    let miner_header = MinerHeader {
        nonce: share.nonce,
        time: share.ntime,
        prev_block: body.template_core.hns_parent_hash,
        tree_root: body.tree_root,
        mask_hash: session.mask_hash,
        extra_nonce: share.extra_nonce,
        reserved_root: body.reserved_root,
        witness_root: body.witness_root,
        merkle_root: body.merkle_root,
        version: body.template_core.block_version,
        bits: body.template_core.bits,
    };
    let raw_share_hash = miner_header.share_hash();
    if raw_share_hash != share.raw_share_hash {
        return Err(ShareError::RawShareHash);
    }
    if raw_share_hash > session.capture_target.0 {
        return Err(ShareError::CaptureTarget);
    }
    // The local HNS oracle is the most expensive boundary. It runs only after
    // object linkage, all signatures/certificates, target derivation, and the
    // share proof itself have passed.
    if !context
        .parent_oracle
        .verify_header_and_chainwork(context.parent_certificate)
    {
        return Err(ShareError::ParentOracleRejected);
    }

    Ok(ValidatedShare {
        share_id: share.object_id(),
        work_key: share.work_key(),
        credited_work: work_for_target(&session.capture_target),
        share,
    })
}

pub fn work_for_target(target: &U256) -> U512 {
    let target = BigUint::from_bytes_be(&target.0);
    let work = (BigUint::one() << 256usize) / (target + BigUint::one());
    biguint_to_u512(&work)
}

impl ShareDag {
    pub fn new(session_id: Hash256, max_parent_age: u64, max_depth: u32) -> Self {
        Self {
            session_id,
            nodes: HashMap::new(),
            tips: BTreeSet::new(),
            insertion: 0,
            max_parent_age,
            max_depth,
        }
    }

    pub fn insert(&mut self, share: ValidatedShare) -> Result<(), ShareError> {
        if share.share.session_id != self.session_id {
            return Err(ShareError::CrossSessionParent);
        }
        if self.nodes.contains_key(&share.share_id) {
            return Err(ShareError::DuplicateShare);
        }
        let mut depth = 0;
        for parent_id in &share.share.gossip_parent_hashes {
            let parent = self.nodes.get(parent_id).ok_or(ShareError::MissingParent)?;
            if parent.share.share.session_id != self.session_id {
                return Err(ShareError::CrossSessionParent);
            }
            if self.insertion.saturating_sub(parent.insertion) > self.max_parent_age {
                return Err(ShareError::ParentTooOld);
            }
            depth = depth.max(parent.depth + 1);
        }
        if depth > self.max_depth {
            return Err(ShareError::MaximumDepth);
        }
        for parent in &share.share.gossip_parent_hashes {
            self.tips.remove(parent);
        }
        self.tips.insert(share.share_id);
        self.nodes.insert(
            share.share_id,
            DagNode {
                share,
                depth,
                insertion: self.insertion,
            },
        );
        self.insertion += 1;
        Ok(())
    }

    pub fn tips(&self) -> Vec<Hash256> {
        self.tips.iter().copied().collect()
    }

    pub fn known_ids(&self) -> BTreeSet<Hash256> {
        self.nodes.keys().copied().collect()
    }

    /// Returns the exact validated share retained for `share_id`.
    ///
    /// Callers may reuse this evidence after the DAG itself has been rebuilt
    /// from and revalidated against durable state, avoiding a second decode of
    /// the same accepted-share record. The lookup never crosses this DAG's
    /// session boundary because [`ShareDag::insert`] enforces that invariant.
    pub fn validated_share(&self, share_id: &Hash256) -> Option<&ValidatedShare> {
        self.nodes.get(share_id).map(|node| &node.share)
    }

    pub fn missing_from(&self, remote_known: &BTreeSet<Hash256>) -> Vec<Hash256> {
        let local = self.known_ids();
        remote_known.difference(&local).copied().collect()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

impl ReceiptBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol_version: u16,
        network_id: u8,
        session_id: Hash256,
        batch_sequence: u64,
        previous_batch_id: Hash256,
        previous_share_count: u64,
        previous_work: U512,
    ) -> Self {
        Self {
            protocol_version,
            network_id,
            session_id,
            batch_sequence,
            previous_batch_id,
            previous_share_count,
            previous_work,
            accepted: HashMap::new(),
        }
    }

    pub fn accept(&mut self, share: ValidatedShare) -> Result<(), ShareError> {
        if share.share.session_id != self.session_id {
            return Err(ShareError::Linkage("receipt session"));
        }
        if self.accepted.contains_key(&share.work_key) {
            return Err(ShareError::DuplicateWork);
        }
        self.accepted.insert(share.work_key, share);
        Ok(())
    }

    /// Persist the exact signed share and its global deduplication key before
    /// making it eligible for a receipt. This is the crash-safe acceptance
    /// path; `accept` remains useful only for isolated pure-state tests.
    pub fn accept_durable(
        &mut self,
        share: ValidatedShare,
        journal: &ProtocolJournal<'_>,
    ) -> Result<(), ShareError> {
        if share.share.session_id != self.session_id {
            return Err(ShareError::Linkage("receipt session"));
        }
        if self.accepted.contains_key(&share.work_key) {
            return Err(ShareError::DuplicateWork);
        }
        let mut encoded = Encoder::new();
        share.share.encode(&mut encoded);
        let records = [
            JournalBatchRecord::new(
                ProtocolRecordKind::AcceptedWorkKey,
                share.work_key.to_vec(),
                share.share_id.to_vec(),
            ),
            JournalBatchRecord::new(
                ProtocolRecordKind::AcceptedShare,
                share.share_id.to_vec(),
                encoded.into_bytes(),
            ),
        ];
        match journal.persist_records_with_conditions_and_batch(&records, &[], &[]) {
            Ok(JournalBatchOutcome::Committed | JournalBatchOutcome::ExactRecord) => {
                self.accept(share)
            }
            Ok(JournalBatchOutcome::PreconditionMismatch) => {
                Err(DurableInvariantError::ImmutableConflict.into())
            }
            Err(DurableInvariantError::ImmutableConflict) => Err(ShareError::DuplicateWork),
            Err(error) => Err(error.into()),
        }
    }

    /// Atomically persist the complete authenticated gateway handoff,
    /// sequence-fence advance, global work key, and accepted share. No gateway
    /// proof becomes receipt-eligible unless every piece commits together.
    pub fn accept_gateway_durable(
        &mut self,
        share: ValidatedShare,
        manifest: &GatewayContextManifestV1,
        assignment: &GatewayAssignmentV1,
        envelope: &GatewayCaptureEnvelopeV1,
        receipt: &GatewayCaptureReceiptV1,
        store: &dyn DurableStore,
    ) -> Result<(), ShareError> {
        let recomputed_share_id = share.share.object_id();
        let recomputed_work_key = share.share.work_key();
        let recomputed_work = work_for_target(&share.share.declared_target);
        if share.share_id != recomputed_share_id
            || share.work_key != recomputed_work_key
            || share.credited_work != recomputed_work
        {
            return Err(ShareError::Linkage("validated gateway share derivation"));
        }
        if share.share.session_id != self.session_id {
            return Err(ShareError::Linkage("receipt session"));
        }
        if self.accepted.contains_key(&share.work_key) {
            return Err(ShareError::DuplicateWork);
        }
        if receipt.outcome != CAPTURE_OUTCOME_ACCEPTED
            || receipt.accepted_share_id != share.share_id
            || share.share.assignment_id != assignment.object_id()
            || share.share.local_telemetry_hash != Some(envelope.object_id())
            || envelope.raw_share_hash != share.share.raw_share_hash
            || envelope.nonce != share.share.nonce
            || envelope.ntime != share.share.ntime
            || envelope.extra_nonce != share.share.extra_nonce
        {
            return Err(ShareError::Linkage("accepted gateway disposition"));
        }

        let mut prepared =
            prepare_capture_disposition(store, manifest, assignment, envelope, receipt)?;
        prepared.records.extend([
            JournalBatchRecord::new(
                ProtocolRecordKind::AcceptedWorkKey,
                share.work_key.to_vec(),
                share.share_id.to_vec(),
            ),
            JournalBatchRecord::new(
                ProtocolRecordKind::AcceptedShare,
                share.share_id.to_vec(),
                share.share.to_canonical_bytes(),
            ),
        ]);
        let journal = ProtocolJournal::new(store);
        match journal.persist_records_with_conditions_and_batch(
            &prepared.records,
            &prepared.conditions,
            &prepared.operations,
        ) {
            Ok(JournalBatchOutcome::Committed | JournalBatchOutcome::ExactRecord) => {
                self.accept(share)
            }
            Ok(JournalBatchOutcome::PreconditionMismatch) => Err(HandoffError::Sequence.into()),
            Err(DurableInvariantError::ImmutableConflict) => {
                match journal.load(ProtocolRecordKind::AcceptedWorkKey, &share.work_key)? {
                    Some(accepted_share_id) if accepted_share_id != share.share_id => {
                        Err(ShareError::DuplicateWork)
                    }
                    _ => Err(DurableInvariantError::ImmutableConflict.into()),
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn finalize(&self, signer_set: SignatureSet) -> Result<ReceiptBatchV2, ShareError> {
        let mut accepted: Vec<_> = self.accepted.values().collect();
        accepted.sort_by_key(|share| (share.work_key, share.share_id));
        let accepted_share_ids: Vec<_> = accepted.iter().map(|share| share.share_id).collect();
        let accepted_work_keys: Vec<_> = accepted.iter().map(|share| share.work_key).collect();
        let credited_work: Vec<_> = accepted.iter().map(|share| share.credited_work).collect();
        let added = credited_work.iter().fold(BigUint::default(), |sum, work| {
            sum + BigUint::from_bytes_be(&work.0)
        });
        let cumulative = BigUint::from_bytes_be(&self.previous_work.0) + added;
        if cumulative.bits() > 512 {
            return Err(ShareError::WorkOverflow);
        }
        Ok(ReceiptBatchV2 {
            protocol_version: self.protocol_version,
            network_id: self.network_id,
            session_id: self.session_id,
            batch_sequence: self.batch_sequence,
            previous_batch_id: self.previous_batch_id,
            accepted_share_ids: accepted_share_ids.clone(),
            accepted_work_keys: accepted_work_keys.clone(),
            credited_work,
            share_merkle_root: merkle_root(&accepted_share_ids),
            cumulative_share_count: self
                .previous_share_count
                .checked_add(accepted.len() as u64)
                .ok_or(ShareError::WorkOverflow)?,
            cumulative_credited_work: biguint_to_u512(&cumulative),
            signer_set,
        })
    }

    pub fn finalize_durable(
        &self,
        signer_set: SignatureSet,
        journal: &ProtocolJournal<'_>,
    ) -> Result<ReceiptBatchV2, ShareError> {
        let batch = self.finalize(signer_set)?;
        let mut encoded = Encoder::new();
        batch.encode(&mut encoded);
        journal.persist(
            ProtocolRecordKind::ReceiptBatch,
            &batch.object_id(),
            encoded.as_bytes(),
        )?;
        Ok(batch)
    }
}

pub fn detect_receipt_equivocation(
    first: &ReceiptBatchV2,
    second: &ReceiptBatchV2,
) -> Result<ReceiptEquivocationProof, ShareError> {
    let first_id = first.object_id();
    let second_id = second.object_id();
    if first.session_id != second.session_id
        || first.batch_sequence != second.batch_sequence
        || first_id == second_id
    {
        return Err(ShareError::NotEquivocation);
    }
    let first_signers: HashSet<_> = first
        .signer_set
        .signatures
        .iter()
        .map(|signature| signature.signer_pubkey)
        .collect();
    let mut equivocating_signers: Vec<_> = second
        .signer_set
        .signatures
        .iter()
        .map(|signature| signature.signer_pubkey)
        .filter(|signer| first_signers.contains(signer))
        .collect();
    equivocating_signers.sort();
    equivocating_signers.dedup();
    if equivocating_signers.is_empty() {
        return Err(ShareError::NotEquivocation);
    }
    Ok(ReceiptEquivocationProof {
        session_id: first.session_id,
        batch_sequence: first.batch_sequence,
        first_batch_id: first_id,
        second_batch_id: second_id,
        equivocating_signers,
    })
}

pub fn verify_receipt_chain(
    batches: &[ReceiptBatchV2],
    receipt_roster: &CommitteeRoster,
) -> Result<ReceiptChainSummary, ShareError> {
    if batches.is_empty() || receipt_roster.role != CommitteeRole::Receipt {
        return Err(ShareError::InvalidReceiptChain);
    }
    let first = &batches[0];
    if first.batch_sequence != 0 || first.previous_batch_id != [0; 32] {
        return Err(ShareError::InvalidReceiptChain);
    }
    let mut share_ids = Vec::new();
    let mut work_keys = Vec::new();
    let mut seen_shares = HashSet::new();
    let mut seen_work = HashSet::new();
    let mut cumulative_work = BigUint::zero();
    for (index, batch) in batches.iter().enumerate() {
        batch
            .validate_entries()
            .map_err(|_| ShareError::InvalidReceiptChain)?;
        receipt_roster.verify(&batch.signer_set, batch)?;
        let invalid_link = if index == 0 {
            false
        } else {
            let previous = &batches[index - 1];
            previous.batch_sequence.checked_add(1) != Some(batch.batch_sequence)
                || batch.previous_batch_id != previous.object_id()
        };
        if batch.protocol_version != first.protocol_version
            || batch.network_id != first.network_id
            || batch.session_id != first.session_id
            || batch.share_merkle_root != merkle_root(&batch.accepted_share_ids)
            || invalid_link
            || batch
                .accepted_share_ids
                .iter()
                .any(|share_id| !seen_shares.insert(*share_id))
            || batch
                .accepted_work_keys
                .iter()
                .any(|work_key| !seen_work.insert(*work_key))
        {
            return Err(ShareError::InvalidReceiptChain);
        }
        share_ids.extend_from_slice(&batch.accepted_share_ids);
        work_keys.extend_from_slice(&batch.accepted_work_keys);
        for work in &batch.credited_work {
            cumulative_work += BigUint::from_bytes_be(&work.0);
        }
        if batch.cumulative_share_count != share_ids.len() as u64
            || BigUint::from_bytes_be(&batch.cumulative_credited_work.0) != cumulative_work
        {
            return Err(ShareError::InvalidReceiptChain);
        }
    }
    if cumulative_work.bits() > 512 {
        return Err(ShareError::WorkOverflow);
    }
    let final_batch_id = batches.last().unwrap().object_id();
    Ok(ReceiptChainSummary {
        session_id: first.session_id,
        final_batch_id,
        accepted_share_ids: share_ids,
        accepted_work_keys: work_keys,
        total_credited_work: biguint_to_u512(&cumulative_work),
    })
}

pub fn build_session_close(
    session_id: Hash256,
    batches: &[ReceiptBatchV2],
    receipt_roster: &CommitteeRoster,
    close_reason: u16,
    opening_root: Hash256,
    mut discovered_blocks: Vec<Hash256>,
    signer_set: SignatureSet,
) -> Result<SessionCloseV2, ShareError> {
    let summary = verify_receipt_chain(batches, receipt_roster)?;
    if summary.session_id != session_id {
        return Err(ShareError::InvalidSessionClose);
    }
    let final_batch = batches.last().unwrap();
    discovered_blocks.sort();
    discovered_blocks.dedup();
    Ok(SessionCloseV2 {
        protocol_version: final_batch.protocol_version,
        network_id: final_batch.network_id,
        session_id,
        final_receipt_batch_id: summary.final_batch_id,
        accepted_share_merkle_root: merkle_root(&summary.accepted_share_ids),
        accepted_work_key_root: merkle_root(&summary.accepted_work_keys),
        accepted_share_count: summary.accepted_share_ids.len() as u64,
        total_credited_work: summary.total_credited_work,
        close_reason,
        mask_opening_transcript_root: opening_root,
        discovered_hns_block_ids: discovered_blocks,
        signer_set,
    })
}

pub fn verify_session_close(
    close: &SessionCloseV2,
    batches: &[ReceiptBatchV2],
    receipt_roster: &CommitteeRoster,
    settlement_roster: &CommitteeRoster,
) -> Result<(), ShareError> {
    let summary = verify_receipt_chain(batches, receipt_roster)?;
    if settlement_roster.role != CommitteeRole::Settlement
        || close.session_id != summary.session_id
        || close.final_receipt_batch_id != summary.final_batch_id
        || close.accepted_share_merkle_root != merkle_root(&summary.accepted_share_ids)
        || close.accepted_work_key_root != merkle_root(&summary.accepted_work_keys)
        || close.accepted_share_count != summary.accepted_share_ids.len() as u64
        || close.total_credited_work != summary.total_credited_work
    {
        return Err(ShareError::InvalidSessionClose);
    }
    settlement_roster.verify(&close.signer_set, close)?;
    Ok(())
}

fn compact_target_u256(bits: u32) -> Result<U256, ShareError> {
    let target = compact_to_target(bits);
    if target.sign() != Sign::Plus || target.bits() > 256 {
        return Err(ShareError::InvalidNetworkTarget);
    }
    let bytes = target.to_biguint().unwrap().to_bytes_be();
    let mut out = [0; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(U256(out))
}

fn biguint_to_u512(value: &BigUint) -> U512 {
    let bytes = value.to_bytes_be();
    let mut out = [0; 64];
    let start = 64usize.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(64)..]);
    U512(out)
}

#[cfg(test)]
mod tests;
