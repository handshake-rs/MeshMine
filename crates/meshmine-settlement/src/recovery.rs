//! Bounded payout-recovery checkpoints.
//!
//! A checkpoint is useful only when its source fence is advanced atomically
//! with the ordered source records it summarizes. This module supplies the
//! sealed state, canonical encoding, and monotonic durable head. Runtime
//! composition remains responsible for comparing the checkpoint fence to the
//! live disposition/snapshot/plan/payment heads before admitting new work.

use std::collections::BTreeSet;

use meshmine_codec::{
    CanonicalDecode, CanonicalEncode, CodecError, DecodeLimits, Decoder, Encoder,
};
use meshmine_crypto::verify_certificate;
use meshmine_hns::Hash256;
use meshmine_storage::{
    BatchCondition, BatchOperation, DurableInvariantError, DurableStore, JournalBatchOutcome,
    JournalBatchRecord, ProtocolJournal, ProtocolRecordKind,
};
use meshmine_types::{
    CORE_V2, ED25519_SUITE, PayoutBucketV2, SignatureSet, U512, UnsignedObject, domain_hash,
};
use thiserror::Error;

use crate::{
    BucketCredit, ClosedSessionCredits, DEFAULT_MAX_RETAINED_BUCKET_CREDITS,
    DEFAULT_MAX_RETAINED_SESSIONS, SnapshotAccumulator, SnapshotAccumulatorCheckpoint,
    SnapshotAccumulatorLimits,
};

pub const PAYOUT_RECOVERY_CHECKPOINT_V1: u16 = 1;
pub const PAYOUT_RECOVERY_HEAD_NAMESPACE: &str = "payout-recovery-checkpoint-head/v1";
pub const PAYOUT_RECOVERY_SOURCE_FENCE_NAMESPACE: &str = "payout-recovery-source-fence/v1";
pub const MAX_EXPECTED_PAYOUT_PLANS: usize = 100_000;
pub const MAX_CANONICAL_PLAN_BINDINGS: usize = 100_000;
pub const MAX_PAYOUT_RECOVERY_COMMITTEE_MEMBERS: usize = 256;
const MAX_PAYOUT_CHECKPOINT_BYTES: usize = 64 * 1024 * 1024;
const PAYOUT_RECOVERY_HEAD_MAGIC: [u8; 4] = *b"MMCH";
const PAYOUT_RECOVERY_SOURCE_FENCE_MAGIC: [u8; 4] = *b"MMSF";
const PAYOUT_RECOVERY_WRAPPER_DOMAIN: &str = "meshmine/payout-recovery-wrapper/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayoutRecoverySourceFenceV1 {
    pub disposition_count: u64,
    pub disposition_commitment: Hash256,
    pub snapshot_count: u64,
    pub snapshot_head_id: Hash256,
    pub plan_count: u64,
    pub plan_head_id: Hash256,
    pub canonical_event_count: u64,
    pub canonical_event_commitment: Hash256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpectedPayoutPlanV1 {
    pub plan_sequence: u64,
    pub snapshot_id: Hash256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalPlanBindingV1 {
    pub plan_sequence: u64,
    pub payout_plan_id: Hash256,
    pub payout_snapshot_id: Hash256,
}

/// Exact deployment trust policy for payout-recovery checkpoints.
///
/// This policy is supplied locally and is never inferred from checkpoint
/// bytes. A checkpoint certificate must contain a threshold of these exact
/// settlement members, and its sealed committee/payout-policy identifiers must
/// equal the locally configured values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutRecoveryCommitteePolicyV1 {
    pub network_id: u8,
    pub settlement_committee_id: Hash256,
    pub payout_policy_fingerprint: Hash256,
    pub threshold: u16,
    pub members: BTreeSet<[u8; 32]>,
}

/// Successful durable checkpoint outcomes. Races are errors, rather than
/// successful journal outcomes that a caller could accidentally ignore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayoutRecoveryPersistOutcome {
    Committed,
    AlreadyCurrent,
}

/// One bounded restart point for the complete payout admission state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutRecoveryCheckpointV1 {
    pub core_protocol_version: u16,
    pub checkpoint_version: u16,
    pub network_id: u8,
    pub checkpoint_sequence: u64,
    pub previous_checkpoint_id: Hash256,
    /// Commitment to every deployment parameter that changes payout meaning.
    pub payout_policy_fingerprint: Hash256,
    pub source_fence: PayoutRecoverySourceFenceV1,
    pub accumulator: SnapshotAccumulatorCheckpoint,
    pub expected_plans: Vec<ExpectedPayoutPlanV1>,
    pub canonical_plan_bindings: Vec<CanonicalPlanBindingV1>,
    pub signer_set: SignatureSet,
}

impl CanonicalEncode for PayoutRecoverySourceFenceV1 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u64(self.disposition_count);
        encoder.fixed(&self.disposition_commitment);
        encoder.u64(self.snapshot_count);
        encoder.fixed(&self.snapshot_head_id);
        encoder.u64(self.plan_count);
        encoder.fixed(&self.plan_head_id);
        encoder.u64(self.canonical_event_count);
        encoder.fixed(&self.canonical_event_commitment);
    }
}

impl CanonicalDecode for PayoutRecoverySourceFenceV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            disposition_count: decoder.u64()?,
            disposition_commitment: decoder.array()?,
            snapshot_count: decoder.u64()?,
            snapshot_head_id: decoder.array()?,
            plan_count: decoder.u64()?,
            plan_head_id: decoder.array()?,
            canonical_event_count: decoder.u64()?,
            canonical_event_commitment: decoder.array()?,
        })
    }
}

impl PayoutRecoverySourceFenceV1 {
    fn validate_coherence(&self) -> Result<(), PayoutRecoveryError> {
        let zero_count_has_nonzero_head = |count: u64, head: Hash256| {
            (count == 0 && head != [0; 32]) || (count != 0 && head == [0; 32])
        };
        if zero_count_has_nonzero_head(self.disposition_count, self.disposition_commitment)
            || zero_count_has_nonzero_head(self.snapshot_count, self.snapshot_head_id)
            || zero_count_has_nonzero_head(self.plan_count, self.plan_head_id)
            || zero_count_has_nonzero_head(
                self.canonical_event_count,
                self.canonical_event_commitment,
            )
            || self.plan_count > self.snapshot_count
            || self.disposition_count < self.snapshot_count
        {
            return Err(PayoutRecoveryError::InvalidCheckpoint);
        }
        Ok(())
    }

    fn validate_monotonic_after(&self, previous: &Self) -> Result<(), PayoutRecoveryError> {
        let component_is_monotonic =
            |previous_count: u64, previous_head: Hash256, next_count: u64, next_head: Hash256| {
                next_count > previous_count && next_head != previous_head
                    || next_count == previous_count && next_head == previous_head
            };
        if !component_is_monotonic(
            previous.disposition_count,
            previous.disposition_commitment,
            self.disposition_count,
            self.disposition_commitment,
        ) || !component_is_monotonic(
            previous.snapshot_count,
            previous.snapshot_head_id,
            self.snapshot_count,
            self.snapshot_head_id,
        ) || !component_is_monotonic(
            previous.plan_count,
            previous.plan_head_id,
            self.plan_count,
            self.plan_head_id,
        ) || !component_is_monotonic(
            previous.canonical_event_count,
            previous.canonical_event_commitment,
            self.canonical_event_count,
            self.canonical_event_commitment,
        ) {
            return Err(PayoutRecoveryError::SourceFenceRegression);
        }
        Ok(())
    }
}

fn encode_source_fence(network_id: u8, fence: PayoutRecoverySourceFenceV1) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.fixed(&PAYOUT_RECOVERY_SOURCE_FENCE_MAGIC);
    encoder.u16(PAYOUT_RECOVERY_CHECKPOINT_V1);
    encoder.u8(network_id);
    fence.encode(&mut encoder);
    encoder.into_bytes()
}

fn decode_source_fence(
    network_id: u8,
    bytes: &[u8],
) -> Result<PayoutRecoverySourceFenceV1, PayoutRecoveryError> {
    let mut decoder = Decoder::new(
        bytes,
        DecodeLimits {
            max_object_bytes: 192,
            max_vector_items: 0,
        },
    )
    .map_err(|_| PayoutRecoveryError::InvalidSourceFence)?;
    if decoder
        .array::<4>()
        .map_err(|_| PayoutRecoveryError::InvalidSourceFence)?
        != PAYOUT_RECOVERY_SOURCE_FENCE_MAGIC
        || decoder
            .u16()
            .map_err(|_| PayoutRecoveryError::InvalidSourceFence)?
            != PAYOUT_RECOVERY_CHECKPOINT_V1
        || decoder
            .u8()
            .map_err(|_| PayoutRecoveryError::InvalidSourceFence)?
            != network_id
    {
        return Err(PayoutRecoveryError::InvalidSourceFence);
    }
    let fence = PayoutRecoverySourceFenceV1::decode(&mut decoder)
        .map_err(|_| PayoutRecoveryError::InvalidSourceFence)?;
    decoder
        .finish()
        .map_err(|_| PayoutRecoveryError::InvalidSourceFence)?;
    fence
        .validate_coherence()
        .map_err(|_| PayoutRecoveryError::InvalidSourceFence)?;
    Ok(fence)
}

/// Build, but do not apply, an exact source-fence transition for composition
/// into the same durable transaction as its source records. Online cutover
/// remains disabled until every live source writer uses this primitive.
pub fn payout_recovery_source_fence_transition(
    network_id: u8,
    previous: Option<PayoutRecoverySourceFenceV1>,
    next: PayoutRecoverySourceFenceV1,
) -> Result<(BatchCondition, BatchOperation), PayoutRecoveryError> {
    next.validate_coherence()?;
    if let Some(previous) = previous {
        previous.validate_coherence()?;
        next.validate_monotonic_after(&previous)?;
    }
    let key = network_id.to_string();
    Ok((
        BatchCondition::new(
            PAYOUT_RECOVERY_SOURCE_FENCE_NAMESPACE,
            &key,
            previous.map(|fence| encode_source_fence(network_id, fence)),
        ),
        BatchOperation::put(
            PAYOUT_RECOVERY_SOURCE_FENCE_NAMESPACE,
            key,
            encode_source_fence(network_id, next),
        ),
    ))
}

impl CanonicalEncode for ExpectedPayoutPlanV1 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u64(self.plan_sequence);
        encoder.fixed(&self.snapshot_id);
    }
}

impl CanonicalDecode for ExpectedPayoutPlanV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            plan_sequence: decoder.u64()?,
            snapshot_id: decoder.array()?,
        })
    }
}

impl CanonicalEncode for CanonicalPlanBindingV1 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u64(self.plan_sequence);
        encoder.fixed(&self.payout_plan_id);
        encoder.fixed(&self.payout_snapshot_id);
    }
}

impl CanonicalDecode for CanonicalPlanBindingV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            plan_sequence: decoder.u64()?,
            payout_plan_id: decoder.array()?,
            payout_snapshot_id: decoder.array()?,
        })
    }
}

fn encode_bucket_credit(encoder: &mut Encoder, credit: &BucketCredit) {
    credit.bucket.encode(encoder);
    credit.credit.encode(encoder);
}

fn decode_bucket_credit(decoder: &mut Decoder<'_>) -> Result<BucketCredit, CodecError> {
    Ok(BucketCredit {
        bucket: PayoutBucketV2::decode(decoder)?,
        credit: U512::decode(decoder)?,
    })
}

fn encode_bucket_credits(encoder: &mut Encoder, credits: &[BucketCredit]) {
    encoder.varint(credits.len() as u64);
    for credit in credits {
        encode_bucket_credit(encoder, credit);
    }
}

fn decode_bucket_credits(decoder: &mut Decoder<'_>) -> Result<Vec<BucketCredit>, CodecError> {
    let count = decoder.length(DEFAULT_MAX_RETAINED_BUCKET_CREDITS)?;
    (0..count).map(|_| decode_bucket_credit(decoder)).collect()
}

fn encode_closed_session(encoder: &mut Encoder, session: &ClosedSessionCredits) {
    encoder.fixed(&session.session_close_id);
    encoder.u32(session.close_anchor_height);
    encode_bucket_credits(encoder, &session.work);
    encode_bucket_credits(encoder, &session.service);
}

fn decode_closed_session(decoder: &mut Decoder<'_>) -> Result<ClosedSessionCredits, CodecError> {
    Ok(ClosedSessionCredits {
        session_close_id: decoder.array()?,
        close_anchor_height: decoder.u32()?,
        work: decode_bucket_credits(decoder)?,
        service: decode_bucket_credits(decoder)?,
    })
}

impl CanonicalEncode for SnapshotAccumulatorCheckpoint {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u8(self.network_id);
        encoder.u64(self.next_sequence);
        encoder.fixed(&self.previous_snapshot_id);
        self.snapshot_step_work.encode(encoder);
        self.pplns_window_work.encode(encoder);
        encoder.fixed(&self.settlement_committee_id);
        encoder.varint(self.closed_sessions.len() as u64);
        for session in &self.closed_sessions {
            encode_closed_session(encoder, session);
        }
        self.new_work_since_snapshot.encode(encoder);
    }
}

impl CanonicalDecode for SnapshotAccumulatorCheckpoint {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let network_id = decoder.u8()?;
        let next_sequence = decoder.u64()?;
        let previous_snapshot_id = decoder.array()?;
        let snapshot_step_work = U512::decode(decoder)?;
        let pplns_window_work = U512::decode(decoder)?;
        let settlement_committee_id = decoder.array()?;
        let count = decoder.length(DEFAULT_MAX_RETAINED_SESSIONS)?;
        let closed_sessions = (0..count)
            .map(|_| decode_closed_session(decoder))
            .collect::<Result<Vec<_>, _>>()?;
        let new_work_since_snapshot = U512::decode(decoder)?;
        Ok(Self {
            network_id,
            next_sequence,
            previous_snapshot_id,
            snapshot_step_work,
            pplns_window_work,
            settlement_committee_id,
            closed_sessions,
            new_work_since_snapshot,
        })
    }
}

impl UnsignedObject for PayoutRecoveryCheckpointV1 {
    const DOMAIN_TAG: &'static str = "meshmine/payout-recovery-checkpoint/v1";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encoder.u16(self.core_protocol_version);
        encoder.u16(self.checkpoint_version);
        encoder.u8(self.network_id);
        encoder.u64(self.checkpoint_sequence);
        encoder.fixed(&self.previous_checkpoint_id);
        encoder.fixed(&self.payout_policy_fingerprint);
        self.source_fence.encode(encoder);
        self.accumulator.encode(encoder);
        encoder.varint(self.expected_plans.len() as u64);
        for expected in &self.expected_plans {
            expected.encode(encoder);
        }
        encoder.varint(self.canonical_plan_bindings.len() as u64);
        for binding in &self.canonical_plan_bindings {
            binding.encode(encoder);
        }
    }
}

impl CanonicalEncode for PayoutRecoveryCheckpointV1 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        self.signer_set.encode(encoder);
    }
}

impl CanonicalDecode for PayoutRecoveryCheckpointV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let core_protocol_version = decoder.u16()?;
        let checkpoint_version = decoder.u16()?;
        let network_id = decoder.u8()?;
        let checkpoint_sequence = decoder.u64()?;
        let previous_checkpoint_id = decoder.array()?;
        let payout_policy_fingerprint = decoder.array()?;
        let source_fence = PayoutRecoverySourceFenceV1::decode(decoder)?;
        let accumulator = SnapshotAccumulatorCheckpoint::decode(decoder)?;
        let expected_count = decoder.length(MAX_EXPECTED_PAYOUT_PLANS)?;
        let expected_plans = (0..expected_count)
            .map(|_| ExpectedPayoutPlanV1::decode(decoder))
            .collect::<Result<Vec<_>, _>>()?;
        let binding_count = decoder.length(MAX_CANONICAL_PLAN_BINDINGS)?;
        let canonical_plan_bindings = (0..binding_count)
            .map(|_| CanonicalPlanBindingV1::decode(decoder))
            .collect::<Result<Vec<_>, _>>()?;
        let signer_set = SignatureSet::decode(decoder)?;
        Ok(Self {
            core_protocol_version,
            checkpoint_version,
            network_id,
            checkpoint_sequence,
            previous_checkpoint_id,
            payout_policy_fingerprint,
            source_fence,
            accumulator,
            expected_plans,
            canonical_plan_bindings,
            signer_set,
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PayoutRecoveryError {
    #[error("payout recovery checkpoint is structurally invalid")]
    InvalidCheckpoint,
    #[error("payout recovery checkpoint sequence or predecessor is invalid")]
    Sequence,
    #[error("payout recovery checkpoint head is malformed")]
    InvalidHead,
    #[error("payout recovery checkpoint is missing from its immutable journal")]
    MissingCheckpoint,
    #[error("payout recovery checkpoint is not canonical or has the wrong object ID")]
    NonCanonicalCheckpoint,
    #[error("payout recovery checkpoint exceeds its durable canonical byte bound")]
    CheckpointTooLarge,
    #[error("payout recovery committee policy is invalid or does not match the checkpoint")]
    InvalidCommitteePolicy,
    #[error("payout recovery checkpoint certificate is invalid or below threshold")]
    InvalidCertificate,
    #[error("payout recovery source fence is malformed")]
    InvalidSourceFence,
    #[error("payout recovery checkpoint does not match the exact durable source fence")]
    SourceFenceMismatch,
    #[error("payout recovery source fence regressed or changed without advancing")]
    SourceFenceRegression,
    #[error("payout recovery policy changed within one checkpoint chain")]
    PolicyChange,
    #[error("payout recovery checkpoint lost a concurrent durable race")]
    ConcurrentUpdate,
    #[error("durable payout recovery state failed: {0}")]
    Durable(#[from] DurableInvariantError),
}

impl PayoutRecoveryCheckpointV1 {
    pub fn validate_structure(&self) -> Result<(), PayoutRecoveryError> {
        self.source_fence.validate_coherence()?;
        let expected_queue_length = self
            .source_fence
            .snapshot_count
            .checked_sub(self.source_fence.plan_count)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(PayoutRecoveryError::InvalidCheckpoint)?;
        let expected_next_snapshot = self
            .source_fence
            .snapshot_count
            .checked_add(1)
            .ok_or(PayoutRecoveryError::InvalidCheckpoint)?;
        let expected_plan_start = self
            .source_fence
            .plan_count
            .checked_add(1)
            .ok_or(PayoutRecoveryError::InvalidCheckpoint)?;
        let expected_sequences_are_contiguous =
            self.expected_plans
                .iter()
                .enumerate()
                .all(|(offset, entry)| {
                    u64::try_from(offset)
                        .ok()
                        .and_then(|offset| expected_plan_start.checked_add(offset))
                        == Some(entry.plan_sequence)
                });
        let canonical_sequences: BTreeSet<_> = self
            .canonical_plan_bindings
            .iter()
            .map(|entry| entry.plan_sequence)
            .collect();
        let canonical_plan_ids: BTreeSet<_> = self
            .canonical_plan_bindings
            .iter()
            .map(|entry| entry.payout_plan_id)
            .collect();
        let canonical_snapshot_ids: BTreeSet<_> = self
            .canonical_plan_bindings
            .iter()
            .map(|entry| entry.payout_snapshot_id)
            .collect();
        let expected_snapshot_ids: BTreeSet<_> = self
            .expected_plans
            .iter()
            .map(|entry| entry.snapshot_id)
            .collect();
        let restored_accumulator = SnapshotAccumulator::from_checkpoint(
            self.accumulator.clone(),
            SnapshotAccumulatorLimits::default(),
        )
        .map_err(|_| PayoutRecoveryError::InvalidCheckpoint)?;
        let canonical_accumulator = restored_accumulator
            .checkpoint()
            .map_err(|_| PayoutRecoveryError::InvalidCheckpoint)?;
        if self.core_protocol_version != CORE_V2
            || self.checkpoint_version != PAYOUT_RECOVERY_CHECKPOINT_V1
            || self.checkpoint_sequence == 0
            || self.payout_policy_fingerprint == [0; 32]
            || self.accumulator.network_id != self.network_id
            || self.accumulator.next_sequence != expected_next_snapshot
            || self.accumulator.previous_snapshot_id != self.source_fence.snapshot_head_id
            || self.accumulator.snapshot_step_work == U512::ZERO
            || self.accumulator.pplns_window_work == U512::ZERO
            || self.accumulator.closed_sessions.len() > DEFAULT_MAX_RETAINED_SESSIONS
            || self.expected_plans.len() > MAX_EXPECTED_PAYOUT_PLANS
            || self.expected_plans.len() != expected_queue_length
            || self.canonical_plan_bindings.len() > MAX_CANONICAL_PLAN_BINDINGS
            || canonical_accumulator != self.accumulator
            || !expected_sequences_are_contiguous
            || self
                .expected_plans
                .windows(2)
                .any(|pair| pair[0].plan_sequence >= pair[1].plan_sequence)
            || self
                .expected_plans
                .iter()
                .any(|entry| entry.plan_sequence == 0 || entry.snapshot_id == [0; 32])
            || self
                .canonical_plan_bindings
                .windows(2)
                .any(|pair| pair[0].plan_sequence >= pair[1].plan_sequence)
            || self.canonical_plan_bindings.iter().any(|entry| {
                entry.plan_sequence == 0
                    || entry.plan_sequence > self.source_fence.plan_count
                    || entry.payout_plan_id == [0; 32]
                    || entry.payout_snapshot_id == [0; 32]
            })
            || canonical_sequences.len() != self.canonical_plan_bindings.len()
            || canonical_plan_ids.len() != self.canonical_plan_bindings.len()
            || canonical_snapshot_ids.len() != self.canonical_plan_bindings.len()
            || expected_snapshot_ids.len() != self.expected_plans.len()
            || canonical_snapshot_ids
                .iter()
                .any(|snapshot_id| expected_snapshot_ids.contains(snapshot_id))
            || (self.source_fence.plan_count == 0 && !self.canonical_plan_bindings.is_empty())
            || (self.source_fence.plan_count != 0
                && self.canonical_plan_bindings.last().is_none_or(|binding| {
                    binding.plan_sequence != self.source_fence.plan_count
                        || binding.payout_plan_id != self.source_fence.plan_head_id
                }))
            || (self.source_fence.snapshot_count != self.source_fence.plan_count
                && self.expected_plans.last().is_none_or(|expected| {
                    expected.snapshot_id != self.source_fence.snapshot_head_id
                }))
            || (self.source_fence.snapshot_count == self.source_fence.plan_count
                && !self.expected_plans.is_empty())
            || self.signer_set.validate_order().is_err()
        {
            return Err(PayoutRecoveryError::InvalidCheckpoint);
        }
        Ok(())
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, PayoutRecoveryError> {
        self.validate_structure()?;
        let payload = self.to_canonical_bytes();
        if payload.len() > MAX_PAYOUT_CHECKPOINT_BYTES {
            return Err(PayoutRecoveryError::CheckpointTooLarge);
        }
        let decoded = Self::from_canonical_bytes(
            &payload,
            DecodeLimits {
                max_object_bytes: MAX_PAYOUT_CHECKPOINT_BYTES,
                max_vector_items: DEFAULT_MAX_RETAINED_BUCKET_CREDITS,
            },
        )
        .map_err(|_| PayoutRecoveryError::NonCanonicalCheckpoint)?;
        if decoded != *self || decoded.to_canonical_bytes() != payload {
            return Err(PayoutRecoveryError::NonCanonicalCheckpoint);
        }
        Ok(payload)
    }
}

impl PayoutRecoveryCommitteePolicyV1 {
    fn validate(&self) -> Result<(), PayoutRecoveryError> {
        if self.settlement_committee_id == [0; 32]
            || self.payout_policy_fingerprint == [0; 32]
            || self.members.is_empty()
            || self.members.len() > MAX_PAYOUT_RECOVERY_COMMITTEE_MEMBERS
            || self.threshold == 0
            || usize::from(self.threshold) > self.members.len()
        {
            return Err(PayoutRecoveryError::InvalidCommitteePolicy);
        }
        Ok(())
    }

    fn verify_checkpoint(
        &self,
        checkpoint: &PayoutRecoveryCheckpointV1,
    ) -> Result<(), PayoutRecoveryError> {
        self.validate()?;
        if checkpoint.network_id != self.network_id
            || checkpoint.accumulator.settlement_committee_id != self.settlement_committee_id
            || checkpoint.payout_policy_fingerprint != self.payout_policy_fingerprint
            || checkpoint.signer_set.signature_suite != ED25519_SUITE
            || checkpoint.signer_set.signatures.len() < usize::from(self.threshold)
            || checkpoint
                .signer_set
                .signatures
                .iter()
                .any(|signature| !self.members.contains(&signature.signer_pubkey))
            || verify_certificate(&checkpoint.signer_set, checkpoint.network_id, checkpoint)
                .is_err()
        {
            return Err(PayoutRecoveryError::InvalidCertificate);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PayoutRecoveryHeadV1 {
    network_id: u8,
    checkpoint_sequence: u64,
    checkpoint_id: Hash256,
    checkpoint_wrapper_id: Hash256,
}

fn encode_head(head: PayoutRecoveryHeadV1) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.fixed(&PAYOUT_RECOVERY_HEAD_MAGIC);
    encoder.u16(PAYOUT_RECOVERY_CHECKPOINT_V1);
    encoder.u8(head.network_id);
    encoder.u64(head.checkpoint_sequence);
    encoder.fixed(&head.checkpoint_id);
    encoder.fixed(&head.checkpoint_wrapper_id);
    encoder.into_bytes()
}

fn decode_head(network_id: u8, bytes: &[u8]) -> Result<PayoutRecoveryHeadV1, PayoutRecoveryError> {
    let mut decoder = Decoder::new(
        bytes,
        DecodeLimits {
            max_object_bytes: 96,
            max_vector_items: 0,
        },
    )
    .map_err(|_| PayoutRecoveryError::InvalidHead)?;
    if decoder
        .array::<4>()
        .map_err(|_| PayoutRecoveryError::InvalidHead)?
        != PAYOUT_RECOVERY_HEAD_MAGIC
        || decoder
            .u16()
            .map_err(|_| PayoutRecoveryError::InvalidHead)?
            != PAYOUT_RECOVERY_CHECKPOINT_V1
    {
        return Err(PayoutRecoveryError::InvalidHead);
    }
    let head = PayoutRecoveryHeadV1 {
        network_id: decoder.u8().map_err(|_| PayoutRecoveryError::InvalidHead)?,
        checkpoint_sequence: decoder
            .u64()
            .map_err(|_| PayoutRecoveryError::InvalidHead)?,
        checkpoint_id: decoder
            .array()
            .map_err(|_| PayoutRecoveryError::InvalidHead)?,
        checkpoint_wrapper_id: decoder
            .array()
            .map_err(|_| PayoutRecoveryError::InvalidHead)?,
    };
    decoder
        .finish()
        .map_err(|_| PayoutRecoveryError::InvalidHead)?;
    if head.network_id != network_id
        || head.checkpoint_sequence == 0
        || head.checkpoint_id == [0; 32]
        || head.checkpoint_wrapper_id == [0; 32]
    {
        return Err(PayoutRecoveryError::InvalidHead);
    }
    Ok(head)
}

fn load_checkpoint_at_head(
    store: &dyn DurableStore,
    policy: &PayoutRecoveryCommitteePolicyV1,
    head: PayoutRecoveryHeadV1,
) -> Result<PayoutRecoveryCheckpointV1, PayoutRecoveryError> {
    let payload = ProtocolJournal::new(store)
        .load(
            ProtocolRecordKind::PayoutRecoveryCheckpoint,
            &head.checkpoint_wrapper_id,
        )
        .map_err(PayoutRecoveryError::from)?
        .ok_or(PayoutRecoveryError::MissingCheckpoint)?;
    let checkpoint = PayoutRecoveryCheckpointV1::from_canonical_bytes(
        &payload,
        DecodeLimits {
            max_object_bytes: MAX_PAYOUT_CHECKPOINT_BYTES,
            max_vector_items: DEFAULT_MAX_RETAINED_BUCKET_CREDITS,
        },
    )
    .map_err(|_| PayoutRecoveryError::NonCanonicalCheckpoint)?;
    checkpoint.validate_structure()?;
    if checkpoint.network_id != head.network_id
        || checkpoint.checkpoint_sequence != head.checkpoint_sequence
        || checkpoint.object_id() != head.checkpoint_id
        || domain_hash(PAYOUT_RECOVERY_WRAPPER_DOMAIN, &payload) != head.checkpoint_wrapper_id
        || checkpoint.to_canonical_bytes() != payload
    {
        return Err(PayoutRecoveryError::NonCanonicalCheckpoint);
    }
    policy.verify_checkpoint(&checkpoint)?;
    Ok(checkpoint)
}

fn source_fence_matches(
    store: &dyn DurableStore,
    network_id: u8,
    expected: PayoutRecoverySourceFenceV1,
) -> Result<bool, PayoutRecoveryError> {
    let Some(bytes) = store
        .get(
            PAYOUT_RECOVERY_SOURCE_FENCE_NAMESPACE,
            &network_id.to_string(),
        )
        .map_err(DurableInvariantError::from)?
    else {
        return Ok(false);
    };
    let observed = decode_source_fence(network_id, &bytes)?;
    Ok(observed == expected && bytes == encode_source_fence(network_id, expected))
}

fn validate_checkpoint_transition(
    previous: &PayoutRecoveryCheckpointV1,
    next: &PayoutRecoveryCheckpointV1,
) -> Result<(), PayoutRecoveryError> {
    if next.payout_policy_fingerprint != previous.payout_policy_fingerprint
        || next.accumulator.snapshot_step_work != previous.accumulator.snapshot_step_work
        || next.accumulator.pplns_window_work != previous.accumulator.pplns_window_work
        || next.accumulator.settlement_committee_id != previous.accumulator.settlement_committee_id
    {
        return Err(PayoutRecoveryError::PolicyChange);
    }
    next.source_fence
        .validate_monotonic_after(&previous.source_fence)?;
    if next.source_fence == previous.source_fence
        && (next.accumulator != previous.accumulator
            || next.expected_plans != previous.expected_plans
            || next.canonical_plan_bindings != previous.canonical_plan_bindings)
    {
        return Err(PayoutRecoveryError::SourceFenceRegression);
    }
    Ok(())
}

/// Atomically install one certified immutable checkpoint, advance its
/// per-network head, and condition the transaction on the exact durable source
/// fence it seals. Exact retries are explicit; forks, stale fences, skipped
/// sequences, policy changes, and concurrent races are errors.
pub fn persist_payout_recovery_checkpoint(
    store: &dyn DurableStore,
    checkpoint: &PayoutRecoveryCheckpointV1,
    policy: &PayoutRecoveryCommitteePolicyV1,
) -> Result<PayoutRecoveryPersistOutcome, PayoutRecoveryError> {
    let payload = checkpoint.canonical_payload()?;
    policy.verify_checkpoint(checkpoint)?;
    let key = checkpoint.network_id.to_string();
    let expected_source_fence = encode_source_fence(checkpoint.network_id, checkpoint.source_fence);
    if !source_fence_matches(store, checkpoint.network_id, checkpoint.source_fence)? {
        return Err(PayoutRecoveryError::SourceFenceMismatch);
    }
    let existing = store
        .get(PAYOUT_RECOVERY_HEAD_NAMESPACE, &key)
        .map_err(DurableInvariantError::from)?;
    let checkpoint_id = checkpoint.object_id();
    let checkpoint_wrapper_id = domain_hash(PAYOUT_RECOVERY_WRAPPER_DOMAIN, &payload);
    if let Some(bytes) = existing.as_deref() {
        let current = decode_head(checkpoint.network_id, bytes)?;
        if current.checkpoint_id == checkpoint_id {
            if current.checkpoint_sequence != checkpoint.checkpoint_sequence {
                return Err(PayoutRecoveryError::Sequence);
            }
            let _ = load_checkpoint_at_head(store, policy, current)?;
            if store
                .apply_batch_if_all(
                    &[
                        BatchCondition::equals(
                            PAYOUT_RECOVERY_HEAD_NAMESPACE,
                            &key,
                            bytes.to_vec(),
                        ),
                        BatchCondition::equals(
                            PAYOUT_RECOVERY_SOURCE_FENCE_NAMESPACE,
                            &key,
                            expected_source_fence,
                        ),
                    ],
                    &[],
                )
                .map_err(DurableInvariantError::from)?
            {
                return Ok(PayoutRecoveryPersistOutcome::AlreadyCurrent);
            }
            return Err(PayoutRecoveryError::ConcurrentUpdate);
        } else {
            if checkpoint.checkpoint_sequence
                != current
                    .checkpoint_sequence
                    .checked_add(1)
                    .ok_or(PayoutRecoveryError::Sequence)?
                || checkpoint.previous_checkpoint_id != current.checkpoint_id
            {
                return Err(PayoutRecoveryError::Sequence);
            }
            let previous = load_checkpoint_at_head(store, policy, current)?;
            validate_checkpoint_transition(&previous, checkpoint)?;
        }
    } else if checkpoint.checkpoint_sequence != 1 || checkpoint.previous_checkpoint_id != [0; 32] {
        return Err(PayoutRecoveryError::Sequence);
    }

    let head = PayoutRecoveryHeadV1 {
        network_id: checkpoint.network_id,
        checkpoint_sequence: checkpoint.checkpoint_sequence,
        checkpoint_id,
        checkpoint_wrapper_id,
    };
    let outcome = ProtocolJournal::new(store)
        .persist_records_with_conditions_and_batch(
            &[JournalBatchRecord::new(
                ProtocolRecordKind::PayoutRecoveryCheckpoint,
                checkpoint_wrapper_id.to_vec(),
                payload,
            )],
            &[
                BatchCondition::new(PAYOUT_RECOVERY_HEAD_NAMESPACE, &key, existing),
                BatchCondition::equals(
                    PAYOUT_RECOVERY_SOURCE_FENCE_NAMESPACE,
                    &key,
                    expected_source_fence.clone(),
                ),
            ],
            &[BatchOperation::put(
                PAYOUT_RECOVERY_HEAD_NAMESPACE,
                &key,
                encode_head(head),
            )],
        )
        .map_err(PayoutRecoveryError::from)?;
    match outcome {
        JournalBatchOutcome::Committed => Ok(PayoutRecoveryPersistOutcome::Committed),
        JournalBatchOutcome::ExactRecord
            if source_fence_matches(store, checkpoint.network_id, checkpoint.source_fence)?
                && store
                    .get(PAYOUT_RECOVERY_HEAD_NAMESPACE, &key)
                    .map_err(DurableInvariantError::from)?
                    .as_deref()
                    .is_some_and(|bytes| {
                        decode_head(checkpoint.network_id, bytes).ok() == Some(head)
                    }) =>
        {
            Ok(PayoutRecoveryPersistOutcome::AlreadyCurrent)
        }
        JournalBatchOutcome::ExactRecord | JournalBatchOutcome::PreconditionMismatch => {
            Err(PayoutRecoveryError::ConcurrentUpdate)
        }
    }
}

/// Recover and authenticate the exact head checkpoint with O(1) journal
/// lookups, then require its sealed source fence to equal the live durable row.
/// Online payout cutover remains disabled until every source writer advances
/// that row in its own atomic source transaction.
pub fn load_payout_recovery_checkpoint(
    store: &dyn DurableStore,
    policy: &PayoutRecoveryCommitteePolicyV1,
) -> Result<Option<PayoutRecoveryCheckpointV1>, PayoutRecoveryError> {
    policy.validate()?;
    let network_id = policy.network_id;
    let Some(head_bytes) = store
        .get(PAYOUT_RECOVERY_HEAD_NAMESPACE, &network_id.to_string())
        .map_err(DurableInvariantError::from)?
    else {
        return Ok(None);
    };
    let head = decode_head(network_id, &head_bytes)?;
    let checkpoint = load_checkpoint_at_head(store, policy, head)?;
    if !source_fence_matches(store, network_id, checkpoint.source_fence)? {
        return Err(PayoutRecoveryError::SourceFenceMismatch);
    }
    Ok(Some(checkpoint))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use ed25519_dalek::SigningKey;
    use meshmine_crypto::{assemble_ed25519_set, sign_certificate};
    use meshmine_storage::{MemoryStore, RedbStore};
    use meshmine_types::SignatureBytes;

    use super::*;

    fn hash(byte: u8) -> Hash256 {
        [byte; 32]
    }

    fn bucket(byte: u8) -> PayoutBucketV2 {
        PayoutBucketV2 {
            protocol_version: CORE_V2,
            network_id: 2,
            operator_pubkey: hash(byte),
            bucket_sequence: 1,
            hns_address_version: 0,
            hns_address_hash: vec![byte; 20],
            activation_height: 1,
            retirement_height: None,
            signature: SignatureBytes(vec![byte; 64]),
        }
    }

    fn signing_keys() -> Vec<SigningKey> {
        vec![
            SigningKey::from_bytes(&[41; 32]),
            SigningKey::from_bytes(&[42; 32]),
            SigningKey::from_bytes(&[43; 32]),
        ]
    }

    fn policy(keys: &[SigningKey]) -> PayoutRecoveryCommitteePolicyV1 {
        PayoutRecoveryCommitteePolicyV1 {
            network_id: 2,
            settlement_committee_id: hash(6),
            payout_policy_fingerprint: hash(1),
            threshold: 2,
            members: keys
                .iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
        }
    }

    fn certify(
        mut checkpoint: PayoutRecoveryCheckpointV1,
        keys: &[SigningKey],
    ) -> PayoutRecoveryCheckpointV1 {
        checkpoint.signer_set = assemble_ed25519_set(
            keys.iter()
                .take(2)
                .map(|key| sign_certificate(key, checkpoint.network_id, &checkpoint))
                .collect(),
        )
        .unwrap();
        checkpoint
    }

    fn install_source_fence(
        store: &dyn DurableStore,
        previous: Option<PayoutRecoverySourceFenceV1>,
        next: PayoutRecoverySourceFenceV1,
    ) {
        let (condition, operation) =
            payout_recovery_source_fence_transition(2, previous, next).unwrap();
        assert!(
            store
                .apply_batch_if_all(&[condition], &[operation])
                .unwrap()
        );
    }

    fn secure_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        directory
    }

    fn checkpoint(sequence: u64, previous: Hash256) -> PayoutRecoveryCheckpointV1 {
        PayoutRecoveryCheckpointV1 {
            core_protocol_version: CORE_V2,
            checkpoint_version: PAYOUT_RECOVERY_CHECKPOINT_V1,
            network_id: 2,
            checkpoint_sequence: sequence,
            previous_checkpoint_id: previous,
            payout_policy_fingerprint: hash(1),
            source_fence: PayoutRecoverySourceFenceV1 {
                disposition_count: 2,
                disposition_commitment: hash(2),
                snapshot_count: 2,
                snapshot_head_id: hash(9),
                plan_count: 1,
                plan_head_id: hash(4),
                canonical_event_count: 1,
                canonical_event_commitment: hash(5),
            },
            accumulator: SnapshotAccumulatorCheckpoint {
                network_id: 2,
                next_sequence: 3,
                previous_snapshot_id: hash(9),
                snapshot_step_work: U512([1; 64]),
                pplns_window_work: U512([2; 64]),
                settlement_committee_id: hash(6),
                closed_sessions: vec![ClosedSessionCredits {
                    session_close_id: hash(7),
                    close_anchor_height: 10,
                    work: vec![BucketCredit {
                        bucket: bucket(8),
                        credit: U512([3; 64]),
                    }],
                    service: vec![],
                }],
                new_work_since_snapshot: U512::ZERO,
            },
            expected_plans: vec![ExpectedPayoutPlanV1 {
                plan_sequence: 2,
                snapshot_id: hash(9),
            }],
            canonical_plan_bindings: vec![CanonicalPlanBindingV1 {
                plan_sequence: 1,
                payout_plan_id: hash(4),
                payout_snapshot_id: hash(3),
            }],
            signer_set: SignatureSet {
                signature_suite: ED25519_SUITE,
                signatures: vec![],
            },
        }
    }

    #[test]
    fn checkpoint_round_trips_and_certificate_is_bound_to_local_policy() {
        let keys = signing_keys();
        assert_eq!(
            policy(&keys).verify_checkpoint(&checkpoint(1, [0; 32])),
            Err(PayoutRecoveryError::InvalidCertificate)
        );
        let value = certify(checkpoint(1, [0; 32]), &keys);
        let bytes = value.to_canonical_bytes();
        let decoded = PayoutRecoveryCheckpointV1::from_canonical_bytes(
            &bytes,
            DecodeLimits {
                max_object_bytes: MAX_PAYOUT_CHECKPOINT_BYTES,
                max_vector_items: DEFAULT_MAX_RETAINED_BUCKET_CREDITS,
            },
        )
        .unwrap();
        assert_eq!(decoded, value);
        assert_eq!(value.canonical_payload().unwrap(), bytes);
        policy(&keys).verify_checkpoint(&value).unwrap();

        let mut tampered = value.clone();
        tampered.signer_set.signatures[0].signature.0[0] ^= 1;
        assert_eq!(tampered.object_id(), value.object_id());
        assert_eq!(
            policy(&keys).verify_checkpoint(&tampered),
            Err(PayoutRecoveryError::InvalidCertificate)
        );
    }

    #[test]
    fn durable_head_is_certified_exact_and_constant_lookup_recoverable() {
        let store = MemoryStore::default();
        let keys = signing_keys();
        let policy = policy(&keys);
        let first = certify(checkpoint(1, [0; 32]), &keys);
        install_source_fence(&store, None, first.source_fence);
        assert_eq!(
            persist_payout_recovery_checkpoint(&store, &first, &policy).unwrap(),
            PayoutRecoveryPersistOutcome::Committed
        );
        assert_eq!(
            persist_payout_recovery_checkpoint(&store, &first, &policy).unwrap(),
            PayoutRecoveryPersistOutcome::AlreadyCurrent
        );
        assert_eq!(
            load_payout_recovery_checkpoint(&store, &policy).unwrap(),
            Some(first.clone())
        );

        let mut alternate_wrapper = first.clone();
        alternate_wrapper.signer_set = assemble_ed25519_set(
            keys.iter()
                .skip(1)
                .take(2)
                .map(|key| sign_certificate(key, alternate_wrapper.network_id, &alternate_wrapper))
                .collect(),
        )
        .unwrap();
        assert_eq!(alternate_wrapper.object_id(), first.object_id());
        assert_ne!(
            alternate_wrapper.to_canonical_bytes(),
            first.to_canonical_bytes()
        );
        assert_eq!(
            persist_payout_recovery_checkpoint(&store, &alternate_wrapper, &policy).unwrap(),
            PayoutRecoveryPersistOutcome::AlreadyCurrent
        );
        assert_eq!(
            load_payout_recovery_checkpoint(&store, &policy).unwrap(),
            Some(first.clone())
        );

        let second = certify(checkpoint(2, first.object_id()), &keys);
        assert_eq!(
            persist_payout_recovery_checkpoint(&store, &second, &policy).unwrap(),
            PayoutRecoveryPersistOutcome::Committed
        );
        assert_eq!(
            load_payout_recovery_checkpoint(&store, &policy).unwrap(),
            Some(second.clone())
        );

        let skipped = certify(checkpoint(4, second.object_id()), &keys);
        assert_eq!(
            persist_payout_recovery_checkpoint(&store, &skipped, &policy),
            Err(PayoutRecoveryError::Sequence)
        );
    }

    #[test]
    fn structural_checks_reject_queue_overlap_gaps_and_incoherent_heads() {
        let mut value = checkpoint(1, [0; 32]);
        value.expected_plans.push(ExpectedPayoutPlanV1 {
            plan_sequence: 3,
            snapshot_id: hash(12),
        });
        assert_eq!(
            value.validate_structure(),
            Err(PayoutRecoveryError::InvalidCheckpoint)
        );
        value = checkpoint(1, [0; 32]);
        value.expected_plans[0].plan_sequence = 1;
        assert_eq!(
            value.validate_structure(),
            Err(PayoutRecoveryError::InvalidCheckpoint)
        );

        value = checkpoint(1, [0; 32]);
        value.source_fence.plan_count = 0;
        assert_eq!(
            value.validate_structure(),
            Err(PayoutRecoveryError::InvalidCheckpoint)
        );
    }

    #[test]
    fn nonminimal_accumulator_and_decoder_only_field_overflow_fail_before_commit() {
        let keys = signing_keys();
        let policy = policy(&keys);
        let store = MemoryStore::default();

        let mut nonminimal = checkpoint(1, [0; 32]);
        let mut redundant = nonminimal.accumulator.closed_sessions[0].clone();
        redundant.session_close_id = hash(20);
        nonminimal.accumulator.closed_sessions.insert(0, redundant);
        assert_eq!(
            nonminimal.validate_structure(),
            Err(PayoutRecoveryError::InvalidCheckpoint)
        );

        let mut unencodable = checkpoint(1, [0; 32]);
        unencodable.accumulator.closed_sessions[0].work[0]
            .bucket
            .hns_address_hash = vec![1; 65];
        let unencodable = certify(unencodable, &keys);
        install_source_fence(&store, None, unencodable.source_fence);
        assert_eq!(
            persist_payout_recovery_checkpoint(&store, &unencodable, &policy),
            Err(PayoutRecoveryError::NonCanonicalCheckpoint)
        );
        assert!(
            store
                .get(PAYOUT_RECOVERY_HEAD_NAMESPACE, "2")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn exact_source_fence_and_monotonic_checkpoint_transition_are_required() {
        let store = MemoryStore::default();
        let keys = signing_keys();
        let policy = policy(&keys);
        let first = certify(checkpoint(1, [0; 32]), &keys);

        assert_eq!(
            persist_payout_recovery_checkpoint(&store, &first, &policy),
            Err(PayoutRecoveryError::SourceFenceMismatch)
        );
        install_source_fence(&store, None, first.source_fence);
        persist_payout_recovery_checkpoint(&store, &first, &policy).unwrap();

        let mut changed_without_source = checkpoint(2, first.object_id());
        changed_without_source.accumulator.closed_sessions[0].close_anchor_height += 1;
        let changed_without_source = certify(changed_without_source, &keys);
        assert_eq!(
            persist_payout_recovery_checkpoint(&store, &changed_without_source, &policy),
            Err(PayoutRecoveryError::SourceFenceRegression)
        );

        let mut policy_change = checkpoint(2, first.object_id());
        policy_change.accumulator.snapshot_step_work = U512([4; 64]);
        let policy_change = certify(policy_change, &keys);
        assert_eq!(
            persist_payout_recovery_checkpoint(&store, &policy_change, &policy),
            Err(PayoutRecoveryError::PolicyChange)
        );
    }

    #[test]
    fn load_rejects_a_source_fence_that_advanced_past_the_checkpoint() {
        let store = MemoryStore::default();
        let keys = signing_keys();
        let policy = policy(&keys);
        let first = certify(checkpoint(1, [0; 32]), &keys);
        install_source_fence(&store, None, first.source_fence);
        persist_payout_recovery_checkpoint(&store, &first, &policy).unwrap();

        let mut advanced = first.source_fence;
        advanced.canonical_event_count += 1;
        advanced.canonical_event_commitment = hash(30);
        install_source_fence(&store, Some(first.source_fence), advanced);
        assert_eq!(
            load_payout_recovery_checkpoint(&store, &policy),
            Err(PayoutRecoveryError::SourceFenceMismatch)
        );
    }

    #[test]
    fn concurrent_exact_persistence_has_only_explicit_success_outcomes() {
        let store = Arc::new(MemoryStore::default());
        let keys = signing_keys();
        let policy = Arc::new(policy(&keys));
        let checkpoint = Arc::new(certify(checkpoint(1, [0; 32]), &keys));
        install_source_fence(store.as_ref(), None, checkpoint.source_fence);
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let store = Arc::clone(&store);
            let policy = Arc::clone(&policy);
            let checkpoint = Arc::clone(&checkpoint);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                persist_payout_recovery_checkpoint(
                    store.as_ref(),
                    checkpoint.as_ref(),
                    policy.as_ref(),
                )
            }));
        }
        barrier.wait();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect();
        assert!(outcomes.contains(&PayoutRecoveryPersistOutcome::Committed));
        assert!(outcomes.contains(&PayoutRecoveryPersistOutcome::AlreadyCurrent));
    }

    #[test]
    fn certified_head_and_exact_source_fence_survive_redb_restart() {
        let directory = secure_tempdir();
        let path = directory.path().join("payout-recovery.redb");
        let keys = signing_keys();
        let policy = policy(&keys);
        let checkpoint = certify(checkpoint(1, [0; 32]), &keys);
        {
            let store = RedbStore::create(&path).unwrap();
            install_source_fence(&store, None, checkpoint.source_fence);
            assert_eq!(
                persist_payout_recovery_checkpoint(&store, &checkpoint, &policy).unwrap(),
                PayoutRecoveryPersistOutcome::Committed
            );
            assert_eq!(
                persist_payout_recovery_checkpoint(&store, &checkpoint, &policy).unwrap(),
                PayoutRecoveryPersistOutcome::AlreadyCurrent
            );
        }
        let store = RedbStore::open_existing(&path).unwrap();
        assert_eq!(
            load_payout_recovery_checkpoint(&store, &policy).unwrap(),
            Some(checkpoint)
        );
    }

    #[test]
    fn accumulator_checkpoint_codec_preserves_full_credit_metadata() {
        let value = checkpoint(1, [0; 32]).accumulator;
        let bytes = value.to_canonical_bytes();
        let decoded = SnapshotAccumulatorCheckpoint::from_canonical_bytes(
            &bytes,
            DecodeLimits {
                max_object_bytes: MAX_PAYOUT_CHECKPOINT_BYTES,
                max_vector_items: DEFAULT_MAX_RETAINED_BUCKET_CREDITS,
            },
        )
        .unwrap();
        assert_eq!(decoded, value);
    }
}
