//! Authenticated gateway-to-Core capture handoff.
//!
//! This crate deliberately does not accept mining work by itself. It defines
//! the canonical signed evidence and pure replay/sequence checks that the Core
//! admission transaction must validate before a gateway share can enter the
//! authoritative share, receipt, or payout journals.

use meshmine_codec::{
    CanonicalDecode, CanonicalEncode, CodecError, DecodeLimits, Decoder, Encoder,
};
use meshmine_crypto::verify_object;
use meshmine_hns::Hash256;
use meshmine_storage::{
    BatchCondition, BatchOperation, DurableInvariantError, DurableStore, JournalBatchOutcome,
    JournalBatchRecord, ProtocolJournal, ProtocolRecordKind,
};
use meshmine_types::{
    CORE_V2, ED25519_SUITE, GATEWAY_HANDOFF_V1, GATEWAY_OBSERVATION_CORE_RECEIPT_TIME,
    GATEWAY_OBSERVATION_DELEGATED_SIGNED_TIME_V1, GatewayAssignmentV1, MAX_GATEWAY_CLOCK_SKEW_MS,
    SignatureBytes, UnsignedObject,
};
use thiserror::Error;

pub const MAX_HANDOFF_FRAME_BYTES: u32 = 1024 * 1024;
pub const MAX_HANDOFF_IN_FLIGHT: u16 = 4096;

pub const CAPTURE_OUTCOME_ACCEPTED: u8 = 1;
pub const CAPTURE_OUTCOME_REJECTED: u8 = 2;
pub const CAPTURE_OUTCOME_GRACE_NONCREDIT: u8 = 3;
pub const CAPTURE_OUTCOME_DUPLICATE: u8 = 4;

pub const DRAIN_OUTCOME_COMPLETE: u8 = 1;
pub const DRAIN_OUTCOME_REJECTED: u8 = 2;

pub const GATEWAY_CAPTURE_CURSOR_NAMESPACE: &str = "gateway-capture-cursor/v1";
pub const GATEWAY_CONTEXT_HEAD_NAMESPACE: &str = "gateway-context-head/v1";
pub const GATEWAY_ASSIGNMENT_HEAD_NAMESPACE: &str = "gateway-assignment-head/v1";
pub const GATEWAY_ASSIGNMENT_STATE_NAMESPACE: &str = "gateway-assignment-state/v1";

const ASSIGNMENT_STATE_ACTIVE: u8 = 1;
const ASSIGNMENT_STATE_DRAINED: u8 = 2;

/// Operator authorization binding one gateway identity to one Core handoff
/// identity. Local transport authentication is necessary but not sufficient:
/// peers also have to present this signed context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayContextManifestV1 {
    pub core_protocol_version: u16,
    pub handoff_version: u16,
    pub network_id: u8,
    pub context_sequence: u64,
    pub previous_manifest_id: Hash256,
    pub operator_pubkey: [u8; 32],
    pub gateway_pubkey: [u8; 32],
    pub core_handoff_pubkey: [u8; 32],
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub maximum_frame_bytes: u32,
    pub maximum_in_flight: u16,
    pub operator_signature: SignatureBytes,
}

/// Gateway-signed evidence for one captured proof. It intentionally omits a
/// `ShareV2` ID so the share can commit to this envelope without an ID cycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayCaptureEnvelopeV1 {
    pub core_protocol_version: u16,
    pub handoff_version: u16,
    pub network_id: u8,
    pub context_manifest_id: Hash256,
    pub assignment_id: Hash256,
    pub session_id: Hash256,
    pub gateway_pubkey: [u8; 32],
    pub core_handoff_pubkey: [u8; 32],
    pub gateway_sequence: u64,
    pub gateway_connection_id: Hash256,
    pub gateway_received_ms: u64,
    pub ntime: u64,
    pub extra_nonce: [u8; 24],
    pub nonce: u32,
    pub raw_share_hash: Hash256,
    pub gateway_signature: SignatureBytes,
}

/// Gateway-signed boundary between assignments. Captures at or below the
/// cutoff remain attributable to the previous assignment; captures above it
/// must use the next assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayAssignmentTransitionV1 {
    pub core_protocol_version: u16,
    pub handoff_version: u16,
    pub network_id: u8,
    pub context_manifest_id: Hash256,
    pub gateway_pubkey: [u8; 32],
    pub core_handoff_pubkey: [u8; 32],
    pub transition_sequence: u64,
    pub previous_assignment_id: Hash256,
    pub next_assignment_id: Hash256,
    pub previous_assignment_last_gateway_sequence: u64,
    pub transition_ms: u64,
    pub reason_code: u16,
    pub gateway_signature: SignatureBytes,
}

/// Core-signed durable disposition for a capture envelope. Rejected, grace,
/// and duplicate outcomes never authorize work credit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayCaptureReceiptV1 {
    pub core_protocol_version: u16,
    pub handoff_version: u16,
    pub network_id: u8,
    pub context_manifest_id: Hash256,
    pub assignment_id: Hash256,
    pub capture_envelope_id: Hash256,
    pub gateway_pubkey: [u8; 32],
    pub core_handoff_pubkey: [u8; 32],
    pub receipt_sequence: u64,
    pub core_received_ms: u64,
    pub outcome: u8,
    pub reason_code: u16,
    /// Zero for every non-accepted outcome.
    pub accepted_share_id: Hash256,
    pub core_signature: SignatureBytes,
}

/// Gateway declaration that no later capture will be emitted for an
/// assignment. The final envelope ID is zero only when the assignment emitted
/// no captures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayAssignmentDrainV1 {
    pub core_protocol_version: u16,
    pub handoff_version: u16,
    pub network_id: u8,
    pub context_manifest_id: Hash256,
    pub assignment_id: Hash256,
    pub gateway_pubkey: [u8; 32],
    pub core_handoff_pubkey: [u8; 32],
    pub last_gateway_sequence: u64,
    pub final_capture_envelope_id: Hash256,
    pub drained_ms: u64,
    pub gateway_signature: SignatureBytes,
}

/// Core acknowledgement that all captures through the signed drain boundary
/// have durable dispositions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreAssignmentDrainReceiptV1 {
    pub core_protocol_version: u16,
    pub handoff_version: u16,
    pub network_id: u8,
    pub context_manifest_id: Hash256,
    pub assignment_id: Hash256,
    pub gateway_drain_id: Hash256,
    pub gateway_pubkey: [u8; 32],
    pub core_handoff_pubkey: [u8; 32],
    pub accepted_through_gateway_sequence: u64,
    pub receipt_sequence: u64,
    pub core_received_ms: u64,
    pub outcome: u8,
    pub reason_code: u16,
    pub core_signature: SignatureBytes,
}

macro_rules! impl_canonical_signed {
    ($type:ty, $signature:ident) => {
        impl CanonicalEncode for $type {
            fn encode(&self, encoder: &mut Encoder) {
                self.encode_unsigned(encoder);
                self.$signature.encode(encoder);
            }
        }
    };
}

impl UnsignedObject for GatewayContextManifestV1 {
    const DOMAIN_TAG: &'static str = "meshmine/gateway-context-manifest/v1";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encoder.u16(self.core_protocol_version);
        encoder.u16(self.handoff_version);
        encoder.u8(self.network_id);
        encoder.u64(self.context_sequence);
        encoder.fixed(&self.previous_manifest_id);
        encoder.fixed(&self.operator_pubkey);
        encoder.fixed(&self.gateway_pubkey);
        encoder.fixed(&self.core_handoff_pubkey);
        encoder.u64(self.valid_from_ms);
        encoder.u64(self.valid_until_ms);
        encoder.u32(self.maximum_frame_bytes);
        encoder.u16(self.maximum_in_flight);
    }
}

impl_canonical_signed!(GatewayContextManifestV1, operator_signature);

impl CanonicalDecode for GatewayContextManifestV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            core_protocol_version: decoder.u16()?,
            handoff_version: decoder.u16()?,
            network_id: decoder.u8()?,
            context_sequence: decoder.u64()?,
            previous_manifest_id: decoder.array()?,
            operator_pubkey: decoder.array()?,
            gateway_pubkey: decoder.array()?,
            core_handoff_pubkey: decoder.array()?,
            valid_from_ms: decoder.u64()?,
            valid_until_ms: decoder.u64()?,
            maximum_frame_bytes: decoder.u32()?,
            maximum_in_flight: decoder.u16()?,
            operator_signature: SignatureBytes::decode(decoder)?,
        })
    }
}

impl UnsignedObject for GatewayCaptureEnvelopeV1 {
    const DOMAIN_TAG: &'static str = "meshmine/gateway-capture-envelope/v1";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encoder.u16(self.core_protocol_version);
        encoder.u16(self.handoff_version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.context_manifest_id);
        encoder.fixed(&self.assignment_id);
        encoder.fixed(&self.session_id);
        encoder.fixed(&self.gateway_pubkey);
        encoder.fixed(&self.core_handoff_pubkey);
        encoder.u64(self.gateway_sequence);
        encoder.fixed(&self.gateway_connection_id);
        encoder.u64(self.gateway_received_ms);
        encoder.u64(self.ntime);
        encoder.fixed(&self.extra_nonce);
        encoder.u32(self.nonce);
        encoder.fixed(&self.raw_share_hash);
    }
}

impl_canonical_signed!(GatewayCaptureEnvelopeV1, gateway_signature);

impl CanonicalDecode for GatewayCaptureEnvelopeV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            core_protocol_version: decoder.u16()?,
            handoff_version: decoder.u16()?,
            network_id: decoder.u8()?,
            context_manifest_id: decoder.array()?,
            assignment_id: decoder.array()?,
            session_id: decoder.array()?,
            gateway_pubkey: decoder.array()?,
            core_handoff_pubkey: decoder.array()?,
            gateway_sequence: decoder.u64()?,
            gateway_connection_id: decoder.array()?,
            gateway_received_ms: decoder.u64()?,
            ntime: decoder.u64()?,
            extra_nonce: decoder.array()?,
            nonce: decoder.u32()?,
            raw_share_hash: decoder.array()?,
            gateway_signature: SignatureBytes::decode(decoder)?,
        })
    }
}

impl UnsignedObject for GatewayAssignmentTransitionV1 {
    const DOMAIN_TAG: &'static str = "meshmine/gateway-assignment-transition/v1";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encoder.u16(self.core_protocol_version);
        encoder.u16(self.handoff_version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.context_manifest_id);
        encoder.fixed(&self.gateway_pubkey);
        encoder.fixed(&self.core_handoff_pubkey);
        encoder.u64(self.transition_sequence);
        encoder.fixed(&self.previous_assignment_id);
        encoder.fixed(&self.next_assignment_id);
        encoder.u64(self.previous_assignment_last_gateway_sequence);
        encoder.u64(self.transition_ms);
        encoder.u16(self.reason_code);
    }
}

impl_canonical_signed!(GatewayAssignmentTransitionV1, gateway_signature);

impl CanonicalDecode for GatewayAssignmentTransitionV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            core_protocol_version: decoder.u16()?,
            handoff_version: decoder.u16()?,
            network_id: decoder.u8()?,
            context_manifest_id: decoder.array()?,
            gateway_pubkey: decoder.array()?,
            core_handoff_pubkey: decoder.array()?,
            transition_sequence: decoder.u64()?,
            previous_assignment_id: decoder.array()?,
            next_assignment_id: decoder.array()?,
            previous_assignment_last_gateway_sequence: decoder.u64()?,
            transition_ms: decoder.u64()?,
            reason_code: decoder.u16()?,
            gateway_signature: SignatureBytes::decode(decoder)?,
        })
    }
}

impl UnsignedObject for GatewayCaptureReceiptV1 {
    const DOMAIN_TAG: &'static str = "meshmine/gateway-capture-receipt/v1";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encoder.u16(self.core_protocol_version);
        encoder.u16(self.handoff_version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.context_manifest_id);
        encoder.fixed(&self.assignment_id);
        encoder.fixed(&self.capture_envelope_id);
        encoder.fixed(&self.gateway_pubkey);
        encoder.fixed(&self.core_handoff_pubkey);
        encoder.u64(self.receipt_sequence);
        encoder.u64(self.core_received_ms);
        encoder.u8(self.outcome);
        encoder.u16(self.reason_code);
        encoder.fixed(&self.accepted_share_id);
    }
}

impl_canonical_signed!(GatewayCaptureReceiptV1, core_signature);

impl CanonicalDecode for GatewayCaptureReceiptV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            core_protocol_version: decoder.u16()?,
            handoff_version: decoder.u16()?,
            network_id: decoder.u8()?,
            context_manifest_id: decoder.array()?,
            assignment_id: decoder.array()?,
            capture_envelope_id: decoder.array()?,
            gateway_pubkey: decoder.array()?,
            core_handoff_pubkey: decoder.array()?,
            receipt_sequence: decoder.u64()?,
            core_received_ms: decoder.u64()?,
            outcome: decoder.u8()?,
            reason_code: decoder.u16()?,
            accepted_share_id: decoder.array()?,
            core_signature: SignatureBytes::decode(decoder)?,
        })
    }
}

impl UnsignedObject for GatewayAssignmentDrainV1 {
    const DOMAIN_TAG: &'static str = "meshmine/gateway-assignment-drain/v1";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encoder.u16(self.core_protocol_version);
        encoder.u16(self.handoff_version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.context_manifest_id);
        encoder.fixed(&self.assignment_id);
        encoder.fixed(&self.gateway_pubkey);
        encoder.fixed(&self.core_handoff_pubkey);
        encoder.u64(self.last_gateway_sequence);
        encoder.fixed(&self.final_capture_envelope_id);
        encoder.u64(self.drained_ms);
    }
}

impl_canonical_signed!(GatewayAssignmentDrainV1, gateway_signature);

impl CanonicalDecode for GatewayAssignmentDrainV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            core_protocol_version: decoder.u16()?,
            handoff_version: decoder.u16()?,
            network_id: decoder.u8()?,
            context_manifest_id: decoder.array()?,
            assignment_id: decoder.array()?,
            gateway_pubkey: decoder.array()?,
            core_handoff_pubkey: decoder.array()?,
            last_gateway_sequence: decoder.u64()?,
            final_capture_envelope_id: decoder.array()?,
            drained_ms: decoder.u64()?,
            gateway_signature: SignatureBytes::decode(decoder)?,
        })
    }
}

impl UnsignedObject for CoreAssignmentDrainReceiptV1 {
    const DOMAIN_TAG: &'static str = "meshmine/core-assignment-drain-receipt/v1";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encoder.u16(self.core_protocol_version);
        encoder.u16(self.handoff_version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.context_manifest_id);
        encoder.fixed(&self.assignment_id);
        encoder.fixed(&self.gateway_drain_id);
        encoder.fixed(&self.gateway_pubkey);
        encoder.fixed(&self.core_handoff_pubkey);
        encoder.u64(self.accepted_through_gateway_sequence);
        encoder.u64(self.receipt_sequence);
        encoder.u64(self.core_received_ms);
        encoder.u8(self.outcome);
        encoder.u16(self.reason_code);
    }
}

impl_canonical_signed!(CoreAssignmentDrainReceiptV1, core_signature);

impl CanonicalDecode for CoreAssignmentDrainReceiptV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            core_protocol_version: decoder.u16()?,
            handoff_version: decoder.u16()?,
            network_id: decoder.u8()?,
            context_manifest_id: decoder.array()?,
            assignment_id: decoder.array()?,
            gateway_drain_id: decoder.array()?,
            gateway_pubkey: decoder.array()?,
            core_handoff_pubkey: decoder.array()?,
            accepted_through_gateway_sequence: decoder.u64()?,
            receipt_sequence: decoder.u64()?,
            core_received_ms: decoder.u64()?,
            outcome: decoder.u8()?,
            reason_code: decoder.u16()?,
            core_signature: SignatureBytes::decode(decoder)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureSequenceDecision {
    New,
    ExactRetry,
}

/// Minimal per-assignment durable sequence fence. Runtime code must update
/// this cursor in the same transaction as the envelope, disposition, accepted
/// share/work records, observation, active-receipt row, and ingest cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayCaptureCursorV1 {
    pub assignment_id: Hash256,
    pub next_gateway_sequence: u64,
    pub last_envelope_id: Hash256,
    pub last_gateway_received_ms: u64,
    pub drained_through_sequence: Option<u64>,
}

impl CanonicalEncode for GatewayCaptureCursorV1 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.fixed(&self.assignment_id);
        encoder.u64(self.next_gateway_sequence);
        encoder.fixed(&self.last_envelope_id);
        encoder.u64(self.last_gateway_received_ms);
        match self.drained_through_sequence {
            None => encoder.u8(0),
            Some(sequence) => {
                encoder.u8(1);
                encoder.u64(sequence);
            }
        }
    }
}

impl CanonicalDecode for GatewayCaptureCursorV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            assignment_id: decoder.array()?,
            next_gateway_sequence: decoder.u64()?,
            last_envelope_id: decoder.array()?,
            last_gateway_received_ms: decoder.u64()?,
            drained_through_sequence: decoder.option(|decoder| decoder.u64())?,
        })
    }
}

impl GatewayCaptureCursorV1 {
    pub fn new(assignment_id: Hash256) -> Self {
        Self {
            assignment_id,
            next_gateway_sequence: 1,
            last_envelope_id: [0; 32],
            last_gateway_received_ms: 0,
            drained_through_sequence: None,
        }
    }

    pub fn classify(
        &self,
        envelope: &GatewayCaptureEnvelopeV1,
    ) -> Result<CaptureSequenceDecision, HandoffError> {
        if envelope.assignment_id != self.assignment_id {
            return Err(HandoffError::Linkage("cursor assignment"));
        }
        let envelope_id = envelope.object_id();
        if envelope.gateway_sequence == self.next_gateway_sequence {
            if self.drained_through_sequence.is_some() {
                return Err(HandoffError::CaptureAfterDrain);
            }
            if self.next_gateway_sequence > 1
                && envelope.gateway_received_ms < self.last_gateway_received_ms
            {
                return Err(HandoffError::ObservationTime);
            }
            return Ok(CaptureSequenceDecision::New);
        }
        if envelope.gateway_sequence.checked_add(1) == Some(self.next_gateway_sequence)
            && envelope_id == self.last_envelope_id
        {
            return Ok(CaptureSequenceDecision::ExactRetry);
        }
        Err(HandoffError::Sequence)
    }

    pub fn advance(&mut self, envelope: &GatewayCaptureEnvelopeV1) -> Result<(), HandoffError> {
        match self.classify(envelope)? {
            CaptureSequenceDecision::New => {
                self.next_gateway_sequence = self
                    .next_gateway_sequence
                    .checked_add(1)
                    .ok_or(HandoffError::Sequence)?;
                self.last_envelope_id = envelope.object_id();
                self.last_gateway_received_ms = envelope.gateway_received_ms;
                Ok(())
            }
            CaptureSequenceDecision::ExactRetry => Ok(()),
        }
    }

    pub fn apply_drain(&mut self, drain: &GatewayAssignmentDrainV1) -> Result<(), HandoffError> {
        if drain.assignment_id != self.assignment_id
            || drain.last_gateway_sequence.checked_add(1) != Some(self.next_gateway_sequence)
            || (drain.last_gateway_sequence == 0 && drain.final_capture_envelope_id != [0; 32])
            || (drain.last_gateway_sequence != 0
                && drain.final_capture_envelope_id != self.last_envelope_id)
        {
            return Err(HandoffError::DrainBoundary);
        }
        match self.drained_through_sequence {
            None => self.drained_through_sequence = Some(drain.last_gateway_sequence),
            Some(existing) if existing == drain.last_gateway_sequence => {}
            Some(_) => return Err(HandoffError::DrainBoundary),
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HandoffError {
    #[error("handoff object version, network, or identity mismatch")]
    Context,
    #[error("handoff object linkage mismatch: {0}")]
    Linkage(&'static str),
    #[error("handoff signature verification failed")]
    Signature,
    #[error("invalid or replayed handoff sequence")]
    Sequence,
    #[error("gateway observation time exceeds its signed policy")]
    ObservationTime,
    #[error("invalid capture disposition")]
    Disposition,
    #[error("capture arrived after the assignment drain boundary")]
    CaptureAfterDrain,
    #[error("invalid assignment drain boundary")]
    DrainBoundary,
    #[error("durable handoff state failed: {0}")]
    Durable(#[from] DurableInvariantError),
    #[error("durable handoff cursor is malformed")]
    Cursor,
}

fn version_context(
    core_protocol_version: u16,
    handoff_version: u16,
    network_id: u8,
    expected_network_id: u8,
    gateway_pubkey: [u8; 32],
    core_handoff_pubkey: [u8; 32],
) -> Result<(), HandoffError> {
    if core_protocol_version != CORE_V2
        || handoff_version != GATEWAY_HANDOFF_V1
        || network_id != expected_network_id
        || gateway_pubkey == [0; 32]
        || core_handoff_pubkey == [0; 32]
        || gateway_pubkey == core_handoff_pubkey
    {
        return Err(HandoffError::Context);
    }
    Ok(())
}

pub fn validate_gateway_assignment(
    manifest: &GatewayContextManifestV1,
    assignment: &GatewayAssignmentV1,
) -> Result<(), HandoffError> {
    version_context(
        assignment.core_protocol_version,
        assignment.handoff_version,
        assignment.network_id,
        manifest.network_id,
        assignment.gateway_pubkey,
        assignment.core_handoff_pubkey,
    )?;
    if assignment.assignment_sequence == 0
        || manifest.operator_pubkey != assignment.operator_pubkey
        || manifest.gateway_pubkey != assignment.gateway_pubkey
        || manifest.core_handoff_pubkey != assignment.core_handoff_pubkey
        || assignment.nonce_stride == 0
        || assignment.nonce_start > assignment.nonce_end
        || assignment.extra_nonce2_start_be > assignment.extra_nonce2_end_be
        || !matches!(
            assignment.observation_policy,
            GATEWAY_OBSERVATION_CORE_RECEIPT_TIME | GATEWAY_OBSERVATION_DELEGATED_SIGNED_TIME_V1
        )
        || assignment.maximum_clock_skew_ms > MAX_GATEWAY_CLOCK_SKEW_MS
        || (assignment.observation_policy == GATEWAY_OBSERVATION_CORE_RECEIPT_TIME
            && assignment.maximum_clock_skew_ms != 0)
    {
        return Err(HandoffError::Context);
    }
    verify_object(
        &assignment.operator_pubkey,
        ED25519_SUITE,
        &assignment.operator_signature,
        assignment.network_id,
        assignment,
    )
    .map_err(|_| HandoffError::Signature)
}

pub fn validate_context_manifest(
    manifest: &GatewayContextManifestV1,
    now_ms: u64,
) -> Result<(), HandoffError> {
    version_context(
        manifest.core_protocol_version,
        manifest.handoff_version,
        manifest.network_id,
        manifest.network_id,
        manifest.gateway_pubkey,
        manifest.core_handoff_pubkey,
    )?;
    if manifest.context_sequence == 0
        || manifest.valid_from_ms > now_ms
        || now_ms > manifest.valid_until_ms
        || manifest.maximum_frame_bytes == 0
        || manifest.maximum_frame_bytes > MAX_HANDOFF_FRAME_BYTES
        || manifest.maximum_in_flight == 0
        || manifest.maximum_in_flight > MAX_HANDOFF_IN_FLIGHT
    {
        return Err(HandoffError::Context);
    }
    verify_object(
        &manifest.operator_pubkey,
        ED25519_SUITE,
        &manifest.operator_signature,
        manifest.network_id,
        manifest,
    )
    .map_err(|_| HandoffError::Signature)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SequenceHeadV1 {
    network_id: u8,
    sequence: u64,
    object_id: Hash256,
}

fn identity_key(network_id: u8, gateway_pubkey: [u8; 32]) -> String {
    format!("{network_id:02x}-{}", hex::encode(gateway_pubkey))
}

fn encode_sequence_head(magic: [u8; 4], head: SequenceHeadV1) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.fixed(&magic);
    encoder.u8(head.network_id);
    encoder.u64(head.sequence);
    encoder.fixed(&head.object_id);
    encoder.into_bytes()
}

fn decode_sequence_head(
    expected_magic: [u8; 4],
    expected_network_id: u8,
    bytes: &[u8],
) -> Result<SequenceHeadV1, HandoffError> {
    let mut decoder = Decoder::new(
        bytes,
        DecodeLimits {
            max_object_bytes: 64,
            max_vector_items: 0,
        },
    )
    .map_err(|_| HandoffError::Cursor)?;
    if decoder.array::<4>().map_err(|_| HandoffError::Cursor)? != expected_magic {
        return Err(HandoffError::Cursor);
    }
    let head = SequenceHeadV1 {
        network_id: decoder.u8().map_err(|_| HandoffError::Cursor)?,
        sequence: decoder.u64().map_err(|_| HandoffError::Cursor)?,
        object_id: decoder.array().map_err(|_| HandoffError::Cursor)?,
    };
    decoder.finish().map_err(|_| HandoffError::Cursor)?;
    if head.network_id != expected_network_id || head.sequence == 0 || head.object_id == [0; 32] {
        return Err(HandoffError::Cursor);
    }
    Ok(head)
}

fn assignment_state_value(network_id: u8, assignment_id: Hash256, status: u8) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.fixed(b"MMAS");
    encoder.u8(network_id);
    encoder.fixed(&assignment_id);
    encoder.u8(status);
    encoder.into_bytes()
}

fn exact_journal_object<T>(
    store: &dyn DurableStore,
    kind: ProtocolRecordKind,
    object_id: Hash256,
    expected: &T,
) -> Result<(), HandoffError>
where
    T: CanonicalEncode,
{
    if ProtocolJournal::new(store)
        .load(kind, &object_id)?
        .as_deref()
        != Some(expected.to_canonical_bytes().as_slice())
    {
        return Err(HandoffError::Linkage("durable handoff authorization"));
    }
    Ok(())
}

/// Install an operator-signed gateway/Core identity context before any mining
/// assignment may be authorized. Per-gateway sequence and predecessor checks
/// prevent context rollback.
pub fn persist_gateway_context_manifest(
    store: &dyn DurableStore,
    manifest: &GatewayContextManifestV1,
    now_ms: u64,
) -> Result<JournalBatchOutcome, HandoffError> {
    validate_context_manifest(manifest, now_ms)?;
    let key = identity_key(manifest.network_id, manifest.gateway_pubkey);
    let existing = store
        .get(GATEWAY_CONTEXT_HEAD_NAMESPACE, &key)
        .map_err(DurableInvariantError::from)?;
    let manifest_id = manifest.object_id();
    match existing.as_deref() {
        None if manifest.context_sequence != 1 || manifest.previous_manifest_id != [0; 32] => {
            return Err(HandoffError::Sequence);
        }
        None => {}
        Some(bytes) => {
            let current = decode_sequence_head(*b"MMCX", manifest.network_id, bytes)?;
            if current.object_id == manifest_id {
                if current.sequence != manifest.context_sequence {
                    return Err(HandoffError::Sequence);
                }
            } else if manifest.context_sequence
                != current
                    .sequence
                    .checked_add(1)
                    .ok_or(HandoffError::Sequence)?
                || manifest.previous_manifest_id != current.object_id
            {
                return Err(HandoffError::Sequence);
            }
        }
    }
    ProtocolJournal::new(store)
        .persist_records_with_conditions_and_batch(
            &[JournalBatchRecord::new(
                ProtocolRecordKind::GatewayContextManifest,
                manifest_id.to_vec(),
                manifest.to_canonical_bytes(),
            )],
            &[BatchCondition::new(
                GATEWAY_CONTEXT_HEAD_NAMESPACE,
                &key,
                existing,
            )],
            &[BatchOperation::put(
                GATEWAY_CONTEXT_HEAD_NAMESPACE,
                key,
                encode_sequence_head(
                    *b"MMCX",
                    SequenceHeadV1 {
                        network_id: manifest.network_id,
                        sequence: manifest.context_sequence,
                        object_id: manifest_id,
                    },
                ),
            )],
        )
        .map_err(HandoffError::from)
}

fn current_manifest_head_bytes(
    store: &dyn DurableStore,
    manifest: &GatewayContextManifestV1,
) -> Result<(String, Vec<u8>), HandoffError> {
    let key = identity_key(manifest.network_id, manifest.gateway_pubkey);
    let bytes = store
        .get(GATEWAY_CONTEXT_HEAD_NAMESPACE, &key)
        .map_err(DurableInvariantError::from)?
        .ok_or(HandoffError::Linkage("context manifest head"))?;
    let head = decode_sequence_head(*b"MMCX", manifest.network_id, &bytes)?;
    if head.sequence != manifest.context_sequence || head.object_id != manifest.object_id() {
        return Err(HandoffError::Sequence);
    }
    exact_journal_object(
        store,
        ProtocolRecordKind::GatewayContextManifest,
        manifest.object_id(),
        manifest,
    )?;
    Ok((key, bytes))
}

fn current_assignment_head_bytes(
    store: &dyn DurableStore,
    assignment: &GatewayAssignmentV1,
) -> Result<(String, Vec<u8>), HandoffError> {
    let key = identity_key(assignment.network_id, assignment.gateway_pubkey);
    let bytes = store
        .get(GATEWAY_ASSIGNMENT_HEAD_NAMESPACE, &key)
        .map_err(DurableInvariantError::from)?
        .ok_or(HandoffError::Linkage("gateway assignment head"))?;
    let head = decode_sequence_head(*b"MMAH", assignment.network_id, &bytes)?;
    if head.sequence != assignment.assignment_sequence || head.object_id != assignment.object_id() {
        return Err(HandoffError::Sequence);
    }
    Ok((key, bytes))
}

/// Install the first assignment for a gateway identity. Every replacement must
/// use `persist_gateway_assignment_transition`, which requires the previous
/// assignment's durable drain.
pub fn persist_gateway_assignment_authorization(
    store: &dyn DurableStore,
    manifest: &GatewayContextManifestV1,
    assignment: &GatewayAssignmentV1,
) -> Result<JournalBatchOutcome, HandoffError> {
    validate_gateway_assignment(manifest, assignment)?;
    let (context_key, context_head) = current_manifest_head_bytes(store, manifest)?;
    let head_key = identity_key(assignment.network_id, assignment.gateway_pubkey);
    let existing_head = store
        .get(GATEWAY_ASSIGNMENT_HEAD_NAMESPACE, &head_key)
        .map_err(DurableInvariantError::from)?;
    let assignment_id = assignment.object_id();
    match existing_head.as_deref() {
        None if assignment.assignment_sequence != 1 => return Err(HandoffError::Sequence),
        None => {}
        Some(bytes) => {
            let current = decode_sequence_head(*b"MMAH", assignment.network_id, bytes)?;
            if current.object_id != assignment_id
                || current.sequence != assignment.assignment_sequence
            {
                return Err(HandoffError::Sequence);
            }
        }
    }
    let state_key = hex::encode(assignment_id);
    let active = assignment_state_value(
        assignment.network_id,
        assignment_id,
        ASSIGNMENT_STATE_ACTIVE,
    );
    let existing_state = store
        .get(GATEWAY_ASSIGNMENT_STATE_NAMESPACE, &state_key)
        .map_err(DurableInvariantError::from)?;
    if existing_state
        .as_ref()
        .is_some_and(|value| value != &active)
    {
        return Err(HandoffError::CaptureAfterDrain);
    }
    ProtocolJournal::new(store)
        .persist_records_with_conditions_and_batch(
            &[JournalBatchRecord::new(
                ProtocolRecordKind::GatewayAssignment,
                assignment_id.to_vec(),
                assignment.to_canonical_bytes(),
            )],
            &[
                BatchCondition::equals(GATEWAY_CONTEXT_HEAD_NAMESPACE, context_key, context_head),
                BatchCondition::new(GATEWAY_ASSIGNMENT_HEAD_NAMESPACE, &head_key, existing_head),
                BatchCondition::new(
                    GATEWAY_ASSIGNMENT_STATE_NAMESPACE,
                    &state_key,
                    existing_state,
                ),
            ],
            &[
                BatchOperation::put(
                    GATEWAY_ASSIGNMENT_HEAD_NAMESPACE,
                    head_key,
                    encode_sequence_head(
                        *b"MMAH",
                        SequenceHeadV1 {
                            network_id: assignment.network_id,
                            sequence: assignment.assignment_sequence,
                            object_id: assignment_id,
                        },
                    ),
                ),
                BatchOperation::put(GATEWAY_ASSIGNMENT_STATE_NAMESPACE, state_key, active),
            ],
        )
        .map_err(HandoffError::from)
}

/// Validate gateway evidence and select the only observation time that may be
/// passed to Core share validation.
pub fn validate_capture_envelope(
    manifest: &GatewayContextManifestV1,
    assignment: &GatewayAssignmentV1,
    envelope: &GatewayCaptureEnvelopeV1,
    core_received_ms: u64,
) -> Result<u64, HandoffError> {
    validate_gateway_assignment(manifest, assignment)?;
    version_context(
        envelope.core_protocol_version,
        envelope.handoff_version,
        envelope.network_id,
        assignment.network_id,
        envelope.gateway_pubkey,
        envelope.core_handoff_pubkey,
    )?;
    if manifest.object_id() != envelope.context_manifest_id
        || manifest.network_id != envelope.network_id
        || manifest.operator_pubkey != assignment.operator_pubkey
        || manifest.gateway_pubkey != envelope.gateway_pubkey
        || manifest.core_handoff_pubkey != envelope.core_handoff_pubkey
        || assignment.gateway_pubkey != envelope.gateway_pubkey
        || assignment.core_handoff_pubkey != envelope.core_handoff_pubkey
        || assignment.object_id() != envelope.assignment_id
        || assignment.session_id != envelope.session_id
        || assignment.ntime != envelope.ntime
        || !assignment.accepts_extra_nonce(&envelope.extra_nonce)
        || envelope.nonce < assignment.nonce_start
        || envelope.nonce > assignment.nonce_end
        || (envelope.nonce - assignment.nonce_start).checked_rem(assignment.nonce_stride) != Some(0)
    {
        return Err(HandoffError::Linkage("capture envelope"));
    }
    if envelope.gateway_sequence == 0 {
        return Err(HandoffError::Sequence);
    }
    verify_object(
        &envelope.gateway_pubkey,
        ED25519_SUITE,
        &envelope.gateway_signature,
        envelope.network_id,
        envelope,
    )
    .map_err(|_| HandoffError::Signature)?;

    match assignment.observation_policy {
        GATEWAY_OBSERVATION_CORE_RECEIPT_TIME if assignment.maximum_clock_skew_ms == 0 => {
            Ok(core_received_ms)
        }
        GATEWAY_OBSERVATION_DELEGATED_SIGNED_TIME_V1
            if assignment.maximum_clock_skew_ms > 0
                && assignment.maximum_clock_skew_ms <= MAX_GATEWAY_CLOCK_SKEW_MS
                && envelope.gateway_received_ms.abs_diff(core_received_ms)
                    <= assignment.maximum_clock_skew_ms =>
        {
            Ok(envelope.gateway_received_ms)
        }
        _ => Err(HandoffError::ObservationTime),
    }
}

pub fn validate_capture_receipt(
    envelope: &GatewayCaptureEnvelopeV1,
    receipt: &GatewayCaptureReceiptV1,
) -> Result<(), HandoffError> {
    version_context(
        receipt.core_protocol_version,
        receipt.handoff_version,
        receipt.network_id,
        envelope.network_id,
        receipt.gateway_pubkey,
        receipt.core_handoff_pubkey,
    )?;
    if receipt.context_manifest_id != envelope.context_manifest_id
        || receipt.assignment_id != envelope.assignment_id
        || receipt.capture_envelope_id != envelope.object_id()
        || receipt.gateway_pubkey != envelope.gateway_pubkey
        || receipt.core_handoff_pubkey != envelope.core_handoff_pubkey
        || receipt.receipt_sequence == 0
        || receipt.receipt_sequence != envelope.gateway_sequence
    {
        return Err(HandoffError::Linkage("capture receipt"));
    }
    let accepted = receipt.outcome == CAPTURE_OUTCOME_ACCEPTED;
    if !matches!(
        receipt.outcome,
        CAPTURE_OUTCOME_ACCEPTED
            | CAPTURE_OUTCOME_REJECTED
            | CAPTURE_OUTCOME_GRACE_NONCREDIT
            | CAPTURE_OUTCOME_DUPLICATE
    ) || accepted == (receipt.accepted_share_id == [0; 32])
    {
        return Err(HandoffError::Disposition);
    }
    verify_object(
        &receipt.core_handoff_pubkey,
        ED25519_SUITE,
        &receipt.core_signature,
        receipt.network_id,
        receipt,
    )
    .map_err(|_| HandoffError::Signature)
}

/// Complete immutable evidence plus the exact cursor compare-and-swap needed
/// for one capture disposition. Accepted captures must append their
/// `AcceptedWorkKey` and `AcceptedShare` records before committing this batch;
/// noncredit dispositions may commit it directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedCaptureDisposition {
    pub records: Vec<JournalBatchRecord>,
    pub conditions: Vec<BatchCondition>,
    pub operations: Vec<BatchOperation>,
    pub sequence_decision: CaptureSequenceDecision,
}

pub fn prepare_capture_disposition(
    store: &dyn DurableStore,
    manifest: &GatewayContextManifestV1,
    assignment: &GatewayAssignmentV1,
    envelope: &GatewayCaptureEnvelopeV1,
    receipt: &GatewayCaptureReceiptV1,
) -> Result<PreparedCaptureDisposition, HandoffError> {
    validate_context_manifest(manifest, receipt.core_received_ms)?;
    validate_capture_envelope(manifest, assignment, envelope, receipt.core_received_ms)?;
    validate_capture_receipt(envelope, receipt)?;

    exact_journal_object(
        store,
        ProtocolRecordKind::GatewayContextManifest,
        manifest.object_id(),
        manifest,
    )?;
    exact_journal_object(
        store,
        ProtocolRecordKind::GatewayAssignment,
        assignment.object_id(),
        assignment,
    )?;
    let records = vec![
        JournalBatchRecord::new(
            ProtocolRecordKind::GatewayContextManifest,
            manifest.object_id().to_vec(),
            manifest.to_canonical_bytes(),
        ),
        JournalBatchRecord::new(
            ProtocolRecordKind::GatewayAssignment,
            assignment.object_id().to_vec(),
            assignment.to_canonical_bytes(),
        ),
        JournalBatchRecord::new(
            ProtocolRecordKind::GatewayCaptureEnvelope,
            envelope.object_id().to_vec(),
            envelope.to_canonical_bytes(),
        ),
        // Keying the receipt by envelope ID makes a second disposition for
        // the same capture an immutable conflict even if its object ID is
        // otherwise distinct.
        JournalBatchRecord::new(
            ProtocolRecordKind::GatewayCaptureReceipt,
            envelope.object_id().to_vec(),
            receipt.to_canonical_bytes(),
        ),
    ];
    let journal = ProtocolJournal::new(store);
    let existing_envelope = journal.load(
        ProtocolRecordKind::GatewayCaptureEnvelope,
        &envelope.object_id(),
    )?;
    let existing_receipt = journal.load(
        ProtocolRecordKind::GatewayCaptureReceipt,
        &envelope.object_id(),
    )?;
    if existing_envelope.as_deref() == Some(envelope.to_canonical_bytes().as_slice())
        && existing_receipt.as_deref() == Some(receipt.to_canonical_bytes().as_slice())
    {
        return Ok(PreparedCaptureDisposition {
            records,
            conditions: vec![],
            operations: vec![],
            sequence_decision: CaptureSequenceDecision::ExactRetry,
        });
    }
    if existing_envelope.is_some() || existing_receipt.is_some() {
        return Err(DurableInvariantError::ImmutableConflict.into());
    }

    let (context_head_key, context_head) = current_manifest_head_bytes(store, manifest)?;
    let (assignment_head_key, assignment_head) = current_assignment_head_bytes(store, assignment)?;

    let assignment_state_key = hex::encode(assignment.object_id());
    let active_state = assignment_state_value(
        assignment.network_id,
        assignment.object_id(),
        ASSIGNMENT_STATE_ACTIVE,
    );
    if store
        .get(GATEWAY_ASSIGNMENT_STATE_NAMESPACE, &assignment_state_key)
        .map_err(DurableInvariantError::from)?
        .as_deref()
        != Some(active_state.as_slice())
    {
        return Err(HandoffError::CaptureAfterDrain);
    }

    let cursor_key = hex::encode(assignment.object_id());
    let existing_cursor = store
        .get(GATEWAY_CAPTURE_CURSOR_NAMESPACE, &cursor_key)
        .map_err(DurableInvariantError::from)?;
    let mut cursor = match existing_cursor.as_deref() {
        None => GatewayCaptureCursorV1::new(assignment.object_id()),
        Some(bytes) => GatewayCaptureCursorV1::from_canonical_bytes(
            bytes,
            DecodeLimits {
                max_object_bytes: 128,
                max_vector_items: 0,
            },
        )
        .map_err(|_| HandoffError::Cursor)?,
    };
    if cursor.assignment_id != assignment.object_id()
        || cursor.next_gateway_sequence == 0
        || (cursor.next_gateway_sequence == 1
            && (cursor.last_envelope_id != [0; 32] || cursor.last_gateway_received_ms != 0))
        || (cursor.next_gateway_sequence > 1 && cursor.last_envelope_id == [0; 32])
        || cursor
            .drained_through_sequence
            .is_some_and(|sequence| sequence.checked_add(1) != Some(cursor.next_gateway_sequence))
    {
        return Err(HandoffError::Cursor);
    }
    let sequence_decision = cursor.classify(envelope)?;
    cursor.advance(envelope)?;

    Ok(PreparedCaptureDisposition {
        records,
        conditions: vec![
            BatchCondition::equals(
                GATEWAY_CONTEXT_HEAD_NAMESPACE,
                context_head_key,
                context_head,
            ),
            BatchCondition::equals(
                GATEWAY_ASSIGNMENT_HEAD_NAMESPACE,
                assignment_head_key,
                assignment_head,
            ),
            BatchCondition::equals(
                GATEWAY_ASSIGNMENT_STATE_NAMESPACE,
                assignment_state_key,
                active_state,
            ),
            BatchCondition::new(
                GATEWAY_CAPTURE_CURSOR_NAMESPACE,
                cursor_key.clone(),
                existing_cursor,
            ),
        ],
        operations: vec![BatchOperation::put(
            GATEWAY_CAPTURE_CURSOR_NAMESPACE,
            cursor_key,
            cursor.to_canonical_bytes(),
        )],
        sequence_decision,
    })
}

/// Persist a rejected, grace-noncredit, or duplicate capture. Accepted
/// captures are refused here because their share/work evidence must be added
/// to the very same transaction by the Core share admission path.
pub fn persist_noncredit_capture_disposition(
    store: &dyn DurableStore,
    manifest: &GatewayContextManifestV1,
    assignment: &GatewayAssignmentV1,
    envelope: &GatewayCaptureEnvelopeV1,
    receipt: &GatewayCaptureReceiptV1,
) -> Result<JournalBatchOutcome, HandoffError> {
    if receipt.outcome == CAPTURE_OUTCOME_ACCEPTED {
        return Err(HandoffError::Disposition);
    }
    let prepared = prepare_capture_disposition(store, manifest, assignment, envelope, receipt)?;
    ProtocolJournal::new(store)
        .persist_records_with_conditions_and_batch(
            &prepared.records,
            &prepared.conditions,
            &prepared.operations,
        )
        .map_err(HandoffError::from)
}

pub fn validate_transition(
    manifest: &GatewayContextManifestV1,
    transition: &GatewayAssignmentTransitionV1,
) -> Result<(), HandoffError> {
    validate_context_manifest(manifest, transition.transition_ms)?;
    version_context(
        transition.core_protocol_version,
        transition.handoff_version,
        transition.network_id,
        manifest.network_id,
        transition.gateway_pubkey,
        transition.core_handoff_pubkey,
    )?;
    if transition.context_manifest_id != manifest.object_id()
        || transition.gateway_pubkey != manifest.gateway_pubkey
        || transition.core_handoff_pubkey != manifest.core_handoff_pubkey
        || transition.transition_sequence == 0
        || transition.previous_assignment_id == [0; 32]
        || transition.next_assignment_id == [0; 32]
        || transition.previous_assignment_id == transition.next_assignment_id
    {
        return Err(HandoffError::Linkage("assignment transition"));
    }
    verify_object(
        &transition.gateway_pubkey,
        ED25519_SUITE,
        &transition.gateway_signature,
        transition.network_id,
        transition,
    )
    .map_err(|_| HandoffError::Signature)
}

pub fn validate_gateway_drain(
    manifest: &GatewayContextManifestV1,
    drain: &GatewayAssignmentDrainV1,
) -> Result<(), HandoffError> {
    validate_context_manifest(manifest, drain.drained_ms)?;
    version_context(
        drain.core_protocol_version,
        drain.handoff_version,
        drain.network_id,
        manifest.network_id,
        drain.gateway_pubkey,
        drain.core_handoff_pubkey,
    )?;
    if drain.context_manifest_id != manifest.object_id()
        || drain.gateway_pubkey != manifest.gateway_pubkey
        || drain.core_handoff_pubkey != manifest.core_handoff_pubkey
        || drain.assignment_id == [0; 32]
        || (drain.last_gateway_sequence == 0 && drain.final_capture_envelope_id != [0; 32])
        || (drain.last_gateway_sequence != 0 && drain.final_capture_envelope_id == [0; 32])
    {
        return Err(HandoffError::DrainBoundary);
    }
    verify_object(
        &drain.gateway_pubkey,
        ED25519_SUITE,
        &drain.gateway_signature,
        drain.network_id,
        drain,
    )
    .map_err(|_| HandoffError::Signature)
}

pub fn validate_core_drain_receipt(
    manifest: &GatewayContextManifestV1,
    drain: &GatewayAssignmentDrainV1,
    receipt: &CoreAssignmentDrainReceiptV1,
) -> Result<(), HandoffError> {
    validate_gateway_drain(manifest, drain)?;
    version_context(
        receipt.core_protocol_version,
        receipt.handoff_version,
        receipt.network_id,
        drain.network_id,
        receipt.gateway_pubkey,
        receipt.core_handoff_pubkey,
    )?;
    if receipt.context_manifest_id != drain.context_manifest_id
        || receipt.assignment_id != drain.assignment_id
        || receipt.gateway_drain_id != drain.object_id()
        || receipt.gateway_pubkey != drain.gateway_pubkey
        || receipt.core_handoff_pubkey != drain.core_handoff_pubkey
        || receipt.receipt_sequence == 0
        || receipt.accepted_through_gateway_sequence != drain.last_gateway_sequence
        || !matches!(
            receipt.outcome,
            DRAIN_OUTCOME_COMPLETE | DRAIN_OUTCOME_REJECTED
        )
    {
        return Err(HandoffError::DrainBoundary);
    }
    verify_object(
        &receipt.core_handoff_pubkey,
        ED25519_SUITE,
        &receipt.core_signature,
        receipt.network_id,
        receipt,
    )
    .map_err(|_| HandoffError::Signature)
}

fn load_gateway_assignment(
    store: &dyn DurableStore,
    assignment_id: Hash256,
) -> Result<GatewayAssignmentV1, HandoffError> {
    let payload = ProtocolJournal::new(store)
        .load(ProtocolRecordKind::GatewayAssignment, &assignment_id)?
        .ok_or(HandoffError::Linkage("durable gateway assignment"))?;
    let assignment = GatewayAssignmentV1::from_canonical_bytes(
        &payload,
        DecodeLimits {
            max_object_bytes: 4096,
            max_vector_items: 0,
        },
    )
    .map_err(|_| HandoffError::Linkage("durable gateway assignment"))?;
    if assignment.object_id() != assignment_id || assignment.to_canonical_bytes() != payload {
        return Err(HandoffError::Linkage("durable gateway assignment"));
    }
    Ok(assignment)
}

/// Seal an assignment and its capture cursor atomically. New capture admission
/// conditions the same active-state bytes, so exactly one side of a
/// capture-versus-drain race can commit.
pub fn persist_gateway_assignment_drain(
    store: &dyn DurableStore,
    manifest: &GatewayContextManifestV1,
    drain: &GatewayAssignmentDrainV1,
) -> Result<JournalBatchOutcome, HandoffError> {
    validate_gateway_drain(manifest, drain)?;
    exact_journal_object(
        store,
        ProtocolRecordKind::GatewayContextManifest,
        manifest.object_id(),
        manifest,
    )?;
    let assignment = load_gateway_assignment(store, drain.assignment_id)?;
    validate_gateway_assignment(manifest, &assignment)?;

    let state_key = hex::encode(drain.assignment_id);
    let active = assignment_state_value(
        drain.network_id,
        drain.assignment_id,
        ASSIGNMENT_STATE_ACTIVE,
    );
    let drained = assignment_state_value(
        drain.network_id,
        drain.assignment_id,
        ASSIGNMENT_STATE_DRAINED,
    );
    let existing_state = store
        .get(GATEWAY_ASSIGNMENT_STATE_NAMESPACE, &state_key)
        .map_err(DurableInvariantError::from)?;
    let cursor_key = state_key.clone();
    let existing_cursor = store
        .get(GATEWAY_CAPTURE_CURSOR_NAMESPACE, &cursor_key)
        .map_err(DurableInvariantError::from)?;
    let mut cursor = match existing_cursor.as_deref() {
        None => GatewayCaptureCursorV1::new(drain.assignment_id),
        Some(bytes) => GatewayCaptureCursorV1::from_canonical_bytes(
            bytes,
            DecodeLimits {
                max_object_bytes: 128,
                max_vector_items: 0,
            },
        )
        .map_err(|_| HandoffError::Cursor)?,
    };
    cursor.apply_drain(drain)?;
    let record = JournalBatchRecord::new(
        ProtocolRecordKind::GatewayAssignmentDrain,
        drain.assignment_id.to_vec(),
        drain.to_canonical_bytes(),
    );
    if existing_state.as_deref() == Some(drained.as_slice()) {
        if ProtocolJournal::new(store)
            .load(
                ProtocolRecordKind::GatewayAssignmentDrain,
                &drain.assignment_id,
            )?
            .as_deref()
            != Some(drain.to_canonical_bytes().as_slice())
        {
            return Err(DurableInvariantError::ImmutableConflict.into());
        }
        return Ok(JournalBatchOutcome::ExactRecord);
    }
    let (context_head_key, context_head) = current_manifest_head_bytes(store, manifest)?;
    let (assignment_head_key, assignment_head) = current_assignment_head_bytes(store, &assignment)?;
    if existing_state.as_deref() != Some(active.as_slice()) {
        return Err(HandoffError::Linkage("active gateway assignment"));
    }
    ProtocolJournal::new(store)
        .persist_records_with_conditions_and_batch(
            &[record],
            &[
                BatchCondition::equals(
                    GATEWAY_CONTEXT_HEAD_NAMESPACE,
                    context_head_key,
                    context_head,
                ),
                BatchCondition::equals(
                    GATEWAY_ASSIGNMENT_HEAD_NAMESPACE,
                    assignment_head_key,
                    assignment_head,
                ),
                BatchCondition::equals(GATEWAY_ASSIGNMENT_STATE_NAMESPACE, &state_key, active),
                BatchCondition::new(
                    GATEWAY_CAPTURE_CURSOR_NAMESPACE,
                    &cursor_key,
                    existing_cursor,
                ),
            ],
            &[
                BatchOperation::put(
                    GATEWAY_CAPTURE_CURSOR_NAMESPACE,
                    cursor_key,
                    cursor.to_canonical_bytes(),
                ),
                BatchOperation::put(GATEWAY_ASSIGNMENT_STATE_NAMESPACE, state_key, drained),
            ],
        )
        .map_err(HandoffError::from)
}

/// Install the next assignment only through a signed transition from the exact
/// current, durably drained predecessor.
pub fn persist_gateway_assignment_transition(
    store: &dyn DurableStore,
    manifest: &GatewayContextManifestV1,
    next_assignment: &GatewayAssignmentV1,
    transition: &GatewayAssignmentTransitionV1,
) -> Result<JournalBatchOutcome, HandoffError> {
    validate_transition(manifest, transition)?;
    validate_gateway_assignment(manifest, next_assignment)?;
    let previous = load_gateway_assignment(store, transition.previous_assignment_id)?;
    validate_gateway_assignment(manifest, &previous)?;
    if transition.next_assignment_id != next_assignment.object_id()
        || transition.transition_sequence != next_assignment.assignment_sequence
        || previous.assignment_sequence.checked_add(1) != Some(next_assignment.assignment_sequence)
        || previous.gateway_pubkey != next_assignment.gateway_pubkey
        || previous.core_handoff_pubkey != next_assignment.core_handoff_pubkey
        || previous.operator_pubkey != next_assignment.operator_pubkey
    {
        return Err(HandoffError::Sequence);
    }
    let (context_key, context_head) = current_manifest_head_bytes(store, manifest)?;
    let head_key = identity_key(next_assignment.network_id, next_assignment.gateway_pubkey);
    let existing_head = store
        .get(GATEWAY_ASSIGNMENT_HEAD_NAMESPACE, &head_key)
        .map_err(DurableInvariantError::from)?
        .ok_or(HandoffError::Sequence)?;
    let current = decode_sequence_head(*b"MMAH", next_assignment.network_id, &existing_head)?;
    let next_id = next_assignment.object_id();
    if current.object_id == next_id && current.sequence == next_assignment.assignment_sequence {
        exact_journal_object(
            store,
            ProtocolRecordKind::GatewayAssignmentTransition,
            transition.previous_assignment_id,
            transition,
        )?;
        return Ok(JournalBatchOutcome::ExactRecord);
    }
    if current.object_id != previous.object_id() || current.sequence != previous.assignment_sequence
    {
        return Err(HandoffError::Sequence);
    }
    let previous_state_key = hex::encode(previous.object_id());
    let previous_drained = assignment_state_value(
        previous.network_id,
        previous.object_id(),
        ASSIGNMENT_STATE_DRAINED,
    );
    if store
        .get(GATEWAY_ASSIGNMENT_STATE_NAMESPACE, &previous_state_key)
        .map_err(DurableInvariantError::from)?
        .as_deref()
        != Some(previous_drained.as_slice())
    {
        return Err(HandoffError::DrainBoundary);
    }
    let previous_cursor = store
        .get(GATEWAY_CAPTURE_CURSOR_NAMESPACE, &previous_state_key)
        .map_err(DurableInvariantError::from)?
        .ok_or(HandoffError::DrainBoundary)?;
    let cursor = GatewayCaptureCursorV1::from_canonical_bytes(
        &previous_cursor,
        DecodeLimits {
            max_object_bytes: 128,
            max_vector_items: 0,
        },
    )
    .map_err(|_| HandoffError::Cursor)?;
    if cursor.drained_through_sequence != Some(transition.previous_assignment_last_gateway_sequence)
    {
        return Err(HandoffError::DrainBoundary);
    }
    let next_state_key = hex::encode(next_id);
    let existing_next_state = store
        .get(GATEWAY_ASSIGNMENT_STATE_NAMESPACE, &next_state_key)
        .map_err(DurableInvariantError::from)?;
    if existing_next_state.is_some() {
        return Err(HandoffError::Sequence);
    }
    ProtocolJournal::new(store)
        .persist_records_with_conditions_and_batch(
            &[
                JournalBatchRecord::new(
                    ProtocolRecordKind::GatewayAssignment,
                    next_id.to_vec(),
                    next_assignment.to_canonical_bytes(),
                ),
                JournalBatchRecord::new(
                    ProtocolRecordKind::GatewayAssignmentTransition,
                    transition.previous_assignment_id.to_vec(),
                    transition.to_canonical_bytes(),
                ),
            ],
            &[
                BatchCondition::equals(GATEWAY_CONTEXT_HEAD_NAMESPACE, context_key, context_head),
                BatchCondition::equals(GATEWAY_ASSIGNMENT_HEAD_NAMESPACE, &head_key, existing_head),
                BatchCondition::equals(
                    GATEWAY_ASSIGNMENT_STATE_NAMESPACE,
                    previous_state_key,
                    previous_drained,
                ),
                BatchCondition::new(
                    GATEWAY_ASSIGNMENT_STATE_NAMESPACE,
                    &next_state_key,
                    existing_next_state,
                ),
            ],
            &[
                BatchOperation::put(
                    GATEWAY_ASSIGNMENT_HEAD_NAMESPACE,
                    head_key,
                    encode_sequence_head(
                        *b"MMAH",
                        SequenceHeadV1 {
                            network_id: next_assignment.network_id,
                            sequence: next_assignment.assignment_sequence,
                            object_id: next_id,
                        },
                    ),
                ),
                BatchOperation::put(
                    GATEWAY_ASSIGNMENT_STATE_NAMESPACE,
                    next_state_key,
                    assignment_state_value(
                        next_assignment.network_id,
                        next_id,
                        ASSIGNMENT_STATE_ACTIVE,
                    ),
                ),
            ],
        )
        .map_err(HandoffError::from)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use meshmine_codec::{CanonicalDecode, CanonicalEncode, DecodeLimits};
    use meshmine_crypto::sign_object;
    use meshmine_storage::{MemoryStore, ProtocolJournal, ProtocolRecordKind};
    use meshmine_types::{GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16, U256};

    use super::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn hash(byte: u8) -> Hash256 {
        [byte; 32]
    }

    fn manifest(
        operator: &SigningKey,
        gateway: &SigningKey,
        core: &SigningKey,
    ) -> GatewayContextManifestV1 {
        let mut value = GatewayContextManifestV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: 2,
            context_sequence: 1,
            previous_manifest_id: [0; 32],
            operator_pubkey: operator.verifying_key().to_bytes(),
            gateway_pubkey: gateway.verifying_key().to_bytes(),
            core_handoff_pubkey: core.verifying_key().to_bytes(),
            valid_from_ms: 10,
            valid_until_ms: 1_000,
            maximum_frame_bytes: 65_536,
            maximum_in_flight: 64,
            operator_signature: SignatureBytes::empty(),
        };
        value.operator_signature = sign_object(operator, 2, &value);
        value
    }

    fn assignment(
        operator: &SigningKey,
        gateway: &SigningKey,
        core: &SigningKey,
        policy: u16,
    ) -> GatewayAssignmentV1 {
        let mut value = GatewayAssignmentV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: 2,
            session_id: hash(1),
            body_package_id: hash(2),
            body_certificate_id: hash(3),
            operator_pubkey: operator.verifying_key().to_bytes(),
            gateway_pubkey: gateway.verifying_key().to_bytes(),
            core_handoff_pubkey: core.verifying_key().to_bytes(),
            worker_id_hash: hash(4),
            payout_bucket_id: hash(5),
            assignment_sequence: 1,
            ntime: 50,
            extra_nonce_profile: GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16,
            observation_policy: policy,
            maximum_clock_skew_ms: if policy == GATEWAY_OBSERVATION_CORE_RECEIPT_TIME {
                0
            } else {
                5
            },
            extra_nonce_prefix: [6; 4],
            extra_nonce2_start_be: [0, 0, 0, 1],
            extra_nonce2_end_be: [0, 0, 0, 9],
            nonce_start: 0,
            nonce_end: 100,
            nonce_stride: 2,
            edge_target: U256([0xff; 32]),
            capture_target: U256([0xfe; 32]),
            telemetry_level: 1,
            operator_signature: SignatureBytes::empty(),
        };
        value.operator_signature = sign_object(operator, 2, &value);
        value
    }

    fn envelope(
        manifest: &GatewayContextManifestV1,
        assignment: &GatewayAssignmentV1,
        gateway: &SigningKey,
        sequence: u64,
    ) -> GatewayCaptureEnvelopeV1 {
        let mut extra_nonce = [0; 24];
        extra_nonce[..4].copy_from_slice(&assignment.extra_nonce_prefix);
        extra_nonce[4..8].copy_from_slice(&[0, 0, 0, 2]);
        let mut value = GatewayCaptureEnvelopeV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: 2,
            context_manifest_id: manifest.object_id(),
            assignment_id: assignment.object_id(),
            session_id: assignment.session_id,
            gateway_pubkey: gateway.verifying_key().to_bytes(),
            core_handoff_pubkey: assignment.core_handoff_pubkey,
            gateway_sequence: sequence,
            gateway_connection_id: hash(7),
            gateway_received_ms: 100,
            ntime: assignment.ntime,
            extra_nonce,
            nonce: 4,
            raw_share_hash: hash(8),
            gateway_signature: SignatureBytes::empty(),
        };
        value.gateway_signature = sign_object(gateway, 2, &value);
        value
    }

    fn noncredit_receipt(
        envelope: &GatewayCaptureEnvelopeV1,
        core: &SigningKey,
    ) -> GatewayCaptureReceiptV1 {
        let mut value = GatewayCaptureReceiptV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: envelope.network_id,
            context_manifest_id: envelope.context_manifest_id,
            assignment_id: envelope.assignment_id,
            capture_envelope_id: envelope.object_id(),
            gateway_pubkey: envelope.gateway_pubkey,
            core_handoff_pubkey: envelope.core_handoff_pubkey,
            receipt_sequence: envelope.gateway_sequence,
            core_received_ms: envelope.gateway_received_ms + 1,
            outcome: CAPTURE_OUTCOME_REJECTED,
            reason_code: 1,
            accepted_share_id: [0; 32],
            core_signature: SignatureBytes::empty(),
        };
        value.core_signature = sign_object(core, value.network_id, &value);
        value
    }

    fn drain(
        manifest: &GatewayContextManifestV1,
        assignment: &GatewayAssignmentV1,
        gateway: &SigningKey,
        sequence: u64,
        final_envelope_id: Hash256,
    ) -> GatewayAssignmentDrainV1 {
        let mut value = GatewayAssignmentDrainV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: manifest.network_id,
            context_manifest_id: manifest.object_id(),
            assignment_id: assignment.object_id(),
            gateway_pubkey: manifest.gateway_pubkey,
            core_handoff_pubkey: manifest.core_handoff_pubkey,
            last_gateway_sequence: sequence,
            final_capture_envelope_id: final_envelope_id,
            drained_ms: 120,
            gateway_signature: SignatureBytes::empty(),
        };
        value.gateway_signature = sign_object(gateway, value.network_id, &value);
        value
    }

    fn roundtrip<T>(value: &T)
    where
        T: CanonicalEncode + CanonicalDecode + PartialEq + std::fmt::Debug,
    {
        let bytes = value.to_canonical_bytes();
        assert_eq!(
            T::from_canonical_bytes(&bytes, DecodeLimits::default()).unwrap(),
            *value
        );
    }

    #[test]
    fn signed_handoff_objects_round_trip_canonically() {
        let operator = key(10);
        let gateway = key(11);
        let core = key(12);
        let manifest = manifest(&operator, &gateway, &core);
        let assignment = assignment(
            &operator,
            &gateway,
            &core,
            GATEWAY_OBSERVATION_CORE_RECEIPT_TIME,
        );
        let envelope = envelope(&manifest, &assignment, &gateway, 1);
        let transition = GatewayAssignmentTransitionV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: 2,
            context_manifest_id: manifest.object_id(),
            gateway_pubkey: gateway.verifying_key().to_bytes(),
            core_handoff_pubkey: core.verifying_key().to_bytes(),
            transition_sequence: 1,
            previous_assignment_id: assignment.object_id(),
            next_assignment_id: hash(13),
            previous_assignment_last_gateway_sequence: 1,
            transition_ms: 110,
            reason_code: 1,
            gateway_signature: SignatureBytes::empty(),
        };
        let receipt = GatewayCaptureReceiptV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: 2,
            context_manifest_id: manifest.object_id(),
            assignment_id: assignment.object_id(),
            capture_envelope_id: envelope.object_id(),
            gateway_pubkey: gateway.verifying_key().to_bytes(),
            core_handoff_pubkey: core.verifying_key().to_bytes(),
            receipt_sequence: 1,
            core_received_ms: 101,
            outcome: CAPTURE_OUTCOME_ACCEPTED,
            reason_code: 0,
            accepted_share_id: hash(14),
            core_signature: SignatureBytes::empty(),
        };
        let drain = GatewayAssignmentDrainV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: 2,
            context_manifest_id: manifest.object_id(),
            assignment_id: assignment.object_id(),
            gateway_pubkey: gateway.verifying_key().to_bytes(),
            core_handoff_pubkey: core.verifying_key().to_bytes(),
            last_gateway_sequence: 1,
            final_capture_envelope_id: envelope.object_id(),
            drained_ms: 120,
            gateway_signature: SignatureBytes::empty(),
        };
        let drain_receipt = CoreAssignmentDrainReceiptV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: 2,
            context_manifest_id: manifest.object_id(),
            assignment_id: assignment.object_id(),
            gateway_drain_id: drain.object_id(),
            gateway_pubkey: gateway.verifying_key().to_bytes(),
            core_handoff_pubkey: core.verifying_key().to_bytes(),
            accepted_through_gateway_sequence: 1,
            receipt_sequence: 2,
            core_received_ms: 121,
            outcome: DRAIN_OUTCOME_COMPLETE,
            reason_code: 0,
            core_signature: SignatureBytes::empty(),
        };
        roundtrip(&manifest);
        roundtrip(&envelope);
        roundtrip(&transition);
        roundtrip(&receipt);
        roundtrip(&drain);
        roundtrip(&drain_receipt);
        assert_ne!(envelope.object_id(), receipt.object_id());
    }

    #[test]
    fn capture_evidence_selects_only_the_signed_observation_policy() {
        let operator = key(20);
        let gateway = key(21);
        let core = key(22);
        let manifest = manifest(&operator, &gateway, &core);
        validate_context_manifest(&manifest, 100).unwrap();

        let core_policy = assignment(
            &operator,
            &gateway,
            &core,
            GATEWAY_OBSERVATION_CORE_RECEIPT_TIME,
        );
        let core_envelope = envelope(&manifest, &core_policy, &gateway, 1);
        assert_eq!(
            validate_capture_envelope(&manifest, &core_policy, &core_envelope, 104).unwrap(),
            104
        );

        let delegated = assignment(
            &operator,
            &gateway,
            &core,
            GATEWAY_OBSERVATION_DELEGATED_SIGNED_TIME_V1,
        );
        let delegated_envelope = envelope(&manifest, &delegated, &gateway, 1);
        assert_eq!(
            validate_capture_envelope(&manifest, &delegated, &delegated_envelope, 104).unwrap(),
            100
        );
        assert_eq!(
            validate_capture_envelope(&manifest, &delegated, &delegated_envelope, 106),
            Err(HandoffError::ObservationTime)
        );

        let mut bad_signature = delegated_envelope;
        bad_signature.gateway_signature.0[0] ^= 1;
        assert_eq!(
            validate_capture_envelope(&manifest, &delegated, &bad_signature, 104),
            Err(HandoffError::Signature)
        );
    }

    #[test]
    fn sequence_cursor_is_gap_free_idempotent_and_drain_fenced() {
        let operator = key(30);
        let gateway = key(31);
        let core = key(32);
        let manifest = manifest(&operator, &gateway, &core);
        let assignment = assignment(
            &operator,
            &gateway,
            &core,
            GATEWAY_OBSERVATION_CORE_RECEIPT_TIME,
        );
        let first = envelope(&manifest, &assignment, &gateway, 1);
        let mut cursor = GatewayCaptureCursorV1::new(assignment.object_id());
        assert_eq!(cursor.classify(&first), Ok(CaptureSequenceDecision::New));
        cursor.advance(&first).unwrap();
        assert_eq!(
            cursor.classify(&first),
            Ok(CaptureSequenceDecision::ExactRetry)
        );
        assert_eq!(
            cursor.classify(&envelope(&manifest, &assignment, &gateway, 3)),
            Err(HandoffError::Sequence)
        );
        let mut regressed_time = envelope(&manifest, &assignment, &gateway, 2);
        regressed_time.gateway_received_ms = 99;
        regressed_time.gateway_signature = sign_object(&gateway, 2, &regressed_time);
        assert_eq!(
            cursor.classify(&regressed_time),
            Err(HandoffError::ObservationTime)
        );

        let mut drain = GatewayAssignmentDrainV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: 2,
            context_manifest_id: manifest.object_id(),
            assignment_id: assignment.object_id(),
            gateway_pubkey: gateway.verifying_key().to_bytes(),
            core_handoff_pubkey: core.verifying_key().to_bytes(),
            last_gateway_sequence: 1,
            final_capture_envelope_id: first.object_id(),
            drained_ms: 120,
            gateway_signature: SignatureBytes::empty(),
        };
        drain.gateway_signature = sign_object(&gateway, 2, &drain);
        validate_gateway_drain(&manifest, &drain).unwrap();
        cursor.apply_drain(&drain).unwrap();
        assert_eq!(
            cursor.classify(&envelope(&manifest, &assignment, &gateway, 2)),
            Err(HandoffError::CaptureAfterDrain)
        );
    }

    #[test]
    fn core_receipts_are_signed_and_noncredit_outcomes_cannot_name_a_share() {
        let operator = key(40);
        let gateway = key(41);
        let core = key(42);
        let manifest = manifest(&operator, &gateway, &core);
        let assignment = assignment(
            &operator,
            &gateway,
            &core,
            GATEWAY_OBSERVATION_CORE_RECEIPT_TIME,
        );
        let envelope = envelope(&manifest, &assignment, &gateway, 1);
        let mut receipt = GatewayCaptureReceiptV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: 2,
            context_manifest_id: manifest.object_id(),
            assignment_id: assignment.object_id(),
            capture_envelope_id: envelope.object_id(),
            gateway_pubkey: gateway.verifying_key().to_bytes(),
            core_handoff_pubkey: core.verifying_key().to_bytes(),
            receipt_sequence: 1,
            core_received_ms: 101,
            outcome: CAPTURE_OUTCOME_ACCEPTED,
            reason_code: 0,
            accepted_share_id: hash(43),
            core_signature: SignatureBytes::empty(),
        };
        receipt.core_signature = sign_object(&core, 2, &receipt);
        validate_capture_receipt(&envelope, &receipt).unwrap();

        receipt.outcome = CAPTURE_OUTCOME_GRACE_NONCREDIT;
        receipt.core_signature = sign_object(&core, 2, &receipt);
        assert_eq!(
            validate_capture_receipt(&envelope, &receipt),
            Err(HandoffError::Disposition)
        );
        receipt.accepted_share_id = [0; 32];
        receipt.core_signature = sign_object(&core, 2, &receipt);
        validate_capture_receipt(&envelope, &receipt).unwrap();

        let store = MemoryStore::default();
        persist_gateway_context_manifest(&store, &manifest, 100).unwrap();
        persist_gateway_assignment_authorization(&store, &manifest, &assignment).unwrap();
        persist_noncredit_capture_disposition(&store, &manifest, &assignment, &envelope, &receipt)
            .unwrap();
        let journal = ProtocolJournal::new(&store);
        assert_eq!(
            journal
                .load(
                    ProtocolRecordKind::GatewayCaptureEnvelope,
                    &envelope.object_id()
                )
                .unwrap(),
            Some(envelope.to_canonical_bytes())
        );
        assert_eq!(
            journal
                .load(
                    ProtocolRecordKind::GatewayCaptureReceipt,
                    &envelope.object_id()
                )
                .unwrap(),
            Some(receipt.to_canonical_bytes())
        );
        assert!(
            journal
                .recover_kind(
                    ProtocolRecordKind::AcceptedShare,
                    meshmine_storage::ScanLimits {
                        maximum_records: 1,
                        maximum_value_bytes: 1,
                        maximum_total_bytes: 1,
                    }
                )
                .unwrap()
                .records
                .is_empty()
        );

        let mut conflicting = receipt.clone();
        conflicting.reason_code = 9;
        conflicting.core_signature = sign_object(&core, 2, &conflicting);
        assert!(matches!(
            persist_noncredit_capture_disposition(
                &store,
                &manifest,
                &assignment,
                &envelope,
                &conflicting,
            ),
            Err(HandoffError::Durable(
                DurableInvariantError::ImmutableConflict
            ))
        ));
    }

    #[test]
    fn durable_drain_rejects_new_capture_but_preserves_exact_retry() {
        let operator = key(50);
        let gateway = key(51);
        let core = key(52);
        let manifest = manifest(&operator, &gateway, &core);
        let assignment = assignment(
            &operator,
            &gateway,
            &core,
            GATEWAY_OBSERVATION_CORE_RECEIPT_TIME,
        );
        let store = MemoryStore::default();
        persist_gateway_context_manifest(&store, &manifest, 100).unwrap();
        persist_gateway_assignment_authorization(&store, &manifest, &assignment).unwrap();

        let first = envelope(&manifest, &assignment, &gateway, 1);
        let first_receipt = noncredit_receipt(&first, &core);
        persist_noncredit_capture_disposition(
            &store,
            &manifest,
            &assignment,
            &first,
            &first_receipt,
        )
        .unwrap();
        let assignment_drain = drain(&manifest, &assignment, &gateway, 1, first.object_id());
        persist_gateway_assignment_drain(&store, &manifest, &assignment_drain).unwrap();

        assert!(matches!(
            persist_noncredit_capture_disposition(
                &store,
                &manifest,
                &assignment,
                &first,
                &first_receipt,
            ),
            Ok(JournalBatchOutcome::Committed | JournalBatchOutcome::ExactRecord)
        ));
        let second = envelope(&manifest, &assignment, &gateway, 2);
        let second_receipt = noncredit_receipt(&second, &core);
        assert_eq!(
            persist_noncredit_capture_disposition(
                &store,
                &manifest,
                &assignment,
                &second,
                &second_receipt,
            ),
            Err(HandoffError::CaptureAfterDrain)
        );
    }

    #[test]
    fn transition_requires_drain_and_atomically_activates_only_the_successor() {
        let operator = key(60);
        let gateway = key(61);
        let core = key(62);
        let manifest = manifest(&operator, &gateway, &core);
        let previous = assignment(
            &operator,
            &gateway,
            &core,
            GATEWAY_OBSERVATION_CORE_RECEIPT_TIME,
        );
        let mut next = previous.clone();
        next.assignment_sequence = 2;
        next.ntime = 51;
        next.operator_signature = sign_object(&operator, 2, &next);
        let mut transition = GatewayAssignmentTransitionV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: 2,
            context_manifest_id: manifest.object_id(),
            gateway_pubkey: manifest.gateway_pubkey,
            core_handoff_pubkey: manifest.core_handoff_pubkey,
            transition_sequence: 2,
            previous_assignment_id: previous.object_id(),
            next_assignment_id: next.object_id(),
            previous_assignment_last_gateway_sequence: 0,
            transition_ms: 121,
            reason_code: 1,
            gateway_signature: SignatureBytes::empty(),
        };
        transition.gateway_signature = sign_object(&gateway, 2, &transition);
        let store = MemoryStore::default();
        persist_gateway_context_manifest(&store, &manifest, 100).unwrap();
        persist_gateway_assignment_authorization(&store, &manifest, &previous).unwrap();

        assert_eq!(
            persist_gateway_assignment_transition(&store, &manifest, &next, &transition),
            Err(HandoffError::DrainBoundary)
        );
        let previous_drain = drain(&manifest, &previous, &gateway, 0, [0; 32]);
        persist_gateway_assignment_drain(&store, &manifest, &previous_drain).unwrap();
        persist_gateway_assignment_transition(&store, &manifest, &next, &transition).unwrap();
        assert_eq!(
            persist_gateway_assignment_drain(&store, &manifest, &previous_drain),
            Ok(JournalBatchOutcome::ExactRecord)
        );

        let stale = envelope(&manifest, &previous, &gateway, 1);
        assert!(matches!(
            persist_noncredit_capture_disposition(
                &store,
                &manifest,
                &previous,
                &stale,
                &noncredit_receipt(&stale, &core),
            ),
            Err(HandoffError::Sequence | HandoffError::CaptureAfterDrain)
        ));
        let successor = envelope(&manifest, &next, &gateway, 1);
        persist_noncredit_capture_disposition(
            &store,
            &manifest,
            &next,
            &successor,
            &noncredit_receipt(&successor, &core),
        )
        .unwrap();
    }

    #[test]
    fn context_head_rejects_rollback_and_stale_capture_authorization() {
        let operator = key(70);
        let gateway = key(71);
        let core = key(72);
        let first = manifest(&operator, &gateway, &core);
        let assignment = assignment(
            &operator,
            &gateway,
            &core,
            GATEWAY_OBSERVATION_CORE_RECEIPT_TIME,
        );
        let store = MemoryStore::default();
        persist_gateway_context_manifest(&store, &first, 100).unwrap();
        persist_gateway_assignment_authorization(&store, &first, &assignment).unwrap();

        let mut second = first.clone();
        second.context_sequence = 2;
        second.previous_manifest_id = first.object_id();
        second.operator_signature = sign_object(&operator, 2, &second);
        persist_gateway_context_manifest(&store, &second, 100).unwrap();
        assert_eq!(
            persist_gateway_context_manifest(&store, &first, 100),
            Err(HandoffError::Sequence)
        );

        let stale = envelope(&first, &assignment, &gateway, 1);
        assert_eq!(
            persist_noncredit_capture_disposition(
                &store,
                &first,
                &assignment,
                &stale,
                &noncredit_receipt(&stale, &core),
            ),
            Err(HandoffError::Sequence)
        );
    }
}
