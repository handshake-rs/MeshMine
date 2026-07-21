use meshmine_codec::{
    CanonicalDecode, CanonicalEncode, CodecError, DecodeLimits, Decoder, Encoder,
};
use meshmine_handoff::{
    CoreAssignmentDrainReceiptV1, GatewayAssignmentDrainV1, GatewayAssignmentTransitionV1,
    GatewayCaptureEnvelopeV1, GatewayCaptureReceiptV1,
};
use meshmine_hns::Hash256;
use meshmine_types::{CORE_V2, SignatureBytes, UnsignedObject};
use thiserror::Error;

use crate::CoreAssignmentBundleV1;

pub const CORE_LINK_PROTOCOL_V1: u16 = 1;
pub const MAX_CORE_LINK_ERROR_BYTES: usize = 4 * 1024;
pub const MAX_CORE_LINK_FRAME_BYTES: usize = 8 * 1024 * 1024 + 64 * 1024;
pub const MAX_CORE_LINK_IN_FLIGHT: usize = 4096;
pub const CORE_LINK_AUTH_TIMEOUT_MS: u64 = 5_000;
pub const CORE_LINK_IDLE_TIMEOUT_MS: u64 = 30_000;

pub const FRAME_ASSIGNMENT_OFFER: u8 = 1;
pub const FRAME_ASSIGNMENT_ACK: u8 = 2;
pub const FRAME_CAPTURE_SUBMISSION: u8 = 3;
pub const FRAME_CAPTURE_DISPOSITION: u8 = 4;
pub const FRAME_DRAIN_REQUIRED: u8 = 5;
pub const FRAME_DRAIN_SUBMISSION: u8 = 6;
pub const FRAME_DRAIN_DISPOSITION: u8 = 7;
pub const FRAME_HEARTBEAT: u8 = 8;
pub const FRAME_ERROR: u8 = 9;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreLinkServerChallengeV1 {
    pub core_protocol_version: u16,
    pub link_protocol_version: u16,
    pub network_id: u8,
    pub core_handoff_pubkey: [u8; 32],
    pub expected_gateway_pubkey: [u8; 32],
    pub challenge_nonce: Hash256,
    pub server_nonce: Hash256,
    pub issued_at_ms: u64,
    pub core_signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreLinkClientProofV1 {
    pub core_protocol_version: u16,
    pub link_protocol_version: u16,
    pub network_id: u8,
    pub gateway_pubkey: [u8; 32],
    pub core_handoff_pubkey: [u8; 32],
    pub challenge_nonce: Hash256,
    pub server_nonce: Hash256,
    pub client_nonce: Hash256,
    pub peer_uid: u32,
    pub peer_pid: u32,
    pub gateway_signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreLinkAuthAcceptedV1 {
    pub core_protocol_version: u16,
    pub link_protocol_version: u16,
    pub network_id: u8,
    pub gateway_pubkey: [u8; 32],
    pub core_handoff_pubkey: [u8; 32],
    pub challenge_nonce: Hash256,
    pub server_nonce: Hash256,
    pub client_nonce: Hash256,
    pub connection_id: Hash256,
    pub accepted_at_ms: u64,
    pub core_signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignmentAckV1 {
    pub link_protocol_version: u16,
    pub network_id: u8,
    pub bundle_id: Hash256,
    pub assignment_id: Hash256,
    pub gateway_pubkey: [u8; 32],
    pub accepted_at_ms: u64,
    pub gateway_signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureSubmissionV1 {
    pub link_protocol_version: u16,
    pub network_id: u8,
    pub request_id: Hash256,
    pub envelope: GatewayCaptureEnvelopeV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureDispositionV1 {
    pub link_protocol_version: u16,
    pub network_id: u8,
    pub request_id: Hash256,
    pub receipt: GatewayCaptureReceiptV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainRequiredV1 {
    pub link_protocol_version: u16,
    pub network_id: u8,
    pub current_assignment_id: Hash256,
    pub next_bundle_id: Hash256,
    pub next_assignment_id: Hash256,
    pub credit_cutoff_ms: u64,
    pub previous_submission_end_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainSubmissionV1 {
    pub link_protocol_version: u16,
    pub network_id: u8,
    pub request_id: Hash256,
    pub next_bundle_id: Hash256,
    pub drain: GatewayAssignmentDrainV1,
    pub transition: GatewayAssignmentTransitionV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainDispositionV1 {
    pub link_protocol_version: u16,
    pub network_id: u8,
    pub request_id: Hash256,
    pub receipt: CoreAssignmentDrainReceiptV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeartbeatV1 {
    pub link_protocol_version: u16,
    pub network_id: u8,
    pub sent_at_ms: u64,
    pub current_bundle_id: Hash256,
    pub pending_capture_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreLinkErrorV1 {
    pub link_protocol_version: u16,
    pub network_id: u8,
    pub request_id: Hash256,
    pub error_code: u16,
    pub retryable: bool,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
// Assignment offers intentionally carry the complete, independently signed
// context bundle as one canonical message.
#[allow(clippy::large_enum_variant)]
pub enum CoreLinkMessage {
    AssignmentOffer(CoreAssignmentBundleV1),
    AssignmentAck(AssignmentAckV1),
    CaptureSubmission(CaptureSubmissionV1),
    CaptureDisposition(CaptureDispositionV1),
    DrainRequired(DrainRequiredV1),
    DrainSubmission(DrainSubmissionV1),
    DrainDisposition(DrainDispositionV1),
    Heartbeat(HeartbeatV1),
    Error(CoreLinkErrorV1),
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("core-link message codec failed: {0}")]
    Codec(#[from] CodecError),
    #[error("unknown core-link frame kind {0}")]
    UnknownFrame(u8),
    #[error("core-link error message exceeds its bound")]
    ErrorMessageTooLarge,
    #[error("core-link protocol or network mismatch")]
    Context,
}

macro_rules! signed_object {
    ($type:ty, $domain:literal, $signature:ident, { $($field:ident => $encode:expr),* $(,)? }) => {
        impl UnsignedObject for $type {
            const DOMAIN_TAG: &'static str = $domain;
            fn encode_unsigned(&self, encoder: &mut Encoder) {
                $(($encode)(encoder, &self.$field);)*
            }
        }
        impl CanonicalEncode for $type {
            fn encode(&self, encoder: &mut Encoder) {
                self.encode_unsigned(encoder);
                self.$signature.encode(encoder);
            }
        }
    };
}

fn e_u8(encoder: &mut Encoder, value: &u8) {
    encoder.u8(*value);
}
fn e_u16(encoder: &mut Encoder, value: &u16) {
    encoder.u16(*value);
}
fn e_u32(encoder: &mut Encoder, value: &u32) {
    encoder.u32(*value);
}
fn e_u64(encoder: &mut Encoder, value: &u64) {
    encoder.u64(*value);
}
fn e_hash(encoder: &mut Encoder, value: &Hash256) {
    encoder.fixed(value);
}

signed_object!(CoreLinkServerChallengeV1, "meshmine/core-link-server-challenge/v1", core_signature, {
    core_protocol_version => e_u16,
    link_protocol_version => e_u16,
    network_id => e_u8,
    core_handoff_pubkey => e_hash,
    expected_gateway_pubkey => e_hash,
    challenge_nonce => e_hash,
    server_nonce => e_hash,
    issued_at_ms => e_u64,
});

signed_object!(CoreLinkClientProofV1, "meshmine/core-link-client-proof/v1", gateway_signature, {
    core_protocol_version => e_u16,
    link_protocol_version => e_u16,
    network_id => e_u8,
    gateway_pubkey => e_hash,
    core_handoff_pubkey => e_hash,
    challenge_nonce => e_hash,
    server_nonce => e_hash,
    client_nonce => e_hash,
    peer_uid => e_u32,
    peer_pid => e_u32,
});

signed_object!(CoreLinkAuthAcceptedV1, "meshmine/core-link-auth-accepted/v1", core_signature, {
    core_protocol_version => e_u16,
    link_protocol_version => e_u16,
    network_id => e_u8,
    gateway_pubkey => e_hash,
    core_handoff_pubkey => e_hash,
    challenge_nonce => e_hash,
    server_nonce => e_hash,
    client_nonce => e_hash,
    connection_id => e_hash,
    accepted_at_ms => e_u64,
});

signed_object!(AssignmentAckV1, "meshmine/core-link-assignment-ack/v1", gateway_signature, {
    link_protocol_version => e_u16,
    network_id => e_u8,
    bundle_id => e_hash,
    assignment_id => e_hash,
    gateway_pubkey => e_hash,
    accepted_at_ms => e_u64,
});

impl CanonicalDecode for CoreLinkServerChallengeV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            core_protocol_version: decoder.u16()?,
            link_protocol_version: decoder.u16()?,
            network_id: decoder.u8()?,
            core_handoff_pubkey: decoder.array()?,
            expected_gateway_pubkey: decoder.array()?,
            challenge_nonce: decoder.array()?,
            server_nonce: decoder.array()?,
            issued_at_ms: decoder.u64()?,
            core_signature: SignatureBytes::decode(decoder)?,
        })
    }
}
impl CanonicalDecode for CoreLinkClientProofV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            core_protocol_version: decoder.u16()?,
            link_protocol_version: decoder.u16()?,
            network_id: decoder.u8()?,
            gateway_pubkey: decoder.array()?,
            core_handoff_pubkey: decoder.array()?,
            challenge_nonce: decoder.array()?,
            server_nonce: decoder.array()?,
            client_nonce: decoder.array()?,
            peer_uid: decoder.u32()?,
            peer_pid: decoder.u32()?,
            gateway_signature: SignatureBytes::decode(decoder)?,
        })
    }
}
impl CanonicalDecode for CoreLinkAuthAcceptedV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            core_protocol_version: decoder.u16()?,
            link_protocol_version: decoder.u16()?,
            network_id: decoder.u8()?,
            gateway_pubkey: decoder.array()?,
            core_handoff_pubkey: decoder.array()?,
            challenge_nonce: decoder.array()?,
            server_nonce: decoder.array()?,
            client_nonce: decoder.array()?,
            connection_id: decoder.array()?,
            accepted_at_ms: decoder.u64()?,
            core_signature: SignatureBytes::decode(decoder)?,
        })
    }
}
impl CanonicalDecode for AssignmentAckV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            link_protocol_version: decoder.u16()?,
            network_id: decoder.u8()?,
            bundle_id: decoder.array()?,
            assignment_id: decoder.array()?,
            gateway_pubkey: decoder.array()?,
            accepted_at_ms: decoder.u64()?,
            gateway_signature: SignatureBytes::decode(decoder)?,
        })
    }
}

impl CanonicalEncode for CaptureSubmissionV1 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.link_protocol_version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.request_id);
        self.envelope.encode(encoder);
    }
}
impl CanonicalDecode for CaptureSubmissionV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            link_protocol_version: decoder.u16()?,
            network_id: decoder.u8()?,
            request_id: decoder.array()?,
            envelope: GatewayCaptureEnvelopeV1::decode(decoder)?,
        })
    }
}
impl CanonicalEncode for CaptureDispositionV1 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.link_protocol_version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.request_id);
        self.receipt.encode(encoder);
    }
}
impl CanonicalDecode for CaptureDispositionV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            link_protocol_version: decoder.u16()?,
            network_id: decoder.u8()?,
            request_id: decoder.array()?,
            receipt: GatewayCaptureReceiptV1::decode(decoder)?,
        })
    }
}
impl CanonicalEncode for DrainRequiredV1 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.link_protocol_version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.current_assignment_id);
        encoder.fixed(&self.next_bundle_id);
        encoder.fixed(&self.next_assignment_id);
        encoder.u64(self.credit_cutoff_ms);
        encoder.u64(self.previous_submission_end_ms);
    }
}
impl CanonicalDecode for DrainRequiredV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            link_protocol_version: decoder.u16()?,
            network_id: decoder.u8()?,
            current_assignment_id: decoder.array()?,
            next_bundle_id: decoder.array()?,
            next_assignment_id: decoder.array()?,
            credit_cutoff_ms: decoder.u64()?,
            previous_submission_end_ms: decoder.u64()?,
        })
    }
}
impl CanonicalEncode for DrainSubmissionV1 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.link_protocol_version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.request_id);
        encoder.fixed(&self.next_bundle_id);
        self.drain.encode(encoder);
        self.transition.encode(encoder);
    }
}
impl CanonicalDecode for DrainSubmissionV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            link_protocol_version: decoder.u16()?,
            network_id: decoder.u8()?,
            request_id: decoder.array()?,
            next_bundle_id: decoder.array()?,
            drain: GatewayAssignmentDrainV1::decode(decoder)?,
            transition: GatewayAssignmentTransitionV1::decode(decoder)?,
        })
    }
}
impl CanonicalEncode for DrainDispositionV1 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.link_protocol_version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.request_id);
        self.receipt.encode(encoder);
    }
}
impl CanonicalDecode for DrainDispositionV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            link_protocol_version: decoder.u16()?,
            network_id: decoder.u8()?,
            request_id: decoder.array()?,
            receipt: CoreAssignmentDrainReceiptV1::decode(decoder)?,
        })
    }
}
impl CanonicalEncode for HeartbeatV1 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.link_protocol_version);
        encoder.u8(self.network_id);
        encoder.u64(self.sent_at_ms);
        encoder.fixed(&self.current_bundle_id);
        encoder.u32(self.pending_capture_count);
    }
}
impl CanonicalDecode for HeartbeatV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            link_protocol_version: decoder.u16()?,
            network_id: decoder.u8()?,
            sent_at_ms: decoder.u64()?,
            current_bundle_id: decoder.array()?,
            pending_capture_count: decoder.u32()?,
        })
    }
}
impl CanonicalEncode for CoreLinkErrorV1 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.link_protocol_version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.request_id);
        encoder.u16(self.error_code);
        encoder.u8(u8::from(self.retryable));
        encoder.bytes(self.message.as_bytes());
    }
}
impl CanonicalDecode for CoreLinkErrorV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let link_protocol_version = decoder.u16()?;
        let network_id = decoder.u8()?;
        let request_id = decoder.array()?;
        let error_code = decoder.u16()?;
        let retryable = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(CodecError::InvalidField("retryable flag")),
        };
        let message = String::from_utf8(decoder.bytes(MAX_CORE_LINK_ERROR_BYTES)?)
            .map_err(|_| CodecError::InvalidField("error UTF-8"))?;
        Ok(Self {
            link_protocol_version,
            network_id,
            request_id,
            error_code,
            retryable,
            message,
        })
    }
}

impl CoreLinkMessage {
    pub fn frame_kind(&self) -> u8 {
        match self {
            Self::AssignmentOffer(_) => FRAME_ASSIGNMENT_OFFER,
            Self::AssignmentAck(_) => FRAME_ASSIGNMENT_ACK,
            Self::CaptureSubmission(_) => FRAME_CAPTURE_SUBMISSION,
            Self::CaptureDisposition(_) => FRAME_CAPTURE_DISPOSITION,
            Self::DrainRequired(_) => FRAME_DRAIN_REQUIRED,
            Self::DrainSubmission(_) => FRAME_DRAIN_SUBMISSION,
            Self::DrainDisposition(_) => FRAME_DRAIN_DISPOSITION,
            Self::Heartbeat(_) => FRAME_HEARTBEAT,
            Self::Error(_) => FRAME_ERROR,
        }
    }

    pub fn encode_payload(&self) -> Vec<u8> {
        match self {
            Self::AssignmentOffer(value) => value.to_canonical_bytes(),
            Self::AssignmentAck(value) => value.to_canonical_bytes(),
            Self::CaptureSubmission(value) => value.to_canonical_bytes(),
            Self::CaptureDisposition(value) => value.to_canonical_bytes(),
            Self::DrainRequired(value) => value.to_canonical_bytes(),
            Self::DrainSubmission(value) => value.to_canonical_bytes(),
            Self::DrainDisposition(value) => value.to_canonical_bytes(),
            Self::Heartbeat(value) => value.to_canonical_bytes(),
            Self::Error(value) => value.to_canonical_bytes(),
        }
    }

    pub fn decode(kind: u8, payload: &[u8], maximum: usize) -> Result<Self, ProtocolError> {
        let limits = DecodeLimits {
            max_object_bytes: maximum,
            max_vector_items: 100_000,
        };
        Ok(match kind {
            FRAME_ASSIGNMENT_OFFER => Self::AssignmentOffer(
                CoreAssignmentBundleV1::from_canonical_bytes(payload, limits)?,
            ),
            FRAME_ASSIGNMENT_ACK => {
                Self::AssignmentAck(AssignmentAckV1::from_canonical_bytes(payload, limits)?)
            }
            FRAME_CAPTURE_SUBMISSION => {
                Self::CaptureSubmission(CaptureSubmissionV1::from_canonical_bytes(payload, limits)?)
            }
            FRAME_CAPTURE_DISPOSITION => Self::CaptureDisposition(
                CaptureDispositionV1::from_canonical_bytes(payload, limits)?,
            ),
            FRAME_DRAIN_REQUIRED => {
                Self::DrainRequired(DrainRequiredV1::from_canonical_bytes(payload, limits)?)
            }
            FRAME_DRAIN_SUBMISSION => {
                Self::DrainSubmission(DrainSubmissionV1::from_canonical_bytes(payload, limits)?)
            }
            FRAME_DRAIN_DISPOSITION => {
                Self::DrainDisposition(DrainDispositionV1::from_canonical_bytes(payload, limits)?)
            }
            FRAME_HEARTBEAT => Self::Heartbeat(HeartbeatV1::from_canonical_bytes(payload, limits)?),
            FRAME_ERROR => Self::Error(CoreLinkErrorV1::from_canonical_bytes(payload, limits)?),
            other => return Err(ProtocolError::UnknownFrame(other)),
        })
    }

    pub fn validate_context(&self, network_id: u8) -> Result<(), ProtocolError> {
        let (version, observed_network) = match self {
            Self::AssignmentOffer(value) => (value.bundle_version, value.network_id),
            Self::AssignmentAck(value) => (value.link_protocol_version, value.network_id),
            Self::CaptureSubmission(value) => (value.link_protocol_version, value.network_id),
            Self::CaptureDisposition(value) => (value.link_protocol_version, value.network_id),
            Self::DrainRequired(value) => (value.link_protocol_version, value.network_id),
            Self::DrainSubmission(value) => (value.link_protocol_version, value.network_id),
            Self::DrainDisposition(value) => (value.link_protocol_version, value.network_id),
            Self::Heartbeat(value) => (value.link_protocol_version, value.network_id),
            Self::Error(value) => (value.link_protocol_version, value.network_id),
        };
        if observed_network != network_id || version != CORE_LINK_PROTOCOL_V1 {
            return Err(ProtocolError::Context);
        }
        let valid = match self {
            Self::AssignmentOffer(value) => {
                value.bundle_sequence != 0 && value.assignment.object_id() != [0; 32]
            }
            Self::AssignmentAck(value) => {
                value.bundle_id != [0; 32]
                    && value.assignment_id != [0; 32]
                    && value.gateway_pubkey != [0; 32]
            }
            Self::CaptureSubmission(value) => {
                value.request_id != [0; 32] && value.envelope.object_id() != [0; 32]
            }
            Self::CaptureDisposition(value) => {
                value.request_id != [0; 32] && value.receipt.capture_envelope_id != [0; 32]
            }
            Self::DrainRequired(value) => {
                value.current_assignment_id != [0; 32]
                    && value.next_bundle_id != [0; 32]
                    && value.next_assignment_id != [0; 32]
                    && value.credit_cutoff_ms <= value.previous_submission_end_ms
            }
            Self::DrainSubmission(value) => {
                value.request_id != [0; 32]
                    && value.next_bundle_id != [0; 32]
                    && value.drain.object_id() != [0; 32]
                    && value.transition.object_id() != [0; 32]
            }
            Self::DrainDisposition(value) => {
                value.request_id != [0; 32] && value.receipt.gateway_drain_id != [0; 32]
            }
            Self::Heartbeat(_) => true,
            Self::Error(value) => value.message.len() <= MAX_CORE_LINK_ERROR_BYTES,
        };
        if !valid {
            return Err(match self {
                Self::Error(_) => ProtocolError::ErrorMessageTooLarge,
                _ => ProtocolError::Context,
            });
        }
        Ok(())
    }
}

pub fn validate_auth_context(core_protocol_version: u16, link_protocol_version: u16) -> bool {
    core_protocol_version == CORE_V2 && link_protocol_version == CORE_LINK_PROTOCOL_V1
}
