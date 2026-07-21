use ed25519_dalek::SigningKey;
use meshmine_codec::{
    CanonicalDecode, CanonicalEncode, CodecError, DecodeLimits, Decoder, Encoder,
};
use meshmine_crypto::{sign_object, verify_object};
use meshmine_gateway::ForwardedCapture;
use meshmine_handoff::{
    GatewayAssignmentDrainV1, GatewayAssignmentTransitionV1, GatewayCaptureEnvelopeV1,
    GatewayCaptureReceiptV1, validate_capture_receipt,
};
use meshmine_hns::Hash256;
use meshmine_storage::{BatchCondition, BatchOperation, DurableStore, ScanLimits, StorageError};
use meshmine_types::{
    CORE_V2, ED25519_SUITE, GATEWAY_HANDOFF_V1, GatewayAssignmentV1, SignatureBytes, UnsignedObject,
};
use thiserror::Error;

use crate::CoreAssignmentBundleV1;

pub const OPERATOR_BUNDLE_NAMESPACE: &str = "core-link-operator-bundle/v1";
pub const OPERATOR_ASSIGNMENT_INDEX_NAMESPACE: &str = "core-link-operator-assignment-index/v1";
pub const OPERATOR_CAPTURE_ENVELOPE_NAMESPACE: &str = "core-link-capture-envelope/v1";
pub const OPERATOR_CAPTURE_RECEIPT_NAMESPACE: &str = "core-link-capture-receipt/v1";
pub const OPERATOR_CAPTURE_SEQUENCE_NAMESPACE: &str = "core-link-capture-sequence/v1";
pub const OPERATOR_CAPTURE_CAPACITY_NAMESPACE: &str = "core-link-capture-capacity/v1";
pub const OPERATOR_CAPTURE_CAPACITY_KEY: &str = "pending";
pub const OPERATOR_DRAIN_NAMESPACE: &str = "core-link-assignment-drain/v1";
pub const OPERATOR_TRANSITION_NAMESPACE: &str = "core-link-assignment-transition/v1";
pub const MAX_OPERATOR_CAPTURE_RECORDS: usize = 100_000;
pub const MAX_OPERATOR_CAPTURE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewaySequenceHeadV1 {
    pub assignment_id: Hash256,
    pub sequence: u64,
    pub final_envelope_id: Hash256,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OperatorCaptureCapacityV1 {
    pub pending_records: u64,
    pub pending_bytes: u64,
}

#[derive(Debug, Error)]
pub enum SpoolError {
    #[error("operator capture spool storage failed: {0}")]
    Storage(#[from] StorageError),
    #[error("operator capture spool codec failed: {0}")]
    Codec(#[from] CodecError),
    #[error("operator capture does not match an installed assignment")]
    Assignment,
    #[error("operator capture envelope conflicts with durable state")]
    Conflict,
    #[error("operator capture sequence allocation lost its compare-and-swap")]
    SequenceRace,
    #[error("operator capture receipt is invalid")]
    Receipt,
    #[error("operator capture spool exceeds its bounded capacity")]
    Capacity,
}

pub struct OperatorCaptureSpool<'a> {
    store: &'a dyn DurableStore,
    network_id: u8,
    gateway_signing_key: &'a SigningKey,
    core_handoff_pubkey: [u8; 32],
    connection_id: Hash256,
}

impl<'a> OperatorCaptureSpool<'a> {
    pub fn new(
        store: &'a dyn DurableStore,
        network_id: u8,
        gateway_signing_key: &'a SigningKey,
        core_handoff_pubkey: [u8; 32],
        connection_id: Hash256,
    ) -> Self {
        Self {
            store,
            network_id,
            gateway_signing_key,
            core_handoff_pubkey,
            connection_id,
        }
    }

    pub fn persist_bundle(&self, bundle: &CoreAssignmentBundleV1) -> Result<(), SpoolError> {
        if bundle.network_id != self.network_id
            || bundle.assignment.gateway_pubkey
                != self.gateway_signing_key.verifying_key().to_bytes()
            || bundle.assignment.core_handoff_pubkey != self.core_handoff_pubkey
            || verify_object(
                &self.core_handoff_pubkey,
                ED25519_SUITE,
                &bundle.core_signature,
                bundle.network_id,
                bundle,
            )
            .is_err()
        {
            return Err(SpoolError::Assignment);
        }
        let bundle_id = bundle.object_id();
        let bundle_key = hex::encode(bundle_id);
        let assignment_key = assignment_sequence_key(bundle.assignment.assignment_sequence);
        let bytes = bundle.to_canonical_bytes();
        let existing_bundle = self.store.get(OPERATOR_BUNDLE_NAMESPACE, &bundle_key)?;
        let existing_index = self
            .store
            .get(OPERATOR_ASSIGNMENT_INDEX_NAMESPACE, &assignment_key)?;
        if existing_bundle.as_deref() == Some(bytes.as_slice())
            && existing_index.as_deref() == Some(bundle_id.as_slice())
        {
            return Ok(());
        }
        if existing_bundle.is_some() || existing_index.is_some() {
            return Err(SpoolError::Conflict);
        }
        if !self.store.apply_batch_if_all(
            &[
                BatchCondition::absent(OPERATOR_BUNDLE_NAMESPACE, &bundle_key),
                BatchCondition::absent(OPERATOR_ASSIGNMENT_INDEX_NAMESPACE, &assignment_key),
            ],
            &[
                BatchOperation::put(OPERATOR_BUNDLE_NAMESPACE, bundle_key, bytes),
                BatchOperation::put(
                    OPERATOR_ASSIGNMENT_INDEX_NAMESPACE,
                    assignment_key,
                    bundle_id.to_vec(),
                ),
            ],
        )? {
            return Err(SpoolError::SequenceRace);
        }
        Ok(())
    }

    pub fn bundle_for_sequence(&self, sequence: u64) -> Result<CoreAssignmentBundleV1, SpoolError> {
        let bundle_id = self
            .store
            .get(
                OPERATOR_ASSIGNMENT_INDEX_NAMESPACE,
                &assignment_sequence_key(sequence),
            )?
            .ok_or(SpoolError::Assignment)?;
        if bundle_id.len() != 32 {
            return Err(SpoolError::Conflict);
        }
        let bytes = self
            .store
            .get(OPERATOR_BUNDLE_NAMESPACE, &hex::encode(&bundle_id))?
            .ok_or(SpoolError::Assignment)?;
        let bundle = CoreAssignmentBundleV1::from_canonical_bytes(
            &bytes,
            DecodeLimits {
                max_object_bytes: 8 * 1024 * 1024,
                max_vector_items: 100_000,
            },
        )?;
        let expected_bundle_id: Hash256 = bundle_id
            .as_slice()
            .try_into()
            .map_err(|_| SpoolError::Conflict)?;
        if bundle.object_id() != expected_bundle_id
            || bundle.to_canonical_bytes() != bytes
            || bundle.network_id != self.network_id
            || bundle.assignment.assignment_sequence != sequence
            || bundle.assignment.gateway_pubkey
                != self.gateway_signing_key.verifying_key().to_bytes()
            || bundle.assignment.core_handoff_pubkey != self.core_handoff_pubkey
            || verify_object(
                &self.core_handoff_pubkey,
                ED25519_SUITE,
                &bundle.core_signature,
                bundle.network_id,
                &bundle,
            )
            .is_err()
        {
            return Err(SpoolError::Conflict);
        }
        Ok(bundle)
    }

    pub fn prepare_envelope(
        &self,
        capture: &ForwardedCapture,
    ) -> Result<GatewayCaptureEnvelopeV1, SpoolError> {
        let work_key = capture.work_key();
        let work_key_hex = hex::encode(work_key);
        let bundle = self.bundle_for_sequence(capture.assignment_sequence)?;
        validate_capture_assignment(capture, &bundle.assignment)?;
        validate_capture_context(capture, &bundle)?;
        if let Some(bytes) = self
            .store
            .get(OPERATOR_CAPTURE_ENVELOPE_NAMESPACE, &work_key_hex)?
        {
            let envelope = GatewayCaptureEnvelopeV1::from_canonical_bytes(
                &bytes,
                DecodeLimits {
                    max_object_bytes: 4096,
                    max_vector_items: 0,
                },
            )?;
            validate_capture_matches(capture, &envelope)?;
            return Ok(envelope);
        }
        let assignment_id = bundle.assignment.object_id();
        let sequence_key = hex::encode(assignment_id);
        let existing_head = self
            .store
            .get(OPERATOR_CAPTURE_SEQUENCE_NAMESPACE, &sequence_key)?;
        let current = match existing_head.as_deref() {
            None => GatewaySequenceHeadV1 {
                assignment_id,
                sequence: 0,
                final_envelope_id: [0; 32],
            },
            Some(bytes) => decode_sequence_head(bytes)?,
        };
        if current.assignment_id != assignment_id {
            return Err(SpoolError::Conflict);
        }
        let next_sequence = current
            .sequence
            .checked_add(1)
            .ok_or(SpoolError::Capacity)?;
        let mut envelope = GatewayCaptureEnvelopeV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: self.network_id,
            context_manifest_id: bundle.manifest.object_id(),
            assignment_id,
            session_id: bundle.session.object_id(),
            gateway_pubkey: self.gateway_signing_key.verifying_key().to_bytes(),
            core_handoff_pubkey: self.core_handoff_pubkey,
            gateway_sequence: next_sequence,
            gateway_connection_id: self.connection_id,
            gateway_received_ms: capture.received_ms,
            ntime: capture.miner_header.time,
            extra_nonce: capture.miner_header.extra_nonce,
            nonce: capture.miner_header.nonce,
            raw_share_hash: capture.raw_share_hash,
            gateway_signature: SignatureBytes::empty(),
        };
        envelope.gateway_signature =
            sign_object(self.gateway_signing_key, self.network_id, &envelope);
        let envelope_id = envelope.object_id();
        let envelope_bytes = envelope.to_canonical_bytes();
        let existing_capacity = self.store.get(
            OPERATOR_CAPTURE_CAPACITY_NAMESPACE,
            OPERATOR_CAPTURE_CAPACITY_KEY,
        )?;
        let capacity = match existing_capacity.as_deref() {
            Some(bytes) => decode_capture_capacity(bytes)?,
            None => OperatorCaptureCapacityV1::default(),
        };
        let envelope_len = u64::try_from(envelope_bytes.len()).map_err(|_| SpoolError::Capacity)?;
        let next_capacity = OperatorCaptureCapacityV1 {
            pending_records: capacity
                .pending_records
                .checked_add(1)
                .ok_or(SpoolError::Capacity)?,
            pending_bytes: capacity
                .pending_bytes
                .checked_add(envelope_len)
                .ok_or(SpoolError::Capacity)?,
        };
        if next_capacity.pending_records
            > u64::try_from(MAX_OPERATOR_CAPTURE_RECORDS).map_err(|_| SpoolError::Capacity)?
            || next_capacity.pending_bytes > MAX_OPERATOR_CAPTURE_BYTES
        {
            return Err(SpoolError::Capacity);
        }
        let next_head = GatewaySequenceHeadV1 {
            assignment_id,
            sequence: next_sequence,
            final_envelope_id: envelope_id,
        };
        if !self.store.apply_batch_if_all(
            &[
                BatchCondition::new(
                    OPERATOR_CAPTURE_SEQUENCE_NAMESPACE,
                    &sequence_key,
                    existing_head,
                ),
                BatchCondition::absent(OPERATOR_CAPTURE_ENVELOPE_NAMESPACE, &work_key_hex),
                BatchCondition::new(
                    OPERATOR_CAPTURE_CAPACITY_NAMESPACE,
                    OPERATOR_CAPTURE_CAPACITY_KEY,
                    existing_capacity,
                ),
            ],
            &[
                BatchOperation::put(
                    OPERATOR_CAPTURE_SEQUENCE_NAMESPACE,
                    sequence_key,
                    encode_sequence_head(next_head),
                ),
                BatchOperation::put(
                    OPERATOR_CAPTURE_ENVELOPE_NAMESPACE,
                    work_key_hex,
                    envelope_bytes,
                ),
                BatchOperation::put(
                    OPERATOR_CAPTURE_CAPACITY_NAMESPACE,
                    OPERATOR_CAPTURE_CAPACITY_KEY,
                    encode_capture_capacity(next_capacity),
                ),
            ],
        )? {
            return Err(SpoolError::SequenceRace);
        }
        Ok(envelope)
    }

    pub fn record_receipt(
        &self,
        work_key: Hash256,
        envelope: &GatewayCaptureEnvelopeV1,
        receipt: &GatewayCaptureReceiptV1,
    ) -> Result<(), SpoolError> {
        validate_capture_receipt(envelope, receipt).map_err(|_| SpoolError::Receipt)?;
        if receipt.core_handoff_pubkey != self.core_handoff_pubkey
            || receipt.network_id != self.network_id
        {
            return Err(SpoolError::Receipt);
        }
        let key = hex::encode(work_key);
        let receipt_bytes = receipt.to_canonical_bytes();
        if self
            .store
            .get(OPERATOR_CAPTURE_RECEIPT_NAMESPACE, &key)?
            .as_deref()
            == Some(receipt_bytes.as_slice())
        {
            return Ok(());
        }
        let envelope_bytes = envelope.to_canonical_bytes();
        let stored_envelope = self
            .store
            .get(OPERATOR_CAPTURE_ENVELOPE_NAMESPACE, &key)?
            .ok_or(SpoolError::Conflict)?;
        if stored_envelope != envelope_bytes {
            return Err(SpoolError::Conflict);
        }
        let existing_capacity = self
            .store
            .get(
                OPERATOR_CAPTURE_CAPACITY_NAMESPACE,
                OPERATOR_CAPTURE_CAPACITY_KEY,
            )?
            .ok_or(SpoolError::Conflict)?;
        let capacity = decode_capture_capacity(&existing_capacity)?;
        let envelope_len = u64::try_from(envelope_bytes.len()).map_err(|_| SpoolError::Capacity)?;
        let next_capacity = OperatorCaptureCapacityV1 {
            pending_records: capacity
                .pending_records
                .checked_sub(1)
                .ok_or(SpoolError::Conflict)?,
            pending_bytes: capacity
                .pending_bytes
                .checked_sub(envelope_len)
                .ok_or(SpoolError::Conflict)?,
        };
        if !self.store.apply_batch_if_all(
            &[
                BatchCondition::absent(OPERATOR_CAPTURE_RECEIPT_NAMESPACE, &key),
                BatchCondition::equals(OPERATOR_CAPTURE_ENVELOPE_NAMESPACE, &key, envelope_bytes),
                BatchCondition::equals(
                    OPERATOR_CAPTURE_CAPACITY_NAMESPACE,
                    OPERATOR_CAPTURE_CAPACITY_KEY,
                    existing_capacity,
                ),
            ],
            &[
                BatchOperation::put(
                    OPERATOR_CAPTURE_RECEIPT_NAMESPACE,
                    &key,
                    receipt_bytes.clone(),
                ),
                BatchOperation::delete(OPERATOR_CAPTURE_ENVELOPE_NAMESPACE, &key),
                BatchOperation::put(
                    OPERATOR_CAPTURE_CAPACITY_NAMESPACE,
                    OPERATOR_CAPTURE_CAPACITY_KEY,
                    encode_capture_capacity(next_capacity),
                ),
            ],
        )? {
            if self
                .store
                .get(OPERATOR_CAPTURE_RECEIPT_NAMESPACE, &key)?
                .as_deref()
                == Some(receipt_bytes.as_slice())
            {
                return Ok(());
            }
            return Err(SpoolError::SequenceRace);
        }
        Ok(())
    }

    pub fn receipt(
        &self,
        work_key: Hash256,
    ) -> Result<Option<GatewayCaptureReceiptV1>, SpoolError> {
        let Some(bytes) = self
            .store
            .get(OPERATOR_CAPTURE_RECEIPT_NAMESPACE, &hex::encode(work_key))?
        else {
            return Ok(None);
        };
        Ok(Some(GatewayCaptureReceiptV1::from_canonical_bytes(
            &bytes,
            DecodeLimits {
                max_object_bytes: 4096,
                max_vector_items: 0,
            },
        )?))
    }

    pub fn sequence_head(
        &self,
        assignment_id: Hash256,
    ) -> Result<GatewaySequenceHeadV1, SpoolError> {
        let key = hex::encode(assignment_id);
        match self.store.get(OPERATOR_CAPTURE_SEQUENCE_NAMESPACE, &key)? {
            Some(bytes) => decode_sequence_head(&bytes),
            None => Ok(GatewaySequenceHeadV1 {
                assignment_id,
                sequence: 0,
                final_envelope_id: [0; 32],
            }),
        }
    }

    pub fn pending_for_assignment(&self, assignment_id: Hash256) -> Result<usize, SpoolError> {
        let records = self.store.scan_namespace(
            OPERATOR_CAPTURE_ENVELOPE_NAMESPACE,
            ScanLimits {
                maximum_records: MAX_OPERATOR_CAPTURE_RECORDS,
                maximum_value_bytes: 16 * 1024,
                maximum_total_bytes: MAX_OPERATOR_CAPTURE_BYTES,
            },
        )?;
        let mut pending = 0usize;
        for record in records {
            if self
                .store
                .get(OPERATOR_CAPTURE_RECEIPT_NAMESPACE, &record.key)?
                .is_some()
            {
                continue;
            }
            let envelope = GatewayCaptureEnvelopeV1::from_canonical_bytes(
                &record.value,
                DecodeLimits {
                    max_object_bytes: 4096,
                    max_vector_items: 0,
                },
            )?;
            if envelope.assignment_id == assignment_id {
                pending = pending.checked_add(1).ok_or(SpoolError::Capacity)?;
            }
        }
        Ok(pending)
    }

    pub fn persist_drain_and_transition(
        &self,
        drain: &GatewayAssignmentDrainV1,
        transition: &GatewayAssignmentTransitionV1,
    ) -> Result<(), SpoolError> {
        let drain_key = hex::encode(drain.assignment_id);
        let transition_key = hex::encode(transition.previous_assignment_id);
        let drain_bytes = drain.to_canonical_bytes();
        let transition_bytes = transition.to_canonical_bytes();
        let existing_drain = self.store.get(OPERATOR_DRAIN_NAMESPACE, &drain_key)?;
        let existing_transition = self
            .store
            .get(OPERATOR_TRANSITION_NAMESPACE, &transition_key)?;
        if existing_drain.as_deref() == Some(drain_bytes.as_slice())
            && existing_transition.as_deref() == Some(transition_bytes.as_slice())
        {
            return Ok(());
        }
        if existing_drain.is_some() || existing_transition.is_some() {
            return Err(SpoolError::Conflict);
        }
        if !self.store.apply_batch_if_all(
            &[
                BatchCondition::absent(OPERATOR_DRAIN_NAMESPACE, &drain_key),
                BatchCondition::absent(OPERATOR_TRANSITION_NAMESPACE, &transition_key),
            ],
            &[
                BatchOperation::put(OPERATOR_DRAIN_NAMESPACE, drain_key, drain_bytes),
                BatchOperation::put(
                    OPERATOR_TRANSITION_NAMESPACE,
                    transition_key,
                    transition_bytes,
                ),
            ],
        )? {
            return Err(SpoolError::SequenceRace);
        }
        Ok(())
    }
}

impl CanonicalEncode for GatewaySequenceHeadV1 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.fixed(b"MMS8");
        encoder.fixed(&self.assignment_id);
        encoder.u64(self.sequence);
        encoder.fixed(&self.final_envelope_id);
    }
}
impl CanonicalDecode for GatewaySequenceHeadV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        if decoder.array::<4>()? != *b"MMS8" {
            return Err(CodecError::InvalidField("gateway sequence magic"));
        }
        Ok(Self {
            assignment_id: decoder.array()?,
            sequence: decoder.u64()?,
            final_envelope_id: decoder.array()?,
        })
    }
}

fn encode_sequence_head(head: GatewaySequenceHeadV1) -> Vec<u8> {
    head.to_canonical_bytes()
}
fn decode_sequence_head(bytes: &[u8]) -> Result<GatewaySequenceHeadV1, SpoolError> {
    Ok(GatewaySequenceHeadV1::from_canonical_bytes(
        bytes,
        DecodeLimits {
            max_object_bytes: 80,
            max_vector_items: 0,
        },
    )?)
}

fn encode_capture_capacity(capacity: OperatorCaptureCapacityV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&capacity.pending_records.to_le_bytes());
    bytes.extend_from_slice(&capacity.pending_bytes.to_le_bytes());
    bytes
}

fn decode_capture_capacity(bytes: &[u8]) -> Result<OperatorCaptureCapacityV1, SpoolError> {
    if bytes.len() != 16 {
        return Err(SpoolError::Conflict);
    }
    let mut records = [0u8; 8];
    records.copy_from_slice(&bytes[..8]);
    let mut total = [0u8; 8];
    total.copy_from_slice(&bytes[8..]);
    let capacity = OperatorCaptureCapacityV1 {
        pending_records: u64::from_le_bytes(records),
        pending_bytes: u64::from_le_bytes(total),
    };
    if capacity.pending_records
        > u64::try_from(MAX_OPERATOR_CAPTURE_RECORDS).map_err(|_| SpoolError::Capacity)?
        || capacity.pending_bytes > MAX_OPERATOR_CAPTURE_BYTES
    {
        return Err(SpoolError::Capacity);
    }
    Ok(capacity)
}

fn assignment_sequence_key(sequence: u64) -> String {
    format!("{sequence:020}")
}

fn validate_capture_matches(
    capture: &ForwardedCapture,
    envelope: &GatewayCaptureEnvelopeV1,
) -> Result<(), SpoolError> {
    if envelope.ntime != capture.miner_header.time
        || envelope.extra_nonce != capture.miner_header.extra_nonce
        || envelope.nonce != capture.miner_header.nonce
        || envelope.raw_share_hash != capture.raw_share_hash
    {
        return Err(SpoolError::Conflict);
    }
    Ok(())
}

fn validate_capture_assignment(
    capture: &ForwardedCapture,
    assignment: &GatewayAssignmentV1,
) -> Result<(), SpoolError> {
    let nonce_offset = capture
        .miner_header
        .nonce
        .checked_sub(assignment.nonce_start);
    if capture.assignment_sequence != assignment.assignment_sequence
        || capture.job_id != hex::encode(assignment.object_id())
        || capture.miner_header.time != assignment.ntime
        || !assignment.accepts_extra_nonce(&capture.miner_header.extra_nonce)
        || nonce_offset.is_none_or(|offset| {
            capture.miner_header.nonce > assignment.nonce_end
                || assignment.nonce_stride == 0
                || offset % assignment.nonce_stride != 0
        })
        || capture.telemetry_level as u8 != assignment.telemetry_level
        || capture.miner_header.share_hash() != capture.raw_share_hash
        || capture.raw_share_hash > assignment.capture_target.0
    {
        return Err(SpoolError::Assignment);
    }
    Ok(())
}

fn validate_capture_context(
    capture: &ForwardedCapture,
    bundle: &CoreAssignmentBundleV1,
) -> Result<(), SpoolError> {
    let header = &capture.miner_header;
    if capture.received_ms < bundle.session.assignment_start_ms
        || capture.received_ms > bundle.session.submission_end_ms
        || header.prev_block != bundle.session.parent_hash
        || header.mask_hash != bundle.session.mask_hash
        || header.merkle_root != bundle.body.merkle_root
        || header.witness_root != bundle.body.witness_root
        || header.tree_root != bundle.body.tree_root
        || header.reserved_root != bundle.body.reserved_root
        || header.version != bundle.body.template_core.block_version
        || header.bits != bundle.body.template_core.bits
    {
        return Err(SpoolError::Assignment);
    }
    Ok(())
}

pub fn build_drain_and_transition(
    bundle: &CoreAssignmentBundleV1,
    next_bundle: &CoreAssignmentBundleV1,
    sequence_head: GatewaySequenceHeadV1,
    gateway_signing_key: &SigningKey,
    drained_ms: u64,
) -> Result<(GatewayAssignmentDrainV1, GatewayAssignmentTransitionV1), SpoolError> {
    let replacement = next_bundle
        .replacement
        .as_ref()
        .ok_or(SpoolError::Assignment)?;
    if replacement.previous_assignment_id != bundle.assignment.object_id()
        || sequence_head.assignment_id != bundle.assignment.object_id()
    {
        return Err(SpoolError::Assignment);
    }
    let mut drain = GatewayAssignmentDrainV1 {
        core_protocol_version: CORE_V2,
        handoff_version: GATEWAY_HANDOFF_V1,
        network_id: bundle.network_id,
        context_manifest_id: bundle.manifest.object_id(),
        assignment_id: bundle.assignment.object_id(),
        gateway_pubkey: gateway_signing_key.verifying_key().to_bytes(),
        core_handoff_pubkey: bundle.assignment.core_handoff_pubkey,
        last_gateway_sequence: sequence_head.sequence,
        final_capture_envelope_id: sequence_head.final_envelope_id,
        drained_ms,
        gateway_signature: SignatureBytes::empty(),
    };
    drain.gateway_signature = sign_object(gateway_signing_key, bundle.network_id, &drain);
    let mut transition = GatewayAssignmentTransitionV1 {
        core_protocol_version: CORE_V2,
        handoff_version: GATEWAY_HANDOFF_V1,
        network_id: bundle.network_id,
        context_manifest_id: next_bundle.manifest.object_id(),
        gateway_pubkey: gateway_signing_key.verifying_key().to_bytes(),
        core_handoff_pubkey: next_bundle.assignment.core_handoff_pubkey,
        transition_sequence: next_bundle.assignment.assignment_sequence,
        previous_assignment_id: bundle.assignment.object_id(),
        next_assignment_id: next_bundle.assignment.object_id(),
        previous_assignment_last_gateway_sequence: sequence_head.sequence,
        transition_ms: replacement.credit_cutoff_ms,
        reason_code: replacement.reason_code,
        gateway_signature: SignatureBytes::empty(),
    };
    transition.gateway_signature = sign_object(gateway_signing_key, bundle.network_id, &transition);
    Ok((drain, transition))
}

#[cfg(test)]
mod tests {
    use meshmine_gateway::TelemetryLevel;
    use meshmine_hns::MinerHeader;
    use meshmine_types::{
        GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16,
        GATEWAY_OBSERVATION_CORE_RECEIPT_TIME, U256,
    };

    use super::*;

    fn assignment_and_capture() -> (GatewayAssignmentV1, ForwardedCapture) {
        let assignment = GatewayAssignmentV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: 2,
            session_id: [1; 32],
            body_package_id: [2; 32],
            body_certificate_id: [3; 32],
            operator_pubkey: [4; 32],
            gateway_pubkey: [5; 32],
            core_handoff_pubkey: [6; 32],
            worker_id_hash: [7; 32],
            payout_bucket_id: [8; 32],
            assignment_sequence: 9,
            ntime: 100,
            extra_nonce_profile: GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16,
            observation_policy: GATEWAY_OBSERVATION_CORE_RECEIPT_TIME,
            maximum_clock_skew_ms: 0,
            extra_nonce_prefix: [10, 11, 12, 13],
            extra_nonce2_start_be: 1u32.to_be_bytes(),
            extra_nonce2_end_be: 2u32.to_be_bytes(),
            nonce_start: 10,
            nonce_end: 20,
            nonce_stride: 2,
            edge_target: U256([0xff; 32]),
            capture_target: U256([0xff; 32]),
            telemetry_level: TelemetryLevel::StockAsic as u8,
            operator_signature: SignatureBytes::empty(),
        };
        let mut extra_nonce = [0; 24];
        extra_nonce[..4].copy_from_slice(&assignment.extra_nonce_prefix);
        extra_nonce[4..8].copy_from_slice(&1u32.to_be_bytes());
        let miner_header = MinerHeader {
            nonce: 12,
            time: assignment.ntime,
            prev_block: [20; 32],
            tree_root: [21; 32],
            mask_hash: [22; 32],
            extra_nonce,
            reserved_root: [23; 32],
            witness_root: [24; 32],
            merkle_root: [25; 32],
            version: 1,
            bits: 0x207f_ffff,
        };
        let capture = ForwardedCapture {
            username: "operator.worker".to_owned(),
            job_id: hex::encode(assignment.object_id()),
            assignment_sequence: assignment.assignment_sequence,
            raw_share_hash: miner_header.share_hash(),
            miner_header,
            received_ms: 150,
            credit_eligible: true,
            telemetry_level: TelemetryLevel::StockAsic,
        };
        (assignment, capture)
    }

    fn refresh_hash(capture: &mut ForwardedCapture) {
        capture.raw_share_hash = capture.miner_header.share_hash();
    }

    #[test]
    fn spool_rechecks_every_signed_miner_selected_assignment_field() {
        let (assignment, capture) = assignment_and_capture();
        validate_capture_assignment(&capture, &assignment).unwrap();

        let mut wrong_prefix = capture.clone();
        wrong_prefix.miner_header.extra_nonce[0] ^= 1;
        refresh_hash(&mut wrong_prefix);
        assert!(matches!(
            validate_capture_assignment(&wrong_prefix, &assignment),
            Err(SpoolError::Assignment)
        ));

        let mut wrong_nonce2 = capture.clone();
        wrong_nonce2.miner_header.extra_nonce[4..8].copy_from_slice(&3u32.to_be_bytes());
        refresh_hash(&mut wrong_nonce2);
        assert!(matches!(
            validate_capture_assignment(&wrong_nonce2, &assignment),
            Err(SpoolError::Assignment)
        ));

        let mut malformed_tail = capture.clone();
        malformed_tail.miner_header.extra_nonce[23] = 1;
        refresh_hash(&mut malformed_tail);
        assert!(matches!(
            validate_capture_assignment(&malformed_tail, &assignment),
            Err(SpoolError::Assignment)
        ));

        let mut wrong_stride = capture.clone();
        wrong_stride.miner_header.nonce = 13;
        refresh_hash(&mut wrong_stride);
        assert!(matches!(
            validate_capture_assignment(&wrong_stride, &assignment),
            Err(SpoolError::Assignment)
        ));

        let mut wrong_telemetry = capture.clone();
        wrong_telemetry.telemetry_level = TelemetryLevel::ObservableController;
        assert!(matches!(
            validate_capture_assignment(&wrong_telemetry, &assignment),
            Err(SpoolError::Assignment)
        ));

        let mut forged_hash = capture;
        forged_hash.raw_share_hash[0] ^= 1;
        assert!(matches!(
            validate_capture_assignment(&forged_hash, &assignment),
            Err(SpoolError::Assignment)
        ));
    }
}
