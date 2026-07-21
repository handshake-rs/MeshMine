//! Core-side durable assignment activation and gateway-capture admission.
//!
//! This module composes the existing immutable handoff journal with exact
//! `ShareV2` validation. It is intentionally fail-closed: a bundle is never
//! made active unless its complete signed context validates, and a capture is
//! never acknowledged as accepted unless the gateway evidence, globally
//! deduplicated work key, and signed share commit in one durable transaction.

use ed25519_dalek::SigningKey;
use meshmine_codec::{CanonicalDecode, CanonicalEncode, CodecError, DecodeLimits};
use meshmine_crypto::sign_object;
use meshmine_handoff::{
    CAPTURE_OUTCOME_ACCEPTED, CAPTURE_OUTCOME_DUPLICATE, CAPTURE_OUTCOME_REJECTED,
    CoreAssignmentDrainReceiptV1, DRAIN_OUTCOME_COMPLETE, GatewayAssignmentDrainV1,
    GatewayAssignmentTransitionV1, GatewayCaptureEnvelopeV1, GatewayCaptureReceiptV1, HandoffError,
    persist_gateway_assignment_authorization, persist_gateway_assignment_drain,
    persist_gateway_assignment_transition, persist_gateway_context_manifest,
    persist_noncredit_capture_disposition, validate_capture_receipt, validate_core_drain_receipt,
};
use meshmine_hns::Hash256;
use meshmine_share::{
    GatewayShareValidationContext, ParentChainOracle, ReceiptBuilder, ShareError,
    validate_gateway_share,
};
use meshmine_storage::{
    BatchCondition, BatchOperation, DurableInvariantError, DurableStore, JournalBatchOutcome,
    ProtocolJournal, ProtocolRecordKind, StorageError,
};
use meshmine_types::{CORE_V2, GATEWAY_HANDOFF_V1, ShareV2, SignatureBytes, U512, UnsignedObject};
use thiserror::Error;

use crate::CoreAssignmentBundleV1;

pub const CORE_BUNDLE_NAMESPACE: &str = "core-link-core-bundle/v1";
pub const CORE_BUNDLE_ASSIGNMENT_INDEX_NAMESPACE: &str =
    "core-link-core-bundle-assignment-index/v1";
pub const CORE_BUNDLE_STATE_NAMESPACE: &str = "core-link-core-bundle-state/v1";
pub const CORE_BUNDLE_ACTIVE_KEY: &str = "active";
pub const CORE_BUNDLE_PENDING_KEY: &str = "pending";

pub const CAPTURE_REASON_VALIDATED: u16 = 0;
pub const CAPTURE_REASON_DUPLICATE_WORK: u16 = 1;
pub const CAPTURE_REASON_SHARE_LINKAGE: u16 = 2;
pub const CAPTURE_REASON_CAPTURE_TARGET: u16 = 3;
pub const CAPTURE_REASON_PARENT_ORACLE: u16 = 4;
pub const CAPTURE_REASON_SESSION_WINDOW: u16 = 5;
pub const CAPTURE_REASON_SIGNATURE: u16 = 6;
pub const CAPTURE_REASON_CONTEXT: u16 = 7;
pub const CAPTURE_REASON_OTHER: u16 = u16::MAX;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureAdmission {
    pub receipt: GatewayCaptureReceiptV1,
    pub accepted_share_id: Option<Hash256>,
    pub exact_retry: bool,
}

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("Core-link bundle validation failed: {0}")]
    Bundle(#[from] crate::BundleError),
    #[error("gateway handoff admission failed: {0}")]
    Handoff(#[from] HandoffError),
    #[error("share admission failed: {0}")]
    Share(#[from] ShareError),
    #[error("durable Core-link storage failed: {0}")]
    Storage(#[from] StorageError),
    #[error("durable Core-link invariant failed: {0}")]
    Durable(#[from] DurableInvariantError),
    #[error("Core-link canonical decoding failed: {0}")]
    Codec(#[from] CodecError),
    #[error("Core-link identity or sequence binding is invalid")]
    Identity,
    #[error("the locally configured HNS parent oracle rejected the bundle parent")]
    ParentOracle,
    #[error("no active Core assignment bundle exists")]
    NoActiveBundle,
    #[error("no pending Core assignment bundle exists")]
    NoPendingBundle,
    #[error("capture references an unknown assignment")]
    UnknownAssignment,
    #[error("Core assignment state changed concurrently")]
    StateRace,
}

pub struct CoreAdmissionEngine<'a> {
    store: &'a dyn DurableStore,
    network_id: u8,
    core_signing_key: &'a SigningKey,
    operator_signing_key: &'a SigningKey,
    parent_oracle: &'a dyn ParentChainOracle,
}

impl<'a> CoreAdmissionEngine<'a> {
    pub fn new(
        store: &'a dyn DurableStore,
        network_id: u8,
        core_signing_key: &'a SigningKey,
        operator_signing_key: &'a SigningKey,
        parent_oracle: &'a dyn ParentChainOracle,
    ) -> Self {
        Self {
            store,
            network_id,
            core_signing_key,
            operator_signing_key,
            parent_oracle,
        }
    }

    pub fn stage_bundle(
        &self,
        bundle: &CoreAssignmentBundleV1,
        now_ms: u64,
    ) -> Result<(), AdmissionError> {
        self.validate_local_bundle(bundle, now_ms)?;
        let bundle_id = bundle.object_id();
        let bundle_key = hex::encode(bundle_id);
        let assignment_key = hex::encode(bundle.assignment.object_id());
        let bytes = bundle.to_canonical_bytes();

        let existing_bundle = self.store.get(CORE_BUNDLE_NAMESPACE, &bundle_key)?;
        let existing_index = self
            .store
            .get(CORE_BUNDLE_ASSIGNMENT_INDEX_NAMESPACE, &assignment_key)?;
        if existing_bundle.as_deref() == Some(bytes.as_slice())
            && existing_index.as_deref() == Some(bundle_id.as_slice())
        {
            return self.install_or_mark_pending(bundle, now_ms);
        }
        if existing_bundle.is_some() || existing_index.is_some() {
            return Err(AdmissionError::Identity);
        }
        if !self.store.apply_batch_if_all(
            &[
                BatchCondition::absent(CORE_BUNDLE_NAMESPACE, &bundle_key),
                BatchCondition::absent(CORE_BUNDLE_ASSIGNMENT_INDEX_NAMESPACE, &assignment_key),
            ],
            &[
                BatchOperation::put(CORE_BUNDLE_NAMESPACE, bundle_key, bytes),
                BatchOperation::put(
                    CORE_BUNDLE_ASSIGNMENT_INDEX_NAMESPACE,
                    assignment_key,
                    bundle_id.to_vec(),
                ),
            ],
        )? {
            return Err(AdmissionError::StateRace);
        }
        self.install_or_mark_pending(bundle, now_ms)
    }

    pub fn active_bundle(&self) -> Result<Option<CoreAssignmentBundleV1>, AdmissionError> {
        self.load_state_bundle(CORE_BUNDLE_ACTIVE_KEY)
    }

    pub fn pending_bundle(&self) -> Result<Option<CoreAssignmentBundleV1>, AdmissionError> {
        self.load_state_bundle(CORE_BUNDLE_PENDING_KEY)
    }

    pub fn bundle_for_assignment(
        &self,
        assignment_id: Hash256,
    ) -> Result<CoreAssignmentBundleV1, AdmissionError> {
        let bundle_id = self
            .store
            .get(
                CORE_BUNDLE_ASSIGNMENT_INDEX_NAMESPACE,
                &hex::encode(assignment_id),
            )?
            .ok_or(AdmissionError::UnknownAssignment)?;
        if bundle_id.len() != 32 {
            return Err(AdmissionError::Identity);
        }
        self.load_bundle_bytes(&bundle_id)
    }

    pub fn admit_capture(
        &self,
        envelope: &GatewayCaptureEnvelopeV1,
        core_received_ms: u64,
    ) -> Result<CaptureAdmission, AdmissionError> {
        let journal = ProtocolJournal::new(self.store);
        if let Some(bytes) = journal.load(
            ProtocolRecordKind::GatewayCaptureReceipt,
            &envelope.object_id(),
        )? {
            let receipt = GatewayCaptureReceiptV1::from_canonical_bytes(
                &bytes,
                DecodeLimits {
                    max_object_bytes: 4096,
                    max_vector_items: 0,
                },
            )?;
            validate_capture_receipt(envelope, &receipt)?;
            return Ok(CaptureAdmission {
                accepted_share_id: (receipt.outcome == CAPTURE_OUTCOME_ACCEPTED)
                    .then_some(receipt.accepted_share_id),
                receipt,
                exact_retry: true,
            });
        }

        let bundle = self.bundle_for_assignment(envelope.assignment_id)?;
        self.validate_local_bundle(&bundle, core_received_ms)?;
        let mut share = ShareV2 {
            protocol_version: CORE_V2,
            network_id: self.network_id,
            session_id: bundle.session.object_id(),
            assignment_id: bundle.assignment.object_id(),
            body_package_id: bundle.body.object_id(),
            operator_pubkey: self.operator_signing_key.verifying_key().to_bytes(),
            payout_bucket_id: bundle.payout_bucket.object_id(),
            nonce: envelope.nonce,
            ntime: envelope.ntime,
            extra_nonce: envelope.extra_nonce,
            raw_share_hash: envelope.raw_share_hash,
            declared_target: bundle.assignment.capture_target,
            gossip_parent_hashes: Vec::new(),
            local_telemetry_hash: Some(envelope.object_id()),
            operator_signature: SignatureBytes::empty(),
        };
        share.operator_signature = sign_object(self.operator_signing_key, self.network_id, &share);
        let context = GatewayShareValidationContext {
            assignment: &bundle.assignment,
            context_manifest: &bundle.manifest,
            capture_envelope: envelope,
            session: &bundle.session,
            parent_certificate: &bundle.parent_certificate,
            body: &bundle.body,
            descriptor: &bundle.descriptor,
            body_certificate: &bundle.body_certificate,
            payout_bucket: &bundle.payout_bucket,
            mask_roster: &bundle.mask_roster,
            availability_roster: &bundle.availability_roster,
            settlement_roster: &bundle.settlement_roster,
            core_received_ms,
            parent_oracle: self.parent_oracle,
        };

        match validate_gateway_share(share, &context) {
            Ok(validated) => {
                let share_id = validated.share_id;
                let accepted = self.capture_receipt(
                    &bundle,
                    envelope,
                    core_received_ms,
                    CAPTURE_OUTCOME_ACCEPTED,
                    CAPTURE_REASON_VALIDATED,
                    share_id,
                );
                let mut builder = ReceiptBuilder::new(
                    CORE_V2,
                    self.network_id,
                    bundle.session.object_id(),
                    1,
                    [0; 32],
                    0,
                    U512([0; 64]),
                );
                match builder.accept_gateway_durable(
                    validated,
                    &bundle.manifest,
                    &bundle.assignment,
                    envelope,
                    &accepted,
                    self.store,
                ) {
                    Ok(()) => Ok(CaptureAdmission {
                        receipt: accepted,
                        accepted_share_id: Some(share_id),
                        exact_retry: false,
                    }),
                    Err(ShareError::DuplicateWork) => self.persist_noncredit(
                        &bundle,
                        envelope,
                        core_received_ms,
                        CAPTURE_OUTCOME_DUPLICATE,
                        CAPTURE_REASON_DUPLICATE_WORK,
                    ),
                    Err(error) => Err(error.into()),
                }
            }
            Err(error) => {
                let reason = share_reason(&error);
                self.persist_noncredit(
                    &bundle,
                    envelope,
                    core_received_ms,
                    if matches!(error, ShareError::DuplicateWork) {
                        CAPTURE_OUTCOME_DUPLICATE
                    } else {
                        CAPTURE_OUTCOME_REJECTED
                    },
                    reason,
                )
            }
        }
    }

    pub fn complete_pending_transition(
        &self,
        drain: &GatewayAssignmentDrainV1,
        transition: &GatewayAssignmentTransitionV1,
        core_received_ms: u64,
    ) -> Result<CoreAssignmentDrainReceiptV1, AdmissionError> {
        let active = self
            .active_bundle()?
            .ok_or(AdmissionError::NoActiveBundle)?;
        let pending = self
            .pending_bundle()?
            .ok_or(AdmissionError::NoPendingBundle)?;
        let replacement = pending
            .replacement
            .as_ref()
            .ok_or(AdmissionError::Identity)?;
        if drain.assignment_id != active.assignment.object_id()
            || replacement.previous_assignment_id != active.assignment.object_id()
            || transition.previous_assignment_id != active.assignment.object_id()
            || transition.next_assignment_id != pending.assignment.object_id()
        {
            return Err(AdmissionError::Identity);
        }

        persist_gateway_assignment_drain(self.store, &active.manifest, drain)?;
        let mut receipt = CoreAssignmentDrainReceiptV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: self.network_id,
            context_manifest_id: active.manifest.object_id(),
            assignment_id: active.assignment.object_id(),
            gateway_drain_id: drain.object_id(),
            gateway_pubkey: active.assignment.gateway_pubkey,
            core_handoff_pubkey: self.core_signing_key.verifying_key().to_bytes(),
            accepted_through_gateway_sequence: drain.last_gateway_sequence,
            receipt_sequence: pending.assignment.assignment_sequence,
            core_received_ms,
            outcome: DRAIN_OUTCOME_COMPLETE,
            reason_code: 0,
            core_signature: SignatureBytes::empty(),
        };
        receipt.core_signature = sign_object(self.core_signing_key, self.network_id, &receipt);
        validate_core_drain_receipt(&active.manifest, drain, &receipt)?;
        ProtocolJournal::new(self.store).persist(
            ProtocolRecordKind::CoreAssignmentDrainReceipt,
            &active.assignment.object_id(),
            &receipt.to_canonical_bytes(),
        )?;

        persist_gateway_context_manifest(self.store, &pending.manifest, core_received_ms)?;
        persist_gateway_assignment_transition(
            self.store,
            &pending.manifest,
            &pending.assignment,
            transition,
        )?;

        let active_id = active.object_id();
        let pending_id = pending.object_id();
        if !self.store.apply_batch_if_all(
            &[
                BatchCondition::equals(
                    CORE_BUNDLE_STATE_NAMESPACE,
                    CORE_BUNDLE_ACTIVE_KEY,
                    active_id.to_vec(),
                ),
                BatchCondition::equals(
                    CORE_BUNDLE_STATE_NAMESPACE,
                    CORE_BUNDLE_PENDING_KEY,
                    pending_id.to_vec(),
                ),
            ],
            &[
                BatchOperation::put(
                    CORE_BUNDLE_STATE_NAMESPACE,
                    CORE_BUNDLE_ACTIVE_KEY,
                    pending_id.to_vec(),
                ),
                BatchOperation::delete(CORE_BUNDLE_STATE_NAMESPACE, CORE_BUNDLE_PENDING_KEY),
            ],
        )? {
            let current = self.active_bundle()?;
            if current.as_ref().map(|bundle| bundle.object_id()) != Some(pending_id) {
                return Err(AdmissionError::StateRace);
            }
        }
        Ok(receipt)
    }

    fn validate_local_bundle(
        &self,
        bundle: &CoreAssignmentBundleV1,
        now_ms: u64,
    ) -> Result<(), AdmissionError> {
        if bundle.network_id != self.network_id
            || bundle.assignment.core_handoff_pubkey
                != self.core_signing_key.verifying_key().to_bytes()
            || bundle.assignment.operator_pubkey
                != self.operator_signing_key.verifying_key().to_bytes()
        {
            return Err(AdmissionError::Identity);
        }
        bundle.validate(now_ms, &self.core_signing_key.verifying_key().to_bytes())?;
        if !self
            .parent_oracle
            .verify_header_and_chainwork(&bundle.parent_certificate)
        {
            return Err(AdmissionError::ParentOracle);
        }
        Ok(())
    }

    fn install_or_mark_pending(
        &self,
        bundle: &CoreAssignmentBundleV1,
        now_ms: u64,
    ) -> Result<(), AdmissionError> {
        match self.active_bundle()? {
            None => {
                if bundle.assignment.assignment_sequence != 1 || bundle.replacement.is_some() {
                    return Err(AdmissionError::Identity);
                }
                persist_gateway_context_manifest(self.store, &bundle.manifest, now_ms)?;
                persist_gateway_assignment_authorization(
                    self.store,
                    &bundle.manifest,
                    &bundle.assignment,
                )?;
                if !self.store.compare_and_swap(
                    CORE_BUNDLE_STATE_NAMESPACE,
                    CORE_BUNDLE_ACTIVE_KEY,
                    None,
                    &bundle.object_id(),
                )? {
                    let active = self.active_bundle()?;
                    if active.as_ref().map(|bundle| bundle.object_id()) != Some(bundle.object_id())
                    {
                        return Err(AdmissionError::StateRace);
                    }
                }
                Ok(())
            }
            Some(active) if active.object_id() == bundle.object_id() => Ok(()),
            Some(active) => {
                let replacement = bundle
                    .replacement
                    .as_ref()
                    .ok_or(AdmissionError::Identity)?;
                if replacement.previous_assignment_id != active.assignment.object_id()
                    || bundle.previous_bundle_id != active.object_id()
                    || bundle.assignment.assignment_sequence
                        != active
                            .assignment
                            .assignment_sequence
                            .checked_add(1)
                            .ok_or(AdmissionError::Identity)?
                {
                    return Err(AdmissionError::Identity);
                }
                let pending = self.pending_bundle()?;
                if let Some(existing) = pending {
                    if existing.object_id() == bundle.object_id() {
                        return Ok(());
                    }
                    return Err(AdmissionError::Identity);
                }
                if !self.store.compare_and_swap(
                    CORE_BUNDLE_STATE_NAMESPACE,
                    CORE_BUNDLE_PENDING_KEY,
                    None,
                    &bundle.object_id(),
                )? {
                    return Err(AdmissionError::StateRace);
                }
                Ok(())
            }
        }
    }

    fn persist_noncredit(
        &self,
        bundle: &CoreAssignmentBundleV1,
        envelope: &GatewayCaptureEnvelopeV1,
        core_received_ms: u64,
        outcome: u8,
        reason_code: u16,
    ) -> Result<CaptureAdmission, AdmissionError> {
        let receipt = self.capture_receipt(
            bundle,
            envelope,
            core_received_ms,
            outcome,
            reason_code,
            [0; 32],
        );
        match persist_noncredit_capture_disposition(
            self.store,
            &bundle.manifest,
            &bundle.assignment,
            envelope,
            &receipt,
        )? {
            JournalBatchOutcome::Committed | JournalBatchOutcome::ExactRecord => {
                Ok(CaptureAdmission {
                    receipt,
                    accepted_share_id: None,
                    exact_retry: false,
                })
            }
            JournalBatchOutcome::PreconditionMismatch => Err(AdmissionError::StateRace),
        }
    }

    fn capture_receipt(
        &self,
        bundle: &CoreAssignmentBundleV1,
        envelope: &GatewayCaptureEnvelopeV1,
        core_received_ms: u64,
        outcome: u8,
        reason_code: u16,
        accepted_share_id: Hash256,
    ) -> GatewayCaptureReceiptV1 {
        let mut receipt = GatewayCaptureReceiptV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id: self.network_id,
            context_manifest_id: bundle.manifest.object_id(),
            assignment_id: bundle.assignment.object_id(),
            capture_envelope_id: envelope.object_id(),
            gateway_pubkey: bundle.assignment.gateway_pubkey,
            core_handoff_pubkey: self.core_signing_key.verifying_key().to_bytes(),
            receipt_sequence: envelope.gateway_sequence,
            core_received_ms,
            outcome,
            reason_code,
            accepted_share_id,
            core_signature: SignatureBytes::empty(),
        };
        receipt.core_signature = sign_object(self.core_signing_key, self.network_id, &receipt);
        receipt
    }

    fn load_state_bundle(
        &self,
        state_key: &str,
    ) -> Result<Option<CoreAssignmentBundleV1>, AdmissionError> {
        let Some(bundle_id) = self.store.get(CORE_BUNDLE_STATE_NAMESPACE, state_key)? else {
            return Ok(None);
        };
        Ok(Some(self.load_bundle_bytes(&bundle_id)?))
    }

    fn load_bundle_bytes(
        &self,
        bundle_id: &[u8],
    ) -> Result<CoreAssignmentBundleV1, AdmissionError> {
        if bundle_id.len() != 32 {
            return Err(AdmissionError::Identity);
        }
        let bytes = self
            .store
            .get(CORE_BUNDLE_NAMESPACE, &hex::encode(bundle_id))?
            .ok_or(AdmissionError::Identity)?;
        let bundle = CoreAssignmentBundleV1::from_canonical_bytes(
            &bytes,
            DecodeLimits {
                max_object_bytes: crate::MAX_CORE_ASSIGNMENT_BUNDLE_BYTES,
                max_vector_items: 100_000,
            },
        )?;
        let mut expected_bundle_id = [0u8; 32];
        expected_bundle_id.copy_from_slice(bundle_id);
        if bundle.object_id() != expected_bundle_id || bundle.to_canonical_bytes() != bytes {
            return Err(AdmissionError::Identity);
        }
        Ok(bundle)
    }
}

fn share_reason(error: &ShareError) -> u16 {
    match error {
        ShareError::DuplicateWork => CAPTURE_REASON_DUPLICATE_WORK,
        ShareError::CaptureTarget | ShareError::RawShareHash => CAPTURE_REASON_CAPTURE_TARGET,
        ShareError::ParentOracleRejected => CAPTURE_REASON_PARENT_ORACLE,
        ShareError::SessionNotOpen => CAPTURE_REASON_SESSION_WINDOW,
        ShareError::OperatorSignature(_) => CAPTURE_REASON_SIGNATURE,
        ShareError::GatewayHandoff(_) => CAPTURE_REASON_CONTEXT,
        ShareError::Linkage(_) => CAPTURE_REASON_SHARE_LINKAGE,
        _ => CAPTURE_REASON_OTHER,
    }
}
