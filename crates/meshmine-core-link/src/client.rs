//! Operator-side authenticated Core-link client and gateway capture adapter.

use std::collections::VecDeque;

use ed25519_dalek::SigningKey;
use meshmine_crypto::{sign_object, verify_object};
use meshmine_gateway::{DurableCaptureConsumer, ForwardedCapture};
use meshmine_handoff::{
    CAPTURE_OUTCOME_ACCEPTED, CAPTURE_OUTCOME_DUPLICATE, CAPTURE_OUTCOME_GRACE_NONCREDIT,
    CAPTURE_OUTCOME_REJECTED, validate_core_drain_receipt,
};
use meshmine_hns::Hash256;
use meshmine_types::{ED25519_SUITE, SignatureBytes, UnsignedObject};
use thiserror::Error;

use crate::{
    AssignmentAckV1, CORE_LINK_PROTOCOL_V1, CaptureSubmissionV1, CoreAssignmentBundleV1,
    CoreLinkConnection, CoreLinkMessage, DrainRequiredV1, DrainSubmissionV1, OperatorCaptureSpool,
    ProtocolError, SpoolError, TransportError, build_drain_and_transition,
};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Core-link transport failed: {0}")]
    Transport(#[from] TransportError),
    #[error("Core-link protocol failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("operator capture spool failed: {0}")]
    Spool(#[from] SpoolError),
    #[error("Core sent an invalid signed object")]
    Signature,
    #[error("Core-link request/response identity mismatch")]
    Request,
    #[error("Core rejected the request: {0}")]
    Remote(String),
    #[error("capture disposition is not terminal")]
    Disposition,
    #[error("assignment drain cannot complete while captures remain pending")]
    PendingCaptures,
}

pub struct OperatorCoreLinkClient<'a> {
    connection: CoreLinkConnection,
    spool: OperatorCaptureSpool<'a>,
    gateway_signing_key: &'a SigningKey,
    pinned_core_pubkey: [u8; 32],
    offers: VecDeque<CoreAssignmentBundleV1>,
    drain_required: Option<DrainRequiredV1>,
}

impl<'a> OperatorCoreLinkClient<'a> {
    pub fn new(
        connection: CoreLinkConnection,
        spool: OperatorCaptureSpool<'a>,
        gateway_signing_key: &'a SigningKey,
        pinned_core_pubkey: [u8; 32],
    ) -> Self {
        Self {
            connection,
            spool,
            gateway_signing_key,
            pinned_core_pubkey,
            offers: VecDeque::new(),
            drain_required: None,
        }
    }

    pub fn connection_id(&self) -> Hash256 {
        self.connection.connection_id()
    }

    pub fn receive_one(&mut self) -> Result<(), ClientError> {
        let message = self.connection.receive()?;
        self.handle_unsolicited(message)
    }

    pub fn next_offer(&mut self) -> Option<CoreAssignmentBundleV1> {
        self.offers.pop_front()
    }

    pub fn pending_drain(&self) -> Option<&DrainRequiredV1> {
        self.drain_required.as_ref()
    }

    pub fn acknowledge_offer(
        &mut self,
        bundle: &CoreAssignmentBundleV1,
        accepted_at_ms: u64,
    ) -> Result<(), ClientError> {
        bundle
            .validate(accepted_at_ms, &self.pinned_core_pubkey)
            .map_err(|_| ClientError::Signature)?;
        self.spool.persist_bundle(bundle)?;
        let mut ack = AssignmentAckV1 {
            link_protocol_version: CORE_LINK_PROTOCOL_V1,
            network_id: bundle.network_id,
            bundle_id: bundle.object_id(),
            assignment_id: bundle.assignment.object_id(),
            gateway_pubkey: self.gateway_signing_key.verifying_key().to_bytes(),
            accepted_at_ms,
            gateway_signature: SignatureBytes::empty(),
        };
        ack.gateway_signature = sign_object(self.gateway_signing_key, bundle.network_id, &ack);
        self.connection.send(&CoreLinkMessage::AssignmentAck(ack))?;
        Ok(())
    }

    pub fn complete_drain(
        &mut self,
        current: &CoreAssignmentBundleV1,
        next: &CoreAssignmentBundleV1,
        drained_ms: u64,
    ) -> Result<(), ClientError> {
        let required = self.drain_required.clone().ok_or(ClientError::Request)?;
        if required.current_assignment_id != current.assignment.object_id()
            || required.next_bundle_id != next.object_id()
            || required.next_assignment_id != next.assignment.object_id()
        {
            return Err(ClientError::Request);
        }
        if self
            .spool
            .pending_for_assignment(current.assignment.object_id())?
            != 0
        {
            return Err(ClientError::PendingCaptures);
        }
        let head = self.spool.sequence_head(current.assignment.object_id())?;
        let (drain, transition) =
            build_drain_and_transition(current, next, head, self.gateway_signing_key, drained_ms)?;
        self.spool
            .persist_drain_and_transition(&drain, &transition)?;
        let request_id = request_id(
            self.connection.connection_id(),
            drain.object_id(),
            next.object_id(),
        );
        self.connection
            .send(&CoreLinkMessage::DrainSubmission(DrainSubmissionV1 {
                link_protocol_version: CORE_LINK_PROTOCOL_V1,
                network_id: current.network_id,
                request_id,
                next_bundle_id: next.object_id(),
                drain: drain.clone(),
                transition,
            }))?;
        loop {
            match self.connection.receive()? {
                CoreLinkMessage::DrainDisposition(disposition)
                    if disposition.request_id == request_id =>
                {
                    validate_core_drain_receipt(&current.manifest, &drain, &disposition.receipt)
                        .map_err(|_| ClientError::Signature)?;
                    if disposition.receipt.core_handoff_pubkey != self.pinned_core_pubkey {
                        return Err(ClientError::Signature);
                    }
                    self.drain_required = None;
                    return Ok(());
                }
                CoreLinkMessage::Error(error) if error.request_id == request_id => {
                    return Err(ClientError::Remote(error.message));
                }
                other => self.handle_unsolicited(other)?,
            }
        }
    }

    fn submit_capture(&mut self, capture: &ForwardedCapture) -> Result<Hash256, ClientError> {
        if let Some(receipt) = self.spool.receipt(capture.work_key())? {
            return terminal_receipt_id(&receipt);
        }
        let envelope = self.spool.prepare_envelope(capture)?;
        let request_id = request_id(
            self.connection.connection_id(),
            envelope.object_id(),
            capture.work_key(),
        );
        self.connection
            .send(&CoreLinkMessage::CaptureSubmission(CaptureSubmissionV1 {
                link_protocol_version: CORE_LINK_PROTOCOL_V1,
                network_id: envelope.network_id,
                request_id,
                envelope: envelope.clone(),
            }))?;
        loop {
            match self.connection.receive()? {
                CoreLinkMessage::CaptureDisposition(disposition)
                    if disposition.request_id == request_id =>
                {
                    if disposition.receipt.capture_envelope_id != envelope.object_id()
                        || disposition.receipt.core_handoff_pubkey != self.pinned_core_pubkey
                    {
                        return Err(ClientError::Request);
                    }
                    verify_object(
                        &self.pinned_core_pubkey,
                        ED25519_SUITE,
                        &disposition.receipt.core_signature,
                        disposition.receipt.network_id,
                        &disposition.receipt,
                    )
                    .map_err(|_| ClientError::Signature)?;
                    self.spool.record_receipt(
                        capture.work_key(),
                        &envelope,
                        &disposition.receipt,
                    )?;
                    return terminal_receipt_id(&disposition.receipt);
                }
                CoreLinkMessage::Error(error) if error.request_id == request_id => {
                    return Err(ClientError::Remote(error.message));
                }
                other => self.handle_unsolicited(other)?,
            }
        }
    }

    fn handle_unsolicited(&mut self, message: CoreLinkMessage) -> Result<(), ClientError> {
        match message {
            CoreLinkMessage::AssignmentOffer(bundle) => {
                self.offers.push_back(bundle);
                Ok(())
            }
            CoreLinkMessage::DrainRequired(required) => {
                self.drain_required = Some(required);
                Ok(())
            }
            CoreLinkMessage::Heartbeat(_) => Ok(()),
            CoreLinkMessage::Error(error) if error.request_id == [0; 32] => {
                Err(ClientError::Remote(error.message))
            }
            _ => Err(ClientError::Request),
        }
    }
}

impl DurableCaptureConsumer for OperatorCoreLinkClient<'_> {
    fn admit_capture(&mut self, capture: &ForwardedCapture) -> Result<Hash256, String> {
        self.submit_capture(capture)
            .map_err(|error| error.to_string())
    }
}

fn terminal_receipt_id(
    receipt: &meshmine_handoff::GatewayCaptureReceiptV1,
) -> Result<Hash256, ClientError> {
    if matches!(
        receipt.outcome,
        CAPTURE_OUTCOME_ACCEPTED
            | CAPTURE_OUTCOME_REJECTED
            | CAPTURE_OUTCOME_GRACE_NONCREDIT
            | CAPTURE_OUTCOME_DUPLICATE
    ) {
        Ok(receipt.object_id())
    } else {
        Err(ClientError::Disposition)
    }
}

fn request_id(connection_id: Hash256, first: Hash256, second: Hash256) -> Hash256 {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(&connection_id);
    bytes.extend_from_slice(&first);
    bytes.extend_from_slice(&second);
    meshmine_types::domain_hash("meshmine/core-link-request/v1", &bytes)
}
