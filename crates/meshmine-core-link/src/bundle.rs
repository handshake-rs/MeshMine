use std::collections::BTreeSet;

use meshmine_body::{validate_body_package, validation_result_hash};
use meshmine_codec::{CanonicalDecode, CanonicalEncode, CodecError, Decoder, Encoder};
use meshmine_crypto::{CryptoError, verify_object};
use meshmine_gateway::{
    GatewayError, GatewayJob, PreviousJobTransition, gateway_assignment_job_id,
    handy_target_from_difficulty,
};
use meshmine_handoff::{
    GatewayContextManifestV1, HandoffError, validate_context_manifest, validate_gateway_assignment,
};
use meshmine_hns::{Hash256, derive_capture_parameters};
use meshmine_share::{CommitteeRole, CommitteeRoster, MAX_COMMITTEE_MEMBERS, ShareError};
use meshmine_types::{
    BlockBodyPackageV2, BodyAvailabilityCertificateV2, BodyErasureDescriptorV2, CORE_V2,
    ED25519_SUITE, GATEWAY_HANDOFF_V1, GatewayAssignmentV1, MaskSessionV2, PayoutBucketV2,
    SessionParentCertificateV2, SignatureBytes, UnsignedObject,
};
use thiserror::Error;

pub const CORE_ASSIGNMENT_BUNDLE_V1: u16 = 1;
pub const MAX_CORE_ASSIGNMENT_BUNDLE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_BUNDLE_COMMITTEE_MEMBERS: usize = MAX_COMMITTEE_MEMBERS;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignmentReplacementV1 {
    pub previous_assignment_id: Hash256,
    pub credit_cutoff_ms: u64,
    pub previous_submission_end_ms: u64,
    pub reason_code: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreAssignmentBundleV1 {
    pub bundle_version: u16,
    pub network_id: u8,
    pub bundle_sequence: u64,
    pub previous_bundle_id: Hash256,
    pub manifest: GatewayContextManifestV1,
    pub assignment: GatewayAssignmentV1,
    pub session: MaskSessionV2,
    pub parent_certificate: SessionParentCertificateV2,
    pub body: BlockBodyPackageV2,
    pub descriptor: BodyErasureDescriptorV2,
    pub body_certificate: BodyAvailabilityCertificateV2,
    pub payout_bucket: PayoutBucketV2,
    pub mask_roster: CommitteeRoster,
    pub availability_roster: CommitteeRoster,
    pub settlement_roster: CommitteeRoster,
    pub advertised_difficulty: u32,
    pub replacement: Option<AssignmentReplacementV1>,
    pub core_signature: SignatureBytes,
}

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("bundle canonical encoding failed: {0}")]
    Codec(#[from] CodecError),
    #[error("bundle signature failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("gateway authorization failed: {0}")]
    Handoff(#[from] HandoffError),
    #[error("gateway job binding failed: {0}")]
    Gateway(#[from] GatewayError),
    #[error("share-context certificate or roster failed: {0}")]
    Share(#[from] ShareError),
    #[error("body package failed structural validation")]
    Body,
    #[error("assignment bundle linkage is invalid: {0}")]
    Linkage(&'static str),
}

impl UnsignedObject for CoreAssignmentBundleV1 {
    const DOMAIN_TAG: &'static str = "meshmine/core-assignment-bundle/v1";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encoder.u16(self.bundle_version);
        encoder.u8(self.network_id);
        encoder.u64(self.bundle_sequence);
        encoder.fixed(&self.previous_bundle_id);
        self.manifest.encode(encoder);
        self.assignment.encode(encoder);
        self.session.encode(encoder);
        self.parent_certificate.encode(encoder);
        self.body.encode(encoder);
        self.descriptor.encode(encoder);
        self.body_certificate.encode(encoder);
        self.payout_bucket.encode(encoder);
        encode_roster(encoder, &self.mask_roster);
        encode_roster(encoder, &self.availability_roster);
        encode_roster(encoder, &self.settlement_roster);
        encoder.u32(self.advertised_difficulty);
        match &self.replacement {
            Some(replacement) => {
                encoder.u8(1);
                encoder.fixed(&replacement.previous_assignment_id);
                encoder.u64(replacement.credit_cutoff_ms);
                encoder.u64(replacement.previous_submission_end_ms);
                encoder.u16(replacement.reason_code);
            }
            None => encoder.u8(0),
        }
    }
}

impl CanonicalEncode for CoreAssignmentBundleV1 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        self.core_signature.encode(encoder);
    }
}

impl CanonicalDecode for CoreAssignmentBundleV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let bundle_version = decoder.u16()?;
        let network_id = decoder.u8()?;
        let bundle_sequence = decoder.u64()?;
        let previous_bundle_id = decoder.array()?;
        let manifest = GatewayContextManifestV1::decode(decoder)?;
        let assignment = GatewayAssignmentV1::decode(decoder)?;
        let session = MaskSessionV2::decode(decoder)?;
        let parent_certificate = SessionParentCertificateV2::decode(decoder)?;
        let body = BlockBodyPackageV2::decode(decoder)?;
        let descriptor = BodyErasureDescriptorV2::decode(decoder)?;
        let body_certificate = BodyAvailabilityCertificateV2::decode(decoder)?;
        let payout_bucket = PayoutBucketV2::decode(decoder)?;
        let mask_roster = decode_roster(decoder)?;
        let availability_roster = decode_roster(decoder)?;
        let settlement_roster = decode_roster(decoder)?;
        let advertised_difficulty = decoder.u32()?;
        let replacement = decoder.option(|decoder| {
            Ok(AssignmentReplacementV1 {
                previous_assignment_id: decoder.array()?,
                credit_cutoff_ms: decoder.u64()?,
                previous_submission_end_ms: decoder.u64()?,
                reason_code: decoder.u16()?,
            })
        })?;
        let core_signature = SignatureBytes::decode(decoder)?;
        Ok(Self {
            bundle_version,
            network_id,
            bundle_sequence,
            previous_bundle_id,
            manifest,
            assignment,
            session,
            parent_certificate,
            body,
            descriptor,
            body_certificate,
            payout_bucket,
            mask_roster,
            availability_roster,
            settlement_roster,
            advertised_difficulty,
            replacement,
            core_signature,
        })
    }
}

impl CoreAssignmentBundleV1 {
    pub fn validate(&self, now_ms: u64, pinned_core_pubkey: &[u8; 32]) -> Result<(), BundleError> {
        if self.bundle_version != CORE_ASSIGNMENT_BUNDLE_V1
            || self.network_id != self.manifest.network_id
            || self.network_id != self.assignment.network_id
            || self.bundle_sequence == 0
            || self.core_signature.0.len() != 64
        {
            return Err(BundleError::Linkage("bundle version, network, or sequence"));
        }
        if self.manifest.core_protocol_version != CORE_V2
            || self.manifest.handoff_version != GATEWAY_HANDOFF_V1
            || self.assignment.core_protocol_version != CORE_V2
            || self.assignment.handoff_version != GATEWAY_HANDOFF_V1
            || self.session.protocol_version != CORE_V2
            || self.parent_certificate.protocol_version != CORE_V2
            || self.body.protocol_version != CORE_V2
            || self.descriptor.protocol_version != CORE_V2
            || self.body_certificate.protocol_version != CORE_V2
            || self.payout_bucket.protocol_version != CORE_V2
        {
            return Err(BundleError::Linkage("nested protocol version"));
        }
        if self.manifest.core_handoff_pubkey != *pinned_core_pubkey
            || self.assignment.core_handoff_pubkey != *pinned_core_pubkey
        {
            return Err(BundleError::Linkage("pinned Core handoff identity"));
        }
        verify_object(
            pinned_core_pubkey,
            ED25519_SUITE,
            &self.core_signature,
            self.network_id,
            self,
        )?;
        validate_context_manifest(&self.manifest, now_ms)?;
        validate_gateway_assignment(&self.manifest, &self.assignment)?;
        validate_body_package(&self.body).map_err(|_| BundleError::Body)?;

        let expected_validation = validation_result_hash(
            self.body.network_id,
            &self.body.template_core_id,
            &self.body.coinbase_raw,
            &self.body.transactions_raw,
        );
        if expected_validation != self.body.consensus_validation_result_hash {
            return Err(BundleError::Linkage("body validation commitment"));
        }
        let assignment_id = self.assignment.object_id();
        let session_id = self.session.object_id();
        let body_id = self.body.object_id();
        let descriptor_id = self.descriptor.object_id();
        let body_certificate_id = self.body_certificate.object_id();
        let parent_id = self.parent_certificate.object_id();
        let bucket_id = self.payout_bucket.object_id();

        if self.assignment.session_id != session_id
            || self.assignment.body_package_id != body_id
            || self.assignment.body_certificate_id != body_certificate_id
            || self.session.parent_certificate_id != parent_id
            || self.session.parent_hash != self.parent_certificate.parent_hash
            || self.body.template_core.hns_parent_hash != self.parent_certificate.parent_hash
            || self.body.template_core.hns_parent_height != self.parent_certificate.parent_height
            || self.descriptor.body_package_id != body_id
            || self.body_certificate.descriptor_id != descriptor_id
            || self.body_certificate.parent_hash != self.parent_certificate.parent_hash
            || self.body_certificate.parent_height != self.parent_certificate.parent_height
            || self.body_certificate.consensus_validation_result_hash
                != self.body.consensus_validation_result_hash
            || self.assignment.payout_bucket_id != bucket_id
            || self.assignment.operator_pubkey != self.body.template_core.operator_pubkey
            || self.assignment.operator_pubkey != self.payout_bucket.operator_pubkey
            || self.assignment.gateway_pubkey != self.manifest.gateway_pubkey
            || self.assignment.core_handoff_pubkey != self.manifest.core_handoff_pubkey
        {
            return Err(BundleError::Linkage("nested object identity"));
        }
        if self.body.template_core_id != self.body.template_core.object_id() {
            return Err(BundleError::Linkage("template core ID"));
        }

        verify_object(
            &self.assignment.operator_pubkey,
            ED25519_SUITE,
            &self.body.operator_signature,
            self.network_id,
            &self.body,
        )?;
        verify_object(
            &self.assignment.operator_pubkey,
            ED25519_SUITE,
            &self.assignment.operator_signature,
            self.network_id,
            &self.assignment,
        )?;
        verify_object(
            &self.assignment.operator_pubkey,
            ED25519_SUITE,
            &self.payout_bucket.signature,
            self.network_id,
            &self.payout_bucket,
        )?;

        if self.mask_roster.role != CommitteeRole::Mask
            || self.mask_roster.id() != self.session.mask_committee_id
            || self.availability_roster.role != CommitteeRole::Availability
            || self.settlement_roster.role != CommitteeRole::Settlement
        {
            return Err(BundleError::Linkage("committee role or identity"));
        }
        self.mask_roster
            .verify(&self.session.signer_set, &self.session)?;
        self.availability_roster
            .verify(&self.body_certificate.signer_set, &self.body_certificate)?;
        self.settlement_roster.verify(
            &self.parent_certificate.signer_set,
            &self.parent_certificate,
        )?;

        if self.session.assignment_start_ms > self.session.assignment_end_ms
            || self.session.assignment_end_ms > self.session.submission_end_ms
            || self.session.submission_end_ms > self.session.timed_open_after_ms
            || self.assignment.ntime < self.body.template_core.minimum_ntime
            || self.assignment.capture_target != self.session.capture_target
            || self.assignment.edge_target.0 < self.session.capture_target.0
            || self.session.accounting_target != self.session.capture_target
        {
            return Err(BundleError::Linkage("session schedule or target"));
        }
        let capture =
            derive_capture_parameters(self.body.template_core.bits, self.session.blind_band_bits_d)
                .map_err(|_| BundleError::Linkage("capture profile"))?;
        if self.session.hns_network_target.0 != capture.network_target
            || self.session.leading_zero_prefix_q != capture.leading_zero_prefix_q
            || self.session.capture_target.0 != capture.capture_target
        {
            return Err(BundleError::Linkage("capture profile"));
        }
        if handy_target_from_difficulty(self.advertised_difficulty)?
            != self.assignment.edge_target.0
        {
            return Err(BundleError::Linkage("HandyStratum difficulty"));
        }
        let assignment_height = self
            .body
            .template_core
            .hns_parent_height
            .checked_add(1)
            .ok_or(BundleError::Linkage("assignment height"))?;
        if self.payout_bucket.activation_height > assignment_height
            || self
                .payout_bucket
                .retirement_height
                .is_some_and(|height| assignment_height >= height)
        {
            return Err(BundleError::Linkage("payout bucket activation"));
        }

        match (&self.replacement, self.assignment.assignment_sequence) {
            (None, 1) => {
                if self.bundle_sequence != 1 || self.previous_bundle_id != [0; 32] {
                    return Err(BundleError::Linkage("initial bundle sequence"));
                }
            }
            (Some(replacement), sequence) if sequence > 1 => {
                if replacement.previous_assignment_id == [0; 32]
                    || replacement.previous_assignment_id == assignment_id
                    || replacement.credit_cutoff_ms > self.session.assignment_start_ms
                    || replacement.previous_submission_end_ms < replacement.credit_cutoff_ms
                    || self.previous_bundle_id == [0; 32]
                    || self.bundle_sequence != sequence
                {
                    return Err(BundleError::Linkage("replacement boundary"));
                }
            }
            _ => return Err(BundleError::Linkage("replacement sequence")),
        }
        Ok(())
    }

    pub fn gateway_job(&self) -> Result<GatewayJob, BundleError> {
        let ntime = u32::try_from(self.assignment.ntime)
            .map_err(|_| BundleError::Linkage("assignment nTime"))?;
        Ok(GatewayJob {
            id: gateway_assignment_job_id(&self.assignment),
            assignment_sequence: 0,
            previous_block: self.session.parent_hash,
            merkle_root: self.body.merkle_root,
            witness_root: self.body.witness_root,
            tree_root: self.body.tree_root,
            reserved_root: self.body.reserved_root,
            version: self.body.template_core.block_version,
            bits: self.body.template_core.bits,
            ntime,
            mask_hash: self.session.mask_hash,
            leading_zero_prefix_q: self.session.leading_zero_prefix_q,
            blind_band_bits_d: self.session.blind_band_bits_d,
            capture_target: self.session.capture_target.0,
            advertised_device_target: self.assignment.edge_target.0,
            advertised_difficulty: self.advertised_difficulty,
            issued_ms: self.session.assignment_start_ms,
            assignment_end_ms: self.session.assignment_end_ms,
            submission_end_ms: self.session.submission_end_ms,
            transaction_hashes: self.body.template_core.ordered_non_coinbase_txids.clone(),
        })
    }

    pub fn previous_job_transition(&self) -> Option<PreviousJobTransition> {
        self.replacement
            .as_ref()
            .map(|replacement| PreviousJobTransition {
                job_id: hex::encode(replacement.previous_assignment_id),
                credit_cutoff_ms: replacement.credit_cutoff_ms,
                submission_end_ms: replacement.previous_submission_end_ms,
            })
    }
}

fn encode_roster(encoder: &mut Encoder, roster: &CommitteeRoster) {
    encoder.u16(roster.protocol_version);
    encoder.u8(roster.network_id);
    encoder.u16(roster.role as u16);
    encoder.u64(roster.epoch);
    encoder.u16(roster.threshold);
    encoder.varint(roster.members.len() as u64);
    for member in &roster.members {
        encoder.fixed(member);
    }
}

fn decode_roster(decoder: &mut Decoder<'_>) -> Result<CommitteeRoster, CodecError> {
    let protocol_version = decoder.u16()?;
    let network_id = decoder.u8()?;
    let role = match decoder.u16()? {
        1 => CommitteeRole::Mask,
        2 => CommitteeRole::Receipt,
        3 => CommitteeRole::Availability,
        4 => CommitteeRole::Settlement,
        _ => return Err(CodecError::InvalidField("committee role")),
    };
    let epoch = decoder.u64()?;
    let threshold = decoder.u16()?;
    let count = decoder.length(MAX_BUNDLE_COMMITTEE_MEMBERS)?;
    let mut members = BTreeSet::new();
    for _ in 0..count {
        if !members.insert(decoder.array()?) {
            return Err(CodecError::InvalidField("duplicate committee member"));
        }
    }
    Ok(CommitteeRoster {
        protocol_version,
        network_id,
        role,
        epoch,
        threshold,
        members,
    })
}
