//! Deterministic valid fixture for the measurable share-validation gate.

use ed25519_dalek::SigningKey;
use meshmine_body::validation_result_hash;
use meshmine_codec::{CanonicalEncode, Encoder};
use meshmine_crypto::{assemble_ed25519_set, sign_certificate, sign_object};
use meshmine_hns::{Hash256, MinerHeader};
use meshmine_types::{
    AssignmentV2, BlockBodyPackageV2, BodyAvailabilityCertificateV2, BodyErasureDescriptorV2,
    CORE_V2, MaskSessionV2, PayoutBucketV2, SessionParentCertificateV2, ShareV2, SignatureBytes,
    SignatureSet, TemplateCoreV2, U256, UnsignedObject,
};

use super::{
    CommitteeRole, CommitteeRoster, ParentChainOracle, ShareError, ShareValidationContext,
    compact_target_u256, validate_share,
};

struct AcceptParent;

impl ParentChainOracle for AcceptParent {
    fn verify_header_and_chainwork(&self, _certificate: &SessionParentCertificateV2) -> bool {
        true
    }
}

pub struct ShareValidationBenchmark {
    operator_key: SigningKey,
    receipt_keys: [SigningKey; 3],
    settlement_keys: [SigningKey; 3],
    share: ShareV2,
    assignment: AssignmentV2,
    session: MaskSessionV2,
    parent: SessionParentCertificateV2,
    body: BlockBodyPackageV2,
    descriptor: BodyErasureDescriptorV2,
    body_certificate: BodyAvailabilityCertificateV2,
    payout_bucket: PayoutBucketV2,
    mask_roster: CommitteeRoster,
    availability_roster: CommitteeRoster,
    receipt_roster: CommitteeRoster,
    settlement_roster: CommitteeRoster,
}

#[derive(Clone)]
pub struct ShareValidationArtifacts {
    pub share: ShareV2,
    pub assignment: AssignmentV2,
    pub session: MaskSessionV2,
    pub parent: SessionParentCertificateV2,
    pub body: BlockBodyPackageV2,
    pub descriptor: BodyErasureDescriptorV2,
    pub body_certificate: BodyAvailabilityCertificateV2,
    pub payout_bucket: PayoutBucketV2,
    pub mask_roster: CommitteeRoster,
    pub availability_roster: CommitteeRoster,
    pub receipt_roster: CommitteeRoster,
    pub settlement_roster: CommitteeRoster,
}

impl ShareValidationBenchmark {
    pub fn new() -> Self {
        let operator_key = key(42);
        let operator_pubkey = operator_key.verifying_key().to_bytes();
        let mask_keys = [key(1), key(2), key(3)];
        let availability_keys = [key(4), key(5), key(6)];
        let settlement_keys = [key(7), key(8), key(9)];
        let receipt_keys = [key(10), key(11), key(12)];
        let mask_roster = roster(CommitteeRole::Mask, &mask_keys);
        let availability_roster = roster(CommitteeRole::Availability, &availability_keys);
        let receipt_roster = roster(CommitteeRole::Receipt, &receipt_keys);
        let settlement_roster = roster(CommitteeRole::Settlement, &settlement_keys);

        let mut payout_bucket = PayoutBucketV2 {
            protocol_version: CORE_V2,
            network_id: 2,
            operator_pubkey,
            bucket_sequence: 1,
            hns_address_version: 0,
            hns_address_hash: vec![10; 20],
            activation_height: 0,
            retirement_height: None,
            signature: SignatureBytes::empty(),
        };
        payout_bucket.signature = sign_object(&operator_key, 2, &payout_bucket);

        let mut parent = SessionParentCertificateV2 {
            protocol_version: CORE_V2,
            network_id: 2,
            parent_hash: hash(11),
            parent_height: 10,
            parent_chainwork: U256(hash(12)),
            observed_ntime: 100,
            certificate_sequence: 0,
            previous_parent_certificate_id: [0; 32],
            signer_set: SignatureSet::empty_ed25519(),
        };
        parent.signer_set = certify(&parent, &settlement_keys);

        let template_core = TemplateCoreV2 {
            protocol_version: CORE_V2,
            network_id: 2,
            hns_parent_hash: parent.parent_hash,
            hns_parent_height: parent.parent_height,
            operator_pubkey,
            operator_fee_bucket_id: payout_bucket.object_id(),
            payout_snapshot_id: hash(13),
            payout_plan_id: hash(14),
            plan_sequence: 1,
            ordered_non_coinbase_txids: vec![],
            ordered_claim_ids: vec![],
            ordered_airdrop_ids: vec![],
            block_version: 0,
            bits: 0x2000_ffff,
            minimum_ntime: 101,
            policy_commitment: hash(15),
        };
        let coinbase_raw = vec![1, 2, 3];
        let transactions_raw = vec![];
        let consensus_validation_result_hash = validation_result_hash(
            2,
            &template_core.object_id(),
            &coinbase_raw,
            &transactions_raw,
        );
        let mut body = BlockBodyPackageV2 {
            protocol_version: CORE_V2,
            network_id: 2,
            template_core_id: template_core.object_id(),
            template_core,
            coinbase_raw,
            transactions_raw,
            merkle_root: hash(16),
            witness_root: hash(17),
            tree_root: hash(18),
            reserved_root: hash(19),
            block_weight: 100,
            block_sigops: 0,
            miner_subsidy: 2_000_000,
            ordinary_transaction_fees: 0,
            claim_airdrop_principal: 0,
            claim_airdrop_fees: 0,
            operator_fee_value: 0,
            work_service_subsidy_value: 2_000_000,
            consensus_validation_result_hash,
            operator_signature: SignatureBytes::empty(),
        };
        body.operator_signature = sign_object(&operator_key, 2, &body);
        let mut body_bytes = Encoder::new();
        body.encode(&mut body_bytes);
        let descriptor = BodyErasureDescriptorV2 {
            protocol_version: CORE_V2,
            network_id: 2,
            body_package_id: body.object_id(),
            original_size: u32::try_from(body_bytes.as_bytes().len()).unwrap(),
            data_shards: 4,
            parity_shards: 2,
            shard_size: 25,
            shard_merkle_root: hash(21),
            expiry_height: 20,
            compression: 0,
        };
        let mut body_certificate = BodyAvailabilityCertificateV2 {
            protocol_version: CORE_V2,
            network_id: 2,
            descriptor_id: descriptor.object_id(),
            parent_hash: parent.parent_hash,
            parent_height: parent.parent_height,
            consensus_validation_result_hash: body.consensus_validation_result_hash,
            challenge_round: 1,
            challenge_transcript_root: hash(22),
            signer_set: SignatureSet::empty_ed25519(),
        };
        body_certificate.signer_set = certify(&body_certificate, &availability_keys);
        let mut session = MaskSessionV2 {
            protocol_version: CORE_V2,
            network_id: 2,
            lane_id: 0,
            session_sequence: 1,
            parent_certificate_id: parent.object_id(),
            parent_hash: parent.parent_hash,
            hns_network_target: compact_target_u256(0x2000_ffff).unwrap(),
            capture_target: U256(
                meshmine_hns::derive_capture_parameters(0x2000_ffff, 1)
                    .unwrap()
                    .capture_target,
            ),
            accounting_target: U256(
                meshmine_hns::derive_capture_parameters(0x2000_ffff, 1)
                    .unwrap()
                    .capture_target,
            ),
            leading_zero_prefix_q: 7,
            blind_band_bits_d: 1,
            mask_hash: hash(23),
            mask_commitment_root: hash(24),
            mask_committee_id: mask_roster.id(),
            fast_eval_policy: 0,
            assignment_start_ms: 1,
            assignment_end_ms: 2,
            submission_end_ms: 3,
            timed_open_after_ms: 4,
            previous_session_id: [0; 32],
            signer_set: SignatureSet::empty_ed25519(),
        };
        session.signer_set = certify(&session, &mask_keys);
        let mut assignment = AssignmentV2 {
            protocol_version: CORE_V2,
            network_id: 2,
            session_id: session.object_id(),
            body_package_id: body.object_id(),
            body_certificate_id: body_certificate.object_id(),
            operator_pubkey,
            worker_id_hash: hash(25),
            payout_bucket_id: payout_bucket.object_id(),
            assignment_sequence: 1,
            ntime: 101,
            extra_nonce: [26; 24],
            nonce_start: 0,
            nonce_end: u32::MAX,
            nonce_stride: 1,
            edge_target: U256([0xff; 32]),
            capture_target: session.capture_target,
            telemetry_level: 0,
            operator_signature: SignatureBytes::empty(),
        };
        assignment.operator_signature = sign_object(&operator_key, 2, &assignment);
        let mut miner = MinerHeader {
            nonce: 0,
            time: assignment.ntime,
            prev_block: body.template_core.hns_parent_hash,
            tree_root: body.tree_root,
            mask_hash: session.mask_hash,
            extra_nonce: assignment.extra_nonce,
            reserved_root: body.reserved_root,
            witness_root: body.witness_root,
            merkle_root: body.merkle_root,
            version: body.template_core.block_version,
            bits: body.template_core.bits,
        };
        while miner.share_hash() > session.capture_target.0 {
            miner.nonce = miner.nonce.checked_add(1).unwrap();
        }
        let mut share = ShareV2 {
            protocol_version: CORE_V2,
            network_id: 2,
            session_id: session.object_id(),
            assignment_id: assignment.object_id(),
            body_package_id: body.object_id(),
            operator_pubkey,
            payout_bucket_id: payout_bucket.object_id(),
            nonce: miner.nonce,
            ntime: miner.time,
            extra_nonce: miner.extra_nonce,
            raw_share_hash: miner.share_hash(),
            declared_target: session.capture_target,
            gossip_parent_hashes: vec![],
            local_telemetry_hash: None,
            operator_signature: SignatureBytes::empty(),
        };
        share.operator_signature = sign_object(&operator_key, 2, &share);
        Self {
            operator_key,
            receipt_keys,
            settlement_keys,
            share,
            assignment,
            session,
            parent,
            body,
            descriptor,
            body_certificate,
            payout_bucket,
            mask_roster,
            availability_roster,
            receipt_roster,
            settlement_roster,
        }
    }

    pub fn validate_once(&self) -> Result<(), ShareError> {
        validate_share(
            self.share.clone(),
            &ShareValidationContext {
                assignment: &self.assignment,
                session: &self.session,
                parent_certificate: &self.parent,
                body: &self.body,
                descriptor: &self.descriptor,
                body_certificate: &self.body_certificate,
                payout_bucket: &self.payout_bucket,
                mask_roster: &self.mask_roster,
                availability_roster: &self.availability_roster,
                settlement_roster: &self.settlement_roster,
                observed_ms: 2,
                parent_oracle: &AcceptParent,
            },
        )?;
        Ok(())
    }

    pub fn artifacts(&self) -> ShareValidationArtifacts {
        ShareValidationArtifacts {
            share: self.share.clone(),
            assignment: self.assignment.clone(),
            session: self.session.clone(),
            parent: self.parent.clone(),
            body: self.body.clone(),
            descriptor: self.descriptor.clone(),
            body_certificate: self.body_certificate.clone(),
            payout_bucket: self.payout_bucket.clone(),
            mask_roster: self.mask_roster.clone(),
            availability_roster: self.availability_roster.clone(),
            receipt_roster: self.receipt_roster.clone(),
            settlement_roster: self.settlement_roster.clone(),
        }
    }

    /// A distinct, correctly signed gossip wrapper for the same physical
    /// work. Durable admission must reject it by work key even though its
    /// share object ID differs.
    pub fn rewrapped_share(&self) -> ShareV2 {
        let mut share = self.share.clone();
        share.local_telemetry_hash = Some(hash(99));
        share.operator_signature = sign_object(&self.operator_key, share.network_id, &share);
        share
    }

    pub fn certify_receipt<T: UnsignedObject>(&self, object: &T) -> SignatureSet {
        certify(object, &self.receipt_keys)
    }

    pub fn certify_settlement<T: UnsignedObject>(&self, object: &T) -> SignatureSet {
        certify(object, &self.settlement_keys)
    }
}

impl Default for ShareValidationBenchmark {
    fn default() -> Self {
        Self::new()
    }
}

fn hash(byte: u8) -> Hash256 {
    [byte; 32]
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn roster(role: CommitteeRole, keys: &[SigningKey]) -> CommitteeRoster {
    CommitteeRoster {
        protocol_version: CORE_V2,
        network_id: 2,
        role,
        epoch: 1,
        threshold: 2,
        members: keys
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect(),
    }
}

fn certify<T: UnsignedObject>(object: &T, keys: &[SigningKey]) -> SignatureSet {
    assemble_ed25519_set(
        keys.iter()
            .take(2)
            .map(|key| sign_certificate(key, 2, object))
            .collect(),
    )
    .unwrap()
}
