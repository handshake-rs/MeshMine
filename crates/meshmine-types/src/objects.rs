use std::collections::HashSet;

use meshmine_codec::{CanonicalDecode, CanonicalEncode, CodecError, Decoder, Encoder};
use meshmine_hns::Hash256;

use crate::{
    MAX_ADDRESS_HASH_BYTES, MAX_BODY_BYTES, MAX_BUCKETS, MAX_OBJECT_HASHES, ObjectError,
    PayoutBucketId, ServiceBucketLeaf, SignatureBytes, SignatureSet, U256, U512, UnsignedObject,
    WorkBucketLeaf, decode_hashes, decode_u512s, domain_hash, encode_hashes, encode_option,
    encode_u512s, validate_bucket_order,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorRecordV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub operator_pubkey: [u8; 32],
    pub sequence: u64,
    pub supported_features: u64,
    pub payout_bucket_ids: Vec<PayoutBucketId>,
    pub contact_metadata_hash: Option<Hash256>,
    pub signature_suite: u16,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutBucketV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub operator_pubkey: [u8; 32],
    pub bucket_sequence: u64,
    pub hns_address_version: u8,
    pub hns_address_hash: Vec<u8>,
    pub activation_height: u32,
    pub retirement_height: Option<u32>,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutSnapshotV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub snapshot_sequence: u64,
    pub previous_snapshot_id: Hash256,
    pub first_session_close_id: Hash256,
    pub last_session_close_id: Hash256,
    pub close_anchor_height: u32,
    pub work_window_target: U512,
    pub actual_work_in_window: U512,
    pub work_buckets: Vec<WorkBucketLeaf>,
    pub service_buckets: Vec<ServiceBucketLeaf>,
    pub share_set_root: Hash256,
    pub service_set_root: Hash256,
    pub settlement_committee_id: Hash256,
    pub signer_set: SignatureSet,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutPlanV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub plan_sequence: u64,
    pub snapshot_id: Hash256,
    pub entropy_anchor_start: u32,
    pub entropy_anchor_count: u16,
    pub entropy_hashes: Vec<Hash256>,
    pub prior_beacon: Hash256,
    pub plan_seed: Hash256,
    pub work_ticket_count: u16,
    pub service_ticket_count: u16,
    pub work_winners: Vec<PayoutBucketId>,
    pub service_winners: Vec<PayoutBucketId>,
    pub selection_transcript_hash: Hash256,
    pub signer_set: SignatureSet,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateCoreV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub hns_parent_hash: Hash256,
    pub hns_parent_height: u32,
    pub operator_pubkey: [u8; 32],
    pub operator_fee_bucket_id: Hash256,
    pub payout_snapshot_id: Hash256,
    pub payout_plan_id: Hash256,
    pub plan_sequence: u64,
    pub ordered_non_coinbase_txids: Vec<Hash256>,
    pub ordered_claim_ids: Vec<Hash256>,
    pub ordered_airdrop_ids: Vec<Hash256>,
    pub block_version: u32,
    pub bits: u32,
    pub minimum_ntime: u64,
    pub policy_commitment: Hash256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockBodyPackageV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub template_core: TemplateCoreV2,
    pub template_core_id: Hash256,
    pub coinbase_raw: Vec<u8>,
    pub transactions_raw: Vec<Vec<u8>>,
    pub merkle_root: Hash256,
    pub witness_root: Hash256,
    pub tree_root: Hash256,
    pub reserved_root: Hash256,
    pub block_weight: u32,
    pub block_sigops: u32,
    pub miner_subsidy: u64,
    pub ordinary_transaction_fees: u64,
    pub claim_airdrop_principal: u64,
    pub claim_airdrop_fees: u64,
    pub operator_fee_value: u64,
    pub work_service_subsidy_value: u64,
    pub hsd_validation_result_hash: Hash256,
    pub operator_signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyErasureDescriptorV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub body_package_id: Hash256,
    pub original_size: u32,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub shard_size: u32,
    pub shard_merkle_root: Hash256,
    pub expiry_height: u32,
    pub compression: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyAvailabilityCertificateV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub descriptor_id: Hash256,
    pub parent_hash: Hash256,
    pub parent_height: u32,
    pub hsd_validation_result_hash: Hash256,
    pub challenge_round: u64,
    pub challenge_transcript_root: Hash256,
    pub signer_set: SignatureSet,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionParentCertificateV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub parent_hash: Hash256,
    pub parent_height: u32,
    pub parent_chainwork: U256,
    pub observed_ntime: u64,
    pub certificate_sequence: u64,
    pub previous_parent_certificate_id: Hash256,
    pub signer_set: SignatureSet,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaskSessionV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub lane_id: u16,
    pub session_sequence: u64,
    pub parent_certificate_id: Hash256,
    pub parent_hash: Hash256,
    pub hns_network_target: U256,
    pub capture_target: U256,
    pub accounting_target: U256,
    pub leading_zero_prefix_q: u16,
    pub blind_band_bits_d: u16,
    pub mask_hash: Hash256,
    pub mask_commitment_root: Hash256,
    pub mask_committee_id: Hash256,
    pub fast_eval_policy: u16,
    pub assignment_start_ms: u64,
    pub assignment_end_ms: u64,
    pub submission_end_ms: u64,
    pub timed_open_after_ms: u64,
    pub previous_session_id: Hash256,
    pub signer_set: SignatureSet,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignmentV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub session_id: Hash256,
    pub body_package_id: Hash256,
    pub body_certificate_id: Hash256,
    pub operator_pubkey: [u8; 32],
    pub worker_id_hash: Hash256,
    pub payout_bucket_id: Hash256,
    pub assignment_sequence: u64,
    pub ntime: u64,
    pub extra_nonce: [u8; 24],
    pub nonce_start: u32,
    pub nonce_end: u32,
    pub nonce_stride: u32,
    pub edge_target: U256,
    pub capture_target: U256,
    pub telemetry_level: u8,
    pub operator_signature: SignatureBytes,
}

/// Pre-mining operator authorization for a HandyStratum gateway assignment.
///
/// This is a distinct Core-v2 extension object, not a relaxed `AssignmentV2`.
/// Its signed extra-nonce profile authorizes the miner-selected four-byte
/// `ExtraNonce2` range before work begins while retaining exact context,
/// target, worker, gateway, and Core handoff identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayAssignmentV1 {
    pub core_protocol_version: u16,
    pub handoff_version: u16,
    pub network_id: u8,
    pub session_id: Hash256,
    pub body_package_id: Hash256,
    pub body_certificate_id: Hash256,
    pub operator_pubkey: [u8; 32],
    pub gateway_pubkey: [u8; 32],
    pub core_handoff_pubkey: [u8; 32],
    pub worker_id_hash: Hash256,
    pub payout_bucket_id: Hash256,
    pub assignment_sequence: u64,
    pub ntime: u64,
    pub extra_nonce_profile: u16,
    pub observation_policy: u16,
    pub maximum_clock_skew_ms: u64,
    pub extra_nonce_prefix: [u8; 4],
    pub extra_nonce2_start_be: [u8; 4],
    pub extra_nonce2_end_be: [u8; 4],
    pub nonce_start: u32,
    pub nonce_end: u32,
    pub nonce_stride: u32,
    pub edge_target: U256,
    pub capture_target: U256,
    pub telemetry_level: u8,
    pub operator_signature: SignatureBytes,
}

impl GatewayAssignmentV1 {
    pub fn accepts_extra_nonce(&self, extra_nonce: &[u8; 24]) -> bool {
        self.extra_nonce_profile
            == crate::GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16
            && self.extra_nonce2_start_be <= self.extra_nonce2_end_be
            && extra_nonce[..4] == self.extra_nonce_prefix
            && &extra_nonce[4..8] >= self.extra_nonce2_start_be.as_slice()
            && &extra_nonce[4..8] <= self.extra_nonce2_end_be.as_slice()
            && extra_nonce[8..].iter().all(|byte| *byte == 0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub session_id: Hash256,
    pub assignment_id: Hash256,
    pub body_package_id: Hash256,
    pub operator_pubkey: [u8; 32],
    pub payout_bucket_id: Hash256,
    pub nonce: u32,
    pub ntime: u64,
    pub extra_nonce: [u8; 24],
    pub raw_share_hash: Hash256,
    pub declared_target: U256,
    pub gossip_parent_hashes: Vec<Hash256>,
    pub local_telemetry_hash: Option<Hash256>,
    pub operator_signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptBatchV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub session_id: Hash256,
    pub batch_sequence: u64,
    pub previous_batch_id: Hash256,
    pub accepted_share_ids: Vec<Hash256>,
    pub accepted_work_keys: Vec<Hash256>,
    pub credited_work: Vec<U512>,
    pub share_merkle_root: Hash256,
    pub cumulative_share_count: u64,
    pub cumulative_credited_work: U512,
    pub signer_set: SignatureSet,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionCloseV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub session_id: Hash256,
    pub final_receipt_batch_id: Hash256,
    pub accepted_share_merkle_root: Hash256,
    pub accepted_work_key_root: Hash256,
    pub accepted_share_count: u64,
    pub total_credited_work: U512,
    pub close_reason: u16,
    pub mask_opening_transcript_root: Hash256,
    pub discovered_hns_block_ids: Vec<Hash256>,
    pub signer_set: SignatureSet,
}

fn encode_prefix(encoder: &mut Encoder, protocol_version: u16, network_id: u8) {
    encoder.u16(protocol_version);
    encoder.u8(network_id);
}

fn decode_prefix(decoder: &mut Decoder<'_>) -> Result<(u16, u8), CodecError> {
    Ok((decoder.u16()?, decoder.u8()?))
}

fn encode_signature(encoder: &mut Encoder, signature: &SignatureBytes) {
    signature.encode(encoder);
}

fn encode_signature_set(encoder: &mut Encoder, signer_set: &SignatureSet) {
    signer_set.encode(encoder);
}

impl UnsignedObject for OperatorRecordV2 {
    const DOMAIN_TAG: &'static str = "meshmine/operator/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encode_prefix(encoder, self.protocol_version, self.network_id);
        encoder.fixed(&self.operator_pubkey);
        encoder.u64(self.sequence);
        encoder.u64(self.supported_features);
        encode_hashes(encoder, &self.payout_bucket_ids);
        encode_option(encoder, &self.contact_metadata_hash, |encoder, hash| {
            encoder.fixed(hash);
        });
        encoder.u16(self.signature_suite);
    }
}

impl CanonicalEncode for OperatorRecordV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        encode_signature(encoder, &self.signature);
    }
}

impl CanonicalDecode for OperatorRecordV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let (protocol_version, network_id) = decode_prefix(decoder)?;
        Ok(Self {
            protocol_version,
            network_id,
            operator_pubkey: decoder.array()?,
            sequence: decoder.u64()?,
            supported_features: decoder.u64()?,
            payout_bucket_ids: decode_hashes(decoder)?,
            contact_metadata_hash: decoder.option(|decoder| decoder.array())?,
            signature_suite: decoder.u16()?,
            signature: SignatureBytes::decode(decoder)?,
        })
    }
}

impl UnsignedObject for PayoutBucketV2 {
    const DOMAIN_TAG: &'static str = "meshmine/payout-bucket/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encode_prefix(encoder, self.protocol_version, self.network_id);
        encoder.fixed(&self.operator_pubkey);
        encoder.u64(self.bucket_sequence);
        encoder.u8(self.hns_address_version);
        encoder.bytes(&self.hns_address_hash);
        encoder.u32(self.activation_height);
        encode_option(encoder, &self.retirement_height, |encoder, height| {
            encoder.u32(*height);
        });
    }
}

impl CanonicalEncode for PayoutBucketV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        encode_signature(encoder, &self.signature);
    }
}

impl CanonicalDecode for PayoutBucketV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let (protocol_version, network_id) = decode_prefix(decoder)?;
        Ok(Self {
            protocol_version,
            network_id,
            operator_pubkey: decoder.array()?,
            bucket_sequence: decoder.u64()?,
            hns_address_version: decoder.u8()?,
            hns_address_hash: decoder.bytes(MAX_ADDRESS_HASH_BYTES)?,
            activation_height: decoder.u32()?,
            retirement_height: decoder.option(|decoder| decoder.u32())?,
            signature: SignatureBytes::decode(decoder)?,
        })
    }
}

impl PayoutSnapshotV2 {
    pub fn validate(&self) -> Result<(), ObjectError> {
        validate_bucket_order(&self.work_buckets, |leaf| &leaf.bucket_id)?;
        validate_bucket_order(&self.service_buckets, |leaf| &leaf.bucket_id)?;
        self.signer_set.validate_order()?;
        Ok(())
    }
}

impl UnsignedObject for PayoutSnapshotV2 {
    const DOMAIN_TAG: &'static str = "meshmine/payout-snapshot/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encode_prefix(encoder, self.protocol_version, self.network_id);
        encoder.u64(self.snapshot_sequence);
        encoder.fixed(&self.previous_snapshot_id);
        encoder.fixed(&self.first_session_close_id);
        encoder.fixed(&self.last_session_close_id);
        encoder.u32(self.close_anchor_height);
        self.work_window_target.encode(encoder);
        self.actual_work_in_window.encode(encoder);
        encoder.varint(self.work_buckets.len() as u64);
        for leaf in &self.work_buckets {
            leaf.encode(encoder);
        }
        encoder.varint(self.service_buckets.len() as u64);
        for leaf in &self.service_buckets {
            leaf.encode(encoder);
        }
        encoder.fixed(&self.share_set_root);
        encoder.fixed(&self.service_set_root);
        encoder.fixed(&self.settlement_committee_id);
    }
}

impl CanonicalEncode for PayoutSnapshotV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        encode_signature_set(encoder, &self.signer_set);
    }
}

impl CanonicalDecode for PayoutSnapshotV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let (protocol_version, network_id) = decode_prefix(decoder)?;
        let snapshot_sequence = decoder.u64()?;
        let previous_snapshot_id = decoder.array()?;
        let first_session_close_id = decoder.array()?;
        let last_session_close_id = decoder.array()?;
        let close_anchor_height = decoder.u32()?;
        let work_window_target = U512::decode(decoder)?;
        let actual_work_in_window = U512::decode(decoder)?;
        let work_count = decoder.length(MAX_BUCKETS)?;
        let work_buckets = (0..work_count)
            .map(|_| WorkBucketLeaf::decode(decoder))
            .collect::<Result<Vec<_>, _>>()?;
        let service_count = decoder.length(MAX_BUCKETS)?;
        let service_buckets = (0..service_count)
            .map(|_| ServiceBucketLeaf::decode(decoder))
            .collect::<Result<Vec<_>, _>>()?;
        let result = Self {
            protocol_version,
            network_id,
            snapshot_sequence,
            previous_snapshot_id,
            first_session_close_id,
            last_session_close_id,
            close_anchor_height,
            work_window_target,
            actual_work_in_window,
            work_buckets,
            service_buckets,
            share_set_root: decoder.array()?,
            service_set_root: decoder.array()?,
            settlement_committee_id: decoder.array()?,
            signer_set: SignatureSet::decode(decoder)?,
        };
        result
            .validate()
            .map_err(|_| CodecError::InvalidField("invalid payout snapshot ordering"))?;
        Ok(result)
    }
}

impl UnsignedObject for PayoutPlanV2 {
    const DOMAIN_TAG: &'static str = "meshmine/payout-plan/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encode_prefix(encoder, self.protocol_version, self.network_id);
        encoder.u64(self.plan_sequence);
        encoder.fixed(&self.snapshot_id);
        encoder.u32(self.entropy_anchor_start);
        encoder.u16(self.entropy_anchor_count);
        encode_hashes(encoder, &self.entropy_hashes);
        encoder.fixed(&self.prior_beacon);
        encoder.fixed(&self.plan_seed);
        encoder.u16(self.work_ticket_count);
        encoder.u16(self.service_ticket_count);
        encode_hashes(encoder, &self.work_winners);
        encode_hashes(encoder, &self.service_winners);
        encoder.fixed(&self.selection_transcript_hash);
    }
}

impl CanonicalEncode for PayoutPlanV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        encode_signature_set(encoder, &self.signer_set);
    }
}

impl CanonicalDecode for PayoutPlanV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let (protocol_version, network_id) = decode_prefix(decoder)?;
        let result = Self {
            protocol_version,
            network_id,
            plan_sequence: decoder.u64()?,
            snapshot_id: decoder.array()?,
            entropy_anchor_start: decoder.u32()?,
            entropy_anchor_count: decoder.u16()?,
            entropy_hashes: decode_hashes(decoder)?,
            prior_beacon: decoder.array()?,
            plan_seed: decoder.array()?,
            work_ticket_count: decoder.u16()?,
            service_ticket_count: decoder.u16()?,
            work_winners: decode_hashes(decoder)?,
            service_winners: decode_hashes(decoder)?,
            selection_transcript_hash: decoder.array()?,
            signer_set: SignatureSet::decode(decoder)?,
        };
        if usize::from(result.entropy_anchor_count) != result.entropy_hashes.len() {
            return Err(CodecError::InvalidField(
                "entropy anchor count does not match entropy hashes",
            ));
        }
        Ok(result)
    }
}

impl UnsignedObject for TemplateCoreV2 {
    const DOMAIN_TAG: &'static str = "meshmine/template-core/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encode_prefix(encoder, self.protocol_version, self.network_id);
        encoder.fixed(&self.hns_parent_hash);
        encoder.u32(self.hns_parent_height);
        encoder.fixed(&self.operator_pubkey);
        encoder.fixed(&self.operator_fee_bucket_id);
        encoder.fixed(&self.payout_snapshot_id);
        encoder.fixed(&self.payout_plan_id);
        encoder.u64(self.plan_sequence);
        encode_hashes(encoder, &self.ordered_non_coinbase_txids);
        encode_hashes(encoder, &self.ordered_claim_ids);
        encode_hashes(encoder, &self.ordered_airdrop_ids);
        encoder.u32(self.block_version);
        encoder.u32(self.bits);
        encoder.u64(self.minimum_ntime);
        encoder.fixed(&self.policy_commitment);
    }
}

impl CanonicalEncode for TemplateCoreV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
    }
}

impl CanonicalDecode for TemplateCoreV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let (protocol_version, network_id) = decode_prefix(decoder)?;
        Ok(Self {
            protocol_version,
            network_id,
            hns_parent_hash: decoder.array()?,
            hns_parent_height: decoder.u32()?,
            operator_pubkey: decoder.array()?,
            operator_fee_bucket_id: decoder.array()?,
            payout_snapshot_id: decoder.array()?,
            payout_plan_id: decoder.array()?,
            plan_sequence: decoder.u64()?,
            ordered_non_coinbase_txids: decode_hashes(decoder)?,
            ordered_claim_ids: decode_hashes(decoder)?,
            ordered_airdrop_ids: decode_hashes(decoder)?,
            block_version: decoder.u32()?,
            bits: decoder.u32()?,
            minimum_ntime: decoder.u64()?,
            policy_commitment: decoder.array()?,
        })
    }
}

impl BlockBodyPackageV2 {
    pub fn validate_links(&self) -> Result<(), ObjectError> {
        if self.protocol_version != self.template_core.protocol_version
            || self.network_id != self.template_core.network_id
        {
            return Err(ObjectError::Codec(CodecError::InvalidField(
                "body and template version/network mismatch",
            )));
        }
        if self.template_core.object_id() != self.template_core_id {
            return Err(ObjectError::Codec(CodecError::InvalidField(
                "template core ID mismatch",
            )));
        }
        Ok(())
    }
}

impl UnsignedObject for BlockBodyPackageV2 {
    const DOMAIN_TAG: &'static str = "meshmine/body-package/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encode_prefix(encoder, self.protocol_version, self.network_id);
        self.template_core.encode(encoder);
        encoder.fixed(&self.template_core_id);
        encoder.bytes(&self.coinbase_raw);
        encoder.varint(self.transactions_raw.len() as u64);
        for transaction in &self.transactions_raw {
            encoder.bytes(transaction);
        }
        encoder.fixed(&self.merkle_root);
        encoder.fixed(&self.witness_root);
        encoder.fixed(&self.tree_root);
        encoder.fixed(&self.reserved_root);
        encoder.u32(self.block_weight);
        encoder.u32(self.block_sigops);
        encoder.u64(self.miner_subsidy);
        encoder.u64(self.ordinary_transaction_fees);
        encoder.u64(self.claim_airdrop_principal);
        encoder.u64(self.claim_airdrop_fees);
        encoder.u64(self.operator_fee_value);
        encoder.u64(self.work_service_subsidy_value);
        encoder.fixed(&self.hsd_validation_result_hash);
    }
}

impl CanonicalEncode for BlockBodyPackageV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        encode_signature(encoder, &self.operator_signature);
    }
}

impl CanonicalDecode for BlockBodyPackageV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let (protocol_version, network_id) = decode_prefix(decoder)?;
        let template_core = TemplateCoreV2::decode(decoder)?;
        let template_core_id = decoder.array()?;
        let coinbase_raw = decoder.bytes(MAX_BODY_BYTES)?;
        let transaction_count = decoder.length(MAX_OBJECT_HASHES)?;
        let transactions_raw = (0..transaction_count)
            .map(|_| decoder.bytes(MAX_BODY_BYTES))
            .collect::<Result<Vec<_>, _>>()?;
        let result = Self {
            protocol_version,
            network_id,
            template_core,
            template_core_id,
            coinbase_raw,
            transactions_raw,
            merkle_root: decoder.array()?,
            witness_root: decoder.array()?,
            tree_root: decoder.array()?,
            reserved_root: decoder.array()?,
            block_weight: decoder.u32()?,
            block_sigops: decoder.u32()?,
            miner_subsidy: decoder.u64()?,
            ordinary_transaction_fees: decoder.u64()?,
            claim_airdrop_principal: decoder.u64()?,
            claim_airdrop_fees: decoder.u64()?,
            operator_fee_value: decoder.u64()?,
            work_service_subsidy_value: decoder.u64()?,
            hsd_validation_result_hash: decoder.array()?,
            operator_signature: SignatureBytes::decode(decoder)?,
        };
        result
            .validate_links()
            .map_err(|_| CodecError::InvalidField("invalid body/template linkage"))?;
        Ok(result)
    }
}

impl UnsignedObject for BodyErasureDescriptorV2 {
    const DOMAIN_TAG: &'static str = "meshmine/body-erasure/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encode_prefix(encoder, self.protocol_version, self.network_id);
        encoder.fixed(&self.body_package_id);
        encoder.u32(self.original_size);
        encoder.u16(self.data_shards);
        encoder.u16(self.parity_shards);
        encoder.u32(self.shard_size);
        encoder.fixed(&self.shard_merkle_root);
        encoder.u32(self.expiry_height);
        encoder.u16(self.compression);
    }
}

impl CanonicalEncode for BodyErasureDescriptorV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
    }
}

impl CanonicalDecode for BodyErasureDescriptorV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let (protocol_version, network_id) = decode_prefix(decoder)?;
        Ok(Self {
            protocol_version,
            network_id,
            body_package_id: decoder.array()?,
            original_size: decoder.u32()?,
            data_shards: decoder.u16()?,
            parity_shards: decoder.u16()?,
            shard_size: decoder.u32()?,
            shard_merkle_root: decoder.array()?,
            expiry_height: decoder.u32()?,
            compression: decoder.u16()?,
        })
    }
}

impl UnsignedObject for BodyAvailabilityCertificateV2 {
    const DOMAIN_TAG: &'static str = "meshmine/body-certificate/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encode_prefix(encoder, self.protocol_version, self.network_id);
        encoder.fixed(&self.descriptor_id);
        encoder.fixed(&self.parent_hash);
        encoder.u32(self.parent_height);
        encoder.fixed(&self.hsd_validation_result_hash);
        encoder.u64(self.challenge_round);
        encoder.fixed(&self.challenge_transcript_root);
    }
}

impl CanonicalEncode for BodyAvailabilityCertificateV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        encode_signature_set(encoder, &self.signer_set);
    }
}

impl CanonicalDecode for BodyAvailabilityCertificateV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let (protocol_version, network_id) = decode_prefix(decoder)?;
        Ok(Self {
            protocol_version,
            network_id,
            descriptor_id: decoder.array()?,
            parent_hash: decoder.array()?,
            parent_height: decoder.u32()?,
            hsd_validation_result_hash: decoder.array()?,
            challenge_round: decoder.u64()?,
            challenge_transcript_root: decoder.array()?,
            signer_set: SignatureSet::decode(decoder)?,
        })
    }
}

impl UnsignedObject for SessionParentCertificateV2 {
    const DOMAIN_TAG: &'static str = "meshmine/parent-certificate/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encode_prefix(encoder, self.protocol_version, self.network_id);
        encoder.fixed(&self.parent_hash);
        encoder.u32(self.parent_height);
        self.parent_chainwork.encode(encoder);
        encoder.u64(self.observed_ntime);
        encoder.u64(self.certificate_sequence);
        encoder.fixed(&self.previous_parent_certificate_id);
    }
}

impl CanonicalEncode for SessionParentCertificateV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        encode_signature_set(encoder, &self.signer_set);
    }
}

impl CanonicalDecode for SessionParentCertificateV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let (protocol_version, network_id) = decode_prefix(decoder)?;
        Ok(Self {
            protocol_version,
            network_id,
            parent_hash: decoder.array()?,
            parent_height: decoder.u32()?,
            parent_chainwork: U256::decode(decoder)?,
            observed_ntime: decoder.u64()?,
            certificate_sequence: decoder.u64()?,
            previous_parent_certificate_id: decoder.array()?,
            signer_set: SignatureSet::decode(decoder)?,
        })
    }
}

impl UnsignedObject for MaskSessionV2 {
    const DOMAIN_TAG: &'static str = "meshmine/mask-session/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encode_prefix(encoder, self.protocol_version, self.network_id);
        encoder.u16(self.lane_id);
        encoder.u64(self.session_sequence);
        encoder.fixed(&self.parent_certificate_id);
        encoder.fixed(&self.parent_hash);
        self.hns_network_target.encode(encoder);
        self.capture_target.encode(encoder);
        self.accounting_target.encode(encoder);
        encoder.u16(self.leading_zero_prefix_q);
        encoder.u16(self.blind_band_bits_d);
        encoder.fixed(&self.mask_hash);
        encoder.fixed(&self.mask_commitment_root);
        encoder.fixed(&self.mask_committee_id);
        encoder.u16(self.fast_eval_policy);
        encoder.u64(self.assignment_start_ms);
        encoder.u64(self.assignment_end_ms);
        encoder.u64(self.submission_end_ms);
        encoder.u64(self.timed_open_after_ms);
        encoder.fixed(&self.previous_session_id);
    }
}

impl CanonicalEncode for MaskSessionV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        encode_signature_set(encoder, &self.signer_set);
    }
}

impl CanonicalDecode for MaskSessionV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let (protocol_version, network_id) = decode_prefix(decoder)?;
        Ok(Self {
            protocol_version,
            network_id,
            lane_id: decoder.u16()?,
            session_sequence: decoder.u64()?,
            parent_certificate_id: decoder.array()?,
            parent_hash: decoder.array()?,
            hns_network_target: U256::decode(decoder)?,
            capture_target: U256::decode(decoder)?,
            accounting_target: U256::decode(decoder)?,
            leading_zero_prefix_q: decoder.u16()?,
            blind_band_bits_d: decoder.u16()?,
            mask_hash: decoder.array()?,
            mask_commitment_root: decoder.array()?,
            mask_committee_id: decoder.array()?,
            fast_eval_policy: decoder.u16()?,
            assignment_start_ms: decoder.u64()?,
            assignment_end_ms: decoder.u64()?,
            submission_end_ms: decoder.u64()?,
            timed_open_after_ms: decoder.u64()?,
            previous_session_id: decoder.array()?,
            signer_set: SignatureSet::decode(decoder)?,
        })
    }
}

impl UnsignedObject for AssignmentV2 {
    const DOMAIN_TAG: &'static str = "meshmine/assignment/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encode_prefix(encoder, self.protocol_version, self.network_id);
        encoder.fixed(&self.session_id);
        encoder.fixed(&self.body_package_id);
        encoder.fixed(&self.body_certificate_id);
        encoder.fixed(&self.operator_pubkey);
        encoder.fixed(&self.worker_id_hash);
        encoder.fixed(&self.payout_bucket_id);
        encoder.u64(self.assignment_sequence);
        encoder.u64(self.ntime);
        encoder.fixed(&self.extra_nonce);
        encoder.u32(self.nonce_start);
        encoder.u32(self.nonce_end);
        encoder.u32(self.nonce_stride);
        self.edge_target.encode(encoder);
        self.capture_target.encode(encoder);
        encoder.u8(self.telemetry_level);
    }
}

impl CanonicalEncode for AssignmentV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        encode_signature(encoder, &self.operator_signature);
    }
}

impl CanonicalDecode for AssignmentV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let (protocol_version, network_id) = decode_prefix(decoder)?;
        Ok(Self {
            protocol_version,
            network_id,
            session_id: decoder.array()?,
            body_package_id: decoder.array()?,
            body_certificate_id: decoder.array()?,
            operator_pubkey: decoder.array()?,
            worker_id_hash: decoder.array()?,
            payout_bucket_id: decoder.array()?,
            assignment_sequence: decoder.u64()?,
            ntime: decoder.u64()?,
            extra_nonce: decoder.array()?,
            nonce_start: decoder.u32()?,
            nonce_end: decoder.u32()?,
            nonce_stride: decoder.u32()?,
            edge_target: U256::decode(decoder)?,
            capture_target: U256::decode(decoder)?,
            telemetry_level: decoder.u8()?,
            operator_signature: SignatureBytes::decode(decoder)?,
        })
    }
}

impl UnsignedObject for GatewayAssignmentV1 {
    const DOMAIN_TAG: &'static str = "meshmine/gateway-assignment/v1";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encoder.u16(self.core_protocol_version);
        encoder.u16(self.handoff_version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.session_id);
        encoder.fixed(&self.body_package_id);
        encoder.fixed(&self.body_certificate_id);
        encoder.fixed(&self.operator_pubkey);
        encoder.fixed(&self.gateway_pubkey);
        encoder.fixed(&self.core_handoff_pubkey);
        encoder.fixed(&self.worker_id_hash);
        encoder.fixed(&self.payout_bucket_id);
        encoder.u64(self.assignment_sequence);
        encoder.u64(self.ntime);
        encoder.u16(self.extra_nonce_profile);
        encoder.u16(self.observation_policy);
        encoder.u64(self.maximum_clock_skew_ms);
        encoder.fixed(&self.extra_nonce_prefix);
        encoder.fixed(&self.extra_nonce2_start_be);
        encoder.fixed(&self.extra_nonce2_end_be);
        encoder.u32(self.nonce_start);
        encoder.u32(self.nonce_end);
        encoder.u32(self.nonce_stride);
        self.edge_target.encode(encoder);
        self.capture_target.encode(encoder);
        encoder.u8(self.telemetry_level);
    }
}

impl CanonicalEncode for GatewayAssignmentV1 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        encode_signature(encoder, &self.operator_signature);
    }
}

impl CanonicalDecode for GatewayAssignmentV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            core_protocol_version: decoder.u16()?,
            handoff_version: decoder.u16()?,
            network_id: decoder.u8()?,
            session_id: decoder.array()?,
            body_package_id: decoder.array()?,
            body_certificate_id: decoder.array()?,
            operator_pubkey: decoder.array()?,
            gateway_pubkey: decoder.array()?,
            core_handoff_pubkey: decoder.array()?,
            worker_id_hash: decoder.array()?,
            payout_bucket_id: decoder.array()?,
            assignment_sequence: decoder.u64()?,
            ntime: decoder.u64()?,
            extra_nonce_profile: decoder.u16()?,
            observation_policy: decoder.u16()?,
            maximum_clock_skew_ms: decoder.u64()?,
            extra_nonce_prefix: decoder.array()?,
            extra_nonce2_start_be: decoder.array()?,
            extra_nonce2_end_be: decoder.array()?,
            nonce_start: decoder.u32()?,
            nonce_end: decoder.u32()?,
            nonce_stride: decoder.u32()?,
            edge_target: U256::decode(decoder)?,
            capture_target: U256::decode(decoder)?,
            telemetry_level: decoder.u8()?,
            operator_signature: SignatureBytes::decode(decoder)?,
        })
    }
}

impl ShareV2 {
    pub const MAX_DAG_PARENTS: usize = 4;

    pub fn work_key(&self) -> Hash256 {
        let mut encoder = Encoder::new();
        encoder.fixed(&self.session_id);
        encoder.fixed(&self.body_package_id);
        encoder.u64(self.ntime);
        encoder.fixed(&self.extra_nonce);
        encoder.u32(self.nonce);
        encoder.fixed(&self.raw_share_hash);
        domain_hash("meshmine/share-work-key/v2", encoder.as_bytes())
    }

    pub fn validate_parents(&self) -> Result<(), ObjectError> {
        if self.gossip_parent_hashes.len() > Self::MAX_DAG_PARENTS {
            return Err(ObjectError::Codec(CodecError::LengthLimit {
                actual: self.gossip_parent_hashes.len(),
                maximum: Self::MAX_DAG_PARENTS,
            }));
        }
        let unique: HashSet<_> = self.gossip_parent_hashes.iter().collect();
        if unique.len() != self.gossip_parent_hashes.len() {
            return Err(ObjectError::UnsortedDagParents);
        }
        Ok(())
    }
}

impl UnsignedObject for ShareV2 {
    const DOMAIN_TAG: &'static str = "meshmine/share/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encode_prefix(encoder, self.protocol_version, self.network_id);
        encoder.fixed(&self.session_id);
        encoder.fixed(&self.assignment_id);
        encoder.fixed(&self.body_package_id);
        encoder.fixed(&self.operator_pubkey);
        encoder.fixed(&self.payout_bucket_id);
        encoder.u32(self.nonce);
        encoder.u64(self.ntime);
        encoder.fixed(&self.extra_nonce);
        encoder.fixed(&self.raw_share_hash);
        self.declared_target.encode(encoder);
        encode_hashes(encoder, &self.gossip_parent_hashes);
        encode_option(encoder, &self.local_telemetry_hash, |encoder, hash| {
            encoder.fixed(hash);
        });
    }
}

impl CanonicalEncode for ShareV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        encode_signature(encoder, &self.operator_signature);
    }
}

impl CanonicalDecode for ShareV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let (protocol_version, network_id) = decode_prefix(decoder)?;
        let session_id = decoder.array()?;
        let assignment_id = decoder.array()?;
        let body_package_id = decoder.array()?;
        let operator_pubkey = decoder.array()?;
        let payout_bucket_id = decoder.array()?;
        let nonce = decoder.u32()?;
        let ntime = decoder.u64()?;
        let extra_nonce = decoder.array()?;
        let raw_share_hash = decoder.array()?;
        let declared_target = U256::decode(decoder)?;
        let parent_count = decoder.length(Self::MAX_DAG_PARENTS)?;
        let gossip_parent_hashes = (0..parent_count)
            .map(|_| decoder.array())
            .collect::<Result<Vec<_>, _>>()?;
        let result = Self {
            protocol_version,
            network_id,
            session_id,
            assignment_id,
            body_package_id,
            operator_pubkey,
            payout_bucket_id,
            nonce,
            ntime,
            extra_nonce,
            raw_share_hash,
            declared_target,
            gossip_parent_hashes,
            local_telemetry_hash: decoder.option(|decoder| decoder.array())?,
            operator_signature: SignatureBytes::decode(decoder)?,
        };
        result
            .validate_parents()
            .map_err(|_| CodecError::InvalidField("duplicate DAG parents"))?;
        Ok(result)
    }
}

impl ReceiptBatchV2 {
    pub fn validate_entries(&self) -> Result<(), ObjectError> {
        let length = self.accepted_share_ids.len();
        if self.accepted_work_keys.len() != length || self.credited_work.len() != length {
            return Err(ObjectError::ReceiptLengthMismatch);
        }
        for index in 1..length {
            let previous = (
                &self.accepted_work_keys[index - 1],
                &self.accepted_share_ids[index - 1],
            );
            let current = (
                &self.accepted_work_keys[index],
                &self.accepted_share_ids[index],
            );
            if previous >= current {
                return Err(ObjectError::UnsortedReceiptEntries);
            }
        }
        self.signer_set.validate_order()?;
        Ok(())
    }
}

impl UnsignedObject for ReceiptBatchV2 {
    const DOMAIN_TAG: &'static str = "meshmine/receipt-batch/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encode_prefix(encoder, self.protocol_version, self.network_id);
        encoder.fixed(&self.session_id);
        encoder.u64(self.batch_sequence);
        encoder.fixed(&self.previous_batch_id);
        encode_hashes(encoder, &self.accepted_share_ids);
        encode_hashes(encoder, &self.accepted_work_keys);
        encode_u512s(encoder, &self.credited_work);
        encoder.fixed(&self.share_merkle_root);
        encoder.u64(self.cumulative_share_count);
        self.cumulative_credited_work.encode(encoder);
    }
}

impl CanonicalEncode for ReceiptBatchV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        encode_signature_set(encoder, &self.signer_set);
    }
}

impl CanonicalDecode for ReceiptBatchV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let (protocol_version, network_id) = decode_prefix(decoder)?;
        let result = Self {
            protocol_version,
            network_id,
            session_id: decoder.array()?,
            batch_sequence: decoder.u64()?,
            previous_batch_id: decoder.array()?,
            accepted_share_ids: decode_hashes(decoder)?,
            accepted_work_keys: decode_hashes(decoder)?,
            credited_work: decode_u512s(decoder)?,
            share_merkle_root: decoder.array()?,
            cumulative_share_count: decoder.u64()?,
            cumulative_credited_work: U512::decode(decoder)?,
            signer_set: SignatureSet::decode(decoder)?,
        };
        result
            .validate_entries()
            .map_err(|_| CodecError::InvalidField("invalid receipt entries"))?;
        Ok(result)
    }
}

impl UnsignedObject for SessionCloseV2 {
    const DOMAIN_TAG: &'static str = "meshmine/session-close/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encode_prefix(encoder, self.protocol_version, self.network_id);
        encoder.fixed(&self.session_id);
        encoder.fixed(&self.final_receipt_batch_id);
        encoder.fixed(&self.accepted_share_merkle_root);
        encoder.fixed(&self.accepted_work_key_root);
        encoder.u64(self.accepted_share_count);
        self.total_credited_work.encode(encoder);
        encoder.u16(self.close_reason);
        encoder.fixed(&self.mask_opening_transcript_root);
        encode_hashes(encoder, &self.discovered_hns_block_ids);
    }
}

impl CanonicalEncode for SessionCloseV2 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        encode_signature_set(encoder, &self.signer_set);
    }
}

impl CanonicalDecode for SessionCloseV2 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let (protocol_version, network_id) = decode_prefix(decoder)?;
        Ok(Self {
            protocol_version,
            network_id,
            session_id: decoder.array()?,
            final_receipt_batch_id: decoder.array()?,
            accepted_share_merkle_root: decoder.array()?,
            accepted_work_key_root: decoder.array()?,
            accepted_share_count: decoder.u64()?,
            total_credited_work: U512::decode(decoder)?,
            close_reason: decoder.u16()?,
            mask_opening_transcript_root: decoder.array()?,
            discovered_hns_block_ids: decode_hashes(decoder)?,
            signer_set: SignatureSet::decode(decoder)?,
        })
    }
}
