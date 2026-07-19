use std::{collections::HashMap, fs, path::PathBuf};

use meshmine_codec::CanonicalEncode;
use meshmine_types::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct VectorFile {
    wire_profile: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    unsigned_hex: String,
    canonical_hex: String,
    id_hex: String,
    work_key_hex: Option<String>,
}

fn hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn signature(byte: u8) -> SignatureBytes {
    SignatureBytes(vec![byte; 64])
}

fn signer_set() -> SignatureSet {
    SignatureSet {
        signature_suite: ED25519_SUITE,
        signatures: vec![
            SignerSignature {
                signer_pubkey: hash(1),
                signature: signature(11),
            },
            SignerSignature {
                signer_pubkey: hash(2),
                signature: signature(22),
            },
        ],
    }
}

fn assert_vector<T: UnsignedObject + CanonicalEncode>(
    vectors: &HashMap<String, Vector>,
    name: &str,
    object: &T,
) {
    let vector = &vectors[name];
    assert_eq!(hex::encode(object.unsigned_bytes()), vector.unsigned_hex);
    assert_eq!(
        hex::encode(object.to_canonical_bytes()),
        vector.canonical_hex
    );
    assert_eq!(hex::encode(object.object_id()), vector.id_hex);
}

#[test]
fn rust_matches_node_core_v2_golden_vectors() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../specs/wire-vectors/core-v2.json");
    let file: VectorFile = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(file.wire_profile, "meshmine-core-v2-research");
    let vectors: HashMap<_, _> = file
        .vectors
        .into_iter()
        .map(|vector| (vector.name.clone(), vector))
        .collect();
    assert_eq!(vectors.len(), 14, "every Core v2 object needs a vector");

    let operator = OperatorRecordV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        operator_pubkey: hash(1),
        sequence: 2,
        supported_features: 3,
        payout_bucket_ids: vec![hash(4), hash(5)],
        contact_metadata_hash: Some(hash(6)),
        signature_suite: ED25519_SUITE,
        signature: signature(7),
    };
    assert_vector(&vectors, "operator-record-v2", &operator);

    let bucket = PayoutBucketV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        operator_pubkey: hash(1),
        bucket_sequence: 2,
        hns_address_version: 0,
        hns_address_hash: vec![3; 20],
        activation_height: 4,
        retirement_height: Some(5),
        signature: signature(6),
    };
    assert_vector(&vectors, "payout-bucket-v2", &bucket);

    let snapshot = PayoutSnapshotV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        snapshot_sequence: 1,
        previous_snapshot_id: hash(1),
        first_session_close_id: hash(2),
        last_session_close_id: hash(3),
        close_anchor_height: 4,
        work_window_target: U512([5; 64]),
        actual_work_in_window: U512([6; 64]),
        work_buckets: vec![WorkBucketLeaf {
            bucket_id: hash(1),
            operator_pubkey: hash(7),
            hns_address_version: 0,
            hns_address_hash: vec![8; 20],
            credited_work: U512([9; 64]),
        }],
        service_buckets: vec![ServiceBucketLeaf {
            bucket_id: hash(2),
            operator_pubkey: hash(10),
            hns_address_version: 0,
            hns_address_hash: vec![11; 20],
            certified_service_credit: U512([12; 64]),
        }],
        share_set_root: hash(13),
        service_set_root: hash(14),
        settlement_committee_id: hash(15),
        signer_set: signer_set(),
    };
    assert_vector(&vectors, "payout-snapshot-v2", &snapshot);

    let plan = PayoutPlanV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        plan_sequence: 1,
        snapshot_id: hash(2),
        entropy_anchor_start: 3,
        entropy_anchor_count: 1,
        entropy_hashes: vec![hash(4)],
        prior_beacon: hash(5),
        plan_seed: hash(6),
        work_ticket_count: 7,
        service_ticket_count: 8,
        work_winners: vec![hash(9)],
        service_winners: vec![hash(10)],
        selection_transcript_hash: hash(11),
        signer_set: signer_set(),
    };
    assert_vector(&vectors, "payout-plan-v2", &plan);

    let template = TemplateCoreV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        hns_parent_hash: hash(1),
        hns_parent_height: 100,
        operator_pubkey: hash(2),
        operator_fee_bucket_id: hash(3),
        payout_snapshot_id: hash(4),
        payout_plan_id: hash(5),
        plan_sequence: 6,
        ordered_non_coinbase_txids: vec![hash(7), hash(8)],
        ordered_claim_ids: vec![hash(9)],
        ordered_airdrop_ids: vec![],
        block_version: 10,
        bits: 0x207f_ffff,
        minimum_ntime: 11,
        policy_commitment: hash(12),
    };
    assert_vector(&vectors, "template-core-v2", &template);

    let body = BlockBodyPackageV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        template_core: template.clone(),
        template_core_id: template.object_id(),
        coinbase_raw: vec![1, 2, 3],
        transactions_raw: vec![vec![4, 5], vec![6]],
        merkle_root: hash(13),
        witness_root: hash(14),
        tree_root: hash(15),
        reserved_root: hash(16),
        block_weight: 17,
        block_sigops: 18,
        miner_subsidy: 19,
        ordinary_transaction_fees: 20,
        claim_airdrop_principal: 21,
        claim_airdrop_fees: 22,
        operator_fee_value: 23,
        work_service_subsidy_value: 24,
        hsd_validation_result_hash: hash(25),
        operator_signature: signature(26),
    };
    assert_vector(&vectors, "body-package-v2", &body);

    let descriptor = BodyErasureDescriptorV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        body_package_id: hash(1),
        original_size: 2,
        data_shards: 3,
        parity_shards: 4,
        shard_size: 5,
        shard_merkle_root: hash(6),
        expiry_height: 7,
        compression: 8,
    };
    assert_vector(&vectors, "body-erasure-v2", &descriptor);

    let body_certificate = BodyAvailabilityCertificateV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        descriptor_id: hash(1),
        parent_hash: hash(2),
        parent_height: 3,
        hsd_validation_result_hash: hash(4),
        challenge_round: 5,
        challenge_transcript_root: hash(6),
        signer_set: signer_set(),
    };
    assert_vector(&vectors, "body-certificate-v2", &body_certificate);

    let parent_certificate = SessionParentCertificateV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        parent_hash: hash(1),
        parent_height: 2,
        parent_chainwork: U256([3; 32]),
        observed_ntime: 4,
        certificate_sequence: 5,
        previous_parent_certificate_id: hash(6),
        signer_set: signer_set(),
    };
    assert_vector(&vectors, "parent-certificate-v2", &parent_certificate);

    let mask_session = MaskSessionV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        lane_id: 1,
        session_sequence: 2,
        parent_certificate_id: hash(3),
        parent_hash: hash(4),
        hns_network_target: U256([5; 32]),
        capture_target: U256([6; 32]),
        accounting_target: U256([6; 32]),
        leading_zero_prefix_q: 7,
        blind_band_bits_d: 8,
        mask_hash: hash(9),
        mask_commitment_root: hash(10),
        mask_committee_id: hash(11),
        fast_eval_policy: 12,
        assignment_start_ms: 13,
        assignment_end_ms: 14,
        submission_end_ms: 15,
        timed_open_after_ms: 16,
        previous_session_id: hash(17),
        signer_set: signer_set(),
    };
    assert_vector(&vectors, "mask-session-v2", &mask_session);

    let assignment = AssignmentV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        session_id: hash(1),
        body_package_id: hash(2),
        body_certificate_id: hash(3),
        operator_pubkey: hash(4),
        worker_id_hash: hash(5),
        payout_bucket_id: hash(6),
        assignment_sequence: 7,
        ntime: 8,
        extra_nonce: [9; 24],
        nonce_start: 10,
        nonce_end: 11,
        nonce_stride: 12,
        edge_target: U256([13; 32]),
        capture_target: U256([14; 32]),
        telemetry_level: 0,
        operator_signature: signature(15),
    };
    assert_vector(&vectors, "assignment-v2", &assignment);

    let share = ShareV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        session_id: hash(1),
        assignment_id: hash(2),
        body_package_id: hash(3),
        operator_pubkey: hash(4),
        payout_bucket_id: hash(5),
        nonce: 6,
        ntime: 7,
        extra_nonce: [8; 24],
        raw_share_hash: hash(9),
        declared_target: U256([10; 32]),
        gossip_parent_hashes: vec![hash(11), hash(12)],
        local_telemetry_hash: Some(hash(13)),
        operator_signature: signature(14),
    };
    assert_vector(&vectors, "share-v2", &share);
    assert_eq!(
        hex::encode(share.work_key()),
        vectors["share-v2"].work_key_hex.as_deref().unwrap()
    );

    let receipt = ReceiptBatchV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        session_id: hash(1),
        batch_sequence: 2,
        previous_batch_id: hash(3),
        accepted_share_ids: vec![hash(10), hash(11)],
        accepted_work_keys: vec![hash(4), hash(5)],
        credited_work: vec![U512([6; 64]), U512([7; 64])],
        share_merkle_root: hash(8),
        cumulative_share_count: 9,
        cumulative_credited_work: U512([10; 64]),
        signer_set: signer_set(),
    };
    assert_vector(&vectors, "receipt-batch-v2", &receipt);

    let close = SessionCloseV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        session_id: hash(1),
        final_receipt_batch_id: hash(2),
        accepted_share_merkle_root: hash(3),
        accepted_work_key_root: hash(4),
        accepted_share_count: 5,
        total_credited_work: U512([6; 64]),
        close_reason: 7,
        mask_opening_transcript_root: hash(8),
        discovered_hns_block_ids: vec![hash(9)],
        signer_set: signer_set(),
    };
    assert_vector(&vectors, "session-close-v2", &close);
}
