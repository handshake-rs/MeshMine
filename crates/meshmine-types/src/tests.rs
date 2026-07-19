use std::collections::{HashMap, HashSet};

use meshmine_codec::{CanonicalDecode, CanonicalEncode, DecodeLimits};

use crate::*;

fn hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn u256(byte: u8) -> U256 {
    U256([byte; 32])
}

fn u512(byte: u8) -> U512 {
    U512([byte; 64])
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

fn template() -> TemplateCoreV2 {
    TemplateCoreV2 {
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
    }
}

fn body() -> BlockBodyPackageV2 {
    let template_core = template();
    let template_core_id = template_core.object_id();
    BlockBodyPackageV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        template_core,
        template_core_id,
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
    }
}

fn share() -> ShareV2 {
    ShareV2 {
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
        declared_target: u256(10),
        gossip_parent_hashes: vec![hash(11), hash(12)],
        local_telemetry_hash: Some(hash(13)),
        operator_signature: signature(14),
    }
}

fn gateway_assignment() -> GatewayAssignmentV1 {
    GatewayAssignmentV1 {
        core_protocol_version: CORE_V2,
        handoff_version: GATEWAY_HANDOFF_V1,
        network_id: 2,
        session_id: hash(1),
        body_package_id: hash(2),
        body_certificate_id: hash(3),
        operator_pubkey: hash(4),
        gateway_pubkey: hash(5),
        core_handoff_pubkey: hash(6),
        worker_id_hash: hash(7),
        payout_bucket_id: hash(8),
        assignment_sequence: 9,
        ntime: 10,
        extra_nonce_profile: GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16,
        observation_policy: GATEWAY_OBSERVATION_CORE_RECEIPT_TIME,
        maximum_clock_skew_ms: 0,
        extra_nonce_prefix: [11; 4],
        extra_nonce2_start_be: [0, 0, 0, 2],
        extra_nonce2_end_be: [0, 0, 0, 4],
        nonce_start: 12,
        nonce_end: 13,
        nonce_stride: 14,
        edge_target: u256(15),
        capture_target: u256(16),
        telemetry_level: 0,
        operator_signature: signature(17),
    }
}

fn roundtrip<T>(value: &T)
where
    T: CanonicalEncode + CanonicalDecode + PartialEq + std::fmt::Debug,
{
    let encoded = value.to_canonical_bytes();
    let decoded = T::from_canonical_bytes(&encoded, DecodeLimits::default()).unwrap();
    assert_eq!(&decoded, value);
}

#[test]
fn every_core_object_round_trips_canonically() {
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
    roundtrip(&operator);

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
    roundtrip(&bucket);

    let snapshot = PayoutSnapshotV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        snapshot_sequence: 1,
        previous_snapshot_id: hash(1),
        first_session_close_id: hash(2),
        last_session_close_id: hash(3),
        close_anchor_height: 4,
        work_window_target: u512(5),
        actual_work_in_window: u512(6),
        work_buckets: vec![WorkBucketLeaf {
            bucket_id: hash(1),
            operator_pubkey: hash(7),
            hns_address_version: 0,
            hns_address_hash: vec![8; 20],
            credited_work: u512(9),
        }],
        service_buckets: vec![ServiceBucketLeaf {
            bucket_id: hash(2),
            operator_pubkey: hash(10),
            hns_address_version: 0,
            hns_address_hash: vec![11; 20],
            certified_service_credit: u512(12),
        }],
        share_set_root: hash(13),
        service_set_root: hash(14),
        settlement_committee_id: hash(15),
        signer_set: signer_set(),
    };
    roundtrip(&snapshot);

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
    roundtrip(&plan);
    roundtrip(&template());
    roundtrip(&body());

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
    roundtrip(&descriptor);

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
    roundtrip(&body_certificate);

    let parent_certificate = SessionParentCertificateV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        parent_hash: hash(1),
        parent_height: 2,
        parent_chainwork: u256(3),
        observed_ntime: 4,
        certificate_sequence: 5,
        previous_parent_certificate_id: hash(6),
        signer_set: signer_set(),
    };
    roundtrip(&parent_certificate);

    let mask_session = MaskSessionV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        lane_id: 1,
        session_sequence: 2,
        parent_certificate_id: hash(3),
        parent_hash: hash(4),
        hns_network_target: u256(5),
        capture_target: u256(6),
        accounting_target: u256(6),
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
    roundtrip(&mask_session);

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
        edge_target: u256(13),
        capture_target: u256(14),
        telemetry_level: 0,
        operator_signature: signature(15),
    };
    roundtrip(&assignment);
    roundtrip(&gateway_assignment());
    roundtrip(&share());

    let receipt = ReceiptBatchV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        session_id: hash(1),
        batch_sequence: 2,
        previous_batch_id: hash(3),
        accepted_share_ids: vec![hash(10), hash(11)],
        accepted_work_keys: vec![hash(4), hash(5)],
        credited_work: vec![u512(6), u512(7)],
        share_merkle_root: hash(8),
        cumulative_share_count: 9,
        cumulative_credited_work: u512(10),
        signer_set: signer_set(),
    };
    roundtrip(&receipt);

    let close = SessionCloseV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        session_id: hash(1),
        final_receipt_batch_id: hash(2),
        accepted_share_merkle_root: hash(3),
        accepted_work_key_root: hash(4),
        accepted_share_count: 5,
        total_credited_work: u512(6),
        close_reason: 7,
        mask_opening_transcript_root: hash(8),
        discovered_hns_block_ids: vec![hash(9)],
        signer_set: signer_set(),
    };
    roundtrip(&close);
}

#[test]
fn identifiers_exclude_signatures_and_include_body_fields() {
    let mut object = share();
    let original_id = object.object_id();
    let original_work_key = object.work_key();

    object.operator_signature = signature(99);
    assert_eq!(object.object_id(), original_id);

    object.gossip_parent_hashes = vec![hash(20)];
    assert_ne!(object.object_id(), original_id);
    assert_eq!(object.work_key(), original_work_key);

    object.nonce += 1;
    assert_ne!(object.work_key(), original_work_key);

    let mut body = body();
    let body_id = body.object_id();
    body.operator_signature = signature(100);
    assert_eq!(body.object_id(), body_id);
    body.coinbase_raw.push(42);
    assert_ne!(body.object_id(), body_id);

    let mut gateway = gateway_assignment();
    let gateway_id = gateway.object_id();
    assert_ne!(
        gateway_id,
        assignment_domain_collision_fixture().object_id()
    );
    gateway.operator_signature = signature(101);
    assert_eq!(gateway.object_id(), gateway_id);
    gateway.extra_nonce2_end_be[3] += 1;
    assert_ne!(gateway.object_id(), gateway_id);
}

fn assignment_domain_collision_fixture() -> AssignmentV2 {
    AssignmentV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        session_id: hash(1),
        body_package_id: hash(2),
        body_certificate_id: hash(3),
        operator_pubkey: hash(4),
        worker_id_hash: hash(7),
        payout_bucket_id: hash(8),
        assignment_sequence: 9,
        ntime: 10,
        extra_nonce: [11; 24],
        nonce_start: 12,
        nonce_end: 13,
        nonce_stride: 14,
        edge_target: u256(15),
        capture_target: u256(16),
        telemetry_level: 0,
        operator_signature: signature(17),
    }
}

#[test]
fn gateway_assignment_accepts_only_its_signed_handy_extra_nonce_range() {
    let mut assignment = gateway_assignment();
    for nonce2 in [[0, 0, 0, 2], [0, 0, 0, 3], [0, 0, 0, 4]] {
        let mut extra_nonce = [0; 24];
        extra_nonce[..4].copy_from_slice(&assignment.extra_nonce_prefix);
        extra_nonce[4..8].copy_from_slice(&nonce2);
        assert!(assignment.accepts_extra_nonce(&extra_nonce));
    }
    for nonce2 in [[0, 0, 0, 1], [0, 0, 0, 5]] {
        let mut extra_nonce = [0; 24];
        extra_nonce[..4].copy_from_slice(&assignment.extra_nonce_prefix);
        extra_nonce[4..8].copy_from_slice(&nonce2);
        assert!(!assignment.accepts_extra_nonce(&extra_nonce));
    }
    let mut malformed = [0; 24];
    malformed[..4].copy_from_slice(&assignment.extra_nonce_prefix);
    malformed[4..8].copy_from_slice(&[0, 0, 0, 3]);
    malformed[8] = 1;
    assert!(!assignment.accepts_extra_nonce(&malformed));
    malformed[8] = 0;
    malformed[0] ^= 1;
    assert!(!assignment.accepts_extra_nonce(&malformed));

    assignment.extra_nonce2_start_be = [0, 0, 0, 5];
    assignment.extra_nonce2_end_be = [0, 0, 0, 4];
    assert!(!assignment.accepts_extra_nonce(&[0; 24]));
    assignment.extra_nonce_profile = 0;
    assert!(!assignment.accepts_extra_nonce(&[0; 24]));
}

#[test]
fn rejects_noncanonical_lengths_trailing_bytes_and_oversized_signatures() {
    let mut operator = OperatorRecordV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        operator_pubkey: hash(1),
        sequence: 2,
        supported_features: 3,
        payout_bucket_ids: vec![],
        contact_metadata_hash: None,
        signature_suite: ED25519_SUITE,
        signature: signature(4),
    };
    let encoded = operator.to_canonical_bytes();

    let mut noncanonical = encoded.clone();
    // Prefix + key + sequence + features is 51 bytes; the empty bucket vector follows.
    noncanonical.splice(51..52, [0x80, 0x00]);
    assert!(
        OperatorRecordV2::from_canonical_bytes(&noncanonical, DecodeLimits::default()).is_err()
    );

    let mut trailing = encoded;
    trailing.push(0);
    assert!(OperatorRecordV2::from_canonical_bytes(&trailing, DecodeLimits::default()).is_err());

    operator.signature = SignatureBytes(vec![0; MAX_SIGNATURE_BYTES + 1]);
    assert!(
        OperatorRecordV2::from_canonical_bytes(
            &operator.to_canonical_bytes(),
            DecodeLimits::default()
        )
        .is_err()
    );
}

#[test]
fn rejects_unsorted_certificate_signers_and_receipts() {
    let mut set = signer_set();
    set.signatures.reverse();
    let bytes = set.to_canonical_bytes();
    assert!(SignatureSet::from_canonical_bytes(&bytes, DecodeLimits::default()).is_err());

    let receipt = ReceiptBatchV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        session_id: hash(1),
        batch_sequence: 2,
        previous_batch_id: hash(3),
        accepted_share_ids: vec![hash(4), hash(5)],
        accepted_work_keys: vec![hash(9), hash(8)],
        credited_work: vec![u512(1), u512(1)],
        share_merkle_root: hash(6),
        cumulative_share_count: 2,
        cumulative_credited_work: u512(2),
        signer_set: signer_set(),
    };
    assert!(
        ReceiptBatchV2::from_canonical_bytes(
            &receipt.to_canonical_bytes(),
            DecodeLimits::default()
        )
        .is_err()
    );
}

#[test]
fn declared_object_id_dependency_graph_is_acyclic() {
    // Previous-ID links point to already finalized objects, represented here
    // as explicit prior nodes rather than self-edges on the current object.
    let graph: HashMap<&str, Vec<&str>> = HashMap::from([
        ("prior-session-close", vec![]),
        ("prior-parent-certificate", vec![]),
        ("prior-mask-session", vec![]),
        ("prior-receipt-batch", vec![]),
        ("payout-snapshot", vec!["prior-session-close"]),
        ("payout-plan", vec!["payout-snapshot"]),
        ("template-core", vec!["payout-snapshot", "payout-plan"]),
        ("body-package", vec!["template-core"]),
        ("body-erasure", vec!["body-package"]),
        ("body-certificate", vec!["body-erasure"]),
        ("parent-certificate", vec!["prior-parent-certificate"]),
        (
            "mask-session",
            vec!["parent-certificate", "prior-mask-session"],
        ),
        (
            "assignment",
            vec!["mask-session", "body-package", "body-certificate"],
        ),
        (
            "gateway-assignment",
            vec!["mask-session", "body-package", "body-certificate"],
        ),
        ("share", vec!["assignment", "body-package", "mask-session"]),
        ("receipt-batch", vec!["share", "prior-receipt-batch"]),
        ("session-close", vec!["mask-session", "receipt-batch"]),
    ]);

    fn visit<'a>(
        node: &'a str,
        graph: &HashMap<&'a str, Vec<&'a str>>,
        visiting: &mut HashSet<&'a str>,
        visited: &mut HashSet<&'a str>,
    ) {
        assert!(visiting.insert(node), "object ID cycle at {node}");
        for dependency in &graph[node] {
            assert_ne!(node, *dependency, "object ID directly depends on itself");
            if !visited.contains(dependency) {
                visit(dependency, graph, visiting, visited);
            }
        }
        visiting.remove(node);
        visited.insert(node);
    }

    let mut visited = HashSet::new();
    for node in graph.keys() {
        if !visited.contains(node) {
            visit(node, &graph, &mut HashSet::new(), &mut visited);
        }
    }
    assert_eq!(visited.len(), graph.len());
}
