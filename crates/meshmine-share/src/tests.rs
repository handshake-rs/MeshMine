use ed25519_dalek::SigningKey;
use meshmine_crypto::{assemble_ed25519_set, sign_certificate, sign_object};
use meshmine_handoff::{
    persist_gateway_assignment_authorization, persist_gateway_context_manifest,
};
use meshmine_hns::MinerHeader;
use meshmine_storage::{MemoryStore, ProtocolJournal, ProtocolRecordKind, RedbStore};
use meshmine_types::{
    CORE_V2, GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16, SignatureBytes,
    SignerSignature, WorkBucketLeaf,
};

use super::*;

fn secure_tempdir() -> std::io::Result<tempfile::TempDir> {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(directory)
}

struct TestParentOracle(bool);

impl ParentChainOracle for TestParentOracle {
    fn verify_header_and_chainwork(&self, _certificate: &SessionParentCertificateV2) -> bool {
        self.0
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

fn certificate_subject() -> PayoutBucketV2 {
    PayoutBucketV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        operator_pubkey: hash(99),
        bucket_sequence: 0,
        hns_address_version: 0,
        hns_address_hash: vec![1; 20],
        activation_height: 0,
        retirement_height: None,
        signature: SignatureBytes::empty(),
    }
}

#[test]
fn committee_roster_rejects_empty_roster_with_empty_certificate() {
    let roster = CommitteeRoster {
        protocol_version: CORE_V2,
        network_id: 2,
        role: CommitteeRole::Settlement,
        epoch: 1,
        threshold: 1,
        members: BTreeSet::new(),
    };

    assert!(matches!(
        roster.verify(&SignatureSet::empty_ed25519(), &certificate_subject()),
        Err(ShareError::InvalidCommitteeRoster)
    ));
}

#[test]
fn committee_roster_rejects_zero_threshold_with_members() {
    let keys = [key(1), key(2), key(3)];
    let mut roster = roster(CommitteeRole::Settlement, &keys);
    roster.threshold = 0;

    assert!(matches!(
        roster.verify(&SignatureSet::empty_ed25519(), &certificate_subject()),
        Err(ShareError::InvalidCommitteeRoster)
    ));
}

#[test]
fn committee_roster_rejects_threshold_above_member_count() {
    let keys = [key(1), key(2), key(3)];
    let mut roster = roster(CommitteeRole::Settlement, &keys);
    roster.threshold = 4;

    assert!(matches!(
        roster.verify(&SignatureSet::empty_ed25519(), &certificate_subject()),
        Err(ShareError::InvalidCommitteeRoster)
    ));
}

#[test]
fn committee_roster_rejects_oversized_member_set() {
    let members = (0..=MAX_COMMITTEE_MEMBERS)
        .map(|index| {
            let mut member = [0; 32];
            member[..8].copy_from_slice(&(index as u64).to_le_bytes());
            member
        })
        .collect();
    let roster = CommitteeRoster {
        protocol_version: CORE_V2,
        network_id: 2,
        role: CommitteeRole::Settlement,
        epoch: 1,
        threshold: 1,
        members,
    };

    assert!(matches!(
        roster.verify(&SignatureSet::empty_ed25519(), &certificate_subject()),
        Err(ShareError::InvalidCommitteeRoster)
    ));
}

#[test]
fn committee_roster_accepts_valid_threshold_certificate() {
    let keys = [key(1), key(2), key(3)];
    let roster = roster(CommitteeRole::Settlement, &keys);
    let subject = certificate_subject();
    let certificate = certify(&subject, &keys);

    assert!(roster.validate().is_ok());
    assert!(roster.verify(&certificate, &subject).is_ok());
}

#[test]
fn exact_share_validation_checks_hns_header_signatures_and_certificates() {
    let operator_key = key(42);
    let operator_pubkey = operator_key.verifying_key().to_bytes();
    let mask_keys = [key(1), key(2), key(3)];
    let availability_keys = [key(4), key(5), key(6)];
    let settlement_keys = [key(7), key(8), key(9)];
    let mask_roster = roster(CommitteeRole::Mask, &mask_keys);
    let availability_roster = roster(CommitteeRole::Availability, &availability_keys);
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

    let mut parent_certificate = SessionParentCertificateV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        parent_hash: hash(11),
        parent_height: 10,
        parent_chainwork: U256(hash(12)),
        observed_ntime: 100,
        certificate_sequence: 1,
        previous_parent_certificate_id: [0; 32],
        signer_set: SignatureSet::empty_ed25519(),
    };
    parent_certificate.signer_set = certify(&parent_certificate, &settlement_keys);

    let template_core = meshmine_types::TemplateCoreV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        hns_parent_hash: parent_certificate.parent_hash,
        hns_parent_height: parent_certificate.parent_height,
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
    let template_core_id = template_core.object_id();
    let mut body = BlockBodyPackageV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        template_core,
        template_core_id,
        coinbase_raw: vec![1, 2, 3],
        transactions_raw: vec![],
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
        consensus_validation_result_hash: hash(20),
        operator_signature: SignatureBytes::empty(),
    };
    body.operator_signature = sign_object(&operator_key, 2, &body);

    let descriptor = BodyErasureDescriptorV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        body_package_id: body.object_id(),
        original_size: 100,
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
        parent_hash: parent_certificate.parent_hash,
        parent_height: parent_certificate.parent_height,
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
        parent_certificate_id: parent_certificate.object_id(),
        parent_hash: parent_certificate.parent_hash,
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

    let context = ShareValidationContext {
        assignment: &assignment,
        session: &session,
        parent_certificate: &parent_certificate,
        body: &body,
        descriptor: &descriptor,
        body_certificate: &body_certificate,
        payout_bucket: &payout_bucket,
        mask_roster: &mask_roster,
        availability_roster: &availability_roster,
        settlement_roster: &settlement_roster,
        observed_ms: 2,
        parent_oracle: &TestParentOracle(true),
    };
    let validated = validate_share(share.clone(), &context).unwrap();
    assert_eq!(validated.share_id, share.object_id());
    assert_eq!(validated.work_key, share.work_key());

    let gateway_key = key(43);
    let core_handoff_key = key(44);
    let mut context_manifest = GatewayContextManifestV1 {
        core_protocol_version: CORE_V2,
        handoff_version: GATEWAY_HANDOFF_V1,
        network_id: 2,
        context_sequence: 1,
        previous_manifest_id: [0; 32],
        operator_pubkey,
        gateway_pubkey: gateway_key.verifying_key().to_bytes(),
        core_handoff_pubkey: core_handoff_key.verifying_key().to_bytes(),
        valid_from_ms: 1,
        valid_until_ms: 4,
        maximum_frame_bytes: 65_536,
        maximum_in_flight: 64,
        operator_signature: SignatureBytes::empty(),
    };
    context_manifest.operator_signature = sign_object(&operator_key, 2, &context_manifest);
    let mut gateway_assignment = GatewayAssignmentV1 {
        core_protocol_version: CORE_V2,
        handoff_version: GATEWAY_HANDOFF_V1,
        network_id: 2,
        session_id: session.object_id(),
        body_package_id: body.object_id(),
        body_certificate_id: body_certificate.object_id(),
        operator_pubkey,
        gateway_pubkey: gateway_key.verifying_key().to_bytes(),
        core_handoff_pubkey: core_handoff_key.verifying_key().to_bytes(),
        worker_id_hash: hash(25),
        payout_bucket_id: payout_bucket.object_id(),
        assignment_sequence: 1,
        ntime: 101,
        extra_nonce_profile: GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16,
        observation_policy: GATEWAY_OBSERVATION_CORE_RECEIPT_TIME,
        maximum_clock_skew_ms: 0,
        extra_nonce_prefix: [26; 4],
        extra_nonce2_start_be: [0, 0, 0, 2],
        extra_nonce2_end_be: [0, 0, 0, 4],
        nonce_start: 0,
        nonce_end: u32::MAX,
        nonce_stride: 1,
        edge_target: U256([0xff; 32]),
        capture_target: session.capture_target,
        telemetry_level: 0,
        operator_signature: SignatureBytes::empty(),
    };
    gateway_assignment.operator_signature = sign_object(&operator_key, 2, &gateway_assignment);
    let mut gateway_extra_nonce = [0; 24];
    gateway_extra_nonce[..4].copy_from_slice(&gateway_assignment.extra_nonce_prefix);
    gateway_extra_nonce[4..8].copy_from_slice(&[0, 0, 0, 3]);
    let mut gateway_miner = MinerHeader {
        nonce: 0,
        time: gateway_assignment.ntime,
        prev_block: body.template_core.hns_parent_hash,
        tree_root: body.tree_root,
        mask_hash: session.mask_hash,
        extra_nonce: gateway_extra_nonce,
        reserved_root: body.reserved_root,
        witness_root: body.witness_root,
        merkle_root: body.merkle_root,
        version: body.template_core.block_version,
        bits: body.template_core.bits,
    };
    while gateway_miner.share_hash() > session.capture_target.0 {
        gateway_miner.nonce = gateway_miner.nonce.checked_add(1).unwrap();
    }
    let mut capture_envelope = GatewayCaptureEnvelopeV1 {
        core_protocol_version: CORE_V2,
        handoff_version: GATEWAY_HANDOFF_V1,
        network_id: 2,
        context_manifest_id: context_manifest.object_id(),
        assignment_id: gateway_assignment.object_id(),
        session_id: session.object_id(),
        gateway_pubkey: gateway_key.verifying_key().to_bytes(),
        core_handoff_pubkey: core_handoff_key.verifying_key().to_bytes(),
        gateway_sequence: 1,
        gateway_connection_id: hash(27),
        gateway_received_ms: 2,
        ntime: gateway_miner.time,
        extra_nonce: gateway_miner.extra_nonce,
        nonce: gateway_miner.nonce,
        raw_share_hash: gateway_miner.share_hash(),
        gateway_signature: SignatureBytes::empty(),
    };
    capture_envelope.gateway_signature = sign_object(&gateway_key, 2, &capture_envelope);
    let mut gateway_share = ShareV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        session_id: session.object_id(),
        assignment_id: gateway_assignment.object_id(),
        body_package_id: body.object_id(),
        operator_pubkey,
        payout_bucket_id: payout_bucket.object_id(),
        nonce: gateway_miner.nonce,
        ntime: gateway_miner.time,
        extra_nonce: gateway_miner.extra_nonce,
        raw_share_hash: gateway_miner.share_hash(),
        declared_target: session.capture_target,
        gossip_parent_hashes: vec![],
        local_telemetry_hash: Some(capture_envelope.object_id()),
        operator_signature: SignatureBytes::empty(),
    };
    gateway_share.operator_signature = sign_object(&operator_key, 2, &gateway_share);
    let gateway_context = GatewayShareValidationContext {
        assignment: &gateway_assignment,
        context_manifest: &context_manifest,
        capture_envelope: &capture_envelope,
        session: &session,
        parent_certificate: &parent_certificate,
        body: &body,
        descriptor: &descriptor,
        body_certificate: &body_certificate,
        payout_bucket: &payout_bucket,
        mask_roster: &mask_roster,
        availability_roster: &availability_roster,
        settlement_roster: &settlement_roster,
        core_received_ms: 2,
        parent_oracle: &TestParentOracle(true),
    };
    let gateway_validated =
        validate_gateway_share(gateway_share.clone(), &gateway_context).unwrap();
    assert_eq!(gateway_validated.share_id, gateway_share.object_id());
    assert_eq!(gateway_validated.work_key, gateway_share.work_key());
    let mut capture_receipt = GatewayCaptureReceiptV1 {
        core_protocol_version: CORE_V2,
        handoff_version: GATEWAY_HANDOFF_V1,
        network_id: 2,
        context_manifest_id: context_manifest.object_id(),
        assignment_id: gateway_assignment.object_id(),
        capture_envelope_id: capture_envelope.object_id(),
        gateway_pubkey: gateway_key.verifying_key().to_bytes(),
        core_handoff_pubkey: core_handoff_key.verifying_key().to_bytes(),
        receipt_sequence: 1,
        core_received_ms: 2,
        outcome: CAPTURE_OUTCOME_ACCEPTED,
        reason_code: 0,
        accepted_share_id: gateway_validated.share_id,
        core_signature: SignatureBytes::empty(),
    };
    capture_receipt.core_signature = sign_object(&core_handoff_key, 2, &capture_receipt);
    let gateway_store = MemoryStore::default();
    persist_gateway_context_manifest(&gateway_store, &context_manifest, 2).unwrap();
    persist_gateway_assignment_authorization(
        &gateway_store,
        &context_manifest,
        &gateway_assignment,
    )
    .unwrap();
    let gateway_builder =
        || ReceiptBuilder::new(CORE_V2, 2, session.object_id(), 0, [0; 32], 0, U512::ZERO);
    let mut forged_share_id = gateway_validated.clone();
    forged_share_id.share_id = hash(201);
    assert!(matches!(
        gateway_builder().accept_gateway_durable(
            forged_share_id,
            &context_manifest,
            &gateway_assignment,
            &capture_envelope,
            &capture_receipt,
            &gateway_store,
        ),
        Err(ShareError::Linkage("validated gateway share derivation"))
    ));
    let mut forged_work_key = gateway_validated.clone();
    forged_work_key.work_key = hash(202);
    assert!(matches!(
        gateway_builder().accept_gateway_durable(
            forged_work_key,
            &context_manifest,
            &gateway_assignment,
            &capture_envelope,
            &capture_receipt,
            &gateway_store,
        ),
        Err(ShareError::Linkage("validated gateway share derivation"))
    ));
    let mut forged_credit = gateway_validated.clone();
    forged_credit.credited_work = U512::ZERO;
    assert!(matches!(
        gateway_builder().accept_gateway_durable(
            forged_credit,
            &context_manifest,
            &gateway_assignment,
            &capture_envelope,
            &capture_receipt,
            &gateway_store,
        ),
        Err(ShareError::Linkage("validated gateway share derivation"))
    ));
    let mut gateway_builder =
        ReceiptBuilder::new(CORE_V2, 2, session.object_id(), 0, [0; 32], 0, U512::ZERO);
    gateway_builder
        .accept_gateway_durable(
            gateway_validated.clone(),
            &context_manifest,
            &gateway_assignment,
            &capture_envelope,
            &capture_receipt,
            &gateway_store,
        )
        .unwrap();
    let gateway_journal = ProtocolJournal::new(&gateway_store);
    assert!(
        gateway_journal
            .load(
                ProtocolRecordKind::GatewayCaptureEnvelope,
                &capture_envelope.object_id()
            )
            .unwrap()
            .is_some()
    );
    assert_eq!(
        gateway_journal
            .load(
                ProtocolRecordKind::AcceptedWorkKey,
                &gateway_validated.work_key
            )
            .unwrap()
            .as_deref(),
        Some(gateway_validated.share_id.as_slice())
    );
    assert!(
        gateway_store
            .get(
                meshmine_handoff::GATEWAY_CAPTURE_CURSOR_NAMESPACE,
                &hex::encode(gateway_assignment.object_id())
            )
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        validate_share(gateway_share.clone(), &context),
        Err(ShareError::Linkage("share assignment ID"))
    ));

    let mut outside_range = gateway_share.clone();
    outside_range.extra_nonce[7] = 5;
    outside_range.operator_signature = sign_object(&operator_key, 2, &outside_range);
    assert!(matches!(
        validate_gateway_share(outside_range, &gateway_context),
        Err(ShareError::Linkage("gateway capture envelope"))
    ));

    let mut bad_gateway_signature = gateway_assignment.clone();
    bad_gateway_signature.operator_signature.0[0] ^= 1;
    let bad_gateway_signature_context = GatewayShareValidationContext {
        assignment: &bad_gateway_signature,
        ..gateway_context
    };
    assert!(matches!(
        validate_gateway_share(gateway_share.clone(), &bad_gateway_signature_context),
        Err(ShareError::GatewayHandoff(HandoffError::Signature))
    ));

    let late_gateway_context = GatewayShareValidationContext {
        core_received_ms: 4,
        ..gateway_context
    };
    assert!(matches!(
        validate_gateway_share(gateway_share, &late_gateway_context),
        Err(ShareError::SessionNotOpen)
    ));

    let rejected_context = ShareValidationContext {
        parent_oracle: &TestParentOracle(false),
        ..context
    };
    assert!(matches!(
        validate_share(share.clone(), &rejected_context),
        Err(ShareError::ParentOracleRejected)
    ));

    let closed_context = ShareValidationContext {
        observed_ms: 4,
        ..context
    };
    assert!(matches!(
        validate_share(share.clone(), &closed_context),
        Err(ShareError::SessionNotOpen)
    ));

    let mut bad_session = session.clone();
    bad_session.blind_band_bits_d = 2;
    bad_session.signer_set = certify(&bad_session, &mask_keys);
    let mut bad_assignment = assignment.clone();
    bad_assignment.session_id = bad_session.object_id();
    bad_assignment.operator_signature = sign_object(&operator_key, 2, &bad_assignment);
    let mut bad_share = share.clone();
    bad_share.session_id = bad_session.object_id();
    bad_share.assignment_id = bad_assignment.object_id();
    bad_share.operator_signature = sign_object(&operator_key, 2, &bad_share);
    let bad_profile_context = ShareValidationContext {
        assignment: &bad_assignment,
        session: &bad_session,
        ..context
    };
    assert!(matches!(
        validate_share(bad_share, &bad_profile_context),
        Err(ShareError::InvalidCaptureProfile)
    ));

    share.raw_share_hash[0] ^= 1;
    share.operator_signature = sign_object(&operator_key, 2, &share);
    assert!(matches!(
        validate_share(share, &context),
        Err(ShareError::RawShareHash)
    ));
}

fn fake_validated(seed: u8, parents: Vec<Hash256>) -> ValidatedShare {
    let share = ShareV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        session_id: hash(1),
        assignment_id: hash(seed.wrapping_add(2)),
        body_package_id: hash(3),
        operator_pubkey: hash(4),
        payout_bucket_id: hash(5),
        nonce: u32::from(seed),
        ntime: 7,
        extra_nonce: [8; 24],
        raw_share_hash: hash(seed.wrapping_add(9)),
        declared_target: U256([0xff; 32]),
        gossip_parent_hashes: parents,
        local_telemetry_hash: None,
        operator_signature: SignatureBytes(vec![seed; 64]),
    };
    ValidatedShare {
        share_id: share.object_id(),
        work_key: share.work_key(),
        credited_work: U512::ZERO,
        share,
    }
}

#[test]
fn concurrent_dag_branches_reconcile_and_all_receive_receipt_credit() {
    let root = fake_validated(1, vec![]);
    let left = fake_validated(2, vec![root.share_id]);
    let right = fake_validated(3, vec![root.share_id]);
    let mut dag = ShareDag::new(hash(1), 100, 100);
    dag.insert(root.clone()).unwrap();
    dag.insert(left.clone()).unwrap();
    dag.insert(right.clone()).unwrap();
    assert_eq!(dag.len(), 3);
    assert_eq!(dag.validated_share(&root.share_id), Some(&root));
    assert_eq!(dag.validated_share(&left.share_id), Some(&left));
    assert!(dag.validated_share(&hash(99)).is_none());
    let mut foreign = fake_validated(4, vec![]);
    foreign.share.session_id = hash(2);
    foreign.share_id = foreign.share.object_id();
    foreign.work_key = foreign.share.work_key();
    assert!(matches!(
        dag.insert(foreign.clone()),
        Err(ShareError::CrossSessionParent)
    ));
    assert!(dag.validated_share(&foreign.share_id).is_none());
    assert_eq!(
        dag.tips(),
        vec![
            left.share_id.min(right.share_id),
            left.share_id.max(right.share_id)
        ]
    );

    let remote: BTreeSet<_> = [root.share_id, left.share_id, right.share_id, hash(99)]
        .into_iter()
        .collect();
    assert_eq!(dag.missing_from(&remote), vec![hash(99)]);

    let mut receipts = ReceiptBuilder::new(2, 2, hash(1), 0, [0; 32], 0, U512::ZERO);
    receipts.accept(right).unwrap();
    receipts.accept(root).unwrap();
    receipts.accept(left).unwrap();
    let batch = receipts.finalize(SignatureSet::empty_ed25519()).unwrap();
    assert_eq!(batch.accepted_share_ids.len(), 3);
    assert_eq!(
        batch.share_merkle_root,
        merkle_root(&batch.accepted_share_ids)
    );
}

#[test]
fn accepted_share_work_key_and_receipt_survive_process_restart() {
    let directory = secure_tempdir().unwrap();
    let path = directory.path().join("receipts.redb");
    let share = fake_validated(70, vec![]);
    let share_id = share.share_id;
    let work_key = share.work_key;
    let batch_id;
    {
        let store = RedbStore::create(&path).unwrap();
        let journal = ProtocolJournal::new(&store);
        let mut builder = ReceiptBuilder::new(2, 2, hash(1), 1, [0; 32], 0, U512::ZERO);
        builder.accept_durable(share, &journal).unwrap();
        let batch = builder
            .finalize_durable(SignatureSet::empty_ed25519(), &journal)
            .unwrap();
        batch_id = batch.object_id();
    }
    let store = RedbStore::create(&path).unwrap();
    let journal = ProtocolJournal::new(&store);
    assert!(
        journal
            .load(ProtocolRecordKind::AcceptedShare, &share_id)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        journal
            .load(ProtocolRecordKind::AcceptedWorkKey, &work_key)
            .unwrap(),
        Some(share_id.to_vec())
    );
    assert!(
        journal
            .load(ProtocolRecordKind::ReceiptBatch, &batch_id)
            .unwrap()
            .is_some()
    );
}

#[test]
fn durable_alternate_wrapper_conflict_leaves_no_partial_share_record() {
    let store = MemoryStore::default();
    let journal = ProtocolJournal::new(&store);
    let original = fake_validated(71, vec![]);
    let mut alternate_share = original.share.clone();
    alternate_share.gossip_parent_hashes = vec![hash(72)];
    let alternate = ValidatedShare {
        share_id: alternate_share.object_id(),
        work_key: alternate_share.work_key(),
        credited_work: original.credited_work,
        share: alternate_share,
    };
    assert_ne!(original.share_id, alternate.share_id);
    assert_eq!(original.work_key, alternate.work_key);

    let mut first = ReceiptBuilder::new(2, 2, hash(1), 0, [0; 32], 0, U512::ZERO);
    first.accept_durable(original.clone(), &journal).unwrap();
    let mut second = ReceiptBuilder::new(2, 2, hash(1), 0, [0; 32], 0, U512::ZERO);
    assert!(matches!(
        second.accept_durable(alternate.clone(), &journal),
        Err(ShareError::DuplicateWork)
    ));
    assert_eq!(
        journal
            .load(ProtocolRecordKind::AcceptedWorkKey, &original.work_key)
            .unwrap(),
        Some(original.share_id.to_vec())
    );
    assert!(
        journal
            .load(ProtocolRecordKind::AcceptedShare, &alternate.share_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn rewrapped_proof_gets_one_credit_and_receipt_roots_are_deterministic() {
    let original = fake_validated(4, vec![]);
    let mut rewrapped_share = original.share.clone();
    rewrapped_share.gossip_parent_hashes = vec![hash(77)];
    let rewrapped = ValidatedShare {
        share_id: rewrapped_share.object_id(),
        work_key: rewrapped_share.work_key(),
        credited_work: original.credited_work,
        share: rewrapped_share,
    };
    assert_ne!(original.share_id, rewrapped.share_id);
    assert_eq!(original.work_key, rewrapped.work_key);

    let mut builder = ReceiptBuilder::new(2, 2, hash(1), 0, [0; 32], 0, U512::ZERO);
    builder.accept(original).unwrap();
    assert!(matches!(
        builder.accept(rewrapped),
        Err(ShareError::DuplicateWork)
    ));

    let shares = [
        fake_validated(10, vec![]),
        fake_validated(11, vec![]),
        fake_validated(12, vec![]),
    ];
    let mut first = ReceiptBuilder::new(2, 2, hash(1), 1, hash(2), 0, U512::ZERO);
    let mut second = ReceiptBuilder::new(2, 2, hash(1), 1, hash(2), 0, U512::ZERO);
    for share in &shares {
        first.accept(share.clone()).unwrap();
    }
    for share in shares.iter().rev() {
        second.accept(share.clone()).unwrap();
    }
    assert_eq!(
        first.finalize(SignatureSet::empty_ed25519()).unwrap(),
        second.finalize(SignatureSet::empty_ed25519()).unwrap()
    );
}

#[test]
fn receipt_chain_is_append_only_and_close_root_covers_every_batch() {
    let receipt_keys = [key(40), key(41), key(42)];
    let receipt_roster = roster(CommitteeRole::Receipt, &receipt_keys);
    let first_share = fake_validated(20, vec![]);
    let second_share = fake_validated(21, vec![]);
    let mut first_builder = ReceiptBuilder::new(2, 2, hash(1), 0, [0; 32], 0, U512::ZERO);
    first_builder.accept(first_share.clone()).unwrap();
    let mut first = first_builder
        .finalize(SignatureSet::empty_ed25519())
        .unwrap();
    first.signer_set = certify(&first, &receipt_keys);

    let mut second_builder = ReceiptBuilder::new(
        2,
        2,
        hash(1),
        1,
        first.object_id(),
        first.cumulative_share_count,
        first.cumulative_credited_work,
    );
    second_builder.accept(second_share.clone()).unwrap();
    let mut second = second_builder
        .finalize(SignatureSet::empty_ed25519())
        .unwrap();
    second.signer_set = certify(&second, &receipt_keys);
    let summary = verify_receipt_chain(&[first.clone(), second.clone()], &receipt_roster).unwrap();
    assert_eq!(
        summary.accepted_share_ids,
        vec![first_share.share_id, second_share.share_id]
    );
    assert_eq!(
        summary.accepted_work_keys,
        vec![first_share.work_key, second_share.work_key]
    );

    let settlement_keys = [key(43), key(44), key(45)];
    let settlement_roster = roster(CommitteeRole::Settlement, &settlement_keys);
    let mut close = build_session_close(
        hash(1),
        &[first.clone(), second.clone()],
        &receipt_roster,
        1,
        hash(9),
        vec![],
        SignatureSet::empty_ed25519(),
    )
    .unwrap();
    close.signer_set = certify(&close, &settlement_keys);
    verify_session_close(
        &close,
        &[first.clone(), second.clone()],
        &receipt_roster,
        &settlement_roster,
    )
    .unwrap();
    assert_eq!(
        close.accepted_share_merkle_root,
        merkle_root(&[first_share.share_id, second_share.share_id])
    );

    let mut replay_builder = ReceiptBuilder::new(
        2,
        2,
        hash(1),
        1,
        first.object_id(),
        first.cumulative_share_count,
        first.cumulative_credited_work,
    );
    replay_builder.accept(first_share).unwrap();
    let mut replay = replay_builder
        .finalize(SignatureSet::empty_ed25519())
        .unwrap();
    replay.signer_set = certify(&replay, &receipt_keys);
    assert!(matches!(
        verify_receipt_chain(&[first, replay], &receipt_roster),
        Err(ShareError::InvalidReceiptChain)
    ));
}

#[test]
fn conflicting_receipts_produce_fault_proof_and_close_is_deterministic() {
    let signer = SignerSignature {
        signer_pubkey: hash(1),
        signature: SignatureBytes(vec![2; 64]),
    };
    let mut first_builder = ReceiptBuilder::new(2, 2, hash(1), 1, [0; 32], 0, U512::ZERO);
    first_builder.accept(fake_validated(1, vec![])).unwrap();
    let first = first_builder
        .finalize(SignatureSet {
            signature_suite: ED25519_SUITE,
            signatures: vec![signer.clone()],
        })
        .unwrap();
    let mut second_builder = ReceiptBuilder::new(2, 2, hash(1), 1, [0; 32], 0, U512::ZERO);
    second_builder.accept(fake_validated(2, vec![])).unwrap();
    let second = second_builder
        .finalize(SignatureSet {
            signature_suite: ED25519_SUITE,
            signatures: vec![signer],
        })
        .unwrap();
    let proof = detect_receipt_equivocation(&first, &second).unwrap();
    assert_eq!(proof.equivocating_signers, vec![hash(1)]);

    let receipt_keys = [key(30), key(31), key(32)];
    let receipt_roster = roster(CommitteeRole::Receipt, &receipt_keys);
    let mut close_builder = ReceiptBuilder::new(2, 2, hash(1), 0, [0; 32], 0, U512::ZERO);
    close_builder.accept(fake_validated(3, vec![])).unwrap();
    let mut close_batch = close_builder
        .finalize(SignatureSet::empty_ed25519())
        .unwrap();
    close_batch.signer_set = certify(&close_batch, &receipt_keys);
    let settlement_keys = [key(33), key(34), key(35)];
    let settlement_roster = roster(CommitteeRole::Settlement, &settlement_keys);
    let mut close = build_session_close(
        hash(1),
        std::slice::from_ref(&close_batch),
        &receipt_roster,
        1,
        hash(3),
        vec![hash(5), hash(4), hash(5)],
        SignatureSet::empty_ed25519(),
    )
    .unwrap();
    close.signer_set = certify(&close, &settlement_keys);
    verify_session_close(
        &close,
        std::slice::from_ref(&close_batch),
        &receipt_roster,
        &settlement_roster,
    )
    .unwrap();
    assert_eq!(close.discovered_hns_block_ids, vec![hash(4), hash(5)]);
    assert_eq!(close.final_receipt_batch_id, close_batch.object_id());
}

#[test]
fn work_uses_exact_integer_arithmetic() {
    assert_eq!(
        work_for_target(&U256([0xff; 32])),
        U512({
            let mut value = [0; 64];
            value[63] = 1;
            value
        })
    );
    let zero_work = work_for_target(&U256::ZERO);
    let expected = BigUint::one() << 256usize;
    assert_eq!(BigUint::from_bytes_be(&zero_work.0), expected);

    // Keep the work-bucket type in the compile-time integration surface.
    let leaf = WorkBucketLeaf {
        bucket_id: hash(1),
        operator_pubkey: hash(2),
        hns_address_version: 0,
        hns_address_hash: vec![3; 20],
        credited_work: zero_work,
    };
    assert_eq!(leaf.credited_work, zero_work);
}
