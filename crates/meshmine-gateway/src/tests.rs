use std::io::{BufRead, BufReader, Cursor, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use meshmine_crypto::sign_object;
use meshmine_storage::{MemoryStore, RedbStore};
use meshmine_types::{
    CORE_V2, GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16, GATEWAY_HANDOFF_V1,
    GATEWAY_OBSERVATION_CORE_RECEIPT_TIME, SignatureBytes, SignatureSet, U256,
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

fn hash(byte: u8) -> Hash256 {
    [byte; 32]
}

fn job() -> GatewayJob {
    GatewayJob {
        id: "job-000000000001".to_owned(),
        assignment_sequence: 0,
        previous_block: hash(1),
        merkle_root: hash(2),
        witness_root: hash(3),
        tree_root: hash(4),
        reserved_root: hash(5),
        version: 0,
        bits: 0x203f_ffff,
        ntime: 0x6500_0000,
        mask_hash: hash(6),
        leading_zero_prefix_q: 1,
        blind_band_bits_d: 1,
        capture_target: meshmine_hns::derive_capture_parameters(0x203f_ffff, 1)
            .unwrap()
            .capture_target,
        advertised_device_target: [0xff; 32],
        advertised_difficulty: 1,
        issued_ms: 100,
        assignment_end_ms: 200,
        submission_end_ms: 250,
        transaction_hashes: vec![hash(7), hash(8)],
    }
}

fn handy_job() -> GatewayJob {
    let mut value = job();
    value.bits = 0x1925_ae67;
    value.blind_band_bits_d = 12;
    let capture = derive_capture_parameters(value.bits, value.blind_band_bits_d).unwrap();
    value.leading_zero_prefix_q = capture.leading_zero_prefix_q;
    value.capture_target = capture.capture_target;
    value.advertised_difficulty = 1;
    value.advertised_device_target = handy_target_from_difficulty(1).unwrap();
    value
}

struct AuthorizedFixture {
    manifest: GatewayContextManifestV1,
    assignment: GatewayAssignmentV1,
    session: MaskSessionV2,
    body: BlockBodyPackageV2,
    descriptor: BodyErasureDescriptorV2,
    body_certificate: BodyAvailabilityCertificateV2,
    job: GatewayJob,
}

fn authorized_fixture(assignment_sequence: u64) -> AuthorizedFixture {
    let operator = SigningKey::from_bytes(&[41; 32]);
    let operator_pubkey = operator.verifying_key().to_bytes();
    let gateway_pubkey = SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes();
    let core_handoff_pubkey = SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes();
    let worker_id_hash = hash(20);
    let mut manifest = GatewayContextManifestV1 {
        core_protocol_version: CORE_V2,
        handoff_version: GATEWAY_HANDOFF_V1,
        network_id: 2,
        context_sequence: 1,
        previous_manifest_id: [0; 32],
        operator_pubkey,
        gateway_pubkey,
        core_handoff_pubkey,
        valid_from_ms: 1,
        valid_until_ms: 1_000,
        maximum_frame_bytes: 64 * 1024,
        maximum_in_flight: 32,
        operator_signature: SignatureBytes::empty(),
    };
    manifest.operator_signature = sign_object(&operator, manifest.network_id, &manifest);

    let base_job = job();
    let session = MaskSessionV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        lane_id: 1,
        session_sequence: 1,
        parent_certificate_id: hash(31),
        parent_hash: base_job.previous_block,
        hns_network_target: U256(hash(32)),
        capture_target: U256(base_job.capture_target),
        accounting_target: U256(base_job.capture_target),
        leading_zero_prefix_q: base_job.leading_zero_prefix_q,
        blind_band_bits_d: base_job.blind_band_bits_d,
        mask_hash: base_job.mask_hash,
        mask_commitment_root: hash(33),
        mask_committee_id: hash(34),
        fast_eval_policy: 1,
        assignment_start_ms: base_job.issued_ms,
        assignment_end_ms: base_job.assignment_end_ms,
        submission_end_ms: base_job.submission_end_ms,
        timed_open_after_ms: 300,
        previous_session_id: [0; 32],
        signer_set: SignatureSet::empty_ed25519(),
    };
    let template_core = meshmine_types::TemplateCoreV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        hns_parent_hash: base_job.previous_block,
        hns_parent_height: 99,
        operator_pubkey,
        operator_fee_bucket_id: hash(35),
        payout_snapshot_id: hash(36),
        payout_plan_id: hash(37),
        plan_sequence: 1,
        ordered_non_coinbase_txids: base_job.transaction_hashes.clone(),
        ordered_claim_ids: Vec::new(),
        ordered_airdrop_ids: Vec::new(),
        block_version: base_job.version,
        bits: base_job.bits,
        minimum_ntime: u64::from(base_job.ntime),
        policy_commitment: hash(38),
    };
    let template_core_id = template_core.object_id();
    let body = BlockBodyPackageV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        template_core,
        template_core_id,
        coinbase_raw: vec![1, 2],
        transactions_raw: vec![vec![3], vec![4]],
        merkle_root: base_job.merkle_root,
        witness_root: base_job.witness_root,
        tree_root: base_job.tree_root,
        reserved_root: base_job.reserved_root,
        block_weight: 1_000,
        block_sigops: 1,
        miner_subsidy: 2_000,
        ordinary_transaction_fees: 100,
        claim_airdrop_principal: 0,
        claim_airdrop_fees: 0,
        operator_fee_value: 20,
        work_service_subsidy_value: 2_080,
        hsd_validation_result_hash: hash(39),
        operator_signature: SignatureBytes::empty(),
    };
    let body_package_id = body.object_id();
    let descriptor = BodyErasureDescriptorV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        body_package_id,
        original_size: 100,
        data_shards: 2,
        parity_shards: 1,
        shard_size: 50,
        shard_merkle_root: hash(40),
        expiry_height: 200,
        compression: 0,
    };
    let body_certificate = BodyAvailabilityCertificateV2 {
        protocol_version: CORE_V2,
        network_id: 2,
        descriptor_id: descriptor.object_id(),
        parent_hash: base_job.previous_block,
        parent_height: 99,
        hsd_validation_result_hash: body.hsd_validation_result_hash,
        challenge_round: 1,
        challenge_transcript_root: hash(44),
        signer_set: SignatureSet::empty_ed25519(),
    };
    let mut assignment = GatewayAssignmentV1 {
        core_protocol_version: CORE_V2,
        handoff_version: GATEWAY_HANDOFF_V1,
        network_id: 2,
        session_id: session.object_id(),
        body_package_id,
        body_certificate_id: body_certificate.object_id(),
        operator_pubkey,
        gateway_pubkey,
        core_handoff_pubkey,
        worker_id_hash,
        payout_bucket_id: hash(45),
        assignment_sequence,
        ntime: u64::from(base_job.ntime),
        extra_nonce_profile: GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16,
        observation_policy: GATEWAY_OBSERVATION_CORE_RECEIPT_TIME,
        maximum_clock_skew_ms: 0,
        extra_nonce_prefix: [0, 0, 0, 42],
        extra_nonce2_start_be: 1u32.to_be_bytes(),
        extra_nonce2_end_be: 2u32.to_be_bytes(),
        nonce_start: 0,
        nonce_end: u32::MAX,
        nonce_stride: 1,
        edge_target: U256(base_job.advertised_device_target),
        capture_target: U256(base_job.capture_target),
        telemetry_level: TelemetryLevel::StockAsic as u8,
        operator_signature: SignatureBytes::empty(),
    };
    assignment.operator_signature = sign_object(&operator, assignment.network_id, &assignment);
    let mut authorized_job = base_job;
    authorized_job.id = gateway_assignment_job_id(&assignment);
    AuthorizedFixture {
        manifest,
        assignment,
        session,
        body,
        descriptor,
        body_certificate,
        job: authorized_job,
    }
}

fn setup() -> (tempfile::TempDir, Gateway, [u8; 4]) {
    let directory = secure_tempdir().unwrap();
    let store = Arc::new(RedbStore::create(directory.path().join("gateway.redb")).unwrap());
    let mut gateway = Gateway::open_research_simulator(store).unwrap();
    assert_eq!(gateway.issue_job(job()).unwrap(), 1);
    let prefix = gateway.assignment_nonce_prefix(&hash(20), 1).unwrap();
    (directory, gateway, prefix)
}

fn submission(extra_nonce2: u32, nonce: u32) -> HandySubmission {
    HandySubmission {
        username: "operator.worker".to_owned(),
        job_id: "job-000000000001".to_owned(),
        extra_nonce2: extra_nonce2.to_be_bytes(),
        ntime: 0x6500_0000,
        nonce,
    }
}

fn qualifying_nonces(prefix: [u8; 4], count: usize) -> Vec<u32> {
    let job = job();
    let mut extra_nonce = [0; 24];
    extra_nonce[..4].copy_from_slice(&prefix);
    extra_nonce[4..8].copy_from_slice(&1u32.to_be_bytes());
    let mut nonces = Vec::with_capacity(count);
    for nonce in 0..u32::MAX {
        let header = MinerHeader {
            nonce,
            time: u64::from(job.ntime),
            prev_block: job.previous_block,
            tree_root: job.tree_root,
            mask_hash: job.mask_hash,
            extra_nonce,
            reserved_root: job.reserved_root,
            witness_root: job.witness_root,
            merkle_root: job.merkle_root,
            version: job.version,
            bits: job.bits,
        };
        if header.share_hash() <= job.capture_target {
            nonces.push(nonce);
            if nonces.len() == count {
                return nonces;
            }
        }
    }
    panic!("maximum nonce range did not contain enough capture shares");
}

#[test]
fn handy_notify_is_exact_ten_field_hns_shape_and_contains_no_mask() {
    let (_directory, gateway, _) = setup();
    let notify = gateway.current_job().unwrap().handy_notify();
    let params = notify["params"].as_array().unwrap();
    assert_eq!(params.len(), 10);
    assert_eq!(params[9], hex::encode(hash(6)));
    let raw = serde_json::to_string(&notify).unwrap();
    assert!(!raw.contains(&hex::encode([0x42; 32])));
    assert_eq!(notify["method"], "mining.notify");
}

#[test]
fn all_capture_qualifying_submissions_are_forwarded_and_duplicates_are_rejected() {
    let (_directory, mut gateway, prefix) = setup();
    let nonces = qualifying_nonces(prefix, 1_000);
    for nonce in &nonces {
        let capture = gateway
            .submit(
                prefix,
                TelemetryLevel::StockAsic,
                submission(1, *nonce),
                150,
            )
            .unwrap();
        assert!(capture.raw_share_hash <= [0xff; 32]);
        assert!(capture.credit_eligible);
        assert_eq!(capture.miner_header.extra_nonce[..4], prefix);
        assert_eq!(capture.miner_header.extra_nonce[4..8], 1u32.to_be_bytes());
        assert_eq!(capture.miner_header.extra_nonce[8..], [0; 16]);
    }
    assert_eq!(gateway.forwarded().len(), 1_000);
    assert!(matches!(
        gateway.submit(
            prefix,
            TelemetryLevel::StockAsic,
            submission(1, nonces[0]),
            150
        ),
        Err(GatewayError::Duplicate)
    ));
}

#[test]
fn target_and_stale_windows_are_enforced_while_grace_captures_still_forward() {
    let (_directory, mut gateway, prefix) = setup();
    let nonces = qualifying_nonces(prefix, 4);
    assert!(matches!(
        gateway.submit(
            prefix,
            TelemetryLevel::StockAsic,
            submission(1, nonces[0]),
            99,
        ),
        Err(GatewayError::StaleJob)
    ));
    assert!(gateway.forwarded().is_empty());
    let already_issued = gateway
        .submit(
            prefix,
            TelemetryLevel::StockAsic,
            submission(1, nonces[0]),
            210,
        )
        .unwrap();
    assert!(already_issued.credit_eligible);
    gateway.cancel_job("job-000000000001", 160, 220).unwrap();
    let normal = gateway
        .submit(
            prefix,
            TelemetryLevel::StockAsic,
            submission(1, nonces[1]),
            155,
        )
        .unwrap();
    assert!(normal.credit_eligible);
    let grace = gateway
        .submit(
            prefix,
            TelemetryLevel::StockAsic,
            submission(1, nonces[2]),
            200,
        )
        .unwrap();
    assert!(!grace.credit_eligible);
    assert!(matches!(
        gateway.submit(
            prefix,
            TelemetryLevel::StockAsic,
            submission(1, nonces[3]),
            221
        ),
        Err(GatewayError::StaleJob)
    ));

    let directory = secure_tempdir().unwrap();
    let store = Arc::new(RedbStore::create(directory.path().join("hard.redb")).unwrap());
    let mut invalid = Gateway::open_research_simulator(store).unwrap();
    let mut hard_job = job();
    hard_job.advertised_device_target = [0x7e; 32];
    assert!(matches!(
        invalid.issue_job(hard_job),
        Err(GatewayError::DeviceTargetTooHard)
    ));
}

#[test]
fn prefix_and_assignment_sequences_advance_durably_before_exposure() {
    let directory = secure_tempdir().unwrap();
    let path = directory.path().join("durable.redb");
    let first_prefix;
    {
        let store = Arc::new(RedbStore::create(&path).unwrap());
        let mut gateway = Gateway::open_research_simulator(store).unwrap();
        assert_eq!(gateway.issue_job(job()).unwrap(), 1);
        first_prefix = gateway.assignment_nonce_prefix(&hash(1), 1).unwrap();
    }
    {
        let store = Arc::new(RedbStore::create(&path).unwrap());
        let mut gateway = Gateway::open_research_simulator(store).unwrap();
        assert_eq!(
            gateway.assignment_nonce_prefix(&hash(1), 1).unwrap(),
            first_prefix
        );
        let mut next = job();
        next.id = "job-000000000002".to_owned();
        next.issued_ms = 160;
        assert_eq!(
            gateway
                .issue_job_with_transition(
                    next,
                    Some(PreviousJobTransition {
                        job_id: "job-000000000001".to_owned(),
                        credit_cutoff_ms: 160,
                        submission_end_ms: 220,
                    }),
                )
                .unwrap(),
            2
        );
        let next_prefix = gateway.assignment_nonce_prefix(&hash(1), 2).unwrap();
        assert_ne!(next_prefix, first_prefix);
        assert_ne!(
            gateway.assignment_nonce_prefix(&hash(2), 2).unwrap(),
            next_prefix
        );
    }
}

#[test]
fn signed_gateway_assignment_fixes_job_id_prefix_and_miner_selected_ranges() {
    let directory = secure_tempdir().unwrap();
    let store = Arc::new(RedbStore::create(directory.path().join("authorized.redb")).unwrap());
    let mut gateway = Gateway::open_research_simulator(store).unwrap();
    let fixture = authorized_fixture(1);
    assert_eq!(
        gateway
            .issue_authorized_job(AuthorizedGatewayJobRequest {
                manifest: &fixture.manifest,
                assignment: &fixture.assignment,
                session: &fixture.session,
                body: &fixture.body,
                descriptor: &fixture.descriptor,
                body_certificate: &fixture.body_certificate,
                job: fixture.job.clone(),
                transition: None,
            })
            .unwrap(),
        1
    );
    assert_eq!(
        gateway.current_job().unwrap().id,
        hex::encode(fixture.assignment.object_id())
    );
    let prefix = gateway
        .authorized_assignment_nonce_prefix(&fixture.assignment.worker_id_hash, &fixture.assignment)
        .unwrap();
    assert_eq!(prefix, fixture.assignment.extra_nonce_prefix);

    let nonce = qualifying_nonces(prefix, 1)[0];
    let mut outside_range = submission(3, nonce);
    outside_range.job_id = gateway_assignment_job_id(&fixture.assignment);
    assert!(matches!(
        gateway.submit_authorized(
            &fixture.assignment.worker_id_hash,
            &fixture.assignment,
            prefix,
            TelemetryLevel::StockAsic,
            outside_range,
            150,
        ),
        Err(GatewayError::AssignmentAuthorizationMismatch)
    ));
    assert!(gateway.forwarded().is_empty());

    let mut valid = submission(1, nonce);
    valid.job_id = gateway_assignment_job_id(&fixture.assignment);
    let capture = gateway
        .submit_authorized(
            &fixture.assignment.worker_id_hash,
            &fixture.assignment,
            prefix,
            TelemetryLevel::StockAsic,
            valid,
            150,
        )
        .unwrap();
    assert_eq!(capture.miner_header.extra_nonce[..4], prefix);
    assert_eq!(capture.miner_header.extra_nonce[4..8], 1u32.to_be_bytes());
}

#[test]
fn signed_mismatch_cannot_burn_the_local_assignment_sequence() {
    let directory = secure_tempdir().unwrap();
    let store = Arc::new(RedbStore::create(directory.path().join("sequence.redb")).unwrap());
    let mut gateway = Gateway::open_research_simulator(store).unwrap();
    let wrong_sequence = authorized_fixture(2);
    assert!(matches!(
        gateway.issue_authorized_job(AuthorizedGatewayJobRequest {
            manifest: &wrong_sequence.manifest,
            assignment: &wrong_sequence.assignment,
            session: &wrong_sequence.session,
            body: &wrong_sequence.body,
            descriptor: &wrong_sequence.descriptor,
            body_certificate: &wrong_sequence.body_certificate,
            job: wrong_sequence.job,
            transition: None,
        }),
        Err(GatewayError::AssignmentAuthorizationMismatch)
    ));

    let mut bad_context = authorized_fixture(1);
    bad_context.job.tree_root[0] ^= 1;
    assert!(matches!(
        gateway.issue_authorized_job(AuthorizedGatewayJobRequest {
            manifest: &bad_context.manifest,
            assignment: &bad_context.assignment,
            session: &bad_context.session,
            body: &bad_context.body,
            descriptor: &bad_context.descriptor,
            body_certificate: &bad_context.body_certificate,
            job: bad_context.job,
            transition: None,
        }),
        Err(GatewayError::AssignmentAuthorizationMismatch)
    ));

    let exact = authorized_fixture(1);
    assert_eq!(
        gateway
            .issue_authorized_job(AuthorizedGatewayJobRequest {
                manifest: &exact.manifest,
                assignment: &exact.assignment,
                session: &exact.session,
                body: &exact.body,
                descriptor: &exact.descriptor,
                body_certificate: &exact.body_certificate,
                job: exact.job,
                transition: None,
            })
            .unwrap(),
        1
    );
}

#[test]
fn issued_jobs_captures_and_duplicate_rejection_survive_restart() {
    let directory = secure_tempdir().unwrap();
    let path = directory.path().join("capture-recovery.redb");
    let worker = hash(31);
    let prefix;
    let accepted;
    {
        let store = Arc::new(RedbStore::create(&path).unwrap());
        let mut gateway = Gateway::open_research_simulator(store).unwrap();
        assert_eq!(gateway.issue_job(job()).unwrap(), 1);
        prefix = gateway.assignment_nonce_prefix(&worker, 1).unwrap();
        let nonce = qualifying_nonces(prefix, 1)[0];
        accepted = gateway
            .submit(prefix, TelemetryLevel::StockAsic, submission(1, nonce), 150)
            .unwrap();
    }
    {
        let store = Arc::new(RedbStore::create(&path).unwrap());
        let mut gateway = Gateway::open_research_simulator(store).unwrap();
        assert_eq!(gateway.current_job().unwrap().assignment_sequence, 1);
        assert_eq!(gateway.assignment_nonce_prefix(&worker, 1).unwrap(), prefix);
        assert_eq!(gateway.forwarded(), std::slice::from_ref(&accepted));
        assert!(matches!(
            gateway.submit(
                prefix,
                TelemetryLevel::StockAsic,
                submission(1, accepted.miner_header.nonce),
                150,
            ),
            Err(GatewayError::Duplicate)
        ));
        let mut next = job();
        next.id = "job-000000000002".to_owned();
        next.issued_ms = 160;
        assert_eq!(
            gateway
                .issue_job_with_transition(
                    next,
                    Some(PreviousJobTransition {
                        job_id: "job-000000000001".to_owned(),
                        credit_cutoff_ms: 160,
                        submission_end_ms: 220,
                    }),
                )
                .unwrap(),
            2
        );
    }
}

#[test]
fn acknowledged_capture_payload_is_compacted_but_dedup_survives_restart() {
    let directory = secure_tempdir().unwrap();
    let path = directory.path().join("capture-ack.redb");
    let prefix;
    let nonce;
    let work_key;
    {
        let store = Arc::new(RedbStore::create(&path).unwrap());
        let mut gateway = Gateway::open_research_simulator(store).unwrap();
        gateway.issue_job(job()).unwrap();
        prefix = gateway.assignment_nonce_prefix(&hash(32), 1).unwrap();
        nonce = qualifying_nonces(prefix, 1)[0];
        let capture = gateway
            .submit(prefix, TelemetryLevel::StockAsic, submission(1, nonce), 150)
            .unwrap();
        work_key = capture.work_key();
        assert!(gateway.acknowledge_capture(&work_key).unwrap());
        assert!(gateway.forwarded().is_empty());
        assert!(!gateway.acknowledge_capture(&work_key).unwrap());
    }
    {
        let store = Arc::new(RedbStore::create(&path).unwrap());
        let mut gateway = Gateway::open_research_simulator(store).unwrap();
        assert!(gateway.forwarded().is_empty());
        assert!(!gateway.acknowledge_capture(&work_key).unwrap());
        assert!(matches!(
            gateway.submit(prefix, TelemetryLevel::StockAsic, submission(1, nonce), 150,),
            Err(GatewayError::Duplicate)
        ));
    }
}

#[test]
fn malformed_durable_gateway_state_fails_closed() {
    let directory = secure_tempdir().unwrap();
    let store = Arc::new(RedbStore::create(directory.path().join("malformed.redb")).unwrap());
    store
        .put(ASSIGNMENT_NAMESPACE, "1", b"truncated-assignment")
        .unwrap();
    assert!(matches!(
        Gateway::open(store),
        Err(GatewayError::InvalidDurableState)
    ));

    let store = Arc::new(MemoryStore::default());
    let mut gateway = Gateway::open_research_simulator(store.clone()).unwrap();
    gateway.issue_job(job()).unwrap();
    let prefix = gateway.assignment_nonce_prefix(&hash(33), 1).unwrap();
    let nonce = qualifying_nonces(prefix, 1)[0];
    let mut capture = gateway
        .submit(prefix, TelemetryLevel::StockAsic, submission(1, nonce), 150)
        .unwrap();
    let work_key = capture.work_key();
    capture.received_ms = 99;
    store
        .put(
            CAPTURE_NAMESPACE,
            &hex::encode(work_key),
            &encode_durable_capture(&capture),
        )
        .unwrap();
    drop(gateway);
    assert!(matches!(
        Gateway::open_research_simulator(store),
        Err(GatewayError::InvalidDurableState)
    ));
}

#[test]
fn grace_cutoff_and_closed_state_survive_restart() {
    let directory = secure_tempdir().unwrap();
    let path = directory.path().join("job-state-recovery.redb");
    let prefix;
    let nonces;
    {
        let store = Arc::new(RedbStore::create(&path).unwrap());
        let mut gateway = Gateway::open_research_simulator(store).unwrap();
        gateway.issue_job(job()).unwrap();
        prefix = gateway.assignment_nonce_prefix(&hash(41), 1).unwrap();
        nonces = qualifying_nonces(prefix, 2);
        gateway.cancel_job("job-000000000001", 160, 220).unwrap();
    }
    {
        let store = Arc::new(RedbStore::create(&path).unwrap());
        let mut gateway = Gateway::open_research_simulator(store).unwrap();
        assert!(gateway.current_job().is_none());
        let grace = gateway
            .submit(
                prefix,
                TelemetryLevel::StockAsic,
                submission(1, nonces[0]),
                200,
            )
            .unwrap();
        assert!(!grace.credit_eligible);
        gateway.close_expired(221).unwrap();
    }
    {
        let store = Arc::new(RedbStore::create(&path).unwrap());
        let mut gateway = Gateway::open_research_simulator(store).unwrap();
        assert!(gateway.current_job().is_none());
        assert!(matches!(
            gateway.submit(
                prefix,
                TelemetryLevel::StockAsic,
                submission(1, nonces[1]),
                210,
            ),
            Err(GatewayError::StaleJob)
        ));
    }
}

#[test]
fn handy_difficulty_mapping_is_exact_and_real_device_jobs_fail_closed() {
    let cases = [
        (1, 0x1e00_ffff),
        (2, 0x1d7f_ffff),
        (3, 0x1d55_5555),
        (256, 0x1d00_ffff),
        (65_535, 0x1c01_0001),
        (65_536, 0x1c00_ffff),
        (1_000_000, 0x1b10_c6f7),
        (MAX_HANDY_DIFFICULTY, 0x1a40_0000),
    ];
    for (difficulty, compact) in cases {
        let target = handy_target_from_difficulty(difficulty).unwrap();
        let expected = compact_to_target(compact).to_biguint().unwrap();
        assert_eq!(BigUint::from_bytes_be(&target), expected);
    }
    assert_eq!(
        hex::encode(handy_target_from_difficulty(1).unwrap()),
        "000000ffff000000000000000000000000000000000000000000000000000000"
    );
    assert!(matches!(
        handy_target_from_difficulty(0),
        Err(GatewayError::InvalidDifficulty)
    ));
    assert!(matches!(
        handy_target_from_difficulty(MAX_HANDY_DIFFICULTY + 1),
        Err(GatewayError::InvalidDifficulty)
    ));

    let store = Arc::new(MemoryStore::default());
    let mut gateway = Gateway::open(store).unwrap();
    assert_eq!(gateway.issue_job(handy_job()).unwrap(), 1);

    let mut mismatch = handy_job();
    mismatch.id = "job-000000000002".to_owned();
    mismatch.advertised_device_target[31] ^= 1;
    let store = Arc::new(MemoryStore::default());
    let mut gateway = Gateway::open(store).unwrap();
    assert!(matches!(
        gateway.issue_job(mismatch),
        Err(GatewayError::AdvertisedTargetMismatch)
    ));

    let store = Arc::new(MemoryStore::default());
    let mut gateway = Gateway::open(store).unwrap();
    assert!(matches!(
        gateway.issue_job(job()),
        Err(GatewayError::AdvertisedTargetMismatch)
    ));

    let mut too_hard = handy_job();
    too_hard.advertised_difficulty = MAX_HANDY_DIFFICULTY;
    too_hard.advertised_device_target = handy_target_from_difficulty(MAX_HANDY_DIFFICULTY).unwrap();
    let store = Arc::new(MemoryStore::default());
    let mut gateway = Gateway::open(store).unwrap();
    assert!(matches!(
        gateway.issue_job(too_hard),
        Err(GatewayError::DeviceTargetTooHard)
    ));
}

#[test]
fn exact_issue_retry_and_single_active_transition_survive_restart() {
    let store = Arc::new(MemoryStore::default());
    {
        let mut gateway = Gateway::open_research_simulator(store.clone()).unwrap();
        assert_eq!(gateway.issue_job(job()).unwrap(), 1);
        assert_eq!(gateway.issue_job(job()).unwrap(), 1);
        assert_eq!(gateway.events().len(), 1);

        let mut conflicting = job();
        conflicting.mask_hash = hash(99);
        assert!(matches!(
            gateway.issue_job(conflicting),
            Err(GatewayError::AssignmentConflict)
        ));

        let mut next = job();
        next.id = "job-000000000002".to_owned();
        next.issued_ms = 160;
        assert!(matches!(
            gateway.issue_job(next.clone()),
            Err(GatewayError::ActiveJobExists)
        ));
        assert_eq!(
            gateway
                .issue_job_with_transition(
                    next,
                    Some(PreviousJobTransition {
                        job_id: job().id,
                        credit_cutoff_ms: 160,
                        submission_end_ms: 220,
                    }),
                )
                .unwrap(),
            2
        );
        assert_eq!(gateway.current_job().unwrap().assignment_sequence, 2);
    }
    let mut gateway = Gateway::open_research_simulator(store).unwrap();
    assert_eq!(gateway.current_job().unwrap().assignment_sequence, 2);
    let mut retry = job();
    retry.id = "job-000000000002".to_owned();
    retry.issued_ms = 160;
    assert_eq!(gateway.issue_job(retry).unwrap(), 2);
}

#[test]
fn recovery_rejects_multiple_active_assignments_even_with_a_head() {
    let store = Arc::new(MemoryStore::default());
    Gateway::open_research_simulator(store.clone()).unwrap();
    let mut first = job();
    first.assignment_sequence = 1;
    let mut second = job();
    second.id = "job-000000000002".to_owned();
    second.assignment_sequence = 2;
    store
        .apply_batch(&[
            BatchOperation::put(ASSIGNMENT_NAMESPACE, "1", encode_durable_job(&first)),
            BatchOperation::put(ASSIGNMENT_NAMESPACE, "2", encode_durable_job(&second)),
            BatchOperation::put(
                ASSIGNMENT_STATE_NAMESPACE,
                "1",
                encode_durable_job_state(JobState::Active),
            ),
            BatchOperation::put(
                ASSIGNMENT_STATE_NAMESPACE,
                "2",
                encode_durable_job_state(JobState::Active),
            ),
            BatchOperation::put(
                CURRENT_ASSIGNMENT_NAMESPACE,
                CURRENT_ASSIGNMENT_KEY,
                1u64.to_le_bytes().to_vec(),
            ),
        ])
        .unwrap();
    assert!(matches!(
        Gateway::open_research_simulator(store),
        Err(GatewayError::InvalidDurableState)
    ));
}

#[test]
fn closed_job_retires_only_after_capture_ack_and_id_can_never_reappear() {
    let store = Arc::new(MemoryStore::default());
    let prefix;
    let capture;
    {
        let mut gateway = Gateway::open_research_simulator(store.clone()).unwrap();
        gateway.issue_job(job()).unwrap();
        prefix = gateway.assignment_nonce_prefix(&hash(51), 1).unwrap();
        let nonce = qualifying_nonces(prefix, 1)[0];
        capture = gateway
            .submit(prefix, TelemetryLevel::StockAsic, submission(1, nonce), 150)
            .unwrap();
        gateway.close_expired(251).unwrap();
        assert!(gateway.acknowledge_capture(&capture.work_key()).unwrap());
        gateway.close_expired(251).unwrap();
        gateway.close_expired(251).unwrap();
        assert!(matches!(
            gateway.issue_job(job()),
            Err(GatewayError::InvalidJobId)
        ));
        assert!(matches!(
            gateway.submit(
                prefix,
                TelemetryLevel::StockAsic,
                submission(1, capture.miner_header.nonce),
                150,
            ),
            Err(GatewayError::StaleJob)
        ));
    }
    let mut gateway = Gateway::open_research_simulator(store).unwrap();
    assert!(matches!(
        gateway.issue_job(job()),
        Err(GatewayError::InvalidJobId)
    ));
}

#[test]
fn legacy_six_byte_capture_tombstone_migrates_conservatively() {
    let store = Arc::new(MemoryStore::default());
    let legacy_key = hash(77);
    {
        let mut gateway = Gateway::open_research_simulator(store.clone()).unwrap();
        gateway.issue_job(job()).unwrap();
    }
    let mut legacy = CAPTURE_TOMBSTONE_MAGIC.to_vec();
    legacy.extend_from_slice(&2u16.to_le_bytes());
    store
        .put(
            CAPTURE_TOMBSTONE_NAMESPACE,
            &hex::encode(legacy_key),
            &legacy,
        )
        .unwrap();
    let mut gateway = Gateway::open_research_simulator(store.clone()).unwrap();
    assert!(!gateway.acknowledge_capture(&legacy_key).unwrap());
    gateway.close_expired(251).unwrap();
    assert!(matches!(
        gateway.acknowledge_capture(&legacy_key),
        Err(GatewayError::CaptureNotFound)
    ));
    Gateway::open_research_simulator(store.clone()).unwrap();
    store
        .put(
            CAPTURE_MIGRATION_NAMESPACE,
            LEGACY_TOMBSTONE_CUTOFF_KEY,
            &1u64.to_le_bytes(),
        )
        .unwrap();
    Gateway::open_research_simulator(store.clone()).unwrap();
    assert_eq!(
        store
            .get(CAPTURE_MIGRATION_NAMESPACE, LEGACY_TOMBSTONE_CUTOFF_KEY)
            .unwrap(),
        None
    );
}

#[test]
fn production_gate_rejects_unverified_hs3_and_logs_have_no_completion_claim() {
    let hs3 = DeviceProfile::goldshell_hs3_experimental();
    assert_eq!(hs3.telemetry_level(), TelemetryLevel::StockAsic);
    assert!(matches!(
        hs3.validate_production(),
        Err(GatewayError::HardwareUnverified)
    ));
    assert!(matches!(
        DeviceProfile::goldshell_generic_experimental().validate_production(),
        Err(GatewayError::HardwareUnverified)
    ));
    let (_directory, mut gateway, prefix) = setup();
    let nonce = qualifying_nonces(prefix, 1)[0];
    gateway
        .submit(prefix, TelemetryLevel::StockAsic, submission(1, nonce), 150)
        .unwrap();
    let events = format!("{:?}", gateway.events()).to_ascii_lowercase();
    assert!(!events.contains("range complete"));
    assert!(!events.contains("interval complete"));
    assert!(!events.contains("withholding"));
}

#[test]
fn simulator_mines_through_a_real_local_tcp_rpc_connection() {
    let (_directory, mut gateway, prefix) = setup();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let session = RpcSession::new(
            "operator.worker",
            "secret",
            prefix,
            DeviceProfile::simulator(),
        );
        serve_rpc_connection_with_clock(stream, session, &mut gateway, 3, || 150).unwrap();
        gateway
    });

    let mut client = TcpStream::connect(address).unwrap();
    let mut reader = BufReader::new(client.try_clone().unwrap());
    write_rpc(
        &mut client,
        json!({"id": 1, "method": "mining.subscribe", "params": ["MeshMineSim/2"]}),
    );
    let subscribe = read_rpc(&mut reader);
    let difficulty = read_rpc(&mut reader);
    let notify = read_rpc(&mut reader);
    assert_eq!(subscribe["result"][2], 4);
    assert_eq!(difficulty["method"], "mining.set_difficulty");
    assert_eq!(notify["params"].as_array().unwrap().len(), 10);

    write_rpc(
        &mut client,
        json!({"id": 2, "method": "mining.authorize", "params": ["operator.worker", "secret"]}),
    );
    assert_eq!(read_rpc(&mut reader)["result"], true);
    let nonce = qualifying_nonces(prefix, 1)[0];
    write_rpc(
        &mut client,
        json!({
            "id": 3,
            "method": "mining.submit",
            "params": ["operator.worker", "job-000000000001", "00000001", "65000000", format!("{nonce:08x}")]
        }),
    );
    assert_eq!(read_rpc(&mut reader)["result"], true);
    client.shutdown(std::net::Shutdown::Both).unwrap();

    let gateway = server.join().unwrap();
    assert_eq!(gateway.forwarded().len(), 1);
}

#[test]
fn failover_order_is_bounded_and_deterministic() {
    let mut failover = FailoverPool::new(vec![
        "127.0.0.1:3008".to_owned(),
        "127.0.0.1:3009".to_owned(),
    ])
    .unwrap();
    assert_eq!(failover.active(), "127.0.0.1:3008");
    assert_eq!(failover.fail(), "127.0.0.1:3009");
    assert_eq!(failover.fail(), "127.0.0.1:3008");
}

#[test]
fn rpc_line_reader_stops_before_unbounded_allocation() {
    let input = vec![b'x'; MAX_RPC_LINE + 1_024];
    let mut reader = Cursor::new(input);
    let mut line = String::new();
    assert_eq!(
        read_bounded_rpc_line(&mut reader, &mut line).unwrap(),
        MAX_RPC_LINE + 2
    );
    assert_eq!(line.len(), MAX_RPC_LINE + 2);
    assert!(!line.ends_with('\n'));
}

#[test]
fn production_clock_never_moves_backwards() {
    let first = process_wall_ms();
    let second = process_wall_ms();
    assert!(second >= first);
}

#[test]
fn rpc_session_debug_redacts_password() {
    let session = RpcSession::new(
        "operator.worker",
        "never-log-this-secret",
        [1, 2, 3, 4],
        DeviceProfile::simulator(),
    );
    let debug = format!("{session:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("never-log-this-secret"));
}

#[test]
fn rpc_authorization_uses_bounded_comparison_and_locks_after_failures() {
    assert!(constant_time_password_eq("secret", "secret"));
    assert!(!constant_time_password_eq("secret", "secreu"));
    assert!(!constant_time_password_eq("secret", "secret-longer"));
    assert!(constant_time_password_eq(
        &"x".repeat(MAX_RPC_PASSWORD_BYTES),
        &"x".repeat(MAX_RPC_PASSWORD_BYTES),
    ));
    assert!(!constant_time_password_eq(
        &"x".repeat(MAX_RPC_PASSWORD_BYTES + 1),
        &"x".repeat(MAX_RPC_PASSWORD_BYTES + 1),
    ));

    let (_directory, mut gateway, prefix) = setup();
    let mut session = RpcSession::new(
        "operator.worker",
        "secret",
        prefix,
        DeviceProfile::simulator(),
    );
    for attempt in 0..MAX_AUTHORIZATION_FAILURES {
        let response = rpc_call(
            &mut session,
            &mut gateway,
            json!({
                "id": attempt,
                "method": "mining.authorize",
                "params": ["operator.worker", "wrong"]
            }),
        );
        assert_eq!(response[0]["result"], false);
    }
    let locked = rpc_call(
        &mut session,
        &mut gateway,
        json!({
            "id": 9,
            "method": "mining.authorize",
            "params": ["operator.worker", "secret"]
        }),
    );
    assert_eq!(locked[0]["result"], false);
    assert_eq!(session.authorization_failures(), MAX_AUTHORIZATION_FAILURES);
    assert!(session.authorization_locked());
}

#[test]
fn rpc_server_closes_a_socket_when_authorization_locks() {
    let (_directory, mut gateway, prefix) = setup();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let session = RpcSession::new(
            "operator.worker",
            "secret",
            prefix,
            DeviceProfile::simulator(),
        );
        serve_rpc_connection_with_clock(stream, session, &mut gateway, 100, || 150).unwrap()
    });

    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut requests = Vec::new();
    for attempt in 0..=MAX_AUTHORIZATION_FAILURES {
        serde_json::to_writer(
            &mut requests,
            &json!({
                "id": attempt,
                "method": "mining.authorize",
                "params": ["operator.worker", "wrong"]
            }),
        )
        .unwrap();
        requests.push(b'\n');
    }
    client.write_all(&requests).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();

    let mut reader = BufReader::new(client);
    for _ in 0..MAX_AUTHORIZATION_FAILURES {
        assert_eq!(read_rpc(&mut reader)["result"], false);
    }
    let mut trailing = String::new();
    assert_eq!(reader.read_line(&mut trailing).unwrap(), 0);

    let session = server.join().unwrap();
    assert!(session.authorization_locked());
}

#[test]
fn transactions_require_authentication_and_have_a_response_bound() {
    let (_directory, mut gateway, prefix) = setup();
    let mut session = RpcSession::new(
        "operator.worker",
        "secret",
        prefix,
        DeviceProfile::simulator(),
    );
    let request = json!({
        "id": 1,
        "method": "mining.get_transactions",
        "params": ["job-000000000001"]
    });
    assert_eq!(
        rpc_call(&mut session, &mut gateway, request.clone())[0]["error"][0],
        25
    );
    rpc_call(
        &mut session,
        &mut gateway,
        json!({"id": 2, "method": "mining.subscribe", "params": []}),
    );
    assert_eq!(
        rpc_call(&mut session, &mut gateway, request.clone())[0]["error"][0],
        24
    );
    rpc_call(
        &mut session,
        &mut gateway,
        json!({
            "id": 3,
            "method": "mining.authorize",
            "params": ["operator.worker", "secret"]
        }),
    );
    assert_eq!(
        rpc_call(&mut session, &mut gateway, request)[0]["result"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let directory = secure_tempdir().unwrap();
    let store = Arc::new(RedbStore::create(directory.path().join("large-job.redb")).unwrap());
    let mut large_gateway = Gateway::open_research_simulator(store).unwrap();
    let mut large_job = job();
    large_job.id = "job-000000000099".to_owned();
    large_job.transaction_hashes = vec![hash(9); MAX_RPC_TRANSACTION_HASHES + 1];
    large_gateway.issue_job(large_job).unwrap();
    let mut large_session = RpcSession::new(
        "operator.worker",
        "secret",
        prefix,
        DeviceProfile::simulator(),
    );
    rpc_call(
        &mut large_session,
        &mut large_gateway,
        json!({"id": 4, "method": "mining.subscribe", "params": []}),
    );
    rpc_call(
        &mut large_session,
        &mut large_gateway,
        json!({
            "id": 5,
            "method": "mining.authorize",
            "params": ["operator.worker", "secret"]
        }),
    );
    let response = rpc_call(
        &mut large_session,
        &mut large_gateway,
        json!({
            "id": 6,
            "method": "mining.get_transactions",
            "params": ["job-000000000099"]
        }),
    );
    assert_eq!(response[0]["error"][1], "response-too-large");
    assert!(rpc_response_length(&response[0]) <= MAX_RPC_RESPONSE);
}

#[test]
fn storage_and_capture_capacity_failures_escape_rpc_mapping() {
    assert!(matches!(
        submit_rpc_result(json!(1), Err(GatewayError::CaptureCapacity)),
        Err(GatewayError::CaptureCapacity)
    ));
    assert!(matches!(
        submit_rpc_result(
            json!(1),
            Err(GatewayError::Storage(StorageError::Backend(
                "injected".to_owned()
            )))
        ),
        Err(GatewayError::Storage(_))
    ));
}

#[test]
fn client_io_error_preserves_gateway_for_the_supervisor() {
    let (_directory, mut gateway, prefix) = setup();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let session = RpcSession::new(
            "operator.worker",
            "secret",
            prefix,
            DeviceProfile::simulator(),
        );
        let result = serve_rpc_connection_with_clock(stream, session, &mut gateway, 1, || 150);
        (result, gateway.current_job().is_some())
    });

    let mut client = TcpStream::connect(address).unwrap();
    client.write_all(&[0xff, b'\n']).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let (result, gateway_preserved) = server.join().unwrap();
    assert!(matches!(
        result,
        Err(RpcServeError::ClientIo {
            ref source,
            authorization_failures: 0,
        }) if source.kind() == io::ErrorKind::InvalidData
    ));
    assert!(gateway_preserved);
}

#[test]
fn client_io_error_preserves_partial_authorization_failure_count() {
    let (_directory, mut gateway, prefix) = setup();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let session = RpcSession::new(
            "operator.worker",
            "secret",
            prefix,
            DeviceProfile::simulator(),
        );
        serve_rpc_connection_with_clock(stream, session, &mut gateway, 2, || 150)
    });

    let mut client = TcpStream::connect(address).unwrap();
    write_rpc(
        &mut client,
        json!({
            "id": 1,
            "method": "mining.authorize",
            "params": ["operator.worker", "wrong"]
        }),
    );
    client.write_all(&[0xff, b'\n']).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();

    let result = server.join().unwrap();
    assert!(matches!(
        result,
        Err(RpcServeError::ClientIo {
            ref source,
            authorization_failures: 1,
        }) if source.kind() == io::ErrorKind::InvalidData
    ));
}

#[test]
fn expired_absolute_line_deadline_does_not_read() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let _client = TcpStream::connect(address).unwrap();
    let (stream, _) = listener.accept().unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let deadline = Instant::now() - Duration::from_millis(1);
    let error = read_bounded_rpc_line_until(&mut reader, &mut line, deadline).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn gateway_event_history_is_a_bounded_ring() {
    let (_directory, mut gateway, _) = setup();
    let initial_events = gateway.events().len();
    for index in 0..MAX_GATEWAY_EVENTS + 17 {
        gateway.record_failover(&format!("endpoint-{index}"));
    }
    assert_eq!(gateway.events().len(), MAX_GATEWAY_EVENTS);
    assert_eq!(gateway.dropped_event_count(), 17 + initial_events as u64);
    assert!(matches!(
        gateway.events().back(),
        Some(GatewayEvent::FailoverActivated { endpoint })
            if endpoint == &format!("endpoint-{}", MAX_GATEWAY_EVENTS + 16)
    ));
}

fn rpc_call(session: &mut RpcSession, gateway: &mut Gateway, request: Value) -> Vec<Value> {
    session
        .handle_line(gateway, &serde_json::to_string(&request).unwrap(), 150)
        .unwrap()
}

fn write_rpc(stream: &mut TcpStream, value: Value) {
    serde_json::to_writer(&mut *stream, &value).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
}

fn read_rpc(reader: &mut BufReader<TcpStream>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}
