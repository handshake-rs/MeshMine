use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use meshmine_hns::MinerHeader;
use meshmine_storage::{DurableStore, MemoryStore};
use meshmine_types::{
    AssignmentV2, GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16, GatewayAssignmentV1,
    SignatureBytes, U256,
};

use crate::*;

fn hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn device(byte: u8, kind: BackendKind) -> DeviceCapabilities {
    DeviceCapabilities {
        device_id: hash(byte),
        backend_kind: kind,
        supports_nonce_range: kind != BackendKind::HandyStratum,
        supports_nonce_stride: kind != BackendKind::HandyStratum,
        supports_extra_nonce_range: kind == BackendKind::HandyStratum,
        supports_ntime_rolling: false,
        supports_job_prepare: kind != BackendKind::HandyStratum,
        reports_range_completion: kind != BackendKind::HandyStratum,
        minimum_device_target: U256([0xff; 32]),
        maximum_job_rate_hz: 10,
        preferred_batch_size: 2,
        measured_hashrate: None,
        telemetry_level: 0,
    }
}

fn gateway_assignment(start: u32, end: u32) -> GatewayAssignmentV1 {
    GatewayAssignmentV1 {
        core_protocol_version: 2,
        handoff_version: 1,
        network_id: 0,
        session_id: hash(1),
        body_package_id: hash(2),
        body_certificate_id: hash(3),
        operator_pubkey: hash(4),
        gateway_pubkey: hash(5),
        core_handoff_pubkey: hash(6),
        worker_id_hash: hash(7),
        payout_bucket_id: hash(8),
        assignment_sequence: 9,
        ntime: 1_700_000_000,
        extra_nonce_profile: GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16,
        observation_policy: 1,
        maximum_clock_skew_ms: 60_000,
        extra_nonce_prefix: [1, 2, 3, 4],
        extra_nonce2_start_be: start.to_be_bytes(),
        extra_nonce2_end_be: end.to_be_bytes(),
        nonce_start: 0,
        nonce_end: u32::MAX,
        nonce_stride: 1,
        edge_target: U256([0xff; 32]),
        capture_target: U256([0xff; 32]),
        telemetry_level: 0,
        operator_signature: SignatureBytes::empty(),
    }
}

fn assignment() -> AssignmentV2 {
    AssignmentV2 {
        protocol_version: 2,
        network_id: 0,
        session_id: hash(1),
        body_package_id: hash(2),
        body_certificate_id: hash(3),
        operator_pubkey: hash(4),
        worker_id_hash: hash(7),
        payout_bucket_id: hash(8),
        assignment_sequence: 11,
        ntime: 1_700_000_000,
        extra_nonce: [9; 24],
        nonce_start: 100,
        nonce_end: 200,
        nonce_stride: 1,
        edge_target: U256([0xff; 32]),
        capture_target: U256([0xff; 32]),
        telemetry_level: 1,
        operator_signature: SignatureBytes::empty(),
    }
}

fn planner(store: Arc<dyn DurableStore>) -> WorkPlanner {
    WorkPlanner::open(
        store,
        PlannerLimits {
            maximum_extra_nonce_values_per_lease: 2,
            maximum_nonce_values_per_lease: 2,
            target_native_lease_ms: 250,
        },
    )
    .unwrap()
}

#[test]
fn gateway_leases_are_non_overlapping_and_never_reused() {
    let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
    let planner = planner(store);
    let envelope =
        WorkEnvelope::from_gateway_assignment(&gateway_assignment(100, 110), 77).unwrap();
    let first_device = device(10, BackendKind::HandyStratum);
    let second_device = device(11, BackendKind::HandyStratum);
    let third_device = device(12, BackendKind::HandyStratum);

    let first = planner
        .allocate(&envelope, &first_device, 1_000, None)
        .unwrap();
    let second = planner
        .allocate(&envelope, &second_device, 1_001, None)
        .unwrap();
    assert_eq!(extra_nonce2(&first.extra_nonce_start), Some(100));
    assert_eq!(extra_nonce2(&first.extra_nonce_end), Some(101));
    assert_eq!(extra_nonce2(&second.extra_nonce_start), Some(102));
    assert_eq!(extra_nonce2(&second.extra_nonce_end), Some(103));

    planner
        .retire(&first_device.device_id, &first.lease_id)
        .unwrap();
    let third = planner
        .allocate(&envelope, &third_device, 1_002, None)
        .unwrap();
    assert_eq!(extra_nonce2(&third.extra_nonce_start), Some(104));
    assert_eq!(extra_nonce2(&third.extra_nonce_end), Some(105));
}

#[test]
fn native_workers_receive_disjoint_nonce_batches() {
    let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
    let planner = planner(store);
    let envelope = WorkEnvelope::from_assignment(&assignment(), 22).unwrap();
    let first = planner
        .allocate(&envelope, &device(20, BackendKind::Arm64Cpu), 1, None)
        .unwrap();
    let second = planner
        .allocate(&envelope, &device(21, BackendKind::X86Cpu), 2, None)
        .unwrap();
    assert_eq!((first.nonce_start, first.nonce_end), (100, 101));
    assert_eq!((second.nonce_start, second.nonce_end), (102, 103));
}

#[derive(Default)]
struct SharedBackendState {
    prepared: Option<PreparedDeviceJob>,
    active: Option<u64>,
    events: VecDeque<DeviceEvent>,
}

struct SharedBackend {
    capabilities: DeviceCapabilities,
    state: Arc<Mutex<SharedBackendState>>,
}

impl MiningBackend for SharedBackend {
    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }

    fn prepare_job(&mut self, job: &PreparedDeviceJob) -> Result<(), BackendError> {
        self.state.lock().unwrap().prepared = Some(job.clone());
        Ok(())
    }

    fn activate_job(&mut self, generation: u64) -> Result<(), BackendError> {
        let mut state = self.state.lock().unwrap();
        if state.prepared.as_ref().map(|job| job.generation) != Some(generation) {
            return Err(BackendError::GenerationNotPrepared);
        }
        state.active = Some(generation);
        Ok(())
    }

    fn cancel_job(&mut self, generation: u64) -> Result<(), BackendError> {
        let mut state = self.state.lock().unwrap();
        if state.active == Some(generation) {
            state.active = None;
        }
        Ok(())
    }

    fn poll_events(&mut self, output: &mut dyn FnMut(DeviceEvent)) -> Result<(), BackendError> {
        let mut state = self.state.lock().unwrap();
        while let Some(event) = state.events.pop_front() {
            output(event);
        }
        Ok(())
    }
}

fn template(generation: u64, ntime: u64) -> TemplateWork {
    TemplateWork {
        generation,
        previous_block: hash(31),
        merkle_root: hash(32),
        witness_root: hash(33),
        tree_root: hash(34),
        reserved_root: hash(35),
        version: 1,
        bits: 0x207f_ffff,
        ntime,
        mask_hash: hash(36),
    }
}

#[test]
fn capture_is_acknowledged_only_after_durable_downstream_admission() {
    let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
    let sink = Arc::new(MemoryCaptureSink::default());
    let planner = planner(store.clone());
    let mut coordinator = WorkCoordinator::new(store, planner, sink.clone());
    let state = Arc::new(Mutex::new(SharedBackendState::default()));
    let capabilities = device(40, BackendKind::Arm64Cpu);
    coordinator
        .register_backend(Box::new(SharedBackend {
            capabilities: capabilities.clone(),
            state: state.clone(),
        }))
        .unwrap();
    let assignment = assignment();
    let envelope = WorkEnvelope::from_assignment(&assignment, 55).unwrap();
    let job = coordinator
        .prepare(
            &capabilities.device_id,
            &envelope,
            &template(55, assignment.ntime),
            1_000,
            None,
        )
        .unwrap();
    coordinator.activate(&capabilities.device_id, 55).unwrap();

    let nonce = job.nonce_start;
    let extra_nonce = job.extra_nonce_start;
    let header = MinerHeader {
        nonce,
        time: job.ntime,
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
    let raw_share_hash = header.share_hash();
    state
        .lock()
        .unwrap()
        .events
        .push_back(DeviceEvent::Capture {
            generation: 55,
            nonce,
            ntime: job.ntime,
            extra_nonce,
            raw_share_hash,
            received_at_ms: 1_100,
        });
    let outcomes = coordinator.poll_device(&capabilities.device_id).unwrap();
    assert!(matches!(
        outcomes.as_slice(),
        [CaptureOutcome::DurablyAdmitted { .. }]
    ));
    assert_eq!(sink.records().len(), 1);
    assert_eq!(coordinator.status().unwrap().pending_captures, 0);

    state
        .lock()
        .unwrap()
        .events
        .push_back(DeviceEvent::Capture {
            generation: 55,
            nonce,
            ntime: job.ntime,
            extra_nonce,
            raw_share_hash,
            received_at_ms: 1_101,
        });
    let outcomes = coordinator.poll_device(&capabilities.device_id).unwrap();
    assert!(matches!(
        outcomes.as_slice(),
        [CaptureOutcome::Duplicate { .. }]
    ));
}

struct FailingSink;

impl CaptureSink for FailingSink {
    fn admit_capture(&self, _capture: &CaptureRecord) -> Result<DurableAdmission, String> {
        Err("offline".to_owned())
    }
}

#[test]
fn downstream_failure_leaves_capture_durable_and_unacknowledged() {
    let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
    let planner = planner(store.clone());
    let mut coordinator = WorkCoordinator::new(store, planner, Arc::new(FailingSink));
    let state = Arc::new(Mutex::new(SharedBackendState::default()));
    let capabilities = device(50, BackendKind::Arm64Cpu);
    coordinator
        .register_backend(Box::new(SharedBackend {
            capabilities: capabilities.clone(),
            state: state.clone(),
        }))
        .unwrap();
    let assignment = assignment();
    let envelope = WorkEnvelope::from_assignment(&assignment, 66).unwrap();
    let job = coordinator
        .prepare(
            &capabilities.device_id,
            &envelope,
            &template(66, assignment.ntime),
            2_000,
            None,
        )
        .unwrap();
    coordinator.activate(&capabilities.device_id, 66).unwrap();
    let header = MinerHeader {
        nonce: job.nonce_start,
        time: job.ntime,
        prev_block: job.previous_block,
        tree_root: job.tree_root,
        mask_hash: job.mask_hash,
        extra_nonce: job.extra_nonce_start,
        reserved_root: job.reserved_root,
        witness_root: job.witness_root,
        merkle_root: job.merkle_root,
        version: job.version,
        bits: job.bits,
    };
    state
        .lock()
        .unwrap()
        .events
        .push_back(DeviceEvent::Capture {
            generation: 66,
            nonce: job.nonce_start,
            ntime: job.ntime,
            extra_nonce: job.extra_nonce_start,
            raw_share_hash: header.share_hash(),
            received_at_ms: 2_100,
        });
    assert!(matches!(
        coordinator.poll_device(&capabilities.device_id),
        Err(CoordinatorError::Downstream(_))
    ));
    assert_eq!(coordinator.status().unwrap().pending_captures, 1);
}

#[test]
fn stock_asic_cannot_claim_exhaustive_range_completion() {
    let capabilities = device(60, BackendKind::HandyStratum);
    assert!(!capabilities.reports_range_completion);
    let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
    let planner = planner(store);
    let envelope = WorkEnvelope::from_gateway_assignment(&gateway_assignment(0, 10), 88).unwrap();
    let lease = planner.allocate(&envelope, &capabilities, 1, None).unwrap();
    assert!(matches!(
        planner.complete(&capabilities, &lease.lease_id),
        Err(PlannerError::UnauthorizedCompletion)
    ));
}

#[test]
fn adaptive_target_never_becomes_harder_than_capture() {
    let capture = U256([0x10; 32]);
    let device_minimum = U256([0x20; 32]);
    let initial = U256([0x40; 32]);
    let mut controller = AdaptiveTargetController::new(
        TargetControllerConfig {
            desired_submission_interval_ms: 1_000,
            minimum_observations: 2,
            maximum_step_numerator: 4,
            maximum_step_denominator: 1,
        },
        capture,
        device_minimum,
        U256([0xff; 32]),
        initial,
    )
    .unwrap();
    assert!(controller.observe_submission(1).is_none());
    let target = controller.observe_submission(1).unwrap();
    assert!(target.0 >= device_minimum.0);
    assert!(target.0 >= capture.0);
}

#[test]
fn adaptive_target_eases_when_submissions_are_too_slow() {
    let capture = U256([0x01; 32]);
    let initial = U256([0x10; 32]);
    let mut controller = AdaptiveTargetController::new(
        TargetControllerConfig {
            desired_submission_interval_ms: 1_000,
            minimum_observations: 1,
            maximum_step_numerator: 4,
            maximum_step_denominator: 1,
        },
        capture,
        capture,
        U256([0xff; 32]),
        initial,
    )
    .unwrap();
    let target = controller.observe_submission(4_000).unwrap();
    assert!(target.0 > initial.0);
}

#[test]
fn handy_lease_rejects_nonzero_tail_even_when_lexicographically_in_range() {
    let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
    let planner = planner(store);
    let envelope = WorkEnvelope::from_gateway_assignment(&gateway_assignment(1, 2), 99).unwrap();
    let capabilities = device(70, BackendKind::HandyStratum);
    let lease = planner.allocate(&envelope, &capabilities, 1, None).unwrap();
    let mut malformed = lease.extra_nonce_start;
    malformed[23] = 1;
    assert!(!lease.accepts_extra_nonce(&malformed));
}

#[test]
fn prepared_job_and_lease_recover_without_automatic_activation() {
    let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
    let sink = Arc::new(MemoryCaptureSink::default());
    let first_state = Arc::new(Mutex::new(SharedBackendState::default()));
    let capabilities = device(80, BackendKind::Arm64Cpu);
    {
        let planner = planner(store.clone());
        let mut coordinator = WorkCoordinator::new(store.clone(), planner, sink.clone());
        coordinator
            .register_backend(Box::new(SharedBackend {
                capabilities: capabilities.clone(),
                state: first_state,
            }))
            .unwrap();
        let assignment = assignment();
        let envelope = WorkEnvelope::from_assignment(&assignment, 101).unwrap();
        coordinator
            .prepare(
                &capabilities.device_id,
                &envelope,
                &template(101, assignment.ntime),
                10,
                None,
            )
            .unwrap();
    }

    let recovered_state = Arc::new(Mutex::new(SharedBackendState::default()));
    let planner = planner(store.clone());
    let mut recovered = WorkCoordinator::new(store, planner, sink);
    recovered
        .register_backend(Box::new(SharedBackend {
            capabilities: capabilities.clone(),
            state: recovered_state.clone(),
        }))
        .unwrap();
    let assignment = assignment();
    let envelope = WorkEnvelope::from_assignment(&assignment, 101).unwrap();
    assert!(
        recovered
            .recover_backend(
                &capabilities.device_id,
                &envelope,
                &template(101, assignment.ntime),
                11,
            )
            .unwrap()
    );
    assert!(recovered_state.lock().unwrap().prepared.is_some());
    assert_eq!(recovered_state.lock().unwrap().active, None);
    recovered.activate(&capabilities.device_id, 101).unwrap();
    assert_eq!(recovered_state.lock().unwrap().active, Some(101));
}

#[test]
fn pending_capture_retries_after_restart_and_compacts_only_after_success() {
    let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
    let failing_planner = planner(store.clone());
    let mut failing = WorkCoordinator::new(store.clone(), failing_planner, Arc::new(FailingSink));
    let state = Arc::new(Mutex::new(SharedBackendState::default()));
    let capabilities = device(81, BackendKind::Arm64Cpu);
    failing
        .register_backend(Box::new(SharedBackend {
            capabilities: capabilities.clone(),
            state: state.clone(),
        }))
        .unwrap();
    let assignment = assignment();
    let envelope = WorkEnvelope::from_assignment(&assignment, 102).unwrap();
    let job = failing
        .prepare(
            &capabilities.device_id,
            &envelope,
            &template(102, assignment.ntime),
            20,
            None,
        )
        .unwrap();
    failing.activate(&capabilities.device_id, 102).unwrap();
    let header = MinerHeader {
        nonce: job.nonce_start,
        time: job.ntime,
        prev_block: job.previous_block,
        tree_root: job.tree_root,
        mask_hash: job.mask_hash,
        extra_nonce: job.extra_nonce_start,
        reserved_root: job.reserved_root,
        witness_root: job.witness_root,
        merkle_root: job.merkle_root,
        version: job.version,
        bits: job.bits,
    };
    state
        .lock()
        .unwrap()
        .events
        .push_back(DeviceEvent::Capture {
            generation: 102,
            nonce: job.nonce_start,
            ntime: job.ntime,
            extra_nonce: job.extra_nonce_start,
            raw_share_hash: header.share_hash(),
            received_at_ms: 21,
        });
    assert!(matches!(
        failing.poll_device(&capabilities.device_id),
        Err(CoordinatorError::Downstream(_))
    ));
    assert_eq!(failing.status().unwrap().pending_captures, 1);
    drop(failing);

    let sink = Arc::new(MemoryCaptureSink::default());
    let recovery = WorkCoordinator::new(store.clone(), planner(store), sink.clone());
    let outcomes = recovery.retry_pending_captures(10).unwrap();
    assert!(matches!(
        outcomes.as_slice(),
        [CaptureOutcome::DurablyAdmitted { .. }]
    ));
    assert_eq!(sink.records().len(), 1);
    assert_eq!(recovery.status().unwrap().pending_captures, 0);
}

#[test]
fn expired_active_lease_is_retired_without_reusing_its_namespace() {
    let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
    let planner = planner(store);
    let envelope =
        WorkEnvelope::from_gateway_assignment(&gateway_assignment(100, 110), 103).unwrap();
    let capabilities = device(82, BackendKind::HandyStratum);
    let first = planner
        .allocate(&envelope, &capabilities, 10, Some(20))
        .unwrap();
    assert_eq!(extra_nonce2(&first.extra_nonce_start), Some(100));
    let second = planner
        .allocate(&envelope, &capabilities, 21, Some(40))
        .unwrap();
    assert_eq!(extra_nonce2(&second.extra_nonce_start), Some(102));
    assert_ne!(first.lease_id, second.lease_id);
}

#[test]
fn native_nonce_lease_end_is_aligned_to_the_signed_stride() {
    let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
    let planner = planner(store);
    let mut signed = assignment();
    signed.nonce_start = 100;
    signed.nonce_end = 104;
    signed.nonce_stride = 3;
    let envelope = WorkEnvelope::from_assignment(&signed, 104).unwrap();
    let lease = planner
        .allocate(&envelope, &device(83, BackendKind::Arm64Cpu), 1, None)
        .unwrap();
    assert_eq!(
        (lease.nonce_start, lease.nonce_end, lease.nonce_stride),
        (100, 103, 3)
    );
}

#[test]
fn locally_measured_hashrate_can_refresh_without_changing_device_contract() {
    let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
    let planner = planner(store.clone());
    let mut capabilities = device(84, BackendKind::Arm64Cpu);
    planner.register_device(&capabilities).unwrap();
    capabilities.measured_hashrate = Some(12_345);
    planner.register_device(&capabilities).unwrap();
    let stored = store
        .get(DEVICE_NAMESPACE, &hex::encode(capabilities.device_id))
        .unwrap()
        .unwrap();
    assert_eq!(
        decode_capabilities(&stored).unwrap().measured_hashrate,
        Some(12_345)
    );
}

#[test]
fn adaptive_target_never_exceeds_the_signed_edge_target() {
    let capture = U256([0x01; 32]);
    let signed_maximum = U256([0x20; 32]);
    let initial = U256([0x10; 32]);
    let mut controller = AdaptiveTargetController::new(
        TargetControllerConfig {
            desired_submission_interval_ms: 1_000,
            minimum_observations: 1,
            maximum_step_numerator: 16,
            maximum_step_denominator: 1,
        },
        capture,
        capture,
        signed_maximum,
        initial,
    )
    .unwrap();
    assert_eq!(controller.observe_submission(100_000), Some(signed_maximum));
}

#[test]
fn event_polling_is_bounded_by_coordinator_policy() {
    let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
    let sink = Arc::new(MemoryCaptureSink::default());
    let planner = planner(store.clone());
    let mut coordinator = WorkCoordinator::with_limits(
        store,
        planner,
        sink,
        CoordinatorLimits {
            maximum_backends: 2,
            maximum_events_per_poll: 1,
            maximum_pending_capture_records: 10,
            maximum_pending_capture_bytes: 64 * 1024,
        },
    )
    .unwrap();
    let state = Arc::new(Mutex::new(SharedBackendState::default()));
    let capabilities = device(85, BackendKind::Arm64Cpu);
    coordinator
        .register_backend(Box::new(SharedBackend {
            capabilities: capabilities.clone(),
            state: state.clone(),
        }))
        .unwrap();
    let signed = assignment();
    let envelope = WorkEnvelope::from_assignment(&signed, 105).unwrap();
    coordinator
        .prepare(
            &capabilities.device_id,
            &envelope,
            &template(105, signed.ntime),
            1,
            None,
        )
        .unwrap();
    coordinator.activate(&capabilities.device_id, 105).unwrap();
    let mut locked = state.lock().unwrap();
    locked.events.push_back(DeviceEvent::Telemetry {
        generation: 105,
        hashes_reported: Some(1),
        temperature_millicelsius: None,
        power_millijoules: None,
    });
    locked.events.push_back(DeviceEvent::Telemetry {
        generation: 105,
        hashes_reported: Some(2),
        temperature_millicelsius: None,
        power_millijoules: None,
    });
    drop(locked);
    assert!(matches!(
        coordinator.poll_device(&capabilities.device_id),
        Err(CoordinatorError::Capacity)
    ));
}
