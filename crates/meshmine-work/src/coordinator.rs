use std::collections::BTreeMap;
use std::sync::Arc;

use meshmine_codec::{CanonicalDecode, CanonicalEncode, DecodeLimits};
use meshmine_hns::{Hash256, MinerHeader};
use meshmine_storage::{BatchOperation, DurableStore, StorageError};
use meshmine_types::domain_hash;
use thiserror::Error;

use crate::{
    BackendError, CAPTURE_NAMESPACE, CAPTURE_TOMBSTONE_NAMESPACE, CaptureRecord,
    DeviceCapabilities, DeviceEvent, DeviceId, GENERATION_NAMESPACE, JOB_NAMESPACE,
    LEASE_JOB_NAMESPACE, LeaseError, MiningBackend, PlannerError, PreparedDeviceJob,
    WORK_PROTOCOL_VERSION, WORK_SCHEMA_VERSION, WorkEnvelope, WorkLease, WorkPlanner,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateWork {
    pub generation: u64,
    pub previous_block: Hash256,
    pub merkle_root: Hash256,
    pub witness_root: Hash256,
    pub tree_root: Hash256,
    pub reserved_root: Hash256,
    pub version: u32,
    pub bits: u32,
    pub ntime: u64,
    pub mask_hash: Hash256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableAdmission {
    pub downstream_id: Hash256,
}

pub trait CaptureSink: Send + Sync {
    /// Return only after the corresponding Core/share evidence is durable.
    fn admit_capture(&self, capture: &CaptureRecord) -> Result<DurableAdmission, String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureOutcome {
    TelemetryOnly {
        raw_share_hash: Hash256,
    },
    DurablyAdmitted {
        capture_id: Hash256,
        downstream_id: Hash256,
    },
    Duplicate {
        capture_id: Hash256,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorStatus {
    pub registered_backends: usize,
    pub prepared_devices: usize,
    pub active_devices: usize,
    pub current_generation: Option<u64>,
    pub pending_captures: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoordinatorLimits {
    pub maximum_backends: usize,
    pub maximum_events_per_poll: usize,
    pub maximum_pending_capture_records: usize,
    pub maximum_pending_capture_bytes: u64,
}

impl Default for CoordinatorLimits {
    fn default() -> Self {
        Self {
            maximum_backends: 4_096,
            maximum_events_per_poll: 4_096,
            maximum_pending_capture_records: 100_000,
            maximum_pending_capture_bytes: 64 * 1024 * 1024,
        }
    }
}

impl CoordinatorLimits {
    fn validate(self) -> Result<Self, CoordinatorError> {
        if self.maximum_backends == 0
            || self.maximum_events_per_poll == 0
            || self.maximum_pending_capture_records == 0
            || self.maximum_pending_capture_bytes == 0
        {
            return Err(CoordinatorError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Debug, Error)]
pub enum CoordinatorError {
    #[error(transparent)]
    Planner(#[from] PlannerError),
    #[error(transparent)]
    Backend(#[from] BackendError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Lease(#[from] LeaseError),
    #[error("backend is not registered")]
    BackendNotFound,
    #[error("backend identifier conflicts with an existing registration")]
    BackendConflict,
    #[error("template and signed assignment generations differ")]
    GenerationMismatch,
    #[error("device has no prepared job")]
    JobNotPrepared,
    #[error("device event references a stale or inactive generation")]
    StaleGeneration,
    #[error("capture falls outside its durable lease")]
    CaptureOutsideLease,
    #[error("capture hash does not match exact scalar Handshake verification")]
    CaptureHashMismatch,
    #[error("capture is above the advertised device target")]
    HighHash,
    #[error("downstream durable admission failed: {0}")]
    Downstream(String),
    #[error("range completion is not credible for this backend")]
    UnauthorizedCompletion,
    #[error("durable work state is corrupt")]
    CorruptState,
    #[error("recovery scan limit must be non-zero")]
    RecoveryCapacity,
    #[error("coordinator resource limits are invalid")]
    InvalidLimits,
    #[error("coordinator backend or event capacity was exceeded")]
    Capacity,
}

struct BackendSlot {
    backend: Box<dyn MiningBackend>,
    capabilities: DeviceCapabilities,
    prepared: Option<(WorkLease, PreparedDeviceJob)>,
    active_generation: Option<u64>,
}

pub struct WorkCoordinator {
    store: Arc<dyn DurableStore>,
    planner: WorkPlanner,
    sink: Arc<dyn CaptureSink>,
    backends: BTreeMap<DeviceId, BackendSlot>,
    current_generation: Option<u64>,
    limits: CoordinatorLimits,
}

impl WorkCoordinator {
    pub fn new(
        store: Arc<dyn DurableStore>,
        planner: WorkPlanner,
        sink: Arc<dyn CaptureSink>,
    ) -> Self {
        Self::with_limits(store, planner, sink, CoordinatorLimits::default())
            .expect("default work coordinator limits are valid")
    }

    pub fn with_limits(
        store: Arc<dyn DurableStore>,
        planner: WorkPlanner,
        sink: Arc<dyn CaptureSink>,
        limits: CoordinatorLimits,
    ) -> Result<Self, CoordinatorError> {
        let limits = limits.validate()?;
        Ok(Self {
            store,
            planner,
            sink,
            backends: BTreeMap::new(),
            current_generation: None,
            limits,
        })
    }

    pub fn register_backend(
        &mut self,
        backend: Box<dyn MiningBackend>,
    ) -> Result<DeviceId, CoordinatorError> {
        if self.backends.len() >= self.limits.maximum_backends {
            return Err(CoordinatorError::Capacity);
        }
        let capabilities = backend.capabilities();
        capabilities
            .validate()
            .map_err(|_| CoordinatorError::BackendConflict)?;
        self.planner.register_device(&capabilities)?;
        let device_id = capabilities.device_id;
        if self.backends.contains_key(&device_id) {
            return Err(CoordinatorError::BackendConflict);
        }
        self.backends.insert(
            device_id,
            BackendSlot {
                backend,
                capabilities,
                prepared: None,
                active_generation: None,
            },
        );
        Ok(device_id)
    }

    /// Recover one durable prepared lease after restart. Recovery replays the
    /// PREPARE step only; activation remains an explicit operator/supervisor
    /// decision after the current template and signed assignment context have
    /// been requalified.
    pub fn recover_backend(
        &mut self,
        device_id: &DeviceId,
        envelope: &WorkEnvelope,
        template: &TemplateWork,
        now_ms: u64,
    ) -> Result<bool, CoordinatorError> {
        let slot = self
            .backends
            .get_mut(device_id)
            .ok_or(CoordinatorError::BackendNotFound)?;
        let Some(lease) = self.planner.active_lease(device_id)? else {
            return Ok(false);
        };
        if lease.device_id != *device_id {
            return Err(CoordinatorError::CorruptState);
        }
        if lease.expires_at_ms.is_some_and(|expiry| now_ms > expiry) {
            self.planner.retire(device_id, &lease.lease_id)?;
            return Ok(false);
        }
        if envelope.job_generation != template.generation
            || envelope.ntime != template.ntime
            || envelope.assignment_id != lease.assignment_id
        {
            return Err(CoordinatorError::GenerationMismatch);
        }
        envelope.validate_lease(&lease, &slot.capabilities)?;
        let lease_key = hex::encode(lease.lease_id);
        let job_id = self
            .store
            .get(LEASE_JOB_NAMESPACE, &lease_key)?
            .ok_or(CoordinatorError::CorruptState)?;
        if job_id.len() != 32 {
            return Err(CoordinatorError::CorruptState);
        }
        let job_bytes = self
            .store
            .get(JOB_NAMESPACE, &hex::encode(&job_id))?
            .ok_or(CoordinatorError::CorruptState)?;
        let job = PreparedDeviceJob::from_canonical_bytes(&job_bytes, DecodeLimits::default())
            .map_err(|_| CoordinatorError::CorruptState)?;
        job.validate_against_lease(&lease)?;
        if job.generation != template.generation
            || job.previous_block != template.previous_block
            || job.merkle_root != template.merkle_root
            || job.witness_root != template.witness_root
            || job.tree_root != template.tree_root
            || job.reserved_root != template.reserved_root
            || job.version != template.version
            || job.bits != template.bits
            || job.ntime != template.ntime
            || job.mask_hash != template.mask_hash
        {
            return Err(CoordinatorError::CorruptState);
        }
        slot.backend.prepare_job(&job)?;
        slot.prepared = Some((lease, job));
        slot.active_generation = None;
        Ok(true)
    }

    /// Retry a bounded prefix of captures that were durably spooled before a
    /// prior downstream failure or process restart. The downstream consumer
    /// must be idempotent by `capture_id` because a crash can occur after its
    /// durable commit and before the local tombstone transaction.
    pub fn retry_pending_captures(
        &self,
        maximum: usize,
    ) -> Result<Vec<CaptureOutcome>, CoordinatorError> {
        if maximum == 0 {
            return Err(CoordinatorError::RecoveryCapacity);
        }
        let page = self.store.scan_namespace_after(
            CAPTURE_NAMESPACE,
            None,
            meshmine_storage::ScanLimits {
                maximum_records: maximum,
                maximum_value_bytes: 4 * 1024,
                maximum_total_bytes: (maximum as u64).saturating_mul(4 * 1024),
            },
        )?;
        let mut outcomes = Vec::with_capacity(page.records.len());
        for record in page.records {
            let capture =
                CaptureRecord::from_canonical_bytes(&record.value, DecodeLimits::default())
                    .map_err(|_| CoordinatorError::CorruptState)?;
            let key = hex::encode(capture.capture_id);
            if let Some(downstream_id) = self.store.get(CAPTURE_TOMBSTONE_NAMESPACE, &key)? {
                if downstream_id.len() != 32 {
                    return Err(CoordinatorError::CorruptState);
                }
                self.store.delete(CAPTURE_NAMESPACE, &key)?;
                outcomes.push(CaptureOutcome::Duplicate {
                    capture_id: capture.capture_id,
                });
                continue;
            }
            let admission = self
                .sink
                .admit_capture(&capture)
                .map_err(CoordinatorError::Downstream)?;
            let operations = [
                BatchOperation::put(
                    CAPTURE_TOMBSTONE_NAMESPACE,
                    &key,
                    admission.downstream_id.to_vec(),
                ),
                BatchOperation::delete(CAPTURE_NAMESPACE, &key),
            ];
            if !self.store.apply_batch_if(
                CAPTURE_NAMESPACE,
                &key,
                Some(&record.value),
                &operations,
            )? {
                return Err(CoordinatorError::CorruptState);
            }
            outcomes.push(CaptureOutcome::DurablyAdmitted {
                capture_id: capture.capture_id,
                downstream_id: admission.downstream_id,
            });
        }
        Ok(outcomes)
    }

    /// Prepare one generation across multiple independent device backends.
    /// Each lease is durable before the backend sees the job. If any backend
    /// rejects preparation, already prepared peers are cancelled and their
    /// active-lease markers are retired without rewinding allocation cursors.
    pub fn prepare_generation(
        &mut self,
        assignments: &[(DeviceId, WorkEnvelope)],
        template: &TemplateWork,
        now_ms: u64,
        expires_at_ms: Option<u64>,
    ) -> Result<Vec<PreparedDeviceJob>, CoordinatorError> {
        let mut prepared_devices = Vec::new();
        let mut jobs = Vec::with_capacity(assignments.len());
        for (device_id, envelope) in assignments {
            match self.prepare(device_id, envelope, template, now_ms, expires_at_ms) {
                Ok(job) => {
                    prepared_devices.push(*device_id);
                    jobs.push(job);
                }
                Err(error) => {
                    for prepared in prepared_devices {
                        let _ = self.cancel(&prepared, template.generation);
                    }
                    return Err(error);
                }
            }
        }
        Ok(jobs)
    }

    /// Activate one previously prepared generation on every listed device.
    /// Failure cancels devices already switched during this call. The method
    /// makes no claim of hardware-level atomicity; it bounds the transition and
    /// leaves no device intentionally running a partially accepted generation.
    pub fn activate_generation(
        &mut self,
        device_ids: &[DeviceId],
        generation: u64,
    ) -> Result<(), CoordinatorError> {
        let mut activated = Vec::new();
        for device_id in device_ids {
            match self.activate(device_id, generation) {
                Ok(()) => activated.push(*device_id),
                Err(error) => {
                    for active in activated {
                        let _ = self.cancel(&active, generation);
                    }
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub fn cancel_generation(
        &mut self,
        device_ids: &[DeviceId],
        generation: u64,
    ) -> Result<(), CoordinatorError> {
        let mut first_error = None;
        for device_id in device_ids {
            if let Err(error) = self.cancel(device_id, generation)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            if self
                .backends
                .values()
                .all(|slot| slot.active_generation != Some(generation))
                && self.current_generation == Some(generation)
            {
                self.current_generation = None;
                self.store.delete(GENERATION_NAMESPACE, "active")?;
            }
            Ok(())
        }
    }

    pub fn prepare(
        &mut self,
        device_id: &DeviceId,
        envelope: &WorkEnvelope,
        template: &TemplateWork,
        now_ms: u64,
        expires_at_ms: Option<u64>,
    ) -> Result<PreparedDeviceJob, CoordinatorError> {
        if envelope.job_generation != template.generation || envelope.ntime != template.ntime {
            return Err(CoordinatorError::GenerationMismatch);
        }
        let slot = self
            .backends
            .get_mut(device_id)
            .ok_or(CoordinatorError::BackendNotFound)?;
        let lease = self
            .planner
            .allocate(envelope, &slot.capabilities, now_ms, expires_at_ms)?;
        envelope.validate_lease(&lease, &slot.capabilities)?;
        let mut job = PreparedDeviceJob {
            protocol_version: WORK_PROTOCOL_VERSION,
            job_id: [0; 32],
            assignment_id: envelope.assignment_id,
            lease_id: lease.lease_id,
            generation: template.generation,
            previous_block: template.previous_block,
            merkle_root: template.merkle_root,
            witness_root: template.witness_root,
            tree_root: template.tree_root,
            reserved_root: template.reserved_root,
            version: template.version,
            bits: template.bits,
            ntime: template.ntime,
            mask_hash: template.mask_hash,
            extra_nonce_start: lease.extra_nonce_start,
            extra_nonce_end: lease.extra_nonce_end,
            nonce_start: lease.nonce_start,
            nonce_end: lease.nonce_end,
            nonce_stride: lease.nonce_stride,
            edge_target: lease.edge_target,
            capture_target: lease.capture_target,
        };
        job.job_id = job.canonical_id();
        job.validate_against_lease(&lease)?;
        let job_key = hex::encode(job.job_id);
        let lease_key = hex::encode(lease.lease_id);
        let job_bytes = job.to_canonical_bytes();
        let mapping = job.job_id.to_vec();
        let existing_job = self.store.get(JOB_NAMESPACE, &job_key)?;
        let existing_mapping = self.store.get(LEASE_JOB_NAMESPACE, &lease_key)?;
        if existing_job
            .as_deref()
            .is_some_and(|bytes| bytes != job_bytes.as_slice())
            || existing_mapping
                .as_deref()
                .is_some_and(|bytes| bytes != mapping.as_slice())
        {
            return Err(CoordinatorError::CorruptState);
        }
        if !self.store.apply_batch_if_all(
            &[
                meshmine_storage::BatchCondition::new(JOB_NAMESPACE, &job_key, existing_job),
                meshmine_storage::BatchCondition::new(
                    LEASE_JOB_NAMESPACE,
                    &lease_key,
                    existing_mapping,
                ),
            ],
            &[
                BatchOperation::put(JOB_NAMESPACE, &job_key, job_bytes.clone()),
                BatchOperation::put(LEASE_JOB_NAMESPACE, &lease_key, mapping.clone()),
            ],
        )? {
            return Err(CoordinatorError::CorruptState);
        }
        if self.store.get(JOB_NAMESPACE, &job_key)?.as_deref() != Some(job_bytes.as_slice())
            || self.store.get(LEASE_JOB_NAMESPACE, &lease_key)?.as_deref()
                != Some(mapping.as_slice())
        {
            return Err(CoordinatorError::CorruptState);
        }
        if let Err(error) = slot.backend.prepare_job(&job) {
            let _ = self.planner.retire(device_id, &lease.lease_id);
            return Err(error.into());
        }
        slot.prepared = Some((lease, job.clone()));
        Ok(job)
    }

    pub fn activate(
        &mut self,
        device_id: &DeviceId,
        generation: u64,
    ) -> Result<(), CoordinatorError> {
        let slot = self
            .backends
            .get_mut(device_id)
            .ok_or(CoordinatorError::BackendNotFound)?;
        let (lease, job) = slot
            .prepared
            .as_ref()
            .ok_or(CoordinatorError::JobNotPrepared)?;
        if lease.job_generation != generation || job.generation != generation {
            return Err(CoordinatorError::StaleGeneration);
        }
        slot.backend.activate_job(generation)?;
        slot.active_generation = Some(generation);
        self.current_generation = Some(generation);
        self.store
            .put(GENERATION_NAMESPACE, "active", &generation.to_le_bytes())?;
        Ok(())
    }

    pub fn cancel(
        &mut self,
        device_id: &DeviceId,
        generation: u64,
    ) -> Result<(), CoordinatorError> {
        let slot = self
            .backends
            .get_mut(device_id)
            .ok_or(CoordinatorError::BackendNotFound)?;
        slot.backend.cancel_job(generation)?;
        if let Some((lease, _)) = slot
            .prepared
            .as_ref()
            .filter(|(_, job)| job.generation == generation)
        {
            self.planner.retire(device_id, &lease.lease_id)?;
        }
        if slot.active_generation == Some(generation) {
            slot.active_generation = None;
        }
        if slot
            .prepared
            .as_ref()
            .is_some_and(|(_, job)| job.generation == generation)
        {
            slot.prepared = None;
        }
        if self
            .backends
            .values()
            .all(|candidate| candidate.active_generation != Some(generation))
            && self.current_generation == Some(generation)
        {
            self.current_generation = None;
            self.store.delete(GENERATION_NAMESPACE, "active")?;
        }
        Ok(())
    }

    pub fn poll_device(
        &mut self,
        device_id: &DeviceId,
    ) -> Result<Vec<CaptureOutcome>, CoordinatorError> {
        let mut events = Vec::with_capacity(self.limits.maximum_events_per_poll.min(64));
        let mut overflow = false;
        {
            let slot = self
                .backends
                .get_mut(device_id)
                .ok_or(CoordinatorError::BackendNotFound)?;
            let maximum = self.limits.maximum_events_per_poll;
            slot.backend.poll_events(&mut |event| {
                if events.len() < maximum {
                    events.push(event);
                } else {
                    overflow = true;
                }
            })?;
        }
        if overflow {
            return Err(CoordinatorError::Capacity);
        }
        let mut outcomes = Vec::new();
        for event in events {
            if let Some(outcome) = self.process_event(device_id, event)? {
                outcomes.push(outcome);
            }
        }
        Ok(outcomes)
    }

    pub fn status(&self) -> Result<CoordinatorStatus, CoordinatorError> {
        let pending = self.store.scan_namespace(
            CAPTURE_NAMESPACE,
            meshmine_storage::ScanLimits {
                maximum_records: self.limits.maximum_pending_capture_records,
                maximum_value_bytes: 4096,
                maximum_total_bytes: self.limits.maximum_pending_capture_bytes,
            },
        )?;
        Ok(CoordinatorStatus {
            registered_backends: self.backends.len(),
            prepared_devices: self
                .backends
                .values()
                .filter(|slot| slot.prepared.is_some())
                .count(),
            active_devices: self
                .backends
                .values()
                .filter(|slot| slot.active_generation.is_some())
                .count(),
            current_generation: self.current_generation,
            pending_captures: pending.len(),
        })
    }

    fn process_event(
        &mut self,
        device_id: &DeviceId,
        event: DeviceEvent,
    ) -> Result<Option<CaptureOutcome>, CoordinatorError> {
        match event {
            DeviceEvent::JobAcknowledged { generation, .. } => {
                self.require_active(device_id, generation)?;
                Ok(None)
            }
            DeviceEvent::Capture {
                generation,
                nonce,
                ntime,
                extra_nonce,
                raw_share_hash,
                received_at_ms,
            } => self
                .process_capture(
                    device_id,
                    generation,
                    nonce,
                    ntime,
                    extra_nonce,
                    raw_share_hash,
                    received_at_ms,
                )
                .map(Some),
            DeviceEvent::RangeCompleted {
                generation,
                lease_id,
            } => {
                self.require_active(device_id, generation)?;
                let slot = self.backends.get_mut(device_id).unwrap();
                if !slot.capabilities.reports_range_completion {
                    return Err(CoordinatorError::UnauthorizedCompletion);
                }
                let (lease, _) = slot
                    .prepared
                    .as_ref()
                    .ok_or(CoordinatorError::JobNotPrepared)?;
                if lease.lease_id != lease_id || lease.job_generation != generation {
                    return Err(CoordinatorError::UnauthorizedCompletion);
                }
                self.planner.complete(&slot.capabilities, &lease_id)?;
                slot.prepared = None;
                slot.active_generation = None;
                Ok(None)
            }
            DeviceEvent::Telemetry { generation, .. } => {
                self.require_active(device_id, generation)?;
                Ok(None)
            }
            DeviceEvent::Disconnected => {
                let slot = self.backends.get_mut(device_id).unwrap();
                if let Some((lease, _)) = &slot.prepared {
                    self.planner.retire(device_id, &lease.lease_id)?;
                }
                slot.prepared = None;
                slot.active_generation = None;
                Ok(None)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_capture(
        &mut self,
        device_id: &DeviceId,
        generation: u64,
        nonce: u32,
        ntime: u64,
        extra_nonce: [u8; 24],
        raw_share_hash: Hash256,
        received_at_ms: u64,
    ) -> Result<CaptureOutcome, CoordinatorError> {
        self.require_active(device_id, generation)?;
        let slot = self.backends.get(device_id).unwrap();
        let (lease, job) = slot
            .prepared
            .as_ref()
            .ok_or(CoordinatorError::JobNotPrepared)?;
        if ntime != job.ntime
            || !lease.accepts_extra_nonce(&extra_nonce)
            || nonce < lease.nonce_start
            || nonce > lease.nonce_end
            || lease.nonce_stride == 0
            || nonce.saturating_sub(lease.nonce_start) % lease.nonce_stride != 0
            || lease
                .expires_at_ms
                .is_some_and(|expiry| received_at_ms > expiry)
        {
            return Err(CoordinatorError::CaptureOutsideLease);
        }
        let header = MinerHeader {
            nonce,
            time: ntime,
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
        let expected = header.share_hash();
        if expected != raw_share_hash {
            return Err(CoordinatorError::CaptureHashMismatch);
        }
        if raw_share_hash > job.edge_target.0 {
            return Err(CoordinatorError::HighHash);
        }
        if raw_share_hash > job.capture_target.0 {
            return Ok(CaptureOutcome::TelemetryOnly { raw_share_hash });
        }
        let mut record = CaptureRecord {
            version: WORK_SCHEMA_VERSION,
            capture_id: [0; 32],
            lease_id: lease.lease_id,
            assignment_id: lease.assignment_id,
            device_id: *device_id,
            generation,
            nonce,
            ntime,
            extra_nonce,
            raw_share_hash,
            received_at_ms,
        };
        record.capture_id = record.canonical_id();
        let capture_id = record.capture_id;
        let key = hex::encode(capture_id);
        if self.store.get(CAPTURE_TOMBSTONE_NAMESPACE, &key)?.is_some() {
            return Ok(CaptureOutcome::Duplicate { capture_id });
        }
        let bytes = record.to_canonical_bytes();
        if !self
            .store
            .compare_and_swap(CAPTURE_NAMESPACE, &key, None, &bytes)?
            && self.store.get(CAPTURE_NAMESPACE, &key)?.as_deref() != Some(bytes.as_slice())
        {
            return Err(CoordinatorError::CorruptState);
        }
        let admission = self
            .sink
            .admit_capture(&record)
            .map_err(CoordinatorError::Downstream)?;
        let operations = [
            BatchOperation::put(
                CAPTURE_TOMBSTONE_NAMESPACE,
                &key,
                admission.downstream_id.to_vec(),
            ),
            BatchOperation::delete(CAPTURE_NAMESPACE, &key),
        ];
        if !self
            .store
            .apply_batch_if(CAPTURE_NAMESPACE, &key, Some(&bytes), &operations)?
        {
            return Err(CoordinatorError::CorruptState);
        }
        Ok(CaptureOutcome::DurablyAdmitted {
            capture_id,
            downstream_id: admission.downstream_id,
        })
    }

    fn require_active(
        &self,
        device_id: &DeviceId,
        generation: u64,
    ) -> Result<(), CoordinatorError> {
        let slot = self
            .backends
            .get(device_id)
            .ok_or(CoordinatorError::BackendNotFound)?;
        if slot.active_generation != Some(generation) {
            return Err(CoordinatorError::StaleGeneration);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryCaptureSink {
    records: std::sync::Mutex<BTreeMap<Hash256, CaptureRecord>>,
}

impl MemoryCaptureSink {
    pub fn records(&self) -> BTreeMap<Hash256, CaptureRecord> {
        self.records.lock().unwrap().clone()
    }
}

impl CaptureSink for MemoryCaptureSink {
    fn admit_capture(&self, capture: &CaptureRecord) -> Result<DurableAdmission, String> {
        self.records
            .lock()
            .map_err(|_| "capture sink lock poisoned".to_owned())?
            .insert(capture.capture_id, capture.clone());
        Ok(DurableAdmission {
            downstream_id: domain_hash("MESHMINE/MEMORY_SINK/V1", &capture.capture_id),
        })
    }
}
