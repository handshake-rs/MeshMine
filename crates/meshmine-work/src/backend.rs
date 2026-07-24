use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use meshmine_hns::{Hash256, MinerHeader};
use thiserror::Error;

use crate::{BackendKind, DeviceCapabilities, PreparedDeviceJob};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceEvent {
    JobAcknowledged {
        generation: u64,
        observed_at_ms: u64,
    },
    Capture {
        generation: u64,
        nonce: u32,
        ntime: u64,
        extra_nonce: [u8; 24],
        raw_share_hash: Hash256,
        received_at_ms: u64,
    },
    RangeCompleted {
        generation: u64,
        lease_id: Hash256,
    },
    Telemetry {
        generation: u64,
        hashes_reported: Option<u64>,
        temperature_millicelsius: Option<i32>,
        power_millijoules: Option<u64>,
    },
    Disconnected,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendError {
    #[error("backend rejected an invalid capability descriptor")]
    InvalidCapabilities,
    #[error("backend already has a different prepared job for this generation")]
    ConflictingPreparedJob,
    #[error("requested generation has not been prepared")]
    GenerationNotPrepared,
    #[error("requested generation is not active")]
    GenerationNotActive,
    #[error("backend event queue exceeded its configured bound")]
    EventCapacity,
    #[error("backend operation failed: {0}")]
    Operation(String),
}

pub trait MiningBackend: Send {
    fn capabilities(&self) -> DeviceCapabilities;

    fn prepare_job(&mut self, job: &PreparedDeviceJob) -> Result<(), BackendError>;

    fn activate_job(&mut self, generation: u64) -> Result<(), BackendError>;

    fn cancel_job(&mut self, generation: u64) -> Result<(), BackendError>;

    fn poll_events(&mut self, output: &mut dyn FnMut(DeviceEvent)) -> Result<(), BackendError>;
}

/// Native parallel CPU backend.
///
/// Each worker owns a disjoint nonce stride and precomputes every immutable
/// header commitment once per extra nonce. The bounded event channel applies
/// backpressure without dropping captures. Cancellation is checked inside the
/// hash loop, so a tip transition does not wait for a whole lease.
pub struct CpuBackend {
    capabilities: DeviceCapabilities,
    prepared: Option<PreparedDeviceJob>,
    active_generation: Option<u64>,
    threads: usize,
    event_capacity: usize,
    worker: Option<CpuWorker>,
}

struct CpuWorker {
    cancel: Arc<AtomicBool>,
    events: Receiver<DeviceEvent>,
    handles: Vec<JoinHandle<()>>,
}

impl CpuBackend {
    pub fn new(
        capabilities: DeviceCapabilities,
        threads: usize,
        event_capacity: usize,
    ) -> Result<Self, BackendError> {
        capabilities
            .validate()
            .map_err(|_| BackendError::InvalidCapabilities)?;
        if !matches!(
            capabilities.backend_kind,
            BackendKind::Arm64Cpu | BackendKind::X86Cpu
        ) || !capabilities.supports_nonce_range
            || !capabilities.supports_nonce_stride
            || !capabilities.supports_job_prepare
            || !capabilities.reports_range_completion
            || threads == 0
            || event_capacity == 0
        {
            return Err(BackendError::InvalidCapabilities);
        }
        Ok(Self {
            capabilities,
            prepared: None,
            active_generation: None,
            threads,
            event_capacity,
            worker: None,
        })
    }

    pub fn active_threads(&self) -> usize {
        self.worker
            .as_ref()
            .map_or(0, |worker| worker.handles.len())
    }

    fn stop_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.cancel.store(true, Ordering::Release);
            for handle in worker.handles {
                let _ = handle.join();
            }
        }
    }

    fn start_worker(&mut self, job: PreparedDeviceJob) -> Result<(), BackendError> {
        self.stop_worker();
        let (sender, events) = sync_channel(self.event_capacity);
        let cancel = Arc::new(AtomicBool::new(false));
        let remaining = Arc::new(AtomicUsize::new(self.threads));
        let mut handles = Vec::with_capacity(self.threads);
        for thread_index in 0..self.threads {
            let sender = sender.clone();
            let cancel = Arc::clone(&cancel);
            let remaining = Arc::clone(&remaining);
            let job = job.clone();
            let thread_count = self.threads;
            let name = format!(
                "meshmine-cpu-{}-{thread_index}",
                hex::encode(&self.capabilities.device_id[..4])
            );
            let handle = thread::Builder::new()
                .name(name)
                .spawn(move || {
                    run_cpu_worker(
                        &job,
                        thread_index,
                        thread_count,
                        &cancel,
                        &remaining,
                        &sender,
                    );
                })
                .map_err(|error| BackendError::Operation(error.to_string()))?;
            handles.push(handle);
        }
        drop(sender);
        self.worker = Some(CpuWorker {
            cancel,
            events,
            handles,
        });
        Ok(())
    }
}

impl Drop for CpuBackend {
    fn drop(&mut self) {
        self.stop_worker();
    }
}

impl MiningBackend for CpuBackend {
    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }

    fn prepare_job(&mut self, job: &PreparedDeviceJob) -> Result<(), BackendError> {
        if self
            .prepared
            .as_ref()
            .is_some_and(|current| current.generation == job.generation && current != job)
        {
            return Err(BackendError::ConflictingPreparedJob);
        }
        self.stop_worker();
        self.active_generation = None;
        self.prepared = Some(job.clone());
        Ok(())
    }

    fn activate_job(&mut self, generation: u64) -> Result<(), BackendError> {
        let job = self
            .prepared
            .as_ref()
            .filter(|job| job.generation == generation)
            .cloned()
            .ok_or(BackendError::GenerationNotPrepared)?;
        self.start_worker(job)?;
        self.active_generation = Some(generation);
        Ok(())
    }

    fn cancel_job(&mut self, generation: u64) -> Result<(), BackendError> {
        if self.active_generation == Some(generation) {
            self.stop_worker();
            self.active_generation = None;
        }
        if self.prepared.as_ref().map(|job| job.generation) == Some(generation) {
            self.prepared = None;
        }
        Ok(())
    }

    fn poll_events(&mut self, output: &mut dyn FnMut(DeviceEvent)) -> Result<(), BackendError> {
        let Some(worker) = &self.worker else {
            return Ok(());
        };
        loop {
            match worker.events.try_recv() {
                Ok(event) => output(event),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return Ok(()),
            }
        }
    }
}

fn run_cpu_worker(
    job: &PreparedDeviceJob,
    thread_index: usize,
    thread_count: usize,
    cancel: &AtomicBool,
    remaining: &AtomicUsize,
    sender: &SyncSender<DeviceEvent>,
) {
    if thread_index == 0
        && !send_cpu_event(
            sender,
            cancel,
            DeviceEvent::JobAcknowledged {
                generation: job.generation,
                observed_at_ms: unix_time_ms(),
            },
        )
    {
        return;
    }

    let base_stride = u64::from(job.nonce_stride);
    let partition_stride = base_stride.saturating_mul(thread_count as u64);
    let partition_offset = base_stride.saturating_mul(thread_index as u64);
    let mut extra_nonce = job.extra_nonce_start;
    let mut hashes_since_report = 0u64;
    let mut report_started = Instant::now();

    'extra_nonce: loop {
        let header = MinerHeader {
            nonce: job.nonce_start,
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
        let hasher = header.prepare_hasher();
        let mut nonce_cursor = u64::from(job.nonce_start).saturating_add(partition_offset);
        while nonce_cursor <= u64::from(job.nonce_end) {
            if cancel.load(Ordering::Acquire) {
                return;
            }
            let nonce = nonce_cursor as u32;
            let raw_share_hash = hasher.share_hash(nonce);
            hashes_since_report = hashes_since_report.saturating_add(1);
            if raw_share_hash <= job.edge_target.0
                && !send_cpu_event(
                    sender,
                    cancel,
                    DeviceEvent::Capture {
                        generation: job.generation,
                        nonce,
                        ntime: job.ntime,
                        extra_nonce,
                        raw_share_hash,
                        received_at_ms: unix_time_ms(),
                    },
                )
            {
                return;
            }
            let elapsed = report_started.elapsed();
            if elapsed >= Duration::from_secs(1) {
                let nanos = elapsed.as_nanos().max(1);
                let rate = u128::from(hashes_since_report)
                    .saturating_mul(1_000_000_000)
                    .checked_div(nanos)
                    .and_then(|value| u64::try_from(value).ok())
                    .unwrap_or(u64::MAX);
                let _ = sender.try_send(DeviceEvent::Telemetry {
                    generation: job.generation,
                    hashes_reported: Some(rate),
                    temperature_millicelsius: None,
                    power_millijoules: None,
                });
                hashes_since_report = 0;
                report_started = Instant::now();
            }
            let Some(next) = nonce_cursor.checked_add(partition_stride) else {
                break;
            };
            nonce_cursor = next;
        }
        if extra_nonce == job.extra_nonce_end {
            break 'extra_nonce;
        }
        let Some(next) = next_extra_nonce(extra_nonce, job.extra_nonce_end) else {
            return;
        };
        extra_nonce = next;
    }

    if remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
        let _ = send_cpu_event(
            sender,
            cancel,
            DeviceEvent::RangeCompleted {
                generation: job.generation,
                lease_id: job.lease_id,
            },
        );
    }
}

fn next_extra_nonce(current: [u8; 24], end: [u8; 24]) -> Option<[u8; 24]> {
    if current >= end || current[..4] != end[..4] || current[8..] != [0; 16] || end[8..] != [0; 16]
    {
        return None;
    }
    let value = u32::from_be_bytes(current[4..8].try_into().ok()?);
    let value = value.checked_add(1)?;
    let mut next = current;
    next[4..8].copy_from_slice(&value.to_be_bytes());
    (next <= end).then_some(next)
}

fn send_cpu_event(
    sender: &SyncSender<DeviceEvent>,
    cancel: &AtomicBool,
    mut event: DeviceEvent,
) -> bool {
    loop {
        match sender.try_send(event) {
            Ok(()) => return true,
            Err(TrySendError::Full(returned)) => {
                if cancel.load(Ordering::Acquire) {
                    return false;
                }
                event = returned;
                thread::yield_now();
            }
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

/// Deterministic reference backend used to test coordination semantics without
/// claiming production hashrate or physical range completion.
pub struct SimulatedBackend {
    capabilities: DeviceCapabilities,
    prepared: Option<PreparedDeviceJob>,
    active_generation: Option<u64>,
    events: VecDeque<DeviceEvent>,
    maximum_events: usize,
}

impl SimulatedBackend {
    pub fn new(
        capabilities: DeviceCapabilities,
        maximum_events: usize,
    ) -> Result<Self, BackendError> {
        capabilities
            .validate()
            .map_err(|_| BackendError::InvalidCapabilities)?;
        if maximum_events == 0 {
            return Err(BackendError::EventCapacity);
        }
        Ok(Self {
            capabilities,
            prepared: None,
            active_generation: None,
            events: VecDeque::new(),
            maximum_events,
        })
    }

    pub fn push_event(&mut self, event: DeviceEvent) -> Result<(), BackendError> {
        if self.events.len() >= self.maximum_events {
            return Err(BackendError::EventCapacity);
        }
        self.events.push_back(event);
        Ok(())
    }

    pub fn active_job(&self) -> Option<&PreparedDeviceJob> {
        self.prepared
            .as_ref()
            .filter(|job| Some(job.generation) == self.active_generation)
    }
}

impl MiningBackend for SimulatedBackend {
    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }

    fn prepare_job(&mut self, job: &PreparedDeviceJob) -> Result<(), BackendError> {
        if self
            .prepared
            .as_ref()
            .is_some_and(|current| current.generation == job.generation && current != job)
        {
            return Err(BackendError::ConflictingPreparedJob);
        }
        self.prepared = Some(job.clone());
        Ok(())
    }

    fn activate_job(&mut self, generation: u64) -> Result<(), BackendError> {
        if self.prepared.as_ref().map(|job| job.generation) != Some(generation) {
            return Err(BackendError::GenerationNotPrepared);
        }
        self.active_generation = Some(generation);
        Ok(())
    }

    fn cancel_job(&mut self, generation: u64) -> Result<(), BackendError> {
        if self.active_generation == Some(generation) {
            self.active_generation = None;
        }
        if self.prepared.as_ref().map(|job| job.generation) == Some(generation) {
            self.prepared = None;
        }
        Ok(())
    }

    fn poll_events(&mut self, output: &mut dyn FnMut(DeviceEvent)) -> Result<(), BackendError> {
        while let Some(event) = self.events.pop_front() {
            output(event);
        }
        Ok(())
    }
}

/// Driver boundary for the existing HandyStratum gateway service. The driver
/// owns socket/session details; this adapter owns MeshMine generation and
/// capability semantics. Stock ASICs never gain range-completion authority.
pub trait HandyStratumDriver: Send {
    fn install_job(&mut self, job: &PreparedDeviceJob) -> Result<(), String>;
    fn activate_job(&mut self, generation: u64) -> Result<(), String>;
    fn cancel_job(&mut self, generation: u64) -> Result<(), String>;
    fn poll_events(&mut self, output: &mut dyn FnMut(DeviceEvent)) -> Result<(), String>;
}

pub struct HandyStratumBackend<D> {
    capabilities: DeviceCapabilities,
    driver: D,
    prepared_generation: Option<u64>,
    active_generation: Option<u64>,
}

impl<D: HandyStratumDriver> HandyStratumBackend<D> {
    pub fn new(capabilities: DeviceCapabilities, driver: D) -> Result<Self, BackendError> {
        capabilities
            .validate()
            .map_err(|_| BackendError::InvalidCapabilities)?;
        if capabilities.backend_kind != crate::BackendKind::HandyStratum
            || capabilities.reports_range_completion
            || !capabilities.supports_extra_nonce_range
        {
            return Err(BackendError::InvalidCapabilities);
        }
        Ok(Self {
            capabilities,
            driver,
            prepared_generation: None,
            active_generation: None,
        })
    }

    pub fn driver(&self) -> &D {
        &self.driver
    }
}

impl<D: HandyStratumDriver> MiningBackend for HandyStratumBackend<D> {
    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }

    fn prepare_job(&mut self, job: &PreparedDeviceJob) -> Result<(), BackendError> {
        // Stock protocols have no universal PREPARE command. The driver may
        // cache the translated job, but must not activate it until requested.
        self.driver
            .install_job(job)
            .map_err(BackendError::Operation)?;
        self.prepared_generation = Some(job.generation);
        Ok(())
    }

    fn activate_job(&mut self, generation: u64) -> Result<(), BackendError> {
        if self.prepared_generation != Some(generation) {
            return Err(BackendError::GenerationNotPrepared);
        }
        self.driver
            .activate_job(generation)
            .map_err(BackendError::Operation)?;
        self.active_generation = Some(generation);
        Ok(())
    }

    fn cancel_job(&mut self, generation: u64) -> Result<(), BackendError> {
        self.driver
            .cancel_job(generation)
            .map_err(BackendError::Operation)?;
        if self.active_generation == Some(generation) {
            self.active_generation = None;
        }
        if self.prepared_generation == Some(generation) {
            self.prepared_generation = None;
        }
        Ok(())
    }

    fn poll_events(&mut self, output: &mut dyn FnMut(DeviceEvent)) -> Result<(), BackendError> {
        self.driver
            .poll_events(output)
            .map_err(BackendError::Operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshmine_types::U256;
    use std::{collections::BTreeSet, time::Duration};

    fn cpu_capabilities() -> DeviceCapabilities {
        DeviceCapabilities {
            device_id: [0x44; 32],
            backend_kind: BackendKind::Arm64Cpu,
            supports_nonce_range: true,
            supports_nonce_stride: true,
            supports_extra_nonce_range: true,
            supports_ntime_rolling: false,
            supports_job_prepare: true,
            reports_range_completion: true,
            minimum_device_target: U256([0; 32]),
            maximum_job_rate_hz: 100,
            preferred_batch_size: 32,
            measured_hashrate: None,
            telemetry_level: 1,
        }
    }

    fn prepared_job() -> PreparedDeviceJob {
        PreparedDeviceJob {
            protocol_version: crate::WORK_PROTOCOL_VERSION,
            job_id: [1; 32],
            assignment_id: [2; 32],
            lease_id: [3; 32],
            generation: 7,
            previous_block: [4; 32],
            merkle_root: [5; 32],
            witness_root: [6; 32],
            tree_root: [7; 32],
            reserved_root: [8; 32],
            version: 9,
            bits: 0x207f_ffff,
            ntime: 1_717_171_717,
            mask_hash: [10; 32],
            extra_nonce_start: [11; 24],
            extra_nonce_end: [11; 24],
            nonce_start: 100,
            nonce_end: 131,
            nonce_stride: 1,
            edge_target: U256([0xff; 32]),
            capture_target: U256([0xff; 32]),
        }
    }

    #[test]
    fn cpu_backend_hashes_disjoint_parallel_nonce_ranges() {
        let job = prepared_job();
        let mut backend = CpuBackend::new(cpu_capabilities(), 2, 64).unwrap();
        backend.prepare_job(&job).unwrap();
        backend.activate_job(job.generation).unwrap();
        assert_eq!(backend.active_threads(), 2);

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut captures = BTreeSet::new();
        let mut completed = false;
        while Instant::now() < deadline && !completed {
            backend
                .poll_events(&mut |event| match event {
                    DeviceEvent::Capture {
                        nonce,
                        raw_share_hash,
                        ..
                    } => {
                        let header = MinerHeader {
                            nonce,
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
                        assert_eq!(raw_share_hash, header.share_hash());
                        assert!(captures.insert(nonce));
                    }
                    DeviceEvent::RangeCompleted {
                        generation,
                        lease_id,
                    } => {
                        assert_eq!(generation, job.generation);
                        assert_eq!(lease_id, job.lease_id);
                        completed = true;
                    }
                    _ => {}
                })
                .unwrap();
            thread::sleep(Duration::from_millis(1));
        }
        assert!(completed);
        assert_eq!(captures, (100..=131).collect());
        backend.cancel_job(job.generation).unwrap();
        assert_eq!(backend.active_threads(), 0);
    }
}
