use std::collections::VecDeque;

use meshmine_hns::Hash256;
use thiserror::Error;

use crate::{DeviceCapabilities, PreparedDeviceJob};

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
