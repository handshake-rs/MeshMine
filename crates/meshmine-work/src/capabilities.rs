use meshmine_types::U256;
use thiserror::Error;

pub type DeviceId = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BackendKind {
    HandyStratum = 1,
    NativeWorker = 2,
    ExternalProcess = 3,
    Cuda = 4,
    Rocm = 5,
    Arm64Cpu = 6,
    X86Cpu = 7,
    Vulkan = 8,
    Simulator = 255,
}

impl BackendKind {
    pub fn from_u8(value: u8) -> Result<Self, CapabilityError> {
        match value {
            1 => Ok(Self::HandyStratum),
            2 => Ok(Self::NativeWorker),
            3 => Ok(Self::ExternalProcess),
            4 => Ok(Self::Cuda),
            5 => Ok(Self::Rocm),
            6 => Ok(Self::Arm64Cpu),
            7 => Ok(Self::X86Cpu),
            8 => Ok(Self::Vulkan),
            255 => Ok(Self::Simulator),
            _ => Err(CapabilityError::UnknownBackendKind(value)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCapabilities {
    pub device_id: DeviceId,
    pub backend_kind: BackendKind,
    pub supports_nonce_range: bool,
    pub supports_nonce_stride: bool,
    pub supports_extra_nonce_range: bool,
    pub supports_ntime_rolling: bool,
    pub supports_job_prepare: bool,
    pub reports_range_completion: bool,
    pub minimum_device_target: U256,
    pub maximum_job_rate_hz: u32,
    pub preferred_batch_size: u64,
    pub measured_hashrate: Option<u64>,
    pub telemetry_level: u8,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("device identifier is all zeroes")]
    ZeroDeviceId,
    #[error("maximum job rate must be non-zero")]
    ZeroJobRate,
    #[error("preferred batch size must be non-zero")]
    ZeroBatchSize,
    #[error("range completion is claimed without programmable nonce ranges")]
    InvalidRangeCompletionClaim,
    #[error("nonce stride support is claimed without nonce range support")]
    StrideWithoutRange,
    #[error("unknown backend kind {0}")]
    UnknownBackendKind(u8),
}

impl DeviceCapabilities {
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.device_id == [0; 32] {
            return Err(CapabilityError::ZeroDeviceId);
        }
        if self.maximum_job_rate_hz == 0 {
            return Err(CapabilityError::ZeroJobRate);
        }
        if self.preferred_batch_size == 0 {
            return Err(CapabilityError::ZeroBatchSize);
        }
        if self.supports_nonce_stride && !self.supports_nonce_range {
            return Err(CapabilityError::StrideWithoutRange);
        }
        if self.reports_range_completion && !self.supports_nonce_range {
            return Err(CapabilityError::InvalidRangeCompletionClaim);
        }
        Ok(())
    }

    pub fn is_stock_asic(&self) -> bool {
        self.backend_kind == BackendKind::HandyStratum && !self.reports_range_completion
    }

    /// Compare the durable hardware/protocol contract while allowing the
    /// coordinator to refresh its locally measured hashrate. Measured rate is
    /// observational scheduling input, not a device-owned capability.
    pub fn same_static_contract(&self, other: &Self) -> bool {
        self.device_id == other.device_id
            && self.backend_kind == other.backend_kind
            && self.supports_nonce_range == other.supports_nonce_range
            && self.supports_nonce_stride == other.supports_nonce_stride
            && self.supports_extra_nonce_range == other.supports_extra_nonce_range
            && self.supports_ntime_rolling == other.supports_ntime_rolling
            && self.supports_job_prepare == other.supports_job_prepare
            && self.reports_range_completion == other.reports_range_completion
            && self.minimum_device_target == other.minimum_device_target
            && self.maximum_job_rate_hz == other.maximum_job_rate_hz
            && self.preferred_batch_size == other.preferred_batch_size
            && self.telemetry_level == other.telemetry_level
    }
}
