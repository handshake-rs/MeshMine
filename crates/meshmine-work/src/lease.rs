use meshmine_codec::Encoder;
use meshmine_hns::{Hash256, blake2b_256};
use meshmine_types::{
    AssignmentV2, GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16, GatewayAssignmentV1,
    U256, UnsignedObject, domain_hash,
};
use thiserror::Error;

use crate::{DeviceCapabilities, DeviceId};

pub const WORK_PROTOCOL_VERSION: u16 = 1;
pub const WORK_LEASE_DOMAIN: &str = "MESHMINE/WORK_LEASE/V1";
pub const PREPARED_DEVICE_JOB_DOMAIN: &str = "MESHMINE/PREPARED_DEVICE_JOB/V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeKind {
    AssignmentV2,
    GatewayAssignmentV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkEnvelope {
    pub kind: EnvelopeKind,
    pub assignment_id: Hash256,
    pub assignment_sequence: u64,
    pub job_generation: u64,
    pub worker_id_hash: Hash256,
    pub ntime: u64,
    pub extra_nonce_profile: u16,
    pub extra_nonce_start: [u8; 24],
    pub extra_nonce_end: [u8; 24],
    pub nonce_start: u32,
    pub nonce_end: u32,
    pub nonce_stride: u32,
    pub edge_target: U256,
    pub capture_target: U256,
    pub telemetry_level: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkLease {
    pub protocol_version: u16,
    pub lease_id: Hash256,
    pub assignment_id: Hash256,
    pub assignment_sequence: u64,
    pub job_generation: u64,
    pub device_id: DeviceId,
    pub extra_nonce_profile: u16,
    pub extra_nonce_start: [u8; 24],
    pub extra_nonce_end: [u8; 24],
    pub nonce_start: u32,
    pub nonce_end: u32,
    pub nonce_stride: u32,
    pub edge_target: U256,
    pub capture_target: U256,
    pub activated_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub completion_report_allowed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedDeviceJob {
    pub protocol_version: u16,
    pub job_id: Hash256,
    pub assignment_id: Hash256,
    pub lease_id: Hash256,
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
    pub extra_nonce_start: [u8; 24],
    pub extra_nonce_end: [u8; 24],
    pub nonce_start: u32,
    pub nonce_end: u32,
    pub nonce_stride: u32,
    pub edge_target: U256,
    pub capture_target: U256,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LeaseError {
    #[error("assignment has an invalid nonce range or zero stride")]
    InvalidNonceRange,
    #[error("gateway assignment has an invalid extra-nonce range")]
    InvalidExtraNonceRange,
    #[error("gateway assignment uses an unsupported extra-nonce profile")]
    InvalidExtraNonceProfile,
    #[error("device target is harder than the capture target")]
    DeviceTargetTooHard,
    #[error("lease expands beyond its signed assignment envelope")]
    LeaseOutsideEnvelope,
    #[error("lease requires a capability the device does not advertise")]
    UnsupportedLease,
    #[error("lease identifier does not match its canonical body")]
    InvalidLeaseId,
    #[error("prepared device job identifier does not match its canonical body")]
    InvalidJobId,
    #[error("prepared job does not match its lease")]
    JobLeaseMismatch,
}

impl WorkEnvelope {
    pub fn from_assignment(value: &AssignmentV2, generation: u64) -> Result<Self, LeaseError> {
        validate_targets(&value.edge_target, &value.capture_target)?;
        validate_nonce_range(value.nonce_start, value.nonce_end, value.nonce_stride)?;
        Ok(Self {
            kind: EnvelopeKind::AssignmentV2,
            assignment_id: value.object_id(),
            assignment_sequence: value.assignment_sequence,
            job_generation: generation,
            worker_id_hash: value.worker_id_hash,
            ntime: value.ntime,
            extra_nonce_profile: 0,
            extra_nonce_start: value.extra_nonce,
            extra_nonce_end: value.extra_nonce,
            nonce_start: value.nonce_start,
            nonce_end: value.nonce_end,
            nonce_stride: value.nonce_stride,
            edge_target: value.edge_target,
            capture_target: value.capture_target,
            telemetry_level: value.telemetry_level,
        })
    }

    pub fn from_gateway_assignment(
        value: &GatewayAssignmentV1,
        generation: u64,
    ) -> Result<Self, LeaseError> {
        validate_targets(&value.edge_target, &value.capture_target)?;
        validate_nonce_range(value.nonce_start, value.nonce_end, value.nonce_stride)?;
        if value.extra_nonce_profile != GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16 {
            return Err(LeaseError::InvalidExtraNonceProfile);
        }
        if value.extra_nonce2_start_be > value.extra_nonce2_end_be {
            return Err(LeaseError::InvalidExtraNonceRange);
        }
        let start = gateway_extra_nonce(value.extra_nonce_prefix, value.extra_nonce2_start_be);
        let end = gateway_extra_nonce(value.extra_nonce_prefix, value.extra_nonce2_end_be);
        Ok(Self {
            kind: EnvelopeKind::GatewayAssignmentV1,
            assignment_id: value.object_id(),
            assignment_sequence: value.assignment_sequence,
            job_generation: generation,
            worker_id_hash: value.worker_id_hash,
            ntime: value.ntime,
            extra_nonce_profile: value.extra_nonce_profile,
            extra_nonce_start: start,
            extra_nonce_end: end,
            nonce_start: value.nonce_start,
            nonce_end: value.nonce_end,
            nonce_stride: value.nonce_stride,
            edge_target: value.edge_target,
            capture_target: value.capture_target,
            telemetry_level: value.telemetry_level,
        })
    }

    pub fn validate_lease(
        &self,
        lease: &WorkLease,
        capabilities: &DeviceCapabilities,
    ) -> Result<(), LeaseError> {
        if lease.protocol_version != WORK_PROTOCOL_VERSION
            || lease.assignment_id != self.assignment_id
            || lease.assignment_sequence != self.assignment_sequence
            || lease.job_generation != self.job_generation
            || lease.extra_nonce_profile != self.extra_nonce_profile
            || lease.extra_nonce_start < self.extra_nonce_start
            || lease.extra_nonce_end > self.extra_nonce_end
            || lease.extra_nonce_start > lease.extra_nonce_end
            || lease.nonce_start < self.nonce_start
            || lease.nonce_end > self.nonce_end
            || lease.nonce_start > lease.nonce_end
            || self.nonce_stride == 0
            || lease.nonce_stride == 0
            || lease.nonce_stride % self.nonce_stride != 0
            || lease.nonce_start.saturating_sub(self.nonce_start) % self.nonce_stride != 0
            || lease.edge_target.0 > self.edge_target.0
            || lease.edge_target.0 < self.capture_target.0
            || lease.capture_target != self.capture_target
        {
            return Err(LeaseError::LeaseOutsideEnvelope);
        }
        if lease.extra_nonce_start != lease.extra_nonce_end
            && !capabilities.supports_extra_nonce_range
        {
            return Err(LeaseError::UnsupportedLease);
        }
        if (lease.nonce_start != self.nonce_start
            || lease.nonce_end != self.nonce_end
            || lease.nonce_stride != self.nonce_stride)
            && !capabilities.supports_nonce_range
        {
            return Err(LeaseError::UnsupportedLease);
        }
        if lease.nonce_stride != self.nonce_stride && !capabilities.supports_nonce_stride {
            return Err(LeaseError::UnsupportedLease);
        }
        if lease.completion_report_allowed != capabilities.reports_range_completion
            || lease.edge_target.0 < capabilities.minimum_device_target.0
        {
            return Err(LeaseError::UnsupportedLease);
        }
        validate_targets(&lease.edge_target, &lease.capture_target)?;
        if lease.canonical_id() != lease.lease_id {
            return Err(LeaseError::InvalidLeaseId);
        }
        Ok(())
    }
}

impl WorkLease {
    pub fn canonical_id(&self) -> Hash256 {
        domain_hash(WORK_LEASE_DOMAIN, &self.canonical_body())
    }

    pub fn accepts_extra_nonce(&self, extra_nonce: &[u8; 24]) -> bool {
        if extra_nonce < &self.extra_nonce_start || extra_nonce > &self.extra_nonce_end {
            return false;
        }
        match self.extra_nonce_profile {
            0 => {
                self.extra_nonce_start == self.extra_nonce_end
                    && *extra_nonce == self.extra_nonce_start
            }
            GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16 => {
                extra_nonce[..4] == self.extra_nonce_start[..4]
                    && extra_nonce[..4] == self.extra_nonce_end[..4]
                    && extra_nonce[8..].iter().all(|byte| *byte == 0)
            }
            _ => false,
        }
    }

    pub fn canonical_body(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.u16(self.protocol_version);
        encoder.fixed(&self.assignment_id);
        encoder.u64(self.assignment_sequence);
        encoder.u64(self.job_generation);
        encoder.fixed(&self.device_id);
        encoder.u16(self.extra_nonce_profile);
        encoder.fixed(&self.extra_nonce_start);
        encoder.fixed(&self.extra_nonce_end);
        encoder.u32(self.nonce_start);
        encoder.u32(self.nonce_end);
        encoder.u32(self.nonce_stride);
        encoder.fixed(&self.edge_target.0);
        encoder.fixed(&self.capture_target.0);
        encoder.u64(self.activated_at_ms);
        match self.expires_at_ms {
            None => encoder.u8(0),
            Some(value) => {
                encoder.u8(1);
                encoder.u64(value);
            }
        }
        encoder.u8(u8::from(self.completion_report_allowed));
        encoder.into_bytes()
    }
}

impl PreparedDeviceJob {
    pub fn canonical_id(&self) -> Hash256 {
        domain_hash(PREPARED_DEVICE_JOB_DOMAIN, &self.canonical_body())
    }

    pub fn canonical_body(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.u16(self.protocol_version);
        encoder.fixed(&self.assignment_id);
        encoder.fixed(&self.lease_id);
        encoder.u64(self.generation);
        encoder.fixed(&self.previous_block);
        encoder.fixed(&self.merkle_root);
        encoder.fixed(&self.witness_root);
        encoder.fixed(&self.tree_root);
        encoder.fixed(&self.reserved_root);
        encoder.u32(self.version);
        encoder.u32(self.bits);
        encoder.u64(self.ntime);
        encoder.fixed(&self.mask_hash);
        encoder.fixed(&self.extra_nonce_start);
        encoder.fixed(&self.extra_nonce_end);
        encoder.u32(self.nonce_start);
        encoder.u32(self.nonce_end);
        encoder.u32(self.nonce_stride);
        encoder.fixed(&self.edge_target.0);
        encoder.fixed(&self.capture_target.0);
        encoder.into_bytes()
    }

    pub fn validate_against_lease(&self, lease: &WorkLease) -> Result<(), LeaseError> {
        if self.protocol_version != WORK_PROTOCOL_VERSION
            || self.assignment_id != lease.assignment_id
            || self.lease_id != lease.lease_id
            || self.generation != lease.job_generation
            || self.ntime == 0
            || self.extra_nonce_start != lease.extra_nonce_start
            || self.extra_nonce_end != lease.extra_nonce_end
            || self.nonce_start != lease.nonce_start
            || self.nonce_end != lease.nonce_end
            || self.nonce_stride != lease.nonce_stride
            || self.edge_target != lease.edge_target
            || self.capture_target != lease.capture_target
        {
            return Err(LeaseError::JobLeaseMismatch);
        }
        if self.canonical_id() != self.job_id {
            return Err(LeaseError::InvalidJobId);
        }
        Ok(())
    }
}

pub fn gateway_extra_nonce(prefix: [u8; 4], extra_nonce2: [u8; 4]) -> [u8; 24] {
    let mut value = [0; 24];
    value[..4].copy_from_slice(&prefix);
    value[4..8].copy_from_slice(&extra_nonce2);
    value
}

pub fn extra_nonce2(value: &[u8; 24]) -> Option<u32> {
    if value[8..].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(u32::from_be_bytes(value[4..8].try_into().ok()?))
}

pub fn assignment_fingerprint(envelope: &WorkEnvelope) -> Hash256 {
    let mut encoder = Encoder::new();
    encoder.fixed(&envelope.assignment_id);
    encoder.u64(envelope.job_generation);
    encoder.u16(envelope.extra_nonce_profile);
    encoder.fixed(&envelope.extra_nonce_start);
    encoder.fixed(&envelope.extra_nonce_end);
    encoder.u32(envelope.nonce_start);
    encoder.u32(envelope.nonce_end);
    encoder.u32(envelope.nonce_stride);
    blake2b_256(&[encoder.as_bytes()])
}

fn validate_targets(edge: &U256, capture: &U256) -> Result<(), LeaseError> {
    if edge.0 < capture.0 {
        return Err(LeaseError::DeviceTargetTooHard);
    }
    Ok(())
}

fn validate_nonce_range(start: u32, end: u32, stride: u32) -> Result<(), LeaseError> {
    if start > end || stride == 0 {
        return Err(LeaseError::InvalidNonceRange);
    }
    Ok(())
}
