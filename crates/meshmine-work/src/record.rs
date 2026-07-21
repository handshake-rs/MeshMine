use meshmine_codec::{
    CanonicalDecode, CanonicalEncode, CodecError, DecodeLimits, Decoder, Encoder,
};
use meshmine_hns::Hash256;
use meshmine_types::{U256, domain_hash};

use crate::{BackendKind, DeviceCapabilities, WORK_PROTOCOL_VERSION, WorkLease};

pub const WORK_SCHEMA_VERSION: u16 = 2;
pub const WORK_SCHEMA_NAMESPACE: &str = "work-schema";
pub const WORK_SCHEMA_KEY: &str = "version";
pub const DEVICE_NAMESPACE: &str = "work-device-v1";
pub const LEASE_NAMESPACE: &str = "work-lease-v1";
pub const ACTIVE_LEASE_NAMESPACE: &str = "work-active-lease-v1";
pub const CURSOR_NAMESPACE: &str = "work-cursor-v1";
pub const CAPTURE_NAMESPACE: &str = "work-capture-v2";
pub const CAPTURE_TOMBSTONE_NAMESPACE: &str = "work-capture-tombstone-v2";
pub const GENERATION_NAMESPACE: &str = "work-generation-v1";
pub const LEASE_JOB_NAMESPACE: &str = "work-lease-job-v1";
pub const CAPTURE_DOMAIN: &str = "MESHMINE/WORK_CAPTURE/V2";
pub const EXCLUSIVE_NAMESPACE: &str = "work-exclusive-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureRecord {
    pub version: u16,
    pub capture_id: Hash256,
    pub lease_id: Hash256,
    pub assignment_id: Hash256,
    pub device_id: Hash256,
    pub generation: u64,
    pub nonce: u32,
    pub ntime: u64,
    pub extra_nonce: [u8; 24],
    pub raw_share_hash: Hash256,
    pub received_at_ms: u64,
}

impl CaptureRecord {
    pub fn canonical_id(&self) -> Hash256 {
        let mut encoder = Encoder::new();
        encoder.u16(self.version);
        encoder.fixed(&self.lease_id);
        encoder.fixed(&self.assignment_id);
        encoder.fixed(&self.device_id);
        encoder.u64(self.generation);
        encoder.u32(self.nonce);
        encoder.u64(self.ntime);
        encoder.fixed(&self.extra_nonce);
        encoder.fixed(&self.raw_share_hash);
        // Receipt time is local observation metadata, not work identity. A
        // repeated submission of the same authorized work must retain the same
        // durable identifier even when it arrives at a different millisecond.
        domain_hash(CAPTURE_DOMAIN, encoder.as_bytes())
    }
}

impl CanonicalEncode for DeviceCapabilities {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.fixed(&self.device_id);
        encoder.u8(self.backend_kind as u8);
        encoder.u8(u8::from(self.supports_nonce_range));
        encoder.u8(u8::from(self.supports_nonce_stride));
        encoder.u8(u8::from(self.supports_extra_nonce_range));
        encoder.u8(u8::from(self.supports_ntime_rolling));
        encoder.u8(u8::from(self.supports_job_prepare));
        encoder.u8(u8::from(self.reports_range_completion));
        encoder.fixed(&self.minimum_device_target.0);
        encoder.u32(self.maximum_job_rate_hz);
        encoder.u64(self.preferred_batch_size);
        match self.measured_hashrate {
            None => encoder.u8(0),
            Some(value) => {
                encoder.u8(1);
                encoder.u64(value);
            }
        }
        encoder.u8(self.telemetry_level);
    }
}

impl CanonicalDecode for DeviceCapabilities {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let value = Self {
            device_id: decoder.array()?,
            backend_kind: BackendKind::from_u8(decoder.u8()?)
                .map_err(|_| CodecError::InvalidField("backend_kind"))?,
            supports_nonce_range: bool_value(decoder.u8()?)?,
            supports_nonce_stride: bool_value(decoder.u8()?)?,
            supports_extra_nonce_range: bool_value(decoder.u8()?)?,
            supports_ntime_rolling: bool_value(decoder.u8()?)?,
            supports_job_prepare: bool_value(decoder.u8()?)?,
            reports_range_completion: bool_value(decoder.u8()?)?,
            minimum_device_target: U256(decoder.array()?),
            maximum_job_rate_hz: decoder.u32()?,
            preferred_batch_size: decoder.u64()?,
            measured_hashrate: match decoder.u8()? {
                0 => None,
                1 => Some(decoder.u64()?),
                _ => return Err(CodecError::InvalidField("measured_hashrate")),
            },
            telemetry_level: decoder.u8()?,
        };
        value
            .validate()
            .map_err(|_| CodecError::InvalidField("device_capabilities"))?;
        Ok(value)
    }
}

impl CanonicalEncode for WorkLease {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.protocol_version);
        encoder.fixed(&self.lease_id);
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
    }
}

impl CanonicalDecode for WorkLease {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let value = Self {
            protocol_version: decoder.u16()?,
            lease_id: decoder.array()?,
            assignment_id: decoder.array()?,
            assignment_sequence: decoder.u64()?,
            job_generation: decoder.u64()?,
            device_id: decoder.array()?,
            extra_nonce_profile: decoder.u16()?,
            extra_nonce_start: decoder.array()?,
            extra_nonce_end: decoder.array()?,
            nonce_start: decoder.u32()?,
            nonce_end: decoder.u32()?,
            nonce_stride: decoder.u32()?,
            edge_target: U256(decoder.array()?),
            capture_target: U256(decoder.array()?),
            activated_at_ms: decoder.u64()?,
            expires_at_ms: match decoder.u8()? {
                0 => None,
                1 => Some(decoder.u64()?),
                _ => return Err(CodecError::InvalidField("expires_at_ms")),
            },
            completion_report_allowed: bool_value(decoder.u8()?)?,
        };
        if value.protocol_version != WORK_PROTOCOL_VERSION || value.canonical_id() != value.lease_id
        {
            return Err(CodecError::InvalidField("work_lease"));
        }
        Ok(value)
    }
}

impl CanonicalEncode for CaptureRecord {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.version);
        encoder.fixed(&self.capture_id);
        encoder.fixed(&self.lease_id);
        encoder.fixed(&self.assignment_id);
        encoder.fixed(&self.device_id);
        encoder.u64(self.generation);
        encoder.u32(self.nonce);
        encoder.u64(self.ntime);
        encoder.fixed(&self.extra_nonce);
        encoder.fixed(&self.raw_share_hash);
        encoder.u64(self.received_at_ms);
    }
}

impl CanonicalDecode for CaptureRecord {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let value = Self {
            version: decoder.u16()?,
            capture_id: decoder.array()?,
            lease_id: decoder.array()?,
            assignment_id: decoder.array()?,
            device_id: decoder.array()?,
            generation: decoder.u64()?,
            nonce: decoder.u32()?,
            ntime: decoder.u64()?,
            extra_nonce: decoder.array()?,
            raw_share_hash: decoder.array()?,
            received_at_ms: decoder.u64()?,
        };
        if value.version != WORK_SCHEMA_VERSION || value.canonical_id() != value.capture_id {
            return Err(CodecError::InvalidField("capture_record"));
        }
        Ok(value)
    }
}

pub fn decode_capabilities(bytes: &[u8]) -> Result<DeviceCapabilities, CodecError> {
    DeviceCapabilities::from_canonical_bytes(bytes, DecodeLimits::default())
}

pub fn decode_lease(bytes: &[u8]) -> Result<WorkLease, CodecError> {
    WorkLease::from_canonical_bytes(bytes, DecodeLimits::default())
}

fn bool_value(value: u8) -> Result<bool, CodecError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(CodecError::InvalidField("boolean")),
    }
}

pub const JOB_NAMESPACE: &str = "work-job-v1";

impl CanonicalEncode for crate::PreparedDeviceJob {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.protocol_version);
        encoder.fixed(&self.job_id);
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
    }
}

impl CanonicalDecode for crate::PreparedDeviceJob {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let value = Self {
            protocol_version: decoder.u16()?,
            job_id: decoder.array()?,
            assignment_id: decoder.array()?,
            lease_id: decoder.array()?,
            generation: decoder.u64()?,
            previous_block: decoder.array()?,
            merkle_root: decoder.array()?,
            witness_root: decoder.array()?,
            tree_root: decoder.array()?,
            reserved_root: decoder.array()?,
            version: decoder.u32()?,
            bits: decoder.u32()?,
            ntime: decoder.u64()?,
            mask_hash: decoder.array()?,
            extra_nonce_start: decoder.array()?,
            extra_nonce_end: decoder.array()?,
            nonce_start: decoder.u32()?,
            nonce_end: decoder.u32()?,
            nonce_stride: decoder.u32()?,
            edge_target: U256(decoder.array()?),
            capture_target: U256(decoder.array()?),
        };
        if value.protocol_version != WORK_PROTOCOL_VERSION || value.canonical_id() != value.job_id {
            return Err(CodecError::InvalidField("prepared_device_job"));
        }
        Ok(value)
    }
}
