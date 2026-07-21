use std::sync::Arc;

use meshmine_codec::{CanonicalDecode, CanonicalEncode, DecodeLimits};
use meshmine_storage::{BatchCondition, BatchOperation, DurableStore, StorageError};
use thiserror::Error;

use crate::{
    ACTIVE_LEASE_NAMESPACE, CURSOR_NAMESPACE, DEVICE_NAMESPACE, DeviceCapabilities, DeviceId,
    EXCLUSIVE_NAMESPACE, EnvelopeKind, LEASE_NAMESPACE, LeaseError, WORK_PROTOCOL_VERSION,
    WORK_SCHEMA_KEY, WORK_SCHEMA_NAMESPACE, WORK_SCHEMA_VERSION, WorkEnvelope, WorkLease,
    decode_lease, extra_nonce2, gateway_extra_nonce,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlannerLimits {
    pub maximum_extra_nonce_values_per_lease: u32,
    pub maximum_nonce_values_per_lease: u64,
    pub target_native_lease_ms: u64,
}

impl Default for PlannerLimits {
    fn default() -> Self {
        Self {
            maximum_extra_nonce_values_per_lease: 65_536,
            maximum_nonce_values_per_lease: 16 * 1024 * 1024,
            target_native_lease_ms: 250,
        }
    }
}

#[derive(Debug, Error)]
pub enum PlannerError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Lease(#[from] LeaseError),
    #[error("invalid device capabilities")]
    InvalidCapabilities,
    #[error("work planner schema is missing or incompatible")]
    SchemaMismatch,
    #[error("device already has an active lease for another generation or assignment")]
    DeviceBusy,
    #[error("signed work envelope has no remaining unallocated namespace")]
    EnvelopeExhausted,
    #[error("device cannot safely consume this signed assignment envelope")]
    UnsupportedEnvelope,
    #[error("durable allocation raced another allocator")]
    AllocationRace,
    #[error("durable lease record is corrupt")]
    CorruptLease,
    #[error("range completion was reported by a device that is not allowed to prove it")]
    UnauthorizedCompletion,
    #[error("lease expiry is not later than its durable allocation time")]
    InvalidExpiration,
}

pub struct WorkPlanner {
    store: Arc<dyn DurableStore>,
    limits: PlannerLimits,
}

impl WorkPlanner {
    pub fn open(store: Arc<dyn DurableStore>, limits: PlannerLimits) -> Result<Self, PlannerError> {
        if limits.maximum_extra_nonce_values_per_lease == 0
            || limits.maximum_nonce_values_per_lease == 0
            || limits.target_native_lease_ms == 0
        {
            return Err(PlannerError::UnsupportedEnvelope);
        }
        let expected = WORK_SCHEMA_VERSION.to_le_bytes();
        match store.get(WORK_SCHEMA_NAMESPACE, WORK_SCHEMA_KEY)? {
            Some(value) if value == expected => {}
            Some(_) => return Err(PlannerError::SchemaMismatch),
            None => {
                if !store.compare_and_swap(
                    WORK_SCHEMA_NAMESPACE,
                    WORK_SCHEMA_KEY,
                    None,
                    &expected,
                )? && store
                    .get(WORK_SCHEMA_NAMESPACE, WORK_SCHEMA_KEY)?
                    .as_deref()
                    != Some(expected.as_slice())
                {
                    return Err(PlannerError::SchemaMismatch);
                }
            }
        }
        Ok(Self { store, limits })
    }

    pub fn register_device(&self, capabilities: &DeviceCapabilities) -> Result<(), PlannerError> {
        capabilities
            .validate()
            .map_err(|_| PlannerError::InvalidCapabilities)?;
        let key = hex::encode(capabilities.device_id);
        let bytes = capabilities.to_canonical_bytes();
        match self.store.get(DEVICE_NAMESPACE, &key)? {
            Some(existing) if existing == bytes => Ok(()),
            Some(existing) => {
                let prior = crate::decode_capabilities(&existing)
                    .map_err(|_| PlannerError::InvalidCapabilities)?;
                if !prior.same_static_contract(capabilities) {
                    return Err(PlannerError::InvalidCapabilities);
                }
                if self
                    .store
                    .compare_and_swap(DEVICE_NAMESPACE, &key, Some(&existing), &bytes)?
                    || self.store.get(DEVICE_NAMESPACE, &key)?.as_deref() == Some(bytes.as_slice())
                {
                    Ok(())
                } else {
                    Err(PlannerError::AllocationRace)
                }
            }
            None => {
                if self
                    .store
                    .compare_and_swap(DEVICE_NAMESPACE, &key, None, &bytes)?
                    || self.store.get(DEVICE_NAMESPACE, &key)?.as_deref() == Some(bytes.as_slice())
                {
                    Ok(())
                } else {
                    Err(PlannerError::AllocationRace)
                }
            }
        }
    }

    pub fn allocate(
        &self,
        envelope: &WorkEnvelope,
        capabilities: &DeviceCapabilities,
        now_ms: u64,
        expires_at_ms: Option<u64>,
    ) -> Result<WorkLease, PlannerError> {
        self.allocate_with_edge_target(
            envelope,
            capabilities,
            envelope.edge_target,
            now_ms,
            expires_at_ms,
        )
    }

    pub fn allocate_with_edge_target(
        &self,
        envelope: &WorkEnvelope,
        capabilities: &DeviceCapabilities,
        edge_target: meshmine_types::U256,
        now_ms: u64,
        expires_at_ms: Option<u64>,
    ) -> Result<WorkLease, PlannerError> {
        if expires_at_ms.is_some_and(|expiry| expiry <= now_ms) {
            return Err(PlannerError::InvalidExpiration);
        }
        if edge_target.0 < envelope.capture_target.0
            || edge_target.0 > envelope.edge_target.0
            || edge_target.0 < capabilities.minimum_device_target.0
        {
            return Err(PlannerError::UnsupportedEnvelope);
        }
        self.register_device(capabilities)?;
        let active_key = hex::encode(capabilities.device_id);
        if let Some(existing_id) = self.store.get(ACTIVE_LEASE_NAMESPACE, &active_key)? {
            if existing_id.len() != 32 {
                return Err(PlannerError::CorruptLease);
            }
            let lease_key = hex::encode(&existing_id);
            let bytes = self
                .store
                .get(LEASE_NAMESPACE, &lease_key)?
                .ok_or(PlannerError::CorruptLease)?;
            let lease = decode_lease(&bytes).map_err(|_| PlannerError::CorruptLease)?;
            if lease.expires_at_ms.is_some_and(|expiry| now_ms > expiry) {
                if !self.store.apply_batch_if(
                    ACTIVE_LEASE_NAMESPACE,
                    &active_key,
                    Some(&existing_id),
                    &[BatchOperation::delete(ACTIVE_LEASE_NAMESPACE, &active_key)],
                )? {
                    return Err(PlannerError::AllocationRace);
                }
            } else {
                if lease.assignment_id == envelope.assignment_id
                    && lease.job_generation == envelope.job_generation
                {
                    envelope.validate_lease(&lease, capabilities)?;
                    return Ok(lease);
                }
                return Err(PlannerError::DeviceBusy);
            }
        }

        match envelope.kind {
            EnvelopeKind::GatewayAssignmentV1 => self.allocate_extra_nonce(
                envelope,
                capabilities,
                edge_target,
                now_ms,
                expires_at_ms,
            ),
            EnvelopeKind::AssignmentV2 => {
                self.allocate_nonce(envelope, capabilities, edge_target, now_ms, expires_at_ms)
            }
        }
    }

    pub fn retire(&self, device_id: &DeviceId, lease_id: &[u8; 32]) -> Result<bool, PlannerError> {
        let active_key = hex::encode(device_id);
        self.store
            .apply_batch_if(
                ACTIVE_LEASE_NAMESPACE,
                &active_key,
                Some(lease_id),
                &[BatchOperation::delete(ACTIVE_LEASE_NAMESPACE, &active_key)],
            )
            .map_err(PlannerError::from)
    }

    pub fn complete(
        &self,
        capabilities: &DeviceCapabilities,
        lease_id: &[u8; 32],
    ) -> Result<bool, PlannerError> {
        if !capabilities.reports_range_completion {
            return Err(PlannerError::UnauthorizedCompletion);
        }
        self.retire(&capabilities.device_id, lease_id)
    }

    pub fn active_lease(&self, device_id: &DeviceId) -> Result<Option<WorkLease>, PlannerError> {
        let Some(lease_id) = self
            .store
            .get(ACTIVE_LEASE_NAMESPACE, &hex::encode(device_id))?
        else {
            return Ok(None);
        };
        if lease_id.len() != 32 {
            return Err(PlannerError::CorruptLease);
        }
        let bytes = self
            .store
            .get(LEASE_NAMESPACE, &hex::encode(lease_id))?
            .ok_or(PlannerError::CorruptLease)?;
        WorkLease::from_canonical_bytes(&bytes, DecodeLimits::default())
            .map(Some)
            .map_err(|_| PlannerError::CorruptLease)
    }

    fn allocate_extra_nonce(
        &self,
        envelope: &WorkEnvelope,
        capabilities: &DeviceCapabilities,
        edge_target: meshmine_types::U256,
        now_ms: u64,
        expires_at_ms: Option<u64>,
    ) -> Result<WorkLease, PlannerError> {
        if !capabilities.supports_extra_nonce_range {
            return Err(PlannerError::UnsupportedEnvelope);
        }
        let start =
            extra_nonce2(&envelope.extra_nonce_start).ok_or(PlannerError::UnsupportedEnvelope)?;
        let end =
            extra_nonce2(&envelope.extra_nonce_end).ok_or(PlannerError::UnsupportedEnvelope)?;
        let cursor_key = format!("{}:extra", hex::encode(envelope.assignment_id));
        let cursor_bytes = self.store.get(CURSOR_NAMESPACE, &cursor_key)?;
        let cursor = match decode_cursor(cursor_bytes.as_deref())? {
            CursorState::Unset => u64::from(start),
            CursorState::Next(value) => value,
            CursorState::Exhausted => return Err(PlannerError::EnvelopeExhausted),
        };
        if cursor < u64::from(start) || cursor > u64::from(end) {
            return Err(PlannerError::EnvelopeExhausted);
        }
        let cursor = u32::try_from(cursor).map_err(|_| PlannerError::EnvelopeExhausted)?;
        let requested = u32::try_from(capabilities.preferred_batch_size)
            .unwrap_or(u32::MAX)
            .max(1)
            .min(self.limits.maximum_extra_nonce_values_per_lease);
        let lease_end = cursor.saturating_add(requested - 1).min(end);
        let next = lease_end.checked_add(1);
        let prefix: [u8; 4] = envelope.extra_nonce_start[..4].try_into().unwrap();
        let lease = build_lease(
            envelope,
            capabilities,
            LeaseRange {
                extra_nonce_start: gateway_extra_nonce(prefix, cursor.to_be_bytes()),
                extra_nonce_end: gateway_extra_nonce(prefix, lease_end.to_be_bytes()),
                nonce_start: envelope.nonce_start,
                nonce_end: envelope.nonce_end,
                nonce_stride: envelope.nonce_stride,
            },
            edge_target,
            now_ms,
            expires_at_ms,
        );
        self.persist_allocation(
            &cursor_key,
            cursor_bytes,
            next.map(|value| encode_cursor(u64::from(value))),
            capabilities,
            &lease,
        )?;
        Ok(lease)
    }

    fn allocate_nonce(
        &self,
        envelope: &WorkEnvelope,
        capabilities: &DeviceCapabilities,
        edge_target: meshmine_types::U256,
        now_ms: u64,
        expires_at_ms: Option<u64>,
    ) -> Result<WorkLease, PlannerError> {
        if envelope.extra_nonce_start != envelope.extra_nonce_end {
            return Err(PlannerError::UnsupportedEnvelope);
        }
        if !capabilities.supports_nonce_range {
            let lease = build_lease(
                envelope,
                capabilities,
                LeaseRange {
                    extra_nonce_start: envelope.extra_nonce_start,
                    extra_nonce_end: envelope.extra_nonce_end,
                    nonce_start: envelope.nonce_start,
                    nonce_end: envelope.nonce_end,
                    nonce_stride: envelope.nonce_stride,
                },
                edge_target,
                now_ms,
                expires_at_ms,
            );
            self.persist_exclusive(envelope, capabilities, &lease)?;
            return Ok(lease);
        }

        let cursor_key = format!("{}:nonce", hex::encode(envelope.assignment_id));
        let cursor_bytes = self.store.get(CURSOR_NAMESPACE, &cursor_key)?;
        let cursor = match decode_cursor(cursor_bytes.as_deref())? {
            CursorState::Unset => u64::from(envelope.nonce_start),
            CursorState::Next(value) => value,
            CursorState::Exhausted => return Err(PlannerError::EnvelopeExhausted),
        };
        if cursor > u64::from(envelope.nonce_end) {
            return Err(PlannerError::EnvelopeExhausted);
        }
        let measured_batch = capabilities.measured_hashrate.map(|hashrate| {
            u128::from(hashrate)
                .saturating_mul(u128::from(self.limits.target_native_lease_ms))
                .saturating_div(1_000)
                .min(u128::from(u64::MAX)) as u64
        });
        let requested = measured_batch
            .unwrap_or(capabilities.preferred_batch_size)
            .min(self.limits.maximum_nonce_values_per_lease)
            .max(1);
        let stride = u64::from(envelope.nonce_stride);
        let maximum_steps = u64::from(envelope.nonce_end)
            .saturating_sub(cursor)
            .saturating_div(stride);
        let selected_steps = requested.saturating_sub(1).min(maximum_steps);
        let lease_end = cursor.saturating_add(selected_steps.saturating_mul(stride));
        let next = lease_end.checked_add(stride);
        let lease = build_lease(
            envelope,
            capabilities,
            LeaseRange {
                extra_nonce_start: envelope.extra_nonce_start,
                extra_nonce_end: envelope.extra_nonce_end,
                nonce_start: u32::try_from(cursor).map_err(|_| PlannerError::EnvelopeExhausted)?,
                nonce_end: u32::try_from(lease_end).map_err(|_| PlannerError::EnvelopeExhausted)?,
                nonce_stride: envelope.nonce_stride,
            },
            edge_target,
            now_ms,
            expires_at_ms,
        );
        self.persist_allocation(
            &cursor_key,
            cursor_bytes,
            next.filter(|value| *value <= u64::from(envelope.nonce_end))
                .map(encode_cursor),
            capabilities,
            &lease,
        )?;
        Ok(lease)
    }

    fn persist_exclusive(
        &self,
        envelope: &WorkEnvelope,
        capabilities: &DeviceCapabilities,
        lease: &WorkLease,
    ) -> Result<(), PlannerError> {
        let device_key = hex::encode(capabilities.device_id);
        let lease_key = hex::encode(lease.lease_id);
        let exclusive_key = hex::encode(envelope.assignment_id);
        let operations = [
            BatchOperation::put(LEASE_NAMESPACE, &lease_key, lease.to_canonical_bytes()),
            BatchOperation::put(ACTIVE_LEASE_NAMESPACE, &device_key, lease.lease_id.to_vec()),
            BatchOperation::put(
                EXCLUSIVE_NAMESPACE,
                &exclusive_key,
                capabilities.device_id.to_vec(),
            ),
        ];
        if self.store.apply_batch_if_all(
            &[
                BatchCondition::absent(ACTIVE_LEASE_NAMESPACE, &device_key),
                BatchCondition::absent(EXCLUSIVE_NAMESPACE, &exclusive_key),
            ],
            &operations,
        )? {
            Ok(())
        } else {
            Err(PlannerError::EnvelopeExhausted)
        }
    }

    fn persist_allocation(
        &self,
        cursor_key: &str,
        cursor_before: Option<Vec<u8>>,
        cursor_after: Option<Vec<u8>>,
        capabilities: &DeviceCapabilities,
        lease: &WorkLease,
    ) -> Result<(), PlannerError> {
        let device_key = hex::encode(capabilities.device_id);
        let lease_key = hex::encode(lease.lease_id);
        let mut operations = vec![
            BatchOperation::put(LEASE_NAMESPACE, &lease_key, lease.to_canonical_bytes()),
            BatchOperation::put(ACTIVE_LEASE_NAMESPACE, &device_key, lease.lease_id.to_vec()),
        ];
        match cursor_after {
            Some(value) => {
                operations.push(BatchOperation::put(CURSOR_NAMESPACE, cursor_key, value))
            }
            None => operations.push(BatchOperation::put(
                CURSOR_NAMESPACE,
                cursor_key,
                encode_exhausted_cursor(),
            )),
        }
        let conditions = [
            BatchCondition::new(CURSOR_NAMESPACE, cursor_key, cursor_before),
            BatchCondition::absent(ACTIVE_LEASE_NAMESPACE, &device_key),
        ];
        if self.store.apply_batch_if_all(&conditions, &operations)? {
            Ok(())
        } else {
            Err(PlannerError::AllocationRace)
        }
    }
}

struct LeaseRange {
    extra_nonce_start: [u8; 24],
    extra_nonce_end: [u8; 24],
    nonce_start: u32,
    nonce_end: u32,
    nonce_stride: u32,
}

fn build_lease(
    envelope: &WorkEnvelope,
    capabilities: &DeviceCapabilities,
    range: LeaseRange,
    edge_target: meshmine_types::U256,
    now_ms: u64,
    expires_at_ms: Option<u64>,
) -> WorkLease {
    let mut lease = WorkLease {
        protocol_version: WORK_PROTOCOL_VERSION,
        lease_id: [0; 32],
        assignment_id: envelope.assignment_id,
        assignment_sequence: envelope.assignment_sequence,
        job_generation: envelope.job_generation,
        device_id: capabilities.device_id,
        extra_nonce_profile: envelope.extra_nonce_profile,
        extra_nonce_start: range.extra_nonce_start,
        extra_nonce_end: range.extra_nonce_end,
        nonce_start: range.nonce_start,
        nonce_end: range.nonce_end,
        nonce_stride: range.nonce_stride,
        edge_target,
        capture_target: envelope.capture_target,
        activated_at_ms: now_ms,
        expires_at_ms,
        completion_report_allowed: capabilities.reports_range_completion,
    };
    lease.lease_id = lease.canonical_id();
    lease
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CursorState {
    Unset,
    Next(u64),
    Exhausted,
}

fn decode_cursor(bytes: Option<&[u8]>) -> Result<CursorState, PlannerError> {
    match bytes {
        None => Ok(CursorState::Unset),
        Some(bytes) if bytes.len() == 9 && bytes[0] == 0 => {
            let value: [u8; 8] = bytes[1..].try_into().unwrap();
            Ok(CursorState::Next(u64::from_le_bytes(value)))
        }
        Some(bytes) if bytes == [1] => Ok(CursorState::Exhausted),
        Some(_) => Err(PlannerError::CorruptLease),
    }
}

fn encode_cursor(value: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(9);
    bytes.push(0);
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes
}

fn encode_exhausted_cursor() -> Vec<u8> {
    vec![1]
}
