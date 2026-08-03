//! Local, newline-delimited HandyStratum adapter. The native MeshMine overlay
//! does not use Stratum; this module terminates it at an operator-owned gateway.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use meshmine_handoff::{GatewayContextManifestV1, validate_gateway_assignment};
use meshmine_hns::{
    Hash256, MINER_HEADER_SIZE, MinerHeader, compact_to_target, derive_capture_parameters,
    target_to_compact,
};
use meshmine_storage::{BatchCondition, BatchOperation, DurableStore, ScanLimits, StorageError};
use meshmine_types::{
    BlockBodyPackageV2, BodyAvailabilityCertificateV2, BodyErasureDescriptorV2,
    GatewayAssignmentV1, MaskSessionV2, UnsignedObject, domain_hash,
};
use meshmine_work::{WorkLease, gateway_extra_nonce};
use num_bigint::BigUint;
use serde_json::{Value, json};
use thiserror::Error;

const SEQUENCE_NAMESPACE: &str = "gateway-sequence-v2";
const ASSIGNMENT_NAMESPACE: &str = "gateway-assignment-v2";
const ASSIGNMENT_STATE_NAMESPACE: &str = "gateway-assignment-state-v2";
const CURRENT_ASSIGNMENT_NAMESPACE: &str = "gateway-current-assignment-v3";
const CURRENT_ASSIGNMENT_KEY: &str = "current";
const CURRENT_ASSIGNMENT_FORMAT_KEY: &str = "format";
const CURRENT_ASSIGNMENT_FORMAT: &[u8] = b"single-active-v3";
const ASSIGNMENT_PREFIX_POLICY_NAMESPACE: &str = "gateway-assignment-prefix-policy-v3";
const ASSIGNMENT_PREFIX_NAMESPACE: &str = "gateway-assignment-worker-v3";
const RETIRING_ASSIGNMENT_NAMESPACE: &str = "gateway-retiring-assignment-v3";
const RETIRED_JOB_NAMESPACE: &str = "gateway-retired-job-v3";
const CAPTURE_NAMESPACE: &str = "gateway-capture-v2";
const CAPTURE_TOMBSTONE_NAMESPACE: &str = "gateway-capture-tombstone-v2";
const NEXT_ASSIGNMENT_KEY: &str = "next-assignment";
const NEXT_PREFIX_KEY: &str = "next-prefix";
const CAPTURE_MAGIC: [u8; 4] = *b"MMCF";
const CAPTURE_TOMBSTONE_MAGIC: [u8; 4] = *b"MMCT";
const ASSIGNMENT_STATE_MAGIC: [u8; 4] = *b"MMGS";
const CAPTURE_VERSION: u16 = 2;
const CAPTURE_TOMBSTONE_VERSION: u16 = 3;
const ASSIGNMENT_STATE_VERSION: u16 = 2;
const ASSIGNMENT_PREFIX_POLICY: &[u8] = b"assignment-prefix-v3";
const MAX_HANDY_DIFFICULTY: u32 = 0x03ff_ffff;
const RETIRE_DELETE_BATCH: usize = 4_096;
const MAX_RETIREMENTS_PER_PASS: usize = 1_024;
const MAX_RECOVERED_ASSIGNMENTS: usize = 100_000;
const MAX_RECOVERED_CAPTURES: usize = 1_000_000;
const MAX_RECOVERY_VALUE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ASSIGNMENT_RECOVERY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CAPTURE_RECOVERY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_JOB_TRANSACTIONS: usize = 100_000;
const MAX_RPC_TRANSACTION_HASHES: usize = 700;
const MAX_RPC_PASSWORD_BYTES: usize = 255;
const MAX_AUTHORIZATION_FAILURES: u8 = 8;
pub const MAX_RPC_LINE: usize = 16 * 1024;
pub const MAX_RPC_RESPONSE: usize = 64 * 1024;
pub const MAX_GATEWAY_EVENTS: usize = 10_000;
const RPC_IO_TIMEOUT: Duration = Duration::from_secs(30);
const RPC_LINE_TIMEOUT: Duration = Duration::from_secs(30);
const RPC_CONNECTION_TIMEOUT: Duration = Duration::from_secs(15 * 60);
static PROCESS_CLOCK: OnceLock<ProcessClock> = OnceLock::new();

struct ProcessClock {
    wall_start_ms: u64,
    monotonic_start: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TelemetryLevel {
    StockAsic = 0,
    ObservableController = 1,
    RangeProgrammable = 2,
    AuditableHardware = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareEvidence {
    SimulatorOnly,
    SoftwareProtocolReference,
    HardwareUnverified,
    HardwareCaptureVerified,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceProfile {
    name: &'static str,
    telemetry_level: TelemetryLevel,
    hardware_evidence: HardwareEvidence,
    nonce2_bytes: u8,
    supports_mask_hash: bool,
    capture_submission_verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayJob {
    pub id: String,
    pub assignment_sequence: u64,
    pub previous_block: Hash256,
    pub merkle_root: Hash256,
    pub witness_root: Hash256,
    pub tree_root: Hash256,
    pub reserved_root: Hash256,
    pub version: u32,
    pub bits: u32,
    pub ntime: u32,
    pub mask_hash: Hash256,
    pub leading_zero_prefix_q: u16,
    pub blind_band_bits_d: u16,
    pub capture_target: Hash256,
    pub advertised_device_target: Hash256,
    pub advertised_difficulty: u32,
    pub issued_ms: u64,
    pub assignment_end_ms: u64,
    pub submission_end_ms: u64,
    pub transaction_hashes: Vec<Hash256>,
}

pub struct AuthorizedGatewayJobRequest<'a> {
    pub manifest: &'a GatewayContextManifestV1,
    pub assignment: &'a GatewayAssignmentV1,
    pub session: &'a MaskSessionV2,
    pub body: &'a BlockBodyPackageV2,
    pub descriptor: &'a BodyErasureDescriptorV2,
    pub body_certificate: &'a BodyAvailabilityCertificateV2,
    pub job: GatewayJob,
    pub transition: Option<PreviousJobTransition>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviousJobTransition {
    pub job_id: String,
    pub credit_cutoff_ms: u64,
    pub submission_end_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JobState {
    Active,
    Grace {
        credit_cutoff_ms: u64,
        submission_end_ms: u64,
    },
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandySubmission {
    pub username: String,
    pub job_id: String,
    pub extra_nonce2: [u8; 4],
    pub ntime: u32,
    pub nonce: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardedCapture {
    pub username: String,
    pub job_id: String,
    pub assignment_sequence: u64,
    pub miner_header: MinerHeader,
    pub raw_share_hash: Hash256,
    pub received_ms: u64,
    pub credit_eligible: bool,
    pub telemetry_level: TelemetryLevel,
}

impl ForwardedCapture {
    /// Stable gateway deduplication identity used by durable consumer ACKs.
    pub fn work_key(&self) -> Hash256 {
        capture_work_key(self)
    }
}

/// Downstream Core/share admission boundary. Implementations must return only
/// after the forwarded capture (or its canonical derived share) is durable.
/// A successful return authorizes the gateway to compact its local payload;
/// failures leave the capture pending for at-least-once retry.
pub trait DurableCaptureConsumer {
    /// Return only after the capture is durable downstream. Implementations
    /// must be idempotent by `ForwardedCapture::work_key`: a process can crash
    /// after downstream commit and before the local gateway tombstone commits.
    fn admit_capture(&mut self, capture: &ForwardedCapture) -> Result<Hash256, String>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CaptureDrainReport {
    pub attempted: usize,
    pub acknowledged: usize,
    pub last_downstream_id: Option<Hash256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GatewayEvent {
    JobIssued {
        job_id: String,
        assignment_sequence: u64,
    },
    JobCancelled {
        job_id: String,
        credit_cutoff_ms: u64,
        submission_end_ms: u64,
    },
    CaptureForwarded {
        job_id: String,
        raw_share_hash: Hash256,
        credit_eligible: bool,
    },
    SubmissionRejected {
        job_id: String,
        reason: &'static str,
    },
    FailoverActivated {
        endpoint: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailoverPool {
    endpoints: Vec<String>,
    active: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayStatus {
    pub current_job_id: Option<String>,
    pub current_assignment_sequence: Option<u64>,
    pub current_issued_ms: Option<u64>,
    pub current_assignment_end_ms: Option<u64>,
    pub current_submission_end_ms: Option<u64>,
    pub retained_jobs: usize,
    pub pending_captures: usize,
    pub retiring_assignments: usize,
    pub queued_events: usize,
    pub dropped_events: u64,
}

/// Process-wide controls shared by concurrent local HandyStratum sessions.
/// The controls never authorize work: they only stop or drain already-bound
/// local sessions when the operator service enters fallback or shutdown.
pub struct SharedRpcControl {
    shutdown: AtomicBool,
    fallback: AtomicBool,
    active_connections: AtomicUsize,
    authorization_failures: AtomicU16,
    connection_epoch: AtomicU64,
    maximum_authorization_failures: u16,
}

impl SharedRpcControl {
    pub fn new(maximum_authorization_failures: u16) -> Result<Self, GatewayError> {
        if maximum_authorization_failures == 0 {
            return Err(GatewayError::InvalidRpcControl);
        }
        Ok(Self {
            shutdown: AtomicBool::new(false),
            fallback: AtomicBool::new(false),
            active_connections: AtomicUsize::new(0),
            authorization_failures: AtomicU16::new(0),
            connection_epoch: AtomicU64::new(0),
            maximum_authorization_failures,
        })
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub fn set_fallback(&self, enabled: bool) {
        self.fallback.store(enabled, Ordering::SeqCst);
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    pub fn fallback_active(&self) -> bool {
        self.fallback.load(Ordering::SeqCst)
    }

    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::SeqCst)
    }

    pub fn authorization_failures(&self) -> u16 {
        self.authorization_failures.load(Ordering::SeqCst)
    }

    pub fn connection_epoch(&self) -> u64 {
        self.connection_epoch.load(Ordering::SeqCst)
    }

    /// Force existing sessions to reconnect after an assignment-prefix or
    /// authentication context change. New connections observe the incremented
    /// epoch and receive the new prefix during subscription.
    pub fn rotate_connections(&self) -> u64 {
        self.connection_epoch
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1)
    }

    fn enter_connection(&self) {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
    }

    fn leave_connection(&self) {
        self.active_connections.fetch_sub(1, Ordering::SeqCst);
    }

    fn add_authorization_failures(&self, failures: u8) -> Result<(), GatewayError> {
        if failures == 0 {
            return Ok(());
        }
        let increment = u16::from(failures);
        let previous = self
            .authorization_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                Some(current.saturating_add(increment))
            })
            .unwrap_or_else(|current| current);
        let total = previous.saturating_add(increment);
        if total >= self.maximum_authorization_failures {
            self.set_fallback(true);
            return Err(GatewayError::AuthorizationFailureLimit);
        }
        Ok(())
    }
}

pub struct Gateway {
    store: Arc<dyn DurableStore>,
    jobs: HashMap<String, (GatewayJob, JobState)>,
    current_job: Option<String>,
    seen_work: HashSet<Hash256>,
    forwarded: Vec<ForwardedCapture>,
    capture_indexes: HashMap<Hash256, usize>,
    pending_by_assignment: HashMap<u64, usize>,
    tombstones_by_assignment: HashMap<u64, HashSet<Hash256>>,
    retiring_assignments: HashSet<u64>,
    events: VecDeque<GatewayEvent>,
    dropped_events: u64,
    enforce_handy_target: bool,
}

#[derive(Clone)]
pub struct RpcSession {
    username: String,
    password: String,
    agent: Option<String>,
    nonce_prefix: [u8; 4],
    authorized: bool,
    subscribed: bool,
    authorization_failures: u8,
    profile: DeviceProfile,
    assignment_authorization: Option<RpcAssignmentAuthorization>,
}

#[derive(Clone, Debug)]
struct RpcAssignmentAuthorization {
    worker_id_hash: Hash256,
    assignment: GatewayAssignmentV1,
}

impl fmt::Debug for RpcSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RpcSession")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("agent", &self.agent)
            .field("nonce_prefix", &self.nonce_prefix)
            .field("authorized", &self.authorized)
            .field("subscribed", &self.subscribed)
            .field("authorization_failures", &self.authorization_failures)
            .field("profile", &self.profile)
            .field(
                "assignment_sequence",
                &self
                    .assignment_authorization
                    .as_ref()
                    .map(|authorization| authorization.assignment.assignment_sequence),
            )
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("durable gateway state failed: {0}")]
    Storage(#[from] StorageError),
    #[error("assignment or prefix sequence exhausted")]
    SequenceExhausted,
    #[error("durable assignment key already exists")]
    AssignmentConflict,
    #[error("a different active job requires an explicit certified transition")]
    ActiveJobExists,
    #[error("durable assignment capacity is exhausted")]
    AssignmentCapacity,
    #[error("durable gateway state is malformed or inconsistent")]
    InvalidDurableState,
    #[error("capture is not pending and has no durable acknowledgment")]
    CaptureNotFound,
    #[error("durable downstream capture consumer is unavailable")]
    CaptureConsumerUnavailable,
    #[error("durable capture/tombstone capacity is exhausted")]
    CaptureCapacity,
    #[error("job identifier is invalid or already exists")]
    InvalidJobId,
    #[error("gateway job does not exactly match its signed assignment and mining context")]
    AssignmentAuthorizationMismatch,
    #[error("signed gateway assignment is invalid: {0}")]
    Handoff(#[from] meshmine_handoff::HandoffError),
    #[error("gateway job exceeds its configured resource bounds")]
    JobTooLarge,
    #[error("job timing is invalid")]
    InvalidJobTiming,
    #[error("advertised device target would omit capture-qualifying shares")]
    DeviceTargetTooHard,
    #[error("capture target is inconsistent with HNS bits and blind-band parameters")]
    InvalidCaptureProfile,
    #[error("advertised difficulty is outside the HandyStratum integer range")]
    InvalidDifficulty,
    #[error("advertised device target does not match the advertised HandyStratum difficulty")]
    AdvertisedTargetMismatch,
    #[error("job was not found or is outside its submission window")]
    StaleJob,
    #[error("submission fields are malformed")]
    MalformedSubmission,
    #[error("submission nTime does not match its committed assignment")]
    NtimeMismatch,
    #[error("share does not meet the configured capture target")]
    HighHash,
    #[error("duplicate work submission")]
    Duplicate,
    #[error("device profile is not backed by production hardware evidence")]
    HardwareUnverified,
    #[error("device profile cannot guarantee maskHash capture submission")]
    UnsupportedCapturePath,
    #[error("failover endpoint list is empty")]
    EmptyFailover,
    #[error("RPC transaction response exceeds its configured bound")]
    RpcResponseTooLarge,
    #[error("shared RPC control configuration is invalid")]
    InvalidRpcControl,
    #[error("process-wide authorization failure limit reached")]
    AuthorizationFailureLimit,
    #[error("shared gateway state lock was poisoned")]
    GatewayLockPoisoned,
}

#[derive(Debug, Error)]
pub enum RpcServeError {
    #[error("RPC client I/O failed: {source}")]
    ClientIo {
        #[source]
        source: io::Error,
        authorization_failures: u8,
    },
    #[error("fatal gateway RPC state failed: {0}")]
    Gateway(#[from] GatewayError),
}

impl From<io::Error> for RpcServeError {
    fn from(source: io::Error) -> Self {
        Self::ClientIo {
            source,
            authorization_failures: 0,
        }
    }
}

impl RpcServeError {
    /// Invalid authorization attempts observed before a client-side I/O
    /// failure still count toward the supervisor's process-wide budget.
    pub const fn authorization_failures(&self) -> u8 {
        match self {
            Self::ClientIo {
                authorization_failures,
                ..
            } => *authorization_failures,
            Self::Gateway(_) => 0,
        }
    }
}

impl DeviceProfile {
    pub const fn simulator() -> Self {
        Self {
            name: "meshmine-simulator",
            telemetry_level: TelemetryLevel::StockAsic,
            hardware_evidence: HardwareEvidence::SimulatorOnly,
            nonce2_bytes: 4,
            supports_mask_hash: true,
            capture_submission_verified: true,
        }
    }

    pub const fn handyminer_reference() -> Self {
        Self {
            name: "handyminer-reference",
            telemetry_level: TelemetryLevel::StockAsic,
            hardware_evidence: HardwareEvidence::SoftwareProtocolReference,
            nonce2_bytes: 4,
            supports_mask_hash: true,
            capture_submission_verified: true,
        }
    }

    pub const fn goldshell_hs3_experimental() -> Self {
        Self {
            name: "goldshell-hs3-experimental",
            telemetry_level: TelemetryLevel::StockAsic,
            hardware_evidence: HardwareEvidence::HardwareUnverified,
            nonce2_bytes: 4,
            supports_mask_hash: true,
            capture_submission_verified: false,
        }
    }

    pub const fn goldshell_generic_experimental() -> Self {
        Self {
            name: "goldshell-generic-experimental",
            telemetry_level: TelemetryLevel::StockAsic,
            hardware_evidence: HardwareEvidence::HardwareUnverified,
            nonce2_bytes: 4,
            supports_mask_hash: true,
            capture_submission_verified: false,
        }
    }

    pub fn validate_production(&self) -> Result<(), GatewayError> {
        if self.hardware_evidence != HardwareEvidence::HardwareCaptureVerified {
            return Err(GatewayError::HardwareUnverified);
        }
        if !self.supports_mask_hash || !self.capture_submission_verified {
            return Err(GatewayError::UnsupportedCapturePath);
        }
        Ok(())
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn telemetry_level(&self) -> TelemetryLevel {
        self.telemetry_level
    }

    pub const fn hardware_evidence(&self) -> HardwareEvidence {
        self.hardware_evidence
    }
}

impl GatewayJob {
    pub fn handy_notify(&self) -> Value {
        json!({
            "id": null,
            "method": "mining.notify",
            "params": [
                self.id,
                hex::encode(self.previous_block),
                hex::encode(self.merkle_root),
                hex::encode(self.witness_root),
                hex::encode(self.tree_root),
                hex::encode(self.reserved_root),
                format!("{:08x}", self.version),
                format!("{:08x}", self.bits),
                format!("{:08x}", self.ntime),
                hex::encode(self.mask_hash)
            ]
        })
    }
}

impl Gateway {
    pub fn open(store: Arc<dyn DurableStore>) -> Result<Self, GatewayError> {
        Self::open_with_target_policy(store, true)
    }

    /// Open the explicitly non-production simulator profile. HandyStratum's
    /// integer difficulty dialect cannot represent the intentionally easy
    /// capture targets used by fast local tests.
    pub fn open_simulator(store: Arc<dyn DurableStore>) -> Result<Self, GatewayError> {
        Self::open_with_target_policy(store, false)
    }

    fn open_with_target_policy(
        store: Arc<dyn DurableStore>,
        enforce_handy_target: bool,
    ) -> Result<Self, GatewayError> {
        let format = store.get(CURRENT_ASSIGNMENT_NAMESPACE, CURRENT_ASSIGNMENT_FORMAT_KEY)?;
        if format
            .as_deref()
            .is_some_and(|value| value != CURRENT_ASSIGNMENT_FORMAT)
        {
            return Err(GatewayError::InvalidDurableState);
        }
        let new_store = format.is_none();
        let durable_head = store.get(CURRENT_ASSIGNMENT_NAMESPACE, CURRENT_ASSIGNMENT_KEY)?;
        let durable_head_sequence = durable_head
            .as_deref()
            .map(decode_sequence_value)
            .transpose()?;
        let state_records = store.scan_namespace(
            ASSIGNMENT_STATE_NAMESPACE,
            ScanLimits {
                maximum_records: MAX_RECOVERED_ASSIGNMENTS,
                maximum_value_bytes: MAX_RECOVERY_VALUE_BYTES,
                maximum_total_bytes: MAX_ASSIGNMENT_RECOVERY_BYTES,
            },
        )?;
        let mut recovered_states = HashMap::with_capacity(state_records.len());
        for record in state_records {
            let sequence = record
                .key
                .parse::<u64>()
                .map_err(|_| GatewayError::InvalidDurableState)?;
            if recovered_states
                .insert(sequence, decode_durable_job_state(&record.value)?)
                .is_some()
            {
                return Err(GatewayError::InvalidDurableState);
            }
        }
        let assignment_records = store.scan_namespace(
            ASSIGNMENT_NAMESPACE,
            ScanLimits {
                maximum_records: MAX_RECOVERED_ASSIGNMENTS,
                maximum_value_bytes: MAX_RECOVERY_VALUE_BYTES,
                maximum_total_bytes: MAX_ASSIGNMENT_RECOVERY_BYTES,
            },
        )?;
        let mut jobs = HashMap::with_capacity(assignment_records.len());
        let mut active_jobs = Vec::new();
        for record in assignment_records {
            let sequence = record
                .key
                .parse::<u64>()
                .map_err(|_| GatewayError::InvalidDurableState)?;
            let job = decode_durable_job(&record.value)?;
            validate_job(&job, enforce_handy_target)?;
            let state = match recovered_states.remove(&sequence) {
                Some(state) => state,
                None => return Err(GatewayError::InvalidDurableState),
            };
            validate_recovered_job_state(&job, state)?;
            if sequence != job.assignment_sequence
                || jobs.insert(job.id.clone(), (job.clone(), state)).is_some()
            {
                return Err(GatewayError::InvalidDurableState);
            }
            if state == JobState::Active {
                active_jobs.push((sequence, job.id));
            }
        }
        if !recovered_states.is_empty() {
            return Err(GatewayError::InvalidDurableState);
        }
        if active_jobs.len() > 1 {
            return Err(GatewayError::InvalidDurableState);
        }
        let current_job = match (durable_head_sequence, active_jobs.first()) {
            (Some(head), Some((sequence, id))) if head == *sequence => Some(id.clone()),
            (None, None) => None,
            _ => return Err(GatewayError::InvalidDurableState),
        };
        if new_store {
            if durable_head_sequence.is_some() || !jobs.is_empty() {
                return Err(GatewayError::InvalidDurableState);
            }
            if !store.apply_batch_if(
                CURRENT_ASSIGNMENT_NAMESPACE,
                CURRENT_ASSIGNMENT_FORMAT_KEY,
                None,
                &[BatchOperation::put(
                    CURRENT_ASSIGNMENT_NAMESPACE,
                    CURRENT_ASSIGNMENT_FORMAT_KEY,
                    CURRENT_ASSIGNMENT_FORMAT.to_vec(),
                )],
            )? {
                return Err(GatewayError::InvalidDurableState);
            }
        }

        let assignment_sequences = jobs
            .values()
            .map(|(job, _)| job.assignment_sequence)
            .collect::<HashSet<_>>();

        let retiring_records = store.scan_namespace(
            RETIRING_ASSIGNMENT_NAMESPACE,
            ScanLimits {
                maximum_records: MAX_RECOVERED_ASSIGNMENTS,
                maximum_value_bytes: 64,
                maximum_total_bytes: MAX_ASSIGNMENT_RECOVERY_BYTES,
            },
        )?;
        let mut retiring_assignments = HashSet::with_capacity(retiring_records.len());
        for record in retiring_records {
            let sequence = record
                .key
                .parse::<u64>()
                .map_err(|_| GatewayError::InvalidDurableState)?;
            let id = std::str::from_utf8(&record.value)
                .map_err(|_| GatewayError::InvalidDurableState)?;
            let Some((job, state)) = jobs.get(id) else {
                return Err(GatewayError::InvalidDurableState);
            };
            if job.assignment_sequence != sequence
                || *state != JobState::Closed
                || !retiring_assignments.insert(sequence)
            {
                return Err(GatewayError::InvalidDurableState);
            }
        }

        let tombstone_records = store.scan_namespace(
            CAPTURE_TOMBSTONE_NAMESPACE,
            ScanLimits {
                maximum_records: MAX_RECOVERED_CAPTURES,
                maximum_value_bytes: 14,
                maximum_total_bytes: MAX_CAPTURE_RECOVERY_BYTES,
            },
        )?;
        let mut seen_work = HashSet::with_capacity(tombstone_records.len());
        let mut tombstones_by_assignment: HashMap<u64, HashSet<Hash256>> = HashMap::new();
        for record in tombstone_records {
            let work_key = fixed_hash_key(&record.key)?;
            if !seen_work.insert(work_key) {
                return Err(GatewayError::InvalidDurableState);
            }
            let sequence = decode_capture_tombstone(&record.value)?;
            if !assignment_sequences.contains(&sequence) {
                return Err(GatewayError::InvalidDurableState);
            }
            tombstones_by_assignment
                .entry(sequence)
                .or_default()
                .insert(work_key);
        }

        let capture_records = store.scan_namespace(
            CAPTURE_NAMESPACE,
            ScanLimits {
                maximum_records: MAX_RECOVERED_CAPTURES,
                maximum_value_bytes: MAX_RECOVERY_VALUE_BYTES,
                maximum_total_bytes: MAX_CAPTURE_RECOVERY_BYTES,
            },
        )?;
        let mut forwarded = Vec::with_capacity(capture_records.len());
        let mut pending_by_assignment = HashMap::new();
        for record in capture_records {
            if seen_work.len() >= MAX_RECOVERED_CAPTURES {
                return Err(GatewayError::InvalidDurableState);
            }
            let work_key = fixed_hash_key(&record.key)?;
            let capture = decode_durable_capture(&record.value)?;
            validate_recovered_capture(&capture, &jobs)?;
            if capture_work_key(&capture) != work_key || !seen_work.insert(work_key) {
                return Err(GatewayError::InvalidDurableState);
            }
            *pending_by_assignment
                .entry(capture.assignment_sequence)
                .or_insert(0) += 1;
            forwarded.push(capture);
        }
        if retiring_assignments
            .iter()
            .any(|sequence| pending_by_assignment.contains_key(sequence))
        {
            return Err(GatewayError::InvalidDurableState);
        }
        forwarded.sort_by_key(|capture| {
            (
                capture.assignment_sequence,
                capture.received_ms,
                capture.raw_share_hash,
            )
        });
        let capture_indexes = forwarded
            .iter()
            .enumerate()
            .map(|(index, capture)| (capture_work_key(capture), index))
            .collect();

        Ok(Self {
            store,
            jobs,
            current_job,
            seen_work,
            forwarded,
            capture_indexes,
            pending_by_assignment,
            tombstones_by_assignment,
            retiring_assignments,
            events: VecDeque::new(),
            dropped_events: 0,
            enforce_handy_target,
        })
    }

    /// Allocate a prefix scoped to one worker and one active assignment. The
    /// remaining 20 nonce bytes retain HandyStratum's exact four-byte nonce2
    /// plus sixteen-zero-byte layout.
    pub fn assignment_nonce_prefix(
        &self,
        worker_id_hash: &Hash256,
        assignment_sequence: u64,
    ) -> Result<[u8; 4], GatewayError> {
        let current = self.current_job().ok_or(GatewayError::StaleJob)?;
        if current.assignment_sequence != assignment_sequence {
            return Err(GatewayError::StaleJob);
        }
        let worker_key = format!("{}:{assignment_sequence}", hex::encode(worker_id_hash));
        if let Some(raw) = self.store.get(ASSIGNMENT_PREFIX_NAMESPACE, &worker_key)? {
            return raw.try_into().map_err(|_| GatewayError::SequenceExhausted);
        }
        let policy_key = assignment_sequence.to_string();
        let policy = self
            .store
            .get(ASSIGNMENT_PREFIX_POLICY_NAMESPACE, &policy_key)?;
        if policy
            .as_deref()
            .is_some_and(|value| value != ASSIGNMENT_PREFIX_POLICY)
        {
            return Err(GatewayError::InvalidDurableState);
        }
        let current = allocate_sequence(self.store.as_ref(), NEXT_PREFIX_KEY)?;
        let prefix = u32::try_from(current).map_err(|_| GatewayError::SequenceExhausted)?;
        let prefix = prefix.to_be_bytes();
        if self.store.apply_batch_if(
            ASSIGNMENT_PREFIX_NAMESPACE,
            &worker_key,
            None,
            &[BatchOperation::put(
                ASSIGNMENT_PREFIX_NAMESPACE,
                &worker_key,
                prefix.to_vec(),
            )],
        )? {
            return Ok(prefix);
        }
        self.store
            .get(ASSIGNMENT_PREFIX_NAMESPACE, &worker_key)?
            .ok_or(GatewayError::InvalidDurableState)?
            .try_into()
            .map_err(|_| GatewayError::InvalidDurableState)
    }

    /// Install or recover the exact four-byte prefix authorized by a signed
    /// production gateway assignment. This method never substitutes a
    /// locally chosen prefix.
    pub fn authorized_assignment_nonce_prefix(
        &self,
        worker_id_hash: &Hash256,
        assignment: &GatewayAssignmentV1,
    ) -> Result<[u8; 4], GatewayError> {
        let current = self.current_job().ok_or(GatewayError::StaleJob)?;
        if assignment.worker_id_hash != *worker_id_hash
            || current.id != gateway_assignment_job_id(assignment)
            || current.assignment_sequence != assignment.assignment_sequence
        {
            return Err(GatewayError::AssignmentAuthorizationMismatch);
        }
        let policy_key = assignment.assignment_sequence.to_string();
        if self
            .store
            .get(ASSIGNMENT_PREFIX_POLICY_NAMESPACE, &policy_key)?
            .as_deref()
            != Some(ASSIGNMENT_PREFIX_POLICY)
        {
            return Err(GatewayError::InvalidDurableState);
        }
        let worker_key = format!(
            "{}:{}",
            hex::encode(worker_id_hash),
            assignment.assignment_sequence
        );
        match self.store.get(ASSIGNMENT_PREFIX_NAMESPACE, &worker_key)? {
            Some(existing) if existing.as_slice() == assignment.extra_nonce_prefix => {
                Ok(assignment.extra_nonce_prefix)
            }
            Some(_) => Err(GatewayError::AssignmentAuthorizationMismatch),
            None => {
                let installed = self.store.put_if_absent(
                    ASSIGNMENT_PREFIX_NAMESPACE,
                    &worker_key,
                    &assignment.extra_nonce_prefix,
                )?;
                if installed
                    || self
                        .store
                        .get(ASSIGNMENT_PREFIX_NAMESPACE, &worker_key)?
                        .as_deref()
                        == Some(assignment.extra_nonce_prefix.as_slice())
                {
                    Ok(assignment.extra_nonce_prefix)
                } else {
                    Err(GatewayError::AssignmentAuthorizationMismatch)
                }
            }
        }
    }

    pub fn issue_job(&mut self, job: GatewayJob) -> Result<u64, GatewayError> {
        self.issue_job_with_transition(job, None)
    }

    pub fn issue_job_with_transition(
        &mut self,
        job: GatewayJob,
        transition: Option<PreviousJobTransition>,
    ) -> Result<u64, GatewayError> {
        self.issue_job_internal(job, transition, None)
    }

    /// Issue a job whose HandyStratum identifier is the lowercase hexadecimal
    /// object ID of its signed `GatewayAssignmentV1`. The complete immutable
    /// mining context is cross-checked before any gateway assignment state is
    /// written, and the local durable sequence must equal the signed sequence.
    pub fn issue_authorized_job(
        &mut self,
        request: AuthorizedGatewayJobRequest<'_>,
    ) -> Result<u64, GatewayError> {
        let AuthorizedGatewayJobRequest {
            manifest,
            assignment,
            session,
            body,
            descriptor,
            body_certificate,
            job,
            transition,
        } = request;
        validate_gateway_assignment(manifest, assignment)?;
        validate_authorized_job_binding(
            &job,
            assignment,
            session,
            body,
            descriptor,
            body_certificate,
        )?;
        self.issue_job_internal(job, transition, Some(assignment.assignment_sequence))
    }

    fn issue_job_internal(
        &mut self,
        mut job: GatewayJob,
        transition: Option<PreviousJobTransition>,
        expected_sequence: Option<u64>,
    ) -> Result<u64, GatewayError> {
        if job.assignment_sequence != 0 {
            return Err(GatewayError::AssignmentConflict);
        }
        validate_job(&job, self.enforce_handy_target)?;
        if let Some((existing, state)) = self.jobs.get(&job.id) {
            job.assignment_sequence = existing.assignment_sequence;
            if expected_sequence.is_some_and(|sequence| sequence != existing.assignment_sequence) {
                return Err(GatewayError::AssignmentAuthorizationMismatch);
            }
            if encode_durable_job(&job) == encode_durable_job(existing)
                && *state == JobState::Active
                && self.current_job.as_deref() == Some(existing.id.as_str())
            {
                return Ok(existing.assignment_sequence);
            }
            return Err(GatewayError::AssignmentConflict);
        }
        if let Some(retired) = self.store.get(RETIRED_JOB_NAMESPACE, &job.id)? {
            decode_sequence_value(&retired)?;
            return Err(GatewayError::InvalidJobId);
        }
        if self.jobs.len() >= MAX_RECOVERED_ASSIGNMENTS {
            return Err(GatewayError::AssignmentCapacity);
        }

        let previous = match (self.current_job.as_deref(), transition) {
            (None, None) => None,
            (None, Some(_)) => return Err(GatewayError::InvalidJobTiming),
            (Some(_), None) => return Err(GatewayError::ActiveJobExists),
            (Some(current_id), Some(transition)) => {
                if transition.job_id != current_id {
                    return Err(GatewayError::InvalidJobTiming);
                }
                let (previous, state) = self
                    .jobs
                    .get(current_id)
                    .ok_or(GatewayError::InvalidDurableState)?;
                if *state != JobState::Active
                    || transition.credit_cutoff_ms < previous.issued_ms
                    || job.issued_ms < transition.credit_cutoff_ms
                    || transition.submission_end_ms < transition.credit_cutoff_ms
                    || transition.submission_end_ms > previous.submission_end_ms
                {
                    return Err(GatewayError::InvalidJobTiming);
                }
                Some((
                    previous.id.clone(),
                    previous.assignment_sequence,
                    JobState::Grace {
                        credit_cutoff_ms: transition.credit_cutoff_ms,
                        submission_end_ms: transition.submission_end_ms,
                    },
                ))
            }
        };

        let (sequence_head, sequence, next_sequence) =
            load_sequence_candidate(self.store.as_ref(), NEXT_ASSIGNMENT_KEY)?;
        if expected_sequence.is_some_and(|expected| expected != sequence) {
            return Err(GatewayError::AssignmentAuthorizationMismatch);
        }
        job.assignment_sequence = sequence;
        let sequence_key = sequence.to_string();
        if self
            .store
            .get(ASSIGNMENT_NAMESPACE, &sequence_key)?
            .is_some()
        {
            return Err(GatewayError::AssignmentConflict);
        }
        let expected_head = previous
            .as_ref()
            .map(|(_, previous_sequence, _)| previous_sequence.to_le_bytes());
        let mut operations = vec![
            BatchOperation::put(
                SEQUENCE_NAMESPACE,
                NEXT_ASSIGNMENT_KEY,
                next_sequence.to_le_bytes().to_vec(),
            ),
            BatchOperation::put(
                ASSIGNMENT_NAMESPACE,
                &sequence_key,
                encode_durable_job(&job),
            ),
            BatchOperation::put(
                ASSIGNMENT_STATE_NAMESPACE,
                &sequence_key,
                encode_durable_job_state(JobState::Active),
            ),
            BatchOperation::put(
                ASSIGNMENT_PREFIX_POLICY_NAMESPACE,
                &sequence_key,
                ASSIGNMENT_PREFIX_POLICY.to_vec(),
            ),
            BatchOperation::put(
                CURRENT_ASSIGNMENT_NAMESPACE,
                CURRENT_ASSIGNMENT_KEY,
                sequence.to_le_bytes().to_vec(),
            ),
        ];
        if let Some((_, previous_sequence, previous_state)) = &previous {
            operations.push(BatchOperation::put(
                ASSIGNMENT_STATE_NAMESPACE,
                previous_sequence.to_string(),
                encode_durable_job_state(*previous_state),
            ));
        }
        if !self.store.apply_batch_if_all(
            &[
                BatchCondition::new(
                    CURRENT_ASSIGNMENT_NAMESPACE,
                    CURRENT_ASSIGNMENT_KEY,
                    expected_head.map(|value| value.to_vec()),
                ),
                BatchCondition::new(SEQUENCE_NAMESPACE, NEXT_ASSIGNMENT_KEY, sequence_head),
                BatchCondition::absent(ASSIGNMENT_NAMESPACE, &sequence_key),
            ],
            &operations,
        )? {
            return Err(GatewayError::AssignmentConflict);
        }
        if let Some((previous_id, _, previous_state)) = previous {
            self.jobs
                .get_mut(&previous_id)
                .ok_or(GatewayError::InvalidDurableState)?
                .1 = previous_state;
        }
        let id = job.id.clone();
        self.jobs.insert(id.clone(), (job, JobState::Active));
        self.current_job = Some(id.clone());
        self.push_event(GatewayEvent::JobIssued {
            job_id: id,
            assignment_sequence: sequence,
        });
        Ok(sequence)
    }

    pub fn cancel_job(
        &mut self,
        job_id: &str,
        credit_cutoff_ms: u64,
        submission_end_ms: u64,
    ) -> Result<(), GatewayError> {
        let (job, state) = self.jobs.get(job_id).ok_or(GatewayError::StaleJob)?;
        if credit_cutoff_ms < job.issued_ms
            || submission_end_ms < credit_cutoff_ms
            || submission_end_ms > job.submission_end_ms
        {
            return Err(GatewayError::InvalidJobTiming);
        }
        let next_state = JobState::Grace {
            credit_cutoff_ms,
            submission_end_ms,
        };
        match *state {
            JobState::Active => {
                if self.current_job.as_deref() != Some(job_id)
                    || !self.store.apply_batch_if(
                        CURRENT_ASSIGNMENT_NAMESPACE,
                        CURRENT_ASSIGNMENT_KEY,
                        Some(&job.assignment_sequence.to_le_bytes()),
                        &[
                            BatchOperation::put(
                                ASSIGNMENT_STATE_NAMESPACE,
                                job.assignment_sequence.to_string(),
                                encode_durable_job_state(next_state),
                            ),
                            BatchOperation::delete(
                                CURRENT_ASSIGNMENT_NAMESPACE,
                                CURRENT_ASSIGNMENT_KEY,
                            ),
                        ],
                    )?
                {
                    return Err(GatewayError::InvalidDurableState);
                }
            }
            existing if existing == next_state => {
                if self.store.get(
                    ASSIGNMENT_STATE_NAMESPACE,
                    &job.assignment_sequence.to_string(),
                )? != Some(encode_durable_job_state(next_state))
                {
                    return Err(GatewayError::InvalidDurableState);
                }
                return Ok(());
            }
            JobState::Grace { .. } => return Err(GatewayError::InvalidJobTiming),
            JobState::Closed => return Err(GatewayError::StaleJob),
        }
        self.jobs
            .get_mut(job_id)
            .ok_or(GatewayError::InvalidDurableState)?
            .1 = next_state;
        self.current_job = None;
        self.push_event(GatewayEvent::JobCancelled {
            job_id: job_id.to_owned(),
            credit_cutoff_ms,
            submission_end_ms,
        });
        Ok(())
    }

    pub fn close_expired(&mut self, now_ms: u64) -> Result<(), GatewayError> {
        let expired = self
            .jobs
            .values()
            .filter_map(|(job, state)| {
                let end = match state {
                    JobState::Active => job.submission_end_ms,
                    JobState::Grace {
                        submission_end_ms, ..
                    } => *submission_end_ms,
                    JobState::Closed => return None,
                };
                (now_ms > end).then(|| (job.id.clone(), job.assignment_sequence, *state))
            })
            .collect::<Vec<_>>();
        for (id, sequence, state) in expired {
            let sequence_key = sequence.to_string();
            match state {
                JobState::Active => {
                    if self.current_job.as_deref() != Some(id.as_str())
                        || !self.store.apply_batch_if(
                            CURRENT_ASSIGNMENT_NAMESPACE,
                            CURRENT_ASSIGNMENT_KEY,
                            Some(&sequence.to_le_bytes()),
                            &[
                                BatchOperation::put(
                                    ASSIGNMENT_STATE_NAMESPACE,
                                    &sequence_key,
                                    encode_durable_job_state(JobState::Closed),
                                ),
                                BatchOperation::delete(
                                    CURRENT_ASSIGNMENT_NAMESPACE,
                                    CURRENT_ASSIGNMENT_KEY,
                                ),
                            ],
                        )?
                    {
                        return Err(GatewayError::InvalidDurableState);
                    }
                    self.current_job = None;
                }
                JobState::Grace { .. } => {
                    if !self.store.compare_and_swap(
                        ASSIGNMENT_STATE_NAMESPACE,
                        &sequence_key,
                        Some(&encode_durable_job_state(state)),
                        &encode_durable_job_state(JobState::Closed),
                    )? {
                        return Err(GatewayError::InvalidDurableState);
                    }
                }
                JobState::Closed => unreachable!(),
            }
            self.jobs
                .get_mut(&id)
                .ok_or(GatewayError::InvalidDurableState)?
                .1 = JobState::Closed;
        }
        self.retire_closed_jobs()
    }

    fn retire_closed_jobs(&mut self) -> Result<(), GatewayError> {
        let mut candidates = self
            .jobs
            .values()
            .filter(|(job, state)| {
                *state == JobState::Closed
                    && self
                        .pending_by_assignment
                        .get(&job.assignment_sequence)
                        .copied()
                        .unwrap_or(0)
                        == 0
            })
            .map(|(job, _)| (job.assignment_sequence, job.id.clone()))
            .collect::<Vec<_>>();
        candidates.sort_unstable_by_key(|(sequence, _)| *sequence);
        candidates.truncate(MAX_RETIREMENTS_PER_PASS);

        for (sequence, id) in candidates {
            if !self.retiring_assignments.contains(&sequence) {
                if !self.store.put_if_absent(
                    RETIRING_ASSIGNMENT_NAMESPACE,
                    &sequence.to_string(),
                    id.as_bytes(),
                )? && self
                    .store
                    .get(RETIRING_ASSIGNMENT_NAMESPACE, &sequence.to_string())?
                    != Some(id.as_bytes().to_vec())
                {
                    return Err(GatewayError::InvalidDurableState);
                }
                self.retiring_assignments.insert(sequence);
            }
            self.advance_retirement(sequence, &id)?;
        }
        Ok(())
    }

    fn advance_retirement(&mut self, sequence: u64, id: &str) -> Result<(), GatewayError> {
        if self
            .pending_by_assignment
            .get(&sequence)
            .copied()
            .unwrap_or(0)
            != 0
        {
            return Err(GatewayError::InvalidDurableState);
        }
        let tombstones = self
            .tombstones_by_assignment
            .get(&sequence)
            .map(|keys| {
                keys.iter()
                    .copied()
                    .take(RETIRE_DELETE_BATCH)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !tombstones.is_empty() {
            let operations = tombstones
                .iter()
                .map(|key| BatchOperation::delete(CAPTURE_TOMBSTONE_NAMESPACE, hex::encode(key)))
                .collect::<Vec<_>>();
            self.store.apply_batch(&operations)?;
            for key in tombstones {
                self.seen_work.remove(&key);
                if let Some(keys) = self.tombstones_by_assignment.get_mut(&sequence) {
                    keys.remove(&key);
                }
            }
            if self
                .tombstones_by_assignment
                .get(&sequence)
                .is_some_and(HashSet::is_empty)
            {
                self.tombstones_by_assignment.remove(&sequence);
            }
            return Ok(());
        }

        let sequence_key = sequence.to_string();
        let operations = [
            BatchOperation::put(RETIRED_JOB_NAMESPACE, id, sequence.to_le_bytes().to_vec()),
            BatchOperation::delete(ASSIGNMENT_NAMESPACE, &sequence_key),
            BatchOperation::delete(ASSIGNMENT_STATE_NAMESPACE, &sequence_key),
            BatchOperation::delete(RETIRING_ASSIGNMENT_NAMESPACE, &sequence_key),
        ];
        if !self
            .store
            .apply_batch_if(RETIRED_JOB_NAMESPACE, id, None, &operations)?
        {
            return Err(GatewayError::InvalidDurableState);
        }
        self.jobs
            .remove(id)
            .ok_or(GatewayError::InvalidDurableState)?;
        self.pending_by_assignment.remove(&sequence);
        self.retiring_assignments.remove(&sequence);
        Ok(())
    }

    pub fn current_job(&self) -> Option<&GatewayJob> {
        self.current_job
            .as_ref()
            .and_then(|id| self.jobs.get(id))
            .map(|(job, _)| job)
    }

    /// Clone the exact durable-store handle backing this gateway. Cross-crate
    /// activation protocols use this instead of accepting a second caller-
    /// selected store which could split one assignment across two databases.
    pub fn durable_store(&self) -> Arc<dyn DurableStore> {
        Arc::clone(&self.store)
    }

    pub fn transactions(&self, job_id: &str) -> Result<Vec<String>, GatewayError> {
        let (job, state) = self.jobs.get(job_id).ok_or(GatewayError::StaleJob)?;
        if *state == JobState::Closed {
            return Err(GatewayError::StaleJob);
        }
        if job.transaction_hashes.len() > MAX_RPC_TRANSACTION_HASHES {
            return Err(GatewayError::RpcResponseTooLarge);
        }
        Ok(job.transaction_hashes.iter().map(hex::encode).collect())
    }

    pub fn submit(
        &mut self,
        nonce_prefix: [u8; 4],
        telemetry_level: TelemetryLevel,
        submission: HandySubmission,
        received_ms: u64,
    ) -> Result<ForwardedCapture, GatewayError> {
        let (job, state) = self
            .jobs
            .get(&submission.job_id)
            .cloned()
            .ok_or(GatewayError::StaleJob)?;
        if received_ms < job.issued_ms {
            return self.reject(&submission.job_id, "job-not-issued", GatewayError::StaleJob);
        }
        let credit_eligible = match state {
            JobState::Active => {
                if received_ms > job.submission_end_ms {
                    return self.reject(&submission.job_id, "stale-job", GatewayError::StaleJob);
                }
                // This job was durably issued before assignment_end_ms. That
                // cutoff stops new assignments; it does not retroactively
                // remove credit from already-issued work during its submission
                // window.
                true
            }
            JobState::Grace {
                credit_cutoff_ms,
                submission_end_ms,
            } => {
                if received_ms > submission_end_ms {
                    return self.reject(&submission.job_id, "stale-job", GatewayError::StaleJob);
                }
                received_ms <= credit_cutoff_ms
            }
            JobState::Closed => {
                return self.reject(&submission.job_id, "stale-job", GatewayError::StaleJob);
            }
        };
        if submission.ntime != job.ntime {
            return self.reject(
                &submission.job_id,
                "ntime-mismatch",
                GatewayError::NtimeMismatch,
            );
        }
        let mut extra_nonce = [0; 24];
        extra_nonce[..4].copy_from_slice(&nonce_prefix);
        extra_nonce[4..8].copy_from_slice(&submission.extra_nonce2);
        let miner_header = MinerHeader {
            nonce: submission.nonce,
            time: u64::from(submission.ntime),
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
        let raw_share_hash = miner_header.share_hash();
        if raw_share_hash > job.capture_target {
            return self.reject(&submission.job_id, "high-hash", GatewayError::HighHash);
        }
        let capture = ForwardedCapture {
            username: submission.username,
            job_id: submission.job_id.clone(),
            assignment_sequence: job.assignment_sequence,
            miner_header,
            raw_share_hash,
            received_ms,
            credit_eligible,
            telemetry_level,
        };
        let work_key = capture_work_key(&capture);
        if self.seen_work.contains(&work_key) {
            return self.reject(&submission.job_id, "duplicate", GatewayError::Duplicate);
        }
        if self.seen_work.len() >= MAX_RECOVERED_CAPTURES {
            return self.reject(
                &submission.job_id,
                "capture-capacity",
                GatewayError::CaptureCapacity,
            );
        }
        if !self.store.put_if_absent(
            CAPTURE_NAMESPACE,
            &hex::encode(work_key),
            &encode_durable_capture(&capture),
        )? {
            return self.reject(&submission.job_id, "duplicate", GatewayError::Duplicate);
        }
        self.seen_work.insert(work_key);
        self.capture_indexes.insert(work_key, self.forwarded.len());
        *self
            .pending_by_assignment
            .entry(job.assignment_sequence)
            .or_insert(0) += 1;
        self.forwarded.push(capture.clone());
        self.push_event(GatewayEvent::CaptureForwarded {
            job_id: submission.job_id,
            raw_share_hash,
            credit_eligible,
        });
        Ok(capture)
    }

    /// Validate the miner-selected HandyStratum fields against the signed
    /// nonce range before using the normal durable capture path.
    pub fn submit_authorized(
        &mut self,
        worker_id_hash: &Hash256,
        assignment: &GatewayAssignmentV1,
        nonce_prefix: [u8; 4],
        telemetry_level: TelemetryLevel,
        submission: HandySubmission,
        received_ms: u64,
    ) -> Result<ForwardedCapture, GatewayError> {
        let expected_job_id = gateway_assignment_job_id(assignment);
        let nonce_offset = submission.nonce.checked_sub(assignment.nonce_start);
        if assignment.worker_id_hash != *worker_id_hash
            || submission.job_id != expected_job_id
            || nonce_prefix != assignment.extra_nonce_prefix
            || submission.extra_nonce2 < assignment.extra_nonce2_start_be
            || submission.extra_nonce2 > assignment.extra_nonce2_end_be
            || nonce_offset.is_none_or(|offset| {
                submission.nonce > assignment.nonce_end
                    || assignment.nonce_stride == 0
                    || offset % assignment.nonce_stride != 0
            })
            || u64::from(submission.ntime) != assignment.ntime
            || telemetry_level as u8 != assignment.telemetry_level
        {
            return self.reject(
                &submission.job_id,
                "assignment-authorization-mismatch",
                GatewayError::AssignmentAuthorizationMismatch,
            );
        }
        self.submit(nonce_prefix, telemetry_level, submission, received_ms)
    }

    /// Validate a miner submission against both the signed gateway assignment
    /// and a narrower durable local work lease. The lease may restrict the
    /// signed envelope but may never expand it.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_authorized_lease(
        &mut self,
        device_id: &Hash256,
        worker_id_hash: &Hash256,
        assignment: &GatewayAssignmentV1,
        lease: &WorkLease,
        nonce_prefix: [u8; 4],
        telemetry_level: TelemetryLevel,
        submission: HandySubmission,
        received_ms: u64,
    ) -> Result<ForwardedCapture, GatewayError> {
        let mut extra_nonce = [0; 24];
        extra_nonce[..4].copy_from_slice(&nonce_prefix);
        extra_nonce[4..8].copy_from_slice(&submission.extra_nonce2);
        let nonce_offset = submission.nonce.checked_sub(lease.nonce_start);
        if lease.assignment_id != assignment.object_id()
            || lease.assignment_sequence != assignment.assignment_sequence
            || lease.device_id != *device_id
            || lease.extra_nonce_profile != assignment.extra_nonce_profile
            || lease.extra_nonce_start
                < gateway_extra_nonce(
                    assignment.extra_nonce_prefix,
                    assignment.extra_nonce2_start_be,
                )
            || lease.extra_nonce_end
                > gateway_extra_nonce(
                    assignment.extra_nonce_prefix,
                    assignment.extra_nonce2_end_be,
                )
            || lease.extra_nonce_start > lease.extra_nonce_end
            || extra_nonce < lease.extra_nonce_start
            || extra_nonce > lease.extra_nonce_end
            || lease.nonce_start < assignment.nonce_start
            || lease.nonce_end > assignment.nonce_end
            || lease.nonce_start > lease.nonce_end
            || assignment.nonce_stride == 0
            || lease.nonce_stride == 0
            || !lease.nonce_stride.is_multiple_of(assignment.nonce_stride)
            || nonce_offset.is_none_or(|offset| {
                submission.nonce > lease.nonce_end || offset % lease.nonce_stride != 0
            })
            || lease.edge_target.0 > assignment.edge_target.0
            || lease.edge_target.0 < assignment.capture_target.0
            || lease.capture_target != assignment.capture_target
            || lease
                .expires_at_ms
                .is_some_and(|expiry| received_ms > expiry)
            || lease.job_generation == 0
            || lease.canonical_id() != lease.lease_id
        {
            return self.reject(
                &submission.job_id,
                "local-work-lease-mismatch",
                GatewayError::AssignmentAuthorizationMismatch,
            );
        }
        self.submit_authorized(
            worker_id_hash,
            assignment,
            nonce_prefix,
            telemetry_level,
            submission,
            received_ms,
        )
    }

    fn reject<T>(
        &mut self,
        job_id: &str,
        reason: &'static str,
        error: GatewayError,
    ) -> Result<T, GatewayError> {
        self.push_event(GatewayEvent::SubmissionRejected {
            job_id: job_id.to_owned(),
            reason,
        });
        Err(error)
    }

    pub fn forwarded(&self) -> &[ForwardedCapture] {
        &self.forwarded
    }

    /// Drain a bounded prefix through a durable downstream consumer. The
    /// capture is acknowledged locally only after `admit_capture` succeeds.
    /// Processing stops at the first downstream error so ordering and retry
    /// behavior remain simple and deterministic.
    pub fn drain_captures_durably(
        &mut self,
        consumer: &mut dyn DurableCaptureConsumer,
        maximum: usize,
    ) -> Result<CaptureDrainReport, GatewayError> {
        let mut report = CaptureDrainReport::default();
        for _ in 0..maximum {
            let Some(capture) = self.forwarded.first().cloned() else {
                break;
            };
            report.attempted = report.attempted.saturating_add(1);
            let downstream_id = consumer
                .admit_capture(&capture)
                .map_err(|_| GatewayError::CaptureConsumerUnavailable)?;
            if !self.acknowledge_capture(&capture.work_key())? {
                return Err(GatewayError::InvalidDurableState);
            }
            report.acknowledged = report.acknowledged.saturating_add(1);
            report.last_downstream_id = Some(downstream_id);
        }
        Ok(report)
    }

    /// Atomically retire a capture payload after its consumer has durably
    /// admitted the corresponding protocol share. The compact tombstone keeps
    /// duplicate submissions rejected after process restart.
    pub fn acknowledge_capture(&mut self, work_key: &Hash256) -> Result<bool, GatewayError> {
        let key = hex::encode(work_key);
        let Some(index) = self.capture_indexes.get(work_key).copied() else {
            if !self.seen_work.contains(work_key) {
                return Err(GatewayError::CaptureNotFound);
            }
            let bytes = self
                .store
                .get(CAPTURE_TOMBSTONE_NAMESPACE, &key)?
                .ok_or(GatewayError::InvalidDurableState)?;
            let assignment_sequence = decode_capture_tombstone(&bytes)?;
            if !self
                .jobs
                .values()
                .any(|(job, _)| job.assignment_sequence == assignment_sequence)
            {
                return Err(GatewayError::InvalidDurableState);
            }
            return Ok(false);
        };
        let capture = self
            .forwarded
            .get(index)
            .ok_or(GatewayError::InvalidDurableState)?;
        if capture_work_key(capture) != *work_key {
            return Err(GatewayError::InvalidDurableState);
        }
        let assignment_sequence = capture.assignment_sequence;
        let tombstone = encode_capture_tombstone(assignment_sequence);
        self.store.apply_batch(&[
            BatchOperation::put(CAPTURE_TOMBSTONE_NAMESPACE, &key, tombstone),
            BatchOperation::delete(CAPTURE_NAMESPACE, &key),
        ])?;
        self.tombstones_by_assignment
            .entry(assignment_sequence)
            .or_default()
            .insert(*work_key);
        let pending = self
            .pending_by_assignment
            .get_mut(&assignment_sequence)
            .ok_or(GatewayError::InvalidDurableState)?;
        *pending = pending
            .checked_sub(1)
            .ok_or(GatewayError::InvalidDurableState)?;
        if *pending == 0 {
            self.pending_by_assignment.remove(&assignment_sequence);
        }
        self.capture_indexes.remove(work_key);
        self.forwarded.swap_remove(index);
        if let Some(moved) = self.forwarded.get(index) {
            self.capture_indexes.insert(capture_work_key(moved), index);
        }
        Ok(true)
    }

    pub fn status(&self) -> GatewayStatus {
        let current = self.current_job();
        GatewayStatus {
            current_job_id: current.map(|job| job.id.clone()),
            current_assignment_sequence: current.map(|job| job.assignment_sequence),
            current_issued_ms: current.map(|job| job.issued_ms),
            current_assignment_end_ms: current.map(|job| job.assignment_end_ms),
            current_submission_end_ms: current.map(|job| job.submission_end_ms),
            retained_jobs: self.jobs.len(),
            pending_captures: self.forwarded.len(),
            retiring_assignments: self.retiring_assignments.len(),
            queued_events: self.events.len(),
            dropped_events: self.dropped_events,
        }
    }

    pub fn drain_events(&mut self, maximum: usize) -> Vec<GatewayEvent> {
        let count = maximum.min(self.events.len());
        self.events.drain(..count).collect()
    }

    pub fn events(&self) -> &VecDeque<GatewayEvent> {
        &self.events
    }

    pub const fn dropped_event_count(&self) -> u64 {
        self.dropped_events
    }

    fn push_event(&mut self, event: GatewayEvent) {
        if self.events.len() == MAX_GATEWAY_EVENTS {
            self.events.pop_front();
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
        self.events.push_back(event);
    }

    pub fn record_failover(&mut self, endpoint: &str) {
        self.push_event(GatewayEvent::FailoverActivated {
            endpoint: endpoint.to_owned(),
        });
    }
}

impl RpcSession {
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        nonce_prefix: [u8; 4],
        profile: DeviceProfile,
    ) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            agent: None,
            nonce_prefix,
            authorized: false,
            subscribed: false,
            authorization_failures: 0,
            profile,
            assignment_authorization: None,
        }
    }

    /// Construct a Core-linked RPC session bound to one signed assignment.
    /// The advertised nonce prefix is derived from the assignment so callers
    /// cannot accidentally pair a locally allocated prefix with signed work.
    pub fn new_authorized(
        username: impl Into<String>,
        password: impl Into<String>,
        profile: DeviceProfile,
        worker_id_hash: Hash256,
        assignment: GatewayAssignmentV1,
    ) -> Result<Self, GatewayError> {
        if assignment.worker_id_hash != worker_id_hash
            || profile.telemetry_level() as u8 != assignment.telemetry_level
        {
            return Err(GatewayError::AssignmentAuthorizationMismatch);
        }
        Ok(Self {
            username: username.into(),
            password: password.into(),
            agent: None,
            nonce_prefix: assignment.extra_nonce_prefix,
            authorized: false,
            subscribed: false,
            authorization_failures: 0,
            profile,
            assignment_authorization: Some(RpcAssignmentAuthorization {
                worker_id_hash,
                assignment,
            }),
        })
    }

    pub fn handle_line(
        &mut self,
        gateway: &mut Gateway,
        line: &str,
        received_ms: u64,
    ) -> Result<Vec<Value>, GatewayError> {
        if line.len() > MAX_RPC_LINE {
            return Ok(vec![rpc_error(Value::Null, 0, "request-too-large")]);
        }
        let request: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => return Ok(vec![rpc_error(Value::Null, 0, "invalid-json")]),
        };
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = match request.get("method").and_then(Value::as_str) {
            Some(method) => method,
            None => return Ok(vec![rpc_error(id, 0, "invalid-method")]),
        };
        let params = request
            .get("params")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        match method {
            "mining.subscribe" => {
                if let Some(agent) = params.first().and_then(Value::as_str) {
                    if agent.is_empty() || agent.len() > 255 {
                        return Ok(vec![rpc_error(id, 0, "invalid-params")]);
                    }
                    self.agent = Some(agent.to_owned());
                }
                self.subscribed = true;
                let sid = hex::encode(self.nonce_prefix);
                let mut responses = vec![rpc_result(
                    id,
                    json!([
                        [["mining.notify", sid], ["mining.set_difficulty", sid]],
                        sid,
                        self.profile.nonce2_bytes
                    ]),
                )];
                if let Some(job) = gateway
                    .current_job()
                    .filter(|job| received_ms <= job.assignment_end_ms)
                {
                    responses.push(json!({
                        "id": null,
                        "method": "mining.set_difficulty",
                        "params": [job.advertised_difficulty]
                    }));
                    responses.push(job.handy_notify());
                }
                Ok(responses)
            }
            "mining.authorize" => {
                let valid = self.authorization_failures < MAX_AUTHORIZATION_FAILURES
                    && params.len() == 2
                    && params[0].as_str() == Some(self.username.as_str())
                    && params[1].as_str().is_some_and(|candidate| {
                        constant_time_password_eq(&self.password, candidate)
                    });
                if !valid {
                    self.authorization_failures = self
                        .authorization_failures
                        .saturating_add(1)
                        .min(MAX_AUTHORIZATION_FAILURES);
                }
                self.authorized = valid;
                Ok(vec![rpc_result(id, json!(valid))])
            }
            "mining.submit" => {
                if !self.subscribed {
                    return Ok(vec![rpc_error(id, 25, "not-subscribed")]);
                }
                if !self.authorized {
                    return Ok(vec![rpc_error(id, 24, "unauthorized-user")]);
                }
                let submission = match parse_submission(&params) {
                    Ok(submission) if submission.username == self.username => submission,
                    _ => return Ok(vec![rpc_error(id, 0, "invalid-params")]),
                };
                let result = match self.assignment_authorization.as_ref() {
                    Some(authorization) => gateway.submit_authorized(
                        &authorization.worker_id_hash,
                        &authorization.assignment,
                        self.nonce_prefix,
                        self.profile.telemetry_level,
                        submission,
                        received_ms,
                    ),
                    None => gateway.submit(
                        self.nonce_prefix,
                        self.profile.telemetry_level,
                        submission,
                        received_ms,
                    ),
                };
                submit_rpc_result(id, result)
            }
            "mining.get_transactions" => {
                if !self.subscribed {
                    return Ok(vec![rpc_error(id, 25, "not-subscribed")]);
                }
                if !self.authorized {
                    return Ok(vec![rpc_error(id, 24, "unauthorized-user")]);
                }
                let Some(job_id) = params.first().and_then(Value::as_str) else {
                    return Ok(vec![rpc_error(id, 21, "job-not-found")]);
                };
                match gateway.transactions(job_id) {
                    Ok(transactions) => {
                        let response = rpc_result(id.clone(), json!(transactions));
                        if rpc_response_length(&response) > MAX_RPC_RESPONSE {
                            Ok(vec![rpc_error(id, 0, "response-too-large")])
                        } else {
                            Ok(vec![response])
                        }
                    }
                    Err(GatewayError::RpcResponseTooLarge) => {
                        Ok(vec![rpc_error(id, 0, "response-too-large")])
                    }
                    Err(_) => Ok(vec![rpc_error(id, 21, "job-not-found")]),
                }
            }
            _ => Ok(vec![rpc_error(id, 20, "unknown-method")]),
        }
    }

    /// Invalid authorization attempts are intentionally observable by the
    /// loopback process so reconnects can share a process-wide failure budget.
    pub const fn authorization_failures(&self) -> u8 {
        self.authorization_failures
    }

    pub const fn subscribed(&self) -> bool {
        self.subscribed
    }

    pub const fn authorization_locked(&self) -> bool {
        self.authorization_failures >= MAX_AUTHORIZATION_FAILURES
    }
}

fn constant_time_password_eq(expected: &str, candidate: &str) -> bool {
    let expected = expected.as_bytes();
    let candidate = candidate.as_bytes();
    let mut difference = expected.len() ^ candidate.len();
    for index in 0..MAX_RPC_PASSWORD_BYTES {
        let left = expected.get(index).copied().unwrap_or(0);
        let right = candidate.get(index).copied().unwrap_or(0);
        difference |= usize::from(left ^ right);
    }
    difference == 0
        && expected.len() <= MAX_RPC_PASSWORD_BYTES
        && candidate.len() <= MAX_RPC_PASSWORD_BYTES
}

fn submit_rpc_result(
    id: Value,
    result: Result<ForwardedCapture, GatewayError>,
) -> Result<Vec<Value>, GatewayError> {
    match result {
        Ok(_) => Ok(vec![rpc_result(id, json!(true))]),
        Err(GatewayError::HighHash) => Ok(vec![rpc_error(id, 23, "high-hash")]),
        Err(GatewayError::Duplicate) => Ok(vec![rpc_error(id, 22, "duplicate")]),
        Err(GatewayError::StaleJob) => Ok(vec![rpc_error(id, 21, "job-not-found")]),
        Err(GatewayError::NtimeMismatch) => Ok(vec![rpc_error(id, 20, "ntime-mismatch")]),
        Err(error @ (GatewayError::Storage(_) | GatewayError::CaptureCapacity)) => Err(error),
        Err(_) => Ok(vec![rpc_error(id, 20, "invalid-share")]),
    }
}

/// Serve one local HandyStratum connection while allowing a supervisor to push
/// replacement jobs and to force immediate fallback. Gateway state is locked
/// only while processing one request or taking one job snapshot; slow sockets
/// never serialize unrelated miners.
pub fn serve_rpc_connection_shared(
    stream: TcpStream,
    mut session: RpcSession,
    gateway: Arc<Mutex<Gateway>>,
    control: Arc<SharedRpcControl>,
    max_requests: usize,
    update_interval: Duration,
) -> Result<RpcSession, RpcServeError> {
    if max_requests == 0 || update_interval.is_zero() {
        return Err(GatewayError::InvalidRpcControl.into());
    }
    if control.shutdown_requested() || control.fallback_active() {
        let _ = stream.shutdown(Shutdown::Both);
        return Ok(session);
    }

    let connection_epoch = control.connection_epoch();
    control.enter_connection();
    struct ConnectionGuard<'a>(&'a SharedRpcControl);
    impl Drop for ConnectionGuard<'_> {
        fn drop(&mut self) {
            self.0.leave_connection();
        }
    }
    let _connection_guard = ConnectionGuard(control.as_ref());

    let connection_deadline = Instant::now() + RPC_CONNECTION_TIMEOUT;
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    let subscribed = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let last_job = Arc::new(Mutex::new(None::<String>));
    let writer_error = Arc::new(Mutex::new(None::<io::Error>));

    let update_stream = stream.try_clone()?;
    let update_gateway = gateway.clone();
    let update_control = control.clone();
    let update_writer = writer.clone();
    let update_subscribed = subscribed.clone();
    let update_done = done.clone();
    let update_last_job = last_job.clone();
    let update_error = writer_error.clone();
    let updater = std::thread::spawn(move || {
        while !update_done.load(Ordering::SeqCst)
            && !update_control.shutdown_requested()
            && !update_control.fallback_active()
            && update_control.connection_epoch() == connection_epoch
        {
            std::thread::sleep(update_interval);
            if !update_subscribed.load(Ordering::SeqCst) {
                continue;
            }
            let now_ms = process_wall_ms();
            let update = {
                let mut guard = match update_gateway.lock() {
                    Ok(guard) => guard,
                    Err(_) => {
                        if let Ok(mut error) = update_error.lock() {
                            *error = Some(io::Error::other("gateway lock poisoned"));
                        }
                        break;
                    }
                };
                if guard.close_expired(now_ms).is_err() {
                    if let Ok(mut error) = update_error.lock() {
                        *error = Some(io::Error::other("gateway expiration failed"));
                    }
                    break;
                }
                guard.current_job().and_then(|job| {
                    if now_ms > job.assignment_end_ms {
                        return None;
                    }
                    let sent = update_last_job.lock().ok()?.clone();
                    if sent.as_deref() == Some(job.id.as_str()) {
                        return None;
                    }
                    Some((
                        job.id.clone(),
                        job.advertised_difficulty,
                        job.handy_notify(),
                    ))
                })
            };
            let Some((job_id, difficulty, notification)) = update else {
                continue;
            };
            let write_result = (|| -> io::Result<()> {
                let mut writer = update_writer
                    .lock()
                    .map_err(|_| io::Error::other("RPC writer lock poisoned"))?;
                write_rpc_response_until(
                    &mut writer,
                    &json!({
                        "id": null,
                        "method": "mining.set_difficulty",
                        "params": [difficulty]
                    }),
                    connection_deadline,
                )?;
                write_rpc_response_until(&mut writer, &notification, connection_deadline)
            })();
            if let Err(error) = write_result {
                if let Ok(mut stored) = update_error.lock() {
                    *stored = Some(error);
                }
                break;
            }
            if let Ok(mut sent) = update_last_job.lock() {
                *sent = Some(job_id);
            }
        }
        let _ = update_stream.shutdown(Shutdown::Both);
    });

    let mut reader = BufReader::new(stream.try_clone()?);
    let result = (|| -> Result<(), RpcServeError> {
        for _ in 0..max_requests {
            if control.shutdown_requested()
                || control.fallback_active()
                || control.connection_epoch() != connection_epoch
            {
                break;
            }
            let line_deadline = (Instant::now() + RPC_LINE_TIMEOUT).min(connection_deadline);
            let mut line = String::new();
            let bytes_read =
                match read_bounded_rpc_line_until(&mut reader, &mut line, line_deadline) {
                    Ok(bytes_read) => bytes_read,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                        ) =>
                    {
                        break;
                    }
                    Err(error) => return Err(error.into()),
                };
            if bytes_read == 0 {
                break;
            }
            if line.len() == MAX_RPC_LINE + 2 && !line.ends_with('\n') {
                let mut writer = writer
                    .lock()
                    .map_err(|_| GatewayError::GatewayLockPoisoned)?;
                write_rpc_response_until(
                    &mut writer,
                    &rpc_error(Value::Null, 0, "request-too-large"),
                    connection_deadline,
                )?;
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']);
            let received_ms = process_wall_ms();
            let subscribed_before = session.subscribed();
            let responses = {
                let mut gateway = gateway
                    .lock()
                    .map_err(|_| GatewayError::GatewayLockPoisoned)?;
                gateway.close_expired(received_ms)?;
                let responses = session.handle_line(&mut gateway, line, received_ms)?;
                if !subscribed_before
                    && session.subscribed()
                    && let Some(job) = gateway.current_job()
                    && let Ok(mut sent) = last_job.lock()
                {
                    *sent = Some(job.id.clone());
                }
                responses
            };
            subscribed.store(session.subscribed(), Ordering::SeqCst);
            {
                let mut writer = writer
                    .lock()
                    .map_err(|_| GatewayError::GatewayLockPoisoned)?;
                for response in responses {
                    write_rpc_response_until(&mut writer, &response, connection_deadline)?;
                }
            }
            if session.authorization_locked() {
                break;
            }
        }
        Ok(())
    })();

    done.store(true, Ordering::SeqCst);
    let _ = stream.shutdown(Shutdown::Both);
    let _ = updater.join();
    control
        .add_authorization_failures(session.authorization_failures())
        .map_err(RpcServeError::Gateway)?;
    if let Some(error) = writer_error
        .lock()
        .map_err(|_| GatewayError::GatewayLockPoisoned)?
        .take()
        && result.is_ok()
    {
        return Err(RpcServeError::ClientIo {
            source: error,
            authorization_failures: session.authorization_failures(),
        });
    }
    result?;
    Ok(session)
}

impl FailoverPool {
    pub fn new(endpoints: Vec<String>) -> Result<Self, GatewayError> {
        if endpoints.is_empty() || endpoints.iter().any(String::is_empty) {
            return Err(GatewayError::EmptyFailover);
        }
        Ok(Self {
            endpoints,
            active: 0,
        })
    }

    pub fn active(&self) -> &str {
        &self.endpoints[self.active]
    }

    pub fn fail(&mut self) -> &str {
        self.active = (self.active + 1) % self.endpoints.len();
        self.active()
    }
}

/// Serve a bounded number of newline-delimited RPC requests. The caller owns
/// listener lifecycle and authentication scope; ASIC Stratum is local-only.
pub fn serve_rpc_connection(
    stream: TcpStream,
    session: RpcSession,
    gateway: &mut Gateway,
    max_requests: usize,
) -> Result<RpcSession, RpcServeError> {
    serve_rpc_connection_with_clock(stream, session, gateway, max_requests, process_wall_ms)
}

/// Clock-injected server used by deterministic tests. Production callers use
/// `serve_rpc_connection`, whose process-wide wall-time anchor advances only
/// with a monotonic clock so a wall-clock rollback or long-lived socket cannot
/// extend a submission window.
pub fn serve_rpc_connection_with_clock(
    stream: TcpStream,
    mut session: RpcSession,
    gateway: &mut Gateway,
    max_requests: usize,
    now_ms: impl FnMut() -> u64,
) -> Result<RpcSession, RpcServeError> {
    match serve_rpc_connection_loop(stream, &mut session, gateway, max_requests, now_ms) {
        Ok(()) => Ok(session),
        Err(RpcServeError::ClientIo { source, .. }) => Err(RpcServeError::ClientIo {
            source,
            authorization_failures: session.authorization_failures(),
        }),
        Err(error) => Err(error),
    }
}

fn serve_rpc_connection_loop(
    mut stream: TcpStream,
    session: &mut RpcSession,
    gateway: &mut Gateway,
    max_requests: usize,
    mut now_ms: impl FnMut() -> u64,
) -> Result<(), RpcServeError> {
    let connection_deadline = Instant::now() + RPC_CONNECTION_TIMEOUT;
    let mut reader = BufReader::new(stream.try_clone()?);
    for _ in 0..max_requests {
        let line_deadline = (Instant::now() + RPC_LINE_TIMEOUT).min(connection_deadline);
        let mut line = String::new();
        let bytes_read = match read_bounded_rpc_line_until(&mut reader, &mut line, line_deadline) {
            Ok(bytes_read) => bytes_read,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        };
        if bytes_read == 0 {
            break;
        }
        if line.len() == MAX_RPC_LINE + 2 && !line.ends_with('\n') {
            write_rpc_response_until(
                &mut stream,
                &rpc_error(Value::Null, 0, "request-too-large"),
                connection_deadline,
            )?;
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        let received_ms = now_ms();
        gateway.close_expired(received_ms)?;
        for response in session.handle_line(gateway, line, received_ms)? {
            write_rpc_response_until(&mut stream, &response, connection_deadline)?;
        }
        // Send the final negative response, then stop servicing this socket.
        // Merely skipping future password comparisons would still let a local
        // client consume the complete request bound after exhausting auth.
        if session.authorization_locked() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
fn read_bounded_rpc_line(reader: &mut impl BufRead, line: &mut String) -> io::Result<usize> {
    std::io::Read::take(&mut *reader, (MAX_RPC_LINE + 2) as u64).read_line(line)
}

fn read_bounded_rpc_line_until(
    reader: &mut BufReader<TcpStream>,
    line: &mut String,
    deadline: Instant,
) -> io::Result<usize> {
    let maximum = MAX_RPC_LINE + 2;
    let mut bytes = Vec::with_capacity(maximum.min(4_096));
    while bytes.len() < maximum {
        reader
            .get_ref()
            .set_read_timeout(Some(remaining_io_timeout(deadline)?))?;
        let available = reader.fill_buf()?;
        if available.is_empty() {
            break;
        }
        let available = &available[..available.len().min(maximum - bytes.len())];
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        let found_newline = available.get(take.saturating_sub(1)) == Some(&b'\n');
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if found_newline {
            break;
        }
    }
    let bytes_read = bytes.len();
    *line = String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "RPC line is not UTF-8"))?;
    Ok(bytes_read)
}

fn remaining_io_timeout(deadline: Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "RPC deadline elapsed",
        ));
    }
    Ok(remaining.min(RPC_IO_TIMEOUT))
}

fn rpc_response_length(response: &Value) -> usize {
    serde_json::to_vec(response).map_or(usize::MAX, |bytes| bytes.len().saturating_add(1))
}

fn write_rpc_response_until(
    stream: &mut TcpStream,
    response: &Value,
    deadline: Instant,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(response).map_err(io::Error::other)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_RPC_RESPONSE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "RPC response exceeds configured bound",
        ));
    }
    let mut remaining = bytes.as_slice();
    while !remaining.is_empty() {
        stream.set_write_timeout(Some(remaining_io_timeout(deadline)?))?;
        match stream.write(remaining)? {
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "RPC client stopped accepting a response",
                ));
            }
            written => remaining = &remaining[written..],
        }
    }
    Ok(())
}

fn process_wall_ms() -> u64 {
    let clock = PROCESS_CLOCK.get_or_init(|| ProcessClock {
        wall_start_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            }),
        monotonic_start: Instant::now(),
    });
    let elapsed_ms = u64::try_from(clock.monotonic_start.elapsed().as_millis()).unwrap_or(u64::MAX);
    clock.wall_start_ms.saturating_add(elapsed_ms)
}

fn parse_submission(params: &[Value]) -> Result<HandySubmission, GatewayError> {
    if params.len() < 5 {
        return Err(GatewayError::MalformedSubmission);
    }
    let username = bounded_string(&params[0], 1, 100)?;
    let job_id = bounded_string(&params[1], 12, 64)?;
    let extra_nonce2 = fixed_hex::<4>(&params[2])?;
    let ntime = hex_u32(&params[3])?;
    let nonce = hex_u32(&params[4])?;
    Ok(HandySubmission {
        username,
        job_id,
        extra_nonce2,
        ntime,
        nonce,
    })
}

fn bounded_string(value: &Value, minimum: usize, maximum: usize) -> Result<String, GatewayError> {
    let value = value.as_str().ok_or(GatewayError::MalformedSubmission)?;
    if value.len() < minimum || value.len() > maximum {
        return Err(GatewayError::MalformedSubmission);
    }
    Ok(value.to_owned())
}

fn fixed_hex<const N: usize>(value: &Value) -> Result<[u8; N], GatewayError> {
    let value = value.as_str().ok_or(GatewayError::MalformedSubmission)?;
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GatewayError::MalformedSubmission);
    }
    hex::decode(value)
        .map_err(|_| GatewayError::MalformedSubmission)?
        .try_into()
        .map_err(|_| GatewayError::MalformedSubmission)
}

fn hex_u32(value: &Value) -> Result<u32, GatewayError> {
    let bytes = fixed_hex::<4>(value)?;
    Ok(u32::from_be_bytes(bytes))
}

/// Canonical HandyStratum job identifier for the authenticated production
/// gateway path. It is the lowercase hexadecimal unsigned object ID, not an
/// operator-selected display string.
pub fn gateway_assignment_job_id(assignment: &GatewayAssignmentV1) -> String {
    hex::encode(assignment.object_id())
}

#[allow(clippy::too_many_arguments)]
fn validate_authorized_job_binding(
    job: &GatewayJob,
    assignment: &GatewayAssignmentV1,
    session: &MaskSessionV2,
    body: &BlockBodyPackageV2,
    descriptor: &BodyErasureDescriptorV2,
    body_certificate: &BodyAvailabilityCertificateV2,
) -> Result<(), GatewayError> {
    let template = &body.template_core;
    let assignment_ntime = u32::try_from(assignment.ntime)
        .map_err(|_| GatewayError::AssignmentAuthorizationMismatch)?;
    let context_matches = assignment.session_id == session.object_id()
        && assignment.body_package_id == body.object_id()
        && assignment.body_certificate_id == body_certificate.object_id()
        && descriptor.body_package_id == assignment.body_package_id
        && body_certificate.descriptor_id == descriptor.object_id()
        && body_certificate.parent_hash == session.parent_hash
        && body_certificate.parent_height == template.hns_parent_height
        && body_certificate.consensus_validation_result_hash
            == body.consensus_validation_result_hash
        && assignment.network_id == session.network_id
        && assignment.network_id == body.network_id
        && assignment.network_id == descriptor.network_id
        && assignment.network_id == body_certificate.network_id
        && assignment.core_protocol_version == session.protocol_version
        && assignment.core_protocol_version == body.protocol_version
        && assignment.core_protocol_version == descriptor.protocol_version
        && assignment.core_protocol_version == body_certificate.protocol_version
        && body.template_core_id == template.object_id()
        && template.network_id == assignment.network_id
        && template.hns_parent_hash == session.parent_hash
        && session.capture_target == assignment.capture_target
        && job.id == gateway_assignment_job_id(assignment)
        && job.assignment_sequence == 0
        && job.previous_block == session.parent_hash
        && job.merkle_root == body.merkle_root
        && job.witness_root == body.witness_root
        && job.tree_root == body.tree_root
        && job.reserved_root == body.reserved_root
        && job.version == template.block_version
        && job.bits == template.bits
        && job.ntime == assignment_ntime
        && assignment.ntime >= template.minimum_ntime
        && job.mask_hash == session.mask_hash
        && job.leading_zero_prefix_q == session.leading_zero_prefix_q
        && job.blind_band_bits_d == session.blind_band_bits_d
        && job.capture_target == session.capture_target.0
        && job.capture_target == assignment.capture_target.0
        && job.advertised_device_target == assignment.edge_target.0
        && job.issued_ms == session.assignment_start_ms
        && job.assignment_end_ms == session.assignment_end_ms
        && job.submission_end_ms == session.submission_end_ms
        && job.transaction_hashes == template.ordered_non_coinbase_txids;
    if !context_matches {
        return Err(GatewayError::AssignmentAuthorizationMismatch);
    }
    Ok(())
}

fn validate_job(job: &GatewayJob, enforce_handy_target: bool) -> Result<(), GatewayError> {
    if job.id.len() < 12
        || job.id.len() > 64
        || !job
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(GatewayError::InvalidJobId);
    }
    if job.transaction_hashes.len() > MAX_JOB_TRANSACTIONS {
        return Err(GatewayError::JobTooLarge);
    }
    if job.issued_ms > job.assignment_end_ms || job.assignment_end_ms > job.submission_end_ms {
        return Err(GatewayError::InvalidJobTiming);
    }
    if job.advertised_difficulty == 0 || job.advertised_difficulty > MAX_HANDY_DIFFICULTY {
        return Err(GatewayError::InvalidDifficulty);
    }
    let capture = derive_capture_parameters(job.bits, job.blind_band_bits_d)
        .map_err(|_| GatewayError::InvalidCaptureProfile)?;
    if job.leading_zero_prefix_q != capture.leading_zero_prefix_q
        || job.capture_target != capture.capture_target
    {
        return Err(GatewayError::InvalidCaptureProfile);
    }
    if enforce_handy_target
        && job.advertised_device_target != handy_target_from_difficulty(job.advertised_difficulty)?
    {
        return Err(GatewayError::AdvertisedTargetMismatch);
    }
    // Targets are canonical big-endian integers. A smaller target is harder;
    // advertising one would make the device omit valid captures. Test
    // simulator mode still enforces this relation even when its intentionally
    // easy target is not representable by HandyStratum's integer difficulty.
    if job.advertised_device_target < job.capture_target {
        return Err(GatewayError::DeviceTargetTooHard);
    }
    Ok(())
}

pub fn handy_target_from_difficulty(difficulty: u32) -> Result<Hash256, GatewayError> {
    if difficulty == 0 || difficulty > MAX_HANDY_DIFFICULTY {
        return Err(GatewayError::InvalidDifficulty);
    }
    // Exact pinned HandyStratum util.targetFromDifficulty semantics:
    // floor(diff1_max / difficulty), compact through the HNS consensus
    // codec, then expand it before the server compares a submitted proof.
    let mut maximum = [0xff; 32];
    maximum[..3].fill(0);
    let target = BigUint::from_bytes_be(&maximum) / difficulty;
    let compact = target_to_compact(&target);
    let effective = compact_to_target(compact)
        .to_biguint()
        .ok_or(GatewayError::InvalidDifficulty)?;
    let bytes = effective.to_bytes_be();
    if bytes.len() > 32 {
        return Err(GatewayError::InvalidDifficulty);
    }
    let mut output = [0; 32];
    output[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(output)
}

fn capture_work_key(capture: &ForwardedCapture) -> Hash256 {
    let mut work = Vec::with_capacity(capture.job_id.len() + 24 + 4 + 4 + 32);
    work.extend_from_slice(capture.job_id.as_bytes());
    work.extend_from_slice(&capture.miner_header.extra_nonce);
    work.extend_from_slice(&(capture.miner_header.time as u32).to_le_bytes());
    work.extend_from_slice(&capture.miner_header.nonce.to_le_bytes());
    work.extend_from_slice(&capture.raw_share_hash);
    domain_hash("meshmine/gateway-work/v2", &work)
}

fn validate_recovered_capture(
    capture: &ForwardedCapture,
    jobs: &HashMap<String, (GatewayJob, JobState)>,
) -> Result<(), GatewayError> {
    if capture.username.is_empty() || capture.username.len() > 100 {
        return Err(GatewayError::InvalidDurableState);
    }
    let (job, _) = jobs
        .get(&capture.job_id)
        .ok_or(GatewayError::InvalidDurableState)?;
    let header = &capture.miner_header;
    if capture.assignment_sequence != job.assignment_sequence
        || header.time != u64::from(job.ntime)
        || header.prev_block != job.previous_block
        || header.merkle_root != job.merkle_root
        || header.witness_root != job.witness_root
        || header.tree_root != job.tree_root
        || header.reserved_root != job.reserved_root
        || header.version != job.version
        || header.bits != job.bits
        || header.mask_hash != job.mask_hash
        || header.extra_nonce[8..].iter().any(|byte| *byte != 0)
        || header.share_hash() != capture.raw_share_hash
        || capture.raw_share_hash > job.capture_target
        || capture.received_ms < job.issued_ms
        || capture.received_ms > job.submission_end_ms
    {
        return Err(GatewayError::InvalidDurableState);
    }
    Ok(())
}

fn validate_recovered_job_state(job: &GatewayJob, state: JobState) -> Result<(), GatewayError> {
    if let JobState::Grace {
        credit_cutoff_ms,
        submission_end_ms,
    } = state
        && (credit_cutoff_ms < job.issued_ms
            || submission_end_ms < credit_cutoff_ms
            || submission_end_ms > job.submission_end_ms)
    {
        return Err(GatewayError::InvalidDurableState);
    }
    Ok(())
}

fn fixed_hash_key(value: &str) -> Result<Hash256, GatewayError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GatewayError::InvalidDurableState);
    }
    let hash: Hash256 = hex::decode(value)
        .map_err(|_| GatewayError::InvalidDurableState)?
        .try_into()
        .map_err(|_| GatewayError::InvalidDurableState)?;
    if hex::encode(hash) != value {
        return Err(GatewayError::InvalidDurableState);
    }
    Ok(hash)
}

fn decode_sequence_value(bytes: &[u8]) -> Result<u64, GatewayError> {
    Ok(u64::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| GatewayError::InvalidDurableState)?,
    ))
}

fn load_sequence_candidate(
    store: &dyn DurableStore,
    key: &str,
) -> Result<(Option<Vec<u8>>, u64, u64), GatewayError> {
    let raw = store.get(SEQUENCE_NAMESPACE, key)?;
    let current = match raw.as_deref() {
        Some(bytes) => u64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| GatewayError::SequenceExhausted)?,
        ),
        None => 1,
    };
    let next = current
        .checked_add(1)
        .ok_or(GatewayError::SequenceExhausted)?;
    Ok((raw, current, next))
}

fn allocate_sequence(store: &dyn DurableStore, key: &str) -> Result<u64, GatewayError> {
    loop {
        let (raw, current, next) = load_sequence_candidate(store, key)?;
        if store.compare_and_swap(SEQUENCE_NAMESPACE, key, raw.as_deref(), &next.to_le_bytes())? {
            return Ok(current);
        }
    }
}

fn encode_durable_job(job: &GatewayJob) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(320 + job.id.len() + job.transaction_hashes.len() * 32);
    bytes.extend_from_slice(&(job.id.len() as u64).to_le_bytes());
    bytes.extend_from_slice(job.id.as_bytes());
    bytes.extend_from_slice(&job.assignment_sequence.to_le_bytes());
    for hash in [
        &job.previous_block,
        &job.merkle_root,
        &job.witness_root,
        &job.tree_root,
        &job.reserved_root,
    ] {
        bytes.extend_from_slice(hash);
    }
    bytes.extend_from_slice(&job.version.to_le_bytes());
    bytes.extend_from_slice(&job.bits.to_le_bytes());
    bytes.extend_from_slice(&job.ntime.to_le_bytes());
    bytes.extend_from_slice(&job.mask_hash);
    bytes.extend_from_slice(&job.leading_zero_prefix_q.to_le_bytes());
    bytes.extend_from_slice(&job.blind_band_bits_d.to_le_bytes());
    bytes.extend_from_slice(&job.capture_target);
    bytes.extend_from_slice(&job.advertised_device_target);
    bytes.extend_from_slice(&job.advertised_difficulty.to_le_bytes());
    bytes.extend_from_slice(&job.issued_ms.to_le_bytes());
    bytes.extend_from_slice(&job.assignment_end_ms.to_le_bytes());
    bytes.extend_from_slice(&job.submission_end_ms.to_le_bytes());
    bytes.extend_from_slice(&(job.transaction_hashes.len() as u64).to_le_bytes());
    for transaction_hash in &job.transaction_hashes {
        bytes.extend_from_slice(transaction_hash);
    }
    bytes
}

fn decode_durable_job(bytes: &[u8]) -> Result<GatewayJob, GatewayError> {
    let mut reader = DurableReader::new(bytes);
    let id_length = reader.bounded_length(64)?;
    let id = reader.string(id_length)?;
    let assignment_sequence = reader.u64()?;
    let previous_block = reader.hash()?;
    let merkle_root = reader.hash()?;
    let witness_root = reader.hash()?;
    let tree_root = reader.hash()?;
    let reserved_root = reader.hash()?;
    let version = reader.u32()?;
    let bits = reader.u32()?;
    let ntime = reader.u32()?;
    let mask_hash = reader.hash()?;
    let leading_zero_prefix_q = reader.u16()?;
    let blind_band_bits_d = reader.u16()?;
    let capture_target = reader.hash()?;
    let advertised_device_target = reader.hash()?;
    let advertised_difficulty = reader.u32()?;
    let issued_ms = reader.u64()?;
    let assignment_end_ms = reader.u64()?;
    let submission_end_ms = reader.u64()?;
    let transaction_count = reader.bounded_length(MAX_JOB_TRANSACTIONS)?;
    let mut transaction_hashes = Vec::with_capacity(transaction_count);
    for _ in 0..transaction_count {
        transaction_hashes.push(reader.hash()?);
    }
    reader.finish()?;
    Ok(GatewayJob {
        id,
        assignment_sequence,
        previous_block,
        merkle_root,
        witness_root,
        tree_root,
        reserved_root,
        version,
        bits,
        ntime,
        mask_hash,
        leading_zero_prefix_q,
        blind_band_bits_d,
        capture_target,
        advertised_device_target,
        advertised_difficulty,
        issued_ms,
        assignment_end_ms,
        submission_end_ms,
        transaction_hashes,
    })
}

fn encode_durable_job_state(state: JobState) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + 2 + 1 + 16);
    bytes.extend_from_slice(&ASSIGNMENT_STATE_MAGIC);
    bytes.extend_from_slice(&ASSIGNMENT_STATE_VERSION.to_le_bytes());
    match state {
        JobState::Active => bytes.push(0),
        JobState::Grace {
            credit_cutoff_ms,
            submission_end_ms,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&credit_cutoff_ms.to_le_bytes());
            bytes.extend_from_slice(&submission_end_ms.to_le_bytes());
        }
        JobState::Closed => bytes.push(2),
    }
    bytes
}

fn decode_durable_job_state(bytes: &[u8]) -> Result<JobState, GatewayError> {
    let mut reader = DurableReader::new(bytes);
    if reader.take(4)? != ASSIGNMENT_STATE_MAGIC || reader.u16()? != ASSIGNMENT_STATE_VERSION {
        return Err(GatewayError::InvalidDurableState);
    }
    let state = match reader.byte()? {
        0 => JobState::Active,
        1 => JobState::Grace {
            credit_cutoff_ms: reader.u64()?,
            submission_end_ms: reader.u64()?,
        },
        2 => JobState::Closed,
        _ => return Err(GatewayError::InvalidDurableState),
    };
    reader.finish()?;
    Ok(state)
}

fn encode_capture_tombstone(assignment_sequence: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(14);
    bytes.extend_from_slice(&CAPTURE_TOMBSTONE_MAGIC);
    bytes.extend_from_slice(&CAPTURE_TOMBSTONE_VERSION.to_le_bytes());
    bytes.extend_from_slice(&assignment_sequence.to_le_bytes());
    bytes
}

fn decode_capture_tombstone(bytes: &[u8]) -> Result<u64, GatewayError> {
    let mut reader = DurableReader::new(bytes);
    if reader.take(4)? != CAPTURE_TOMBSTONE_MAGIC {
        return Err(GatewayError::InvalidDurableState);
    }
    let version = reader.u16()?;
    match (version, bytes.len()) {
        (CAPTURE_TOMBSTONE_VERSION, 14) => {
            let assignment_sequence = reader.u64()?;
            reader.finish()?;
            Ok(assignment_sequence)
        }
        _ => Err(GatewayError::InvalidDurableState),
    }
}

fn encode_durable_capture(capture: &ForwardedCapture) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        4 + 2
            + 2
            + capture.username.len()
            + 2
            + capture.job_id.len()
            + 8
            + MINER_HEADER_SIZE
            + 32
            + 8
            + 2,
    );
    bytes.extend_from_slice(&CAPTURE_MAGIC);
    bytes.extend_from_slice(&CAPTURE_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(capture.username.len() as u16).to_le_bytes());
    bytes.extend_from_slice(capture.username.as_bytes());
    bytes.extend_from_slice(&(capture.job_id.len() as u16).to_le_bytes());
    bytes.extend_from_slice(capture.job_id.as_bytes());
    bytes.extend_from_slice(&capture.assignment_sequence.to_le_bytes());
    bytes.extend_from_slice(&capture.miner_header.to_bytes());
    bytes.extend_from_slice(&capture.raw_share_hash);
    bytes.extend_from_slice(&capture.received_ms.to_le_bytes());
    bytes.push(u8::from(capture.credit_eligible));
    bytes.push(capture.telemetry_level as u8);
    bytes
}

fn decode_durable_capture(bytes: &[u8]) -> Result<ForwardedCapture, GatewayError> {
    let mut reader = DurableReader::new(bytes);
    if reader.take(4)? != CAPTURE_MAGIC || reader.u16()? != CAPTURE_VERSION {
        return Err(GatewayError::InvalidDurableState);
    }
    let username_length = usize::from(reader.u16()?);
    if username_length == 0 || username_length > 100 {
        return Err(GatewayError::InvalidDurableState);
    }
    let username = reader.string(username_length)?;
    let job_id_length = usize::from(reader.u16()?);
    if !(12..=64).contains(&job_id_length) {
        return Err(GatewayError::InvalidDurableState);
    }
    let job_id = reader.string(job_id_length)?;
    let assignment_sequence = reader.u64()?;
    let miner_header = MinerHeader::from_bytes(reader.take(MINER_HEADER_SIZE)?)
        .map_err(|_| GatewayError::InvalidDurableState)?;
    let raw_share_hash = reader.hash()?;
    let received_ms = reader.u64()?;
    let credit_eligible = match reader.byte()? {
        0 => false,
        1 => true,
        _ => return Err(GatewayError::InvalidDurableState),
    };
    let telemetry_level = match reader.byte()? {
        0 => TelemetryLevel::StockAsic,
        1 => TelemetryLevel::ObservableController,
        2 => TelemetryLevel::RangeProgrammable,
        3 => TelemetryLevel::AuditableHardware,
        _ => return Err(GatewayError::InvalidDurableState),
    };
    reader.finish()?;
    Ok(ForwardedCapture {
        username,
        job_id,
        assignment_sequence,
        miner_header,
        raw_share_hash,
        received_ms,
        credit_eligible,
        telemetry_level,
    })
}

struct DurableReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> DurableReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], GatewayError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(GatewayError::InvalidDurableState)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(GatewayError::InvalidDurableState)?;
        self.cursor = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, GatewayError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, GatewayError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| GatewayError::InvalidDurableState)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, GatewayError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| GatewayError::InvalidDurableState)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, GatewayError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| GatewayError::InvalidDurableState)?,
        ))
    }

    fn bounded_length(&mut self, maximum: usize) -> Result<usize, GatewayError> {
        let value = usize::try_from(self.u64()?).map_err(|_| GatewayError::InvalidDurableState)?;
        if value > maximum {
            return Err(GatewayError::InvalidDurableState);
        }
        Ok(value)
    }

    fn hash(&mut self) -> Result<Hash256, GatewayError> {
        self.take(32)?
            .try_into()
            .map_err(|_| GatewayError::InvalidDurableState)
    }

    fn string(&mut self, length: usize) -> Result<String, GatewayError> {
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| GatewayError::InvalidDurableState)
    }

    fn finish(self) -> Result<(), GatewayError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(GatewayError::InvalidDurableState)
        }
    }
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"id": id, "result": result, "error": null})
}

fn rpc_error(id: Value, code: u16, reason: &'static str) -> Value {
    json!({"id": id, "result": null, "error": [code, reason, false]})
}

#[cfg(test)]
mod tests;
