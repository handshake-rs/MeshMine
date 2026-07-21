use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use meshmine_gateway::{
    DeviceProfile, Gateway, GatewayError, GatewayEvent, GatewayJob, HardwareEvidence,
    PreviousJobTransition, RpcSession, SharedRpcControl, serve_rpc_connection_shared,
};
use meshmine_hns::Hash256;
use meshmine_service::{
    CoreCaptureReceiptV1, GatewayStatusView, HealthSample, OperatorCountersView, OperatorSnapshot,
    ReceiptBackedCaptureConsumer, ServiceEventJournal, ServiceMode, Supervisor, SupervisorPolicy,
    dashboard_html, initialize_service_store, json_response,
};
use meshmine_storage::{DurableStore, RedbStore};
use meshmine_types::domain_hash;
use serde::Deserialize;

const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_JOB_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PASSWORD_FILE_BYTES: u64 = 1_024;
const MAX_HTTP_REQUEST_LINE: usize = 8 * 1024;
const MAX_HTTP_CONNECTIONS: usize = 128;
const MAX_PROFILE_CONNECTIONS: usize = 4_096;
const MAX_PROFILE_REQUESTS: usize = 1_000_000;
const MAX_CAPTURE_DRAIN_BATCH: usize = 10_000;
const PRODUCTION_ELIGIBLE: bool = false;
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(35);
const MAX_FALLBACK_ENDPOINTS: usize = 32;
const MAX_FALLBACK_ENDPOINT_BYTES: usize = 2_048;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorConfig {
    gateway_listen: String,
    dashboard_listen: String,
    gateway_state: PathBuf,
    service_state: PathBuf,
    job_file: PathBuf,
    password_file: PathBuf,
    username: String,
    profile: String,
    network_id: u8,
    core_receipt_pubkey: String,
    #[serde(default)]
    fallback_endpoints: Vec<String>,
    #[serde(default = "default_poll_interval_ms")]
    poll_interval_ms: u64,
    #[serde(default = "default_job_reload_interval_ms")]
    job_reload_interval_ms: u64,
    #[serde(default = "default_max_connections")]
    maximum_connections: usize,
    #[serde(default = "default_max_requests")]
    maximum_requests_per_connection: usize,
    #[serde(default = "default_capture_drain_batch")]
    capture_drain_batch: usize,
    #[serde(default = "default_max_auth_failures")]
    maximum_authorization_failures: u16,
    #[serde(default = "default_unhealthy_samples")]
    unhealthy_samples_before_fallback: u32,
    #[serde(default = "default_healthy_samples")]
    healthy_samples_before_restore: u32,
    #[serde(default = "default_fallback_hold_ms")]
    minimum_fallback_hold_ms: u64,
    #[serde(default = "default_capture_soft_limit")]
    capture_backlog_soft_limit: usize,
    #[serde(default = "default_capture_hard_limit")]
    capture_backlog_hard_limit: usize,
    #[serde(default = "default_event_capacity")]
    event_capacity: usize,
    #[serde(default)]
    production: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JobFile {
    id: String,
    previous_block: String,
    merkle_root: String,
    witness_root: String,
    tree_root: String,
    reserved_root: String,
    version: u32,
    bits: u32,
    ntime: u32,
    mask_hash: String,
    leading_zero_prefix_q: u16,
    blind_band_bits_d: u16,
    capture_target: String,
    advertised_device_target: String,
    advertised_difficulty: u32,
    issued_ms: u64,
    assignment_end_ms: u64,
    submission_end_ms: u64,
    #[serde(default)]
    transaction_hashes: Vec<String>,
    #[serde(default)]
    previous_job_transition: Option<PreviousJobTransitionFile>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviousJobTransitionFile {
    job_id: String,
    credit_cutoff_ms: u64,
    submission_end_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct ServiceCounters {
    accepted_captures: u64,
    rejected_submissions: u64,
    job_issues: u64,
    job_cancellations: u64,
    failovers: u64,
}

impl From<ServiceCounters> for OperatorCountersView {
    fn from(value: ServiceCounters) -> Self {
        Self {
            accepted_captures: value.accepted_captures,
            rejected_submissions: value.rejected_submissions,
            job_issues: value.job_issues,
            job_cancellations: value.job_cancellations,
            failovers: value.failovers,
        }
    }
}

struct AtomicTaskGuard(Arc<AtomicUsize>);

impl Drop for AtomicTaskGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct ListenerAliveGuard(Arc<AtomicBool>);

impl Drop for ListenerAliveGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("meshmine-operatord: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        Some("serve") => serve_command(&arguments[1..]).await,
        Some("import-core-receipt") => import_receipt_command(&arguments[1..]),
        _ => Err(usage().into()),
    }
}

async fn serve_command(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let config_path = single_path_argument(arguments, "--config")?;
    let config: OperatorConfig = serde_json::from_slice(&read_secure_file(
        config_path,
        MAX_CONFIG_BYTES,
        false,
        "operator config",
    )?)?;
    validate_config(&config)?;
    if config.production {
        return Err("standalone operator service is pre-production and ACK-only".into());
    }

    let gateway_address: SocketAddr = config.gateway_listen.parse()?;
    let dashboard_address: SocketAddr = config.dashboard_listen.parse()?;
    validate_loopback(gateway_address, "gateway")?;
    validate_loopback(dashboard_address, "dashboard")?;
    let initial_password = read_password(&config.password_file)?;
    let mut password_fingerprint = meshmine_hns::blake2b_256(&[initial_password.as_bytes()]);
    drop(initial_password);
    let mut credentials_available = true;
    let mut credentials_error_reported = false;
    let profile = profile(&config.profile)?;
    let core_receipt_pubkey = nonzero_hash(&config.core_receipt_pubkey, "Core receipt public key")?;

    let gateway_store = open_store(&config.gateway_state)?;
    let service_store = open_store(&config.service_state)?;
    initialize_service_store(&service_store, config.network_id, &core_receipt_pubkey)?;
    let mut gateway = if profile.hardware_evidence() == HardwareEvidence::SimulatorOnly {
        Gateway::open_research_simulator(gateway_store)?
    } else {
        Gateway::open(gateway_store)?
    };
    let (job, transition, job_fingerprint) = load_job_file(&config.job_file)?;
    validate_job_window(&job, wall_ms()?)?;
    gateway.close_expired(wall_ms()?)?;
    let sequence = gateway.issue_job_with_transition(job, transition)?;
    let worker_id = domain_hash("meshmine/gateway-worker/v2", config.username.as_bytes());
    let initial_prefix = gateway.assignment_nonce_prefix(&worker_id, sequence)?;

    let gateway = Arc::new(Mutex::new(gateway));
    let nonce_prefix = Arc::new(RwLock::new(initial_prefix));
    let control = Arc::new(SharedRpcControl::new(
        config.maximum_authorization_failures,
    )?);
    let shutdown = Arc::new(AtomicBool::new(false));
    let active_accept_tasks = Arc::new(AtomicUsize::new(0));
    let gateway_listener_alive = Arc::new(AtomicBool::new(false));
    let dashboard_listener_alive = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(Mutex::new(ServiceCounters::default()));
    let snapshot = Arc::new(RwLock::new(initial_snapshot(
        &config,
        gateway
            .lock()
            .map_err(|_| "gateway lock poisoned")?
            .status()
            .into(),
        wall_ms()?,
    )));
    let journal = Arc::new(ServiceEventJournal::new(
        service_store.clone(),
        config.event_capacity,
    )?);
    journal.append(
        wall_ms()?,
        "service-start",
        format!(
            "Standalone operator service started with profile {}",
            config.profile
        ),
    )?;

    let receipt_consumer = Arc::new(Mutex::new(ReceiptBackedCaptureConsumer::new(
        service_store.clone(),
        config.network_id,
        core_receipt_pubkey,
    )));

    let gateway_thread = spawn_gateway_listener(
        gateway_address,
        config.clone(),
        profile.clone(),
        gateway.clone(),
        nonce_prefix.clone(),
        control.clone(),
        shutdown.clone(),
        active_accept_tasks.clone(),
        gateway_listener_alive.clone(),
        journal.clone(),
    )?;
    let dashboard_thread = spawn_dashboard_listener(
        dashboard_address,
        snapshot.clone(),
        shutdown.clone(),
        dashboard_listener_alive.clone(),
    )?;

    let supervisor_policy = SupervisorPolicy {
        unhealthy_samples_before_fallback: config.unhealthy_samples_before_fallback,
        healthy_samples_before_restore: config.healthy_samples_before_restore,
        minimum_fallback_hold_ms: config.minimum_fallback_hold_ms,
        capture_backlog_soft_limit: config.capture_backlog_soft_limit,
        capture_backlog_hard_limit: config.capture_backlog_hard_limit,
    };
    let mut supervisor = Supervisor::new(supervisor_policy, wall_ms()?)?;
    let mut last_observed_job_fingerprint = job_fingerprint;
    let mut last_job_reload_ms = 0u64;
    let mut next_fallback_index = 0usize;
    let mut active_fallback_endpoint: Option<String> = None;

    let mut interval = tokio::time::interval(Duration::from_millis(config.poll_interval_ms));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                shutdown.store(true, Ordering::SeqCst);
                control.request_shutdown();
                if let Some(transition) = supervisor.begin_draining(wall_ms()?) {
                    journal.append_transition(&transition)?;
                }
                break;
            }
            _ = interval.tick() => {
                let now_ms = wall_ms()?;
                if now_ms.saturating_sub(last_job_reload_ms) >= config.job_reload_interval_ms {
                    last_job_reload_ms = now_ms;

                    match read_password(&config.password_file) {
                        Ok(password) => {
                            let fingerprint = meshmine_hns::blake2b_256(&[password.as_bytes()]);
                            if fingerprint != password_fingerprint {
                                password_fingerprint = fingerprint;
                                control.rotate_connections();
                                journal.append(
                                    now_ms,
                                    "credentials-rotated",
                                    "gateway password changed; active sessions were rotated",
                                )?;
                            }
                            if !credentials_available {
                                journal.append(
                                    now_ms,
                                    "credentials-restored",
                                    "gateway password file is readable again",
                                )?;
                            }
                            credentials_available = true;
                            credentials_error_reported = false;
                        }
                        Err(error) => {
                            credentials_available = false;
                            if !credentials_error_reported {
                                journal.append(
                                    now_ms,
                                    "credentials-unavailable",
                                    error.to_string(),
                                )?;
                                credentials_error_reported = true;
                            }
                        }
                    }

                    match load_job_file(&config.job_file) {
                        Ok((job, transition, fingerprint)) if fingerprint != last_observed_job_fingerprint => {
                            last_observed_job_fingerprint = fingerprint;
                            let installation = (|| -> Result<(u64, [u8; 4]), Box<dyn Error>> {
                                validate_job_window(&job, now_ms)?;
                                let sequence = {
                                    let mut locked = gateway
                                        .lock()
                                        .map_err(|_| "gateway lock poisoned")?;
                                    locked.close_expired(now_ms)?;
                                    locked.issue_job_with_transition(job, transition)?
                                };
                                let prefix = gateway
                                    .lock()
                                    .map_err(|_| "gateway lock poisoned")?
                                    .assignment_nonce_prefix(&worker_id, sequence)?;
                                Ok((sequence, prefix))
                            })();
                            match installation {
                                Ok((sequence, prefix)) => {
                                    *nonce_prefix
                                        .write()
                                        .map_err(|_| "nonce-prefix lock poisoned")? = prefix;
                                    control.rotate_connections();
                                    journal.append(
                                        now_ms,
                                        "job-reloaded",
                                        format!("installed assignment sequence {sequence}"),
                                    )?;
                                }
                                Err(error) => {
                                    journal.append(
                                        now_ms,
                                        "job-reload-rejected",
                                        error.to_string(),
                                    )?;
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            journal.append(now_ms, "job-reload-error", error.to_string())?;
                        }
                    }
                }

                let (capture_drain, gateway_events) = {
                    let mut locked = gateway.lock().map_err(|_| "gateway lock poisoned")?;
                    let mut consumer = receipt_consumer
                        .lock()
                        .map_err(|_| "receipt consumer lock poisoned")?;
                    let capture_drain =
                        locked.drain_captures_durably(&mut *consumer, config.capture_drain_batch);
                    let gateway_events = locked.drain_events(meshmine_gateway::MAX_GATEWAY_EVENTS);
                    (capture_drain, gateway_events)
                };
                match capture_drain {
                    Ok(report) if report.acknowledged > 0 => {
                        journal.append(
                            now_ms,
                            "capture-drain",
                            format!(
                                "acknowledged {} Core-admitted captures",
                                report.acknowledged
                            ),
                        )?;
                    }
                    Ok(_) | Err(GatewayError::CaptureConsumerUnavailable) => {}
                    Err(error) => {
                        journal.append(now_ms, "capture-drain-error", error.to_string())?;
                    }
                }
                observe_gateway_events(&gateway_events, &counters, &journal, now_ms)?;

                let gateway_status = gateway
                    .lock()
                    .map_err(|_| "gateway lock poisoned")?
                    .status();
                let receipt_store_available = service_store
                    .get(meshmine_service::CORE_CAPTURE_RECEIPT_NAMESPACE, "health-probe")
                    .is_ok();
                let sample = HealthSample {
                    now_ms,
                    gateway_available: gateway_listener_alive.load(Ordering::SeqCst),
                    receipt_store_available,
                    credentials_available,
                    core_link_available: true,
                    drain_pending: false,
                    authorization_failure_limit: control.fallback_active()
                        && control.authorization_failures() >= config.maximum_authorization_failures,
                    current_job_id: gateway_status.current_job_id.clone(),
                    job_issued_ms: gateway_status.current_issued_ms,
                    assignment_end_ms: gateway_status.current_assignment_end_ms,
                    pending_captures: gateway_status.pending_captures,
                    shutdown_requested: shutdown.load(Ordering::SeqCst),
                };
                if let Some(transition) = supervisor.sample(sample) {
                    journal.append_transition(&transition)?;
                    match transition.to {
                        ServiceMode::Fallback => {
                            control.set_fallback(true);
                            control.rotate_connections();
                            if config.fallback_endpoints.is_empty() {
                                active_fallback_endpoint = None;
                            } else {
                                let endpoint = config.fallback_endpoints
                                    [next_fallback_index % config.fallback_endpoints.len()]
                                    .clone();
                                next_fallback_index =
                                    (next_fallback_index + 1) % config.fallback_endpoints.len();
                                gateway
                                    .lock()
                                    .map_err(|_| "gateway lock poisoned")?
                                    .record_failover(&endpoint);
                                active_fallback_endpoint = Some(endpoint);
                            }
                        }
                        ServiceMode::Mining => {
                            control.set_fallback(false);
                            active_fallback_endpoint = None;
                        },
                        ServiceMode::Draining | ServiceMode::Stopped => control.request_shutdown(),
                        ServiceMode::Bootstrapping | ServiceMode::Degraded => {}
                    }
                }

                let events = journal.recent(100)?;
                let fallback_endpoint = if supervisor.snapshot().mode == ServiceMode::Fallback {
                    active_fallback_endpoint.clone()
                } else {
                    None
                };
                let counter_snapshot = *counters
                    .lock()
                    .map_err(|_| "counter lock poisoned")?;
                let new_snapshot = OperatorSnapshot {
                    generated_at_ms: now_ms,
                    supervisor: supervisor.snapshot().clone(),
                    gateway: gateway_status.into(),
                    gateway_listen: config.gateway_listen.clone(),
                    dashboard_listen: config.dashboard_listen.clone(),
                    active_connections: control.active_connections(),
                    authorization_failures: control.authorization_failures(),
                    gateway_listener_alive: gateway_listener_alive.load(Ordering::SeqCst),
                    dashboard_listener_alive: dashboard_listener_alive.load(Ordering::SeqCst),
                    credentials_available,
                    core_link_connected: false,
                    core_link_last_message_ms: None,
                    active_bundle_id: None,
                    pending_bundle_id: None,
                    assignment_drain_pending: false,
                    counters: counter_snapshot.into(),
                    fallback_endpoint,
                    production_eligible: PRODUCTION_ELIGIBLE,
                    authority_note: "Observation-only operator composition. It distributes already-bound local gateway work and acknowledges captures only after an immutable Core receipt exists; it cannot create assignments, shares, masks, or native mainnet authority.".to_owned(),
                    events,
                };
                *snapshot.write().map_err(|_| "snapshot lock poisoned")? = new_snapshot;
            }
        }
    }

    let shutdown_started = Instant::now();
    while active_accept_tasks.load(Ordering::SeqCst) > 0
        && shutdown_started.elapsed() < GRACEFUL_SHUTDOWN_TIMEOUT
    {
        thread::sleep(Duration::from_millis(25));
    }
    if active_accept_tasks.load(Ordering::SeqCst) > 0 {
        journal.append(
            wall_ms()?,
            "shutdown-timeout",
            format!(
                "{} gateway sessions remained after the graceful shutdown deadline",
                active_accept_tasks.load(Ordering::SeqCst)
            ),
        )?;
    }
    join_service_thread(gateway_thread, "gateway listener")?;
    join_service_thread(dashboard_thread, "dashboard listener")?;
    if let Some(transition) = supervisor.stop(wall_ms()?) {
        journal.append_transition(&transition)?;
    }
    Ok(())
}

fn import_receipt_command(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let config_path = PathBuf::from(named_argument(arguments, "--config")?);
    let receipt_path = PathBuf::from(named_argument(arguments, "--receipt")?);
    let config: OperatorConfig = serde_json::from_slice(&read_secure_file(
        &config_path,
        MAX_CONFIG_BYTES,
        false,
        "operator config",
    )?)?;
    validate_config(&config)?;
    let core_receipt_pubkey = nonzero_hash(&config.core_receipt_pubkey, "Core receipt public key")?;
    validate_absolute(&receipt_path, "Core receipt")?;
    let receipt: CoreCaptureReceiptV1 = serde_json::from_slice(&read_secure_file(
        &receipt_path,
        64 * 1024,
        false,
        "Core receipt",
    )?)?;
    receipt.validate(config.network_id, &core_receipt_pubkey)?;
    let store = open_store(&config.service_state)?;
    initialize_service_store(&store, config.network_id, &core_receipt_pubkey)?;
    let consumer = ReceiptBackedCaptureConsumer::new(store, config.network_id, core_receipt_pubkey);
    consumer.record_core_receipt(&receipt)?;
    println!(
        "imported signed Core receipt {} for work {}",
        hex::encode(receipt.receipt_id),
        hex::encode(receipt.work_key)
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_gateway_listener(
    address: SocketAddr,
    config: OperatorConfig,
    profile: DeviceProfile,
    gateway: Arc<Mutex<Gateway>>,
    nonce_prefix: Arc<RwLock<[u8; 4]>>,
    control: Arc<SharedRpcControl>,
    shutdown: Arc<AtomicBool>,
    active_tasks: Arc<AtomicUsize>,
    listener_alive: Arc<AtomicBool>,
    journal: Arc<ServiceEventJournal>,
) -> Result<thread::JoinHandle<Result<(), String>>, Box<dyn Error>> {
    let listener = TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    Ok(thread::spawn(move || {
        listener_alive.store(true, Ordering::SeqCst);
        let _alive_guard = ListenerAliveGuard(listener_alive);
        while !shutdown.load(Ordering::SeqCst) && !control.shutdown_requested() {
            match listener.accept() {
                Ok((stream, peer)) => {
                    if !peer.ip().is_loopback() || control.fallback_active() {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                    if active_tasks.load(Ordering::SeqCst) >= config.maximum_connections {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                    active_tasks.fetch_add(1, Ordering::SeqCst);
                    let active_tasks = active_tasks.clone();
                    let gateway = gateway.clone();
                    let control = control.clone();
                    let profile = profile.clone();
                    let username = config.username.clone();
                    let password = match read_password(&config.password_file) {
                        Ok(password) => password,
                        Err(error) => {
                            active_tasks.fetch_sub(1, Ordering::SeqCst);
                            let _ = journal.append(
                                wall_ms().unwrap_or(0),
                                "password-read-error",
                                error.to_string(),
                            );
                            continue;
                        }
                    };
                    let prefix = match nonce_prefix.read() {
                        Ok(prefix) => *prefix,
                        Err(_) => {
                            active_tasks.fetch_sub(1, Ordering::SeqCst);
                            continue;
                        }
                    };
                    let max_requests = config.maximum_requests_per_connection;
                    let update_interval = Duration::from_millis(config.poll_interval_ms.max(10));
                    let session_journal = journal.clone();
                    thread::spawn(move || {
                        let _task_guard = AtomicTaskGuard(active_tasks);
                        let session = RpcSession::new(username, password, prefix, profile);
                        let result = serve_rpc_connection_shared(
                            stream,
                            session,
                            gateway,
                            control,
                            max_requests,
                            update_interval,
                        );
                        if let Err(error) = result {
                            let _ = session_journal.append(
                                wall_ms().unwrap_or(0),
                                "gateway-session-error",
                                error.to_string(),
                            );
                        }
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }))
}

fn spawn_dashboard_listener(
    address: SocketAddr,
    snapshot: Arc<RwLock<OperatorSnapshot>>,
    shutdown: Arc<AtomicBool>,
    listener_alive: Arc<AtomicBool>,
) -> Result<thread::JoinHandle<Result<(), String>>, Box<dyn Error>> {
    let listener = TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    Ok(thread::spawn(move || {
        listener_alive.store(true, Ordering::SeqCst);
        let _alive_guard = ListenerAliveGuard(listener_alive);
        let active = Arc::new(AtomicUsize::new(0));
        while !shutdown.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, peer)) => {
                    if !peer.ip().is_loopback()
                        || active.load(Ordering::SeqCst) >= MAX_HTTP_CONNECTIONS
                    {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                    active.fetch_add(1, Ordering::SeqCst);
                    let active = active.clone();
                    let snapshot = snapshot.clone();
                    thread::spawn(move || {
                        let _task_guard = AtomicTaskGuard(active);
                        let _ = serve_http(stream, snapshot);
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }))
}

fn serve_http(
    mut stream: TcpStream,
    snapshot: Arc<RwLock<OperatorSnapshot>>,
) -> Result<(), Box<dyn Error>> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    let mut limited = std::io::Read::take(&mut reader, (MAX_HTTP_REQUEST_LINE + 1) as u64);
    limited.read_line(&mut line)?;
    if line.len() > MAX_HTTP_REQUEST_LINE {
        return write_http(
            &mut stream,
            413,
            "text/plain; charset=utf-8",
            b"request too large",
        );
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    if method != "GET" {
        return write_http(
            &mut stream,
            405,
            "text/plain; charset=utf-8",
            b"method not allowed",
        );
    }
    match path {
        "/" => write_http(
            &mut stream,
            200,
            "text/html; charset=utf-8",
            dashboard_html().as_bytes(),
        ),
        "/api/v1/status" => {
            let snapshot = snapshot.read().map_err(|_| "snapshot lock poisoned")?;
            let bytes = json_response(&snapshot)?;
            write_http(&mut stream, 200, "application/json", &bytes)
        }
        "/api/v1/health" => {
            let snapshot = snapshot.read().map_err(|_| "snapshot lock poisoned")?;
            let healthy = matches!(
                snapshot.supervisor.mode,
                ServiceMode::Mining | ServiceMode::Degraded
            );
            let code = if healthy { 200 } else { 503 };
            let body = if healthy {
                b"healthy".as_slice()
            } else {
                b"unhealthy".as_slice()
            };
            write_http(&mut stream, code, "text/plain; charset=utf-8", body)
        }
        _ => write_http(&mut stream, 404, "text/plain; charset=utf-8", b"not found"),
    }
}

fn write_http(
    stream: &mut TcpStream,
    code: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), Box<dyn Error>> {
    let reason = match code {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn observe_gateway_events(
    events: &[GatewayEvent],
    counters: &Arc<Mutex<ServiceCounters>>,
    journal: &ServiceEventJournal,
    now_ms: u64,
) -> Result<(), Box<dyn Error>> {
    let mut capture_count = 0u64;
    let mut rejection_count = 0u64;
    let mut latest_capture = None::<String>;
    let mut latest_rejection = None::<String>;
    let mut durable_events = Vec::<(&'static str, String)>::new();

    {
        let mut counters = counters.lock().map_err(|_| "counter lock poisoned")?;
        for event in events {
            match event {
                GatewayEvent::JobIssued {
                    job_id,
                    assignment_sequence,
                } => {
                    counters.job_issues = counters.job_issues.saturating_add(1);
                    durable_events.push((
                        "gateway-job-issued",
                        format!("{job_id} sequence {assignment_sequence}"),
                    ));
                }
                GatewayEvent::JobCancelled { job_id, .. } => {
                    counters.job_cancellations = counters.job_cancellations.saturating_add(1);
                    durable_events.push(("gateway-job-cancelled", job_id.clone()));
                }
                GatewayEvent::CaptureForwarded {
                    job_id,
                    raw_share_hash,
                    credit_eligible,
                } => {
                    counters.accepted_captures = counters.accepted_captures.saturating_add(1);
                    capture_count = capture_count.saturating_add(1);
                    latest_capture = Some(format!(
                        "{job_id} {} credit={credit_eligible}",
                        hex::encode(raw_share_hash)
                    ));
                }
                GatewayEvent::SubmissionRejected { job_id, reason } => {
                    counters.rejected_submissions = counters.rejected_submissions.saturating_add(1);
                    rejection_count = rejection_count.saturating_add(1);
                    latest_rejection = Some(format!("{job_id}: {reason}"));
                }
                GatewayEvent::FailoverActivated { endpoint } => {
                    counters.failovers = counters.failovers.saturating_add(1);
                    durable_events.push(("gateway-failover", endpoint.clone()));
                }
            }
        }
    }

    if capture_count > 0 {
        durable_events.push((
            "gateway-capture-batch",
            format!(
                "observed {capture_count} captures; latest={}",
                latest_capture.as_deref().unwrap_or("unavailable")
            ),
        ));
    }
    if rejection_count > 0 {
        durable_events.push((
            "gateway-rejection-batch",
            format!(
                "observed {rejection_count} rejected submissions; latest={}",
                latest_rejection.as_deref().unwrap_or("unavailable")
            ),
        ));
    }
    for (kind, message) in durable_events {
        journal.append(now_ms, kind, message)?;
    }
    Ok(())
}

fn initial_snapshot(
    config: &OperatorConfig,
    gateway: GatewayStatusView,
    now_ms: u64,
) -> OperatorSnapshot {
    OperatorSnapshot {
        generated_at_ms: now_ms,
        supervisor: meshmine_service::SupervisorSnapshot {
            schema_version: meshmine_service::SERVICE_SCHEMA_VERSION,
            profile: meshmine_service::SERVICE_PROFILE.to_owned(),
            mode: ServiceMode::Bootstrapping,
            reason: meshmine_service::HealthReason::NoCurrentJob,
            transition_sequence: 0,
            changed_at_ms: now_ms,
            sampled_at_ms: now_ms,
            consecutive_healthy: 0,
            consecutive_unhealthy: 0,
            current_job_id: gateway.current_job_id.clone(),
            pending_captures: gateway.pending_captures,
        },
        gateway,
        gateway_listen: config.gateway_listen.clone(),
        dashboard_listen: config.dashboard_listen.clone(),
        active_connections: 0,
        authorization_failures: 0,
        gateway_listener_alive: false,
        dashboard_listener_alive: false,
        credentials_available: true,
        core_link_connected: false,
        core_link_last_message_ms: None,
        active_bundle_id: None,
        pending_bundle_id: None,
        assignment_drain_pending: false,
        counters: OperatorCountersView::default(),
        fallback_endpoint: None,
        production_eligible: PRODUCTION_ELIGIBLE,
        authority_note: "Observation-only standalone operator composition".to_owned(),
        events: Vec::new(),
    }
}

fn load_job_file(
    path: &Path,
) -> Result<(GatewayJob, Option<PreviousJobTransition>, Hash256), Box<dyn Error>> {
    let bytes = read_secure_file(path, MAX_JOB_FILE_BYTES, false, "gateway job")?;
    let fingerprint = meshmine_hns::blake2b_256(&[&bytes]);
    let value: JobFile = serde_json::from_slice(&bytes)?;
    let transition =
        value
            .previous_job_transition
            .as_ref()
            .map(|transition| PreviousJobTransition {
                job_id: transition.job_id.clone(),
                credit_cutoff_ms: transition.credit_cutoff_ms,
                submission_end_ms: transition.submission_end_ms,
            });
    let job = GatewayJob {
        id: value.id,
        assignment_sequence: 0,
        previous_block: hash(&value.previous_block)?,
        merkle_root: hash(&value.merkle_root)?,
        witness_root: hash(&value.witness_root)?,
        tree_root: hash(&value.tree_root)?,
        reserved_root: hash(&value.reserved_root)?,
        version: value.version,
        bits: value.bits,
        ntime: value.ntime,
        mask_hash: hash(&value.mask_hash)?,
        leading_zero_prefix_q: value.leading_zero_prefix_q,
        blind_band_bits_d: value.blind_band_bits_d,
        capture_target: hash(&value.capture_target)?,
        advertised_device_target: hash(&value.advertised_device_target)?,
        advertised_difficulty: value.advertised_difficulty,
        issued_ms: value.issued_ms,
        assignment_end_ms: value.assignment_end_ms,
        submission_end_ms: value.submission_end_ms,
        transaction_hashes: value
            .transaction_hashes
            .iter()
            .map(|hash_value| hash(hash_value))
            .collect::<Result<Vec<_>, _>>()?,
    };
    Ok((job, transition, fingerprint))
}

fn validate_config(config: &OperatorConfig) -> Result<(), Box<dyn Error>> {
    for (path, name) in [
        (&config.gateway_state, "gateway state"),
        (&config.service_state, "service state"),
        (&config.job_file, "job file"),
        (&config.password_file, "password file"),
    ] {
        validate_absolute(path, name)?;
    }
    if config.gateway_state == config.service_state {
        return Err("gateway and service state databases must be separate files".into());
    }
    if config.username.is_empty() || config.username.len() > 100 {
        return Err("username must contain 1..100 UTF-8 bytes".into());
    }
    nonzero_hash(&config.core_receipt_pubkey, "Core receipt public key")?;
    if config.poll_interval_ms < 10
        || config.job_reload_interval_ms < config.poll_interval_ms
        || config.maximum_connections == 0
        || config.maximum_connections > MAX_PROFILE_CONNECTIONS
        || config.maximum_requests_per_connection == 0
        || config.maximum_requests_per_connection > MAX_PROFILE_REQUESTS
        || config.capture_drain_batch == 0
        || config.capture_drain_batch > MAX_CAPTURE_DRAIN_BATCH
        || config.event_capacity == 0
        || config.event_capacity > 100_000
    {
        return Err("operator service resource bound is invalid".into());
    }
    if config.maximum_authorization_failures == 0
        || config.fallback_endpoints.len() > MAX_FALLBACK_ENDPOINTS
        || config.fallback_endpoints.iter().any(|endpoint| {
            endpoint.is_empty()
                || endpoint.len() > MAX_FALLBACK_ENDPOINT_BYTES
                || endpoint.chars().any(char::is_control)
        })
    {
        return Err("operator authorization or fallback configuration is invalid".into());
    }
    let mut unique_fallbacks = HashSet::new();
    if config
        .fallback_endpoints
        .iter()
        .any(|endpoint| !unique_fallbacks.insert(endpoint))
    {
        return Err("fallback endpoints must be unique".into());
    }
    Ok(())
}

fn validate_job_window(job: &GatewayJob, now_ms: u64) -> Result<(), Box<dyn Error>> {
    if now_ms < job.issued_ms || now_ms > job.assignment_end_ms {
        return Err("gateway job is outside its assignment window".into());
    }
    Ok(())
}

fn profile(value: &str) -> Result<DeviceProfile, Box<dyn Error>> {
    Ok(match value {
        "simulator" => DeviceProfile::simulator(),
        "handyminer" => DeviceProfile::handyminer_reference(),
        "hs3" => DeviceProfile::goldshell_hs3_experimental(),
        "goldshell" => DeviceProfile::goldshell_generic_experimental(),
        _ => return Err("unknown device profile".into()),
    })
}

fn open_store(path: &Path) -> Result<Arc<dyn DurableStore>, Box<dyn Error>> {
    validate_state_path(path)?;
    let existed = path.exists();
    let store: Arc<dyn DurableStore> = if existed {
        Arc::new(RedbStore::open_existing(path)?)
    } else {
        Arc::new(RedbStore::create(path)?)
    };
    #[cfg(unix)]
    if !existed {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    validate_state_path(path)?;
    Ok(store)
}

fn read_password(path: &Path) -> Result<String, Box<dyn Error>> {
    let bytes = read_secure_file(path, MAX_PASSWORD_FILE_BYTES, true, "password file")?;
    let mut password = String::from_utf8(bytes)?;
    while password.ends_with('\n') || password.ends_with('\r') {
        password.pop();
    }
    if password.is_empty()
        || password.len() > 255
        || password
            .chars()
            .any(|character| matches!(character, '\r' | '\n'))
    {
        return Err("password file must contain one 1..255 byte UTF-8 line".into());
    }
    Ok(password)
}

fn read_secure_file(
    path: &Path,
    maximum_bytes: u64,
    private: bool,
    description: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    validate_absolute(path, description)?;
    #[cfg(unix)]
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    #[cfg(not(unix))]
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(format!("{description} is not a bounded regular file").into());
    }
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no arguments and reads process credentials only.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid {
            return Err(format!("{description} must be owned by the effective user").into());
        }
        let forbidden = if private { 0o077 } else { 0o022 };
        if metadata.permissions().mode() & forbidden != 0 {
            return Err(format!("{description} permissions are too broad").into());
        }
        let current = fs::symlink_metadata(path)?;
        if current.file_type().is_symlink()
            || current.dev() != metadata.dev()
            || current.ino() != metadata.ino()
        {
            return Err(format!("{description} path changed during validation").into());
        }
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len().min(maximum_bytes))?);
    std::io::Read::take(&mut file, maximum_bytes.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(format!("{description} grew while being read").into());
    }
    #[cfg(unix)]
    {
        let current = file.metadata()?;
        if current.dev() != metadata.dev() || current.ino() != metadata.ino() {
            return Err(format!("{description} descriptor changed during read").into());
        }
    }
    Ok(bytes)
}

fn join_service_thread(
    handle: thread::JoinHandle<Result<(), String>>,
    name: &str,
) -> Result<(), Box<dyn Error>> {
    let result = handle
        .join()
        .map_err(|_| io::Error::other(format!("{name} thread panicked")))?;
    result.map_err(|error| io::Error::other(format!("{name} failed: {error}")))?;
    Ok(())
}

fn validate_state_path(path: &Path) -> Result<(), Box<dyn Error>> {
    validate_absolute(path, "state database")?;
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("state database must be a nonsymlink regular file".into());
    }
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no arguments and reads process credentials only.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid {
            return Err("state database must be owned by the effective user".into());
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err("state database must not be group- or world-writable".into());
        }
    }
    Ok(())
}

fn validate_loopback(address: SocketAddr, name: &str) -> Result<(), Box<dyn Error>> {
    if !address.ip().is_loopback() {
        return Err(format!("{name} listener must use an explicit loopback address").into());
    }
    Ok(())
}

fn validate_absolute(path: &Path, name: &str) -> Result<(), Box<dyn Error>> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!("{name} path must be absolute and contain no parent traversal").into());
    }
    Ok(())
}

fn hash(value: &str) -> Result<Hash256, Box<dyn Error>> {
    let bytes = hex::decode(value)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected 32 bytes, got {}", bytes.len()).into())
}

fn nonzero_hash(value: &str, name: &str) -> Result<Hash256, Box<dyn Error>> {
    let value = hash(value)?;
    if value == [0; 32] {
        return Err(format!("{name} must not be all zero").into());
    }
    Ok(value)
}

fn wall_ms() -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn single_path_argument<'a>(
    arguments: &'a [String],
    name: &str,
) -> Result<&'a Path, Box<dyn Error>> {
    if arguments.len() != 2 || arguments[0] != name {
        return Err(usage().into());
    }
    Ok(Path::new(&arguments[1]))
}

fn named_argument<'a>(arguments: &'a [String], name: &str) -> Result<&'a str, Box<dyn Error>> {
    const ALLOWED: &[&str] = &["--config", "--receipt"];
    if arguments.len() != 4 {
        return Err(usage().into());
    }
    let mut seen = HashSet::new();
    let mut found = None;
    for pair in arguments.chunks_exact(2) {
        let key = pair[0].as_str();
        let value = pair[1].as_str();
        if !ALLOWED.contains(&key) || !seen.insert(key) || value.starts_with("--") {
            return Err(usage().into());
        }
        if key == name {
            found = Some(value);
        }
    }
    found.ok_or_else(|| format!("missing {name}").into())
}

fn usage() -> String {
    "usage:\n  meshmine-operatord serve --config /absolute/operator.json\n  meshmine-operatord import-core-receipt --config /absolute/operator.json --receipt /absolute/core-receipt.json".to_owned()
}

const fn default_poll_interval_ms() -> u64 {
    250
}
const fn default_job_reload_interval_ms() -> u64 {
    1_000
}
const fn default_max_connections() -> usize {
    256
}
const fn default_max_requests() -> usize {
    100_000
}
const fn default_capture_drain_batch() -> usize {
    1_000
}
const fn default_max_auth_failures() -> u16 {
    32
}
const fn default_unhealthy_samples() -> u32 {
    3
}
const fn default_healthy_samples() -> u32 {
    5
}
const fn default_fallback_hold_ms() -> u64 {
    15_000
}
const fn default_capture_soft_limit() -> usize {
    10_000
}
const fn default_capture_hard_limit() -> usize {
    90_000
}
const fn default_event_capacity() -> usize {
    10_000
}
