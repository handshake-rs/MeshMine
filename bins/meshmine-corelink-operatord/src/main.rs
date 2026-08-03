use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use ipnet::IpNet;
use k256::ecdsa::SigningKey as Secp256k1SigningKey;
use meshmine_core_link::{
    ClientError, CoreAssignmentBundleV1, CoreLinkLimits, MAX_CORE_LINK_FRAME_BYTES,
    OperatorCaptureSpool, OperatorCoreLinkClient, TransportError, connect_authenticated,
};
use meshmine_gateway::{
    AuthorizedGatewayJobRequest, DeviceProfile, Gateway, GatewayEvent, HardwareEvidence,
    MAX_GATEWAY_EVENTS, RpcSession, SharedRpcControl, serve_rpc_connection_shared,
};
use meshmine_pool_stats::{
    EXPERIMENTAL_PROFILE_ID, MAX_SNAPSHOT_LIFETIME, PoolStatsDocumentV1, PoolStatsSnapshotV1,
    PublicMode, public_stats_html,
};
use meshmine_service::{
    GatewayStatusView, HealthSample, OperatorCountersView, OperatorSnapshot, ServiceEventJournal,
    ServiceMode, Supervisor, SupervisorPolicy, dashboard_html, initialize_service_store,
    json_response,
};
use meshmine_storage::{DurableStore, RedbStore};
use meshmine_types::{GatewayAssignmentV1, UnsignedObject};
use serde::Deserialize;

const MAX_CONFIG_BYTES: u64 = 128 * 1024;
const MAX_KEY_BYTES: u64 = 256;
const MAX_PASSWORD_BYTES: u64 = 1024;
const MAX_HTTP_REQUEST_LINE: usize = 4096;
const MAX_HTTP_CONNECTIONS: usize = 64;
const MAX_PUBLIC_STATS_CONNECTIONS: usize = 128;
const MAX_HNSA_OBJECT_BYTES: u64 = 1024;
const MAX_FALLBACK_ENDPOINTS: usize = 16;
const MAX_FALLBACK_ENDPOINT_BYTES: usize = 1024;
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(35);
const AUTHORITY_NOTE: &str = "Unified operator is pre-authority: Core bundles remain signed, live-parent-qualified, and production=false";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema_version: u16,
    production: bool,
    network_id: u8,
    core_socket_path: PathBuf,
    gateway_signing_key_file: PathBuf,
    pinned_core_pubkey: String,
    corelink_state: PathBuf,
    gateway_state: PathBuf,
    service_state: PathBuf,
    gateway_listen: String,
    #[serde(default)]
    gateway_allowed_cidrs: Vec<String>,
    dashboard_listen: String,
    #[serde(default)]
    public_stats: Option<PublicStatsConfig>,
    password_file: PathBuf,
    username: String,
    profile: String,
    #[serde(default)]
    fallback_endpoints: Vec<String>,
    #[serde(default = "default_poll_ms")]
    poll_interval_ms: u64,
    #[serde(default = "default_capture_batch")]
    capture_drain_batch: usize,
    #[serde(default = "default_connections")]
    maximum_connections: usize,
    #[serde(default = "default_requests")]
    maximum_requests_per_connection: usize,
    #[serde(default = "default_auth_failures")]
    maximum_authorization_failures: u16,
    #[serde(default = "default_unhealthy_samples")]
    unhealthy_samples_before_fallback: u32,
    #[serde(default = "default_healthy_samples")]
    healthy_samples_before_restore: u32,
    #[serde(default = "default_fallback_hold_ms")]
    minimum_fallback_hold_ms: u64,
    #[serde(default = "default_backlog_soft")]
    capture_backlog_soft_limit: usize,
    #[serde(default = "default_backlog_hard")]
    capture_backlog_hard_limit: usize,
    #[serde(default = "default_event_capacity")]
    event_capacity: usize,
    #[serde(default = "default_reconnect_initial_ms")]
    reconnect_initial_ms: u64,
    #[serde(default = "default_reconnect_maximum_ms")]
    reconnect_maximum_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicStatsConfig {
    listen: String,
    network_magic: u32,
    endpoint_signing_key_file: PathBuf,
    service_authorization_file: PathBuf,
    endpoint_delegation_file: PathBuf,
    authorization_id: String,
    delegation_id: String,
    endpoint_sequence: u64,
    delegation_expires_at: u64,
    #[serde(default = "default_public_stats_lifetime")]
    snapshot_lifetime_seconds: u64,
    #[serde(default = "default_public_stats_publish_interval_ms")]
    publish_interval_ms: u64,
}

struct PublicStatsPublisher {
    config: PublicStatsConfig,
    endpoint_key: Secp256k1SigningKey,
    service_authorization: Vec<u8>,
    endpoint_delegation: Vec<u8>,
    authorization_id: [u8; 32],
    delegation_id: [u8; 32],
    operator_id: [u8; 32],
    sequence_store: Arc<dyn DurableStore>,
    next_publish_at_ms: u64,
    disabled: bool,
}

#[derive(Default)]
struct ServiceCounters {
    accepted_captures: u64,
    rejected_submissions: u64,
    job_issues: u64,
    job_cancellations: u64,
    failovers: u64,
}

impl From<&ServiceCounters> for OperatorCountersView {
    fn from(value: &ServiceCounters) -> Self {
        Self {
            accepted_captures: value.accepted_captures,
            rejected_submissions: value.rejected_submissions,
            job_issues: value.job_issues,
            job_cancellations: value.job_cancellations,
            failovers: value.failovers,
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("meshmine-corelink-operatord: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.first().map(String::as_str) != Some("serve") {
        return Err(usage().into());
    }
    let config_path = flag_path(&arguments[1..], "--config")?;
    let config: Config = serde_json::from_slice(&read_secure_file(
        config_path,
        MAX_CONFIG_BYTES,
        false,
        "operator Core-link config",
    )?)?;
    validate_config(&config)?;
    serve(config)
}

fn serve(config: Config) -> Result<(), Box<dyn Error>> {
    let gateway_key = load_signing_key(&config.gateway_signing_key_file)?;
    let operator_id = gateway_key.verifying_key().to_bytes();
    let core_pubkey = parse_hash(&config.pinned_core_pubkey)?;
    let gateway_store = open_store(&config.gateway_state)?;
    let link_store = open_store(&config.corelink_state)?;
    let service_store = open_store(&config.service_state)?;
    initialize_service_store(&service_store, config.network_id, &core_pubkey)?;
    let mut public_stats_publisher = config
        .public_stats
        .as_ref()
        .map(|public| load_public_stats_publisher(public, operator_id, service_store.clone()))
        .transpose()?;
    let journal = ServiceEventJournal::new(service_store.clone(), config.event_capacity)?;
    let mut supervisor = Supervisor::new(
        SupervisorPolicy {
            unhealthy_samples_before_fallback: config.unhealthy_samples_before_fallback,
            healthy_samples_before_restore: config.healthy_samples_before_restore,
            minimum_fallback_hold_ms: config.minimum_fallback_hold_ms,
            capture_backlog_soft_limit: config.capture_backlog_soft_limit,
            capture_backlog_hard_limit: config.capture_backlog_hard_limit,
        },
        wall_ms()?,
    )?;

    let device_profile = profile(&config.profile)?;
    let gateway = if device_profile.hardware_evidence() == HardwareEvidence::SimulatorOnly {
        Gateway::open_simulator(gateway_store)?
    } else {
        Gateway::open(gateway_store)?
    };
    let worker_id =
        meshmine_types::domain_hash("meshmine/gateway-worker/v2", config.username.as_bytes());
    let initial_sequence = gateway.status().current_assignment_sequence;
    let recovery_spool = OperatorCaptureSpool::new(
        link_store.as_ref(),
        config.network_id,
        &gateway_key,
        core_pubkey,
        [0; 32],
    );
    let mut active_bundle = initial_sequence
        .map(|sequence| recovery_spool.bundle_for_sequence(sequence))
        .transpose()?;
    let mut pending_bundle: Option<CoreAssignmentBundleV1> = None;

    if let Some(bundle) = active_bundle.as_ref() {
        gateway.authorized_assignment_nonce_prefix(&worker_id, &bundle.assignment)?;
    }
    let active_assignment = Arc::new(RwLock::new(
        active_bundle
            .as_ref()
            .map(|bundle| bundle.assignment.clone()),
    ));
    let gateway = Arc::new(Mutex::new(gateway));
    let control = Arc::new(SharedRpcControl::new(
        config.maximum_authorization_failures,
    )?);
    if active_bundle.is_none() {
        control.set_fallback(true);
    }
    let shutdown = Arc::new(AtomicBool::new(false));
    spawn_shutdown_watcher(shutdown.clone(), control.clone())?;
    let active_tasks = Arc::new(AtomicUsize::new(0));
    let gateway_listener_alive = Arc::new(AtomicBool::new(false));
    let dashboard_listener_alive = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(Mutex::new(ServiceCounters::default()));

    let initial_gateway_status = gateway
        .lock()
        .map_err(|_| "gateway lock poisoned")?
        .status();
    let snapshot = Arc::new(RwLock::new(initial_snapshot(
        &config,
        initial_gateway_status.into(),
        wall_ms()?,
        active_bundle.as_ref(),
    )));
    let public_stats_document = Arc::new(RwLock::new(None::<Vec<u8>>));

    let listener = spawn_gateway_listener(
        config.clone(),
        device_profile,
        gateway.clone(),
        active_assignment.clone(),
        worker_id,
        control.clone(),
        shutdown.clone(),
        active_tasks.clone(),
        gateway_listener_alive.clone(),
    )?;
    let dashboard = spawn_dashboard_listener(
        config.dashboard_listen.parse()?,
        snapshot.clone(),
        shutdown.clone(),
        dashboard_listener_alive.clone(),
    )?;
    let public_stats_listener = config
        .public_stats
        .as_ref()
        .map(|public| {
            spawn_public_stats_listener(
                public.listen.parse()?,
                public_stats_document.clone(),
                shutdown.clone(),
            )
        })
        .transpose()?;

    journal.append(
        wall_ms()?,
        "service-start",
        "Unified Core-link operator service started",
    )?;
    println!(
        "Core-linked HandyStratum gateway listening on {}",
        config.gateway_listen
    );
    println!(
        "operator dashboard listening on {}",
        config.dashboard_listen
    );
    if let Some(public) = config.public_stats.as_ref() {
        println!(
            "public signed pool statistics listening on {}",
            public.listen
        );
    }

    let loop_result = service_loop(
        &config,
        &gateway_key,
        core_pubkey,
        link_store.as_ref(),
        &gateway,
        &active_assignment,
        &control,
        &worker_id,
        &journal,
        &mut supervisor,
        &snapshot,
        &gateway_listener_alive,
        &dashboard_listener_alive,
        &active_tasks,
        &counters,
        &shutdown,
        &mut active_bundle,
        &mut pending_bundle,
        public_stats_publisher.as_mut(),
        &public_stats_document,
    );
    shutdown.store(true, Ordering::SeqCst);
    control.request_shutdown();
    control.rotate_connections();
    let shutdown_started = Instant::now();
    while active_tasks.load(Ordering::SeqCst) > 0
        && shutdown_started.elapsed() < GRACEFUL_SHUTDOWN_TIMEOUT
    {
        thread::sleep(Duration::from_millis(25));
    }
    if active_tasks.load(Ordering::SeqCst) > 0 {
        journal.append(
            wall_ms()?,
            "shutdown-timeout",
            format!(
                "{} gateway sessions remained after the graceful shutdown deadline",
                active_tasks.load(Ordering::SeqCst)
            ),
        )?;
    }
    join_service_thread(listener, "gateway listener")?;
    join_service_thread(dashboard, "dashboard listener")?;
    if let Some(listener) = public_stats_listener {
        join_service_thread(listener, "public statistics listener")?;
    }
    if let Some(transition) = supervisor.stop(wall_ms()?) {
        journal.append_transition(&transition)?;
    }
    loop_result
}

#[allow(clippy::too_many_arguments)]
fn service_loop(
    config: &Config,
    gateway_key: &SigningKey,
    core_pubkey: [u8; 32],
    link_store: &dyn DurableStore,
    gateway: &Arc<Mutex<Gateway>>,
    active_assignment: &Arc<RwLock<Option<GatewayAssignmentV1>>>,
    control: &Arc<SharedRpcControl>,
    worker_id: &[u8; 32],
    journal: &ServiceEventJournal,
    supervisor: &mut Supervisor,
    snapshot: &Arc<RwLock<OperatorSnapshot>>,
    gateway_listener_alive: &Arc<AtomicBool>,
    dashboard_listener_alive: &Arc<AtomicBool>,
    active_tasks: &Arc<AtomicUsize>,
    counters: &Arc<Mutex<ServiceCounters>>,
    shutdown: &Arc<AtomicBool>,
    active_bundle: &mut Option<CoreAssignmentBundleV1>,
    pending_bundle: &mut Option<CoreAssignmentBundleV1>,
    mut public_stats_publisher: Option<&mut PublicStatsPublisher>,
    public_stats_document: &Arc<RwLock<Option<Vec<u8>>>>,
) -> Result<(), Box<dyn Error>> {
    let mut client: Option<OperatorCoreLinkClient<'_>> = None;
    let mut reconnect_delay = config.reconnect_initial_ms;
    let mut next_reconnect_ms = 0u64;
    let mut last_core_message_ms = None;
    let mut expect_authoritative_active_offer = false;
    let mut active_fallback_endpoint = None::<String>;
    let mut next_fallback_index = 0usize;
    let mut credentials_available = true;
    let mut credentials_error_reported = false;
    let mut shutdown_deadline_ms = None::<u64>;

    loop {
        let now = wall_ms()?;
        if shutdown.load(Ordering::SeqCst) && shutdown_deadline_ms.is_none() {
            shutdown_deadline_ms = Some(now.saturating_add(
                u64::try_from(GRACEFUL_SHUTDOWN_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
            ));
            control.set_fallback(true);
            control.rotate_connections();
            journal.append(
                now,
                "service-draining",
                "operator shutdown requested; draining durable captures within the bounded deadline",
            )?;
        }
        if client.is_none() && now >= next_reconnect_ms && shutdown_deadline_ms.is_none() {
            match connect_client(config, gateway_key, core_pubkey, link_store) {
                Ok(connected) => {
                    client = Some(connected);
                    reconnect_delay = config.reconnect_initial_ms;
                    last_core_message_ms = Some(now);
                    expect_authoritative_active_offer = true;
                    journal.append(
                        now,
                        "core-link-connected",
                        "authenticated Core link established",
                    )?;
                }
                Err(error) => {
                    if next_reconnect_ms == 0 || now >= next_reconnect_ms {
                        journal.append(now, "core-link-connect-failed", error.to_string())?;
                    }
                    next_reconnect_ms = now.saturating_add(reconnect_delay);
                    reconnect_delay = reconnect_delay
                        .saturating_mul(2)
                        .min(config.reconnect_maximum_ms);
                }
            }
        }

        let mut disconnect_reason = None::<String>;
        if let Some(connected) = client.as_mut() {
            match connected.receive_one() {
                Ok(()) => last_core_message_ms = Some(now),
                Err(ClientError::Transport(TransportError::Io(error)))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => disconnect_reason = Some(error.to_string()),
            }
            while let Some(bundle) = connected.next_offer() {
                connected.acknowledge_offer(&bundle, now)?;
                if expect_authoritative_active_offer {
                    expect_authoritative_active_offer = false;
                    if active_bundle
                        .as_ref()
                        .is_none_or(|active| active.object_id() != bundle.object_id())
                    {
                        {
                            let mut locked = gateway.lock().map_err(|_| "gateway lock poisoned")?;
                            install_job(&mut locked, &bundle)?;
                            locked.authorized_assignment_nonce_prefix(
                                worker_id,
                                &bundle.assignment,
                            )?;
                            *active_assignment
                                .write()
                                .map_err(|_| "assignment lock poisoned")? =
                                Some(bundle.assignment.clone());
                        }
                        journal.append(
                            now,
                            "assignment-activated",
                            format!(
                                "reconciled authoritative active bundle {}",
                                hex::encode(bundle.object_id())
                            ),
                        )?;
                        *active_bundle = Some(bundle);
                        control.rotate_connections();
                    }
                    continue;
                }
                if active_bundle
                    .as_ref()
                    .is_some_and(|active| active.object_id() == bundle.object_id())
                {
                    continue;
                }
                journal.append(
                    now,
                    "assignment-pending",
                    format!(
                        "staged replacement bundle {}",
                        hex::encode(bundle.object_id())
                    ),
                )?;
                *pending_bundle = Some(bundle);
            }
        }
        if let Some(reason) = disconnect_reason {
            journal.append(now, "core-link-disconnected", reason)?;
            client = None;
            next_reconnect_ms = now.saturating_add(reconnect_delay);
            reconnect_delay = reconnect_delay
                .saturating_mul(2)
                .min(config.reconnect_maximum_ms);
        }

        match read_password(&config.password_file) {
            Ok(_) => {
                if !credentials_available {
                    journal.append(
                        now,
                        "credentials-restored",
                        "gateway password is readable again",
                    )?;
                    control.rotate_connections();
                }
                credentials_available = true;
                credentials_error_reported = false;
            }
            Err(error) => {
                credentials_available = false;
                if !credentials_error_reported {
                    journal.append(now, "credentials-unavailable", error.to_string())?;
                    credentials_error_reported = true;
                }
            }
        }

        let (capture_drain, gateway_events) = if let Some(connected) = client.as_mut() {
            let mut locked = gateway.lock().map_err(|_| "gateway lock poisoned")?;
            let now = wall_ms()?;
            if connected.pending_drain().is_none() {
                locked.close_expired(now)?;
            }
            let drain = locked.drain_captures_durably(connected, config.capture_drain_batch);
            let events = locked.drain_events(MAX_GATEWAY_EVENTS);
            (Some(drain), events)
        } else {
            let mut locked = gateway.lock().map_err(|_| "gateway lock poisoned")?;
            (None, locked.drain_events(MAX_GATEWAY_EVENTS))
        };
        if let Some(result) = capture_drain {
            match result {
                Ok(report) if report.acknowledged > 0 => {
                    journal.append(
                        now,
                        "capture-drain",
                        format!(
                            "Core terminally acknowledged {} captures",
                            report.acknowledged
                        ),
                    )?;
                }
                Ok(_) | Err(meshmine_gateway::GatewayError::CaptureConsumerUnavailable) => {}
                Err(error) => {
                    journal.append(now, "capture-drain-error", error.to_string())?;
                }
            }
        }
        observe_gateway_events(&gateway_events, counters, journal, now)?;

        let required_drain = client
            .as_ref()
            .and_then(|connected| connected.pending_drain())
            .cloned();
        if let (Some(required), Some(active), Some(next)) = (
            required_drain,
            active_bundle.as_ref(),
            pending_bundle.as_ref(),
        ) && now >= required.credit_cutoff_ms
        {
            control.set_fallback(true);
            if now >= required.previous_submission_end_ms {
                let connected = client
                    .as_mut()
                    .ok_or("Core link disappeared during drain")?;
                connected.complete_drain(active, next, now)?;
                {
                    let mut locked = gateway.lock().map_err(|_| "gateway lock poisoned")?;
                    install_job(&mut locked, next)?;
                    locked.authorized_assignment_nonce_prefix(worker_id, &next.assignment)?;
                    *active_assignment
                        .write()
                        .map_err(|_| "assignment lock poisoned")? = Some(next.assignment.clone());
                }
                journal.append(
                    now,
                    "assignment-transition-complete",
                    format!(
                        "activated replacement bundle {}",
                        hex::encode(next.object_id())
                    ),
                )?;
                *active_bundle = Some(next.clone());
                *pending_bundle = None;
                control.rotate_connections();
            }
        }

        let gateway_status = gateway
            .lock()
            .map_err(|_| "gateway lock poisoned")?
            .status();
        let core_connected = client.is_some();
        let core_ready = core_connected && !expect_authoritative_active_offer;
        let drain_pending = client
            .as_ref()
            .and_then(|connected| connected.pending_drain())
            .is_some();
        let sample = HealthSample {
            now_ms: now,
            gateway_available: gateway_listener_alive.load(Ordering::SeqCst),
            receipt_store_available: link_store
                .get(
                    meshmine_core_link::OPERATOR_CAPTURE_RECEIPT_NAMESPACE,
                    "health-probe",
                )
                .is_ok(),
            credentials_available,
            core_link_available: core_ready,
            drain_pending,
            authorization_failure_limit: control.authorization_failures()
                >= config.maximum_authorization_failures,
            current_job_id: gateway_status.current_job_id.clone(),
            job_issued_ms: gateway_status.current_issued_ms,
            assignment_end_ms: gateway_status.current_assignment_end_ms,
            pending_captures: gateway_status.pending_captures,
            shutdown_requested: shutdown.load(Ordering::SeqCst),
        };
        if let Some(transition) = supervisor.sample(sample) {
            journal.append_transition(&transition)?;
            match transition.to {
                ServiceMode::Mining | ServiceMode::Degraded => {
                    control.set_fallback(false);
                    active_fallback_endpoint = None;
                }
                ServiceMode::Fallback | ServiceMode::Draining => {
                    control.set_fallback(true);
                    control.rotate_connections();
                    if transition.to == ServiceMode::Fallback
                        && !config.fallback_endpoints.is_empty()
                    {
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
                ServiceMode::Bootstrapping | ServiceMode::Stopped => {}
            }
        }

        let pending_capture_count = gateway_status.pending_captures;
        let counter_view = {
            let locked = counters.lock().map_err(|_| "counter lock poisoned")?;
            OperatorCountersView::from(&*locked)
        };
        let recent = journal.recent(100)?;
        let updated = OperatorSnapshot {
            generated_at_ms: now,
            supervisor: supervisor.snapshot().clone(),
            gateway: gateway_status.into(),
            gateway_listen: config.gateway_listen.clone(),
            dashboard_listen: config.dashboard_listen.clone(),
            active_connections: active_tasks.load(Ordering::SeqCst),
            authorization_failures: control.authorization_failures(),
            gateway_listener_alive: gateway_listener_alive.load(Ordering::SeqCst),
            dashboard_listener_alive: dashboard_listener_alive.load(Ordering::SeqCst),
            credentials_available,
            core_link_connected: core_connected,
            core_link_last_message_ms: last_core_message_ms,
            active_bundle_id: active_bundle
                .as_ref()
                .map(|bundle| hex::encode(bundle.object_id())),
            pending_bundle_id: pending_bundle
                .as_ref()
                .map(|bundle| hex::encode(bundle.object_id())),
            assignment_drain_pending: drain_pending,
            counters: counter_view,
            fallback_endpoint: active_fallback_endpoint.clone(),
            production_eligible: false,
            authority_note: AUTHORITY_NOTE.to_owned(),
            events: recent,
        };
        if let Some(publisher) = public_stats_publisher.as_deref_mut() {
            match publisher.publish(&updated, active_bundle.as_ref()) {
                Ok(Some(document)) => {
                    *public_stats_document
                        .write()
                        .map_err(|_| "public statistics lock poisoned")? = Some(document);
                }
                Ok(None) => {}
                Err(error) => {
                    publisher.disabled = true;
                    *public_stats_document
                        .write()
                        .map_err(|_| "public statistics lock poisoned")? = None;
                    journal.append(now, "public-stats-disabled", error.to_string())?;
                }
            }
        }
        *snapshot.write().map_err(|_| "snapshot lock poisoned")? = updated;
        if let Some(deadline_ms) = shutdown_deadline_ms
            && (pending_capture_count == 0 || now >= deadline_ms)
        {
            break;
        }
        thread::sleep(Duration::from_millis(config.poll_interval_ms.max(10)));
    }
    Ok(())
}

fn spawn_shutdown_watcher(
    shutdown: Arc<AtomicBool>,
    control: Arc<SharedRpcControl>,
) -> Result<(), Box<dyn Error>> {
    thread::Builder::new()
        .name("meshmine-signal".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(_) => return,
            };
            if runtime.block_on(tokio::signal::ctrl_c()).is_ok() {
                shutdown.store(true, Ordering::SeqCst);
                control.set_fallback(true);
                control.rotate_connections();
            }
        })?;
    Ok(())
}

fn join_service_thread(
    handle: thread::JoinHandle<Result<(), String>>,
    name: &str,
) -> Result<(), Box<dyn Error>> {
    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!("{name} failed: {error}").into()),
        Err(_) => Err(format!("{name} panicked").into()),
    }
}

fn connect_client<'a>(
    config: &Config,
    gateway_key: &'a SigningKey,
    core_pubkey: [u8; 32],
    link_store: &'a dyn DurableStore,
) -> Result<OperatorCoreLinkClient<'a>, Box<dyn Error>> {
    let connection = connect_authenticated(
        &config.core_socket_path,
        config.network_id,
        gateway_key,
        core_pubkey,
        CoreLinkLimits {
            maximum_frame_bytes: MAX_CORE_LINK_FRAME_BYTES,
            read_timeout_ms: config.poll_interval_ms.max(25),
            write_timeout_ms: 30_000,
        },
    )?;
    let connection_id = connection.connection_id();
    let spool = OperatorCaptureSpool::new(
        link_store,
        config.network_id,
        gateway_key,
        core_pubkey,
        connection_id,
    );
    Ok(OperatorCoreLinkClient::new(
        connection,
        spool,
        gateway_key,
        core_pubkey,
    ))
}

fn install_job(
    gateway: &mut Gateway,
    bundle: &CoreAssignmentBundleV1,
) -> Result<(), Box<dyn Error>> {
    let job = bundle.gateway_job()?;
    gateway.issue_authorized_job(AuthorizedGatewayJobRequest {
        manifest: &bundle.manifest,
        assignment: &bundle.assignment,
        session: &bundle.session,
        body: &bundle.body,
        descriptor: &bundle.descriptor,
        body_certificate: &bundle.body_certificate,
        job,
        transition: bundle.previous_job_transition(),
    })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_gateway_listener(
    config: Config,
    profile: DeviceProfile,
    gateway: Arc<Mutex<Gateway>>,
    active_assignment: Arc<RwLock<Option<GatewayAssignmentV1>>>,
    worker_id: [u8; 32],
    control: Arc<SharedRpcControl>,
    shutdown: Arc<AtomicBool>,
    active_tasks: Arc<AtomicUsize>,
    listener_alive: Arc<AtomicBool>,
) -> Result<thread::JoinHandle<Result<(), String>>, Box<dyn Error>> {
    let address: SocketAddr = config.gateway_listen.parse()?;
    let allowed_networks = parse_gateway_allowed_cidrs(&config.gateway_allowed_cidrs)?;
    let listener = TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    Ok(thread::spawn(move || {
        listener_alive.store(true, Ordering::SeqCst);
        let _alive = ListenerAliveGuard(listener_alive);
        while !shutdown.load(Ordering::SeqCst) && !control.shutdown_requested() {
            match listener.accept() {
                Ok((stream, peer)) => {
                    if !gateway_peer_allowed(peer.ip(), &allowed_networks)
                        || control.fallback_active()
                        || active_tasks.load(Ordering::SeqCst) >= config.maximum_connections
                    {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                    let password = match read_password(&config.password_file) {
                        Ok(password) => password,
                        Err(_) => continue,
                    };
                    let assignment = match active_assignment.read() {
                        Ok(assignment) => assignment.clone(),
                        Err(_) => continue,
                    };
                    let Some(assignment) = assignment else {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    };
                    let session = match RpcSession::new_authorized(
                        config.username.clone(),
                        password,
                        profile.clone(),
                        worker_id,
                        assignment,
                    ) {
                        Ok(session) => session,
                        Err(_) => {
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                            continue;
                        }
                    };
                    active_tasks.fetch_add(1, Ordering::SeqCst);
                    let active_tasks = active_tasks.clone();
                    let gateway = gateway.clone();
                    let control = control.clone();
                    let maximum_requests = config.maximum_requests_per_connection;
                    let update_interval = Duration::from_millis(config.poll_interval_ms.max(10));
                    thread::spawn(move || {
                        let _guard = TaskGuard(active_tasks);
                        let _ = serve_rpc_connection_shared(
                            stream,
                            session,
                            gateway,
                            control,
                            maximum_requests,
                            update_interval,
                        );
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

fn spawn_public_stats_listener(
    address: SocketAddr,
    document: Arc<RwLock<Option<Vec<u8>>>>,
    shutdown: Arc<AtomicBool>,
) -> Result<thread::JoinHandle<Result<(), String>>, Box<dyn Error>> {
    let listener = TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    Ok(thread::spawn(move || {
        let active = Arc::new(AtomicUsize::new(0));
        while !shutdown.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if active.load(Ordering::SeqCst) >= MAX_PUBLIC_STATS_CONNECTIONS {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                    active.fetch_add(1, Ordering::SeqCst);
                    let active = active.clone();
                    let document = document.clone();
                    thread::spawn(move || {
                        let _guard = TaskGuard(active);
                        let _ = serve_public_stats_http(stream, document);
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

fn serve_public_stats_http(
    mut stream: TcpStream,
    document: Arc<RwLock<Option<Vec<u8>>>>,
) -> Result<(), Box<dyn Error>> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    let mut limited = std::io::Read::take(&mut reader, (MAX_HTTP_REQUEST_LINE + 1) as u64);
    limited.read_line(&mut line)?;
    if line.len() > MAX_HTTP_REQUEST_LINE {
        return write_public_http(
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
        return write_public_http(
            &mut stream,
            405,
            "text/plain; charset=utf-8",
            b"method not allowed",
        );
    }
    if path == "/" {
        return write_public_http(
            &mut stream,
            200,
            "text/html; charset=utf-8",
            public_stats_html().as_bytes(),
        );
    }
    if path != "/api/v1/pool-stats" {
        return write_public_http(&mut stream, 404, "text/plain; charset=utf-8", b"not found");
    }
    let document = document
        .read()
        .map_err(|_| "public statistics lock poisoned")?;
    match document.as_deref() {
        Some(body) => write_public_http(&mut stream, 200, "application/json", body),
        None => write_public_http(
            &mut stream,
            503,
            "text/plain; charset=utf-8",
            b"statistics unavailable",
        ),
    }
}

fn write_public_http(
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
    let content_security_policy = if content_type.starts_with("text/html") {
        "default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"
    } else {
        "default-src 'none'"
    };
    write!(
        stream,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: {content_security_policy}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
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
        let _alive = ListenerAliveGuard(listener_alive);
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
                        let _guard = TaskGuard(active);
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
    let mut captures = 0u64;
    let mut rejections = 0u64;
    let mut messages = Vec::<(&'static str, String)>::new();
    {
        let mut counters = counters.lock().map_err(|_| "counter lock poisoned")?;
        for event in events {
            match event {
                GatewayEvent::JobIssued {
                    job_id,
                    assignment_sequence,
                } => {
                    counters.job_issues = counters.job_issues.saturating_add(1);
                    messages.push((
                        "gateway-job-issued",
                        format!("{job_id} sequence {assignment_sequence}"),
                    ));
                }
                GatewayEvent::JobCancelled { job_id, .. } => {
                    counters.job_cancellations = counters.job_cancellations.saturating_add(1);
                    messages.push(("gateway-job-cancelled", job_id.clone()));
                }
                GatewayEvent::CaptureForwarded { .. } => {
                    counters.accepted_captures = counters.accepted_captures.saturating_add(1);
                    captures = captures.saturating_add(1);
                }
                GatewayEvent::SubmissionRejected { .. } => {
                    counters.rejected_submissions = counters.rejected_submissions.saturating_add(1);
                    rejections = rejections.saturating_add(1);
                }
                GatewayEvent::FailoverActivated { endpoint } => {
                    counters.failovers = counters.failovers.saturating_add(1);
                    messages.push(("gateway-failover", endpoint.clone()));
                }
            }
        }
    }
    if captures > 0 {
        messages.push((
            "gateway-capture-batch",
            format!("observed {captures} captures"),
        ));
    }
    if rejections > 0 {
        messages.push((
            "gateway-rejection-batch",
            format!("observed {rejections} rejections"),
        ));
    }
    for (kind, message) in messages {
        journal.append(now_ms, kind, message)?;
    }
    Ok(())
}

fn initial_snapshot(
    config: &Config,
    gateway: GatewayStatusView,
    now_ms: u64,
    active_bundle: Option<&CoreAssignmentBundleV1>,
) -> OperatorSnapshot {
    OperatorSnapshot {
        generated_at_ms: now_ms,
        supervisor: meshmine_service::SupervisorSnapshot {
            schema_version: meshmine_service::SERVICE_SCHEMA_VERSION,
            profile: meshmine_service::SERVICE_PROFILE.to_owned(),
            mode: ServiceMode::Bootstrapping,
            reason: meshmine_service::HealthReason::CoreLinkUnavailable,
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
        active_bundle_id: active_bundle.map(|bundle| hex::encode(bundle.object_id())),
        pending_bundle_id: None,
        assignment_drain_pending: false,
        counters: OperatorCountersView::default(),
        fallback_endpoint: None,
        production_eligible: false,
        authority_note: AUTHORITY_NOTE.to_owned(),
        events: Vec::new(),
    }
}

impl PublicStatsPublisher {
    fn publish(
        &mut self,
        operator: &OperatorSnapshot,
        active_bundle: Option<&CoreAssignmentBundleV1>,
    ) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        if self.disabled || operator.generated_at_ms < self.next_publish_at_ms {
            return Ok(None);
        }
        let generated_at = operator.generated_at_ms / 1000;
        if generated_at >= self.config.delegation_expires_at {
            return Err("HNSA endpoint delegation expired".into());
        }
        let sequence =
            reserve_public_stats_sequence(self.sequence_store.as_ref(), &self.operator_id)?;
        self.next_publish_at_ms = operator
            .generated_at_ms
            .saturating_add(self.config.publish_interval_ms);
        let (tip_height, tip_hash) = active_bundle
            .map(|bundle| {
                (
                    bundle.parent_certificate.parent_height,
                    bundle.parent_certificate.parent_hash,
                )
            })
            .unwrap_or((0, [0; 32]));
        let mut snapshot = PoolStatsSnapshotV1 {
            network_magic: self.config.network_magic,
            profile_id: EXPERIMENTAL_PROFILE_ID,
            authorization_id: self.authorization_id,
            delegation_id: self.delegation_id,
            endpoint_sequence: self.config.endpoint_sequence,
            sequence,
            generated_at,
            expires_at: generated_at
                .saturating_add(self.config.snapshot_lifetime_seconds)
                .min(self.config.delegation_expires_at),
            operator_id: self.operator_id,
            tip_height,
            tip_hash,
            connected_miners: u32::try_from(operator.active_connections)?,
            connected_mesh_peers: 0,
            accepted_shares: operator.counters.accepted_captures,
            rejected_shares: operator.counters.rejected_submissions,
            pending_captures: u32::try_from(operator.gateway.pending_captures)?,
            last_found_block: None,
            mode: public_mode(operator.supervisor.mode),
            production_eligible: operator.production_eligible,
            endpoint_signature: Vec::new(),
        };
        snapshot.sign(&self.endpoint_key)?;
        let document = PoolStatsDocumentV1::new(
            &self.service_authorization,
            &self.endpoint_delegation,
            &snapshot,
        )?;
        Ok(Some(serde_json::to_vec(&document)?))
    }
}

fn public_mode(mode: ServiceMode) -> PublicMode {
    match mode {
        ServiceMode::Bootstrapping => PublicMode::Bootstrapping,
        ServiceMode::Mining => PublicMode::Mining,
        ServiceMode::Degraded => PublicMode::Degraded,
        ServiceMode::Fallback => PublicMode::Fallback,
        ServiceMode::Draining => PublicMode::Draining,
        ServiceMode::Stopped => PublicMode::Stopped,
    }
}

fn load_public_stats_publisher(
    config: &PublicStatsConfig,
    operator_id: [u8; 32],
    sequence_store: Arc<dyn DurableStore>,
) -> Result<PublicStatsPublisher, Box<dyn Error>> {
    let endpoint_key = load_secp256k1_signing_key(&config.endpoint_signing_key_file)?;
    let service_authorization = read_hex_file(
        &config.service_authorization_file,
        MAX_HNSA_OBJECT_BYTES,
        "HNSA service authorization",
    )?;
    let endpoint_delegation = read_hex_file(
        &config.endpoint_delegation_file,
        MAX_HNSA_OBJECT_BYTES,
        "HNSA endpoint delegation",
    )?;
    Ok(PublicStatsPublisher {
        config: config.clone(),
        endpoint_key,
        service_authorization,
        endpoint_delegation,
        authorization_id: parse_hash(&config.authorization_id)?,
        delegation_id: parse_hash(&config.delegation_id)?,
        operator_id,
        sequence_store,
        next_publish_at_ms: 0,
        disabled: false,
    })
}

fn reserve_public_stats_sequence(
    store: &dyn DurableStore,
    operator_id: &[u8; 32],
) -> Result<u64, Box<dyn Error>> {
    const NAMESPACE: &str = "pool-stats-sequence/v1";
    let key = hex::encode(operator_id);
    loop {
        let current = store.get(NAMESPACE, &key)?;
        let previous = match current.as_deref() {
            None => 0,
            Some(bytes) => u64::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| "invalid durable public-statistics sequence")?,
            ),
        };
        let next = previous
            .checked_add(1)
            .ok_or("public statistics sequence exhausted")?;
        if store.compare_and_swap(NAMESPACE, &key, current.as_deref(), &next.to_le_bytes())? {
            return Ok(next);
        }
    }
}

fn parse_gateway_allowed_cidrs(values: &[String]) -> Result<Vec<IpNet>, Box<dyn Error>> {
    if values.len() > 16 {
        return Err("too many gateway CIDR allowlist entries".into());
    }
    values
        .iter()
        .map(|value| {
            let network: IpNet = value.parse()?;
            let trusted = match network {
                IpNet::V4(network) => {
                    network.prefix_len() >= 8
                        && (network.network().is_private()
                            || network.network().is_link_local()
                            || network.network().is_loopback())
                }
                IpNet::V6(network) => {
                    network.prefix_len() >= 16
                        && (network.network().is_unique_local()
                            || network.network().is_unicast_link_local()
                            || network.network().is_loopback())
                }
            };
            if !trusted {
                return Err(
                    format!("gateway CIDR is not a bounded private network: {network}").into(),
                );
            }
            Ok(network)
        })
        .collect()
}

fn gateway_peer_allowed(peer: IpAddr, allowed_networks: &[IpNet]) -> bool {
    peer.is_loopback()
        || allowed_networks
            .iter()
            .any(|network| network.contains(&peer))
}

fn validate_config(config: &Config) -> Result<(), Box<dyn Error>> {
    if config.schema_version != 2 || config.production {
        return Err("unified operator requires schema 2 and production=false".into());
    }
    for (path, name) in [
        (&config.core_socket_path, "Core socket"),
        (&config.gateway_signing_key_file, "gateway signing key"),
        (&config.corelink_state, "Core-link state"),
        (&config.gateway_state, "gateway state"),
        (&config.service_state, "service state"),
        (&config.password_file, "password file"),
    ] {
        validate_absolute(path, name)?;
    }
    if config.corelink_state == config.gateway_state
        || config.corelink_state == config.service_state
        || config.gateway_state == config.service_state
    {
        return Err("Core-link, gateway, and service state must be separate files".into());
    }
    let gateway_address: SocketAddr = config.gateway_listen.parse()?;
    let dashboard_address: SocketAddr = config.dashboard_listen.parse()?;
    let allowed_networks = parse_gateway_allowed_cidrs(&config.gateway_allowed_cidrs)?;
    if !gateway_address.ip().is_loopback() && allowed_networks.is_empty() {
        return Err("non-loopback ASIC gateway requires a private CIDR allowlist".into());
    }
    if !dashboard_address.ip().is_loopback() {
        return Err("operator dashboard must use loopback".into());
    }
    if let Some(public) = config.public_stats.as_ref() {
        let public_address: SocketAddr = public.listen.parse()?;
        if public_address == gateway_address || public_address == dashboard_address {
            return Err("public statistics listener must use a distinct socket".into());
        }
        for (path, name) in [
            (
                &public.endpoint_signing_key_file,
                "HNSA endpoint signing key",
            ),
            (
                &public.service_authorization_file,
                "HNSA service authorization",
            ),
            (&public.endpoint_delegation_file, "HNSA endpoint delegation"),
        ] {
            validate_absolute(path, name)?;
        }
        if public.endpoint_signing_key_file == config.gateway_signing_key_file {
            return Err("HNSA endpoint key must be separate from the ASIC gateway key".into());
        }
        let authorization_id = parse_hash(&public.authorization_id)?;
        let delegation_id = parse_hash(&public.delegation_id)?;
        let now = wall_ms()? / 1000;
        if is_zero_hash(&authorization_id)
            || is_zero_hash(&delegation_id)
            || public.endpoint_sequence == 0
            || public.snapshot_lifetime_seconds < 10
            || public.snapshot_lifetime_seconds > MAX_SNAPSHOT_LIFETIME
            || public.publish_interval_ms < 1_000
            || public.publish_interval_ms > public.snapshot_lifetime_seconds.saturating_mul(500)
            || public.delegation_expires_at <= now.saturating_add(public.snapshot_lifetime_seconds)
        {
            return Err("invalid bounded public-statistics configuration".into());
        }
    }
    if config.username.is_empty()
        || config.username.len() > 100
        || config.poll_interval_ms < 10
        || config.capture_drain_batch == 0
        || config.capture_drain_batch > 100_000
        || config.maximum_connections == 0
        || config.maximum_connections > 4096
        || config.maximum_requests_per_connection == 0
        || config.maximum_authorization_failures == 0
        || config.event_capacity == 0
        || config.event_capacity > 100_000
        || config.reconnect_initial_ms < 25
        || config.reconnect_maximum_ms < config.reconnect_initial_ms
        || config.reconnect_maximum_ms > 300_000
        || config.fallback_endpoints.len() > MAX_FALLBACK_ENDPOINTS
        || config.fallback_endpoints.iter().any(|endpoint| {
            endpoint.is_empty()
                || endpoint.len() > MAX_FALLBACK_ENDPOINT_BYTES
                || endpoint.chars().any(char::is_control)
        })
    {
        return Err("invalid bounded unified-operator configuration".into());
    }
    SupervisorPolicy {
        unhealthy_samples_before_fallback: config.unhealthy_samples_before_fallback,
        healthy_samples_before_restore: config.healthy_samples_before_restore,
        minimum_fallback_hold_ms: config.minimum_fallback_hold_ms,
        capture_backlog_soft_limit: config.capture_backlog_soft_limit,
        capture_backlog_hard_limit: config.capture_backlog_hard_limit,
    }
    .validate()?;
    Ok(())
}

fn profile(name: &str) -> Result<DeviceProfile, Box<dyn Error>> {
    match name {
        "simulator" => Ok(DeviceProfile::simulator()),
        "handyminer-reference" | "handyminer" => Ok(DeviceProfile::handyminer_reference()),
        "goldshell-hs3-experimental" | "hs3" => Ok(DeviceProfile::goldshell_hs3_experimental()),
        "goldshell-generic-experimental" | "goldshell" => {
            Ok(DeviceProfile::goldshell_generic_experimental())
        }
        _ => Err("unknown gateway profile".into()),
    }
}

fn open_store(path: &Path) -> Result<Arc<dyn DurableStore>, Box<dyn Error>> {
    validate_absolute(path, "state database")?;
    let existed = path.exists();
    let store: Arc<dyn DurableStore> = if existed {
        Arc::new(RedbStore::open_existing(path)?)
    } else {
        Arc::new(RedbStore::create(path)?)
    };
    if !existed {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(store)
}

fn load_signing_key(path: &Path) -> Result<SigningKey, Box<dyn Error>> {
    let bytes = read_secure_file(path, MAX_KEY_BYTES, true, "gateway signing key")?;
    let decoded = hex::decode(String::from_utf8(bytes)?.trim())?;
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "gateway key must be 32 bytes")?;
    Ok(SigningKey::from_bytes(&key))
}

fn load_secp256k1_signing_key(path: &Path) -> Result<Secp256k1SigningKey, Box<dyn Error>> {
    let bytes = read_secure_file(path, MAX_KEY_BYTES, true, "HNSA endpoint signing key")?;
    let decoded = hex::decode(String::from_utf8(bytes)?.trim())?;
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "HNSA endpoint key must be 32 bytes")?;
    Secp256k1SigningKey::from_bytes((&key).into())
        .map_err(|_| "invalid HNSA endpoint signing key".into())
}

fn read_hex_file(path: &Path, maximum: u64, name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let encoded = String::from_utf8(read_secure_file(path, maximum, false, name)?)?;
    let decoded = hex::decode(encoded.trim())?;
    if decoded.is_empty() || decoded.len() as u64 > maximum {
        return Err(format!("{name} has invalid decoded size").into());
    }
    Ok(decoded)
}

fn read_password(path: &Path) -> Result<String, Box<dyn Error>> {
    let bytes = read_secure_file(path, MAX_PASSWORD_BYTES, true, "password file")?;
    let password = String::from_utf8(bytes)?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if password.is_empty() || password.len() > 255 {
        return Err("invalid password".into());
    }
    Ok(password)
}

fn read_secure_file(
    path: &Path,
    maximum: u64,
    private: bool,
    name: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    validate_absolute(path, name)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no arguments and reads process credentials only.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.len() > maximum || metadata.uid() != uid {
        return Err(format!("{name} is not a bounded user-owned regular file").into());
    }
    let forbidden = if private { 0o077 } else { 0o022 };
    if metadata.permissions().mode() & forbidden != 0 {
        return Err(format!("{name} permissions are too broad").into());
    }
    let current = fs::symlink_metadata(path)?;
    if current.file_type().is_symlink()
        || current.dev() != metadata.dev()
        || current.ino() != metadata.ino()
    {
        return Err(format!("{name} path changed during validation").into());
    }
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(format!("{name} grew while read").into());
    }
    Ok(bytes)
}

fn parse_hash(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    Ok(hex::decode(value)?
        .try_into()
        .map_err(|_| "expected 32-byte hex")?)
}

fn is_zero_hash(value: &[u8; 32]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn validate_absolute(path: &Path, name: &str) -> Result<(), Box<dyn Error>> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!("{name} must be absolute without parent traversal").into());
    }
    Ok(())
}

fn flag_path<'a>(arguments: &'a [String], flag: &str) -> Result<&'a Path, Box<dyn Error>> {
    let index = arguments
        .iter()
        .position(|argument| argument == flag)
        .ok_or_else(usage)?;
    Ok(Path::new(arguments.get(index + 1).ok_or_else(usage)?))
}

fn wall_ms() -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

struct TaskGuard(Arc<AtomicUsize>);
impl Drop for TaskGuard {
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

const fn default_poll_ms() -> u64 {
    100
}
const fn default_capture_batch() -> usize {
    1024
}
const fn default_connections() -> usize {
    128
}
const fn default_requests() -> usize {
    1_000_000
}
const fn default_auth_failures() -> u16 {
    64
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
const fn default_backlog_soft() -> usize {
    10_000
}
const fn default_backlog_hard() -> usize {
    90_000
}
const fn default_event_capacity() -> usize {
    10_000
}
const fn default_reconnect_initial_ms() -> u64 {
    250
}
const fn default_reconnect_maximum_ms() -> u64 {
    30_000
}
const fn default_public_stats_lifetime() -> u64 {
    60
}
const fn default_public_stats_publish_interval_ms() -> u64 {
    2_000
}

fn usage() -> String {
    "usage: meshmine-corelink-operatord serve --config /absolute/operator-corelink-v9.json"
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshmine_storage::MemoryStore;

    #[test]
    fn public_statistics_sequence_is_durable_and_operator_scoped() {
        let store = MemoryStore::default();
        assert_eq!(
            reserve_public_stats_sequence(&store, &[1; 32]).expect("first sequence"),
            1
        );
        assert_eq!(
            reserve_public_stats_sequence(&store, &[1; 32]).expect("second sequence"),
            2
        );
        assert_eq!(
            reserve_public_stats_sequence(&store, &[2; 32]).expect("other operator"),
            1
        );
    }

    #[test]
    fn malformed_public_statistics_sequence_fails_closed() {
        let store = MemoryStore::default();
        store
            .put("pool-stats-sequence/v1", &hex::encode([1; 32]), &[0; 7])
            .expect("malformed sequence fixture");
        assert!(reserve_public_stats_sequence(&store, &[1; 32]).is_err());
    }
}
