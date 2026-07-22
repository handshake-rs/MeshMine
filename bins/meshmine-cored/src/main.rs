use std::error::Error;
use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use meshmine_codec::{CanonicalDecode, CanonicalEncode, DecodeLimits};
use meshmine_core_link::{
    AdmissionError, CORE_LINK_PROTOCOL_V1, CaptureDispositionV1, CoreAdmissionEngine,
    CoreAssignmentBundleV1, CoreLinkErrorV1, CoreLinkLimits, CoreLinkMessage, DrainDispositionV1,
    DrainRequiredV1, MAX_CORE_ASSIGNMENT_BUNDLE_BYTES, MAX_CORE_LINK_FRAME_BYTES, TransportError,
    authenticate_server, bind_secure_listener,
};
use meshmine_crypto::verify_object;
use meshmine_parent_oracle::{
    LiveParentOracle, LiveParentPolicy, MAX_PARENT_AUTHORIZATION_BYTES,
    MAX_PARENT_RPC_RESPONSE_BYTES, ParentRpcSource,
};
use meshmine_storage::{DurableStore, RedbStore, ScanLimits};
use meshmine_types::{ED25519_SUITE, UnsignedObject};
use serde::Deserialize;

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_KEY_BYTES: u64 = 256;
const MAX_PARENT_ORACLE_BYTES: u64 = 128 * 1024;
const MAX_BUNDLE_FILE_BYTES: u64 = MAX_CORE_ASSIGNMENT_BUNDLE_BYTES as u64;
const CORE_ACK_NAMESPACE: &str = "core-link-assignment-ack/v1";
const DEFAULT_PARENT_REQUALIFICATION_INTERVAL_MS: u64 = 1_000;
const MAX_PARENT_REQUALIFICATION_INTERVAL_MS: u64 = 5_000;
const MAX_CORE_LINK_WRITE_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreConfig {
    schema_version: u16,
    production: bool,
    network_id: u8,
    socket_path: PathBuf,
    state_path: PathBuf,
    core_signing_key_file: PathBuf,
    operator_signing_key_file: PathBuf,
    expected_gateway_pubkey: String,
    expected_peer_uid: u32,
    parent_oracle_file: PathBuf,
    maximum_frame_bytes: Option<usize>,
    read_timeout_ms: Option<u64>,
    write_timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentOracleFile {
    schema_version: u16,
    network_id: u8,
    minimum_confirmations: u32,
    maximum_certificate_depth: u32,
    maximum_header_age_ms: u64,
    cache_ttl_ms: u64,
    hsrd: ParentRpcSourceFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentRpcSourceFile {
    label: String,
    address: String,
    path: String,
    authorization_header_file: PathBuf,
    connect_timeout_ms: u64,
    read_timeout_ms: u64,
    write_timeout_ms: u64,
    maximum_response_bytes: usize,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("meshmine-cored: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        Some("serve") => {
            let config = load_config(single_path_argument(&arguments[1..], "--config")?)?;
            serve(config)
        }
        Some("stage-bundle") => {
            let config = load_config(single_path_argument(&arguments[1..], "--config")?)?;
            let bundle_path = single_path_argument(&arguments[1..], "--bundle")?;
            stage_bundle(&config, bundle_path)
        }
        Some("status") => {
            let config = load_config(single_path_argument(&arguments[1..], "--config")?)?;
            status(&config)
        }
        _ => Err(usage().into()),
    }
}

fn stage_bundle(config: &CoreConfig, bundle_path: &Path) -> Result<(), Box<dyn Error>> {
    validate_config(config)?;
    let keys = load_keys(config)?;
    let oracle = load_parent_oracle(config)?;
    let store = open_store(&config.state_path)?;
    let bundle = load_bundle(bundle_path)?;
    let engine =
        CoreAdmissionEngine::new(store.as_ref(), config.network_id, &keys.0, &keys.1, &oracle);
    oracle.qualify_active(&bundle.parent_certificate)?;
    engine.stage_bundle(&bundle, wall_ms()?)?;
    println!(
        "staged Core assignment bundle {} sequence {}",
        hex::encode(bundle.object_id()),
        bundle.bundle_sequence
    );
    Ok(())
}

fn status(config: &CoreConfig) -> Result<(), Box<dyn Error>> {
    validate_config(config)?;
    let keys = load_keys(config)?;
    let oracle = load_parent_oracle(config)?;
    let store = open_store(&config.state_path)?;
    let engine =
        CoreAdmissionEngine::new(store.as_ref(), config.network_id, &keys.0, &keys.1, &oracle);
    let active = engine.active_bundle()?;
    let pending = engine.pending_bundle()?;
    let active_parent_qualification = active.as_ref().map(|bundle| {
        let result = oracle.qualify_active(&bundle.parent_certificate);
        result.unwrap_or_else(|_| oracle.status())
    });
    let pending_parent_qualification = pending.as_ref().map(|bundle| {
        let result = oracle.qualify_active(&bundle.parent_certificate);
        result.unwrap_or_else(|_| oracle.status())
    });
    let captures = store.scan_namespace(
        "journal/gateway-capture-receipt/v1",
        ScanLimits {
            maximum_records: 1_000_000,
            maximum_value_bytes: 16 * 1024,
            maximum_total_bytes: 512 * 1024 * 1024,
        },
    )?;
    println!("{{");
    println!("  \"network_id\": {},", config.network_id);
    println!(
        "  \"active_bundle_id\": {},",
        json_optional_hash(active.as_ref().map(|bundle| bundle.object_id()))
    );
    println!(
        "  \"pending_bundle_id\": {},",
        json_optional_hash(pending.as_ref().map(|bundle| bundle.object_id()))
    );
    println!("  \"capture_receipts\": {},", captures.len());
    println!(
        "  \"active_parent_qualification\": {},",
        serde_json::to_string(&active_parent_qualification)?
    );
    println!(
        "  \"pending_parent_qualification\": {}",
        serde_json::to_string(&pending_parent_qualification)?
    );
    println!("}}");
    Ok(())
}

fn serve(config: CoreConfig) -> Result<(), Box<dyn Error>> {
    validate_config(&config)?;
    let (core_key, operator_key) = load_keys(&config)?;
    let oracle = load_parent_oracle(&config)?;
    let store = open_store(&config.state_path)?;
    let engine = CoreAdmissionEngine::new(
        store.as_ref(),
        config.network_id,
        &core_key,
        &operator_key,
        &oracle,
    );
    let active = engine
        .active_bundle()?
        .ok_or("no active bundle; use stage-bundle before serve")?;
    oracle.qualify_active(&active.parent_certificate)?;
    // SAFETY: geteuid has no arguments and only reads process credentials.
    let owner = unsafe { libc::geteuid() };
    let listener = bind_secure_listener(&config.socket_path, owner)?;
    let limits = CoreLinkLimits {
        maximum_frame_bytes: config
            .maximum_frame_bytes
            .unwrap_or(MAX_CORE_LINK_FRAME_BYTES),
        read_timeout_ms: config
            .read_timeout_ms
            .unwrap_or(DEFAULT_PARENT_REQUALIFICATION_INTERVAL_MS),
        write_timeout_ms: config
            .write_timeout_ms
            .unwrap_or(MAX_CORE_LINK_WRITE_TIMEOUT_MS),
    };
    println!("listening on {}", config.socket_path.display());
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("accept failed: {error}");
                continue;
            }
        };
        match authenticate_server(
            stream,
            config.network_id,
            &core_key,
            parse_hash(&config.expected_gateway_pubkey)?,
            config.expected_peer_uid,
            limits,
        ) {
            Ok(mut connection) => {
                if let Err(error) =
                    serve_connection(&mut connection, &engine, &oracle, store.as_ref(), &config)
                {
                    eprintln!("Core-link connection ended: {error}");
                }
            }
            Err(error) => eprintln!("authentication rejected: {error}"),
        }
    }
    Ok(())
}

fn serve_connection(
    connection: &mut meshmine_core_link::CoreLinkConnection,
    engine: &CoreAdmissionEngine<'_>,
    oracle: &LiveParentOracle,
    store: &dyn DurableStore,
    config: &CoreConfig,
) -> Result<(), Box<dyn Error>> {
    send_assignment_state(connection, engine, oracle)?;
    loop {
        let message = match connection.receive() {
            Ok(message) => message,
            Err(TransportError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                ensure_active_parent(engine, oracle)?;
                connection.send(&CoreLinkMessage::Heartbeat(
                    meshmine_core_link::HeartbeatV1 {
                        link_protocol_version: CORE_LINK_PROTOCOL_V1,
                        network_id: config.network_id,
                        sent_at_ms: wall_ms()?,
                        current_bundle_id: engine
                            .active_bundle()?
                            .map(|bundle| bundle.object_id())
                            .unwrap_or([0; 32]),
                        pending_capture_count: 0,
                    },
                ))?;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        match message {
            CoreLinkMessage::AssignmentAck(ack) => {
                let gateway = parse_hash(&config.expected_gateway_pubkey)?;
                verify_object(
                    &gateway,
                    ED25519_SUITE,
                    &ack.gateway_signature,
                    config.network_id,
                    &ack,
                )
                .map_err(|_| "invalid assignment acknowledgment signature")?;
                let active = engine.active_bundle()?;
                let pending = engine.pending_bundle()?;
                let known = active.iter().chain(pending.iter()).any(|bundle| {
                    bundle.object_id() == ack.bundle_id
                        && bundle.assignment.object_id() == ack.assignment_id
                });
                if !known || ack.gateway_pubkey != gateway {
                    return Err("assignment acknowledgment references unknown state".into());
                }
                store.put_if_absent(
                    CORE_ACK_NAMESPACE,
                    &hex::encode(ack.bundle_id),
                    &ack.to_canonical_bytes(),
                )?;
            }
            CoreLinkMessage::CaptureSubmission(submission) => {
                match engine.admit_capture(&submission.envelope, wall_ms()?) {
                    Ok(admission) => connection.send(&CoreLinkMessage::CaptureDisposition(
                        CaptureDispositionV1 {
                            link_protocol_version: CORE_LINK_PROTOCOL_V1,
                            network_id: config.network_id,
                            request_id: submission.request_id,
                            receipt: admission.receipt,
                        },
                    ))?,
                    Err(error) => send_error(
                        connection,
                        config.network_id,
                        submission.request_id,
                        100,
                        false,
                        &error.to_string(),
                    )?,
                }
            }
            CoreLinkMessage::DrainSubmission(submission) => {
                let pending = engine.pending_bundle()?.ok_or("no pending bundle")?;
                if submission.next_bundle_id != pending.object_id() {
                    send_error(
                        connection,
                        config.network_id,
                        submission.request_id,
                        200,
                        false,
                        "drain references a different pending bundle",
                    )?;
                    continue;
                }
                oracle.qualify_active(&pending.parent_certificate)?;
                match engine.complete_pending_transition(
                    &submission.drain,
                    &submission.transition,
                    wall_ms()?,
                ) {
                    Ok(receipt) => {
                        connection.send(&CoreLinkMessage::DrainDisposition(
                            DrainDispositionV1 {
                                link_protocol_version: CORE_LINK_PROTOCOL_V1,
                                network_id: config.network_id,
                                request_id: submission.request_id,
                                receipt,
                            },
                        ))?;
                        send_assignment_state(connection, engine, oracle)?;
                    }
                    Err(error) => send_error(
                        connection,
                        config.network_id,
                        submission.request_id,
                        201,
                        false,
                        &error.to_string(),
                    )?,
                }
            }
            CoreLinkMessage::Heartbeat(heartbeat) => {
                ensure_active_parent(engine, oracle)?;
                connection.send(&CoreLinkMessage::Heartbeat(
                    meshmine_core_link::HeartbeatV1 {
                        link_protocol_version: CORE_LINK_PROTOCOL_V1,
                        network_id: config.network_id,
                        sent_at_ms: wall_ms()?,
                        current_bundle_id: engine
                            .active_bundle()?
                            .map(|bundle| bundle.object_id())
                            .unwrap_or(heartbeat.current_bundle_id),
                        pending_capture_count: heartbeat.pending_capture_count,
                    },
                ))?;
            }
            _ => send_error(
                connection,
                config.network_id,
                [0; 32],
                1,
                false,
                "message is invalid in the Core server role",
            )?,
        }
    }
}

fn send_assignment_state(
    connection: &mut meshmine_core_link::CoreLinkConnection,
    engine: &CoreAdmissionEngine<'_>,
    oracle: &LiveParentOracle,
) -> Result<(), Box<dyn Error>> {
    let active = engine
        .active_bundle()?
        .ok_or(AdmissionError::NoActiveBundle)?;
    oracle.qualify_active(&active.parent_certificate)?;
    connection.send(&CoreLinkMessage::AssignmentOffer(active.clone()))?;
    if let Some(pending) = engine.pending_bundle()? {
        oracle.qualify_active(&pending.parent_certificate)?;
        connection.send(&CoreLinkMessage::AssignmentOffer(pending.clone()))?;
        let replacement = pending
            .replacement
            .as_ref()
            .ok_or("pending bundle lacks replacement")?;
        connection.send(&CoreLinkMessage::DrainRequired(DrainRequiredV1 {
            link_protocol_version: CORE_LINK_PROTOCOL_V1,
            network_id: pending.network_id,
            current_assignment_id: active.assignment.object_id(),
            next_bundle_id: pending.object_id(),
            next_assignment_id: pending.assignment.object_id(),
            credit_cutoff_ms: replacement.credit_cutoff_ms,
            previous_submission_end_ms: replacement.previous_submission_end_ms,
        }))?;
    }
    Ok(())
}

fn ensure_active_parent(
    engine: &CoreAdmissionEngine<'_>,
    oracle: &LiveParentOracle,
) -> Result<(), Box<dyn Error>> {
    let active = engine
        .active_bundle()?
        .ok_or(AdmissionError::NoActiveBundle)?;
    oracle.qualify_active(&active.parent_certificate)?;
    Ok(())
}

fn send_error(
    connection: &mut meshmine_core_link::CoreLinkConnection,
    network_id: u8,
    request_id: [u8; 32],
    error_code: u16,
    retryable: bool,
    message: &str,
) -> Result<(), TransportError> {
    let bounded = message.chars().take(1024).collect::<String>();
    connection.send(&CoreLinkMessage::Error(CoreLinkErrorV1 {
        link_protocol_version: CORE_LINK_PROTOCOL_V1,
        network_id,
        request_id,
        error_code,
        retryable,
        message: bounded,
    }))
}

fn load_config(path: &Path) -> Result<CoreConfig, Box<dyn Error>> {
    let config: CoreConfig = serde_json::from_slice(&read_secure_file(
        path,
        MAX_CONFIG_BYTES,
        false,
        "Core-link config",
    )?)?;
    validate_config(&config)?;
    Ok(config)
}

fn validate_config(config: &CoreConfig) -> Result<(), Box<dyn Error>> {
    if config.schema_version != 2 || config.production {
        return Err("Core-link service requires schema 2 and production=false".into());
    }
    for (path, name) in [
        (&config.socket_path, "socket"),
        (&config.state_path, "state"),
        (&config.core_signing_key_file, "Core signing key"),
        (&config.operator_signing_key_file, "operator signing key"),
        (&config.parent_oracle_file, "parent oracle"),
    ] {
        validate_absolute(path, name)?;
    }
    let gateway = parse_hash(&config.expected_gateway_pubkey)?;
    let read_timeout_ms = config
        .read_timeout_ms
        .unwrap_or(DEFAULT_PARENT_REQUALIFICATION_INTERVAL_MS);
    let write_timeout_ms = config
        .write_timeout_ms
        .unwrap_or(MAX_CORE_LINK_WRITE_TIMEOUT_MS);
    if gateway == [0; 32]
        || config
            .maximum_frame_bytes
            .unwrap_or(MAX_CORE_LINK_FRAME_BYTES)
            > MAX_CORE_LINK_FRAME_BYTES
        || config.maximum_frame_bytes == Some(0)
        || read_timeout_ms == 0
        || read_timeout_ms > MAX_PARENT_REQUALIFICATION_INTERVAL_MS
        || write_timeout_ms == 0
        || write_timeout_ms > MAX_CORE_LINK_WRITE_TIMEOUT_MS
    {
        return Err(
            "invalid Core-link identity, frame limit, or bounded parent-requalification timeout"
                .into(),
        );
    }
    Ok(())
}

fn load_keys(config: &CoreConfig) -> Result<(SigningKey, SigningKey), Box<dyn Error>> {
    Ok((
        load_signing_key(&config.core_signing_key_file, "Core signing key")?,
        load_signing_key(&config.operator_signing_key_file, "operator signing key")?,
    ))
}

fn load_signing_key(path: &Path, description: &str) -> Result<SigningKey, Box<dyn Error>> {
    let bytes = read_secure_file(path, MAX_KEY_BYTES, true, description)?;
    let text = String::from_utf8(bytes)?;
    let decoded = hex::decode(text.trim())?;
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| format!("{description} must contain exactly 32 hexadecimal bytes"))?;
    Ok(SigningKey::from_bytes(&key))
}

fn load_parent_oracle(config: &CoreConfig) -> Result<LiveParentOracle, Box<dyn Error>> {
    let file: ParentOracleFile = serde_json::from_slice(&read_secure_file(
        &config.parent_oracle_file,
        MAX_PARENT_ORACLE_BYTES,
        false,
        "parent oracle configuration",
    )?)?;
    if file.schema_version != 2 || file.network_id != config.network_id {
        return Err("parent oracle schema or network mismatch".into());
    }
    let policy = LiveParentPolicy {
        network_id: file.network_id,
        minimum_confirmations: file.minimum_confirmations,
        maximum_certificate_depth: file.maximum_certificate_depth,
        maximum_header_age: Duration::from_millis(file.maximum_header_age_ms),
        cache_ttl: Duration::from_millis(file.cache_ttl_ms),
    };
    let hsrd = build_parent_source(file.hsrd)?;
    Ok(LiveParentOracle::new(policy, hsrd)?)
}

fn build_parent_source(source: ParentRpcSourceFile) -> Result<ParentRpcSource, Box<dyn Error>> {
    let address: SocketAddr = source.address.parse()?;
    let bytes = read_secure_file(
        &source.authorization_header_file,
        MAX_PARENT_AUTHORIZATION_BYTES as u64,
        true,
        "hsrd RPC authorization header",
    )?;
    let authorization_header = String::from_utf8(bytes)?.trim().to_owned();
    if authorization_header.is_empty()
        || authorization_header
            .chars()
            .any(|character| matches!(character, '\r' | '\n'))
    {
        return Err("hsrd RPC authorization header must be one nonempty line".into());
    }
    let runtime = ParentRpcSource {
        label: source.label,
        address,
        path: source.path,
        authorization_header,
        connect_timeout: Duration::from_millis(source.connect_timeout_ms),
        read_timeout: Duration::from_millis(source.read_timeout_ms),
        write_timeout: Duration::from_millis(source.write_timeout_ms),
        maximum_response_bytes: source.maximum_response_bytes,
    };
    runtime.validate()?;
    if runtime.maximum_response_bytes > MAX_PARENT_RPC_RESPONSE_BYTES {
        return Err("parent RPC response bound exceeds the hard maximum".into());
    }
    Ok(runtime)
}

fn load_bundle(path: &Path) -> Result<CoreAssignmentBundleV1, Box<dyn Error>> {
    let bytes = read_secure_file(path, MAX_BUNDLE_FILE_BYTES, false, "assignment bundle")?;
    Ok(CoreAssignmentBundleV1::from_canonical_bytes(
        &bytes,
        DecodeLimits {
            max_object_bytes: MAX_CORE_ASSIGNMENT_BUNDLE_BYTES,
            max_vector_items: 100_000,
        },
    )?)
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

fn read_secure_file(
    path: &Path,
    maximum_bytes: u64,
    private: bool,
    description: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    validate_absolute(path, description)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(format!("{description} is not a bounded regular file").into());
    }
    // SAFETY: geteuid has no arguments and only reads process credentials.
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
    let mut bytes = Vec::new();
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(format!("{description} grew while being read").into());
    }
    Ok(bytes)
}

fn parse_hash(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let bytes = hex::decode(value)?;
    Ok(bytes
        .try_into()
        .map_err(|_| "expected exactly 32 hexadecimal bytes")?)
}

fn single_path_argument<'a>(
    arguments: &'a [String],
    name: &str,
) -> Result<&'a Path, Box<dyn Error>> {
    let position = arguments
        .iter()
        .position(|argument| argument == name)
        .ok_or_else(usage)?;
    arguments
        .get(position + 1)
        .map(Path::new)
        .ok_or_else(|| usage().into())
}

fn validate_absolute(path: &Path, name: &str) -> Result<(), Box<dyn Error>> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!("{name} path must be absolute without parent traversal").into());
    }
    Ok(())
}

fn wall_ms() -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn json_optional_hash(value: Option<[u8; 32]>) -> String {
    value
        .map(|hash| format!("\"{}\"", hex::encode(hash)))
        .unwrap_or_else(|| "null".to_owned())
}

fn usage() -> String {
    "usage:\n  meshmine-cored serve --config /absolute/core.json\n  meshmine-cored stage-bundle --config /absolute/core.json --bundle /absolute/bundle.bin\n  meshmine-cored status --config /absolute/core.json".to_owned()
}
