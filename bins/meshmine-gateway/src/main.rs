use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use meshmine_gateway::{
    DeviceProfile, Gateway, GatewayJob, HardwareEvidence, PreviousJobTransition, RpcServeError,
    RpcSession, serve_rpc_connection,
};
use meshmine_hns::Hash256;
use meshmine_storage::RedbStore;
use meshmine_types::domain_hash;
use serde::Deserialize;

const MAX_JOB_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PASSWORD_FILE_BYTES: u64 = 1_024;
const MAX_PROCESS_AUTHORIZATION_FAILURES: u16 = 32;
// Keep process-level production admission separate from device evidence. A
// future verified ASIC profile must not accidentally enable this bounded
// harness before its durable share consumer exists.
const CAPTURE_CONSUMER_PRODUCTION_READY: bool = false;

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviousJobTransitionFile {
    job_id: String,
    credit_cutoff_ms: u64,
    submission_end_ms: u64,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("meshmine-gateway: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.first().map(String::as_str) != Some("serve") {
        return Err("usage: meshmine-gateway serve --listen 127.0.0.1:PORT --state FILE --job FILE --username USER --password-file FILE --profile simulator|handyminer|hs3|goldshell [--production] [--max-connections N] [--max-requests N]".into());
    }
    validate_arguments(&arguments)?;
    let address: SocketAddr = argument(&arguments, "--listen")?.parse()?;
    validate_loopback(address)?;
    let state = Path::new(argument(&arguments, "--state")?);
    let job_path = Path::new(argument(&arguments, "--job")?);
    let username = argument(&arguments, "--username")?;
    validate_runtime_path(state, "state")?;
    validate_runtime_path(job_path, "job")?;
    if username.is_empty() || username.len() > 100 {
        return Err("username must contain 1..100 UTF-8 bytes".into());
    }
    if optional_argument(&arguments, "--password").is_some() {
        return Err("--password is rejected because process arguments are public; use --password-file with mode 0600".into());
    }
    let password_path = Path::new(argument(&arguments, "--password-file")?);
    validate_runtime_path(password_path, "password")?;
    let password = read_password_file(password_path)?;
    // Research target policy must be an explicit operator choice. Falling
    // back to the simulator would silently weaken exact HandyStratum target
    // enforcement after a misspelled or omitted profile argument.
    let profile = profile(argument(&arguments, "--profile")?)?;
    let production_eligible =
        profile.validate_production().is_ok() && CAPTURE_CONSUMER_PRODUCTION_READY;
    if arguments.iter().any(|argument| argument == "--production") {
        profile.validate_production()?;
        if !CAPTURE_CONSUMER_PRODUCTION_READY {
            return Err(
                "production gateway is disabled until captures have a durable downstream consumer"
                    .into(),
            );
        }
    }
    let max_connections = optional_argument(&arguments, "--max-connections")
        .map(str::parse)
        .transpose()?
        .unwrap_or(1usize);
    let max_requests = optional_argument(&arguments, "--max-requests")
        .map(str::parse)
        .transpose()?
        .unwrap_or(10_000usize);
    if max_connections == 0
        || max_connections > 1_024
        || max_requests == 0
        || max_requests > 1_000_000
    {
        return Err("connection/request bound is outside the safe profile".into());
    }

    let job_file: JobFile = serde_json::from_slice(&read_bounded_file(
        job_path,
        MAX_JOB_FILE_BYTES,
        "job file",
    )?)?;
    let transition = job_file
        .previous_job_transition
        .as_ref()
        .map(|value| PreviousJobTransition {
            job_id: value.job_id.clone(),
            credit_cutoff_ms: value.credit_cutoff_ms,
            submission_end_ms: value.submission_end_ms,
        });
    let job: GatewayJob = job_file.try_into()?;
    // Bind before any assignment or nonce namespace becomes externally
    // durable. A bad/unavailable address must not burn an active job.
    let listener = TcpListener::bind(address)?;
    let store = Arc::new(RedbStore::create(state)?);
    let mut gateway = if profile.hardware_evidence() == HardwareEvidence::SimulatorOnly {
        Gateway::open_research_simulator(store)?
    } else {
        Gateway::open(store)?
    };
    let recovery_ms = wall_ms()?;
    validate_job_wall_window(job.issued_ms, job.assignment_end_ms, recovery_ms)?;
    gateway.close_expired(recovery_ms)?;
    // State recovery and retirement may touch bounded but substantial durable
    // history. Re-read the clock at the last possible point before issuance so
    // that work is not assigned using a window that expired during recovery.
    validate_job_wall_window(job.issued_ms, job.assignment_end_ms, wall_ms()?)?;
    let sequence = gateway.issue_job_with_transition(job, transition)?;
    let worker_id = domain_hash("meshmine/gateway-worker/v2", username.as_bytes());
    let nonce_prefix = gateway.assignment_nonce_prefix(&worker_id, sequence)?;
    println!("status=local-gateway-listening");
    println!("listen={}", listener.local_addr()?);
    println!("assignment_sequence={sequence}");
    println!("profile={}", profile.name());
    println!("production_eligible={production_eligible}");
    println!("telemetry_level={}", profile.telemetry_level() as u8);

    let mut authorization_failures = 0u16;
    for _ in 0..max_connections {
        let (stream, peer) = listener.accept()?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let session = RpcSession::new(username, &password, nonce_prefix, profile.clone());
        match serve_rpc_connection(stream, session, &mut gateway, max_requests) {
            Ok(session) => {
                authorization_failures = checked_authorization_failures(
                    authorization_failures,
                    session.authorization_failures(),
                )?;
            }
            Err(error @ RpcServeError::ClientIo { .. }) => {
                authorization_failures = checked_authorization_failures(
                    authorization_failures,
                    error.authorization_failures(),
                )?;
                eprintln!("meshmine-gateway: client connection failed: {error}");
            }
            Err(RpcServeError::Gateway(error)) => return Err(error.into()),
        }
    }
    println!("forwarded_captures={}", gateway.forwarded().len());
    Ok(())
}

fn checked_authorization_failures(
    accumulated: u16,
    session_failures: u8,
) -> Result<u16, Box<dyn Error>> {
    let accumulated = accumulated
        .checked_add(u16::from(session_failures))
        .ok_or("process authorization failure counter overflowed")?;
    if accumulated >= MAX_PROCESS_AUTHORIZATION_FAILURES {
        return Err("process authorization failure limit reached".into());
    }
    Ok(accumulated)
}

fn wall_ms() -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn validate_job_wall_window(
    issued_ms: u64,
    assignment_end_ms: u64,
    now_ms: u64,
) -> Result<(), Box<dyn Error>> {
    if now_ms < issued_ms {
        return Err("job assignment window has not started".into());
    }
    if now_ms > assignment_end_ms {
        return Err("job assignment window has already ended".into());
    }
    Ok(())
}

impl TryFrom<JobFile> for GatewayJob {
    type Error = Box<dyn Error>;

    fn try_from(value: JobFile) -> Result<Self, Self::Error> {
        Ok(Self {
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
                .map(|value| hash(value))
                .collect::<Result<_, _>>()?,
        })
    }
}

fn profile(name: &str) -> Result<DeviceProfile, Box<dyn Error>> {
    Ok(match name {
        "simulator" => DeviceProfile::simulator(),
        "handyminer" => DeviceProfile::handyminer_reference(),
        "hs3" => DeviceProfile::goldshell_hs3_experimental(),
        "goldshell" => DeviceProfile::goldshell_generic_experimental(),
        _ => return Err("unknown device profile".into()),
    })
}

fn validate_loopback(address: SocketAddr) -> Result<(), Box<dyn Error>> {
    if !address.ip().is_loopback() {
        return Err("legacy Stratum listener must use an explicit loopback address".into());
    }
    Ok(())
}

fn validate_runtime_path(path: &Path, description: &str) -> Result<(), Box<dyn Error>> {
    if !path.is_absolute() {
        return Err(format!("{description} path must be absolute").into());
    }
    Ok(())
}

fn read_password_file(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut file = open_runtime_file(path)?;
    let metadata = file.metadata()?;
    validate_opened_runtime_file(path, &metadata, true, "password file")?;
    let bytes = read_bounded_reader(
        &mut file,
        &metadata,
        MAX_PASSWORD_FILE_BYTES,
        "password file",
    )?;
    validate_opened_runtime_file(path, &file.metadata()?, true, "password file")?;
    let mut password = String::from_utf8(bytes)?;
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    if password.is_empty() || password.len() > 255 || password.contains(['\r', '\n']) {
        return Err("password file must contain one 1..255 byte UTF-8 line".into());
    }
    Ok(password)
}

fn open_runtime_file(path: &Path) -> Result<fs::File, Box<dyn Error>> {
    #[cfg(unix)]
    {
        Ok(fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?)
    }
    #[cfg(not(unix))]
    {
        Ok(fs::File::open(path)?)
    }
}

fn read_bounded_file(
    path: &Path,
    maximum_bytes: u64,
    description: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = open_runtime_file(path)?;
    let metadata = file.metadata()?;
    validate_opened_runtime_file(path, &metadata, false, description)?;
    let bytes = read_bounded_reader(&mut file, &metadata, maximum_bytes, description)?;
    validate_opened_runtime_file(path, &file.metadata()?, false, description)?;
    Ok(bytes)
}

fn validate_opened_runtime_file(
    path: &Path,
    opened: &fs::Metadata,
    private: bool,
    description: &str,
) -> Result<(), Box<dyn Error>> {
    if !opened.file_type().is_file() {
        return Err(format!("{description} must be a regular file, not a symlink").into());
    }
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no arguments and only reads process credentials.
        let effective_user = unsafe { libc::geteuid() };
        if opened.uid() != effective_user {
            return Err(format!("{description} must be owned by the current user").into());
        }
        let forbidden = if private { 0o077 } else { 0o022 };
        if opened.permissions().mode() & forbidden != 0 {
            let requirement = if private {
                "must not be accessible by group/other"
            } else {
                "must not be writable by group/other"
            };
            return Err(format!("{description} {requirement}").into());
        }

        let current = fs::symlink_metadata(path)?;
        if current.file_type().is_symlink()
            || !current.is_file()
            || current.dev() != opened.dev()
            || current.ino() != opened.ino()
        {
            return Err(format!("{description} path changed during descriptor validation").into());
        }
    }
    Ok(())
}

fn read_bounded_reader(
    reader: &mut fs::File,
    metadata: &fs::Metadata,
    maximum_bytes: u64,
    description: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(format!("{description} is not a regular bounded file").into());
    }
    let read_limit = maximum_bytes
        .checked_add(1)
        .ok_or_else(|| format!("{description} byte bound overflowed"))?;
    let initial_capacity = usize::try_from(maximum_bytes.min(64 * 1024))?;
    let mut bytes = Vec::with_capacity(initial_capacity);
    reader.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(format!("{description} changed while it was being read").into());
    }
    Ok(bytes)
}

fn hash(value: &str) -> Result<Hash256, Box<dyn Error>> {
    let bytes = hex::decode(value)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        format!(
            "expected 32-byte lowercase/uppercase hex, got {} bytes",
            bytes.len()
        )
        .into()
    })
}

fn argument<'a>(arguments: &'a [String], name: &str) -> Result<&'a str, Box<dyn Error>> {
    optional_argument(arguments, name).ok_or_else(|| format!("missing {name}").into())
}

fn validate_arguments(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    const VALUE_ARGUMENTS: &[&str] = &[
        "--listen",
        "--state",
        "--job",
        "--username",
        "--password-file",
        "--password",
        "--profile",
        "--max-connections",
        "--max-requests",
    ];
    const FLAG_ARGUMENTS: &[&str] = &["--production"];

    let mut seen = HashSet::new();
    let mut index = 1;
    while index < arguments.len() {
        let name = arguments[index].as_str();
        if !seen.insert(name) {
            return Err(format!("duplicate argument {name}").into());
        }
        if FLAG_ARGUMENTS.contains(&name) {
            index += 1;
            continue;
        }
        if !VALUE_ARGUMENTS.contains(&name) {
            return Err(format!("unknown argument {name}").into());
        }
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {name}"))?;
        if value.starts_with("--") {
            return Err(format!("missing value for {name}").into());
        }
        index += 2;
    }
    Ok(())
}

fn optional_argument<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secure_tempdir() -> std::io::Result<tempfile::TempDir> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        }
        Ok(directory)
    }

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn legacy_listener_is_loopback_only() {
        assert!(validate_loopback("127.0.0.1:3333".parse().unwrap()).is_ok());
        assert!(validate_loopback("[::1]:3333".parse().unwrap()).is_ok());
        assert!(validate_loopback("0.0.0.0:3333".parse().unwrap()).is_err());
    }

    #[test]
    fn safety_critical_runtime_paths_are_absolute() {
        assert!(validate_runtime_path(Path::new("/tmp/gateway.redb"), "state").is_ok());
        assert!(validate_runtime_path(Path::new("gateway.redb"), "state").is_err());
    }

    #[test]
    fn command_arguments_are_explicit_and_unambiguous() {
        let valid = arguments(&[
            "serve",
            "--listen",
            "127.0.0.1:3333",
            "--state",
            "/tmp/gateway.redb",
            "--job",
            "/tmp/job.json",
            "--username",
            "operator.worker",
            "--password-file",
            "/tmp/gateway.password",
            "--profile",
            "simulator",
            "--production",
        ]);
        assert!(validate_arguments(&valid).is_ok());
        assert_eq!(argument(&valid, "--profile").unwrap(), "simulator");

        let unknown = arguments(&["serve", "--profiel", "simulator"]);
        assert!(validate_arguments(&unknown).is_err());
        let duplicate = arguments(&["serve", "--profile", "simulator", "--profile", "handyminer"]);
        assert!(validate_arguments(&duplicate).is_err());
        let missing_value = arguments(&["serve", "--profile", "--production"]);
        assert!(validate_arguments(&missing_value).is_err());
        let missing_profile = arguments(&["serve", "--production"]);
        assert!(argument(&missing_profile, "--profile").is_err());
    }

    #[test]
    fn job_wall_window_is_closed_and_cannot_start_early() {
        assert!(validate_job_wall_window(10, 20, 9).is_err());
        assert!(validate_job_wall_window(10, 20, 10).is_ok());
        assert!(validate_job_wall_window(10, 20, 20).is_ok());
        assert!(validate_job_wall_window(10, 20, 21).is_err());
    }

    #[test]
    fn authorization_failures_have_a_process_wide_ceiling() {
        assert_eq!(checked_authorization_failures(0, 8).unwrap(), 8);
        assert_eq!(checked_authorization_failures(23, 8).unwrap(), 31);
        assert!(checked_authorization_failures(24, 8).is_err());
        assert!(checked_authorization_failures(u16::MAX, 1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn password_file_is_bounded_and_private() {
        let directory = secure_tempdir().unwrap();
        let path = directory.path().join("gateway.password");
        fs::write(&path, b"secret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_password_file(&path).unwrap(), "secret");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_password_file(&path).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, vec![b'x'; MAX_PASSWORD_FILE_BYTES as usize + 1]).unwrap();
        assert!(read_password_file(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn password_file_open_does_not_follow_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = secure_tempdir().unwrap();
        let target = directory.path().join("target.password");
        let link = directory.path().join("gateway.password");
        fs::write(&target, b"secret\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &link).unwrap();
        assert!(read_password_file(&link).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn job_file_is_owner_controlled_and_opened_without_following_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = secure_tempdir().unwrap();
        let target = directory.path().join("job.json");
        let link = directory.path().join("job-link.json");
        fs::write(&target, b"{}\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_bounded_file(&target, MAX_JOB_FILE_BYTES, "job file").unwrap(),
            b"{}\n"
        );

        fs::set_permissions(&target, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(read_bounded_file(&target, MAX_JOB_FILE_BYTES, "job file").is_err());

        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&target, &link).unwrap();
        assert!(read_bounded_file(&link, MAX_JOB_FILE_BYTES, "job file").is_err());
    }
}
