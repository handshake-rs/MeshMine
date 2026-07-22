//! Live local HNS parent qualification for MeshMine Core.
//!
//! The oracle deliberately supports one bounded, authenticated, loopback hsrd
//! JSON-RPC source. It consumes one immutable `getparentauthority` snapshot so
//! authority, active-tip membership, validation status, and header fields
//! cannot be assembled across a tip transition. HSD is an offline fixture
//! oracle only and has no runtime role here.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use meshmine_share::ParentChainOracle;
use meshmine_types::{SessionParentCertificateV2, UnsignedObject};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

pub const MAX_PARENT_RPC_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PARENT_RPC_PATH_BYTES: usize = 512;
pub const MAX_PARENT_AUTHORIZATION_BYTES: usize = 4096;
pub const MIN_HSRD_PARENT_AUTHORITY_API_VERSION: u32 = 9;
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct ParentRpcSource {
    pub label: String,
    pub address: SocketAddr,
    pub path: String,
    pub authorization_header: String,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub maximum_response_bytes: usize,
}

impl std::fmt::Debug for ParentRpcSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParentRpcSource")
            .field("label", &self.label)
            .field("address", &self.address)
            .field("path", &self.path)
            .field("authorization_header", &"[REDACTED]")
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("write_timeout", &self.write_timeout)
            .field("maximum_response_bytes", &self.maximum_response_bytes)
            .finish()
    }
}

impl ParentRpcSource {
    pub fn validate(&self) -> Result<(), ParentOracleError> {
        if self.label.is_empty()
            || self.label.len() > 64
            || self.label.chars().any(char::is_control)
            || !self.address.ip().is_loopback()
            || !self.path.starts_with('/')
            || self.path.len() > MAX_PARENT_RPC_PATH_BYTES
            || self
                .path
                .chars()
                .any(|character| matches!(character, '\r' | '\n'))
            || self.connect_timeout.is_zero()
            || self.read_timeout.is_zero()
            || self.write_timeout.is_zero()
            || self.maximum_response_bytes == 0
            || self.maximum_response_bytes > MAX_PARENT_RPC_RESPONSE_BYTES
            || self.authorization_header.is_empty()
            || self.authorization_header.len() > MAX_PARENT_AUTHORIZATION_BYTES
            || self
                .authorization_header
                .chars()
                .any(|character| matches!(character, '\r' | '\n'))
        {
            return Err(ParentOracleError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct LiveParentPolicy {
    pub network_id: u8,
    pub minimum_confirmations: u32,
    pub maximum_certificate_depth: u32,
    pub maximum_header_age: Duration,
    pub cache_ttl: Duration,
}

impl LiveParentPolicy {
    pub fn validate(&self) -> Result<(), ParentOracleError> {
        if self.network_id > 3
            || self.minimum_confirmations == 0
            || self.maximum_certificate_depth.saturating_add(1) < self.minimum_confirmations
            || self.maximum_header_age.is_zero()
            || self.cache_ttl > Duration::from_secs(60)
        {
            return Err(ParentOracleError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentHeaderView {
    pub hash: String,
    pub height: u32,
    pub chainwork: String,
    pub confirmations: i64,
    pub time: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentChainView {
    pub blocks: u32,
    pub headers: u32,
    #[serde(rename = "bestblockhash")]
    pub best_block_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentAuthorityView {
    pub mode: String,
    pub consensus_complete: bool,
    pub can_authorize_mining_templates: bool,
    pub can_accept_mining_candidates: bool,
    pub blockers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentTipValidationView {
    pub header_context_valid: bool,
    pub checkpoint_valid: bool,
    pub deployment_state_valid: bool,
    pub body_present: bool,
    pub body_syntax_valid: bool,
    pub absolute_finality_valid: bool,
    pub relative_locks_valid: bool,
    pub scripts_valid: bool,
    pub covenant_links_valid: bool,
    pub covenants_context_valid: bool,
    pub claims_and_airdrops_valid: bool,
    pub utxo_connected: bool,
    pub name_state_connected: bool,
    pub tree_root_valid: bool,
    pub undo_present: bool,
    pub active_chain: bool,
    pub failed: bool,
}

impl ParentTipValidationView {
    fn is_mining_authoritative(&self) -> bool {
        self.header_context_valid
            && self.checkpoint_valid
            && self.deployment_state_valid
            && self.body_present
            && self.body_syntax_valid
            && self.absolute_finality_valid
            && self.relative_locks_valid
            && self.scripts_valid
            && self.covenant_links_valid
            && self.covenants_context_valid
            && self.claims_and_airdrops_valid
            && self.utxo_connected
            && self.name_state_connected
            && self.tree_root_valid
            && self.undo_present
            && self.active_chain
            && !self.failed
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ParentAuthoritySnapshot {
    api_version: u32,
    network: String,
    rpc_authentication_required: bool,
    chain: ParentChainView,
    header: ParentHeaderView,
    authority: ParentAuthorityView,
    authoritative_mining_tip: bool,
    pending_best_chain_activation: bool,
    tip_validation: Option<ParentTipValidationView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentQualificationStatus {
    pub checked_at_ms: u64,
    pub qualified: bool,
    pub tip_required: bool,
    pub certificate_id: String,
    pub parent_hash: String,
    pub parent_height: u32,
    pub authoritative_source: String,
    pub reason: String,
    pub hsrd: Option<ParentHeaderView>,
    pub hsrd_authority: Option<ParentAuthorityView>,
}

impl ParentQualificationStatus {
    fn initial() -> Self {
        Self {
            checked_at_ms: 0,
            qualified: false,
            tip_required: false,
            certificate_id: String::new(),
            parent_hash: String::new(),
            parent_height: 0,
            authoritative_source: String::new(),
            reason: "not checked".to_owned(),
            hsrd: None,
            hsrd_authority: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum ParentOracleError {
    #[error("parent-oracle configuration is invalid")]
    InvalidConfiguration,
    #[error("parent source transport failed: {0}")]
    Transport(String),
    #[error("parent source returned an invalid HTTP response")]
    Http,
    #[error("parent source returned an oversized response")]
    OversizedResponse,
    #[error("parent source returned malformed JSON-RPC")]
    JsonRpc,
    #[error("parent source rejected the JSON-RPC request: {0}")]
    Remote(String),
    #[error("parent source network does not match the certificate network")]
    Network,
    #[error("parent certificate is not on the authoritative active chain")]
    Noncanonical,
    #[error("parent certificate fields do not match the live HNS header")]
    CertificateMismatch,
    #[error("parent certificate is outside the configured confirmation/depth policy")]
    Depth,
    #[error("parent header is older than the configured freshness policy")]
    Stale,
    #[error("hsrd is not currently a complete native consensus authority")]
    AuthorityUnavailable,
    #[error("system clock is unavailable")]
    Clock,
}

#[derive(Clone, Debug)]
struct CachedQualification {
    certificate_id: [u8; 32],
    tip_required: bool,
    expires_at_ms: u64,
    status: ParentQualificationStatus,
}

pub struct LiveParentOracle {
    policy: LiveParentPolicy,
    hsrd: ParentRpcSource,
    cache: Mutex<Option<CachedQualification>>,
    status: Mutex<ParentQualificationStatus>,
}

impl LiveParentOracle {
    pub fn new(policy: LiveParentPolicy, hsrd: ParentRpcSource) -> Result<Self, ParentOracleError> {
        policy.validate()?;
        hsrd.validate()?;
        Ok(Self {
            policy,
            hsrd,
            cache: Mutex::new(None),
            status: Mutex::new(ParentQualificationStatus::initial()),
        })
    }

    pub fn status(&self) -> ParentQualificationStatus {
        self.status
            .lock()
            .map(|status| status.clone())
            .unwrap_or_else(|_| ParentQualificationStatus {
                reason: "status lock poisoned".to_owned(),
                ..ParentQualificationStatus::initial()
            })
    }

    pub fn qualify(
        &self,
        certificate: &SessionParentCertificateV2,
    ) -> Result<ParentQualificationStatus, ParentOracleError> {
        self.qualify_with_mode(certificate, false)
    }

    /// Qualify a certificate for an actively served mining assignment.
    ///
    /// Historical capture admission may accept a bounded canonical ancestor,
    /// but an active device job must build on the current authoritative tip.
    pub fn qualify_active(
        &self,
        certificate: &SessionParentCertificateV2,
    ) -> Result<ParentQualificationStatus, ParentOracleError> {
        self.qualify_with_mode(certificate, true)
    }

    fn qualify_with_mode(
        &self,
        certificate: &SessionParentCertificateV2,
        tip_required: bool,
    ) -> Result<ParentQualificationStatus, ParentOracleError> {
        let now_ms = wall_ms()?;
        let certificate_id = certificate.object_id();
        if let Ok(cache) = self.cache.lock()
            && let Some(cached) = cache.as_ref()
            && cached.certificate_id == certificate_id
            && cached.tip_required == tip_required
            && now_ms <= cached.expires_at_ms
        {
            return Ok(cached.status.clone());
        }

        let result = self.qualify_uncached(certificate, now_ms, tip_required);
        let status = match &result {
            Ok(status) => status.clone(),
            Err(error) => ParentQualificationStatus {
                checked_at_ms: now_ms,
                qualified: false,
                tip_required,
                certificate_id: hex::encode(certificate_id),
                parent_hash: hex::encode(certificate.parent_hash),
                parent_height: certificate.parent_height,
                authoritative_source: self.hsrd.label.clone(),
                reason: error.to_string(),
                hsrd: None,
                hsrd_authority: None,
            },
        };
        if let Ok(mut current) = self.status.lock() {
            *current = status.clone();
        }
        if result.is_ok() {
            if let Ok(mut cache) = self.cache.lock() {
                *cache = Some(CachedQualification {
                    certificate_id,
                    tip_required,
                    expires_at_ms: now_ms.saturating_add(
                        u64::try_from(self.policy.cache_ttl.as_millis()).unwrap_or(u64::MAX),
                    ),
                    status,
                });
            }
        } else if let Ok(mut cache) = self.cache.lock() {
            *cache = None;
        }
        result
    }

    fn qualify_uncached(
        &self,
        certificate: &SessionParentCertificateV2,
        now_ms: u64,
        tip_required: bool,
    ) -> Result<ParentQualificationStatus, ParentOracleError> {
        if certificate.network_id != self.policy.network_id {
            return Err(ParentOracleError::Network);
        }
        let snapshot = fetch_parent_authority(&self.hsrd, certificate.parent_hash)?;
        if snapshot.api_version < MIN_HSRD_PARENT_AUTHORITY_API_VERSION {
            return Err(ParentOracleError::AuthorityUnavailable);
        }
        if snapshot.network != expected_chain_name(self.policy.network_id)? {
            return Err(ParentOracleError::Network);
        }
        if !snapshot.rpc_authentication_required
            || snapshot.authority.mode != "native"
            || !snapshot.authority.consensus_complete
            || !snapshot.authority.can_authorize_mining_templates
            || !snapshot.authority.can_accept_mining_candidates
            || !snapshot.authority.blockers.is_empty()
            || !snapshot.authoritative_mining_tip
            || snapshot.pending_best_chain_activation
            || !snapshot
                .tip_validation
                .as_ref()
                .is_some_and(ParentTipValidationView::is_mining_authoritative)
        {
            return Err(ParentOracleError::AuthorityUnavailable);
        }
        validate_authoritative_header(
            &self.policy,
            certificate,
            &snapshot.chain,
            &snapshot.header,
            now_ms,
            tip_required,
        )?;

        let scope = if tip_required {
            "active-tip"
        } else {
            "canonical-depth"
        };
        Ok(ParentQualificationStatus {
            checked_at_ms: now_ms,
            qualified: true,
            tip_required,
            certificate_id: hex::encode(certificate.object_id()),
            parent_hash: hex::encode(certificate.parent_hash),
            parent_height: certificate.parent_height,
            authoritative_source: self.hsrd.label.clone(),
            reason: format!(
                "authenticated native hsrd {scope} consensus-authority qualification passed"
            ),
            hsrd: Some(snapshot.header),
            hsrd_authority: Some(snapshot.authority),
        })
    }
}

impl ParentChainOracle for LiveParentOracle {
    fn verify_header_and_chainwork(&self, certificate: &SessionParentCertificateV2) -> bool {
        self.qualify(certificate).is_ok()
    }
}

fn validate_authoritative_header(
    policy: &LiveParentPolicy,
    certificate: &SessionParentCertificateV2,
    chain: &ParentChainView,
    header: &ParentHeaderView,
    now_ms: u64,
    tip_required: bool,
) -> Result<(), ParentOracleError> {
    if header.confirmations <= 0
        || chain.headers < chain.blocks
        || chain.blocks < certificate.parent_height
    {
        return Err(ParentOracleError::Noncanonical);
    }
    let confirmations =
        u32::try_from(header.confirmations).map_err(|_| ParentOracleError::Depth)?;
    let depth = chain.blocks.saturating_sub(certificate.parent_height);
    if confirmations < policy.minimum_confirmations
        || depth > policy.maximum_certificate_depth
        || depth.saturating_add(1) != confirmations
    {
        return Err(ParentOracleError::Depth);
    }
    validate_certificate_fields(certificate, header)?;
    if tip_required
        && (confirmations != 1
            || chain.blocks != certificate.parent_height
            || !chain
                .best_block_hash
                .eq_ignore_ascii_case(&hex::encode(certificate.parent_hash)))
    {
        return Err(ParentOracleError::Noncanonical);
    }
    let age_ms = now_ms.saturating_sub(header.time.saturating_mul(1000));
    if age_ms > u64::try_from(policy.maximum_header_age.as_millis()).unwrap_or(u64::MAX) {
        return Err(ParentOracleError::Stale);
    }
    Ok(())
}

fn validate_certificate_fields(
    certificate: &SessionParentCertificateV2,
    header: &ParentHeaderView,
) -> Result<(), ParentOracleError> {
    let expected_hash = hex::encode(certificate.parent_hash);
    let expected_work = hex::encode(certificate.parent_chainwork.0);
    if !header.hash.eq_ignore_ascii_case(&expected_hash)
        || header.height != certificate.parent_height
        || header.time != certificate.observed_ntime
        || !normalize_chainwork_hex(&header.chainwork)?.eq_ignore_ascii_case(&expected_work)
    {
        return Err(ParentOracleError::CertificateMismatch);
    }
    Ok(())
}

fn fetch_parent_authority(
    source: &ParentRpcSource,
    hash: [u8; 32],
) -> Result<ParentAuthoritySnapshot, ParentOracleError> {
    let value = rpc_call(source, "getparentauthority", json!([hex::encode(hash)]))?;
    let snapshot = serde_json::from_value::<ParentAuthoritySnapshot>(value)
        .map_err(|_| ParentOracleError::JsonRpc)?;
    if snapshot.header.hash.len() != 64
        || hex::decode(&snapshot.header.hash).is_err()
        || snapshot.chain.best_block_hash.len() != 64
        || hex::decode(&snapshot.chain.best_block_hash).is_err()
    {
        return Err(ParentOracleError::JsonRpc);
    }
    normalize_chainwork_hex(&snapshot.header.chainwork)?;
    Ok(snapshot)
}

fn rpc_call(
    source: &ParentRpcSource,
    method: &str,
    params: Value,
) -> Result<Value, ParentOracleError> {
    source.validate()?;
    let id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    }))
    .map_err(|_| ParentOracleError::JsonRpc)?;
    let mut stream = TcpStream::connect_timeout(&source.address, source.connect_timeout)
        .map_err(|error| ParentOracleError::Transport(error.to_string()))?;
    stream
        .set_read_timeout(Some(source.read_timeout))
        .map_err(|error| ParentOracleError::Transport(error.to_string()))?;
    stream
        .set_write_timeout(Some(source.write_timeout))
        .map_err(|error| ParentOracleError::Transport(error.to_string()))?;
    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        source.path,
        source.address,
        body.len()
    );
    request.push_str("Authorization: ");
    request.push_str(&source.authorization_header);
    request.push_str("\r\n");
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.write_all(&body))
        .and_then(|_| stream.flush())
        .map_err(|error| ParentOracleError::Transport(error.to_string()))?;

    let maximum = source
        .maximum_response_bytes
        .checked_add(MAX_HTTP_HEADER_BYTES)
        .ok_or(ParentOracleError::OversizedResponse)?;
    let mut response = Vec::new();
    stream
        .take(u64::try_from(maximum + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut response)
        .map_err(|error| ParentOracleError::Transport(error.to_string()))?;
    if response.len() > maximum {
        return Err(ParentOracleError::OversizedResponse);
    }
    let body = parse_http_response(&response)?;
    if body.len() > source.maximum_response_bytes {
        return Err(ParentOracleError::OversizedResponse);
    }
    let envelope: Value = serde_json::from_slice(body).map_err(|_| ParentOracleError::JsonRpc)?;
    if envelope.get("id").and_then(Value::as_u64) != Some(id) {
        return Err(ParentOracleError::JsonRpc);
    }
    if let Some(error) = envelope.get("error").filter(|value| !value.is_null()) {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("remote JSON-RPC error")
            .chars()
            .take(1024)
            .collect::<String>();
        return Err(ParentOracleError::Remote(message));
    }
    envelope
        .get("result")
        .cloned()
        .ok_or(ParentOracleError::JsonRpc)
}

fn parse_http_response(response: &[u8]) -> Result<&[u8], ParentOracleError> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(ParentOracleError::Http)?;
    if separator > MAX_HTTP_HEADER_BYTES {
        return Err(ParentOracleError::Http);
    }
    let headers =
        std::str::from_utf8(&response[..separator]).map_err(|_| ParentOracleError::Http)?;
    let mut lines = headers.split("\r\n");
    let status = lines.next().ok_or(ParentOracleError::Http)?;
    if !(status.starts_with("HTTP/1.1 200 ") || status.starts_with("HTTP/1.0 200 ")) {
        return Err(ParentOracleError::Http);
    }
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(ParentOracleError::Http);
        };
        if name.eq_ignore_ascii_case("transfer-encoding") && !value.trim().is_empty() {
            return Err(ParentOracleError::Http);
        }
        if name.eq_ignore_ascii_case("content-length") {
            let length = value
                .trim()
                .parse::<usize>()
                .map_err(|_| ParentOracleError::Http)?;
            if content_length.replace(length).is_some() {
                return Err(ParentOracleError::Http);
            }
        }
    }
    let body = &response[separator + 4..];
    if let Some(length) = content_length
        && body.len() != length
    {
        return Err(ParentOracleError::Http);
    }
    Ok(body)
}

fn normalize_chainwork_hex(value: &str) -> Result<String, ParentOracleError> {
    if value.is_empty() || value.len() > 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ParentOracleError::JsonRpc);
    }
    let mut normalized = String::with_capacity(64);
    normalized.extend(std::iter::repeat_n('0', 64 - value.len()));
    normalized.push_str(value);
    Ok(normalized.to_ascii_lowercase())
}

fn expected_chain_name(network_id: u8) -> Result<&'static str, ParentOracleError> {
    match network_id {
        0 => Ok("mainnet"),
        1 => Ok("testnet"),
        2 => Ok("regtest"),
        3 => Ok("simnet"),
        _ => Err(ParentOracleError::Network),
    }
}

fn wall_ms() -> Result<u64, ParentOracleError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ParentOracleError::Clock)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| ParentOracleError::Clock)
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;

    use meshmine_types::{CORE_V2, SignatureSet, U256};

    use super::*;

    fn test_certificate(now_seconds: u64) -> SessionParentCertificateV2 {
        let mut work = [0u8; 32];
        work[31] = 1;
        SessionParentCertificateV2 {
            protocol_version: CORE_V2,
            network_id: 2,
            parent_hash: [7; 32],
            parent_height: 100,
            parent_chainwork: U256(work),
            observed_ntime: now_seconds,
            certificate_sequence: 1,
            previous_parent_certificate_id: [0; 32],
            signer_set: SignatureSet::empty_ed25519(),
        }
    }

    fn spawn_rpc_source_view(
        network: &'static str,
        header_hash: [u8; 32],
        header_time: u64,
        blocks: u32,
        best_block_hash: [u8; 32],
        confirmations: i64,
        authoritative: bool,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (headers, request) = read_http_request(&mut stream);
            assert!(
                headers
                    .lines()
                    .any(|line| { line.eq_ignore_ascii_case("Authorization: Bearer test-secret") })
            );
            let envelope: Value = serde_json::from_slice(&request).unwrap();
            let id = envelope.get("id").cloned().unwrap();
            assert_eq!(envelope["method"], "getparentauthority");
            let all_valid = json!({
                "header_context_valid": true,
                "checkpoint_valid": true,
                "deployment_state_valid": true,
                "body_present": true,
                "body_syntax_valid": true,
                "absolute_finality_valid": true,
                "relative_locks_valid": true,
                "scripts_valid": true,
                "covenant_links_valid": true,
                "covenants_context_valid": true,
                "claims_and_airdrops_valid": true,
                "utxo_connected": true,
                "name_state_connected": true,
                "tree_root_valid": true,
                "undo_present": true,
                "active_chain": true,
                "failed": false,
            });
            let result = json!({
                "api_version": MIN_HSRD_PARENT_AUTHORITY_API_VERSION,
                "network": network,
                "rpc_authentication_required": true,
                "chain": {
                    "blocks": blocks,
                    "headers": blocks,
                    "bestblockhash": hex::encode(best_block_hash),
                },
                "header": {
                        "hash": hex::encode(header_hash),
                        "height": 100,
                        "chainwork": "1",
                        "confirmations": confirmations,
                        "time": header_time,
                },
                "authority": {
                    "mode": "native",
                    "consensus_complete": authoritative,
                    "can_authorize_mining_templates": authoritative,
                    "can_accept_mining_candidates": authoritative,
                    "blockers": if authoritative { json!([]) } else { json!(["historical replay"]) },
                },
                "authoritative_mining_tip": authoritative,
                "pending_best_chain_activation": false,
                "tip_validation": all_valid,
            });
            let body = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result,
                "error": Value::Null,
            }))
            .unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
            stream.flush().unwrap();
        });
        address
    }

    fn read_http_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        let header_end = loop {
            let mut buffer = [0u8; 1024];
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&buffer[..read]);
            if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let headers = std::str::from_utf8(&bytes[..header_end])
            .unwrap()
            .to_owned();
        let content_length = headers
            .split("\r\n")
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        while bytes.len() < header_end + content_length {
            let mut buffer = [0u8; 1024];
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&buffer[..read]);
        }
        (
            headers,
            bytes[header_end..header_end + content_length].to_vec(),
        )
    }

    fn source(label: &str, address: SocketAddr) -> ParentRpcSource {
        ParentRpcSource {
            label: label.to_owned(),
            address,
            path: "/".to_owned(),
            authorization_header: "Bearer test-secret".to_owned(),
            connect_timeout: Duration::from_secs(1),
            read_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_secs(2),
            maximum_response_bytes: 64 * 1024,
        }
    }

    fn policy() -> LiveParentPolicy {
        LiveParentPolicy {
            network_id: 2,
            minimum_confirmations: 1,
            maximum_certificate_depth: 12,
            maximum_header_age: Duration::from_secs(60),
            cache_ttl: Duration::from_secs(1),
        }
    }

    #[test]
    fn authenticated_native_hsrd_canonical_depth_qualification_passes() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let certificate = test_certificate(now);
        let hsrd = spawn_rpc_source_view(
            "regtest",
            certificate.parent_hash,
            now,
            101,
            [9; 32],
            2,
            true,
        );
        let oracle = LiveParentOracle::new(policy(), source("hsrd", hsrd)).unwrap();
        let status = oracle.qualify(&certificate).unwrap();
        assert!(status.qualified);
        assert!(!status.tip_required);
        assert_eq!(status.hsrd.unwrap().confirmations, 2);
        assert!(status.hsrd_authority.unwrap().consensus_complete);
    }

    #[test]
    fn authenticated_native_hsrd_active_tip_qualification_passes() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let certificate = test_certificate(now);
        let hsrd = spawn_rpc_source_view(
            "regtest",
            certificate.parent_hash,
            now,
            certificate.parent_height,
            certificate.parent_hash,
            1,
            true,
        );
        let oracle = LiveParentOracle::new(policy(), source("hsrd", hsrd)).unwrap();
        let status = oracle.qualify_active(&certificate).unwrap();
        assert!(status.qualified);
        assert!(status.tip_required);
        assert_eq!(status.hsrd.unwrap().confirmations, 1);
    }

    #[test]
    fn active_tip_qualification_rejects_a_deep_canonical_parent() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let certificate = test_certificate(now);
        let hsrd = spawn_rpc_source_view(
            "regtest",
            certificate.parent_hash,
            now,
            101,
            [9; 32],
            2,
            true,
        );
        let oracle = LiveParentOracle::new(policy(), source("hsrd", hsrd)).unwrap();
        assert!(matches!(
            oracle.qualify_active(&certificate),
            Err(ParentOracleError::Noncanonical)
        ));
    }

    #[test]
    fn incomplete_hsrd_authority_fails_closed() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let certificate = test_certificate(now);
        let hsrd = spawn_rpc_source_view(
            "regtest",
            certificate.parent_hash,
            now,
            101,
            [9; 32],
            2,
            false,
        );
        let oracle = LiveParentOracle::new(policy(), source("hsrd", hsrd)).unwrap();
        assert!(matches!(
            oracle.qualify(&certificate),
            Err(ParentOracleError::AuthorityUnavailable)
        ));
        assert!(!oracle.status().qualified);
    }

    #[test]
    fn chainwork_is_left_padded() {
        assert_eq!(
            normalize_chainwork_hex("1").unwrap(),
            format!("{}1", "0".repeat(63))
        );
        assert!(normalize_chainwork_hex("").is_err());
        assert!(normalize_chainwork_hex(&"1".repeat(65)).is_err());
    }

    #[test]
    fn source_requires_an_authorization_header() {
        let unauthenticated = ParentRpcSource {
            label: "hsrd".to_owned(),
            address: "127.0.0.1:12037".parse().unwrap(),
            path: "/".to_owned(),
            authorization_header: String::new(),
            connect_timeout: Duration::from_secs(1),
            read_timeout: Duration::from_secs(1),
            write_timeout: Duration::from_secs(1),
            maximum_response_bytes: 1024,
        };
        assert!(LiveParentOracle::new(policy(), unauthenticated).is_err());
    }

    #[test]
    fn parser_rejects_chunked_or_non_200_responses() {
        assert!(parse_http_response(b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n").is_err());
        assert!(
            parse_http_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
                .is_err()
        );
    }
}
