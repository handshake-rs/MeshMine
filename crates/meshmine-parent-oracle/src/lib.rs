//! Live local HNS parent qualification for MeshMine Core.
//!
//! The oracle deliberately supports only bounded loopback JSON-RPC sources.
//! One HSD source is authoritative for active-chain membership. An optional
//! HSRD source can be required as an independently implemented shadow witness.
//! Failure, disagreement, stale observations, malformed responses, and source
//! network mismatches all fail closed.

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
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParentSourceKind {
    Hsd,
    Hsrd,
}

#[derive(Clone, Debug)]
pub struct ParentRpcSource {
    pub label: String,
    pub kind: ParentSourceKind,
    pub address: SocketAddr,
    pub path: String,
    pub authorization_header: Option<String>,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub maximum_response_bytes: usize,
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
            || self.authorization_header.as_ref().is_some_and(|header| {
                header.is_empty()
                    || header.len() > MAX_PARENT_AUTHORIZATION_BYTES
                    || header
                        .chars()
                        .any(|character| matches!(character, '\r' | '\n'))
            })
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
    pub maximum_tip_lag_blocks: u32,
    pub maximum_header_age: Duration,
    pub cache_ttl: Duration,
    pub require_hsrd_match: bool,
}

impl LiveParentPolicy {
    pub fn validate(&self) -> Result<(), ParentOracleError> {
        if self.network_id > 3
            || self.minimum_confirmations == 0
            || self.maximum_certificate_depth.saturating_add(1) < self.minimum_confirmations
            || self.maximum_tip_lag_blocks > 100_000
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
    pub chain: String,
    pub blocks: u32,
    pub headers: u32,
    pub best_block_hash: String,
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
    pub shadow_source: Option<String>,
    pub reason: String,
    pub hsd: Option<ParentHeaderView>,
    pub hsrd: Option<ParentHeaderView>,
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
            shadow_source: None,
            reason: "not checked".to_owned(),
            hsd: None,
            hsrd: None,
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
    #[error("HSRD shadow source does not agree with HSD")]
    ShadowDisagreement,
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
    hsd: ParentRpcSource,
    hsrd: Option<ParentRpcSource>,
    cache: Mutex<Option<CachedQualification>>,
    status: Mutex<ParentQualificationStatus>,
}

impl LiveParentOracle {
    pub fn new(
        policy: LiveParentPolicy,
        hsd: ParentRpcSource,
        hsrd: Option<ParentRpcSource>,
    ) -> Result<Self, ParentOracleError> {
        policy.validate()?;
        hsd.validate()?;
        if hsd.kind != ParentSourceKind::Hsd {
            return Err(ParentOracleError::InvalidConfiguration);
        }
        if let Some(source) = hsrd.as_ref() {
            source.validate()?;
            if source.kind != ParentSourceKind::Hsrd {
                return Err(ParentOracleError::InvalidConfiguration);
            }
        }
        if policy.require_hsrd_match && hsrd.is_none() {
            return Err(ParentOracleError::InvalidConfiguration);
        }
        Ok(Self {
            policy,
            hsd,
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
                authoritative_source: self.hsd.label.clone(),
                shadow_source: self.hsrd.as_ref().map(|source| source.label.clone()),
                reason: error.to_string(),
                hsd: None,
                hsrd: None,
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
        let expected_chain = expected_chain_name(self.policy.network_id, ParentSourceKind::Hsd)?;
        let hsd_chain = fetch_chain_info(&self.hsd)?;
        if hsd_chain.chain != expected_chain {
            return Err(ParentOracleError::Network);
        }
        let hsd_header = fetch_header(&self.hsd, certificate.parent_hash)?;
        validate_authoritative_header(
            &self.policy,
            certificate,
            &hsd_chain,
            &hsd_header,
            now_ms,
            tip_required,
        )?;

        let mut hsrd_header = None;
        let mut shadow_note = None::<String>;
        if let Some(source) = self.hsrd.as_ref() {
            let shadow_result = (|| -> Result<ParentHeaderView, ParentOracleError> {
                let expected = expected_chain_name(self.policy.network_id, ParentSourceKind::Hsrd)?;
                let chain = fetch_chain_info(source)?;
                if chain.chain != expected {
                    return Err(ParentOracleError::Network);
                }
                let block_lag = hsd_chain.blocks.saturating_sub(chain.blocks);
                let header_lag = hsd_chain.headers.saturating_sub(chain.headers);
                if block_lag.max(header_lag) > self.policy.maximum_tip_lag_blocks {
                    return Err(ParentOracleError::ShadowDisagreement);
                }
                let header = fetch_header(source, certificate.parent_hash)?;
                validate_shadow_header(certificate, &hsd_header, &chain, &header, tip_required)?;
                Ok(header)
            })();
            match shadow_result {
                Ok(header) => hsrd_header = Some(header),
                Err(error) if self.policy.require_hsrd_match => return Err(error),
                Err(error) => shadow_note = Some(error.to_string()),
            }
        }
        if self.policy.require_hsrd_match && hsrd_header.is_none() {
            return Err(ParentOracleError::ShadowDisagreement);
        }

        let scope = if tip_required {
            "active-tip"
        } else {
            "canonical-depth"
        };
        let reason = match shadow_note {
            Some(note) => format!(
                "live HSD {scope} qualification passed; optional HSRD witness unavailable: {note}"
            ),
            None if hsrd_header.is_some() => {
                format!("live HSD {scope} qualification and HSRD shadow agreement passed")
            }
            None => format!("live HSD {scope} qualification passed"),
        };
        Ok(ParentQualificationStatus {
            checked_at_ms: now_ms,
            qualified: true,
            tip_required,
            certificate_id: hex::encode(certificate.object_id()),
            parent_hash: hex::encode(certificate.parent_hash),
            parent_height: certificate.parent_height,
            authoritative_source: self.hsd.label.clone(),
            shadow_source: self.hsrd.as_ref().map(|source| source.label.clone()),
            reason,
            hsd: Some(hsd_header),
            hsrd: hsrd_header,
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
    if header.confirmations <= 0 {
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

fn validate_shadow_header(
    certificate: &SessionParentCertificateV2,
    authoritative: &ParentHeaderView,
    chain: &ParentChainView,
    shadow: &ParentHeaderView,
    tip_required: bool,
) -> Result<(), ParentOracleError> {
    validate_certificate_fields(certificate, shadow)?;
    if shadow.confirmations <= 0
        || authoritative.hash != shadow.hash
        || authoritative.height != shadow.height
        || authoritative.chainwork != shadow.chainwork
        || authoritative.time != shadow.time
    {
        return Err(ParentOracleError::ShadowDisagreement);
    }
    if tip_required
        && (shadow.confirmations != 1
            || chain.blocks != certificate.parent_height
            || !chain
                .best_block_hash
                .eq_ignore_ascii_case(&hex::encode(certificate.parent_hash)))
    {
        return Err(ParentOracleError::ShadowDisagreement);
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

fn fetch_chain_info(source: &ParentRpcSource) -> Result<ParentChainView, ParentOracleError> {
    let value = rpc_call(source, "getblockchaininfo", json!([]))?;
    let chain = value
        .get("chain")
        .and_then(Value::as_str)
        .ok_or(ParentOracleError::JsonRpc)?
        .to_owned();
    let blocks = value
        .get("blocks")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(ParentOracleError::JsonRpc)?;
    let headers = value
        .get("headers")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(ParentOracleError::JsonRpc)?;
    let best_block_hash = value
        .get("bestblockhash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if best_block_hash.len() != 64 || hex::decode(&best_block_hash).is_err() {
        return Err(ParentOracleError::JsonRpc);
    }
    Ok(ParentChainView {
        chain,
        blocks,
        headers,
        best_block_hash,
    })
}

fn fetch_header(
    source: &ParentRpcSource,
    hash: [u8; 32],
) -> Result<ParentHeaderView, ParentOracleError> {
    let value = rpc_call(source, "getblockheader", json!([hex::encode(hash), true]))?;
    let header_hash = value
        .get("hash")
        .and_then(Value::as_str)
        .ok_or(ParentOracleError::JsonRpc)?
        .to_owned();
    if header_hash.len() != 64 || hex::decode(&header_hash).is_err() {
        return Err(ParentOracleError::JsonRpc);
    }
    let height = value
        .get("height")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(ParentOracleError::JsonRpc)?;
    let chainwork = value
        .get("chainwork")
        .and_then(Value::as_str)
        .ok_or(ParentOracleError::JsonRpc)?
        .to_owned();
    let confirmations = value
        .get("confirmations")
        .and_then(Value::as_i64)
        .ok_or(ParentOracleError::JsonRpc)?;
    let time = value
        .get("time")
        .and_then(Value::as_u64)
        .ok_or(ParentOracleError::JsonRpc)?;
    normalize_chainwork_hex(&chainwork)?;
    Ok(ParentHeaderView {
        hash: header_hash,
        height,
        chainwork,
        confirmations,
        time,
    })
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
    if let Some(header) = source.authorization_header.as_ref() {
        request.push_str("Authorization: ");
        request.push_str(header);
        request.push_str("\r\n");
    }
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

fn expected_chain_name(
    network_id: u8,
    kind: ParentSourceKind,
) -> Result<&'static str, ParentOracleError> {
    match (network_id, kind) {
        (0, ParentSourceKind::Hsd) => Ok("main"),
        (1, ParentSourceKind::Hsd) => Ok("test"),
        (2, ParentSourceKind::Hsd) => Ok("regtest"),
        (3, ParentSourceKind::Hsd) => Ok("simnet"),
        (0, ParentSourceKind::Hsrd) => Ok("mainnet"),
        (1, ParentSourceKind::Hsrd) => Ok("testnet"),
        (2, ParentSourceKind::Hsrd) => Ok("regtest"),
        (3, ParentSourceKind::Hsrd) => Ok("simnet"),
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

    fn spawn_rpc_source(
        chain_name: &'static str,
        header_hash: [u8; 32],
        header_time: u64,
    ) -> SocketAddr {
        spawn_rpc_source_view(chain_name, header_hash, header_time, 101, [9; 32], 2)
    }

    fn spawn_rpc_source_view(
        chain_name: &'static str,
        header_hash: [u8; 32],
        header_time: u64,
        blocks: u32,
        best_block_hash: [u8; 32],
        confirmations: i64,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                let envelope: Value = serde_json::from_slice(&request).unwrap();
                let id = envelope.get("id").cloned().unwrap();
                let method = envelope.get("method").and_then(Value::as_str).unwrap();
                let result = match method {
                    "getblockchaininfo" => json!({
                        "chain": chain_name,
                        "blocks": blocks,
                        "headers": blocks,
                        "bestblockhash": hex::encode(best_block_hash),
                    }),
                    "getblockheader" => json!({
                        "hash": hex::encode(header_hash),
                        "height": 100,
                        "chainwork": "1",
                        "confirmations": confirmations,
                        "time": header_time,
                    }),
                    _ => panic!("unexpected method"),
                };
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
            }
        });
        address
    }

    fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
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
        let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
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
        bytes[header_end..header_end + content_length].to_vec()
    }

    fn source(label: &str, kind: ParentSourceKind, address: SocketAddr) -> ParentRpcSource {
        ParentRpcSource {
            label: label.to_owned(),
            kind,
            address,
            path: "/".to_owned(),
            authorization_header: None,
            connect_timeout: Duration::from_secs(1),
            read_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_secs(2),
            maximum_response_bytes: 64 * 1024,
        }
    }

    fn policy(require_hsrd_match: bool) -> LiveParentPolicy {
        LiveParentPolicy {
            network_id: 2,
            minimum_confirmations: 1,
            maximum_certificate_depth: 12,
            maximum_tip_lag_blocks: 2,
            maximum_header_age: Duration::from_secs(60),
            cache_ttl: Duration::from_secs(1),
            require_hsrd_match,
        }
    }

    #[test]
    fn live_hsd_canonical_depth_qualification_passes() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let certificate = test_certificate(now);
        let hsd = spawn_rpc_source("regtest", certificate.parent_hash, now);
        let oracle = LiveParentOracle::new(
            policy(false),
            source("hsd", ParentSourceKind::Hsd, hsd),
            None,
        )
        .unwrap();
        let status = oracle.qualify(&certificate).unwrap();
        assert!(status.qualified);
        assert!(!status.tip_required);
        assert_eq!(status.hsd.unwrap().confirmations, 2);
    }

    #[test]
    fn live_hsd_active_tip_qualification_passes() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let certificate = test_certificate(now);
        let hsd = spawn_rpc_source_view(
            "regtest",
            certificate.parent_hash,
            now,
            certificate.parent_height,
            certificate.parent_hash,
            1,
        );
        let oracle = LiveParentOracle::new(
            policy(false),
            source("hsd", ParentSourceKind::Hsd, hsd),
            None,
        )
        .unwrap();
        let status = oracle.qualify_active(&certificate).unwrap();
        assert!(status.qualified);
        assert!(status.tip_required);
        assert_eq!(status.hsd.unwrap().confirmations, 1);
    }

    #[test]
    fn active_tip_qualification_rejects_a_deep_canonical_parent() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let certificate = test_certificate(now);
        let hsd = spawn_rpc_source("regtest", certificate.parent_hash, now);
        let oracle = LiveParentOracle::new(
            policy(false),
            source("hsd", ParentSourceKind::Hsd, hsd),
            None,
        )
        .unwrap();
        assert!(matches!(
            oracle.qualify_active(&certificate),
            Err(ParentOracleError::Noncanonical)
        ));
    }

    #[test]
    fn required_shadow_disagreement_fails_closed() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let certificate = test_certificate(now);
        let hsd = spawn_rpc_source("regtest", certificate.parent_hash, now);
        let hsrd = spawn_rpc_source("regtest", [8; 32], now);
        let oracle = LiveParentOracle::new(
            policy(true),
            source("hsd", ParentSourceKind::Hsd, hsd),
            Some(source("hsrd", ParentSourceKind::Hsrd, hsrd)),
        )
        .unwrap();
        assert!(matches!(
            oracle.qualify(&certificate),
            Err(ParentOracleError::CertificateMismatch | ParentOracleError::ShadowDisagreement)
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
    fn policy_requires_an_hsrd_source_when_agreement_is_mandatory() {
        let policy = LiveParentPolicy {
            network_id: 2,
            minimum_confirmations: 1,
            maximum_certificate_depth: 8,
            maximum_tip_lag_blocks: 2,
            maximum_header_age: Duration::from_secs(3600),
            cache_ttl: Duration::from_secs(1),
            require_hsrd_match: true,
        };
        let source = ParentRpcSource {
            label: "hsd".to_owned(),
            kind: ParentSourceKind::Hsd,
            address: "127.0.0.1:12037".parse().unwrap(),
            path: "/".to_owned(),
            authorization_header: None,
            connect_timeout: Duration::from_secs(1),
            read_timeout: Duration::from_secs(1),
            write_timeout: Duration::from_secs(1),
            maximum_response_bytes: 1024,
        };
        assert!(LiveParentOracle::new(policy, source, None).is_err());
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
