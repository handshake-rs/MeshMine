use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use meshmine_codec::{CanonicalDecode, CanonicalEncode, DecodeLimits};
use meshmine_crypto::{sign_object, verify_object};
use meshmine_hns::{Hash256, blake2b_256};
use meshmine_types::{CORE_V2, ED25519_SUITE};
use thiserror::Error;

use crate::{
    CORE_LINK_AUTH_TIMEOUT_MS, CORE_LINK_IDLE_TIMEOUT_MS, CORE_LINK_PROTOCOL_V1,
    CoreLinkAuthAcceptedV1, CoreLinkClientProofV1, CoreLinkMessage, CoreLinkServerChallengeV1,
    MAX_CORE_LINK_FRAME_BYTES, ProtocolError, validate_auth_context,
};

const FRAME_MAGIC: [u8; 4] = *b"MMK8";
const FRAME_HEADER_BYTES: usize = 20;
const FRAME_CHECKSUM_BYTES: usize = 32;
const AUTH_SERVER_CHALLENGE: u8 = 0xf0;
const AUTH_CLIENT_PROOF: u8 = 0xf1;
const AUTH_ACCEPTED: u8 = 0xf2;
const MAX_AUTH_FRAME_BYTES: usize = 4 * 1024;
const SOCKET_MODE: u32 = 0o600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreLinkLimits {
    pub maximum_frame_bytes: usize,
    pub read_timeout_ms: u64,
    pub write_timeout_ms: u64,
}

impl Default for CoreLinkLimits {
    fn default() -> Self {
        Self {
            maximum_frame_bytes: MAX_CORE_LINK_FRAME_BYTES,
            read_timeout_ms: CORE_LINK_IDLE_TIMEOUT_MS,
            write_timeout_ms: CORE_LINK_IDLE_TIMEOUT_MS,
        }
    }
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("core-link I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("core-link protocol failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("core-link authentication failed: {0}")]
    Authentication(&'static str),
    #[error("core-link signature verification failed")]
    Signature,
    #[error("core-link frame is malformed: {0}")]
    Malformed(&'static str),
    #[error("core-link frame sequence is not monotonic")]
    Sequence,
    #[error("core-link frame exceeds configured limits")]
    FrameLimit,
    #[error("core-link socket path is unsafe")]
    UnsafeSocket,
    #[error("peer credentials are unavailable on this platform")]
    PeerCredentialsUnavailable,
}

pub struct CoreLinkConnection {
    stream: UnixStream,
    network_id: u8,
    connection_id: Hash256,
    remote_pubkey: [u8; 32],
    send_sequence: u64,
    receive_sequence: u64,
    limits: CoreLinkLimits,
}

impl CoreLinkConnection {
    pub fn network_id(&self) -> u8 {
        self.network_id
    }
    pub fn connection_id(&self) -> Hash256 {
        self.connection_id
    }
    pub fn remote_pubkey(&self) -> [u8; 32] {
        self.remote_pubkey
    }

    pub fn send(&mut self, message: &CoreLinkMessage) -> Result<(), TransportError> {
        message.validate_context(self.network_id)?;
        let next = self
            .send_sequence
            .checked_add(1)
            .ok_or(TransportError::Sequence)?;
        let payload = message.encode_payload();
        write_frame(
            &mut self.stream,
            message.frame_kind(),
            next,
            &payload,
            self.limits,
        )?;
        self.send_sequence = next;
        Ok(())
    }

    pub fn receive(&mut self) -> Result<CoreLinkMessage, TransportError> {
        let (kind, sequence, payload) = read_frame(&mut self.stream, self.limits)?;
        let expected = self
            .receive_sequence
            .checked_add(1)
            .ok_or(TransportError::Sequence)?;
        if sequence != expected {
            return Err(TransportError::Sequence);
        }
        let message = CoreLinkMessage::decode(kind, &payload, self.limits.maximum_frame_bytes)?;
        message.validate_context(self.network_id)?;
        self.receive_sequence = sequence;
        Ok(message)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), TransportError> {
        self.stream.set_read_timeout(timeout)?;
        Ok(())
    }
}

pub fn bind_secure_listener(
    path: &Path,
    expected_owner: u32,
) -> Result<UnixListener, TransportError> {
    if !path.is_absolute() {
        return Err(TransportError::UnsafeSocket);
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket()
            || metadata.uid() != expected_owner
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(TransportError::UnsafeSocket);
        }
        match UnixStream::connect(path) {
            Ok(_) => return Err(TransportError::UnsafeSocket),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) => {}
            Err(error) => return Err(error.into()),
        }
        fs::remove_file(path)?;
    }
    let parent = path.parent().ok_or(TransportError::UnsafeSocket)?;
    let parent_meta = fs::symlink_metadata(parent)?;
    if !parent_meta.is_dir()
        || parent_meta.file_type().is_symlink()
        || (parent_meta.uid() != 0 && parent_meta.uid() != expected_owner)
    {
        return Err(TransportError::UnsafeSocket);
    }
    if parent_meta.permissions().mode() & 0o002 != 0
        && parent_meta.permissions().mode() & libc::S_ISVTX == 0
    {
        return Err(TransportError::UnsafeSocket);
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_owner
        || metadata.permissions().mode() & 0o077 != 0
    {
        let _ = fs::remove_file(path);
        return Err(TransportError::UnsafeSocket);
    }
    Ok(listener)
}

pub fn authenticate_server(
    mut stream: UnixStream,
    network_id: u8,
    core_signing_key: &SigningKey,
    expected_gateway_pubkey: [u8; 32],
    expected_peer_uid: u32,
    limits: CoreLinkLimits,
) -> Result<CoreLinkConnection, TransportError> {
    apply_timeouts(
        &stream,
        CORE_LINK_AUTH_TIMEOUT_MS,
        CORE_LINK_AUTH_TIMEOUT_MS,
    )?;
    let credentials = peer_credentials(&stream)?;
    if credentials.uid != expected_peer_uid {
        return Err(TransportError::Authentication("peer UID mismatch"));
    }
    let challenge_nonce: Hash256 = rand::random();
    let server_nonce: Hash256 = rand::random();
    let core_pubkey = core_signing_key.verifying_key().to_bytes();
    let mut challenge = CoreLinkServerChallengeV1 {
        core_protocol_version: CORE_V2,
        link_protocol_version: CORE_LINK_PROTOCOL_V1,
        network_id,
        core_handoff_pubkey: core_pubkey,
        expected_gateway_pubkey,
        challenge_nonce,
        server_nonce,
        issued_at_ms: wall_ms(),
        core_signature: meshmine_types::SignatureBytes::empty(),
    };
    challenge.core_signature = sign_object(core_signing_key, network_id, &challenge);
    write_frame(
        &mut stream,
        AUTH_SERVER_CHALLENGE,
        0,
        &challenge.to_canonical_bytes(),
        auth_limits(),
    )?;
    let (kind, sequence, payload) = read_frame(&mut stream, auth_limits())?;
    if kind != AUTH_CLIENT_PROOF || sequence != 0 {
        return Err(TransportError::Authentication("client proof frame"));
    }
    let proof = CoreLinkClientProofV1::from_canonical_bytes(
        &payload,
        DecodeLimits {
            max_object_bytes: MAX_AUTH_FRAME_BYTES,
            max_vector_items: 16,
        },
    )
    .map_err(|_| TransportError::Authentication("client proof encoding"))?;
    if !validate_auth_context(proof.core_protocol_version, proof.link_protocol_version)
        || proof.network_id != network_id
        || proof.gateway_pubkey != expected_gateway_pubkey
        || proof.core_handoff_pubkey != core_pubkey
        || proof.challenge_nonce != challenge_nonce
        || proof.server_nonce != server_nonce
        || proof.peer_uid != credentials.uid
        || proof.peer_pid != credentials.pid
    {
        return Err(TransportError::Authentication("client proof context"));
    }
    verify_object(
        &expected_gateway_pubkey,
        ED25519_SUITE,
        &proof.gateway_signature,
        network_id,
        &proof,
    )
    .map_err(|_| TransportError::Signature)?;
    let connection_id = connection_id(
        network_id,
        core_pubkey,
        expected_gateway_pubkey,
        challenge_nonce,
        server_nonce,
        proof.client_nonce,
        credentials,
    );
    let mut accepted = CoreLinkAuthAcceptedV1 {
        core_protocol_version: CORE_V2,
        link_protocol_version: CORE_LINK_PROTOCOL_V1,
        network_id,
        gateway_pubkey: expected_gateway_pubkey,
        core_handoff_pubkey: core_pubkey,
        challenge_nonce,
        server_nonce,
        client_nonce: proof.client_nonce,
        connection_id,
        accepted_at_ms: wall_ms(),
        core_signature: meshmine_types::SignatureBytes::empty(),
    };
    accepted.core_signature = sign_object(core_signing_key, network_id, &accepted);
    write_frame(
        &mut stream,
        AUTH_ACCEPTED,
        0,
        &accepted.to_canonical_bytes(),
        auth_limits(),
    )?;
    apply_timeouts(&stream, limits.read_timeout_ms, limits.write_timeout_ms)?;
    Ok(CoreLinkConnection {
        stream,
        network_id,
        connection_id,
        remote_pubkey: expected_gateway_pubkey,
        send_sequence: 0,
        receive_sequence: 0,
        limits,
    })
}

pub fn authenticate_client(
    mut stream: UnixStream,
    network_id: u8,
    gateway_signing_key: &SigningKey,
    pinned_core_pubkey: [u8; 32],
    limits: CoreLinkLimits,
) -> Result<CoreLinkConnection, TransportError> {
    apply_timeouts(
        &stream,
        CORE_LINK_AUTH_TIMEOUT_MS,
        CORE_LINK_AUTH_TIMEOUT_MS,
    )?;
    let (kind, sequence, payload) = read_frame(&mut stream, auth_limits())?;
    if kind != AUTH_SERVER_CHALLENGE || sequence != 0 {
        return Err(TransportError::Authentication("server challenge frame"));
    }
    let challenge = CoreLinkServerChallengeV1::from_canonical_bytes(
        &payload,
        DecodeLimits {
            max_object_bytes: MAX_AUTH_FRAME_BYTES,
            max_vector_items: 16,
        },
    )
    .map_err(|_| TransportError::Authentication("server challenge encoding"))?;
    let gateway_pubkey = gateway_signing_key.verifying_key().to_bytes();
    let now_ms = wall_ms();
    if challenge.issued_at_ms > now_ms.saturating_add(CORE_LINK_AUTH_TIMEOUT_MS)
        || now_ms.saturating_sub(challenge.issued_at_ms) > CORE_LINK_AUTH_TIMEOUT_MS
    {
        return Err(TransportError::Authentication("stale server challenge"));
    }
    if !validate_auth_context(
        challenge.core_protocol_version,
        challenge.link_protocol_version,
    ) || challenge.network_id != network_id
        || challenge.core_handoff_pubkey != pinned_core_pubkey
        || challenge.expected_gateway_pubkey != gateway_pubkey
    {
        return Err(TransportError::Authentication("server challenge context"));
    }
    verify_object(
        &pinned_core_pubkey,
        ED25519_SUITE,
        &challenge.core_signature,
        network_id,
        &challenge,
    )
    .map_err(|_| TransportError::Signature)?;
    let credentials = local_credentials();
    let client_nonce: Hash256 = rand::random();
    let mut proof = CoreLinkClientProofV1 {
        core_protocol_version: CORE_V2,
        link_protocol_version: CORE_LINK_PROTOCOL_V1,
        network_id,
        gateway_pubkey,
        core_handoff_pubkey: pinned_core_pubkey,
        challenge_nonce: challenge.challenge_nonce,
        server_nonce: challenge.server_nonce,
        client_nonce,
        peer_uid: credentials.uid,
        peer_pid: credentials.pid,
        gateway_signature: meshmine_types::SignatureBytes::empty(),
    };
    proof.gateway_signature = sign_object(gateway_signing_key, network_id, &proof);
    write_frame(
        &mut stream,
        AUTH_CLIENT_PROOF,
        0,
        &proof.to_canonical_bytes(),
        auth_limits(),
    )?;
    let (kind, sequence, payload) = read_frame(&mut stream, auth_limits())?;
    if kind != AUTH_ACCEPTED || sequence != 0 {
        return Err(TransportError::Authentication("auth accepted frame"));
    }
    let accepted = CoreLinkAuthAcceptedV1::from_canonical_bytes(
        &payload,
        DecodeLimits {
            max_object_bytes: MAX_AUTH_FRAME_BYTES,
            max_vector_items: 16,
        },
    )
    .map_err(|_| TransportError::Authentication("auth accepted encoding"))?;
    let now_ms = wall_ms();
    if accepted.accepted_at_ms > now_ms.saturating_add(CORE_LINK_AUTH_TIMEOUT_MS)
        || now_ms.saturating_sub(accepted.accepted_at_ms) > CORE_LINK_AUTH_TIMEOUT_MS
    {
        return Err(TransportError::Authentication("stale auth acceptance"));
    }
    let expected_connection_id = connection_id(
        network_id,
        pinned_core_pubkey,
        gateway_pubkey,
        challenge.challenge_nonce,
        challenge.server_nonce,
        client_nonce,
        credentials,
    );
    if !validate_auth_context(
        accepted.core_protocol_version,
        accepted.link_protocol_version,
    ) || accepted.network_id != network_id
        || accepted.gateway_pubkey != gateway_pubkey
        || accepted.core_handoff_pubkey != pinned_core_pubkey
        || accepted.challenge_nonce != challenge.challenge_nonce
        || accepted.server_nonce != challenge.server_nonce
        || accepted.client_nonce != client_nonce
        || accepted.connection_id != expected_connection_id
    {
        return Err(TransportError::Authentication("auth accepted context"));
    }
    verify_object(
        &pinned_core_pubkey,
        ED25519_SUITE,
        &accepted.core_signature,
        network_id,
        &accepted,
    )
    .map_err(|_| TransportError::Signature)?;
    apply_timeouts(&stream, limits.read_timeout_ms, limits.write_timeout_ms)?;
    Ok(CoreLinkConnection {
        stream,
        network_id,
        connection_id: accepted.connection_id,
        remote_pubkey: pinned_core_pubkey,
        send_sequence: 0,
        receive_sequence: 0,
        limits,
    })
}

pub fn connect_authenticated(
    path: &Path,
    network_id: u8,
    gateway_signing_key: &SigningKey,
    pinned_core_pubkey: [u8; 32],
    limits: CoreLinkLimits,
) -> Result<CoreLinkConnection, TransportError> {
    if !path.is_absolute() {
        return Err(TransportError::UnsafeSocket);
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(TransportError::UnsafeSocket);
    }
    authenticate_client(
        UnixStream::connect(path)?,
        network_id,
        gateway_signing_key,
        pinned_core_pubkey,
        limits,
    )
}

pub fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, TransportError> {
    #[cfg(target_os = "linux")]
    {
        let mut credentials = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: the descriptor is live, the output pointer is valid for
        // `length`, and the kernel initializes one `ucred` value.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if length as usize != std::mem::size_of::<libc::ucred>() || credentials.pid <= 0 {
            return Err(TransportError::PeerCredentialsUnavailable);
        }
        Ok(PeerCredentials {
            pid: u32::try_from(credentials.pid)
                .map_err(|_| TransportError::PeerCredentialsUnavailable)?,
            uid: credentials.uid,
            gid: credentials.gid,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        Err(TransportError::PeerCredentialsUnavailable)
    }
}

fn local_credentials() -> PeerCredentials {
    // SAFETY: credential queries take no pointers and do not mutate process state.
    PeerCredentials {
        pid: std::process::id(),
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
    }
}

fn connection_id(
    network_id: u8,
    core_pubkey: [u8; 32],
    gateway_pubkey: [u8; 32],
    challenge: Hash256,
    server_nonce: Hash256,
    client_nonce: Hash256,
    credentials: PeerCredentials,
) -> Hash256 {
    let mut bytes = Vec::with_capacity(1 + 32 * 5 + 12);
    bytes.push(network_id);
    bytes.extend_from_slice(&core_pubkey);
    bytes.extend_from_slice(&gateway_pubkey);
    bytes.extend_from_slice(&challenge);
    bytes.extend_from_slice(&server_nonce);
    bytes.extend_from_slice(&client_nonce);
    bytes.extend_from_slice(&credentials.pid.to_le_bytes());
    bytes.extend_from_slice(&credentials.uid.to_le_bytes());
    bytes.extend_from_slice(&credentials.gid.to_le_bytes());
    meshmine_types::domain_hash("meshmine/core-link-connection/v1", &bytes)
}

fn write_frame(
    stream: &mut UnixStream,
    kind: u8,
    sequence: u64,
    payload: &[u8],
    limits: CoreLinkLimits,
) -> Result<(), TransportError> {
    if payload.len() > limits.maximum_frame_bytes {
        return Err(TransportError::FrameLimit);
    }
    let length = u32::try_from(payload.len()).map_err(|_| TransportError::FrameLimit)?;
    let mut header = Vec::with_capacity(FRAME_HEADER_BYTES);
    header.extend_from_slice(&FRAME_MAGIC);
    header.extend_from_slice(&CORE_LINK_PROTOCOL_V1.to_le_bytes());
    header.push(kind);
    header.push(0);
    header.extend_from_slice(&sequence.to_le_bytes());
    header.extend_from_slice(&length.to_le_bytes());
    let checksum = blake2b_256(&[header.as_slice(), payload]);
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.write_all(&checksum)?;
    stream.flush()?;
    Ok(())
}

fn read_frame(
    stream: &mut UnixStream,
    limits: CoreLinkLimits,
) -> Result<(u8, u64, Vec<u8>), TransportError> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    stream.read_exact(&mut header)?;
    if header[..4] != FRAME_MAGIC
        || u16::from_le_bytes(
            header[4..6]
                .try_into()
                .map_err(|_| TransportError::Malformed("version"))?,
        ) != CORE_LINK_PROTOCOL_V1
        || header[7] != 0
    {
        return Err(TransportError::Malformed("frame header"));
    }
    let kind = header[6];
    let sequence = u64::from_le_bytes(
        header[8..16]
            .try_into()
            .map_err(|_| TransportError::Malformed("sequence"))?,
    );
    let length = u32::from_le_bytes(
        header[16..20]
            .try_into()
            .map_err(|_| TransportError::Malformed("length"))?,
    ) as usize;
    if length > limits.maximum_frame_bytes {
        return Err(TransportError::FrameLimit);
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;
    let mut checksum = [0u8; FRAME_CHECKSUM_BYTES];
    stream.read_exact(&mut checksum)?;
    if blake2b_256(&[header.as_slice(), payload.as_slice()]) != checksum {
        return Err(TransportError::Malformed("frame checksum"));
    }
    Ok((kind, sequence, payload))
}

fn auth_limits() -> CoreLinkLimits {
    CoreLinkLimits {
        maximum_frame_bytes: MAX_AUTH_FRAME_BYTES,
        read_timeout_ms: CORE_LINK_AUTH_TIMEOUT_MS,
        write_timeout_ms: CORE_LINK_AUTH_TIMEOUT_MS,
    }
}

fn apply_timeouts(stream: &UnixStream, read_ms: u64, write_ms: u64) -> Result<(), TransportError> {
    stream.set_read_timeout(Some(Duration::from_millis(read_ms)))?;
    stream.set_write_timeout(Some(Duration::from_millis(write_ms)))?;
    Ok(())
}

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| {
            u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
        })
}
