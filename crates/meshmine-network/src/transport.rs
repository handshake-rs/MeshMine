//! Native authenticated QUIC transport for MM-0001 section 16.
//!
//! TLS pins the addressed server certificate. Both sides additionally prove
//! their independent Ed25519 transport identity over a fresh server challenge,
//! keeping transport identity separate from the optional payout/operator key.
//! Each gossip message or large-object request gets its own bounded QUIC
//! bidirectional stream.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use meshmine_codec::{
    CanonicalDecode, CanonicalEncode, CodecError, DecodeLimits, Decoder, Encoder,
};
use meshmine_crypto::{sign_object, verify_object};
use meshmine_hns::Hash256;
use meshmine_types::{ED25519_SUITE, SignatureBytes, UnsignedObject};
use quinn::rustls::RootCertStore;
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig, VarInt};
use thiserror::Error;
use tokio::sync::{Semaphore, watch};
use tokio::time::timeout;

use crate::{
    GossipTopic, IngressDecision, NetworkError, ObjectEnvelope, OverlayNode, PeerHello,
    ProtocolLane, RequestProtocol,
};

const CORE_V2: u16 = 2;
const AUTH_STREAM: u8 = 0;
const GOSSIP_STREAM: u8 = 1;
const REQUEST_STREAM: u8 = 2;
const STATUS_OK: u8 = 0;
const STATUS_NOT_FOUND: u8 = 1;
const STATUS_REJECTED: u8 = 2;
const STATUS_QUOTA: u8 = 3;
const MAX_HELLO_BYTES: usize = 512;
const MAX_STATUS_BYTES: usize = 64;
const MAX_TRUSTED_SERVER_CERTIFICATES: usize = 8;

#[derive(Clone)]
pub struct TransportIdentity {
    signing_key: Arc<SigningKey>,
    economic_operator_pubkey: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuicTransportLimits {
    pub maximum_connections: usize,
    pub maximum_concurrent_streams: u32,
    /// Maximum application callbacks executing on Tokio's blocking pool for
    /// one server. Additional bounded streams wait without occupying a worker.
    pub maximum_blocking_callbacks: usize,
    /// Reserved callback capacity for tip/session/opening/fault traffic.
    pub maximum_fast_path_callbacks: usize,
    /// Reserved callback capacity for shares, receipts, and closes.
    pub maximum_accounting_callbacks: usize,
    /// Reserved callback capacity for body metadata and body retrieval.
    pub maximum_availability_callbacks: usize,
    /// Reserved callback capacity for snapshots, plans, and payout proofs.
    pub maximum_settlement_callbacks: usize,
    pub maximum_gossip_frame_bytes: usize,
    pub maximum_response_bytes: usize,
    pub authentication_timeout_ms: u64,
    pub idle_timeout_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedGossipFrame {
    pub protocol_version: u16,
    pub network_id: u8,
    pub topic: GossipTopic,
    pub object_id: Hash256,
    pub missing_parent: bool,
    pub parent_fetch_depth: u16,
    pub payload: Vec<u8>,
    pub transport_signature: SignatureBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlayRequest {
    pub protocol_version: u16,
    pub network_id: u8,
    pub protocol: RequestProtocol,
    pub object_id: Hash256,
    pub shard_index: Option<u16>,
}

pub trait OverlayApplication: Send + Sync + 'static {
    /// Perform the complete object-specific validation and durable write. A
    /// transport signature alone is never enough to return `true` here.
    fn validate_and_store_gossip(
        &self,
        peer: [u8; 32],
        topic: GossipTopic,
        object_id: Hash256,
        payload: &[u8],
    ) -> bool;

    /// Fetch a bounded response for a request/response stream. Body packages
    /// and shards are deliberately unavailable through gossip.
    fn load_response(&self, request: &OverlayRequest) -> Option<Vec<u8>>;
}

pub struct QuicOverlayServer<A: OverlayApplication> {
    endpoint: Endpoint,
    identity: TransportIdentity,
    network_id: u8,
    admission: Arc<Mutex<OverlayNode>>,
    application: Arc<A>,
    callback_gates: CallbackGates,
    limits: QuicTransportLimits,
}

pub struct QuicOverlayPeer {
    endpoint: Endpoint,
    connection: Connection,
    identity: TransportIdentity,
    network_id: u8,
    remote_transport_pubkey: [u8; 32],
    limits: QuicTransportLimits,
}

#[derive(Clone)]
struct CallbackGates {
    fast_path: Arc<Semaphore>,
    accounting: Arc<Semaphore>,
    availability: Arc<Semaphore>,
    settlement: Arc<Semaphore>,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("QUIC configuration failed: {0}")]
    Configuration(String),
    #[error("QUIC connection failed: {0}")]
    Connection(String),
    #[error("bounded transport frame is malformed: {0}")]
    MalformedFrame(String),
    #[error("mutual transport authentication failed: {0}")]
    Authentication(String),
    #[error("remote peer rejected the request")]
    RemoteRejected,
    #[error("remote peer body/request quota was exceeded")]
    RemoteQuota,
    #[error("local overlay admission rejected the request: {0}")]
    Admission(String),
    #[error("transport state mutex was poisoned")]
    Poisoned,
    #[error("transport blocking worker failed: {0}")]
    Worker(String),
}

impl Default for QuicTransportLimits {
    fn default() -> Self {
        Self {
            maximum_connections: 1_024,
            maximum_concurrent_streams: 128,
            maximum_blocking_callbacks: 128,
            maximum_fast_path_callbacks: 32,
            maximum_accounting_callbacks: 48,
            maximum_availability_callbacks: 32,
            maximum_settlement_callbacks: 16,
            maximum_gossip_frame_bytes: 1024 * 1024 + 1024,
            maximum_response_bytes: 4 * 1024 * 1024,
            authentication_timeout_ms: 5_000,
            idle_timeout_ms: 30_000,
        }
    }
}

impl CallbackGates {
    fn new(limits: QuicTransportLimits) -> Self {
        Self {
            fast_path: Arc::new(Semaphore::new(limits.maximum_fast_path_callbacks)),
            accounting: Arc::new(Semaphore::new(limits.maximum_accounting_callbacks)),
            availability: Arc::new(Semaphore::new(limits.maximum_availability_callbacks)),
            settlement: Arc::new(Semaphore::new(limits.maximum_settlement_callbacks)),
        }
    }

    fn gate(&self, lane: ProtocolLane) -> Arc<Semaphore> {
        match lane {
            ProtocolLane::FastPath => self.fast_path.clone(),
            ProtocolLane::Accounting => self.accounting.clone(),
            ProtocolLane::Availability => self.availability.clone(),
            ProtocolLane::Settlement => self.settlement.clone(),
        }
    }
}

impl TransportIdentity {
    pub fn new(signing_key: SigningKey, economic_operator_pubkey: Option<[u8; 32]>) -> Self {
        Self {
            signing_key: Arc::new(signing_key),
            economic_operator_pubkey,
        }
    }

    pub fn transport_pubkey(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    fn hello(&self, network_id: u8, challenge_nonce: Hash256) -> PeerHello {
        let mut hello = PeerHello {
            protocol_version: CORE_V2,
            network_id,
            transport_pubkey: self.transport_pubkey(),
            economic_operator_pubkey: self.economic_operator_pubkey,
            challenge_nonce,
            signature: SignatureBytes::empty(),
        };
        hello.signature = sign_object(self.signing_key.as_ref(), network_id, &hello);
        hello
    }
}

impl SignedGossipFrame {
    pub fn new_signed(
        identity: &TransportIdentity,
        network_id: u8,
        topic: GossipTopic,
        object_id: Hash256,
        missing_parent: bool,
        parent_fetch_depth: u16,
        payload: Vec<u8>,
    ) -> Self {
        let mut frame = Self {
            protocol_version: CORE_V2,
            network_id,
            topic,
            object_id,
            missing_parent,
            parent_fetch_depth,
            payload,
            transport_signature: SignatureBytes::empty(),
        };
        frame.transport_signature = sign_object(identity.signing_key.as_ref(), network_id, &frame);
        frame
    }
}

impl UnsignedObject for SignedGossipFrame {
    const DOMAIN_TAG: &'static str = "meshmine/quic-gossip-frame/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encoder.u16(self.protocol_version);
        encoder.u8(self.network_id);
        encoder.u8(topic_code(self.topic));
        encoder.fixed(&self.object_id);
        encoder.u8(u8::from(self.missing_parent));
        encoder.u16(self.parent_fetch_depth);
        encoder.bytes(&self.payload);
    }
}

impl CanonicalEncode for SignedGossipFrame {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        self.transport_signature.encode(encoder);
    }
}

impl SignedGossipFrame {
    fn decode_bounded(bytes: &[u8], maximum_payload: usize) -> Result<Self, CodecError> {
        let limits = DecodeLimits {
            max_object_bytes: maximum_payload.saturating_add(1024),
            max_vector_items: maximum_payload.saturating_add(1024),
        };
        let mut decoder = Decoder::new(bytes, limits)?;
        let frame = Self {
            protocol_version: decoder.u16()?,
            network_id: decoder.u8()?,
            topic: decode_topic(decoder.u8()?)?,
            object_id: decoder.array()?,
            missing_parent: match decoder.u8()? {
                0 => false,
                1 => true,
                _ => return Err(CodecError::InvalidField("invalid missing-parent flag")),
            },
            parent_fetch_depth: decoder.u16()?,
            payload: decoder.bytes(maximum_payload)?,
            transport_signature: SignatureBytes::decode(&mut decoder)?,
        };
        decoder.finish()?;
        Ok(frame)
    }
}

impl CanonicalEncode for OverlayRequest {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u16(self.protocol_version);
        encoder.u8(self.network_id);
        encoder.u8(request_code(self.protocol));
        encoder.fixed(&self.object_id);
        match self.shard_index {
            Some(index) => {
                encoder.u8(1);
                encoder.u16(index);
            }
            None => encoder.u8(0),
        }
    }
}

impl CanonicalDecode for OverlayRequest {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            protocol_version: decoder.u16()?,
            network_id: decoder.u8()?,
            protocol: decode_request(decoder.u8()?)?,
            object_id: decoder.array()?,
            shard_index: decoder.option(|decoder| decoder.u16())?,
        })
    }
}

impl<A: OverlayApplication> QuicOverlayServer<A> {
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        listen: SocketAddr,
        certificate_der: Vec<u8>,
        private_key_der: Vec<u8>,
        identity: TransportIdentity,
        network_id: u8,
        admission: OverlayNode,
        application: Arc<A>,
        limits: QuicTransportLimits,
    ) -> Result<Self, TransportError> {
        validate_limits(limits)?;
        let server_config = server_config(certificate_der, private_key_der, limits)?;
        let endpoint = Endpoint::server(server_config, listen)
            .map_err(|error| TransportError::Configuration(error.to_string()))?;
        Ok(Self {
            endpoint,
            identity,
            network_id,
            admission: Arc::new(Mutex::new(admission)),
            application,
            callback_gates: CallbackGates::new(limits),
            limits,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint
            .local_addr()
            .map_err(|error| TransportError::Configuration(error.to_string()))
    }

    pub fn admission(&self) -> Arc<Mutex<OverlayNode>> {
        self.admission.clone()
    }

    pub async fn run_until(
        self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), TransportError> {
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else { break; };
                    if self.endpoint.open_connections() >= self.limits.maximum_connections {
                        incoming.refuse();
                        continue;
                    }
                    let identity = self.identity.clone();
                    let admission = self.admission.clone();
                    let application = self.application.clone();
                    let callback_gates = self.callback_gates.clone();
                    let network_id = self.network_id;
                    let limits = self.limits;
                    tokio::spawn(async move {
                        let _ = handle_incoming(
                            incoming,
                            identity,
                            network_id,
                            admission,
                            application,
                            callback_gates,
                            limits,
                        ).await;
                    });
                }
            }
        }
        self.endpoint.close(VarInt::from_u32(0), b"shutdown");
        self.endpoint.wait_idle().await;
        Ok(())
    }
}

impl QuicOverlayPeer {
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        bind: SocketAddr,
        remote: SocketAddr,
        server_name: &str,
        trusted_server_certificate_der: Vec<u8>,
        identity: TransportIdentity,
        network_id: u8,
        limits: QuicTransportLimits,
    ) -> Result<Self, TransportError> {
        Self::connect_with_trusted_certificates(
            bind,
            remote,
            server_name,
            vec![trusted_server_certificate_der],
            identity,
            network_id,
            limits,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_trusted_certificates(
        bind: SocketAddr,
        remote: SocketAddr,
        server_name: &str,
        trusted_server_certificates_der: Vec<Vec<u8>>,
        identity: TransportIdentity,
        network_id: u8,
        limits: QuicTransportLimits,
    ) -> Result<Self, TransportError> {
        validate_limits(limits)?;
        let client_config = client_config(trusted_server_certificates_der, limits)?;
        let mut endpoint = Endpoint::client(bind)
            .map_err(|error| TransportError::Configuration(error.to_string()))?;
        endpoint.set_default_client_config(client_config);
        let connection = timeout(
            Duration::from_millis(limits.authentication_timeout_ms),
            endpoint
                .connect(remote, server_name)
                .map_err(|error| TransportError::Connection(error.to_string()))?,
        )
        .await
        .map_err(|_| TransportError::Connection("TLS handshake timed out".to_owned()))?
        .map_err(|error| TransportError::Connection(error.to_string()))?;
        let remote_transport_pubkey = authenticate_outgoing(
            &connection,
            &identity,
            network_id,
            limits.authentication_timeout_ms,
        )
        .await?;
        Ok(Self {
            endpoint,
            connection,
            identity,
            network_id,
            remote_transport_pubkey,
            limits,
        })
    }

    pub fn remote_transport_pubkey(&self) -> [u8; 32] {
        self.remote_transport_pubkey
    }

    pub async fn gossip(
        &self,
        topic: GossipTopic,
        object_id: Hash256,
        missing_parent: bool,
        parent_fetch_depth: u16,
        payload: Vec<u8>,
    ) -> Result<(), TransportError> {
        let frame = SignedGossipFrame::new_signed(
            &self.identity,
            self.network_id,
            topic,
            object_id,
            missing_parent,
            parent_fetch_depth,
            payload,
        );
        self.gossip_frame(frame).await
    }

    pub async fn gossip_frame(&self, frame: SignedGossipFrame) -> Result<(), TransportError> {
        let mut encoder = Encoder::new();
        frame.encode(&mut encoder);
        let bytes = encoder.into_bytes();
        if bytes.len() > self.limits.maximum_gossip_frame_bytes {
            return Err(TransportError::MalformedFrame(
                "gossip frame exceeds local bound".to_owned(),
            ));
        }
        let response = exchange(&self.connection, GOSSIP_STREAM, &bytes, MAX_STATUS_BYTES).await?;
        decode_empty_status(&response)
    }

    pub async fn request(
        &self,
        protocol: RequestProtocol,
        object_id: Hash256,
        shard_index: Option<u16>,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let request = OverlayRequest {
            protocol_version: CORE_V2,
            network_id: self.network_id,
            protocol,
            object_id,
            shard_index,
        };
        let mut encoder = Encoder::new();
        request.encode(&mut encoder);
        let response = exchange(
            &self.connection,
            REQUEST_STREAM,
            &encoder.into_bytes(),
            self.limits.maximum_response_bytes.saturating_add(16),
        )
        .await?;
        decode_data_status(&response, self.limits.maximum_response_bytes)
    }

    pub async fn close(self) {
        self.shutdown().await;
    }

    pub async fn shutdown(&self) {
        self.connection.close(VarInt::from_u32(0), b"done");
        self.endpoint.wait_idle().await;
    }

    pub async fn wait_closed(&self) {
        let _ = self.connection.closed().await;
    }
}

async fn handle_incoming<A: OverlayApplication>(
    incoming: quinn::Incoming,
    identity: TransportIdentity,
    network_id: u8,
    admission: Arc<Mutex<OverlayNode>>,
    application: Arc<A>,
    callback_gates: CallbackGates,
    limits: QuicTransportLimits,
) -> Result<(), TransportError> {
    let connection = timeout(
        Duration::from_millis(limits.authentication_timeout_ms),
        incoming,
    )
    .await
    .map_err(|_| TransportError::Connection("TLS handshake timed out".to_owned()))?
    .map_err(|error| TransportError::Connection(error.to_string()))?;
    let peer = authenticate_incoming(
        &connection,
        &identity,
        network_id,
        &admission,
        limits.authentication_timeout_ms,
    )
    .await?;
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => return Ok(()),
            Err(error) => return Err(TransportError::Connection(error.to_string())),
        };
        let admission = admission.clone();
        let application = application.clone();
        let callback_gates = callback_gates.clone();
        let stream_connection = connection.clone();
        tokio::spawn(async move {
            let _ = timeout(
                Duration::from_millis(limits.idle_timeout_ms),
                handle_stream(
                    send,
                    recv,
                    stream_connection,
                    peer,
                    network_id,
                    admission,
                    application,
                    callback_gates,
                    limits,
                ),
            )
            .await;
        });
    }
}

async fn authenticate_incoming(
    connection: &Connection,
    identity: &TransportIdentity,
    network_id: u8,
    admission: &Arc<Mutex<OverlayNode>>,
    timeout_ms: u64,
) -> Result<[u8; 32], TransportError> {
    timeout(Duration::from_millis(timeout_ms), async {
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|error| TransportError::Authentication(error.to_string()))?;
        let mut kind = [0; 1];
        recv.read_exact(&mut kind)
            .await
            .map_err(|error| TransportError::Authentication(error.to_string()))?;
        if kind[0] != AUTH_STREAM {
            return Err(TransportError::Authentication(
                "first stream was not authentication".to_owned(),
            ));
        }
        let challenge: Hash256 = rand::random();
        send.write_all(&challenge)
            .await
            .map_err(|error| TransportError::Authentication(error.to_string()))?;
        let hello_bytes = read_frame(&mut recv, MAX_HELLO_BYTES).await?;
        let hello = PeerHello::from_canonical_bytes(
            &hello_bytes,
            DecodeLimits {
                max_object_bytes: MAX_HELLO_BYTES,
                max_vector_items: 16,
            },
        )
        .map_err(frame)?;
        if hello.challenge_nonce != challenge {
            return Err(TransportError::Authentication(
                "challenge nonce mismatch".to_owned(),
            ));
        }
        admission
            .lock()
            .map_err(|_| TransportError::Poisoned)?
            .authenticate_peer(&hello, now_ms())
            .map_err(admission_error)?;

        let response = identity.hello(network_id, challenge);
        let mut encoded = Encoder::new();
        response.encode(&mut encoded);
        write_frame(&mut send, encoded.as_bytes()).await?;
        send.finish()
            .map_err(|error| TransportError::Authentication(error.to_string()))?;
        Ok(hello.transport_pubkey)
    })
    .await
    .map_err(|_| TransportError::Authentication("authentication timed out".to_owned()))?
}

async fn authenticate_outgoing(
    connection: &Connection,
    identity: &TransportIdentity,
    network_id: u8,
    timeout_ms: u64,
) -> Result<[u8; 32], TransportError> {
    timeout(Duration::from_millis(timeout_ms), async {
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| TransportError::Authentication(error.to_string()))?;
        send.write_all(&[AUTH_STREAM])
            .await
            .map_err(|error| TransportError::Authentication(error.to_string()))?;
        let mut challenge = [0; 32];
        recv.read_exact(&mut challenge)
            .await
            .map_err(|error| TransportError::Authentication(error.to_string()))?;
        let hello = identity.hello(network_id, challenge);
        let mut encoded = Encoder::new();
        hello.encode(&mut encoded);
        write_frame(&mut send, encoded.as_bytes()).await?;
        send.finish()
            .map_err(|error| TransportError::Authentication(error.to_string()))?;

        let response_bytes = read_frame(&mut recv, MAX_HELLO_BYTES).await?;
        let response = PeerHello::from_canonical_bytes(
            &response_bytes,
            DecodeLimits {
                max_object_bytes: MAX_HELLO_BYTES,
                max_vector_items: 16,
            },
        )
        .map_err(frame)?;
        if response.protocol_version != CORE_V2
            || response.network_id != network_id
            || response.challenge_nonce != challenge
        {
            return Err(TransportError::Authentication(
                "server hello context mismatch".to_owned(),
            ));
        }
        verify_object(
            &response.transport_pubkey,
            ED25519_SUITE,
            &response.signature,
            network_id,
            &response,
        )
        .map_err(|error| TransportError::Authentication(error.to_string()))?;
        Ok(response.transport_pubkey)
    })
    .await
    .map_err(|_| TransportError::Authentication("authentication timed out".to_owned()))?
}

#[allow(clippy::too_many_arguments)]
async fn handle_stream<A: OverlayApplication>(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    connection: Connection,
    peer: [u8; 32],
    network_id: u8,
    admission: Arc<Mutex<OverlayNode>>,
    application: Arc<A>,
    callback_gates: CallbackGates,
    limits: QuicTransportLimits,
) -> Result<(), TransportError> {
    let mut kind = [0; 1];
    recv.read_exact(&mut kind)
        .await
        .map_err(|error| TransportError::MalformedFrame(error.to_string()))?;
    let status = match kind[0] {
        GOSSIP_STREAM => {
            let bytes = read_frame(&mut recv, limits.maximum_gossip_frame_bytes).await?;
            handle_gossip(
                peer,
                network_id,
                bytes,
                admission.clone(),
                application,
                callback_gates,
                limits.maximum_gossip_frame_bytes,
            )
            .await
        }
        REQUEST_STREAM => {
            let bytes = read_frame(&mut recv, 128).await?;
            handle_request(
                peer,
                network_id,
                bytes,
                admission.clone(),
                application,
                callback_gates,
                limits.maximum_response_bytes,
            )
            .await
        }
        _ => Err(TransportError::MalformedFrame(
            "unknown stream kind".to_owned(),
        )),
    };
    let response = match status {
        Ok(response) => response,
        Err(TransportError::RemoteQuota) => vec![STATUS_QUOTA],
        Err(_) => vec![STATUS_REJECTED],
    };
    write_frame(&mut send, &response).await?;
    send.finish()
        .map_err(|error| TransportError::Connection(error.to_string()))?;
    if admission
        .lock()
        .map_err(|_| TransportError::Poisoned)?
        .peer_is_disconnected(&peer)
    {
        connection.close(VarInt::from_u32(1), b"peer score exhausted");
    }
    Ok(())
}

async fn handle_gossip<A: OverlayApplication>(
    peer: [u8; 32],
    network_id: u8,
    bytes: Vec<u8>,
    admission: Arc<Mutex<OverlayNode>>,
    application: Arc<A>,
    callback_gates: CallbackGates,
    maximum_frame: usize,
) -> Result<Vec<u8>, TransportError> {
    let lane = gossip_lane_hint(&bytes)?;
    let permit = callback_gates
        .gate(lane)
        .acquire_owned()
        .await
        .map_err(|_| TransportError::Worker("application callback gate closed".to_owned()))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        handle_gossip_blocking(
            peer,
            network_id,
            &bytes,
            admission,
            application,
            maximum_frame,
        )
    })
    .await
    .map_err(|error| TransportError::Worker(error.to_string()))?
}

fn handle_gossip_blocking<A: OverlayApplication>(
    peer: [u8; 32],
    network_id: u8,
    bytes: &[u8],
    admission: Arc<Mutex<OverlayNode>>,
    application: Arc<A>,
    maximum_frame: usize,
) -> Result<Vec<u8>, TransportError> {
    let frame = SignedGossipFrame::decode_bounded(bytes, maximum_frame).map_err(frame)?;
    if frame.protocol_version != CORE_V2 || frame.network_id != network_id {
        return Err(TransportError::MalformedFrame(
            "gossip protocol/network mismatch".to_owned(),
        ));
    }
    let encoded_size = u32::try_from(frame.payload.len())
        .map_err(|_| TransportError::MalformedFrame("gossip payload exceeds u32".to_owned()))?;
    let envelope = ObjectEnvelope {
        topic: frame.topic,
        object_id: frame.object_id,
        encoded_size,
        missing_parent: frame.missing_parent,
        parent_fetch_depth: frame.parent_fetch_depth,
    };
    let signature_valid = verify_object(
        &peer,
        ED25519_SUITE,
        &frame.transport_signature,
        network_id,
        &frame,
    )
    .is_ok();
    let decision = admission
        .lock()
        .map_err(|_| TransportError::Poisoned)?
        .begin_validation(&peer, envelope, signature_valid, now_ms())
        .map_err(admission_error)?;
    let token = match decision {
        IngressDecision::Validate(token) => token,
        IngressDecision::AlreadyValidated => return Ok(vec![STATUS_OK]),
    };
    let validation = catch_unwind(AssertUnwindSafe(|| {
        application.validate_and_store_gossip(peer, frame.topic, frame.object_id, &frame.payload)
    }));
    let valid = match validation {
        Ok(valid) => valid,
        Err(_) => {
            // Release the pending token even when application code unwinds.
            // An expired/replaced token is intentionally harmless here.
            let _ = admission
                .lock()
                .map_err(|_| TransportError::Poisoned)?
                .finish_validation(token, false);
            return Err(TransportError::Worker(
                "gossip application callback panicked".to_owned(),
            ));
        }
    };
    admission
        .lock()
        .map_err(|_| TransportError::Poisoned)?
        .finish_validation(token, valid)
        .map_err(admission_error)?;
    Ok(vec![STATUS_OK])
}

async fn handle_request<A: OverlayApplication>(
    peer: [u8; 32],
    network_id: u8,
    bytes: Vec<u8>,
    admission: Arc<Mutex<OverlayNode>>,
    application: Arc<A>,
    callback_gates: CallbackGates,
    maximum_response: usize,
) -> Result<Vec<u8>, TransportError> {
    let lane = request_lane_hint(&bytes)?;
    let permit = callback_gates
        .gate(lane)
        .acquire_owned()
        .await
        .map_err(|_| TransportError::Worker("application callback gate closed".to_owned()))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        handle_request_blocking(
            peer,
            network_id,
            &bytes,
            admission,
            application,
            maximum_response,
        )
    })
    .await
    .map_err(|error| TransportError::Worker(error.to_string()))?
}

fn handle_request_blocking<A: OverlayApplication>(
    peer: [u8; 32],
    network_id: u8,
    bytes: &[u8],
    admission: Arc<Mutex<OverlayNode>>,
    application: Arc<A>,
    maximum_response: usize,
) -> Result<Vec<u8>, TransportError> {
    let request = OverlayRequest::from_canonical_bytes(
        bytes,
        DecodeLimits {
            max_object_bytes: 128,
            max_vector_items: 16,
        },
    )
    .map_err(frame)?;
    if request.protocol_version != CORE_V2 || request.network_id != network_id {
        return Err(TransportError::MalformedFrame(
            "request protocol/network mismatch".to_owned(),
        ));
    }
    let Some(response) = application.load_response(&request) else {
        return Ok(vec![STATUS_NOT_FOUND]);
    };
    if response.len() > maximum_response {
        return Err(TransportError::MalformedFrame(
            "application response exceeds configured bound".to_owned(),
        ));
    }
    admission
        .lock()
        .map_err(|_| TransportError::Poisoned)?
        .request_body_bytes(&peer, response.len() as u64, now_ms())
        .map_err(|error| match error {
            NetworkError::BodyQuota => TransportError::RemoteQuota,
            other => admission_error(other),
        })?;
    let mut encoded = Encoder::new();
    encoded.u8(STATUS_OK);
    encoded.bytes(&response);
    Ok(encoded.into_bytes())
}

async fn exchange(
    connection: &Connection,
    kind: u8,
    payload: &[u8],
    maximum_response: usize,
) -> Result<Vec<u8>, TransportError> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| TransportError::Connection(error.to_string()))?;
    send.write_all(&[kind])
        .await
        .map_err(|error| TransportError::Connection(error.to_string()))?;
    write_frame(&mut send, payload).await?;
    send.finish()
        .map_err(|error| TransportError::Connection(error.to_string()))?;
    read_frame(&mut recv, maximum_response).await
}

async fn write_frame(send: &mut quinn::SendStream, bytes: &[u8]) -> Result<(), TransportError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| TransportError::MalformedFrame("frame exceeds u32".to_owned()))?;
    send.write_all(&length.to_le_bytes())
        .await
        .map_err(|error| TransportError::Connection(error.to_string()))?;
    send.write_all(bytes)
        .await
        .map_err(|error| TransportError::Connection(error.to_string()))?;
    Ok(())
}

async fn read_frame(
    recv: &mut quinn::RecvStream,
    maximum: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut length = [0; 4];
    recv.read_exact(&mut length)
        .await
        .map_err(|error| TransportError::MalformedFrame(error.to_string()))?;
    let length = u32::from_le_bytes(length) as usize;
    if length > maximum {
        return Err(TransportError::MalformedFrame(format!(
            "frame length {length} exceeds {maximum}"
        )));
    }
    let mut bytes = vec![0; length];
    recv.read_exact(&mut bytes)
        .await
        .map_err(|error| TransportError::MalformedFrame(error.to_string()))?;
    Ok(bytes)
}

fn decode_empty_status(bytes: &[u8]) -> Result<(), TransportError> {
    match bytes {
        [STATUS_OK] => Ok(()),
        [STATUS_QUOTA] => Err(TransportError::RemoteQuota),
        [_] => Err(TransportError::RemoteRejected),
        _ => Err(TransportError::MalformedFrame(
            "invalid status response".to_owned(),
        )),
    }
}

fn decode_data_status(bytes: &[u8], maximum: usize) -> Result<Option<Vec<u8>>, TransportError> {
    let mut decoder = Decoder::new(
        bytes,
        DecodeLimits {
            max_object_bytes: maximum.saturating_add(16),
            max_vector_items: maximum.saturating_add(16),
        },
    )
    .map_err(frame)?;
    match decoder.u8().map_err(frame)? {
        STATUS_OK => {
            let data = decoder.bytes(maximum).map_err(frame)?;
            decoder.finish().map_err(frame)?;
            Ok(Some(data))
        }
        STATUS_NOT_FOUND => {
            decoder.finish().map_err(frame)?;
            Ok(None)
        }
        STATUS_QUOTA => Err(TransportError::RemoteQuota),
        _ => Err(TransportError::RemoteRejected),
    }
}

fn server_config(
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
    limits: QuicTransportLimits,
) -> Result<ServerConfig, TransportError> {
    let certificate = CertificateDer::from(certificate_der);
    let key = PrivatePkcs8KeyDer::from(private_key_der);
    let mut config = ServerConfig::with_single_cert(vec![certificate], key.into())
        .map_err(|error| TransportError::Configuration(error.to_string()))?;
    config.transport = Arc::new(transport_config(limits)?);
    Ok(config)
}

fn client_config(
    certificates_der: Vec<Vec<u8>>,
    limits: QuicTransportLimits,
) -> Result<ClientConfig, TransportError> {
    if certificates_der.is_empty() || certificates_der.len() > MAX_TRUSTED_SERVER_CERTIFICATES {
        return Err(TransportError::Configuration(format!(
            "trusted server certificate count must be in 1..={MAX_TRUSTED_SERVER_CERTIFICATES}"
        )));
    }
    let mut roots = RootCertStore::empty();
    for certificate_der in certificates_der {
        roots
            .add(CertificateDer::from(certificate_der))
            .map_err(|error| TransportError::Configuration(error.to_string()))?;
    }
    let mut config = ClientConfig::with_root_certificates(Arc::new(roots))
        .map_err(|error| TransportError::Configuration(error.to_string()))?;
    config.transport_config(Arc::new(transport_config(limits)?));
    Ok(config)
}

fn transport_config(limits: QuicTransportLimits) -> Result<TransportConfig, TransportError> {
    let mut config = TransportConfig::default();
    config.max_concurrent_bidi_streams(VarInt::from_u32(limits.maximum_concurrent_streams));
    config.max_concurrent_uni_streams(VarInt::from_u32(0));
    let idle = Duration::from_millis(limits.idle_timeout_ms)
        .try_into()
        .map_err(|error| TransportError::Configuration(format!("invalid idle timeout: {error}")))?;
    config.max_idle_timeout(Some(idle));
    config.keep_alive_interval(Some(Duration::from_millis(
        limits.idle_timeout_ms.div_ceil(3),
    )));
    Ok(config)
}

fn validate_limits(limits: QuicTransportLimits) -> Result<(), TransportError> {
    let lane_callbacks = limits
        .maximum_fast_path_callbacks
        .checked_add(limits.maximum_accounting_callbacks)
        .and_then(|total| total.checked_add(limits.maximum_availability_callbacks))
        .and_then(|total| total.checked_add(limits.maximum_settlement_callbacks));
    if limits.maximum_connections == 0
        || limits.maximum_concurrent_streams == 0
        || limits.maximum_blocking_callbacks == 0
        || limits.maximum_fast_path_callbacks == 0
        || limits.maximum_accounting_callbacks == 0
        || limits.maximum_availability_callbacks == 0
        || limits.maximum_settlement_callbacks == 0
        || lane_callbacks.is_none_or(|total| total > limits.maximum_blocking_callbacks)
        || limits.maximum_gossip_frame_bytes < 1024
        || limits.maximum_response_bytes == 0
        || limits.authentication_timeout_ms == 0
        || limits.idle_timeout_ms == 0
    {
        return Err(TransportError::Configuration(
            "transport bounds must all be nonzero and gossip frames at least 1 KiB".to_owned(),
        ));
    }
    Ok(())
}

fn gossip_lane_hint(bytes: &[u8]) -> Result<ProtocolLane, TransportError> {
    let topic = bytes
        .get(3)
        .copied()
        .ok_or_else(|| TransportError::MalformedFrame("gossip header is truncated".to_owned()))?;
    decode_topic(topic)
        .map(GossipTopic::protocol_lane)
        .map_err(frame)
}

fn request_lane_hint(bytes: &[u8]) -> Result<ProtocolLane, TransportError> {
    let protocol = bytes
        .get(3)
        .copied()
        .ok_or_else(|| TransportError::MalformedFrame("request header is truncated".to_owned()))?;
    decode_request(protocol)
        .map(RequestProtocol::protocol_lane)
        .map_err(frame)
}

fn topic_code(topic: GossipTopic) -> u8 {
    topic as u8
}

fn decode_topic(value: u8) -> Result<GossipTopic, CodecError> {
    match value {
        0 => Ok(GossipTopic::Parent),
        1 => Ok(GossipTopic::Operator),
        2 => Ok(GossipTopic::BodyDescriptor),
        3 => Ok(GossipTopic::MaskSession),
        4 => Ok(GossipTopic::Share),
        5 => Ok(GossipTopic::ReceiptBatch),
        6 => Ok(GossipTopic::SessionClose),
        7 => Ok(GossipTopic::MaskOpening),
        8 => Ok(GossipTopic::PayoutSnapshot),
        9 => Ok(GossipTopic::PayoutPlan),
        10 => Ok(GossipTopic::FaultProof),
        _ => Err(CodecError::InvalidField("unknown gossip topic")),
    }
}

fn request_code(protocol: RequestProtocol) -> u8 {
    match protocol {
        RequestProtocol::BodyShard => 0,
        RequestProtocol::BodyPackage => 1,
        RequestProtocol::ShareObject => 2,
        RequestProtocol::ReceiptProof => 3,
        RequestProtocol::SessionTranscript => 4,
        RequestProtocol::PayoutTranscript => 5,
        RequestProtocol::CommitteeRoster => 6,
    }
}

fn decode_request(value: u8) -> Result<RequestProtocol, CodecError> {
    match value {
        0 => Ok(RequestProtocol::BodyShard),
        1 => Ok(RequestProtocol::BodyPackage),
        2 => Ok(RequestProtocol::ShareObject),
        3 => Ok(RequestProtocol::ReceiptProof),
        4 => Ok(RequestProtocol::SessionTranscript),
        5 => Ok(RequestProtocol::PayoutTranscript),
        6 => Ok(RequestProtocol::CommitteeRoster),
        _ => Err(CodecError::InvalidField("unknown request protocol")),
    }
}

fn frame(error: CodecError) -> TransportError {
    TransportError::MalformedFrame(error.to_string())
}

fn admission_error(error: NetworkError) -> TransportError {
    TransportError::Admission(error.to_string())
}

fn now_ms() -> u64 {
    static PROCESS_EPOCH: OnceLock<Instant> = OnceLock::new();
    u64::try_from(
        PROCESS_EPOCH
            .get_or_init(Instant::now)
            .elapsed()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

pub fn default_client_bind(remote: SocketAddr) -> SocketAddr {
    match remote.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => "[::]:0".parse().expect("static IPv6 wildcard is valid"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};
    use std::thread;

    use meshmine_types::domain_hash;
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    use super::*;
    use crate::{OverlayEvent, default_overlay_limits};

    type ResponseKey = (u8, Hash256, Option<u16>);

    #[derive(Default)]
    struct TestApplication {
        gossip: Mutex<HashMap<Hash256, Vec<u8>>>,
        gossip_validation_calls: Mutex<HashMap<Hash256, usize>>,
        responses: Mutex<HashMap<ResponseKey, Vec<u8>>>,
    }

    #[derive(Default)]
    struct BlockingGate {
        released: Mutex<bool>,
        wake: Condvar,
    }

    impl BlockingGate {
        fn wait(&self) {
            let mut released = self.released.lock().unwrap();
            while !*released {
                released = self.wake.wait(released).unwrap();
            }
        }

        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.wake.notify_all();
        }

        fn watchdog(self: &Arc<Self>) -> thread::JoinHandle<()> {
            let gate = self.clone();
            thread::spawn(move || {
                let released = gate.released.lock().unwrap();
                let (mut released, timeout) = gate
                    .wake
                    .wait_timeout_while(released, Duration::from_secs(3), |released| !*released)
                    .unwrap();
                if timeout.timed_out() {
                    *released = true;
                    gate.wake.notify_all();
                }
            })
        }
    }

    struct BlockingApplication {
        gate: Arc<BlockingGate>,
        entered: AtomicBool,
        returned: AtomicBool,
        gossip_calls: AtomicUsize,
        response_calls: AtomicUsize,
        response: Option<Vec<u8>>,
    }

    struct LaneIsolationApplication {
        settlement_gate: Arc<BlockingGate>,
        settlement_entered: AtomicBool,
        fast_calls: AtomicUsize,
    }

    impl BlockingApplication {
        fn new(response: Option<Vec<u8>>) -> Self {
            Self {
                gate: Arc::new(BlockingGate::default()),
                entered: AtomicBool::new(false),
                returned: AtomicBool::new(false),
                gossip_calls: AtomicUsize::new(0),
                response_calls: AtomicUsize::new(0),
                response,
            }
        }

        fn block(&self) {
            self.entered.store(true, Ordering::SeqCst);
            self.gate.wait();
            self.returned.store(true, Ordering::SeqCst);
        }
    }

    impl OverlayApplication for BlockingApplication {
        fn validate_and_store_gossip(
            &self,
            _peer: [u8; 32],
            _topic: GossipTopic,
            object_id: Hash256,
            payload: &[u8],
        ) -> bool {
            self.gossip_calls.fetch_add(1, Ordering::SeqCst);
            self.block();
            object_id == domain_hash("meshmine/test-quic-object/v2", payload)
        }

        fn load_response(&self, _request: &OverlayRequest) -> Option<Vec<u8>> {
            self.response_calls.fetch_add(1, Ordering::SeqCst);
            self.block();
            self.response.clone()
        }
    }

    impl OverlayApplication for LaneIsolationApplication {
        fn validate_and_store_gossip(
            &self,
            _peer: [u8; 32],
            topic: GossipTopic,
            object_id: Hash256,
            payload: &[u8],
        ) -> bool {
            match topic.protocol_lane() {
                ProtocolLane::Settlement => {
                    self.settlement_entered.store(true, Ordering::SeqCst);
                    self.settlement_gate.wait();
                }
                ProtocolLane::FastPath => {
                    self.fast_calls.fetch_add(1, Ordering::SeqCst);
                }
                ProtocolLane::Accounting | ProtocolLane::Availability => {}
            }
            object_id == domain_hash("meshmine/test-quic-object/v2", payload)
        }

        fn load_response(&self, _request: &OverlayRequest) -> Option<Vec<u8>> {
            None
        }
    }

    impl OverlayApplication for TestApplication {
        fn validate_and_store_gossip(
            &self,
            _peer: [u8; 32],
            _topic: GossipTopic,
            object_id: Hash256,
            payload: &[u8],
        ) -> bool {
            *self
                .gossip_validation_calls
                .lock()
                .unwrap()
                .entry(object_id)
                .or_default() += 1;
            if object_id != domain_hash("meshmine/test-quic-object/v2", payload) {
                return false;
            }
            self.gossip
                .lock()
                .unwrap()
                .insert(object_id, payload.to_vec());
            true
        }

        fn load_response(&self, request: &OverlayRequest) -> Option<Vec<u8>> {
            self.responses
                .lock()
                .unwrap()
                .get(&(
                    request_code(request.protocol),
                    request.object_id,
                    request.shard_index,
                ))
                .cloned()
        }
    }

    fn certificate() -> (Vec<u8>, Vec<u8>) {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        (cert.der().to_vec(), key_pair.serialize_der())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_gossip_wait_does_not_starve_runtime_or_leak_validation() {
        let client_identity = TransportIdentity::new(SigningKey::from_bytes(&[71; 32]), None);
        let peer = client_identity.transport_pubkey();
        let (overlay_limits, topics) = default_overlay_limits();
        let mut overlay = OverlayNode::new(2, overlay_limits, topics);
        overlay
            .authenticate_peer(&client_identity.hello(2, [1; 32]), now_ms())
            .unwrap();
        let admission = Arc::new(Mutex::new(overlay));
        let application = Arc::new(BlockingApplication::new(None));
        let callback_gates = CallbackGates::new(QuicTransportLimits::default());
        let watchdog = application.gate.watchdog();
        let payload = b"blocking-canonical-parent".to_vec();
        let object_id = domain_hash("meshmine/test-quic-object/v2", &payload);
        let frame = SignedGossipFrame::new_signed(
            &client_identity,
            2,
            GossipTopic::Parent,
            object_id,
            false,
            0,
            payload,
        );
        let mut encoder = Encoder::new();
        frame.encode(&mut encoder);
        let bytes = encoder.into_bytes();
        let mut operation = Box::pin(handle_gossip(
            peer,
            2,
            bytes.clone(),
            admission.clone(),
            application.clone(),
            callback_gates.clone(),
            QuicTransportLimits::default().maximum_gossip_frame_bytes,
        ));

        timeout(Duration::from_secs(1), async {
            loop {
                if application.entered.load(Ordering::SeqCst) {
                    break;
                }
                tokio::select! {
                    result = operation.as_mut() => {
                        panic!("blocking validation returned early: {result:?}")
                    }
                    () = tokio::time::sleep(Duration::from_millis(1)) => {}
                }
            }
        })
        .await
        .expect("the Tokio runtime must remain responsive while validation blocks");
        assert!(
            timeout(Duration::from_millis(25), operation.as_mut())
                .await
                .is_err()
        );
        drop(operation);

        application.gate.release();
        timeout(Duration::from_secs(1), async {
            loop {
                let completed = admission.lock().unwrap().events().iter().any(|event| {
                    matches!(event, OverlayEvent::ValidationCompleted { object_id: id } if id == &object_id)
                });
                if application.returned.load(Ordering::SeqCst) && completed {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("detached blocking validation must finish and release its token");
        watchdog.join().unwrap();

        assert_eq!(
            handle_gossip(
                peer,
                2,
                bytes,
                admission.clone(),
                application.clone(),
                callback_gates,
                QuicTransportLimits::default().maximum_gossip_frame_bytes,
            )
            .await
            .unwrap(),
            vec![STATUS_OK]
        );
        assert_eq!(application.gossip_calls.load(Ordering::SeqCst), 1);
        let overlay = admission.lock().unwrap();
        assert_eq!(
            overlay
                .events()
                .iter()
                .filter(|event| matches!(event, OverlayEvent::ValidationStarted { object_id: id } if id == &object_id))
                .count(),
            1
        );
        assert_eq!(
            overlay
                .events()
                .iter()
                .filter(|event| matches!(event, OverlayEvent::ValidationCompleted { object_id: id } if id == &object_id))
                .count(),
            1
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_settlement_callback_cannot_consume_fast_path_capacity() {
        let client_identity = TransportIdentity::new(SigningKey::from_bytes(&[73; 32]), None);
        let peer = client_identity.transport_pubkey();
        let (overlay_limits, topics) = default_overlay_limits();
        let mut overlay = OverlayNode::new(2, overlay_limits, topics);
        overlay
            .authenticate_peer(&client_identity.hello(2, [3; 32]), now_ms())
            .unwrap();
        let admission = Arc::new(Mutex::new(overlay));
        let application = Arc::new(LaneIsolationApplication {
            settlement_gate: Arc::new(BlockingGate::default()),
            settlement_entered: AtomicBool::new(false),
            fast_calls: AtomicUsize::new(0),
        });
        let mut limits = QuicTransportLimits::default();
        limits.maximum_blocking_callbacks = 4;
        limits.maximum_fast_path_callbacks = 1;
        limits.maximum_accounting_callbacks = 1;
        limits.maximum_availability_callbacks = 1;
        limits.maximum_settlement_callbacks = 1;
        let callback_gates = CallbackGates::new(limits);
        let encode = |topic, payload: Vec<u8>| {
            let object_id = domain_hash("meshmine/test-quic-object/v2", &payload);
            let frame = SignedGossipFrame::new_signed(
                &client_identity,
                2,
                topic,
                object_id,
                false,
                0,
                payload,
            );
            let mut encoder = Encoder::new();
            frame.encode(&mut encoder);
            encoder.into_bytes()
        };
        let settlement_bytes = encode(GossipTopic::PayoutSnapshot, b"settlement".to_vec());
        let fast_bytes = encode(GossipTopic::Parent, b"new-tip".to_vec());
        let settlement = tokio::spawn(handle_gossip(
            peer,
            2,
            settlement_bytes,
            admission.clone(),
            application.clone(),
            callback_gates.clone(),
            limits.maximum_gossip_frame_bytes,
        ));
        timeout(Duration::from_secs(1), async {
            while !application.settlement_entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("settlement callback should enter its dedicated lane");

        assert_eq!(
            timeout(
                Duration::from_millis(250),
                handle_gossip(
                    peer,
                    2,
                    fast_bytes,
                    admission,
                    application.clone(),
                    callback_gates,
                    limits.maximum_gossip_frame_bytes,
                )
            )
            .await
            .expect("fast-path callback must not wait for settlement")
            .unwrap(),
            vec![STATUS_OK]
        );
        assert_eq!(application.fast_calls.load(Ordering::SeqCst), 1);
        application.settlement_gate.release();
        assert_eq!(settlement.await.unwrap().unwrap(), vec![STATUS_OK]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_response_load_stays_off_runtime_and_still_charges_quota() {
        let client_identity = TransportIdentity::new(SigningKey::from_bytes(&[72; 32]), None);
        let peer = client_identity.transport_pubkey();
        let (mut overlay_limits, topics) = default_overlay_limits();
        overlay_limits.body_download_bytes_per_window = 4;
        let mut overlay = OverlayNode::new(2, overlay_limits, topics);
        overlay
            .authenticate_peer(&client_identity.hello(2, [2; 32]), now_ms())
            .unwrap();
        let admission = Arc::new(Mutex::new(overlay));
        let application = Arc::new(BlockingApplication::new(Some(vec![1, 2, 3, 4])));
        let callback_gates = CallbackGates::new(QuicTransportLimits::default());
        let watchdog = application.gate.watchdog();
        let request = OverlayRequest {
            protocol_version: CORE_V2,
            network_id: 2,
            protocol: RequestProtocol::BodyShard,
            object_id: [9; 32],
            shard_index: Some(1),
        };
        let mut encoder = Encoder::new();
        request.encode(&mut encoder);
        let bytes = encoder.into_bytes();
        let mut operation = Box::pin(handle_request(
            peer,
            2,
            bytes.clone(),
            admission.clone(),
            application.clone(),
            callback_gates.clone(),
            4,
        ));

        timeout(Duration::from_secs(1), async {
            loop {
                if application.entered.load(Ordering::SeqCst) {
                    break;
                }
                tokio::select! {
                    result = operation.as_mut() => {
                        panic!("blocking response load returned early: {result:?}")
                    }
                    () = tokio::time::sleep(Duration::from_millis(1)) => {}
                }
            }
        })
        .await
        .expect("the Tokio runtime must remain responsive while response loading blocks");
        assert!(
            timeout(Duration::from_millis(25), operation.as_mut())
                .await
                .is_err()
        );
        drop(operation);
        application.gate.release();
        watchdog.join().unwrap();

        assert!(matches!(
            timeout(
                Duration::from_secs(1),
                handle_request(
                    peer,
                    2,
                    bytes,
                    admission,
                    application.clone(),
                    callback_gates,
                    4,
                )
            )
            .await,
            Ok(Err(TransportError::RemoteQuota))
        ));
        assert_eq!(application.response_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mutually_authenticated_quic_gossip_and_body_streams_enforce_policy() {
        let (certificate, private_key) = certificate();
        let server_identity = TransportIdentity::new(SigningKey::from_bytes(&[1; 32]), None);
        let client_economic = [9; 32];
        let client_identity =
            TransportIdentity::new(SigningKey::from_bytes(&[2; 32]), Some(client_economic));
        let client_pubkey = client_identity.transport_pubkey();
        let (mut overlay_limits, topics) = default_overlay_limits();
        overlay_limits.body_download_bytes_per_window = 8;
        let application = Arc::new(TestApplication::default());
        let first_body = [41; 32];
        let second_body = [42; 32];
        application.responses.lock().unwrap().insert(
            (
                request_code(RequestProtocol::BodyShard),
                first_body,
                Some(3),
            ),
            vec![1, 2, 3, 4, 5, 6],
        );
        application.responses.lock().unwrap().insert(
            (
                request_code(RequestProtocol::BodyShard),
                second_body,
                Some(4),
            ),
            vec![7, 8, 9, 10, 11, 12],
        );
        let limits = QuicTransportLimits::default();
        let server = QuicOverlayServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            certificate.clone(),
            private_key,
            server_identity.clone(),
            2,
            OverlayNode::new(2, overlay_limits, topics),
            application.clone(),
            limits,
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let admission = server.admission();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(server.run_until(shutdown_rx));

        let peer = QuicOverlayPeer::connect(
            default_client_bind(address),
            address,
            "localhost",
            certificate,
            client_identity.clone(),
            2,
            limits,
        )
        .await
        .unwrap();
        assert_eq!(
            peer.remote_transport_pubkey(),
            server_identity.transport_pubkey()
        );
        assert_eq!(
            admission.lock().unwrap().peer_identities(&client_pubkey),
            Some((client_pubkey, Some(client_economic)))
        );

        let payload = b"canonical-parent-certificate".to_vec();
        let object_id = domain_hash("meshmine/test-quic-object/v2", &payload);
        peer.gossip(GossipTopic::Parent, object_id, false, 0, payload.clone())
            .await
            .unwrap();
        peer.gossip(GossipTopic::Parent, object_id, false, 0, payload.clone())
            .await
            .unwrap();
        assert_eq!(
            application.gossip.lock().unwrap().get(&object_id),
            Some(&payload)
        );
        assert_eq!(
            application
                .gossip_validation_calls
                .lock()
                .unwrap()
                .get(&object_id),
            Some(&1)
        );
        {
            let admission_state = admission.lock().unwrap();
            assert_eq!(
                admission_state
                    .events()
                    .iter()
                    .filter(|event| matches!(event, OverlayEvent::ValidationStarted { object_id: id } if id == &object_id))
                    .count(),
                1
            );
            assert_eq!(
                admission_state
                    .events()
                    .iter()
                    .filter(|event| matches!(event, OverlayEvent::ValidationCompleted { object_id: id } if id == &object_id))
                    .count(),
                1
            );
        }

        let mut tampered = SignedGossipFrame::new_signed(
            &client_identity,
            2,
            GossipTopic::Parent,
            domain_hash("meshmine/test-quic-object/v2", b"before"),
            false,
            0,
            b"before".to_vec(),
        );
        tampered.payload = b"after".to_vec();
        assert!(matches!(
            peer.gossip_frame(tampered).await,
            Err(TransportError::RemoteRejected)
        ));
        assert!(
            admission
                .lock()
                .unwrap()
                .events()
                .iter()
                .any(|event| { matches!(event, OverlayEvent::SignatureRejected { .. }) })
        );

        assert_eq!(
            peer.request(RequestProtocol::BodyShard, first_body, Some(3))
                .await
                .unwrap(),
            Some(vec![1, 2, 3, 4, 5, 6])
        );
        assert!(matches!(
            peer.request(RequestProtocol::BodyShard, second_body, Some(4))
                .await,
            Err(TransportError::RemoteQuota)
        ));
        assert_eq!(
            peer.request(RequestProtocol::BodyShard, [99; 32], Some(0))
                .await
                .unwrap(),
            None
        );

        peer.close().await;
        shutdown_tx.send(true).unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn staged_certificate_rotation_trusts_either_bounded_pin() {
        let (server_certificate, private_key) = certificate();
        let (retiring_certificate, retiring_private_key) = certificate();
        let server_identity = TransportIdentity::new(SigningKey::from_bytes(&[51; 32]), None);
        let (overlay_limits, topics) = default_overlay_limits();
        let server = QuicOverlayServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_certificate.clone(),
            private_key,
            server_identity.clone(),
            2,
            OverlayNode::new(2, overlay_limits, topics),
            Arc::new(TestApplication::default()),
            QuicTransportLimits::default(),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(server.run_until(shutdown_rx));
        let client_identity = TransportIdentity::new(SigningKey::from_bytes(&[52; 32]), None);
        let peer = QuicOverlayPeer::connect_with_trusted_certificates(
            default_client_bind(address),
            address,
            "localhost",
            vec![retiring_certificate.clone(), server_certificate.clone()],
            client_identity.clone(),
            2,
            QuicTransportLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            peer.remote_transport_pubkey(),
            server_identity.transport_pubkey()
        );
        peer.close().await;

        let (overlay_limits, topics) = default_overlay_limits();
        let retiring_server = QuicOverlayServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            retiring_certificate.clone(),
            retiring_private_key,
            server_identity.clone(),
            2,
            OverlayNode::new(2, overlay_limits, topics),
            Arc::new(TestApplication::default()),
            QuicTransportLimits::default(),
        )
        .unwrap();
        let retiring_address = retiring_server.local_addr().unwrap();
        let (retiring_shutdown_tx, retiring_shutdown_rx) = watch::channel(false);
        let retiring_server_task = tokio::spawn(retiring_server.run_until(retiring_shutdown_rx));
        let peer = QuicOverlayPeer::connect_with_trusted_certificates(
            default_client_bind(retiring_address),
            retiring_address,
            "localhost",
            vec![retiring_certificate, server_certificate.clone()],
            client_identity.clone(),
            2,
            QuicTransportLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            peer.remote_transport_pubkey(),
            server_identity.transport_pubkey()
        );
        peer.close().await;

        assert!(matches!(
            QuicOverlayPeer::connect_with_trusted_certificates(
                default_client_bind(address),
                address,
                "localhost",
                vec![],
                client_identity.clone(),
                2,
                QuicTransportLimits::default(),
            )
            .await,
            Err(TransportError::Configuration(_))
        ));
        assert!(matches!(
            QuicOverlayPeer::connect_with_trusted_certificates(
                default_client_bind(address),
                address,
                "localhost",
                vec![server_certificate; MAX_TRUSTED_SERVER_CERTIFICATES + 1],
                client_identity,
                2,
                QuicTransportLimits::default(),
            )
            .await,
            Err(TransportError::Configuration(_))
        ));
        retiring_shutdown_tx.send(true).unwrap();
        retiring_server_task.await.unwrap().unwrap();
        shutdown_tx.send(true).unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pinned_tls_certificate_rejects_the_wrong_server() {
        let (server_certificate, private_key) = certificate();
        let (wrong_certificate, _) = certificate();
        let (overlay_limits, topics) = default_overlay_limits();
        let server = QuicOverlayServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_certificate,
            private_key,
            TransportIdentity::new(SigningKey::from_bytes(&[3; 32]), None),
            2,
            OverlayNode::new(2, overlay_limits, topics),
            Arc::new(TestApplication::default()),
            QuicTransportLimits::default(),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(server.run_until(shutdown_rx));
        let result = QuicOverlayPeer::connect(
            default_client_bind(address),
            address,
            "localhost",
            wrong_certificate,
            TransportIdentity::new(SigningKey::from_bytes(&[4; 32]), None),
            2,
            QuicTransportLimits::default(),
        )
        .await;
        assert!(matches!(result, Err(TransportError::Connection(_))));
        shutdown_tx.send(true).unwrap();
        server_task.await.unwrap().unwrap();
    }
}
