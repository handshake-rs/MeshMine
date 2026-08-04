use std::collections::{BTreeSet, HashSet};
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use hns_hnsr_protocol::{
    EndpointReservation, GetRouteBody, HnsrOpcode, HnsrPacket, HnsrService, NamedRoutePolicy,
    NamedRouteRecordV2, NamedRouteTrust, PutResultBody, PutRouteBody, RelayConfig, RelayLimits,
    RelayService, RendezvousService, RouteStoreLimits, RoutesBody, named_route_key,
};
use hns_service_authority::{
    AuthorityRecord, EndpointDelegationV1, ServiceAuthorizationV1, ServiceIdentity,
    public_key as secp256k1_public_key,
};
use meshmine_codec::{CanonicalDecode, DecodeLimits};
use meshmine_crypto::verify_object;
use meshmine_network::{
    GossipTopic, HnsrApplicationResponse, OverlayApplication, OverlayNode, OverlayRequest,
    QuicOverlayPeer, QuicOverlayServer, QuicTransportLimits, TransportIdentity,
    default_overlay_limits,
};
use meshmine_pool_stats::{EXPERIMENTAL_PROFILE_ID, READ_STATS_CAPABILITY, SERVICE_NAME};
use meshmine_storage::{DurableStore, RedbStore};
use meshmine_types::{CORE_V2, ED25519_SUITE, OperatorRecordV2, UnsignedObject};
use serde::Deserialize;
use tokio::sync::watch;
use tokio::time::sleep;
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_KEY_BYTES: u64 = 1024;
const MAX_CERTIFICATE_BYTES: u64 = 128 * 1024;
const MAX_HNSA_OBJECT_BYTES: u64 = 2048;
const MAX_AUTHORITY_CONTEXT_BYTES: u64 = 4096;
const MAX_PEERS: usize = 128;
const OPERATOR_NAMESPACE: &str = "multi-operator-record/v2";
const ROUTE_SEQUENCE_NAMESPACE: &str = "hnsr-named-route-sequence/v1";

type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema_version: u16,
    network_id: u8,
    network_magic: u32,
    listen: String,
    certificate_file: PathBuf,
    certificate_key_file: PathBuf,
    transport_signing_key_file: PathBuf,
    #[serde(default)]
    economic_operator_pubkey: Option<String>,
    state_file: PathBuf,
    relay: RelayFileConfig,
    rendezvous: RendezvousFileConfig,
    #[serde(default)]
    publication: Option<PublicationConfig>,
    peers: Vec<PeerConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayFileConfig {
    signing_key_file: PathBuf,
    public_address: String,
    allow_private_address: bool,
    supported_profiles: Vec<u16>,
    #[serde(default = "default_maximum_reservations")]
    maximum_reservations: usize,
    #[serde(default = "default_maximum_reservations_per_source")]
    maximum_reservations_per_source: usize,
    #[serde(default = "default_maximum_bytes_per_circuit")]
    maximum_bytes_per_circuit: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RendezvousFileConfig {
    allow_private_routes: bool,
    #[serde(default = "default_total_routes")]
    total_records: usize,
    #[serde(default = "default_routes_per_key")]
    records_per_key: usize,
    #[serde(default = "default_routes_per_source")]
    records_per_source: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationConfig {
    endpoint_signing_key_file: PathBuf,
    service_authorization_file: PathBuf,
    endpoint_delegation_file: PathBuf,
    authority_context_file: PathBuf,
    #[serde(default = "default_reservation_lifetime")]
    reservation_lifetime_seconds: u32,
    #[serde(default = "default_route_lifetime")]
    route_lifetime_seconds: u64,
    #[serde(default = "default_reservation_circuits")]
    reservation_circuits: u16,
    #[serde(default = "default_reservation_bytes")]
    reservation_bytes: u64,
    #[serde(default = "default_publication_interval_ms")]
    publication_interval_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityContextFile {
    root_key: String,
    epoch: u32,
    current_height: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerConfig {
    remote: String,
    server_name: String,
    certificate_file: PathBuf,
    expected_transport_pubkey: String,
    hnsr_relay_key: String,
    #[serde(default = "default_reconnect_initial_ms")]
    reconnect_initial_ms: u64,
    #[serde(default = "default_reconnect_maximum_ms")]
    reconnect_maximum_ms: u64,
}

struct OperatorApplication {
    network_id: u8,
    hnsr: Mutex<HnsrService>,
    store: Arc<dyn DurableStore>,
    operator_write: Mutex<()>,
}

struct Publisher {
    config: PublicationConfig,
    store: Arc<dyn DurableStore>,
}

struct PublisherMaterial {
    endpoint_private_key: Zeroizing<[u8; 32]>,
    authorization: ServiceAuthorizationV1,
    delegation: EndpointDelegationV1,
    authority: AuthorityRecord,
    identity: ServiceIdentity,
    current_height: u32,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("meshmine-operatord: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), BoxError> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.first().map(String::as_str) != Some("serve") {
        return Err("usage: meshmine-operatord serve --config FILE".into());
    }
    let config_path = flag_path(&arguments[1..], "--config")?;
    let config: Config =
        serde_json::from_slice(&read_bounded(config_path, MAX_CONFIG_BYTES, false)?)?;
    validate_config(&config)?;
    serve(config).await
}

async fn serve(config: Config) -> Result<(), BoxError> {
    let state: Arc<dyn DurableStore> = Arc::new(RedbStore::create(&config.state_file)?);
    let transport_key = SigningKey::from_bytes(&read_hex_array::<32>(
        &config.transport_signing_key_file,
        true,
    )?);
    let economic_operator_pubkey = config
        .economic_operator_pubkey
        .as_deref()
        .map(parse_hex_array::<32>)
        .transpose()?;
    let identity = TransportIdentity::new(transport_key, economic_operator_pubkey);
    let relay = load_relay(&config)?;
    let rendezvous = RendezvousService::new(
        config.network_magic,
        config.rendezvous.allow_private_routes,
        RouteStoreLimits {
            total_records: config.rendezvous.total_records,
            records_per_key: config.rendezvous.records_per_key,
            records_per_source: config.rendezvous.records_per_source,
        },
    )?;
    let application = Arc::new(OperatorApplication {
        network_id: config.network_id,
        hnsr: Mutex::new(HnsrService::new(Some(relay), Some(rendezvous))),
        store: state.clone(),
        operator_write: Mutex::new(()),
    });
    let (overlay_limits, topic_limits) = default_overlay_limits();
    let server = QuicOverlayServer::bind(
        config.listen.parse()?,
        read_bounded(&config.certificate_file, MAX_CERTIFICATE_BYTES, false)?,
        read_bounded(&config.certificate_key_file, MAX_CERTIFICATE_BYTES, true)?,
        identity.clone(),
        config.network_id,
        OverlayNode::new(config.network_id, overlay_limits, topic_limits),
        application,
        QuicTransportLimits::default(),
    )?;
    let listen = server.local_addr()?;
    let publisher = config.publication.clone().map(|publication| {
        Arc::new(Publisher {
            config: publication,
            store: state,
        })
    });
    if let Some(publisher) = publisher.as_ref() {
        let _ = publisher.load_material(now_seconds()?)?;
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run_until(shutdown_rx.clone()));
    let mut peer_tasks = Vec::with_capacity(config.peers.len());
    for peer in config.peers {
        peer_tasks.push(tokio::spawn(peer_loop(
            peer,
            identity.clone(),
            config.network_id,
            config.network_magic,
            publisher.clone(),
            shutdown_rx.clone(),
        )));
    }
    println!("multi-operator QUIC/HNSR daemon listening on {listen}");
    println!(
        "transport_pubkey={}",
        hex::encode(identity.transport_pubkey())
    );
    println!("configured_peers={}", peer_tasks.len());

    tokio::signal::ctrl_c().await?;
    let _ = shutdown_tx.send(true);
    for task in peer_tasks {
        task.await??;
    }
    server_task.await??;
    Ok(())
}

async fn peer_loop(
    config: PeerConfig,
    identity: TransportIdentity,
    network_id: u8,
    network_magic: u32,
    publisher: Option<Arc<Publisher>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), BoxError> {
    let remote: SocketAddr = config.remote.parse()?;
    let expected_transport_pubkey = parse_hex_array::<32>(&config.expected_transport_pubkey)?;
    let relay_key = parse_hex_array::<33>(&config.hnsr_relay_key)?;
    let certificate = read_bounded(&config.certificate_file, MAX_CERTIFICATE_BYTES, false)?;
    let mut reconnect_ms = config.reconnect_initial_ms;
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let bind = match remote.ip() {
            IpAddr::V4(_) => "0.0.0.0:0".parse()?,
            IpAddr::V6(_) => "[::]:0".parse()?,
        };
        let connection = QuicOverlayPeer::connect(
            bind,
            remote,
            &config.server_name,
            certificate.clone(),
            identity.clone(),
            network_id,
            QuicTransportLimits::default(),
        )
        .await;
        let peer = match connection {
            Ok(peer) if peer.remote_transport_pubkey() == expected_transport_pubkey => peer,
            Ok(peer) => {
                peer.close().await;
                eprintln!(
                    "peer {} presented an unexpected transport identity",
                    config.remote
                );
                wait_or_shutdown(reconnect_ms, &mut shutdown).await?;
                reconnect_ms = next_backoff(reconnect_ms, config.reconnect_maximum_ms);
                continue;
            }
            Err(error) => {
                eprintln!("peer {} connect failed: {error}", config.remote);
                wait_or_shutdown(reconnect_ms, &mut shutdown).await?;
                reconnect_ms = next_backoff(reconnect_ms, config.reconnect_maximum_ms);
                continue;
            }
        };
        reconnect_ms = config.reconnect_initial_ms;
        loop {
            if let Some(publisher) = publisher.as_ref() {
                match publisher
                    .reserve_publish_lookup(&peer, &relay_key, network_magic)
                    .await
                {
                    Ok((route_key, expires_at)) => println!(
                        "peer={} route_key={} verified_until={expires_at}",
                        config.remote,
                        hex::encode(route_key)
                    ),
                    Err(error) => {
                        eprintln!("peer {} HNSR publication failed: {error}", config.remote);
                        break;
                    }
                }
            }
            let interval = publisher
                .as_ref()
                .map_or(30_000, |publisher| publisher.config.publication_interval_ms);
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        peer.close().await;
                        return Ok(());
                    }
                }
                _ = sleep(Duration::from_millis(interval)) => {}
                _ = peer.wait_closed() => break,
            }
        }
        peer.close().await;
    }
}

impl OverlayApplication for OperatorApplication {
    fn validate_and_store_gossip(
        &self,
        _peer: [u8; 32],
        topic: GossipTopic,
        object_id: [u8; 32],
        payload: &[u8],
    ) -> bool {
        if topic != GossipTopic::Operator {
            return false;
        }
        self.validate_and_store_operator(object_id, payload)
            .unwrap_or(false)
    }

    fn load_response(&self, _request: &OverlayRequest) -> Option<Vec<u8>> {
        None
    }

    fn handle_hnsr(&self, peer: [u8; 32], packet: &[u8]) -> HnsrApplicationResponse {
        let Ok(now) = now_seconds() else {
            return HnsrApplicationResponse::Reject;
        };
        let Ok(mut service) = self.hnsr.lock() else {
            return HnsrApplicationResponse::Reject;
        };
        match service.handle_encoded(packet, &hex::encode(peer), now) {
            Ok(Some(response)) => HnsrApplicationResponse::Response(response),
            Ok(None) => HnsrApplicationResponse::NoResponse,
            Err(error) => {
                eprintln!("rejected HNSR packet from {}: {error}", hex::encode(peer));
                HnsrApplicationResponse::Reject
            }
        }
    }
}

impl OperatorApplication {
    fn validate_and_store_operator(
        &self,
        object_id: [u8; 32],
        payload: &[u8],
    ) -> Result<bool, BoxError> {
        let record = OperatorRecordV2::from_canonical_bytes(
            payload,
            DecodeLimits {
                max_object_bytes: 64 * 1024,
                max_vector_items: 1024,
            },
        )?;
        if record.protocol_version != CORE_V2
            || record.network_id != self.network_id
            || record.sequence == 0
            || record.signature_suite != ED25519_SUITE
            || record.object_id() != object_id
            || verify_object(
                &record.operator_pubkey,
                record.signature_suite,
                &record.signature,
                self.network_id,
                &record,
            )
            .is_err()
        {
            return Ok(false);
        }
        let _write = self
            .operator_write
            .lock()
            .map_err(|_| "operator record mutex poisoned")?;
        let key = hex::encode(record.operator_pubkey);
        loop {
            let current = self.store.get(OPERATOR_NAMESPACE, &key)?;
            if let Some(bytes) = current.as_deref() {
                let previous = OperatorRecordV2::from_canonical_bytes(
                    bytes,
                    DecodeLimits {
                        max_object_bytes: 64 * 1024,
                        max_vector_items: 1024,
                    },
                )?;
                if previous.sequence > record.sequence
                    || (previous.sequence == record.sequence && bytes != payload)
                {
                    return Ok(false);
                }
                if bytes == payload {
                    return Ok(true);
                }
            }
            if self
                .store
                .compare_and_swap(OPERATOR_NAMESPACE, &key, current.as_deref(), payload)?
            {
                return Ok(true);
            }
        }
    }
}

impl Publisher {
    async fn reserve_publish_lookup(
        &self,
        peer: &QuicOverlayPeer,
        relay_key: &[u8; 33],
        network_magic: u32,
    ) -> Result<([u8; 32], u64), BoxError> {
        let now = now_seconds()?;
        let material = self.load_material(now)?;
        self.reserve_publish_lookup_with_material(peer, relay_key, network_magic, now, material)
            .await
    }

    async fn reserve_publish_lookup_with_material(
        &self,
        peer: &QuicOverlayPeer,
        relay_key: &[u8; 33],
        network_magic: u32,
        now: u64,
        material: PublisherMaterial,
    ) -> Result<([u8; 32], u64), BoxError> {
        if material.authorization.network_magic != network_magic {
            return Err("publication Handshake network mismatch".into());
        }
        let endpoint = EndpointReservation::new(
            network_magic,
            EXPERIMENTAL_PROFILE_ID,
            *material.endpoint_private_key,
        )?;
        let context_id = random_nonzero::<8>();
        let reserve = endpoint.reserve(
            relay_key,
            context_id,
            self.config.reservation_lifetime_seconds,
            self.config.reservation_circuits,
            self.config.reservation_bytes,
            random_nonzero::<16>(),
        )?;
        let offer = exchange_hnsr(peer, &reserve).await?;
        // The relay stamps the offer when it handles the network request. Use
        // a fresh, monotonic local observation when verifying that ticket so
        // crossing a Unix-second boundary cannot make a valid offer appear to
        // come from the future.
        let now = now.max(now_seconds()?);
        let (confirmation, ticket) = endpoint.confirm_offer(&offer, relay_key, now, true)?;
        let confirmed = exchange_hnsr(peer, &confirmation).await?;
        let ticket = endpoint.accept_confirmation(&confirmed, ticket)?;

        let route_key = named_route_key(&material.identity)?;
        let sequence = reserve_route_sequence(
            self.store.as_ref(),
            &route_key,
            &material.delegation.endpoint_key,
        )?;
        let expires_at = now
            .checked_add(self.config.route_lifetime_seconds)
            .ok_or("route publication time overflow")?
            .min(ticket.expires_at)
            .min(material.delegation.expires_at);
        if expires_at <= now {
            return Err("route publication has no valid lifetime".into());
        }
        let mut route = NamedRouteRecordV2 {
            route_key,
            profile: EXPERIMENTAL_PROFILE_ID,
            sequence,
            issued_at: now,
            expires_at,
            authorization: material.authorization.clone(),
            delegation: material.delegation.clone(),
            tickets: vec![ticket],
            endpoint_signature: Vec::new(),
        };
        route.sign(&material.endpoint_private_key)?;
        route.verify(&material.trust(), now)?;
        let encoded = route.encode()?;

        let put = HnsrPacket::new(
            HnsrOpcode::PutRoute,
            random_nonzero::<8>(),
            PutRouteBody {
                route_key,
                record: encoded.clone(),
            }
            .encode()?,
        )?;
        let put_result = exchange_hnsr(peer, &put).await?;
        if put_result.opcode != HnsrOpcode::PutResult {
            return Err("rendezvous returned the wrong publication opcode".into());
        }
        let result = PutResultBody::decode(&put_result.body)?;
        if result.status != 0 || result.stored_until < expires_at {
            return Err("rendezvous did not retain the complete route lifetime".into());
        }

        let lookup = HnsrPacket::new(
            HnsrOpcode::GetRoute,
            random_nonzero::<8>(),
            GetRouteBody {
                route_key,
                maximum_records: 16,
            }
            .encode()?,
        )?;
        let response = exchange_hnsr(peer, &lookup).await?;
        if response.opcode != HnsrOpcode::Routes {
            return Err("rendezvous returned the wrong lookup opcode".into());
        }
        let routes = RoutesBody::decode(&response.body)?;
        let found = routes.records.iter().any(|candidate| {
            NamedRouteRecordV2::decode(candidate)
                .and_then(|candidate| candidate.verify(&material.trust(), now).map(|_| candidate))
                .is_ok_and(|candidate| candidate.encode().is_ok_and(|bytes| bytes == encoded))
        });
        if !found {
            return Err("published route was absent from verified read-back".into());
        }
        Ok((route_key, expires_at))
    }

    fn load_material(&self, now: u64) -> Result<PublisherMaterial, BoxError> {
        let endpoint_private_key =
            read_hex_array::<32>(&self.config.endpoint_signing_key_file, true)?;
        let authorization = ServiceAuthorizationV1::decode(&read_hex_object(
            &self.config.service_authorization_file,
            MAX_HNSA_OBJECT_BYTES,
        )?)?;
        let delegation = EndpointDelegationV1::decode(&read_hex_object(
            &self.config.endpoint_delegation_file,
            MAX_HNSA_OBJECT_BYTES,
        )?)?;
        let context: AuthorityContextFile = serde_json::from_slice(&read_bounded(
            &self.config.authority_context_file,
            MAX_AUTHORITY_CONTEXT_BYTES,
            false,
        )?)?;
        let authority = AuthorityRecord {
            root_key: parse_hex_array::<33>(&context.root_key)?,
            epoch: context.epoch,
        };
        let identity = authorization.identity();
        if identity.network_magic != authorization.network_magic
            || identity.profile_id != EXPERIMENTAL_PROFILE_ID
            || identity.service_name != SERVICE_NAME
            || authorization.flags != 0
            || secp256k1_public_key(&endpoint_private_key)? != delegation.endpoint_key
        {
            return Err("publication material does not match the pool-stats HNSA profile".into());
        }
        authorization.verify(&authority, &identity, context.current_height, 0)?;
        delegation.verify(&authorization, now, READ_STATS_CAPABILITY, [0; 32])?;
        if delegation.capabilities & READ_STATS_CAPABILITY != READ_STATS_CAPABILITY {
            return Err("HNSA delegation lacks the pool-statistics capability".into());
        }
        Ok(PublisherMaterial {
            endpoint_private_key: Zeroizing::new(endpoint_private_key),
            authorization,
            delegation,
            authority,
            identity,
            current_height: context.current_height,
        })
    }
}

impl PublisherMaterial {
    fn trust(&self) -> NamedRouteTrust<'_> {
        NamedRouteTrust {
            authority: &self.authority,
            identity: &self.identity,
            current_height: self.current_height,
            policy: NamedRoutePolicy {
                maximum_route_lifetime: 900,
                allowed_authorization_flags: 0,
                allowed_endpoint_capabilities: READ_STATS_CAPABILITY,
                required_endpoint_capabilities: READ_STATS_CAPABILITY,
                expected_constraints_hash: [0; 32],
                allow_private_relays: true,
            },
        }
    }
}

async fn exchange_hnsr(
    peer: &QuicOverlayPeer,
    packet: &HnsrPacket,
) -> Result<HnsrPacket, BoxError> {
    let response = peer
        .hnsr(&packet.encode()?)
        .await?
        .ok_or("HNSR operation returned no response")?;
    Ok(HnsrPacket::decode(&response)?)
}

fn load_relay(config: &Config) -> Result<RelayService, BoxError> {
    let address: SocketAddr = config.relay.public_address.parse()?;
    let (host_type, host) = canonical_host(address.ip());
    let supported_profiles = config
        .relay
        .supported_profiles
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    Ok(RelayService::new(
        RelayConfig {
            network_magic: config.network_magic,
            transport: 0,
            host_type,
            host,
            port: address.port(),
            allow_private_address: config.relay.allow_private_address,
            supported_profiles,
            limits: RelayLimits {
                maximum_reservations: config.relay.maximum_reservations,
                maximum_reservations_per_source: config.relay.maximum_reservations_per_source,
                maximum_bytes_per_circuit: config.relay.maximum_bytes_per_circuit,
            },
        },
        read_hex_array::<32>(&config.relay.signing_key_file, true)?,
    )?)
}

fn validate_config(config: &Config) -> Result<(), BoxError> {
    let unique_profiles = config
        .relay
        .supported_profiles
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if config.schema_version != 1
        || config.network_id == 0
        || config.network_magic == 0
        || config.peers.is_empty()
        || config.peers.len() > MAX_PEERS
        || !config
            .relay
            .supported_profiles
            .contains(&EXPERIMENTAL_PROFILE_ID)
        || config.relay.supported_profiles.contains(&0)
        || unique_profiles.len() != config.relay.supported_profiles.len()
    {
        return Err("invalid multi-operator daemon configuration".into());
    }
    let mut paths = vec![
        &config.certificate_file,
        &config.certificate_key_file,
        &config.transport_signing_key_file,
        &config.state_file,
        &config.relay.signing_key_file,
    ];
    for peer in &config.peers {
        paths.push(&peer.certificate_file);
    }
    if let Some(publication) = config.publication.as_ref() {
        paths.extend([
            &publication.endpoint_signing_key_file,
            &publication.service_authorization_file,
            &publication.endpoint_delegation_file,
            &publication.authority_context_file,
        ]);
    }
    if paths.iter().any(|path| !path.is_absolute()) {
        return Err("operator daemon paths must be absolute".into());
    }
    let _: SocketAddr = config.listen.parse()?;
    let _: SocketAddr = config.relay.public_address.parse()?;
    let mut remotes = HashSet::new();
    let mut identities = HashSet::new();
    for peer in &config.peers {
        let remote: SocketAddr = peer.remote.parse()?;
        let identity = parse_hex_array::<32>(&peer.expected_transport_pubkey)?;
        let _ = parse_hex_array::<33>(&peer.hnsr_relay_key)?;
        if peer.server_name.is_empty()
            || peer.reconnect_initial_ms == 0
            || peer.reconnect_initial_ms > peer.reconnect_maximum_ms
            || !remotes.insert(remote)
            || !identities.insert(identity)
        {
            return Err("invalid or duplicate multi-operator peer".into());
        }
    }
    if let Some(publication) = config.publication.as_ref()
        && (publication.reservation_lifetime_seconds < 300
            || publication.route_lifetime_seconds == 0
            || publication.route_lifetime_seconds > 900
            || publication.route_lifetime_seconds
                >= u64::from(publication.reservation_lifetime_seconds)
            || publication.reservation_circuits == 0
            || publication.reservation_bytes == 0
            || publication.publication_interval_ms < 1000
            || publication.publication_interval_ms
                >= publication.route_lifetime_seconds.saturating_mul(1000))
    {
        return Err("invalid HNSR publication schedule".into());
    }
    Ok(())
}

fn reserve_route_sequence(
    store: &dyn DurableStore,
    route_key: &[u8; 32],
    endpoint_key: &[u8; 33],
) -> Result<u64, BoxError> {
    let key = format!("{}:{}", hex::encode(route_key), hex::encode(endpoint_key));
    loop {
        let current = store.get(ROUTE_SEQUENCE_NAMESPACE, &key)?;
        let previous = match current.as_deref() {
            None => 0,
            Some(bytes) => u64::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| "invalid durable HNSR route sequence")?,
            ),
        };
        let next = previous
            .checked_add(1)
            .ok_or("HNSR route sequence exhausted")?;
        if store.compare_and_swap(
            ROUTE_SEQUENCE_NAMESPACE,
            &key,
            current.as_deref(),
            &next.to_le_bytes(),
        )? {
            return Ok(next);
        }
    }
}

async fn wait_or_shutdown(
    delay_ms: u64,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), BoxError> {
    tokio::select! {
        changed = shutdown.changed() => {
            if changed.is_err() || *shutdown.borrow() {
                return Ok(());
            }
        }
        _ = sleep(Duration::from_millis(delay_ms)) => {}
    }
    Ok(())
}

fn next_backoff(current: u64, maximum: u64) -> u64 {
    current.saturating_mul(2).min(maximum)
}

fn canonical_host(address: IpAddr) -> (u8, [u8; 16]) {
    match address {
        IpAddr::V4(address) => {
            let mut host = [0; 16];
            host[10..12].copy_from_slice(&[0xff, 0xff]);
            host[12..].copy_from_slice(&address.octets());
            (1, host)
        }
        IpAddr::V6(address) => (2, address.octets()),
    }
}

fn random_nonzero<const N: usize>() -> [u8; N] {
    loop {
        let value: [u8; N] = rand::random();
        if value != [0; N] {
            return value;
        }
    }
}

fn flag_path<'a>(arguments: &'a [String], flag: &str) -> Result<&'a Path, BoxError> {
    if arguments.len() != 2 || arguments[0] != flag {
        return Err("usage: meshmine-operatord serve --config FILE".into());
    }
    Ok(Path::new(&arguments[1]))
}

fn read_hex_array<const N: usize>(path: &Path, private: bool) -> Result<[u8; N], BoxError> {
    let bytes = read_bounded(path, MAX_KEY_BYTES, private)?;
    let value = std::str::from_utf8(&bytes)?.trim();
    parse_hex_array(value)
}

fn parse_hex_array<const N: usize>(value: &str) -> Result<[u8; N], BoxError> {
    if value.len() != N.saturating_mul(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("expected canonical lowercase fixed-length hex".into());
    }
    Ok(hex::decode(value)?
        .try_into()
        .map_err(|_| "fixed-length hex size mismatch")?)
}

fn read_hex_object(path: &Path, maximum: u64) -> Result<Vec<u8>, BoxError> {
    let encoded = read_bounded(path, maximum.saturating_mul(2).saturating_add(2), false)?;
    let encoded = std::str::from_utf8(&encoded)?.trim();
    if encoded.is_empty()
        || encoded.len() > maximum as usize * 2
        || !encoded.len().is_multiple_of(2)
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid bounded canonical HNSA hex object".into());
    }
    Ok(hex::decode(encoded)?)
}

fn read_bounded(path: &Path, maximum: u64, private: bool) -> Result<Vec<u8>, BoxError> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    validate_file(&file, maximum, private)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err("bounded file exceeds configured maximum".into());
    }
    Ok(bytes)
}

fn validate_file(file: &File, maximum: u64, private: bool) -> Result<(), BoxError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err("expected bounded regular file".into());
    }
    if private && metadata.mode() & 0o077 != 0 {
        return Err("private operator file permissions must be 0600 or stricter".into());
    }
    Ok(())
}

fn now_seconds() -> Result<u64, BoxError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

const fn default_maximum_reservations() -> usize {
    4096
}
const fn default_maximum_reservations_per_source() -> usize {
    64
}
const fn default_maximum_bytes_per_circuit() -> u64 {
    16 * 1024 * 1024
}
const fn default_total_routes() -> usize {
    50_000
}
const fn default_routes_per_key() -> usize {
    16
}
const fn default_routes_per_source() -> usize {
    1024
}
const fn default_reservation_lifetime() -> u32 {
    1200
}
const fn default_route_lifetime() -> u64 {
    600
}
const fn default_reservation_circuits() -> u16 {
    8
}
const fn default_reservation_bytes() -> u64 {
    64 * 1024 * 1024
}
const fn default_publication_interval_ms() -> u64 {
    300_000
}
const fn default_reconnect_initial_ms() -> u64 {
    1000
}
const fn default_reconnect_maximum_ms() -> u64 {
    60_000
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use hns_service_authority::public_key as authority_public_key;
    use meshmine_codec::{CanonicalEncode, Encoder};
    use meshmine_crypto::sign_object;
    use meshmine_storage::MemoryStore;
    use meshmine_types::SignatureBytes;
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    use super::*;

    fn application() -> OperatorApplication {
        let relay = RelayService::new(
            RelayConfig {
                network_magic: 0x6d6f_6f6e,
                transport: 0,
                host_type: 1,
                host: canonical_host("127.0.0.1".parse().unwrap()).1,
                port: 14_039,
                allow_private_address: true,
                supported_profiles: BTreeSet::from([EXPERIMENTAL_PROFILE_ID]),
                limits: RelayLimits::default(),
            },
            [3; 32],
        )
        .unwrap();
        let rendezvous = RendezvousService::new(
            0x6d6f_6f6e,
            true,
            RouteStoreLimits {
                total_records: 32,
                records_per_key: 4,
                records_per_source: 8,
            },
        )
        .unwrap();
        OperatorApplication {
            network_id: 2,
            hnsr: Mutex::new(HnsrService::new(Some(relay), Some(rendezvous))),
            store: Arc::new(MemoryStore::default()),
            operator_write: Mutex::new(()),
        }
    }

    fn operator(sequence: u64, key: &SigningKey) -> OperatorRecordV2 {
        let mut record = OperatorRecordV2 {
            protocol_version: CORE_V2,
            network_id: 2,
            operator_pubkey: key.verifying_key().to_bytes(),
            sequence,
            supported_features: 1,
            payout_bucket_ids: Vec::new(),
            contact_metadata_hash: None,
            signature_suite: ED25519_SUITE,
            signature: SignatureBytes::empty(),
        };
        record.signature = sign_object(key, 2, &record);
        record
    }

    fn bytes(record: &OperatorRecordV2) -> Vec<u8> {
        let mut encoder = Encoder::new();
        record.encode(&mut encoder);
        encoder.into_bytes()
    }

    #[test]
    fn durable_operator_admission_rejects_stale_and_conflicting_sequences() {
        let application = application();
        let key = SigningKey::from_bytes(&[7; 32]);
        let first = operator(1, &key);
        let second = operator(2, &key);
        assert!(
            application
                .validate_and_store_operator(first.object_id(), &bytes(&first))
                .unwrap()
        );
        assert!(
            application
                .validate_and_store_operator(second.object_id(), &bytes(&second))
                .unwrap()
        );
        assert!(
            !application
                .validate_and_store_operator(first.object_id(), &bytes(&first))
                .unwrap()
        );

        let mut conflict = second.clone();
        conflict.supported_features = 2;
        conflict.signature = sign_object(&key, 2, &conflict);
        assert!(
            !application
                .validate_and_store_operator(conflict.object_id(), &bytes(&conflict))
                .unwrap()
        );
    }

    #[test]
    fn route_sequences_are_reserved_before_signing_and_scoped_per_endpoint() {
        let store = MemoryStore::default();
        assert_eq!(
            reserve_route_sequence(&store, &[1; 32], &[2; 33]).unwrap(),
            1
        );
        assert_eq!(
            reserve_route_sequence(&store, &[1; 32], &[2; 33]).unwrap(),
            2
        );
        assert_eq!(
            reserve_route_sequence(&store, &[1; 32], &[3; 33]).unwrap(),
            1
        );
    }

    #[test]
    fn canonical_relay_addresses_preserve_ipv4_and_ipv6() {
        assert_eq!(
            canonical_host("192.0.2.1".parse().unwrap()),
            (1, "::ffff:192.0.2.1".parse::<Ipv6Addr>().unwrap().octets())
        );
        assert_eq!(
            canonical_host("2001:db8::1".parse().unwrap()),
            (2, "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_peer_composes_live_reserve_publish_and_verified_lookup() {
        let server_application = Arc::new(application());
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let server_identity = TransportIdentity::new(SigningKey::from_bytes(&[21; 32]), None);
        let client_identity = TransportIdentity::new(SigningKey::from_bytes(&[22; 32]), None);
        let (overlay_limits, topics) = default_overlay_limits();
        let server = QuicOverlayServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            cert.der().to_vec(),
            key_pair.serialize_der(),
            server_identity,
            2,
            OverlayNode::new(2, overlay_limits, topics),
            server_application.clone(),
            QuicTransportLimits::default(),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server_task = tokio::spawn(server.run_until(shutdown_rx));
        let peer = QuicOverlayPeer::connect(
            "0.0.0.0:0".parse().unwrap(),
            address,
            "localhost",
            cert.der().to_vec(),
            client_identity,
            2,
            QuicTransportLimits::default(),
        )
        .await
        .unwrap();

        let now = now_seconds().unwrap();
        let root_private = [31; 32];
        let service_private = [32; 32];
        let endpoint_private = [33; 32];
        let identity = ServiceIdentity {
            network_magic: 0x6d6f_6f6e,
            name_hash: [34; 32],
            service_name: SERVICE_NAME.to_owned(),
            profile_id: EXPERIMENTAL_PROFILE_ID,
        };
        let authority = AuthorityRecord {
            root_key: authority_public_key(&root_private).unwrap(),
            epoch: 1,
        };
        let mut authorization = ServiceAuthorizationV1 {
            network_magic: identity.network_magic,
            name_hash: identity.name_hash,
            authority_epoch: authority.epoch,
            service_name: identity.service_name.clone(),
            profile_id: identity.profile_id,
            service_key: authority_public_key(&service_private).unwrap(),
            flags: 0,
            serial: 1,
            valid_from_height: 100,
            valid_until_height: 200,
            max_endpoint_lifetime: 3600,
            root_signature: Vec::new(),
        };
        authorization.sign(&root_private).unwrap();
        let mut delegation = EndpointDelegationV1 {
            network_magic: identity.network_magic,
            authorization_id: authorization.id().unwrap(),
            endpoint_key: authority_public_key(&endpoint_private).unwrap(),
            endpoint_sequence: 1,
            issued_at: now,
            expires_at: now + 1800,
            capabilities: READ_STATS_CAPABILITY,
            constraints_hash: [0; 32],
            service_signature: Vec::new(),
        };
        delegation.sign(&service_private).unwrap();
        let publisher = Publisher {
            config: PublicationConfig {
                endpoint_signing_key_file: "/unused/endpoint".into(),
                service_authorization_file: "/unused/authorization".into(),
                endpoint_delegation_file: "/unused/delegation".into(),
                authority_context_file: "/unused/authority".into(),
                reservation_lifetime_seconds: 1200,
                route_lifetime_seconds: 600,
                reservation_circuits: 4,
                reservation_bytes: 4 * 1024 * 1024,
                publication_interval_ms: 300_000,
            },
            store: Arc::new(MemoryStore::default()),
        };
        let material = PublisherMaterial {
            endpoint_private_key: Zeroizing::new(endpoint_private),
            authorization,
            delegation,
            authority,
            identity,
            current_height: 150,
        };
        let relay_key = hns_hnsr_protocol::public_key(&[3; 32]).unwrap();
        let (_, expires_at) = publisher
            .reserve_publish_lookup_with_material(&peer, &relay_key, 0x6d6f_6f6e, now, material)
            .await
            .unwrap();
        assert_eq!(expires_at, now + 600);
        assert_eq!(
            server_application
                .hnsr
                .lock()
                .unwrap()
                .rendezvous()
                .unwrap()
                .route_count(),
            1
        );

        peer.close().await;
        shutdown_tx.send(true).unwrap();
        server_task.await.unwrap().unwrap();
    }
}
