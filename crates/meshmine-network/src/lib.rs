//! Authenticated overlay admission controls and a deterministic partition
//! harness plus a native QUIC transport that wraps the same boundary.

mod transport;

pub use transport::*;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use meshmine_codec::{CanonicalDecode, CanonicalEncode, CodecError, Decoder, Encoder};
use meshmine_crypto::{CryptoError, verify_object};
use meshmine_hns::Hash256;
use meshmine_types::{ED25519_SUITE, SignatureBytes, UnsignedObject, domain_hash};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum GossipTopic {
    Parent = 0,
    Operator = 1,
    BodyDescriptor = 2,
    MaskSession = 3,
    Share = 4,
    ReceiptBatch = 5,
    SessionClose = 6,
    MaskOpening = 7,
    PayoutSnapshot = 8,
    PayoutPlan = 9,
    FaultProof = 10,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestProtocol {
    BodyShard,
    BodyPackage,
    ShareObject,
    ReceiptProof,
    SessionTranscript,
    PayoutTranscript,
    CommitteeRoster,
}

/// Local scheduling boundary for protocol work with different latency and
/// failure requirements. This is deliberately not a wire field: peers cannot
/// select a lane independently of the signed gossip topic or request kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolLane {
    FastPath,
    Accounting,
    Availability,
    Settlement,
}

impl GossipTopic {
    pub const fn protocol_lane(self) -> ProtocolLane {
        match self {
            Self::Parent | Self::MaskSession | Self::MaskOpening | Self::FaultProof => {
                ProtocolLane::FastPath
            }
            Self::Operator | Self::Share | Self::ReceiptBatch | Self::SessionClose => {
                ProtocolLane::Accounting
            }
            Self::BodyDescriptor => ProtocolLane::Availability,
            Self::PayoutSnapshot | Self::PayoutPlan => ProtocolLane::Settlement,
        }
    }
}

impl RequestProtocol {
    pub const fn protocol_lane(self) -> ProtocolLane {
        match self {
            Self::SessionTranscript | Self::CommitteeRoster => ProtocolLane::FastPath,
            Self::ShareObject | Self::ReceiptProof => ProtocolLane::Accounting,
            Self::BodyShard | Self::BodyPackage => ProtocolLane::Availability,
            Self::PayoutTranscript => ProtocolLane::Settlement,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TopicLimit {
    pub maximum_object_bytes: u32,
    pub messages_per_window: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlayLimits {
    pub rate_window_ms: u64,
    /// Maximum number of transport identities retained at once. Admission
    /// evicts only an expired, idle least-recently-active peer and otherwise
    /// fails closed.
    pub maximum_tracked_peers: usize,
    /// Minimum inactivity before an idle peer becomes eligible for eviction.
    pub peer_inactivity_timeout_ms: u64,
    pub maximum_pending_objects_per_peer: u16,
    pub maximum_pending_bytes_per_peer: u64,
    /// Maximum age of an in-flight validation before its budget is reclaimed.
    pub pending_validation_timeout_ms: u64,
    pub maximum_seen_objects: usize,
    pub maximum_orphan_shares: usize,
    /// Maximum number of recent overlay events retained for diagnostics.
    pub maximum_retained_events: usize,
    pub maximum_parent_fetch_depth: u16,
    pub body_download_bytes_per_window: u64,
    pub invalid_object_penalty: i32,
    pub disconnect_score: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockSkewBehavior {
    RejectSession,
    PauseNewAssignments,
}

/// Published deployment clock limits. Runtime code must use a monotonic clock
/// for elapsed windows and use wall time only for bounded peer comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockProfile {
    pub maximum_wall_clock_skew_ms: u64,
    pub maximum_assignment_window_ms: u64,
    pub maximum_submission_grace_ms: u64,
    pub maximum_receipt_finalization_ms: u64,
    pub minimum_timed_open_delay_ms: u64,
    pub maximum_timed_open_delay_ms: u64,
    pub skew_behavior: ClockSkewBehavior,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionSchedule {
    pub assignment_start_ms: u64,
    pub assignment_end_ms: u64,
    pub submission_end_ms: u64,
    pub receipt_boundary_ms: u64,
    pub timed_open_after_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerHello {
    pub protocol_version: u16,
    pub network_id: u8,
    pub transport_pubkey: [u8; 32],
    pub economic_operator_pubkey: Option<[u8; 32]>,
    pub challenge_nonce: Hash256,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectEnvelope {
    pub topic: GossipTopic,
    pub object_id: Hash256,
    pub encoded_size: u32,
    pub missing_parent: bool,
    pub parent_fetch_depth: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IngressToken {
    pub object_id: Hash256,
    pub peer: [u8; 32],
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressDecision {
    Validate(IngressToken),
    AlreadyValidated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OverlayEvent {
    PeerAuthenticated {
        transport_pubkey: [u8; 32],
    },
    SignatureRejected {
        object_id: Hash256,
    },
    ValidationStarted {
        object_id: Hash256,
    },
    ValidationCompleted {
        object_id: Hash256,
    },
    OrphanCached {
        object_id: Hash256,
    },
    PeerPenalized {
        transport_pubkey: [u8; 32],
        score: i32,
    },
    PeerDisconnected {
        transport_pubkey: [u8; 32],
    },
}

#[derive(Debug)]
struct PeerState {
    economic_operator_pubkey: Option<[u8; 32]>,
    last_activity_ms: u64,
    gossip_score: i32,
    availability_score: i32,
    pending_objects: u16,
    pending_bytes: u64,
    body_download_bytes: u64,
    window_start_ms: u64,
    messages_by_topic: BTreeMap<GossipTopic, u16>,
    disconnected: bool,
}

#[derive(Clone, Debug)]
struct PendingObject {
    peer: [u8; 32],
    size: u32,
    started_ms: u64,
    generation: u64,
}

#[derive(Debug)]
pub struct OverlayNode {
    network_id: u8,
    limits: OverlayLimits,
    topic_limits: BTreeMap<GossipTopic, TopicLimit>,
    peers: HashMap<[u8; 32], PeerState>,
    pending: HashMap<Hash256, PendingObject>,
    seen_order: VecDeque<Hash256>,
    seen: HashSet<Hash256>,
    orphans: VecDeque<Hash256>,
    events: Vec<OverlayEvent>,
    dropped_events: u64,
    evicted_peers: u64,
    expired_validations: u64,
    next_validation_generation: u64,
}

#[derive(Clone, Debug, Default)]
pub struct SimulatedNetwork {
    nodes: BTreeSet<String>,
    links: BTreeSet<(String, String)>,
    disabled_links: BTreeSet<(String, String)>,
    objects: BTreeMap<String, BTreeSet<Hash256>>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkError {
    #[error("peer authentication failed: {0}")]
    Authentication(String),
    #[error("peer is unknown or disconnected")]
    PeerUnavailable,
    #[error("peer admission capacity is exhausted")]
    PeerCapacity,
    #[error("object exceeds its topic size bound")]
    ObjectTooLarge,
    #[error("peer exceeded a per-topic rate limit")]
    RateLimited,
    #[error("object was already observed")]
    Duplicate,
    #[error("signature validation failed before expensive validation")]
    InvalidSignature,
    #[error("peer exceeded its pending-validation budget")]
    PendingBudget,
    #[error("share parent fetch depth exceeds the configured bound")]
    ParentDepth,
    #[error("body request exceeds its per-peer quota")]
    BodyQuota,
    #[error("validation token was not found")]
    UnknownValidation,
    #[error("validation token generation space is exhausted")]
    ValidationGenerationExhausted,
    #[error("simulated node or partition set is invalid")]
    InvalidSimulation,
    #[error("peer wall clock exceeds the published skew bound")]
    ClockSkew,
    #[error("session schedule is inconsistent with the published clock profile")]
    InvalidSchedule,
}

impl ClockProfile {
    pub fn validate_peer_time(
        &self,
        local_wall_ms: u64,
        peer_wall_ms: u64,
    ) -> Result<(), NetworkError> {
        if local_wall_ms.abs_diff(peer_wall_ms) > self.maximum_wall_clock_skew_ms {
            return Err(NetworkError::ClockSkew);
        }
        Ok(())
    }

    pub fn validate_schedule(&self, schedule: &SessionSchedule) -> Result<(), NetworkError> {
        let assignment = schedule
            .assignment_end_ms
            .checked_sub(schedule.assignment_start_ms)
            .ok_or(NetworkError::InvalidSchedule)?;
        let grace = schedule
            .submission_end_ms
            .checked_sub(schedule.assignment_end_ms)
            .ok_or(NetworkError::InvalidSchedule)?;
        let finalization = schedule
            .receipt_boundary_ms
            .checked_sub(schedule.submission_end_ms)
            .ok_or(NetworkError::InvalidSchedule)?;
        let open_delay = schedule
            .timed_open_after_ms
            .checked_sub(schedule.receipt_boundary_ms)
            .ok_or(NetworkError::InvalidSchedule)?;
        if self.maximum_wall_clock_skew_ms == 0
            || assignment == 0
            || assignment > self.maximum_assignment_window_ms
            || grace > self.maximum_submission_grace_ms
            || finalization == 0
            || finalization > self.maximum_receipt_finalization_ms
            || open_delay < self.minimum_timed_open_delay_ms
            || open_delay > self.maximum_timed_open_delay_ms
        {
            return Err(NetworkError::InvalidSchedule);
        }
        Ok(())
    }
}

impl UnsignedObject for PeerHello {
    const DOMAIN_TAG: &'static str = "meshmine/peer-hello/v2";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encoder.u16(self.protocol_version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.transport_pubkey);
        match self.economic_operator_pubkey {
            Some(key) => {
                encoder.u8(1);
                encoder.fixed(&key);
            }
            None => encoder.u8(0),
        }
        encoder.fixed(&self.challenge_nonce);
    }
}

impl CanonicalEncode for PeerHello {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
        self.signature.encode(encoder);
    }
}

impl CanonicalDecode for PeerHello {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            protocol_version: decoder.u16()?,
            network_id: decoder.u8()?,
            transport_pubkey: decoder.array()?,
            economic_operator_pubkey: decoder.option(|decoder| decoder.array())?,
            challenge_nonce: decoder.array()?,
            signature: SignatureBytes::decode(decoder)?,
        })
    }
}

impl OverlayNode {
    pub fn new(
        network_id: u8,
        limits: OverlayLimits,
        topic_limits: BTreeMap<GossipTopic, TopicLimit>,
    ) -> Self {
        Self {
            network_id,
            limits,
            topic_limits,
            peers: HashMap::new(),
            pending: HashMap::new(),
            seen_order: VecDeque::new(),
            seen: HashSet::new(),
            orphans: VecDeque::new(),
            events: Vec::new(),
            dropped_events: 0,
            evicted_peers: 0,
            expired_validations: 0,
            next_validation_generation: 0,
        }
    }

    pub fn authenticate_peer(
        &mut self,
        hello: &PeerHello,
        now_ms: u64,
    ) -> Result<(), NetworkError> {
        if hello.protocol_version != 2 || hello.network_id != self.network_id {
            return Err(NetworkError::Authentication("network mismatch".to_owned()));
        }
        verify_object(
            &hello.transport_pubkey,
            ED25519_SUITE,
            &hello.signature,
            hello.network_id,
            hello,
        )
        .map_err(authentication)?;
        self.expire_stale_validations(now_ms);
        if let Some(peer) = self.peers.get_mut(&hello.transport_pubkey) {
            if peer.disconnected {
                return Err(NetworkError::PeerUnavailable);
            }
            if peer.economic_operator_pubkey != hello.economic_operator_pubkey {
                return Err(NetworkError::Authentication(
                    "transport identity attempted to change economic identity".to_owned(),
                ));
            }
            // Reauthentication must not reset rate windows, byte quotas, or
            // accumulated penalties; otherwise reconnects become a trivial
            // quota and reputation bypass.
            peer.last_activity_ms = peer.last_activity_ms.max(now_ms);
            push_bounded_event(
                &mut self.events,
                &mut self.dropped_events,
                self.limits.maximum_retained_events,
                OverlayEvent::PeerAuthenticated {
                    transport_pubkey: hello.transport_pubkey,
                },
            );
            return Ok(());
        }
        if self.limits.maximum_tracked_peers == 0 {
            return Err(NetworkError::PeerCapacity);
        }
        while self.peers.len() >= self.limits.maximum_tracked_peers {
            if !self.evict_inactive_peer(now_ms) {
                return Err(NetworkError::PeerCapacity);
            }
        }
        self.peers.insert(
            hello.transport_pubkey,
            PeerState {
                economic_operator_pubkey: hello.economic_operator_pubkey,
                last_activity_ms: now_ms,
                gossip_score: 0,
                availability_score: 0,
                pending_objects: 0,
                pending_bytes: 0,
                body_download_bytes: 0,
                window_start_ms: now_ms,
                messages_by_topic: BTreeMap::new(),
                disconnected: false,
            },
        );
        push_bounded_event(
            &mut self.events,
            &mut self.dropped_events,
            self.limits.maximum_retained_events,
            OverlayEvent::PeerAuthenticated {
                transport_pubkey: hello.transport_pubkey,
            },
        );
        Ok(())
    }

    pub fn begin_validation(
        &mut self,
        peer_key: &[u8; 32],
        envelope: ObjectEnvelope,
        signature_valid: bool,
        now_ms: u64,
    ) -> Result<IngressDecision, NetworkError> {
        self.expire_stale_validations(now_ms);
        let peer = self
            .peers
            .get_mut(peer_key)
            .filter(|peer| !peer.disconnected)
            .ok_or(NetworkError::PeerUnavailable)?;
        peer.last_activity_ms = peer.last_activity_ms.max(now_ms);
        if now_ms.saturating_sub(peer.window_start_ms) >= self.limits.rate_window_ms {
            peer.window_start_ms = now_ms;
            peer.messages_by_topic.clear();
            peer.body_download_bytes = 0;
        }
        let topic_limit = self
            .topic_limits
            .get(&envelope.topic)
            .ok_or(NetworkError::ObjectTooLarge)?;
        if envelope.encoded_size > topic_limit.maximum_object_bytes {
            return self.penalize(peer_key, NetworkError::ObjectTooLarge);
        }
        let messages = peer.messages_by_topic.entry(envelope.topic).or_default();
        if *messages >= topic_limit.messages_per_window {
            return Err(NetworkError::RateLimited);
        }
        *messages += 1;
        if self.pending.contains_key(&envelope.object_id) {
            return Err(NetworkError::Duplicate);
        }
        // Callers perform cheap signature/certificate verification before this
        // method can allocate a pending expensive-validation slot.
        if !signature_valid {
            push_bounded_event(
                &mut self.events,
                &mut self.dropped_events,
                self.limits.maximum_retained_events,
                OverlayEvent::SignatureRejected {
                    object_id: envelope.object_id,
                },
            );
            return self.penalize(peer_key, NetworkError::InvalidSignature);
        }
        // A completed validation is an idempotent success for transport
        // retries. The signature check above remains mandatory, while the
        // application callback is deliberately skipped so accepted state
        // cannot be replaced by a retry payload.
        if self.seen.contains(&envelope.object_id) {
            return Ok(IngressDecision::AlreadyValidated);
        }
        let next_pending_bytes = peer
            .pending_bytes
            .checked_add(u64::from(envelope.encoded_size))
            .ok_or(NetworkError::PendingBudget)?;
        if peer.pending_objects >= self.limits.maximum_pending_objects_per_peer
            || next_pending_bytes > self.limits.maximum_pending_bytes_per_peer
        {
            return Err(NetworkError::PendingBudget);
        }
        if envelope.topic == GossipTopic::Share && envelope.missing_parent {
            if envelope.parent_fetch_depth > self.limits.maximum_parent_fetch_depth {
                return self.penalize(peer_key, NetworkError::ParentDepth);
            }
            while self.orphans.len() >= self.limits.maximum_orphan_shares {
                self.orphans.pop_front();
            }
            self.orphans.push_back(envelope.object_id);
            push_bounded_event(
                &mut self.events,
                &mut self.dropped_events,
                self.limits.maximum_retained_events,
                OverlayEvent::OrphanCached {
                    object_id: envelope.object_id,
                },
            );
        }
        let generation = self.next_validation_generation;
        let next_validation_generation = self
            .next_validation_generation
            .checked_add(1)
            .ok_or(NetworkError::ValidationGenerationExhausted)?;
        peer.pending_objects += 1;
        peer.pending_bytes = next_pending_bytes;
        self.next_validation_generation = next_validation_generation;
        self.pending.insert(
            envelope.object_id,
            PendingObject {
                peer: *peer_key,
                size: envelope.encoded_size,
                started_ms: now_ms,
                generation,
            },
        );
        push_bounded_event(
            &mut self.events,
            &mut self.dropped_events,
            self.limits.maximum_retained_events,
            OverlayEvent::ValidationStarted {
                object_id: envelope.object_id,
            },
        );
        Ok(IngressDecision::Validate(IngressToken {
            object_id: envelope.object_id,
            peer: *peer_key,
            generation,
        }))
    }

    pub fn finish_validation(
        &mut self,
        token: IngressToken,
        valid: bool,
    ) -> Result<(), NetworkError> {
        let pending = self
            .pending
            .get(&token.object_id)
            .filter(|pending| pending.peer == token.peer && pending.generation == token.generation)
            .ok_or(NetworkError::UnknownValidation)?;
        let pending_peer = pending.peer;
        let pending = self
            .pending
            .remove(&token.object_id)
            .ok_or(NetworkError::UnknownValidation)?;
        debug_assert_eq!(pending.peer, pending_peer);
        let peer = self
            .peers
            .get_mut(&pending.peer)
            .ok_or(NetworkError::PeerUnavailable)?;
        peer.pending_objects = peer.pending_objects.saturating_sub(1);
        peer.pending_bytes = peer.pending_bytes.saturating_sub(u64::from(pending.size));
        if !valid {
            return self.penalize(&pending.peer, NetworkError::InvalidSignature);
        }
        peer.gossip_score += 1;
        self.seen.insert(token.object_id);
        self.seen_order.push_back(token.object_id);
        while self.seen_order.len() > self.limits.maximum_seen_objects {
            if let Some(oldest) = self.seen_order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        push_bounded_event(
            &mut self.events,
            &mut self.dropped_events,
            self.limits.maximum_retained_events,
            OverlayEvent::ValidationCompleted {
                object_id: token.object_id,
            },
        );
        Ok(())
    }

    pub fn request_body_bytes(
        &mut self,
        peer_key: &[u8; 32],
        bytes: u64,
        now_ms: u64,
    ) -> Result<(), NetworkError> {
        let peer = self
            .peers
            .get_mut(peer_key)
            .filter(|peer| !peer.disconnected)
            .ok_or(NetworkError::PeerUnavailable)?;
        peer.last_activity_ms = peer.last_activity_ms.max(now_ms);
        if now_ms.saturating_sub(peer.window_start_ms) >= self.limits.rate_window_ms {
            peer.window_start_ms = now_ms;
            peer.messages_by_topic.clear();
            peer.body_download_bytes = 0;
        }
        if peer.body_download_bytes.saturating_add(bytes)
            > self.limits.body_download_bytes_per_window
        {
            peer.availability_score -= 1;
            return Err(NetworkError::BodyQuota);
        }
        peer.body_download_bytes += bytes;
        peer.availability_score += 1;
        Ok(())
    }

    pub fn peer_identities(&self, peer_key: &[u8; 32]) -> Option<([u8; 32], Option<[u8; 32]>)> {
        self.peers
            .get(peer_key)
            .map(|peer| (*peer_key, peer.economic_operator_pubkey))
    }

    pub fn peer_is_disconnected(&self, peer_key: &[u8; 32]) -> bool {
        self.peers
            .get(peer_key)
            .is_none_or(|peer| peer.disconnected)
    }

    /// Recent events in chronological order. Once the configured bound is
    /// reached, older entries are compacted and counted by
    /// [`Self::dropped_event_count`].
    pub fn events(&self) -> &[OverlayEvent] {
        &self.events
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn dropped_event_count(&self) -> u64 {
        self.dropped_events
    }

    pub fn evicted_peer_count(&self) -> u64 {
        self.evicted_peers
    }

    pub fn expired_validation_count(&self) -> u64 {
        self.expired_validations
    }

    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }

    fn penalize<T>(&mut self, peer_key: &[u8; 32], error: NetworkError) -> Result<T, NetworkError> {
        let (score, disconnected) = {
            let peer = self
                .peers
                .get_mut(peer_key)
                .ok_or(NetworkError::PeerUnavailable)?;
            peer.gossip_score -= self.limits.invalid_object_penalty;
            if peer.gossip_score <= self.limits.disconnect_score {
                peer.disconnected = true;
            }
            (peer.gossip_score, peer.disconnected)
        };
        push_bounded_event(
            &mut self.events,
            &mut self.dropped_events,
            self.limits.maximum_retained_events,
            OverlayEvent::PeerPenalized {
                transport_pubkey: *peer_key,
                score,
            },
        );
        if disconnected {
            push_bounded_event(
                &mut self.events,
                &mut self.dropped_events,
                self.limits.maximum_retained_events,
                OverlayEvent::PeerDisconnected {
                    transport_pubkey: *peer_key,
                },
            );
        }
        Err(error)
    }

    fn evict_inactive_peer(&mut self, now_ms: u64) -> bool {
        // Never evict an identity that owns in-flight validation state. Among
        // expired idle identities, deterministic LRU eviction bounds Sybil
        // churn while keeping recent peers and their reputation state resident.
        let candidate = self
            .peers
            .iter()
            .filter(|(_, peer)| {
                peer.pending_objects == 0
                    && now_ms.saturating_sub(peer.last_activity_ms)
                        >= self.limits.peer_inactivity_timeout_ms
            })
            .min_by_key(|(key, peer)| (peer.last_activity_ms, **key))
            .map(|(key, _)| *key);
        if candidate.is_some_and(|key| self.peers.remove(&key).is_some()) {
            self.evicted_peers = self.evicted_peers.saturating_add(1);
            true
        } else {
            false
        }
    }

    fn expire_stale_validations(&mut self, now_ms: u64) {
        let maximum_age_ms = self.limits.pending_validation_timeout_ms;
        let peers = &mut self.peers;
        let mut expired = 0_u64;
        self.pending.retain(|_, pending| {
            if now_ms.saturating_sub(pending.started_ms) < maximum_age_ms {
                return true;
            }
            if let Some(peer) = peers.get_mut(&pending.peer) {
                peer.pending_objects = peer.pending_objects.saturating_sub(1);
                peer.pending_bytes = peer.pending_bytes.saturating_sub(u64::from(pending.size));
            }
            expired = expired.saturating_add(1);
            false
        });
        self.expired_validations = self.expired_validations.saturating_add(expired);
    }
}

impl SimulatedNetwork {
    pub fn add_node(&mut self, node: impl Into<String>) -> Result<(), NetworkError> {
        let node = node.into();
        if node.is_empty() || !self.nodes.insert(node.clone()) {
            return Err(NetworkError::InvalidSimulation);
        }
        self.objects.insert(node, BTreeSet::new());
        Ok(())
    }

    pub fn connect(&mut self, first: &str, second: &str) -> Result<(), NetworkError> {
        if first == second || !self.nodes.contains(first) || !self.nodes.contains(second) {
            return Err(NetworkError::InvalidSimulation);
        }
        self.links.insert(link(first, second));
        Ok(())
    }

    pub fn partition(&mut self, first: &[&str], second: &[&str]) -> Result<(), NetworkError> {
        if first.iter().any(|node| !self.nodes.contains(*node))
            || second.iter().any(|node| !self.nodes.contains(*node))
        {
            return Err(NetworkError::InvalidSimulation);
        }
        for left in first {
            for right in second {
                let edge = link(left, right);
                if self.links.contains(&edge) {
                    self.disabled_links.insert(edge);
                }
            }
        }
        Ok(())
    }

    pub fn heal_all(&mut self) {
        self.disabled_links.clear();
    }

    pub fn broadcast(&mut self, origin: &str, object_id: Hash256) -> Result<usize, NetworkError> {
        if !self.nodes.contains(origin) {
            return Err(NetworkError::InvalidSimulation);
        }
        let reachable = self.reachable(origin);
        for node in &reachable {
            self.objects.get_mut(node).unwrap().insert(object_id);
        }
        Ok(reachable.len())
    }

    pub fn reconcile(&mut self) {
        let nodes: Vec<_> = self.nodes.iter().cloned().collect();
        for node in nodes {
            let objects: Vec<_> = self.objects[&node].iter().copied().collect();
            for object in objects {
                let _ = self.broadcast(&node, object);
            }
        }
    }

    pub fn objects(&self, node: &str) -> Option<&BTreeSet<Hash256>> {
        self.objects.get(node)
    }

    fn reachable(&self, origin: &str) -> BTreeSet<String> {
        let mut found = BTreeSet::from([origin.to_owned()]);
        let mut queue = VecDeque::from([origin.to_owned()]);
        while let Some(node) = queue.pop_front() {
            for edge in &self.links {
                if self.disabled_links.contains(edge) {
                    continue;
                }
                let neighbor = if edge.0 == node {
                    Some(&edge.1)
                } else if edge.1 == node {
                    Some(&edge.0)
                } else {
                    None
                };
                if let Some(neighbor) = neighbor
                    && found.insert(neighbor.clone())
                {
                    queue.push_back(neighbor.clone());
                }
            }
        }
        found
    }
}

pub fn default_overlay_limits() -> (OverlayLimits, BTreeMap<GossipTopic, TopicLimit>) {
    let limits = OverlayLimits {
        rate_window_ms: 1_000,
        maximum_tracked_peers: 4_096,
        peer_inactivity_timeout_ms: 5 * 60 * 1_000,
        maximum_pending_objects_per_peer: 64,
        maximum_pending_bytes_per_peer: 8 * 1024 * 1024,
        pending_validation_timeout_ms: 60_000,
        maximum_seen_objects: 100_000,
        maximum_orphan_shares: 1_024,
        maximum_retained_events: 65_536,
        maximum_parent_fetch_depth: 32,
        body_download_bytes_per_window: 16 * 1024 * 1024,
        invalid_object_penalty: 10,
        disconnect_score: -100,
    };
    let mut topics = BTreeMap::new();
    for topic in [
        GossipTopic::Parent,
        GossipTopic::Operator,
        GossipTopic::BodyDescriptor,
        GossipTopic::MaskSession,
        GossipTopic::Share,
        GossipTopic::ReceiptBatch,
        GossipTopic::SessionClose,
        GossipTopic::MaskOpening,
        GossipTopic::PayoutSnapshot,
        GossipTopic::PayoutPlan,
        GossipTopic::FaultProof,
    ] {
        topics.insert(
            topic,
            TopicLimit {
                maximum_object_bytes: if topic == GossipTopic::Share {
                    16 * 1024
                } else {
                    1024 * 1024
                },
                messages_per_window: if topic == GossipTopic::Share {
                    1_000
                } else {
                    100
                },
            },
        );
    }
    (limits, topics)
}

fn link(first: &str, second: &str) -> (String, String) {
    if first <= second {
        (first.to_owned(), second.to_owned())
    } else {
        (second.to_owned(), first.to_owned())
    }
}

fn authentication(error: CryptoError) -> NetworkError {
    NetworkError::Authentication(error.to_string())
}

fn push_bounded_event(
    events: &mut Vec<OverlayEvent>,
    dropped_events: &mut u64,
    maximum: usize,
    event: OverlayEvent,
) {
    if maximum == 0 {
        *dropped_events = dropped_events.saturating_add(1);
        return;
    }
    if events.len() >= maximum {
        // Batch compaction keeps event insertion amortized O(1) while the
        // public slice remains chronological and allocation stays bounded.
        let discard = maximum.div_ceil(2).min(events.len());
        events.drain(..discard);
        *dropped_events = dropped_events.saturating_add(u64::try_from(discard).unwrap_or(u64::MAX));
    }
    events.push(event);
}

pub fn simulation_object_id(label: &str) -> Hash256 {
    domain_hash("meshmine/simulation-object/v2", label.as_bytes())
}

#[cfg(test)]
mod tests;
