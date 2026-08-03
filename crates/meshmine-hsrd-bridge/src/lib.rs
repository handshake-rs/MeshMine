//! Exact in-process binding between a committed `hsrd` mining snapshot and a
//! MeshMine gateway job. This boundary does not sign or certify objects; it
//! removes caller-selected mining fields before the existing authenticated
//! gateway authorization path persists and serves the assignment.

#![forbid(unsafe_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use hns_consensus::block_weight;
use hns_mining::{
    MiningJobId, MiningSnapshot, MiningSubscriptions, PreparedMiningJob, SolvedMiningCandidate,
};
use hns_node::NodeService;
use hns_primitives::{Block, Header, NONCE_SIZE};
use meshmine_fast_path::{BlockPublicationIntentV1, PublicationError};
use meshmine_gateway::{
    AuthorizedGatewayJobRequest, Gateway, GatewayError, GatewayJob, PreviousJobTransition,
    gateway_assignment_job_id, handy_target_from_difficulty,
};
use meshmine_handoff::GatewayContextManifestV1;
use meshmine_storage::{DurableStore, StorageError};
use meshmine_types::{
    BlockBodyPackageV2, BodyAvailabilityCertificateV2, BodyErasureDescriptorV2,
    GatewayAssignmentV1, MaskSessionV2, UnsignedObject,
};
use thiserror::Error;

pub const HSRD_ASSIGNMENT_BINDING_NAMESPACE: &str = "hsrd-assignment-binding/v1";
const HSRD_ASSIGNMENT_BINDING_MAGIC: [u8; 4] = *b"MMHB";
const HSRD_ASSIGNMENT_BINDING_VERSION: u16 = 1;
const HSRD_ASSIGNMENT_BINDING_BYTES: usize = 179;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HsrdBoundGatewayJob {
    network_id: u8,
    mining_generation: u64,
    hsrd_job_id: MiningJobId,
    assignment_id: [u8; 32],
    session_id: [u8; 32],
    body_package_id: [u8; 32],
    parent_hash: [u8; 32],
    parent_height: u32,
    gateway_job: GatewayJob,
}

impl HsrdBoundGatewayJob {
    pub const fn network_id(&self) -> u8 {
        self.network_id
    }

    pub const fn mining_generation(&self) -> u64 {
        self.mining_generation
    }

    pub const fn hsrd_job_id(&self) -> MiningJobId {
        self.hsrd_job_id
    }

    pub const fn assignment_id(&self) -> [u8; 32] {
        self.assignment_id
    }

    pub const fn parent_hash(&self) -> [u8; 32] {
        self.parent_hash
    }

    pub const fn parent_height(&self) -> u32 {
        self.parent_height
    }

    pub const fn gateway_job(&self) -> &GatewayJob {
        &self.gateway_job
    }

    pub fn into_gateway_job(self) -> GatewayJob {
        self.gateway_job
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableHsrdAssignmentBindingV1 {
    pub network_id: u8,
    pub mining_generation: u64,
    pub hsrd_job_id: MiningJobId,
    pub assignment_id: [u8; 32],
    pub session_id: [u8; 32],
    pub body_package_id: [u8; 32],
    pub parent_hash: [u8; 32],
    pub parent_height: u32,
}

impl DurableHsrdAssignmentBindingV1 {
    pub fn from_bound(bound: &HsrdBoundGatewayJob) -> Self {
        Self {
            network_id: bound.network_id,
            mining_generation: bound.mining_generation,
            hsrd_job_id: bound.hsrd_job_id,
            assignment_id: bound.assignment_id,
            session_id: bound.session_id,
            body_package_id: bound.body_package_id,
            parent_hash: bound.parent_hash,
            parent_height: bound.parent_height,
        }
    }

    fn validate(&self) -> Result<(), HsrdBridgeError> {
        if self.mining_generation == 0
            || self.hsrd_job_id == [0; 32]
            || self.assignment_id == [0; 32]
            || self.session_id == [0; 32]
            || self.body_package_id == [0; 32]
            || self.parent_hash == [0; 32]
        {
            return Err(HsrdBridgeError::DurableBinding);
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HSRD_ASSIGNMENT_BINDING_BYTES);
        bytes.extend_from_slice(&HSRD_ASSIGNMENT_BINDING_MAGIC);
        bytes.extend_from_slice(&HSRD_ASSIGNMENT_BINDING_VERSION.to_le_bytes());
        bytes.push(self.network_id);
        bytes.extend_from_slice(&self.mining_generation.to_le_bytes());
        bytes.extend_from_slice(&self.hsrd_job_id);
        bytes.extend_from_slice(&self.assignment_id);
        bytes.extend_from_slice(&self.session_id);
        bytes.extend_from_slice(&self.body_package_id);
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.parent_height.to_le_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, HsrdBridgeError> {
        if bytes.len() != HSRD_ASSIGNMENT_BINDING_BYTES
            || bytes[..4] != HSRD_ASSIGNMENT_BINDING_MAGIC
            || u16::from_le_bytes(bytes[4..6].try_into().expect("checked fixed slice"))
                != HSRD_ASSIGNMENT_BINDING_VERSION
        {
            return Err(HsrdBridgeError::DurableBinding);
        }
        let binding = Self {
            network_id: bytes[6],
            mining_generation: u64::from_le_bytes(
                bytes[7..15].try_into().expect("checked fixed slice"),
            ),
            hsrd_job_id: bytes[15..47].try_into().expect("checked fixed slice"),
            assignment_id: bytes[47..79].try_into().expect("checked fixed slice"),
            session_id: bytes[79..111].try_into().expect("checked fixed slice"),
            body_package_id: bytes[111..143].try_into().expect("checked fixed slice"),
            parent_hash: bytes[143..175].try_into().expect("checked fixed slice"),
            parent_height: u32::from_le_bytes(
                bytes[175..179].try_into().expect("checked fixed slice"),
            ),
        };
        binding.validate()?;
        Ok(binding)
    }
}

pub fn persist_bound_gateway_job(
    store: &dyn DurableStore,
    bound: &HsrdBoundGatewayJob,
) -> Result<DurableHsrdAssignmentBindingV1, HsrdBridgeError> {
    let binding = DurableHsrdAssignmentBindingV1::from_bound(bound);
    binding.validate()?;
    let key = hex::encode(binding.assignment_id);
    let encoded = binding.encode();

    match store.get(HSRD_ASSIGNMENT_BINDING_NAMESPACE, &key)? {
        Some(existing) if existing == encoded => Ok(binding),
        Some(_) => Err(HsrdBridgeError::DurableBindingConflict),
        None => {
            if store.compare_and_swap(HSRD_ASSIGNMENT_BINDING_NAMESPACE, &key, None, &encoded)? {
                return Ok(binding);
            }
            match store.get(HSRD_ASSIGNMENT_BINDING_NAMESPACE, &key)? {
                Some(existing) if existing == encoded => Ok(binding),
                _ => Err(HsrdBridgeError::DurableBindingConflict),
            }
        }
    }
}

pub fn load_bound_gateway_job(
    store: &dyn DurableStore,
    assignment_id: [u8; 32],
) -> Result<DurableHsrdAssignmentBindingV1, HsrdBridgeError> {
    let key = hex::encode(assignment_id);
    let bytes = store
        .get(HSRD_ASSIGNMENT_BINDING_NAMESPACE, &key)?
        .ok_or(HsrdBridgeError::DurableBindingMissing)?;
    let binding = DurableHsrdAssignmentBindingV1::decode(&bytes)?;
    if binding.assignment_id != assignment_id {
        return Err(HsrdBridgeError::DurableBinding);
    }
    Ok(binding)
}

pub fn verify_persisted_bound_gateway_job(
    store: &dyn DurableStore,
    bound: &HsrdBoundGatewayJob,
) -> Result<(), HsrdBridgeError> {
    let expected = DurableHsrdAssignmentBindingV1::from_bound(bound);
    let actual = load_bound_gateway_job(store, bound.assignment_id)?;
    if actual != expected {
        return Err(HsrdBridgeError::DurableBindingConflict);
    }
    Ok(())
}

pub struct HsrdOpenedSolutionRequest<'a> {
    pub store: &'a dyn DurableStore,
    pub bound: &'a HsrdBoundGatewayJob,
    pub snapshot: &'a MiningSnapshot,
    pub prepared_job: &'a PreparedMiningJob,
    pub assignment: &'a GatewayAssignmentV1,
    pub nonce: u32,
    pub time: u64,
    pub extra_nonce: [u8; NONCE_SIZE],
    pub mask: [u8; 32],
}

pub fn admit_persisted_opened_solution(
    request: HsrdOpenedSolutionRequest<'_>,
) -> Result<SolvedMiningCandidate, HsrdBridgeError> {
    let HsrdOpenedSolutionRequest {
        store,
        bound,
        snapshot,
        prepared_job,
        assignment,
        nonce,
        time,
        extra_nonce,
        mask,
    } = request;
    verify_persisted_bound_gateway_job(store, bound)?;
    if bound.assignment_id != assignment.object_id()
        || bound.network_id != snapshot.network_id
        || bound.mining_generation != snapshot.generation
        || bound.hsrd_job_id != prepared_job.job_id()
        || bound.session_id != assignment.session_id
        || bound.body_package_id != assignment.body_package_id
        || bound.parent_hash != *snapshot.tip.hash.as_bytes()
        || bound.parent_height != snapshot.tip.height
        || bound.gateway_job.id != gateway_assignment_job_id(assignment)
    {
        return Err(HsrdBridgeError::DurableBindingConflict);
    }
    prepared_job
        .admit_solution(snapshot, nonce, time, extra_nonce, mask)
        .map_err(|_| HsrdBridgeError::Candidate)
}

pub fn publication_intent_for_persisted_candidate(
    store: &dyn DurableStore,
    bound: &HsrdBoundGatewayJob,
    authoritative_snapshot: &MiningSnapshot,
    candidate: &SolvedMiningCandidate,
    winner_share_id: [u8; 32],
    target_ids: Vec<String>,
) -> Result<BlockPublicationIntentV1, HsrdBridgeError> {
    verify_persisted_bound_gateway_job(store, bound)?;
    if authoritative_snapshot.network_id != bound.network_id
        || authoritative_snapshot.generation != bound.mining_generation
        || authoritative_snapshot.tip.hash.as_bytes() != &bound.parent_hash
        || authoritative_snapshot.tip.height != bound.parent_height
    {
        return Err(HsrdBridgeError::StaleAuthority);
    }
    if winner_share_id == [0; 32]
        || candidate.job_id() != bound.hsrd_job_id
        || candidate.snapshot_generation() != bound.mining_generation
        || candidate.parent_height() != bound.parent_height
        || candidate.block().header.prev_block.as_bytes() != &bound.parent_hash
        || !candidate.block().header.verify_pow()
    {
        return Err(HsrdBridgeError::Candidate);
    }
    let block_hash = *candidate.block().hash().as_bytes();
    BlockPublicationIntentV1::new(
        bound.network_id,
        winner_share_id,
        block_hash,
        candidate.block().encode(),
        target_ids,
    )
    .map_err(HsrdBridgeError::Publication)
}

/// Complete the only supported native-template activation transaction.
///
/// The generation/job binding is persisted in the gateway's own durable store
/// before the gateway's atomic assignment activation, so a process interruption
/// is recovered by replaying this exact request. The bridge never creates or
/// signs operator/committee authority objects.
pub struct HsrdGatewayActivationRequest<'a> {
    pub prepared_job: &'a PreparedMiningJob,
    pub manifest: &'a GatewayContextManifestV1,
    pub assignment: &'a GatewayAssignmentV1,
    pub session: &'a MaskSessionV2,
    pub body: &'a BlockBodyPackageV2,
    pub descriptor: &'a BodyErasureDescriptorV2,
    pub body_certificate: &'a BodyAvailabilityCertificateV2,
    pub advertised_difficulty: u32,
    pub transition: Option<PreviousJobTransition>,
}

fn activate_gateway_job(
    gateway: &mut Gateway,
    snapshot: &MiningSnapshot,
    request: HsrdGatewayActivationRequest<'_>,
) -> Result<HsrdBoundGatewayJob, HsrdBridgeError> {
    let HsrdGatewayActivationRequest {
        prepared_job,
        manifest,
        assignment,
        session,
        body,
        descriptor,
        body_certificate,
        advertised_difficulty,
        transition,
    } = request;
    let store = gateway.durable_store();
    let bound = bind_gateway_job(HsrdGatewayJobRequest {
        snapshot,
        prepared_job,
        assignment,
        session,
        body,
        advertised_difficulty,
    })?;
    persist_bound_gateway_job(store.as_ref(), &bound)?;
    let sequence = gateway.issue_authorized_job(AuthorizedGatewayJobRequest {
        manifest,
        assignment,
        session,
        body,
        descriptor,
        body_certificate,
        job: bound.gateway_job.clone(),
        transition,
    })?;
    let current = gateway
        .current_job()
        .ok_or(HsrdBridgeError::ActivationInvariant)?;
    if sequence != assignment.assignment_sequence
        || current.assignment_sequence != sequence
        || current.id != bound.gateway_job.id
        || current.previous_block != bound.parent_hash
    {
        return Err(HsrdBridgeError::ActivationInvariant);
    }
    verify_persisted_bound_gateway_job(store.as_ref(), &bound)?;
    Ok(bound)
}

/// An `hsrd` mining stream which can only be constructed through the node's
/// authority-permit boundary. The staged/observed subscription API cannot
/// construct this type.
#[derive(Debug)]
pub struct AuthoritativeHsrdMiningStream {
    subscriptions: MiningSubscriptions,
    initial_pending: bool,
}

impl AuthoritativeHsrdMiningStream {
    pub fn subscribe(node: &NodeService) -> Result<Self, HsrdBridgeError> {
        let subscriptions = node
            .subscribe_mining_events()
            .map_err(|error| HsrdBridgeError::AuthoritySubscription(error.to_string()))?;
        Ok(Self {
            subscriptions,
            initial_pending: true,
        })
    }

    /// Activate an exact prepared job against the latest authoritative
    /// snapshot. A concurrent tip change is reconciled before this method
    /// returns; subsequent changes are consumed with `reconcile_next`.
    pub fn activate(
        &mut self,
        gateway: &mut Gateway,
        request: HsrdGatewayActivationRequest<'_>,
    ) -> Result<HsrdBoundGatewayJob, HsrdBridgeError> {
        let snapshot = self
            .subscriptions
            .latest_snapshot
            .borrow_and_update()
            .clone()
            .ok_or(HsrdBridgeError::AuthorityUnavailable)?;
        self.initial_pending = false;
        let bound = activate_gateway_job(gateway, snapshot.as_ref(), request)?;

        match self.subscriptions.latest_snapshot.has_changed() {
            Ok(false) => Ok(bound),
            Ok(true) => {
                let latest = self
                    .subscriptions
                    .latest_snapshot
                    .borrow_and_update()
                    .clone();
                let outcome = reconcile_authoritative_tip(
                    gateway,
                    latest.as_deref(),
                    current_unix_time_ms()?,
                )?;
                if matches!(
                    outcome,
                    HsrdGatewayTipReconciliation::Current {
                        assignment_id,
                        mining_generation,
                    } if assignment_id == bound.assignment_id
                        && mining_generation == bound.mining_generation
                ) {
                    Ok(bound)
                } else {
                    Err(HsrdBridgeError::StaleAuthority)
                }
            }
            Err(_) => {
                reconcile_authoritative_tip(gateway, None, current_unix_time_ms()?)?;
                Err(HsrdBridgeError::AuthorityStreamClosed)
            }
        }
    }

    /// Reconcile the current gateway head immediately, including the initial
    /// watch value and restart-recovered gateway state.
    pub fn reconcile_current_at(
        &mut self,
        gateway: &mut Gateway,
        observed_at_ms: u64,
    ) -> Result<HsrdGatewayTipReconciliation, HsrdBridgeError> {
        let snapshot = self
            .subscriptions
            .latest_snapshot
            .borrow_and_update()
            .clone();
        self.initial_pending = false;
        reconcile_authoritative_tip(gateway, snapshot.as_deref(), observed_at_ms)
    }

    /// Wait for the next authoritative tip update and immediately retire any
    /// now-stale ASIC job. The watch channel provides the latest value even if
    /// the diagnostic broadcast stream lagged.
    pub async fn reconcile_next(
        &mut self,
        gateway: &mut Gateway,
    ) -> Result<HsrdGatewayTipReconciliation, HsrdBridgeError> {
        if self.initial_pending {
            return self.reconcile_current_at(gateway, current_unix_time_ms()?);
        }
        if self.subscriptions.latest_snapshot.changed().await.is_err() {
            reconcile_authoritative_tip(gateway, None, current_unix_time_ms()?)?;
            return Err(HsrdBridgeError::AuthorityStreamClosed);
        }
        self.reconcile_current_at(gateway, current_unix_time_ms()?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HsrdGatewayTipReconciliation {
    Idle,
    Current {
        assignment_id: [u8; 32],
        mining_generation: u64,
    },
    Retired {
        assignment_id: [u8; 32],
        mining_generation: u64,
        credit_cutoff_ms: u64,
    },
}

/// Reconcile the durable gateway head against the latest snapshot from
/// `NodeService::subscribe_mining_events`, including after process restart.
/// Passing `None` represents loss of authoritative mining state and retires
/// any active ASIC job. Diagnostic/observed snapshots must never be supplied.
fn reconcile_authoritative_tip(
    gateway: &mut Gateway,
    authoritative_snapshot: Option<&MiningSnapshot>,
    observed_at_ms: u64,
) -> Result<HsrdGatewayTipReconciliation, HsrdBridgeError> {
    let store = gateway.durable_store();
    gateway.close_expired(observed_at_ms)?;
    let Some(job) = gateway.current_job().cloned() else {
        return Ok(HsrdGatewayTipReconciliation::Idle);
    };
    let assignment_id = assignment_id_from_gateway_job(&job)?;
    let binding = load_bound_gateway_job(store.as_ref(), assignment_id)?;
    if binding.parent_hash != job.previous_block || job.assignment_sequence == 0 {
        return Err(HsrdBridgeError::ActivationInvariant);
    }

    let current = authoritative_snapshot.is_some_and(|snapshot| {
        snapshot.network_id == binding.network_id
            && snapshot.generation == binding.mining_generation
            && snapshot.tip.hash.as_bytes() == &binding.parent_hash
            && snapshot.tip.height == binding.parent_height
    });
    if current {
        return Ok(HsrdGatewayTipReconciliation::Current {
            assignment_id,
            mining_generation: binding.mining_generation,
        });
    }

    let credit_cutoff_ms = observed_at_ms.max(job.issued_ms).min(job.submission_end_ms);
    gateway.cancel_job(&job.id, credit_cutoff_ms, job.submission_end_ms)?;
    Ok(HsrdGatewayTipReconciliation::Retired {
        assignment_id,
        mining_generation: binding.mining_generation,
        credit_cutoff_ms,
    })
}

fn current_unix_time_ms() -> Result<u64, HsrdBridgeError> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HsrdBridgeError::Clock)?
        .as_millis();
    u64::try_from(milliseconds).map_err(|_| HsrdBridgeError::Clock)
}

fn assignment_id_from_gateway_job(job: &GatewayJob) -> Result<[u8; 32], HsrdBridgeError> {
    if job.id.len() != 64 || !job.id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HsrdBridgeError::ActivationInvariant);
    }
    let bytes = hex::decode(&job.id).map_err(|_| HsrdBridgeError::ActivationInvariant)?;
    let assignment_id = bytes
        .try_into()
        .map_err(|_| HsrdBridgeError::ActivationInvariant)?;
    if hex::encode(assignment_id) != job.id {
        return Err(HsrdBridgeError::ActivationInvariant);
    }
    Ok(assignment_id)
}

pub struct HsrdGatewayJobRequest<'a> {
    pub snapshot: &'a MiningSnapshot,
    pub prepared_job: &'a PreparedMiningJob,
    pub assignment: &'a GatewayAssignmentV1,
    pub session: &'a MaskSessionV2,
    pub body: &'a BlockBodyPackageV2,
    pub advertised_difficulty: u32,
}

pub fn bind_gateway_job(
    request: HsrdGatewayJobRequest<'_>,
) -> Result<HsrdBoundGatewayJob, HsrdBridgeError> {
    let HsrdGatewayJobRequest {
        snapshot,
        prepared_job,
        assignment,
        session,
        body,
        advertised_difficulty,
    } = request;
    prepared_job
        .validate_for_snapshot(snapshot)
        .map_err(|_| HsrdBridgeError::PreparedJob)?;

    let template = &body.template_core;
    let header = prepared_job.header();
    let parent_hash = *snapshot.tip.hash.as_bytes();
    let ntime = u32::try_from(assignment.ntime).map_err(|_| HsrdBridgeError::TimeRange)?;
    let advertised_device_target = handy_target_from_difficulty(advertised_difficulty)?;

    if snapshot.network_id != assignment.network_id
        || snapshot.network_id != session.network_id
        || snapshot.network_id != body.network_id
        || snapshot.network_id != template.network_id
        || snapshot.tip.hash.as_bytes() != &session.parent_hash
        || parent_hash != template.hns_parent_hash
        || snapshot.tip.height != template.hns_parent_height
        || assignment.session_id != session.object_id()
        || assignment.body_package_id != body.object_id()
        || header.parent_hash.as_bytes() != &parent_hash
        || header.tree_root != body.tree_root
        || header.reserved_root != body.reserved_root
        || header.witness_root != body.witness_root
        || header.merkle_root != body.merkle_root
        || header.version != template.block_version
        || header.bits != template.bits
        || header.minimum_time != template.minimum_ntime
        || assignment.ntime < header.minimum_time
        || header.mask_hash != session.mask_hash
        || session.capture_target != assignment.capture_target
        || assignment.edge_target.0 != advertised_device_target
    {
        return Err(HsrdBridgeError::Context);
    }

    validate_exact_transactions(prepared_job, body)?;
    let provisional = Block {
        header: Header {
            time: header.minimum_time,
            prev_block: header.parent_hash,
            tree_root: header.tree_root,
            reserved_root: header.reserved_root,
            witness_root: header.witness_root,
            merkle_root: header.merkle_root,
            version: header.version,
            bits: header.bits,
            ..Header::default()
        },
        transactions: prepared_job.transactions().to_vec(),
    };
    let exact_weight =
        u32::try_from(block_weight(&provisional)).map_err(|_| HsrdBridgeError::BlockWeight)?;
    if body.block_weight != exact_weight {
        return Err(HsrdBridgeError::BlockWeight);
    }

    Ok(HsrdBoundGatewayJob {
        network_id: snapshot.network_id,
        mining_generation: snapshot.generation,
        hsrd_job_id: prepared_job.job_id(),
        assignment_id: assignment.object_id(),
        session_id: assignment.session_id,
        body_package_id: assignment.body_package_id,
        parent_hash,
        parent_height: snapshot.tip.height,
        gateway_job: GatewayJob {
            id: gateway_assignment_job_id(assignment),
            assignment_sequence: 0,
            previous_block: parent_hash,
            merkle_root: header.merkle_root,
            witness_root: header.witness_root,
            tree_root: header.tree_root,
            reserved_root: header.reserved_root,
            version: header.version,
            bits: header.bits,
            ntime,
            mask_hash: header.mask_hash,
            leading_zero_prefix_q: session.leading_zero_prefix_q,
            blind_band_bits_d: session.blind_band_bits_d,
            capture_target: session.capture_target.0,
            advertised_device_target,
            advertised_difficulty,
            issued_ms: session.assignment_start_ms,
            assignment_end_ms: session.assignment_end_ms,
            submission_end_ms: session.submission_end_ms,
            transaction_hashes: template.ordered_non_coinbase_txids.clone(),
        },
    })
}

fn validate_exact_transactions(
    prepared_job: &PreparedMiningJob,
    body: &BlockBodyPackageV2,
) -> Result<(), HsrdBridgeError> {
    let transactions = prepared_job.transactions();
    let Some(coinbase) = transactions.first() else {
        return Err(HsrdBridgeError::Transactions);
    };
    if coinbase.encode() != body.coinbase_raw
        || transactions.len() != body.transactions_raw.len().saturating_add(1)
        || transactions[1..]
            .iter()
            .zip(&body.transactions_raw)
            .any(|(transaction, raw)| transaction.encode() != *raw)
    {
        return Err(HsrdBridgeError::Transactions);
    }
    let txids = transactions[1..]
        .iter()
        .map(|transaction| *transaction.txid().as_bytes())
        .collect::<Vec<_>>();
    if txids != body.template_core.ordered_non_coinbase_txids {
        return Err(HsrdBridgeError::Transactions);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum HsrdBridgeError {
    #[error("prepared hsrd job is stale or not bound to the supplied snapshot")]
    PreparedJob,
    #[error("hsrd snapshot, MeshMine session, body, and assignment context disagree")]
    Context,
    #[error("assignment nTime is outside the gateway's u32 protocol range")]
    TimeRange,
    #[error("prepared hsrd transactions do not exactly match the certified body")]
    Transactions,
    #[error("prepared hsrd block weight does not match the certified body")]
    BlockWeight,
    #[error("gateway target profile is invalid: {0}")]
    Gateway(#[from] GatewayError),
    #[error("durable hsrd assignment binding is malformed")]
    DurableBinding,
    #[error("durable hsrd assignment binding is missing")]
    DurableBindingMissing,
    #[error("assignment ID is already bound to a different hsrd generation or job")]
    DurableBindingConflict,
    #[error("durable hsrd assignment binding storage failed: {0}")]
    Storage(#[from] StorageError),
    #[error("gateway activation disagrees with its durable hsrd binding")]
    ActivationInvariant,
    #[error("solved candidate is stale for the current authoritative hsrd tip")]
    StaleAuthority,
    #[error("authoritative hsrd mining subscription is unavailable: {0}")]
    AuthoritySubscription(String),
    #[error("authoritative hsrd mining state is unavailable")]
    AuthorityUnavailable,
    #[error("authoritative hsrd mining event stream closed")]
    AuthorityStreamClosed,
    #[error("system clock cannot represent a gateway timestamp")]
    Clock,
    #[error("opened gateway result is not a valid generation-bound hsrd block candidate")]
    Candidate,
    #[error("candidate publication intent is invalid: {0}")]
    Publication(#[from] PublicationError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use hns_consensus::{Network, block_merkle_root, block_weight, block_witness_root};
    use hns_mining::{HeaderSummary, MiningEventHub, MiningHeaderTemplate};
    use hns_primitives::{
        Address, BlockHash, Covenant, CovenantKind, Input, Outpoint, Output, Transaction, Txid,
        Witness, blake2b_256_many,
    };
    use meshmine_crypto::sign_object;
    use meshmine_gateway::{Gateway, TelemetryLevel, handy_target_from_difficulty};
    use meshmine_hns::derive_capture_parameters;
    use meshmine_storage::{DurableStore, MemoryStore};
    use meshmine_types::{
        CORE_V2, GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16, GATEWAY_HANDOFF_V1,
        GATEWAY_OBSERVATION_CORE_RECEIPT_TIME, SignatureBytes, SignatureSet, TemplateCoreV2, U256,
    };

    struct Fixture {
        snapshot: MiningSnapshot,
        prepared: PreparedMiningJob,
        manifest: GatewayContextManifestV1,
        assignment: GatewayAssignmentV1,
        session: MaskSessionV2,
        body: BlockBodyPackageV2,
        descriptor: BodyErasureDescriptorV2,
        body_certificate: BodyAvailabilityCertificateV2,
    }

    fn fixture() -> Fixture {
        fixture_with_target(0x2000_ffff, 7)
    }

    fn gateway_fixture() -> Fixture {
        fixture_with_target(0x1c00_ffff, 7)
    }

    fn fixture_with_target(bits: u32, blind_band_bits_d: u16) -> Fixture {
        let network_id = Network::Regtest.canonical_id();
        let operator = SigningKey::from_bytes(&[41; 32]);
        let operator_pubkey = operator.verifying_key().to_bytes();
        let gateway_pubkey = SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes();
        let core_handoff_pubkey = SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes();
        let mut manifest = GatewayContextManifestV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id,
            context_sequence: 1,
            previous_manifest_id: [0; 32],
            operator_pubkey,
            gateway_pubkey,
            core_handoff_pubkey,
            valid_from_ms: 1,
            valid_until_ms: 10_000,
            maximum_frame_bytes: 64 * 1024,
            maximum_in_flight: 32,
            operator_signature: SignatureBytes::empty(),
        };
        manifest.operator_signature = sign_object(&operator, network_id, &manifest);
        let parent_hash = [1; 32];
        let snapshot = MiningSnapshot {
            network_id,
            generation: 7,
            tip: HeaderSummary {
                hash: BlockHash::new(parent_hash),
                parent_hash: BlockHash::new([2; 32]),
                height: 99,
                tree_root: [3; 32],
                time: 100,
                bits: 0x2000_ffff,
            },
            next_tree_root: [5; 32],
            parent_median_time: 99,
            chainwork: 1_000u64.into(),
        };
        let coinbase = Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::ZERO,
                    index: u32::MAX,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: 50,
                address: Address::new(0, vec![4; 20]).unwrap(),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        };
        let transactions = Arc::<[Transaction]>::from(vec![coinbase]);
        let root_subject = Block {
            header: Header::default(),
            transactions: transactions.to_vec(),
        };
        let merkle_root = block_merkle_root(&root_subject);
        let witness_root = block_witness_root(&root_subject);
        let mask = [9; 32];
        let mask_hash = blake2b_256_many([parent_hash.as_slice(), mask.as_slice()]);
        let header = MiningHeaderTemplate {
            parent_hash: snapshot.tip.hash,
            tree_root: snapshot.next_tree_root,
            reserved_root: [6; 32],
            witness_root,
            merkle_root,
            version: 1,
            bits,
            minimum_time: 101,
            mask_hash,
        };
        let prepared = PreparedMiningJob::new(&snapshot, header.clone(), transactions).unwrap();
        let template_core = TemplateCoreV2 {
            protocol_version: CORE_V2,
            network_id,
            hns_parent_hash: parent_hash,
            hns_parent_height: snapshot.tip.height,
            operator_pubkey,
            operator_fee_bucket_id: [11; 32],
            payout_snapshot_id: [12; 32],
            payout_plan_id: [13; 32],
            plan_sequence: 1,
            ordered_non_coinbase_txids: Vec::new(),
            ordered_claim_ids: Vec::new(),
            ordered_airdrop_ids: Vec::new(),
            block_version: header.version,
            bits: header.bits,
            minimum_ntime: header.minimum_time,
            policy_commitment: [14; 32],
        };
        let template_core_id = template_core.object_id();
        let weight_subject = Block {
            header: Header {
                time: header.minimum_time,
                prev_block: header.parent_hash,
                tree_root: header.tree_root,
                reserved_root: header.reserved_root,
                witness_root: header.witness_root,
                merkle_root: header.merkle_root,
                version: header.version,
                bits: header.bits,
                ..Header::default()
            },
            transactions: prepared.transactions().to_vec(),
        };
        let mut body = BlockBodyPackageV2 {
            protocol_version: CORE_V2,
            network_id,
            template_core,
            template_core_id,
            coinbase_raw: prepared.transactions()[0].encode(),
            transactions_raw: Vec::new(),
            merkle_root,
            witness_root,
            tree_root: header.tree_root,
            reserved_root: header.reserved_root,
            block_weight: u32::try_from(block_weight(&weight_subject)).unwrap(),
            block_sigops: 0,
            miner_subsidy: 50,
            ordinary_transaction_fees: 0,
            claim_airdrop_principal: 0,
            claim_airdrop_fees: 0,
            operator_fee_value: 0,
            work_service_subsidy_value: 50,
            consensus_validation_result_hash: [15; 32],
            operator_signature: SignatureBytes::empty(),
        };
        body.operator_signature = sign_object(&operator, network_id, &body);
        let descriptor = BodyErasureDescriptorV2 {
            protocol_version: CORE_V2,
            network_id,
            body_package_id: body.object_id(),
            original_size: 1,
            data_shards: 1,
            parity_shards: 1,
            shard_size: 1,
            shard_merkle_root: [20; 32],
            expiry_height: 200,
            compression: 0,
        };
        let body_certificate = BodyAvailabilityCertificateV2 {
            protocol_version: CORE_V2,
            network_id,
            descriptor_id: descriptor.object_id(),
            parent_hash,
            parent_height: snapshot.tip.height,
            consensus_validation_result_hash: body.consensus_validation_result_hash,
            challenge_round: 1,
            challenge_transcript_root: [21; 32],
            signer_set: SignatureSet::empty_ed25519(),
        };
        let capture = derive_capture_parameters(header.bits, blind_band_bits_d).unwrap();
        let session = MaskSessionV2 {
            protocol_version: CORE_V2,
            network_id,
            lane_id: 1,
            session_sequence: 1,
            parent_certificate_id: [16; 32],
            parent_hash,
            hns_network_target: U256([17; 32]),
            capture_target: U256(capture.capture_target),
            accounting_target: U256(capture.capture_target),
            leading_zero_prefix_q: capture.leading_zero_prefix_q,
            blind_band_bits_d,
            mask_hash,
            mask_commitment_root: [18; 32],
            mask_committee_id: [19; 32],
            fast_eval_policy: 1,
            assignment_start_ms: 1_000,
            assignment_end_ms: 2_000,
            submission_end_ms: 2_500,
            timed_open_after_ms: 3_000,
            previous_session_id: [0; 32],
            signer_set: SignatureSet::empty_ed25519(),
        };
        let mut assignment = GatewayAssignmentV1 {
            core_protocol_version: CORE_V2,
            handoff_version: GATEWAY_HANDOFF_V1,
            network_id,
            session_id: session.object_id(),
            body_package_id: body.object_id(),
            body_certificate_id: body_certificate.object_id(),
            operator_pubkey,
            gateway_pubkey,
            core_handoff_pubkey,
            worker_id_hash: [23; 32],
            payout_bucket_id: [24; 32],
            assignment_sequence: 1,
            ntime: header.minimum_time,
            extra_nonce_profile: GATEWAY_EXTRA_NONCE_PROFILE_HANDY_PREFIX4_VARIABLE4_ZERO16,
            observation_policy: GATEWAY_OBSERVATION_CORE_RECEIPT_TIME,
            maximum_clock_skew_ms: 0,
            extra_nonce_prefix: [0, 0, 0, 1],
            extra_nonce2_start_be: 0u32.to_be_bytes(),
            extra_nonce2_end_be: u32::MAX.to_be_bytes(),
            nonce_start: 0,
            nonce_end: u32::MAX,
            nonce_stride: 1,
            edge_target: U256(handy_target_from_difficulty(1).unwrap()),
            capture_target: session.capture_target,
            telemetry_level: TelemetryLevel::StockAsic as u8,
            operator_signature: SignatureBytes::empty(),
        };
        assignment.operator_signature = sign_object(&operator, network_id, &assignment);
        Fixture {
            snapshot,
            prepared,
            manifest,
            assignment,
            session,
            body,
            descriptor,
            body_certificate,
        }
    }

    fn bind(fixture: &Fixture) -> Result<HsrdBoundGatewayJob, HsrdBridgeError> {
        bind_gateway_job(HsrdGatewayJobRequest {
            snapshot: &fixture.snapshot,
            prepared_job: &fixture.prepared,
            assignment: &fixture.assignment,
            session: &fixture.session,
            body: &fixture.body,
            advertised_difficulty: 1,
        })
    }

    fn activate(
        fixture: &Fixture,
        stream: &mut AuthoritativeHsrdMiningStream,
        gateway: &mut Gateway,
    ) -> Result<HsrdBoundGatewayJob, HsrdBridgeError> {
        stream.activate(
            gateway,
            HsrdGatewayActivationRequest {
                prepared_job: &fixture.prepared,
                manifest: &fixture.manifest,
                assignment: &fixture.assignment,
                session: &fixture.session,
                body: &fixture.body,
                descriptor: &fixture.descriptor,
                body_certificate: &fixture.body_certificate,
                advertised_difficulty: 1,
                transition: None,
            },
        )
    }

    fn authoritative_stream(
        snapshot: &MiningSnapshot,
    ) -> (MiningEventHub, AuthoritativeHsrdMiningStream) {
        let hub = MiningEventHub::new(Some(Arc::new(snapshot.clone()))).unwrap();
        let stream = AuthoritativeHsrdMiningStream {
            subscriptions: hub.subscribe(),
            initial_pending: true,
        };
        (hub, stream)
    }

    #[test]
    fn exact_hsrd_snapshot_and_prepared_body_build_the_only_gateway_job() {
        let fixture = fixture();
        let bound = bind(&fixture).unwrap();
        assert_eq!(bound.network_id(), Network::Regtest.canonical_id());
        assert_eq!(bound.mining_generation(), 7);
        assert_eq!(bound.hsrd_job_id(), fixture.prepared.job_id());
        assert_eq!(
            bound.gateway_job().id,
            gateway_assignment_job_id(&fixture.assignment)
        );
        assert_eq!(
            bound.gateway_job().previous_block,
            fixture.session.parent_hash
        );
        assert_eq!(
            bound.gateway_job().transaction_hashes,
            Vec::<[u8; 32]>::new()
        );
    }

    #[test]
    fn stale_generation_or_cross_network_snapshot_is_rejected() {
        let mut stale = fixture();
        stale.snapshot.generation += 1;
        assert!(matches!(bind(&stale), Err(HsrdBridgeError::PreparedJob)));

        let mut cross_network = fixture();
        cross_network.snapshot.network_id = Network::Mainnet.canonical_id();
        assert!(matches!(
            bind(&cross_network),
            Err(HsrdBridgeError::PreparedJob)
        ));
    }

    #[test]
    fn certified_body_bytes_and_weight_must_exactly_match_hsrd() {
        let mut wrong_bytes = fixture();
        wrong_bytes.body.coinbase_raw.push(0);
        wrong_bytes.assignment.body_package_id = wrong_bytes.body.object_id();
        assert!(matches!(
            bind(&wrong_bytes),
            Err(HsrdBridgeError::Transactions)
        ));

        let mut wrong_weight = fixture();
        wrong_weight.body.block_weight += 1;
        wrong_weight.assignment.body_package_id = wrong_weight.body.object_id();
        assert!(matches!(
            bind(&wrong_weight),
            Err(HsrdBridgeError::BlockWeight)
        ));
    }

    #[test]
    fn exact_native_job_is_durably_bound_and_activated_idempotently() {
        let fixture = gateway_fixture();
        let store = Arc::new(MemoryStore::default());
        let mut gateway = Gateway::open_simulator(store.clone()).unwrap();
        let (_hub, mut stream) = authoritative_stream(&fixture.snapshot);

        let bound = activate(&fixture, &mut stream, &mut gateway).unwrap();
        assert_eq!(
            gateway.current_job().unwrap().id,
            gateway_assignment_job_id(&fixture.assignment)
        );
        assert_eq!(
            gateway.current_job().unwrap().assignment_sequence,
            fixture.assignment.assignment_sequence
        );
        verify_persisted_bound_gateway_job(store.as_ref(), &bound).unwrap();

        let replayed = activate(&fixture, &mut stream, &mut gateway).unwrap();
        assert_eq!(replayed, bound);
        assert_eq!(gateway.current_job().unwrap().assignment_sequence, 1);
    }

    #[test]
    fn authoritative_tip_reconciliation_retires_stale_asic_work() {
        let fixture = gateway_fixture();
        let store = Arc::new(MemoryStore::default());
        let mut gateway = Gateway::open_simulator(store.clone()).unwrap();
        let (hub, mut stream) = authoritative_stream(&fixture.snapshot);
        let bound = activate(&fixture, &mut stream, &mut gateway).unwrap();

        assert_eq!(
            stream.reconcile_current_at(&mut gateway, 1_500).unwrap(),
            HsrdGatewayTipReconciliation::Current {
                assignment_id: bound.assignment_id(),
                mining_generation: fixture.snapshot.generation,
            }
        );

        let mut replacement_tip = fixture.snapshot.clone();
        replacement_tip.generation += 1;
        replacement_tip.tip.hash = BlockHash::new([30; 32]);
        hub.tip_committed(Arc::new(replacement_tip)).unwrap();
        assert_eq!(
            stream.reconcile_current_at(&mut gateway, 1_500).unwrap(),
            HsrdGatewayTipReconciliation::Retired {
                assignment_id: bound.assignment_id(),
                mining_generation: fixture.snapshot.generation,
                credit_cutoff_ms: 1_500,
            }
        );
        assert!(gateway.current_job().is_none());
        hub.tip_cleared(fixture.snapshot.generation + 2).unwrap();
        assert_eq!(
            stream.reconcile_current_at(&mut gateway, 1_501).unwrap(),
            HsrdGatewayTipReconciliation::Idle
        );
    }

    #[test]
    fn durable_binding_survives_restart_and_rejects_assignment_rebinding() {
        let fixture = fixture();
        let bound = bind(&fixture).unwrap();
        let store = MemoryStore::default();

        let persisted = persist_bound_gateway_job(&store, &bound).unwrap();
        assert_eq!(
            load_bound_gateway_job(&store, bound.assignment_id()).unwrap(),
            persisted
        );
        verify_persisted_bound_gateway_job(&store, &bound).unwrap();
        persist_bound_gateway_job(&store, &bound).unwrap();

        let mut swapped = bound.clone();
        swapped.mining_generation += 1;
        assert!(matches!(
            persist_bound_gateway_job(&store, &swapped),
            Err(HsrdBridgeError::DurableBindingConflict)
        ));
        assert!(matches!(
            verify_persisted_bound_gateway_job(&store, &swapped),
            Err(HsrdBridgeError::DurableBindingConflict)
        ));
    }

    #[test]
    fn durable_binding_recovery_fails_closed_on_missing_or_malformed_state() {
        let fixture = fixture();
        let bound = bind(&fixture).unwrap();
        let store = MemoryStore::default();

        assert!(matches!(
            load_bound_gateway_job(&store, bound.assignment_id()),
            Err(HsrdBridgeError::DurableBindingMissing)
        ));
        store
            .put(
                HSRD_ASSIGNMENT_BINDING_NAMESPACE,
                &hex::encode(bound.assignment_id()),
                b"truncated",
            )
            .unwrap();
        assert!(matches!(
            load_bound_gateway_job(&store, bound.assignment_id()),
            Err(HsrdBridgeError::DurableBinding)
        ));
    }

    #[test]
    fn opened_solution_requires_the_exact_recovered_durable_binding() {
        let fixture = fixture();
        let bound = bind(&fixture).unwrap();
        let store = MemoryStore::default();
        let extra_nonce = [7; NONCE_SIZE];
        let mask = [9; 32];

        assert!(matches!(
            admit_persisted_opened_solution(HsrdOpenedSolutionRequest {
                store: &store,
                bound: &bound,
                snapshot: &fixture.snapshot,
                prepared_job: &fixture.prepared,
                assignment: &fixture.assignment,
                nonce: 0,
                time: 101,
                extra_nonce,
                mask,
            }),
            Err(HsrdBridgeError::DurableBindingMissing)
        ));
        persist_bound_gateway_job(&store, &bound).unwrap();

        let mut nonce = 0u32;
        let candidate = loop {
            match admit_persisted_opened_solution(HsrdOpenedSolutionRequest {
                store: &store,
                bound: &bound,
                snapshot: &fixture.snapshot,
                prepared_job: &fixture.prepared,
                assignment: &fixture.assignment,
                nonce,
                time: 101,
                extra_nonce,
                mask,
            }) {
                Ok(candidate) => break candidate,
                Err(HsrdBridgeError::Candidate) => {
                    nonce = nonce.checked_add(1).expect("nonce space")
                }
                Err(error) => panic!("unexpected bridge error: {error}"),
            }
        };
        assert_eq!(candidate.job_id(), fixture.prepared.job_id());
        assert_eq!(candidate.snapshot_generation(), fixture.snapshot.generation);
        assert!(candidate.block().header.verify_pow());

        let intent = publication_intent_for_persisted_candidate(
            &store,
            &bound,
            &fixture.snapshot,
            &candidate,
            [31; 32],
            vec!["remote-relay".to_owned(), "local-hsrd".to_owned()],
        )
        .unwrap();
        assert_eq!(intent.network_id, fixture.snapshot.network_id);
        assert_eq!(intent.block_hash, *candidate.block().hash().as_bytes());
        assert_eq!(intent.payload, candidate.block().encode());
        assert_eq!(
            intent.target_ids,
            vec!["local-hsrd".to_owned(), "remote-relay".to_owned()]
        );

        let mut stale = fixture.snapshot.clone();
        stale.generation += 1;
        assert!(matches!(
            publication_intent_for_persisted_candidate(
                &store,
                &bound,
                &stale,
                &candidate,
                [31; 32],
                vec!["local-hsrd".to_owned()],
            ),
            Err(HsrdBridgeError::StaleAuthority)
        ));
    }
}
