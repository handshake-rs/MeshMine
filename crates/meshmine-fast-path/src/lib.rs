//! Durable, bounded block-publication fan-out for MeshMine's winner path.
//!
//! The caller reconstructs and validates the candidate before creating an
//! intent. This crate supplies the next boundary: the exact candidate and its
//! target set are durable before external submission, targets execute in
//! parallel, and every completed target result is independently durable.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use meshmine_codec::{
    CanonicalDecode, CanonicalEncode, CodecError, DecodeLimits, Decoder, Encoder,
};
use meshmine_hns::Hash256;
use meshmine_storage::{BatchOperation, DurableStore, StorageError};
use meshmine_types::{UnsignedObject, domain_hash};
use thiserror::Error;
use tokio::task::JoinSet;

pub const PUBLICATION_INTENT_VERSION: u16 = 1;
pub const MAX_PUBLICATION_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PUBLICATION_TARGETS: usize = 32;
pub const MAX_PUBLICATION_TARGET_ID_BYTES: usize = 64;
pub const MAX_PUBLICATION_ATTEMPTS_PER_TARGET: u16 = 16;

const INTENT_NAMESPACE: &str = "block-publication-intent/v1";
const ATTEMPT_HEAD_NAMESPACE: &str = "block-publication-attempt-head/v1";
const ATTEMPT_START_NAMESPACE: &str = "block-publication-attempt-start/v1";
const ATTEMPT_RESULT_NAMESPACE: &str = "block-publication-attempt-result/v1";
const HEAD_STARTED: u8 = 1;
const HEAD_COMPLETED: u8 = 2;

/// Exact reconstructed candidate and the independently administered targets
/// authorized to receive it. `payload` is adapter-specific (for example a raw
/// HNS block or a frozen submitwork package); its hash is checked here, while
/// HNS contextual validation remains a caller precondition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockPublicationIntentV1 {
    pub version: u16,
    pub network_id: u8,
    pub winner_share_id: Hash256,
    pub block_hash: Hash256,
    pub payload_hash: Hash256,
    pub payload: Vec<u8>,
    /// Strictly sorted, unique canonical target identifiers.
    pub target_ids: Vec<String>,
}

impl BlockPublicationIntentV1 {
    pub fn new(
        network_id: u8,
        winner_share_id: Hash256,
        block_hash: Hash256,
        payload: Vec<u8>,
        mut target_ids: Vec<String>,
    ) -> Result<Self, PublicationError> {
        target_ids.sort();
        let intent = Self {
            version: PUBLICATION_INTENT_VERSION,
            network_id,
            winner_share_id,
            block_hash,
            payload_hash: publication_payload_hash(&payload),
            payload,
            target_ids,
        };
        validate_intent(&intent)?;
        Ok(intent)
    }
}

impl UnsignedObject for BlockPublicationIntentV1 {
    const DOMAIN_TAG: &'static str = "meshmine/block-publication-intent/v1";

    fn encode_unsigned(&self, encoder: &mut Encoder) {
        encoder.u16(self.version);
        encoder.u8(self.network_id);
        encoder.fixed(&self.winner_share_id);
        encoder.fixed(&self.block_hash);
        encoder.fixed(&self.payload_hash);
        encoder.bytes(&self.payload);
        encoder.varint(self.target_ids.len() as u64);
        for target_id in &self.target_ids {
            encoder.bytes(target_id.as_bytes());
        }
    }
}

impl CanonicalEncode for BlockPublicationIntentV1 {
    fn encode(&self, encoder: &mut Encoder) {
        self.encode_unsigned(encoder);
    }
}

impl CanonicalDecode for BlockPublicationIntentV1 {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let version = decoder.u16()?;
        let network_id = decoder.u8()?;
        let winner_share_id = decoder.array()?;
        let block_hash = decoder.array()?;
        let payload_hash = decoder.array()?;
        let payload = decoder.bytes(MAX_PUBLICATION_PAYLOAD_BYTES)?;
        let target_count = decoder.length(MAX_PUBLICATION_TARGETS)?;
        let mut target_ids = Vec::with_capacity(target_count);
        for _ in 0..target_count {
            let bytes = decoder.bytes(MAX_PUBLICATION_TARGET_ID_BYTES)?;
            let value = String::from_utf8(bytes)
                .map_err(|_| CodecError::InvalidField("publication target ID is not UTF-8"))?;
            target_ids.push(value);
        }
        Ok(Self {
            version,
            network_id,
            winner_share_id,
            block_hash,
            payload_hash,
            payload,
            target_ids,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PublicationResultKind {
    Accepted = 1,
    AlreadyKnown = 2,
    Rejected = 3,
    Retryable = 4,
}

impl PublicationResultKind {
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Accepted | Self::AlreadyKnown)
    }

    const fn is_terminal(self) -> bool {
        !matches!(self, Self::Retryable)
    }

    fn from_u8(value: u8) -> Result<Self, PublicationError> {
        match value {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::AlreadyKnown),
            3 => Ok(Self::Rejected),
            4 => Ok(Self::Retryable),
            _ => Err(PublicationError::MalformedDurableState),
        }
    }
}

/// Bounded target response. Adapters hash detailed remote responses rather
/// than placing unbounded or sensitive strings in the fast-path journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationTargetResult {
    pub kind: PublicationResultKind,
    pub response_code: u16,
    pub detail_hash: Hash256,
}

impl PublicationTargetResult {
    pub const fn new(
        kind: PublicationResultKind,
        response_code: u16,
        detail_hash: Hash256,
    ) -> Self {
        Self {
            kind,
            response_code,
            detail_hash,
        }
    }
}

/// One independently administered publication endpoint. Implementations must
/// make retries safe for an identical intent: a crash can occur after the
/// remote accepted the candidate but before the local result commit.
pub trait PublicationTarget: Send + Sync {
    fn target_id(&self) -> &str;

    fn submit(
        &self,
        intent: Arc<BlockPublicationIntentV1>,
    ) -> Pin<Box<dyn Future<Output = PublicationTargetResult> + Send + 'static>>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetPublicationReport {
    pub target_id: String,
    pub attempt_sequence: u16,
    pub result: PublicationTargetResult,
    pub submitted_this_run: bool,
    pub attempts_exhausted: bool,
    pub attempt_elapsed_us: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationFanoutReport {
    pub intent_id: Hash256,
    pub targets: Vec<TargetPublicationReport>,
    pub first_accepted_target: Option<String>,
    pub first_accepted_elapsed_us: Option<u64>,
}

impl PublicationFanoutReport {
    pub fn accepted(&self) -> bool {
        self.targets
            .iter()
            .any(|target| target.result.kind.is_success())
    }
}

#[derive(Debug, Error)]
pub enum PublicationError {
    #[error("publication intent is malformed or exceeds its bound")]
    InvalidIntent,
    #[error("publication target set does not exactly match the durable intent")]
    TargetSetMismatch,
    #[error("publication target identifier is malformed or duplicated")]
    InvalidTarget,
    #[error("durable publication state is malformed or inconsistent")]
    MalformedDurableState,
    #[error("publication target task stopped before recording a result")]
    TargetTaskStopped,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("blocking publication-state task failed")]
    BlockingTask,
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Codec(#[from] CodecError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AttemptStartV1 {
    intent_id: Hash256,
    target_id_hash: Hash256,
    sequence: u16,
    started_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AttemptResultV1 {
    intent_id: Hash256,
    target_id_hash: Hash256,
    sequence: u16,
    completed_unix_ms: u64,
    attempt_elapsed_us: u64,
    result: PublicationTargetResult,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AttemptHeadV1 {
    intent_id: Hash256,
    target_id_hash: Hash256,
    sequence: u16,
    state: u8,
    record_hash: Hash256,
}

enum PreparedTarget {
    Submit {
        target: Arc<dyn PublicationTarget>,
        start: AttemptStartV1,
    },
    Existing(TargetPublicationReport),
}

/// Single-writer fan-out coordinator. `&mut self` prevents two calls on the
/// same coordinator from submitting one target concurrently; the durable
/// attempt head supplies exact restart behavior.
pub struct DurableBlockPublisher {
    store: Arc<dyn DurableStore>,
    targets: Vec<Arc<dyn PublicationTarget>>,
}

impl DurableBlockPublisher {
    pub fn new(
        store: Arc<dyn DurableStore>,
        mut targets: Vec<Arc<dyn PublicationTarget>>,
    ) -> Result<Self, PublicationError> {
        if targets.is_empty() || targets.len() > MAX_PUBLICATION_TARGETS {
            return Err(PublicationError::InvalidTarget);
        }
        targets.sort_by(|left, right| left.target_id().cmp(right.target_id()));
        let mut previous = None;
        for target in &targets {
            validate_target_id(target.target_id())?;
            if previous == Some(target.target_id()) {
                return Err(PublicationError::InvalidTarget);
            }
            previous = Some(target.target_id());
        }
        Ok(Self { store, targets })
    }

    /// Persist and fan out an exact candidate. Existing successful or rejected
    /// target results are not submitted again; retryable results advance a
    /// bounded attempt sequence. An unfinished crash-era attempt is safely
    /// resubmitted with the same sequence.
    pub async fn publish(
        &mut self,
        intent: BlockPublicationIntentV1,
    ) -> Result<PublicationFanoutReport, PublicationError> {
        validate_intent(&intent)?;
        let configured_ids = self
            .targets
            .iter()
            .map(|target| target.target_id().to_owned())
            .collect::<Vec<_>>();
        if configured_ids != intent.target_ids {
            return Err(PublicationError::TargetSetMismatch);
        }

        let intent_id = intent.object_id();
        persist_intent(self.store.as_ref(), &intent)?;
        let now_ms = unix_ms()?;
        let mut prepared = Vec::with_capacity(self.targets.len());
        // No external target is called until every durable target head has
        // been validated or prepared. Corruption therefore fails closed.
        for target in &self.targets {
            prepared.push(prepare_target(
                self.store.as_ref(),
                intent_id,
                Arc::clone(target),
                now_ms,
            )?);
        }

        let intent = Arc::new(intent);
        let mut reports = Vec::with_capacity(prepared.len());
        let mut tasks = JoinSet::new();
        for target in prepared {
            match target {
                PreparedTarget::Existing(report) => reports.push(report),
                PreparedTarget::Submit { target, start } => {
                    let store = Arc::clone(&self.store);
                    let intent = Arc::clone(&intent);
                    tasks.spawn(async move {
                        let began = Instant::now();
                        let result = target.submit(intent).await;
                        let elapsed =
                            u64::try_from(began.elapsed().as_micros()).unwrap_or(u64::MAX);
                        let completed_unix_ms = unix_ms()?;
                        let target_id = target.target_id().to_owned();
                        let attempt = AttemptResultV1 {
                            intent_id: start.intent_id,
                            target_id_hash: start.target_id_hash,
                            sequence: start.sequence,
                            completed_unix_ms,
                            attempt_elapsed_us: elapsed,
                            result,
                        };
                        let store_for_commit = Arc::clone(&store);
                        let start_for_commit = start.clone();
                        tokio::task::spawn_blocking(move || {
                            persist_attempt_result(
                                store_for_commit.as_ref(),
                                &start_for_commit,
                                &attempt,
                            )
                        })
                        .await
                        .map_err(|_| PublicationError::BlockingTask)??;
                        Ok::<_, PublicationError>(TargetPublicationReport {
                            target_id,
                            attempt_sequence: start.sequence,
                            result,
                            submitted_this_run: true,
                            attempts_exhausted: false,
                            attempt_elapsed_us: elapsed,
                        })
                    });
                }
            }
        }

        let mut first_error = None;
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(report)) => reports.push(report),
                Ok(Err(error)) => {
                    // Continue collecting every already-started path before
                    // surfacing the durable error to the caller.
                    first_error.get_or_insert(error);
                    // The unfinished start remains durable and is resumed on
                    // the next invocation.
                }
                Err(_) => {
                    first_error.get_or_insert(PublicationError::TargetTaskStopped);
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }

        reports.sort_by(|left, right| left.target_id.cmp(&right.target_id));
        let current_first = reports
            .iter()
            .filter(|report| report.submitted_this_run && report.result.kind.is_success())
            .min_by_key(|report| (report.attempt_elapsed_us, report.target_id.as_str()));
        let existing_first = reports
            .iter()
            .find(|report| !report.submitted_this_run && report.result.kind.is_success());
        let first = existing_first.or(current_first);
        Ok(PublicationFanoutReport {
            intent_id,
            first_accepted_target: first.map(|report| report.target_id.clone()),
            first_accepted_elapsed_us: first
                .filter(|report| report.submitted_this_run)
                .map(|report| report.attempt_elapsed_us),
            targets: reports,
        })
    }
}

pub fn publication_payload_hash(payload: &[u8]) -> Hash256 {
    domain_hash("meshmine/block-publication-payload/v1", payload)
}

fn validate_intent(intent: &BlockPublicationIntentV1) -> Result<(), PublicationError> {
    if intent.version != PUBLICATION_INTENT_VERSION
        || intent.winner_share_id == [0; 32]
        || intent.block_hash == [0; 32]
        || intent.payload.is_empty()
        || intent.payload.len() > MAX_PUBLICATION_PAYLOAD_BYTES
        || publication_payload_hash(&intent.payload) != intent.payload_hash
        || intent.target_ids.is_empty()
        || intent.target_ids.len() > MAX_PUBLICATION_TARGETS
    {
        return Err(PublicationError::InvalidIntent);
    }
    let mut previous = None;
    for target_id in &intent.target_ids {
        validate_target_id(target_id)?;
        if previous.is_some_and(|value: &str| value >= target_id.as_str()) {
            return Err(PublicationError::InvalidIntent);
        }
        previous = Some(target_id.as_str());
    }
    Ok(())
}

fn validate_target_id(target_id: &str) -> Result<(), PublicationError> {
    if target_id.is_empty()
        || target_id.len() > MAX_PUBLICATION_TARGET_ID_BYTES
        || !target_id.is_ascii()
        || !target_id.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
        || !target_id
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(PublicationError::InvalidTarget);
    }
    Ok(())
}

fn persist_intent(
    store: &dyn DurableStore,
    intent: &BlockPublicationIntentV1,
) -> Result<(), PublicationError> {
    let key = hex::encode(intent.object_id());
    let bytes = intent.to_canonical_bytes();
    if store.put_if_absent(INTENT_NAMESPACE, &key, &bytes)? {
        return Ok(());
    }
    if store.get(INTENT_NAMESPACE, &key)?.as_deref() == Some(bytes.as_slice()) {
        return Ok(());
    }
    Err(PublicationError::MalformedDurableState)
}

fn prepare_target(
    store: &dyn DurableStore,
    intent_id: Hash256,
    target: Arc<dyn PublicationTarget>,
    now_ms: u64,
) -> Result<PreparedTarget, PublicationError> {
    let target_id = target.target_id().to_owned();
    let target_id_hash = target_hash(&target_id);
    let key = head_key(intent_id, target_id_hash);
    let existing = store.get(ATTEMPT_HEAD_NAMESPACE, &key)?;
    match existing.as_deref() {
        None => {
            let start = AttemptStartV1 {
                intent_id,
                target_id_hash,
                sequence: 1,
                started_unix_ms: now_ms,
            };
            persist_attempt_start(store, &key, None, &start)?;
            Ok(PreparedTarget::Submit { target, start })
        }
        Some(bytes) => {
            let head = decode_head(bytes)?;
            validate_head_binding(&head, intent_id, target_id_hash)?;
            match head.state {
                HEAD_STARTED => {
                    let start = load_attempt_start(store, &head)?;
                    Ok(PreparedTarget::Submit { target, start })
                }
                HEAD_COMPLETED => {
                    let result = load_attempt_result(store, &head)?;
                    if result.result.kind.is_terminal()
                        || result.sequence >= MAX_PUBLICATION_ATTEMPTS_PER_TARGET
                    {
                        Ok(PreparedTarget::Existing(TargetPublicationReport {
                            target_id,
                            attempt_sequence: result.sequence,
                            result: result.result,
                            submitted_this_run: false,
                            attempts_exhausted: !result.result.kind.is_terminal()
                                && result.sequence >= MAX_PUBLICATION_ATTEMPTS_PER_TARGET,
                            attempt_elapsed_us: result.attempt_elapsed_us,
                        }))
                    } else {
                        let sequence = result
                            .sequence
                            .checked_add(1)
                            .ok_or(PublicationError::MalformedDurableState)?;
                        let start = AttemptStartV1 {
                            intent_id,
                            target_id_hash,
                            sequence,
                            started_unix_ms: now_ms,
                        };
                        persist_attempt_start(store, &key, Some(bytes), &start)?;
                        Ok(PreparedTarget::Submit { target, start })
                    }
                }
                _ => Err(PublicationError::MalformedDurableState),
            }
        }
    }
}

fn persist_attempt_start(
    store: &dyn DurableStore,
    head_key: &str,
    expected_head: Option<&[u8]>,
    start: &AttemptStartV1,
) -> Result<(), PublicationError> {
    let start_bytes = encode_start(start);
    let start_hash = domain_hash("meshmine/block-publication-attempt-start/v1", &start_bytes);
    let head = AttemptHeadV1 {
        intent_id: start.intent_id,
        target_id_hash: start.target_id_hash,
        sequence: start.sequence,
        state: HEAD_STARTED,
        record_hash: start_hash,
    };
    let record_key = attempt_key(start.intent_id, start.target_id_hash, start.sequence);
    if !store.apply_batch_if(
        ATTEMPT_HEAD_NAMESPACE,
        head_key,
        expected_head,
        &[
            BatchOperation::put(ATTEMPT_START_NAMESPACE, record_key, start_bytes),
            BatchOperation::put(ATTEMPT_HEAD_NAMESPACE, head_key, encode_head(&head)),
        ],
    )? {
        return Err(PublicationError::MalformedDurableState);
    }
    Ok(())
}

fn persist_attempt_result(
    store: &dyn DurableStore,
    start: &AttemptStartV1,
    result: &AttemptResultV1,
) -> Result<(), PublicationError> {
    if result.intent_id != start.intent_id
        || result.target_id_hash != start.target_id_hash
        || result.sequence != start.sequence
    {
        return Err(PublicationError::MalformedDurableState);
    }
    let key = head_key(start.intent_id, start.target_id_hash);
    let expected_head = AttemptHeadV1 {
        intent_id: start.intent_id,
        target_id_hash: start.target_id_hash,
        sequence: start.sequence,
        state: HEAD_STARTED,
        record_hash: domain_hash(
            "meshmine/block-publication-attempt-start/v1",
            &encode_start(start),
        ),
    };
    let result_bytes = encode_result(result);
    let completed_head = AttemptHeadV1 {
        intent_id: start.intent_id,
        target_id_hash: start.target_id_hash,
        sequence: start.sequence,
        state: HEAD_COMPLETED,
        record_hash: domain_hash(
            "meshmine/block-publication-attempt-result/v1",
            &result_bytes,
        ),
    };
    let record_key = attempt_key(start.intent_id, start.target_id_hash, start.sequence);
    if !store.apply_batch_if(
        ATTEMPT_HEAD_NAMESPACE,
        &key,
        Some(&encode_head(&expected_head)),
        &[
            BatchOperation::put(ATTEMPT_RESULT_NAMESPACE, record_key, result_bytes),
            BatchOperation::put(
                ATTEMPT_HEAD_NAMESPACE,
                key.clone(),
                encode_head(&completed_head),
            ),
        ],
    )? {
        return Err(PublicationError::MalformedDurableState);
    }
    Ok(())
}

fn load_attempt_start(
    store: &dyn DurableStore,
    head: &AttemptHeadV1,
) -> Result<AttemptStartV1, PublicationError> {
    let key = attempt_key(head.intent_id, head.target_id_hash, head.sequence);
    let bytes = store
        .get(ATTEMPT_START_NAMESPACE, &key)?
        .ok_or(PublicationError::MalformedDurableState)?;
    if domain_hash("meshmine/block-publication-attempt-start/v1", &bytes) != head.record_hash {
        return Err(PublicationError::MalformedDurableState);
    }
    let start = decode_start(&bytes)?;
    if start.intent_id != head.intent_id
        || start.target_id_hash != head.target_id_hash
        || start.sequence != head.sequence
    {
        return Err(PublicationError::MalformedDurableState);
    }
    Ok(start)
}

fn load_attempt_result(
    store: &dyn DurableStore,
    head: &AttemptHeadV1,
) -> Result<AttemptResultV1, PublicationError> {
    let key = attempt_key(head.intent_id, head.target_id_hash, head.sequence);
    let bytes = store
        .get(ATTEMPT_RESULT_NAMESPACE, &key)?
        .ok_or(PublicationError::MalformedDurableState)?;
    if domain_hash("meshmine/block-publication-attempt-result/v1", &bytes) != head.record_hash {
        return Err(PublicationError::MalformedDurableState);
    }
    let result = decode_result(&bytes)?;
    if result.intent_id != head.intent_id
        || result.target_id_hash != head.target_id_hash
        || result.sequence != head.sequence
    {
        return Err(PublicationError::MalformedDurableState);
    }
    Ok(result)
}

fn validate_head_binding(
    head: &AttemptHeadV1,
    intent_id: Hash256,
    target_id_hash: Hash256,
) -> Result<(), PublicationError> {
    if head.intent_id != intent_id
        || head.target_id_hash != target_id_hash
        || head.sequence == 0
        || head.sequence > MAX_PUBLICATION_ATTEMPTS_PER_TARGET
        || !matches!(head.state, HEAD_STARTED | HEAD_COMPLETED)
    {
        return Err(PublicationError::MalformedDurableState);
    }
    Ok(())
}

fn target_hash(target_id: &str) -> Hash256 {
    domain_hash("meshmine/block-publication-target/v1", target_id.as_bytes())
}

fn head_key(intent_id: Hash256, target_id_hash: Hash256) -> String {
    format!("{}-{}", hex::encode(intent_id), hex::encode(target_id_hash))
}

fn attempt_key(intent_id: Hash256, target_id_hash: Hash256, sequence: u16) -> String {
    format!(
        "{}-{}-{sequence:05}",
        hex::encode(intent_id),
        hex::encode(target_id_hash)
    )
}

fn encode_start(value: &AttemptStartV1) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.fixed(b"MMBS");
    encoder.u16(PUBLICATION_INTENT_VERSION);
    encoder.fixed(&value.intent_id);
    encoder.fixed(&value.target_id_hash);
    encoder.u16(value.sequence);
    encoder.u64(value.started_unix_ms);
    encoder.into_bytes()
}

fn decode_start(bytes: &[u8]) -> Result<AttemptStartV1, PublicationError> {
    let mut decoder = bounded_decoder(bytes, 96)?;
    if decoder.array::<4>()? != *b"MMBS" || decoder.u16()? != PUBLICATION_INTENT_VERSION {
        return Err(PublicationError::MalformedDurableState);
    }
    let value = AttemptStartV1 {
        intent_id: decoder.array()?,
        target_id_hash: decoder.array()?,
        sequence: decoder.u16()?,
        started_unix_ms: decoder.u64()?,
    };
    decoder.finish()?;
    Ok(value)
}

fn encode_result(value: &AttemptResultV1) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.fixed(b"MMBR");
    encoder.u16(PUBLICATION_INTENT_VERSION);
    encoder.fixed(&value.intent_id);
    encoder.fixed(&value.target_id_hash);
    encoder.u16(value.sequence);
    encoder.u64(value.completed_unix_ms);
    encoder.u64(value.attempt_elapsed_us);
    encoder.u8(value.result.kind as u8);
    encoder.u16(value.result.response_code);
    encoder.fixed(&value.result.detail_hash);
    encoder.into_bytes()
}

fn decode_result(bytes: &[u8]) -> Result<AttemptResultV1, PublicationError> {
    let mut decoder = bounded_decoder(bytes, 144)?;
    if decoder.array::<4>()? != *b"MMBR" || decoder.u16()? != PUBLICATION_INTENT_VERSION {
        return Err(PublicationError::MalformedDurableState);
    }
    let value = AttemptResultV1 {
        intent_id: decoder.array()?,
        target_id_hash: decoder.array()?,
        sequence: decoder.u16()?,
        completed_unix_ms: decoder.u64()?,
        attempt_elapsed_us: decoder.u64()?,
        result: PublicationTargetResult {
            kind: PublicationResultKind::from_u8(decoder.u8()?)?,
            response_code: decoder.u16()?,
            detail_hash: decoder.array()?,
        },
    };
    decoder.finish()?;
    Ok(value)
}

fn encode_head(value: &AttemptHeadV1) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.fixed(b"MMBH");
    encoder.u16(PUBLICATION_INTENT_VERSION);
    encoder.fixed(&value.intent_id);
    encoder.fixed(&value.target_id_hash);
    encoder.u16(value.sequence);
    encoder.u8(value.state);
    encoder.fixed(&value.record_hash);
    encoder.into_bytes()
}

fn decode_head(bytes: &[u8]) -> Result<AttemptHeadV1, PublicationError> {
    let mut decoder = bounded_decoder(bytes, 112)?;
    if decoder.array::<4>()? != *b"MMBH" || decoder.u16()? != PUBLICATION_INTENT_VERSION {
        return Err(PublicationError::MalformedDurableState);
    }
    let value = AttemptHeadV1 {
        intent_id: decoder.array()?,
        target_id_hash: decoder.array()?,
        sequence: decoder.u16()?,
        state: decoder.u8()?,
        record_hash: decoder.array()?,
    };
    decoder.finish()?;
    Ok(value)
}

fn bounded_decoder(bytes: &[u8], maximum: usize) -> Result<Decoder<'_>, PublicationError> {
    Ok(Decoder::new(
        bytes,
        DecodeLimits {
            max_object_bytes: maximum,
            max_vector_items: MAX_PUBLICATION_TARGETS,
        },
    )?)
}

fn unix_ms() -> Result<u64, PublicationError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PublicationError::Clock)?;
    u64::try_from(duration.as_millis()).map_err(|_| PublicationError::Clock)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use meshmine_storage::{MemoryStore, RedbStore};
    use tokio::sync::Notify;

    use super::*;

    struct TestTarget {
        id: String,
        calls: Arc<AtomicUsize>,
        delay: Duration,
        results: Arc<std::sync::Mutex<Vec<PublicationTargetResult>>>,
        observed_intent: Option<(Arc<dyn DurableStore>, Hash256)>,
        entered: Option<Arc<Notify>>,
    }

    impl PublicationTarget for TestTarget {
        fn target_id(&self) -> &str {
            &self.id
        }

        fn submit(
            &self,
            intent: Arc<BlockPublicationIntentV1>,
        ) -> Pin<Box<dyn Future<Output = PublicationTargetResult> + Send + 'static>> {
            let calls = Arc::clone(&self.calls);
            let delay = self.delay;
            let results = Arc::clone(&self.results);
            let observed_intent = self.observed_intent.clone();
            let entered = self.entered.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                if let Some(entered) = entered {
                    entered.notify_one();
                }
                if let Some((store, expected_id)) = observed_intent {
                    assert_eq!(intent.object_id(), expected_id);
                    assert!(
                        store
                            .get(INTENT_NAMESPACE, &hex::encode(expected_id))
                            .unwrap()
                            .is_some()
                    );
                }
                tokio::time::sleep(delay).await;
                results.lock().unwrap().remove(0)
            })
        }
    }

    fn response(kind: PublicationResultKind, marker: u8) -> PublicationTargetResult {
        PublicationTargetResult::new(kind, u16::from(marker), [marker; 32])
    }

    fn target(
        id: &str,
        delay_ms: u64,
        results: Vec<PublicationTargetResult>,
    ) -> (Arc<dyn PublicationTarget>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(TestTarget {
                id: id.to_owned(),
                calls: Arc::clone(&calls),
                delay: Duration::from_millis(delay_ms),
                results: Arc::new(std::sync::Mutex::new(results)),
                observed_intent: None,
                entered: None,
            }),
            calls,
        )
    }

    fn intent(ids: &[&str]) -> BlockPublicationIntentV1 {
        BlockPublicationIntentV1::new(
            2,
            [7; 32],
            [8; 32],
            vec![1, 2, 3, 4],
            ids.iter().map(|id| (*id).to_owned()).collect(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn intent_is_durable_before_parallel_targets_and_first_success_does_not_cancel() {
        let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
        let intent = intent(&["fast-local", "slow-relay"]);
        let intent_id = intent.object_id();
        let fast_calls = Arc::new(AtomicUsize::new(0));
        let fast: Arc<dyn PublicationTarget> = Arc::new(TestTarget {
            id: "fast-local".to_owned(),
            calls: Arc::clone(&fast_calls),
            delay: Duration::from_millis(1),
            results: Arc::new(std::sync::Mutex::new(vec![response(
                PublicationResultKind::Accepted,
                1,
            )])),
            observed_intent: Some((Arc::clone(&store), intent_id)),
            entered: None,
        });
        let (slow, slow_calls) = target(
            "slow-relay",
            30,
            vec![response(PublicationResultKind::Rejected, 2)],
        );
        let mut publisher =
            DurableBlockPublisher::new(Arc::clone(&store), vec![slow, fast]).unwrap();

        let report = publisher.publish(intent).await.unwrap();

        assert!(report.accepted());
        assert_eq!(report.first_accepted_target.as_deref(), Some("fast-local"));
        assert!(report.first_accepted_elapsed_us.is_some());
        assert_eq!(fast_calls.load(Ordering::SeqCst), 1);
        assert_eq!(slow_calls.load(Ordering::SeqCst), 1);
        assert_eq!(report.targets.len(), 2);
    }

    #[tokio::test]
    async fn retryable_result_advances_once_and_terminal_result_is_not_resubmitted() {
        let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
        let (target, calls) = target(
            "local-hsd",
            0,
            vec![
                response(PublicationResultKind::Retryable, 1),
                response(PublicationResultKind::Accepted, 2),
            ],
        );
        let mut publisher =
            DurableBlockPublisher::new(Arc::clone(&store), vec![Arc::clone(&target)]).unwrap();
        let candidate = intent(&["local-hsd"]);

        let first = publisher.publish(candidate.clone()).await.unwrap();
        assert_eq!(first.targets[0].attempt_sequence, 1);
        assert_eq!(
            first.targets[0].result.kind,
            PublicationResultKind::Retryable
        );
        let second = publisher.publish(candidate.clone()).await.unwrap();
        assert_eq!(second.targets[0].attempt_sequence, 2);
        assert_eq!(
            second.targets[0].result.kind,
            PublicationResultKind::Accepted
        );
        let third = publisher.publish(candidate).await.unwrap();
        assert_eq!(third.targets[0].attempt_sequence, 2);
        assert!(!third.targets[0].submitted_this_run);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn exact_terminal_state_survives_redb_restart() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let path = directory.path().join("publication.redb");
        let candidate = intent(&["relay-a"]);
        let (first_target, first_calls) = target(
            "relay-a",
            0,
            vec![response(PublicationResultKind::AlreadyKnown, 3)],
        );
        {
            let store: Arc<dyn DurableStore> = Arc::new(RedbStore::create(&path).unwrap());
            let mut publisher = DurableBlockPublisher::new(store, vec![first_target]).unwrap();
            assert!(
                publisher
                    .publish(candidate.clone())
                    .await
                    .unwrap()
                    .accepted()
            );
        }
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);

        let (replacement, replacement_calls) = target(
            "relay-a",
            0,
            vec![response(PublicationResultKind::Rejected, 9)],
        );
        let store: Arc<dyn DurableStore> = Arc::new(RedbStore::create(&path).unwrap());
        let mut publisher = DurableBlockPublisher::new(store, vec![replacement]).unwrap();
        let recovered = publisher.publish(candidate).await.unwrap();
        assert!(recovered.accepted());
        assert!(!recovered.targets[0].submitted_this_run);
        assert_eq!(replacement_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn target_set_and_payload_are_canonical_and_bounded() {
        let candidate = intent(&["relay-z", "local-hsd"]);
        assert_eq!(candidate.target_ids, vec!["local-hsd", "relay-z"]);
        let bytes = candidate.to_canonical_bytes();
        let decoded = BlockPublicationIntentV1::from_canonical_bytes(
            &bytes,
            DecodeLimits {
                max_object_bytes: MAX_PUBLICATION_PAYLOAD_BYTES + 4096,
                max_vector_items: MAX_PUBLICATION_TARGETS,
            },
        )
        .unwrap();
        assert_eq!(decoded, candidate);

        let duplicate = BlockPublicationIntentV1::new(
            2,
            [1; 32],
            [2; 32],
            vec![1],
            vec!["relay".to_owned(), "relay".to_owned()],
        );
        assert!(matches!(duplicate, Err(PublicationError::InvalidIntent)));
        assert!(
            BlockPublicationIntentV1::new(2, [1; 32], [2; 32], Vec::new(), vec!["relay".into()])
                .is_err()
        );
    }

    #[tokio::test]
    async fn configured_targets_must_exactly_match_the_durable_intent() {
        let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
        let (only, calls) = target(
            "local-hsd",
            0,
            vec![response(PublicationResultKind::Accepted, 1)],
        );
        let mut publisher = DurableBlockPublisher::new(store, vec![only]).unwrap();
        let error = publisher
            .publish(intent(&["different-relay"]))
            .await
            .unwrap_err();
        assert!(matches!(error, PublicationError::TargetSetMismatch));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unfinished_attempt_is_resubmitted_with_the_same_sequence_after_restart() {
        let store: Arc<dyn DurableStore> = Arc::new(MemoryStore::default());
        let (panicking, panic_calls) = target("local-hsd", 0, Vec::new());
        let candidate = intent(&["local-hsd"]);
        let mut first = DurableBlockPublisher::new(Arc::clone(&store), vec![panicking]).unwrap();
        assert!(matches!(
            first.publish(candidate.clone()).await,
            Err(PublicationError::TargetTaskStopped)
        ));
        assert_eq!(panic_calls.load(Ordering::SeqCst), 1);

        let (replacement, replacement_calls) = target(
            "local-hsd",
            0,
            vec![response(PublicationResultKind::AlreadyKnown, 7)],
        );
        let mut restarted =
            DurableBlockPublisher::new(Arc::clone(&store), vec![replacement]).unwrap();
        let report = restarted.publish(candidate).await.unwrap();
        assert_eq!(report.targets[0].attempt_sequence, 1);
        assert!(report.targets[0].submitted_this_run);
        assert_eq!(replacement_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn mainnet_network_identifier_zero_is_valid() {
        assert!(
            BlockPublicationIntentV1::new(0, [1; 32], [2; 32], vec![1], vec!["local-hsd".into()],)
                .is_ok()
        );
    }
}
