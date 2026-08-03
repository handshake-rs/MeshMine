use std::collections::{BTreeSet, HashMap, HashSet};

use meshmine_codec::{CanonicalEncode, Encoder};
use meshmine_hns::{Hash256, blake2b_256, merkle_root};
use meshmine_storage::{DurableInvariantError, ProtocolJournal, ProtocolRecordKind};
use meshmine_types::{BodyErasureDescriptorV2, UnsignedObject, domain_hash};
use reed_solomon_erasure::galois_8::ReedSolomon;
use thiserror::Error;

const SHARD_DOMAIN: &str = "meshmine/body-shard/v2";
const CHALLENGE_DOMAIN: &str = "meshmine/body-challenge/v2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardProof {
    pub shard_index: u16,
    pub total_shards: u16,
    pub siblings: Vec<Hash256>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredShard {
    pub index: u16,
    pub bytes: Vec<u8>,
    pub proof: ShardProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedBody {
    pub descriptor: BodyErasureDescriptorV2,
    pub shards: Vec<StoredShard>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetrievalChallenge {
    pub descriptor_id: Hash256,
    pub challenge_round: u64,
    pub shard_indices: Vec<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionLimits {
    pub max_package_size: u32,
    pub max_pending_bytes: u64,
    pub max_pending_per_operator: u16,
    pub max_total_shards: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionPolicy {
    pub bootstrap_allowlist: BTreeSet<[u8; 32]>,
    pub accepted_service_receipts: BTreeSet<Hash256>,
    pub minimum_request_stamp_zero_bits: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionCredential {
    BootstrapAllowlist,
    WorkStamp { nonce: u64 },
    ServiceReceipt { receipt_id: Hash256 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AvailabilityRetentionPolicy {
    pub reorganization_horizon: u32,
    pub audit_retention_blocks: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AvailabilitySettlementState {
    pub parent_height: u32,
    pub session_closed: bool,
    pub mask_opened: bool,
    pub discovered_block_safely_propagated: bool,
    pub storage_compensation_end_height: u32,
    pub audit_retention_end_height: u32,
}

#[derive(Debug, Default)]
pub struct AdmissionController {
    seen: HashSet<Hash256>,
    spent_service_receipts: HashSet<Hash256>,
    pending_by_operator: HashMap<[u8; 32], u16>,
    pending_bytes: u64,
    invalid_strikes: HashMap<[u8; 32], u16>,
    banned_until_height: HashMap<[u8; 32], u32>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AvailabilityError {
    #[error("invalid erasure parameters: data={data}, parity={parity}")]
    InvalidParameters { data: u16, parity: u16 },
    #[error("body package exceeds u32 size")]
    PackageTooLarge,
    #[error("Reed-Solomon operation failed: {0}")]
    ReedSolomon(String),
    #[error("not enough valid shards to reconstruct")]
    InsufficientShards,
    #[error("shard {0} has an invalid length")]
    InvalidShardLength(u16),
    #[error("shard {0} has an invalid Merkle proof")]
    InvalidShardProof(u16),
    #[error("shard index {0} is out of range")]
    ShardOutOfRange(u16),
    #[error("duplicate shard index {0}")]
    DuplicateShard(u16),
    #[error("reconstructed body does not match its declared size")]
    InvalidReconstructedSize,
    #[error("body package has already been admitted")]
    DuplicateBody,
    #[error("body package exceeds admission size limit")]
    AdmissionPackageSize,
    #[error("body admission exceeds pending-byte budget")]
    AdmissionByteBudget,
    #[error("operator exceeds pending-body quota")]
    AdmissionOperatorQuota,
    #[error("descriptor exceeds shard-count limit")]
    AdmissionShardLimit,
    #[error("body request lacks an accepted allowlist, work stamp, or service credential")]
    AdmissionCredential,
    #[error("operator is temporarily banned after invalid body submissions")]
    AdmissionBanned,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BodyPersistenceError {
    #[error("encoded descriptor does not identify the supplied canonical body")]
    DescriptorMismatch,
    #[error("durable body state failed: {0}")]
    Durable(#[from] DurableInvariantError),
}

/// Persist a contextually validated body, validation result, erasure
/// descriptor, and every local shard before availability is advertised.
/// Partial crash writes are harmless because each key is immutable and the
/// entire operation is retryable.
pub fn persist_encoded_body(
    journal: &ProtocolJournal<'_>,
    body_package_id: Hash256,
    canonical_body_bytes: &[u8],
    consensus_validation_result_hash: Hash256,
    encoded: &EncodedBody,
) -> Result<(), BodyPersistenceError> {
    if encoded.descriptor.body_package_id != body_package_id
        || usize::try_from(encoded.descriptor.original_size).ok()
            != Some(canonical_body_bytes.len())
    {
        return Err(BodyPersistenceError::DescriptorMismatch);
    }
    journal.persist(
        ProtocolRecordKind::BodyPackage,
        &body_package_id,
        canonical_body_bytes,
    )?;
    journal.persist(
        ProtocolRecordKind::BodyValidation,
        &body_package_id,
        &consensus_validation_result_hash,
    )?;
    let descriptor_id = encoded.descriptor.object_id();
    let mut descriptor_bytes = Encoder::new();
    encoded.descriptor.encode(&mut descriptor_bytes);
    journal.persist(
        ProtocolRecordKind::ErasureDescriptor,
        &descriptor_id,
        descriptor_bytes.as_bytes(),
    )?;
    for shard in &encoded.shards {
        let mut shard_key = Vec::with_capacity(34);
        shard_key.extend_from_slice(&descriptor_id);
        shard_key.extend_from_slice(&shard.index.to_le_bytes());
        let mut shard_bytes = Encoder::new();
        shard_bytes.u16(shard.index);
        shard_bytes.bytes(&shard.bytes);
        shard_bytes.u16(shard.proof.total_shards);
        shard_bytes.varint(shard.proof.siblings.len() as u64);
        for sibling in &shard.proof.siblings {
            shard_bytes.fixed(sibling);
        }
        journal.persist(
            ProtocolRecordKind::BodyShard,
            &shard_key,
            shard_bytes.as_bytes(),
        )?;
    }
    Ok(())
}

impl AvailabilityRetentionPolicy {
    /// A shard can be pruned only after every height- and state-based
    /// obligation has ended. This implements the "later of" rule in 11.4.
    pub fn may_prune(
        &self,
        descriptor: &BodyErasureDescriptorV2,
        state: AvailabilitySettlementState,
        canonical_height: u32,
    ) -> bool {
        let reorg_end = state
            .parent_height
            .saturating_add(self.reorganization_horizon);
        let audit_end = state
            .audit_retention_end_height
            .saturating_add(self.audit_retention_blocks);
        state.session_closed
            && state.mask_opened
            && state.discovered_block_safely_propagated
            && canonical_height >= descriptor.expiry_height
            && canonical_height >= reorg_end
            && canonical_height >= state.storage_compensation_end_height
            && canonical_height >= audit_end
    }
}

pub fn encode_body(
    protocol_version: u16,
    network_id: u8,
    body_package_id: Hash256,
    canonical_body_bytes: &[u8],
    data_shards: u16,
    parity_shards: u16,
    expiry_height: u32,
) -> Result<EncodedBody, AvailabilityError> {
    if data_shards == 0 || parity_shards == 0 {
        return Err(AvailabilityError::InvalidParameters {
            data: data_shards,
            parity: parity_shards,
        });
    }
    let total =
        data_shards
            .checked_add(parity_shards)
            .ok_or(AvailabilityError::InvalidParameters {
                data: data_shards,
                parity: parity_shards,
            })?;
    let original_size = u32::try_from(canonical_body_bytes.len())
        .map_err(|_| AvailabilityError::PackageTooLarge)?;
    let shard_size = canonical_body_bytes
        .len()
        .max(1)
        .div_ceil(usize::from(data_shards));
    let shard_size_u32 =
        u32::try_from(shard_size).map_err(|_| AvailabilityError::PackageTooLarge)?;

    let mut shards = vec![vec![0u8; shard_size]; usize::from(total)];
    for (index, byte) in canonical_body_bytes.iter().enumerate() {
        shards[index / shard_size][index % shard_size] = *byte;
    }
    ReedSolomon::new(usize::from(data_shards), usize::from(parity_shards))
        .map_err(|error| AvailabilityError::ReedSolomon(error.to_string()))?
        .encode(&mut shards)
        .map_err(|error| AvailabilityError::ReedSolomon(error.to_string()))?;

    let leaves: Vec<_> = shards
        .iter()
        .enumerate()
        .map(|(index, shard)| shard_leaf(&body_package_id, index as u16, shard))
        .collect();
    let root = merkle_root(&leaves);
    let stored = shards
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| StoredShard {
            index: index as u16,
            bytes,
            proof: create_proof(&leaves, index),
        })
        .collect();

    Ok(EncodedBody {
        descriptor: BodyErasureDescriptorV2 {
            protocol_version,
            network_id,
            body_package_id,
            original_size,
            data_shards,
            parity_shards,
            shard_size: shard_size_u32,
            shard_merkle_root: root,
            expiry_height,
            compression: 0,
        },
        shards: stored,
    })
}

pub fn reconstruct_body(
    descriptor: &BodyErasureDescriptorV2,
    supplied: &[StoredShard],
) -> Result<Vec<u8>, AvailabilityError> {
    let total = descriptor
        .data_shards
        .checked_add(descriptor.parity_shards)
        .ok_or(AvailabilityError::InvalidParameters {
            data: descriptor.data_shards,
            parity: descriptor.parity_shards,
        })?;
    let shard_size = descriptor.shard_size as usize;
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; usize::from(total)];

    for shard in supplied {
        if shard.index >= total {
            return Err(AvailabilityError::ShardOutOfRange(shard.index));
        }
        if shard.bytes.len() != shard_size {
            return Err(AvailabilityError::InvalidShardLength(shard.index));
        }
        if shards[usize::from(shard.index)].is_some() {
            return Err(AvailabilityError::DuplicateShard(shard.index));
        }
        if !verify_shard(descriptor, shard) {
            return Err(AvailabilityError::InvalidShardProof(shard.index));
        }
        shards[usize::from(shard.index)] = Some(shard.bytes.clone());
    }

    if shards.iter().flatten().count() < usize::from(descriptor.data_shards) {
        return Err(AvailabilityError::InsufficientShards);
    }
    ReedSolomon::new(
        usize::from(descriptor.data_shards),
        usize::from(descriptor.parity_shards),
    )
    .map_err(|error| AvailabilityError::ReedSolomon(error.to_string()))?
    .reconstruct(&mut shards)
    .map_err(|error| AvailabilityError::ReedSolomon(error.to_string()))?;

    let mut body = Vec::with_capacity(usize::from(descriptor.data_shards) * shard_size);
    for shard in shards.iter().take(usize::from(descriptor.data_shards)) {
        body.extend_from_slice(
            shard
                .as_ref()
                .ok_or(AvailabilityError::InsufficientShards)?,
        );
    }
    let original_size = descriptor.original_size as usize;
    if original_size > body.len() {
        return Err(AvailabilityError::InvalidReconstructedSize);
    }
    body.truncate(original_size);
    Ok(body)
}

pub fn verify_shard(descriptor: &BodyErasureDescriptorV2, shard: &StoredShard) -> bool {
    if shard.proof.shard_index != shard.index {
        return false;
    }
    let total = match descriptor.data_shards.checked_add(descriptor.parity_shards) {
        Some(total) => total,
        None => return false,
    };
    if shard.proof.total_shards != total {
        return false;
    }
    let leaf = shard_leaf(&descriptor.body_package_id, shard.index, &shard.bytes);
    verify_proof(&leaf, &shard.proof, &descriptor.shard_merkle_root)
}

pub fn make_retrieval_challenge(
    descriptor: &BodyErasureDescriptorV2,
    challenge_round: u64,
    challenger_nonce: &Hash256,
    requested_shards: u16,
) -> Result<RetrievalChallenge, AvailabilityError> {
    let total = descriptor
        .data_shards
        .checked_add(descriptor.parity_shards)
        .filter(|total| *total > 0)
        .ok_or(AvailabilityError::InvalidParameters {
            data: descriptor.data_shards,
            parity: descriptor.parity_shards,
        })?;
    let requested = requested_shards.min(total);
    let descriptor_id = descriptor.object_id();
    let mut indices = Vec::with_capacity(usize::from(requested));
    let mut counter = 0u64;
    while indices.len() < usize::from(requested) {
        let mut input = Encoder::new();
        input.fixed(&descriptor_id);
        input.u64(challenge_round);
        input.fixed(challenger_nonce);
        input.u64(counter);
        let candidate = domain_hash(CHALLENGE_DOMAIN, input.as_bytes());
        let index = u16::from_le_bytes([candidate[0], candidate[1]]) % total;
        if !indices.contains(&index) {
            indices.push(index);
        }
        counter += 1;
    }
    Ok(RetrievalChallenge {
        descriptor_id,
        challenge_round,
        shard_indices: indices,
    })
}

pub fn verify_challenge_response(
    descriptor: &BodyErasureDescriptorV2,
    challenge: &RetrievalChallenge,
    responses: &[StoredShard],
) -> bool {
    if challenge.descriptor_id != descriptor.object_id()
        || responses.len() != challenge.shard_indices.len()
    {
        return false;
    }
    challenge.shard_indices.iter().all(|expected| {
        responses
            .iter()
            .find(|response| response.index == *expected)
            .is_some_and(|response| verify_shard(descriptor, response))
    })
}

impl AdmissionController {
    pub fn admit(
        &mut self,
        limits: AdmissionLimits,
        policy: &AdmissionPolicy,
        credential: AdmissionCredential,
        operator: [u8; 32],
        current_height: u32,
        descriptor: &BodyErasureDescriptorV2,
    ) -> Result<(), AvailabilityError> {
        if self
            .banned_until_height
            .get(&operator)
            .is_some_and(|until| current_height < *until)
        {
            return Err(AvailabilityError::AdmissionBanned);
        }
        let descriptor_id = descriptor.object_id();
        if !valid_admission_credential(policy, credential, &operator, &descriptor_id) {
            return Err(AvailabilityError::AdmissionCredential);
        }
        if let AdmissionCredential::ServiceReceipt { receipt_id } = credential
            && self.spent_service_receipts.contains(&receipt_id)
        {
            return Err(AvailabilityError::AdmissionCredential);
        }
        if self.seen.contains(&descriptor_id) {
            return Err(AvailabilityError::DuplicateBody);
        }
        if descriptor.original_size > limits.max_package_size {
            return Err(AvailabilityError::AdmissionPackageSize);
        }
        let total = descriptor
            .data_shards
            .checked_add(descriptor.parity_shards)
            .ok_or(AvailabilityError::InvalidParameters {
                data: descriptor.data_shards,
                parity: descriptor.parity_shards,
            })?;
        if descriptor.data_shards == 0
            || descriptor.parity_shards == 0
            || descriptor.shard_size == 0
        {
            return Err(AvailabilityError::InvalidParameters {
                data: descriptor.data_shards,
                parity: descriptor.parity_shards,
            });
        }
        if total > limits.max_total_shards {
            return Err(AvailabilityError::AdmissionShardLimit);
        }
        let pending = self
            .pending_by_operator
            .get(&operator)
            .copied()
            .unwrap_or(0);
        if pending >= limits.max_pending_per_operator {
            return Err(AvailabilityError::AdmissionOperatorQuota);
        }
        let next_bytes = self
            .pending_bytes
            .checked_add(u64::from(descriptor.original_size))
            .ok_or(AvailabilityError::AdmissionByteBudget)?;
        if next_bytes > limits.max_pending_bytes {
            return Err(AvailabilityError::AdmissionByteBudget);
        }
        self.seen.insert(descriptor_id);
        if let AdmissionCredential::ServiceReceipt { receipt_id } = credential {
            self.spent_service_receipts.insert(receipt_id);
        }
        self.pending_by_operator.insert(operator, pending + 1);
        self.pending_bytes = next_bytes;
        Ok(())
    }

    pub fn complete(&mut self, operator: &[u8; 32], original_size: u32) {
        if let Some(pending) = self.pending_by_operator.get_mut(operator) {
            *pending = pending.saturating_sub(1);
            if *pending == 0 {
                self.pending_by_operator.remove(operator);
            }
        }
        self.pending_bytes = self.pending_bytes.saturating_sub(u64::from(original_size));
    }

    pub fn pending_bytes(&self) -> u64 {
        self.pending_bytes
    }

    pub fn record_invalid_body(
        &mut self,
        operator: [u8; 32],
        current_height: u32,
        strike_threshold: u16,
        ban_blocks: u32,
    ) {
        if strike_threshold == 0 || ban_blocks == 0 {
            return;
        }
        let strikes = self.invalid_strikes.entry(operator).or_default();
        *strikes = strikes.saturating_add(1);
        if *strikes >= strike_threshold {
            self.banned_until_height
                .insert(operator, current_height.saturating_add(ban_blocks));
            *strikes = 0;
        }
    }
}

fn valid_admission_credential(
    policy: &AdmissionPolicy,
    credential: AdmissionCredential,
    operator: &[u8; 32],
    descriptor_id: &Hash256,
) -> bool {
    match credential {
        AdmissionCredential::BootstrapAllowlist => policy.bootstrap_allowlist.contains(operator),
        AdmissionCredential::ServiceReceipt { receipt_id } => {
            policy.accepted_service_receipts.contains(&receipt_id)
        }
        AdmissionCredential::WorkStamp { nonce } => {
            if policy.minimum_request_stamp_zero_bits == 0
                || policy.minimum_request_stamp_zero_bits > 256
            {
                return false;
            }
            let mut input = Encoder::new();
            input.fixed(operator);
            input.fixed(descriptor_id);
            input.u64(nonce);
            let stamp = domain_hash("meshmine/body-request-stamp/v2", input.as_bytes());
            leading_zero_bits(&stamp) >= policy.minimum_request_stamp_zero_bits
        }
    }
}

fn leading_zero_bits(hash: &Hash256) -> u16 {
    let mut bits = 0;
    for byte in hash {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros() as u16;
            break;
        }
    }
    bits
}

fn shard_leaf(body_id: &Hash256, index: u16, shard: &[u8]) -> Hash256 {
    let mut body = Encoder::new();
    body.fixed(body_id);
    body.u16(index);
    body.bytes(shard);
    domain_hash(SHARD_DOMAIN, body.as_bytes())
}

fn create_proof(leaves: &[Hash256], index: usize) -> ShardProof {
    let sentinel = blake2b_256(&[&[]]);
    let mut level: Vec<_> = leaves
        .iter()
        .map(|leaf| blake2b_256(&[&[0], leaf]))
        .collect();
    let mut position = index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sibling = position ^ 1;
        siblings.push(level.get(sibling).copied().unwrap_or(sentinel));
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(blake2b_256(&[
                &[1],
                &pair[0],
                pair.get(1).unwrap_or(&sentinel),
            ]));
        }
        level = next;
        position >>= 1;
    }
    ShardProof {
        shard_index: index as u16,
        total_shards: leaves.len() as u16,
        siblings,
    }
}

fn verify_proof(leaf: &Hash256, proof: &ShardProof, expected_root: &Hash256) -> bool {
    let mut root = blake2b_256(&[&[0], leaf]);
    let mut position = usize::from(proof.shard_index);
    for sibling in &proof.siblings {
        root = if position & 1 == 0 {
            blake2b_256(&[&[1], &root, sibling])
        } else {
            blake2b_256(&[&[1], sibling, &root])
        };
        position >>= 1;
    }
    &root == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshmine_storage::{ProtocolJournal, ProtocolRecordKind, RedbStore};

    fn secure_tempdir() -> std::io::Result<tempfile::TempDir> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(directory)
    }

    fn encoded() -> EncodedBody {
        let bytes: Vec<_> = (0..=255).cycle().take(16_777).collect();
        encode_body(2, 2, [7; 32], &bytes, 6, 3, 100).unwrap()
    }

    #[test]
    fn reconstructs_after_configured_shard_failures() {
        let encoded = encoded();
        let original: Vec<_> = (0..=255).cycle().take(16_777).collect();
        let supplied = vec![
            encoded.shards[0].clone(),
            encoded.shards[2].clone(),
            encoded.shards[3].clone(),
            encoded.shards[5].clone(),
            encoded.shards[6].clone(),
            encoded.shards[8].clone(),
        ];
        assert_eq!(
            reconstruct_body(&encoded.descriptor, &supplied).unwrap(),
            original
        );
    }

    #[test]
    fn corrupted_shard_and_proof_fail() {
        let encoded = encoded();
        let mut corrupt = encoded.shards[..6].to_vec();
        corrupt[0].bytes[0] ^= 1;
        assert!(matches!(
            reconstruct_body(&encoded.descriptor, &corrupt),
            Err(AvailabilityError::InvalidShardProof(0))
        ));

        let mut corrupt = encoded.shards[..6].to_vec();
        corrupt[0].proof.siblings[0][0] ^= 1;
        assert!(matches!(
            reconstruct_body(&encoded.descriptor, &corrupt),
            Err(AvailabilityError::InvalidShardProof(0))
        ));
    }

    #[test]
    fn retrieval_challenge_requires_exact_valid_shards() {
        let encoded = encoded();
        let challenge = make_retrieval_challenge(&encoded.descriptor, 9, &[8; 32], 3).unwrap();
        let responses: Vec<_> = challenge
            .shard_indices
            .iter()
            .map(|index| encoded.shards[usize::from(*index)].clone())
            .collect();
        assert!(verify_challenge_response(
            &encoded.descriptor,
            &challenge,
            &responses
        ));
        assert!(!verify_challenge_response(
            &encoded.descriptor,
            &challenge,
            &responses[..2]
        ));
    }

    #[test]
    fn admission_enforces_duplicates_size_bytes_shards_and_operator_quota() {
        let encoded = encoded();
        let limits = AdmissionLimits {
            max_package_size: 20_000,
            max_pending_bytes: 20_000,
            max_pending_per_operator: 1,
            max_total_shards: 9,
        };
        let operator = [1; 32];
        let policy = AdmissionPolicy {
            bootstrap_allowlist: BTreeSet::from([operator]),
            accepted_service_receipts: BTreeSet::new(),
            minimum_request_stamp_zero_bits: 8,
        };
        let mut admission = AdmissionController::default();
        admission
            .admit(
                limits,
                &policy,
                AdmissionCredential::BootstrapAllowlist,
                operator,
                10,
                &encoded.descriptor,
            )
            .unwrap();
        assert_eq!(
            admission.admit(
                limits,
                &policy,
                AdmissionCredential::BootstrapAllowlist,
                operator,
                10,
                &encoded.descriptor,
            ),
            Err(AvailabilityError::DuplicateBody)
        );
        assert_eq!(admission.pending_bytes(), 16_777);

        let mut another = encoded.descriptor.clone();
        another.body_package_id = [2; 32];
        assert_eq!(
            admission.admit(
                limits,
                &policy,
                AdmissionCredential::BootstrapAllowlist,
                operator,
                10,
                &another,
            ),
            Err(AvailabilityError::AdmissionOperatorQuota)
        );
        admission.complete(&operator, encoded.descriptor.original_size);
        assert_eq!(admission.pending_bytes(), 0);

        another.original_size = 20_001;
        let second_policy = AdmissionPolicy {
            bootstrap_allowlist: BTreeSet::from([[2; 32]]),
            ..policy.clone()
        };
        assert_eq!(
            admission.admit(
                limits,
                &second_policy,
                AdmissionCredential::BootstrapAllowlist,
                [2; 32],
                10,
                &another,
            ),
            Err(AvailabilityError::AdmissionPackageSize)
        );

        let mut unauthorized = encoded.descriptor.clone();
        unauthorized.body_package_id = [3; 32];
        assert_eq!(
            admission.admit(
                limits,
                &policy,
                AdmissionCredential::BootstrapAllowlist,
                [9; 32],
                10,
                &unauthorized,
            ),
            Err(AvailabilityError::AdmissionCredential)
        );

        admission.record_invalid_body(operator, 10, 1, 5);
        let mut banned = encoded.descriptor.clone();
        banned.body_package_id = [4; 32];
        assert_eq!(
            admission.admit(
                limits,
                &policy,
                AdmissionCredential::BootstrapAllowlist,
                operator,
                11,
                &banned,
            ),
            Err(AvailabilityError::AdmissionBanned)
        );
        assert!(
            admission
                .admit(
                    limits,
                    &policy,
                    AdmissionCredential::BootstrapAllowlist,
                    operator,
                    15,
                    &banned,
                )
                .is_ok()
        );
    }

    #[test]
    fn work_stamps_and_service_receipts_are_bound_and_not_replayable() {
        let encoded = encoded();
        let operator = [9; 32];
        let receipt_id = [8; 32];
        let policy = AdmissionPolicy {
            bootstrap_allowlist: BTreeSet::new(),
            accepted_service_receipts: BTreeSet::from([receipt_id]),
            minimum_request_stamp_zero_bits: 8,
        };
        let limits = AdmissionLimits {
            max_package_size: 20_000,
            max_pending_bytes: 100_000,
            max_pending_per_operator: 4,
            max_total_shards: 9,
        };
        let mut controller = AdmissionController::default();
        controller
            .admit(
                limits,
                &policy,
                AdmissionCredential::ServiceReceipt { receipt_id },
                operator,
                1,
                &encoded.descriptor,
            )
            .unwrap();

        let mut second = encoded.descriptor.clone();
        second.body_package_id = [6; 32];
        assert_eq!(
            controller.admit(
                limits,
                &policy,
                AdmissionCredential::ServiceReceipt { receipt_id },
                operator,
                1,
                &second,
            ),
            Err(AvailabilityError::AdmissionCredential)
        );

        let descriptor_id = second.object_id();
        let mut third = second.clone();
        third.body_package_id = [5; 32];
        let third_descriptor_id = third.object_id();
        let nonce = (0..u64::MAX)
            .find(|nonce| {
                valid_admission_credential(
                    &policy,
                    AdmissionCredential::WorkStamp { nonce: *nonce },
                    &operator,
                    &descriptor_id,
                ) && !valid_admission_credential(
                    &policy,
                    AdmissionCredential::WorkStamp { nonce: *nonce },
                    &operator,
                    &third_descriptor_id,
                )
            })
            .unwrap();
        controller
            .admit(
                limits,
                &policy,
                AdmissionCredential::WorkStamp { nonce },
                operator,
                1,
                &second,
            )
            .unwrap();

        assert_eq!(
            controller.admit(
                limits,
                &policy,
                AdmissionCredential::WorkStamp { nonce },
                operator,
                1,
                &third,
            ),
            Err(AvailabilityError::AdmissionCredential)
        );
    }

    #[test]
    fn pruning_waits_for_every_height_and_settlement_obligation() {
        let descriptor = encoded().descriptor;
        let policy = AvailabilityRetentionPolicy {
            reorganization_horizon: 20,
            audit_retention_blocks: 10,
        };
        let mut state = AvailabilitySettlementState {
            parent_height: 90,
            session_closed: true,
            mask_opened: true,
            discovered_block_safely_propagated: true,
            storage_compensation_end_height: 105,
            audit_retention_end_height: 102,
        };
        // Later-of height is audit 112, beyond expiry 100/reorg 110/service 105.
        assert!(!policy.may_prune(&descriptor, state, 111));
        assert!(policy.may_prune(&descriptor, state, 112));
        state.mask_opened = false;
        assert!(!policy.may_prune(&descriptor, state, 1_000));
    }

    #[test]
    fn body_validation_descriptor_and_shards_survive_restart() {
        let directory = secure_tempdir().unwrap();
        let path = directory.path().join("availability.redb");
        let body = vec![0x33; 8192];
        let body_id = [7; 32];
        let encoded = encode_body(2, 2, body_id, &body, 4, 2, 100).unwrap();
        let descriptor_id = encoded.descriptor.object_id();
        {
            let store = RedbStore::create(&path).unwrap();
            persist_encoded_body(
                &ProtocolJournal::new(&store),
                body_id,
                &body,
                [8; 32],
                &encoded,
            )
            .unwrap();
        }
        let store = RedbStore::create(&path).unwrap();
        let journal = ProtocolJournal::new(&store);
        assert_eq!(
            journal
                .load(ProtocolRecordKind::BodyPackage, &body_id)
                .unwrap(),
            Some(body)
        );
        assert!(
            journal
                .load(ProtocolRecordKind::ErasureDescriptor, &descriptor_id)
                .unwrap()
                .is_some()
        );
        let mut shard_key = descriptor_id.to_vec();
        shard_key.extend_from_slice(&0u16.to_le_bytes());
        assert!(
            journal
                .load(ProtocolRecordKind::BodyShard, &shard_key)
                .unwrap()
                .is_some()
        );
    }
}
