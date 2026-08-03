//! Stable block-body commitments and deterministic coinbase layout helpers.

mod availability;

pub use availability::*;

use meshmine_codec::Encoder;
use meshmine_hns::{Hash256, blake2b_256};
use meshmine_types::{BlockBodyPackageV2, SignatureBytes, TemplateCoreV2, UnsignedObject};
use thiserror::Error;

pub const COINBASE_COMMITMENT_MAGIC: [u8; 4] = *b"HNSM";
pub const COINBASE_COMMITMENT_SIZE: usize = 147;
const VALIDATION_DOMAIN: &str = "meshmine/consensus-validation-result/v3";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseCommitmentV2 {
    pub protocol_version: u16,
    pub network_id: u8,
    pub template_core_id: Hash256,
    pub payout_snapshot_id: Hash256,
    pub payout_plan_id: Hash256,
    pub plan_sequence: u64,
    pub operator_key_hash: Hash256,
    pub flags: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutOutput {
    pub hns_address_version: u8,
    pub hns_address_hash: Vec<u8>,
    pub value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseOutputSkeleton {
    pub first_work_or_fallback: PayoutOutput,
    pub mandatory_claim_airdrop_outputs: Vec<PayoutOutput>,
    pub remaining_work_outputs: Vec<PayoutOutput>,
    pub service_outputs: Vec<PayoutOutput>,
    pub operator_fee_output: Option<PayoutOutput>,
}

/// Exact HNS base-transaction space that must be reserved for the output-count
/// prefix and ordinary MeshMine payout outputs. Mandatory claim/airdrop output
/// payloads are sized separately from their exact covenant encodings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayoutWeightReservation {
    pub final_output_count: usize,
    pub ordinary_payout_output_count: usize,
    pub reserved_base_bytes: usize,
    pub reserved_weight: usize,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BodyError {
    #[error("invalid coinbase commitment length: expected 147, got {0}")]
    InvalidCommitmentLength(usize),
    #[error("invalid coinbase commitment magic")]
    InvalidCommitmentMagic,
    #[error("body package's template ID does not match its TemplateCore")]
    TemplateIdMismatch,
    #[error("body package and TemplateCore version/network differ")]
    TemplateContextMismatch,
    #[error("coinbase output destinations are not canonically sorted")]
    UnsortedOutputs,
    #[error("invalid HNS payout address")]
    InvalidPayoutAddress,
    #[error("coinbase payout size overflow")]
    PayoutSizeOverflow,
}

impl CoinbaseCommitmentV2 {
    pub fn for_template(template: &TemplateCoreV2, flags: u32) -> Self {
        Self {
            protocol_version: template.protocol_version,
            network_id: template.network_id,
            template_core_id: template.object_id(),
            payout_snapshot_id: template.payout_snapshot_id,
            payout_plan_id: template.payout_plan_id,
            plan_sequence: template.plan_sequence,
            operator_key_hash: blake2b_256(&[&template.operator_pubkey]),
            flags,
        }
    }

    pub fn encode(&self) -> [u8; COINBASE_COMMITMENT_SIZE] {
        let mut out = [0; COINBASE_COMMITMENT_SIZE];
        let mut offset = 0;
        write(&mut out, &mut offset, &COINBASE_COMMITMENT_MAGIC);
        write(&mut out, &mut offset, &self.protocol_version.to_le_bytes());
        write(&mut out, &mut offset, &[self.network_id]);
        write(&mut out, &mut offset, &self.template_core_id);
        write(&mut out, &mut offset, &self.payout_snapshot_id);
        write(&mut out, &mut offset, &self.payout_plan_id);
        write(&mut out, &mut offset, &self.plan_sequence.to_le_bytes());
        write(&mut out, &mut offset, &self.operator_key_hash);
        write(&mut out, &mut offset, &self.flags.to_le_bytes());
        debug_assert_eq!(offset, COINBASE_COMMITMENT_SIZE);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BodyError> {
        if bytes.len() != COINBASE_COMMITMENT_SIZE {
            return Err(BodyError::InvalidCommitmentLength(bytes.len()));
        }
        if bytes[..4] != COINBASE_COMMITMENT_MAGIC {
            return Err(BodyError::InvalidCommitmentMagic);
        }
        let mut offset = 4;
        Ok(Self {
            protocol_version: u16::from_le_bytes(read(bytes, &mut offset)),
            network_id: read::<1>(bytes, &mut offset)[0],
            template_core_id: read(bytes, &mut offset),
            payout_snapshot_id: read(bytes, &mut offset),
            payout_plan_id: read(bytes, &mut offset),
            plan_sequence: u64::from_le_bytes(read(bytes, &mut offset)),
            operator_key_hash: read(bytes, &mut offset),
            flags: u32::from_le_bytes(read(bytes, &mut offset)),
        })
    }
}

impl CoinbaseOutputSkeleton {
    pub fn validate_sorted(&self) -> Result<(), BodyError> {
        if !destinations_sorted(&self.remaining_work_outputs)
            || !destinations_sorted(&self.service_outputs)
        {
            return Err(BodyError::UnsortedOutputs);
        }
        Ok(())
    }

    pub fn ordered_outputs(&self) -> Result<Vec<&PayoutOutput>, BodyError> {
        self.validate_sorted()?;
        let mut outputs = Vec::with_capacity(
            1 + self.mandatory_claim_airdrop_outputs.len()
                + self.remaining_work_outputs.len()
                + self.service_outputs.len()
                + usize::from(self.operator_fee_output.is_some()),
        );
        outputs.push(&self.first_work_or_fallback);
        outputs.extend(&self.mandatory_claim_airdrop_outputs);
        outputs.extend(&self.remaining_work_outputs);
        outputs.extend(&self.service_outputs);
        outputs.extend(self.operator_fee_output.iter());
        Ok(outputs)
    }

    /// Size the ordinary NONE-covenant payout outputs exactly as HNS node does:
    /// value(8) + address version(1) + address length(1) + address bytes +
    /// covenant type(1) + covenant item count varint(1).
    pub fn payout_weight_reservation(&self) -> Result<PayoutWeightReservation, BodyError> {
        self.validate_sorted()?;
        let ordinary = std::iter::once(&self.first_work_or_fallback)
            .chain(&self.remaining_work_outputs)
            .chain(&self.service_outputs)
            .chain(self.operator_fee_output.iter());
        let mut ordinary_payout_output_count = 0usize;
        let mut ordinary_output_bytes = 0usize;
        for output in ordinary {
            validate_hns_address(output)?;
            ordinary_payout_output_count = ordinary_payout_output_count
                .checked_add(1)
                .ok_or(BodyError::PayoutSizeOverflow)?;
            ordinary_output_bytes = ordinary_output_bytes
                .checked_add(12usize)
                .and_then(|size| size.checked_add(output.hns_address_hash.len()))
                .ok_or(BodyError::PayoutSizeOverflow)?;
        }
        let final_output_count = self
            .mandatory_claim_airdrop_outputs
            .len()
            .checked_add(ordinary_payout_output_count)
            .ok_or(BodyError::PayoutSizeOverflow)?;
        let reserved_base_bytes = ordinary_output_bytes
            .checked_add(hns_varint_size(final_output_count))
            .ok_or(BodyError::PayoutSizeOverflow)?;
        let reserved_weight = reserved_base_bytes
            .checked_mul(4)
            .ok_or(BodyError::PayoutSizeOverflow)?;
        Ok(PayoutWeightReservation {
            final_output_count,
            ordinary_payout_output_count,
            reserved_base_bytes,
            reserved_weight,
        })
    }
}

/// Hash the exact no-PoW validation subject without introducing dynamic mask,
/// nonce, assignment, or DAG state into the stable body package.
pub fn validation_result_hash(
    network_id: u8,
    template_core_id: &Hash256,
    coinbase_raw: &[u8],
    transactions_raw: &[Vec<u8>],
) -> Hash256 {
    let mut body = Encoder::new();
    body.u16(2);
    body.u8(network_id);
    body.fixed(template_core_id);
    body.bytes(coinbase_raw);
    body.varint(transactions_raw.len() as u64);
    for transaction in transactions_raw {
        body.bytes(transaction);
    }
    let mut tagged = Encoder::new();
    tagged.bytes(VALIDATION_DOMAIN.as_bytes());
    tagged.fixed(body.as_bytes());
    blake2b_256(&[tagged.as_bytes()])
}

#[allow(clippy::too_many_arguments)]
pub fn build_body_package(
    template_core: TemplateCoreV2,
    coinbase_raw: Vec<u8>,
    transactions_raw: Vec<Vec<u8>>,
    merkle_root: Hash256,
    witness_root: Hash256,
    tree_root: Hash256,
    reserved_root: Hash256,
    block_weight: u32,
    block_sigops: u32,
    miner_subsidy: u64,
    ordinary_transaction_fees: u64,
    claim_airdrop_principal: u64,
    claim_airdrop_fees: u64,
    operator_fee_value: u64,
    work_service_subsidy_value: u64,
    operator_signature: SignatureBytes,
) -> Result<BlockBodyPackageV2, BodyError> {
    let template_core_id = template_core.object_id();
    let consensus_validation_result_hash = validation_result_hash(
        template_core.network_id,
        &template_core_id,
        &coinbase_raw,
        &transactions_raw,
    );
    let package = BlockBodyPackageV2 {
        protocol_version: template_core.protocol_version,
        network_id: template_core.network_id,
        template_core,
        template_core_id,
        coinbase_raw,
        transactions_raw,
        merkle_root,
        witness_root,
        tree_root,
        reserved_root,
        block_weight,
        block_sigops,
        miner_subsidy,
        ordinary_transaction_fees,
        claim_airdrop_principal,
        claim_airdrop_fees,
        operator_fee_value,
        work_service_subsidy_value,
        consensus_validation_result_hash,
        operator_signature,
    };
    validate_body_package(&package)?;
    Ok(package)
}

pub fn validate_body_package(package: &BlockBodyPackageV2) -> Result<(), BodyError> {
    if package.protocol_version != package.template_core.protocol_version
        || package.network_id != package.template_core.network_id
    {
        return Err(BodyError::TemplateContextMismatch);
    }
    if package.template_core.object_id() != package.template_core_id {
        return Err(BodyError::TemplateIdMismatch);
    }
    Ok(())
}

fn destinations_sorted(outputs: &[PayoutOutput]) -> bool {
    outputs.windows(2).all(|pair| {
        (pair[0].hns_address_version, &pair[0].hns_address_hash)
            <= (pair[1].hns_address_version, &pair[1].hns_address_hash)
    })
}

fn validate_hns_address(output: &PayoutOutput) -> Result<(), BodyError> {
    let length = output.hns_address_hash.len();
    if output.hns_address_version > 31
        || !(2..=40).contains(&length)
        || (output.hns_address_version == 0 && length != 20 && length != 32)
    {
        return Err(BodyError::InvalidPayoutAddress);
    }
    Ok(())
}

fn hns_varint_size(value: usize) -> usize {
    if value < 0xfd {
        1
    } else if value <= 0xffff {
        3
    } else if value <= 0xffff_ffff {
        5
    } else {
        9
    }
}

fn write<const N: usize>(out: &mut [u8; N], offset: &mut usize, bytes: &[u8]) {
    out[*offset..*offset + bytes.len()].copy_from_slice(bytes);
    *offset += bytes.len();
}

fn read<const N: usize>(bytes: &[u8], offset: &mut usize) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&bytes[*offset..*offset + N]);
    *offset += N;
    out
}

#[cfg(test)]
mod tests {
    use meshmine_types::{CORE_V2, U256};

    use super::*;

    fn template() -> TemplateCoreV2 {
        TemplateCoreV2 {
            protocol_version: CORE_V2,
            network_id: 2,
            hns_parent_hash: [1; 32],
            hns_parent_height: 2,
            operator_pubkey: [3; 32],
            operator_fee_bucket_id: [4; 32],
            payout_snapshot_id: [5; 32],
            payout_plan_id: [6; 32],
            plan_sequence: 7,
            ordered_non_coinbase_txids: vec![[8; 32]],
            ordered_claim_ids: vec![],
            ordered_airdrop_ids: vec![],
            block_version: 9,
            bits: 0x207f_ffff,
            minimum_ntime: 10,
            policy_commitment: [11; 32],
        }
    }

    fn package() -> BlockBodyPackageV2 {
        build_body_package(
            template(),
            vec![1, 2],
            vec![vec![3, 4]],
            [12; 32],
            [13; 32],
            [14; 32],
            [15; 32],
            16,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            SignatureBytes(vec![24; 64]),
        )
        .unwrap()
    }

    #[test]
    fn coinbase_commitment_is_exact_and_round_trips() {
        let commitment = CoinbaseCommitmentV2::for_template(&template(), 0x1234_5678);
        let encoded = commitment.encode();
        assert_eq!(&encoded[..4], b"HNSM");
        assert_eq!(encoded.len(), COINBASE_COMMITMENT_SIZE);
        assert_eq!(CoinbaseCommitmentV2::decode(&encoded).unwrap(), commitment);
    }

    #[test]
    fn body_id_is_stable_across_dynamic_mining_state() {
        let package = package();
        let id = package.object_id();

        // These dynamic objects reference the body but cannot flow backward
        // into its encoded fields.
        let _mask = [25; 32];
        let _dag_parents = [[26; 32], [27; 32]];
        let _assignment_target = U256([28; 32]);
        assert_eq!(package.object_id(), id);

        let mut changed = package.clone();
        changed.operator_signature = SignatureBytes(vec![99; 64]);
        assert_eq!(changed.object_id(), id);

        changed.coinbase_raw.push(42);
        assert_ne!(changed.object_id(), id);
        changed = package.clone();
        changed.template_core.operator_fee_bucket_id = [42; 32];
        assert_ne!(changed.object_id(), id);
    }

    #[test]
    fn coinbase_skeleton_preserves_required_class_order() {
        let output = |byte| PayoutOutput {
            hns_address_version: 0,
            hns_address_hash: vec![byte; 20],
            value: u64::from(byte),
        };
        let skeleton = CoinbaseOutputSkeleton {
            first_work_or_fallback: output(1),
            mandatory_claim_airdrop_outputs: vec![output(9)],
            remaining_work_outputs: vec![output(2), output(3)],
            service_outputs: vec![output(4), output(5)],
            operator_fee_output: Some(output(6)),
        };
        let values: Vec<_> = skeleton
            .ordered_outputs()
            .unwrap()
            .into_iter()
            .map(|output| output.value)
            .collect();
        assert_eq!(values, [1, 9, 2, 3, 4, 5, 6]);

        // Five ordinary P2WPKH payouts are 32 bytes each under exact HNS node
        // serialization, plus the one-byte final output-count prefix. The
        // mandatory claim payload is accounted by the body builder itself.
        let reservation = skeleton.payout_weight_reservation().unwrap();
        assert_eq!(reservation.final_output_count, 7);
        assert_eq!(reservation.ordinary_payout_output_count, 6);
        assert_eq!(reservation.reserved_base_bytes, 193);
        assert_eq!(reservation.reserved_weight, 772);
    }

    #[test]
    fn payout_reservation_tracks_hns_varint_boundary_and_address_rules() {
        let output = PayoutOutput {
            hns_address_version: 0,
            hns_address_hash: vec![1; 20],
            value: 1,
        };
        let skeleton = CoinbaseOutputSkeleton {
            first_work_or_fallback: output.clone(),
            mandatory_claim_airdrop_outputs: vec![output.clone(); 252],
            remaining_work_outputs: vec![],
            service_outputs: vec![],
            operator_fee_output: None,
        };
        let reservation = skeleton.payout_weight_reservation().unwrap();
        assert_eq!(reservation.final_output_count, 253);
        assert_eq!(reservation.reserved_base_bytes, 35);

        let mut invalid = skeleton;
        invalid.first_work_or_fallback.hns_address_hash = vec![1; 21];
        assert_eq!(
            invalid.payout_weight_reservation(),
            Err(BodyError::InvalidPayoutAddress)
        );
    }
}
