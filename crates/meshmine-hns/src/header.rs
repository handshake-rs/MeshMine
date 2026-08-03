use blake2::{Blake2bVar, digest::VariableOutput};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

pub const HASH_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;
pub const HEADER_SIZE: usize = 236;
pub const MINER_HEADER_SIZE: usize = 256;

pub type Hash256 = [u8; HASH_SIZE];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HeaderError {
    #[error("invalid HNS header length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("miner header contains invalid deterministic padding")]
    InvalidPadding,
}

/// The 236-byte Handshake consensus header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HnsHeader {
    pub nonce: u32,
    pub time: u64,
    pub prev_block: Hash256,
    pub tree_root: Hash256,
    pub extra_nonce: [u8; NONCE_SIZE],
    pub reserved_root: Hash256,
    pub witness_root: Hash256,
    pub merkle_root: Hash256,
    pub version: u32,
    pub bits: u32,
    pub mask: Hash256,
}

/// The 256-byte representation sent to an HNS miner.
///
/// It carries `mask_hash`, not the secret mask, exactly like
/// `AbstractBlock.toMiner()` in `HNS node`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinerHeader {
    pub nonce: u32,
    pub time: u64,
    pub prev_block: Hash256,
    pub tree_root: Hash256,
    pub mask_hash: Hash256,
    pub extra_nonce: [u8; NONCE_SIZE],
    pub reserved_root: Hash256,
    pub witness_root: Hash256,
    pub merkle_root: Hash256,
    pub version: u32,
    pub bits: u32,
}

/// Precomputed immutable portion of an HNS miner header.
///
/// A mining loop changes the nonce far more often than any other field.
/// Keeping the subheader commitment and deterministic padding outside that
/// loop removes two BLAKE2b computations per attempted nonce while preserving
/// the exact scalar `MinerHeader::share_hash` result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedMinerHasher {
    preheader: [u8; 128],
    padding8: [u8; 8],
    padding32: [u8; 32],
}

impl Default for HnsHeader {
    fn default() -> Self {
        Self {
            nonce: 0,
            time: 0,
            prev_block: [0; HASH_SIZE],
            tree_root: [0; HASH_SIZE],
            extra_nonce: [0; NONCE_SIZE],
            reserved_root: [0; HASH_SIZE],
            witness_root: [0; HASH_SIZE],
            merkle_root: [0; HASH_SIZE],
            version: 0,
            bits: 0,
            mask: [0; HASH_SIZE],
        }
    }
}

impl HnsHeader {
    pub fn from_bytes(data: &[u8]) -> Result<Self, HeaderError> {
        if data.len() != HEADER_SIZE {
            return Err(HeaderError::InvalidLength {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        let mut cursor = 0;
        Ok(Self {
            nonce: read_u32(data, &mut cursor),
            time: read_u64(data, &mut cursor),
            prev_block: read_array(data, &mut cursor),
            tree_root: read_array(data, &mut cursor),
            extra_nonce: read_array(data, &mut cursor),
            reserved_root: read_array(data, &mut cursor),
            witness_root: read_array(data, &mut cursor),
            merkle_root: read_array(data, &mut cursor),
            version: read_u32(data, &mut cursor),
            bits: read_u32(data, &mut cursor),
            mask: read_array(data, &mut cursor),
        })
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0; HEADER_SIZE];
        let mut cursor = 0;
        write_u32(&mut out, &mut cursor, self.nonce);
        write_u64(&mut out, &mut cursor, self.time);
        write_bytes(&mut out, &mut cursor, &self.prev_block);
        write_bytes(&mut out, &mut cursor, &self.tree_root);
        write_bytes(&mut out, &mut cursor, &self.extra_nonce);
        write_bytes(&mut out, &mut cursor, &self.reserved_root);
        write_bytes(&mut out, &mut cursor, &self.witness_root);
        write_bytes(&mut out, &mut cursor, &self.merkle_root);
        write_u32(&mut out, &mut cursor, self.version);
        write_u32(&mut out, &mut cursor, self.bits);
        write_bytes(&mut out, &mut cursor, &self.mask);
        debug_assert_eq!(cursor, HEADER_SIZE);
        out
    }

    /// Repeating bytes derived from `prevBlock XOR treeRoot`.
    pub fn padding(&self, size: usize) -> Vec<u8> {
        deterministic_padding(&self.prev_block, &self.tree_root, size)
    }

    pub fn subheader(&self) -> [u8; 128] {
        subheader(
            &self.extra_nonce,
            &self.reserved_root,
            &self.witness_root,
            &self.merkle_root,
            self.version,
            self.bits,
        )
    }

    pub fn sub_hash(&self) -> Hash256 {
        blake2b_256(&[&self.subheader()])
    }

    pub fn mask_hash(&self) -> Hash256 {
        blake2b_256(&[&self.prev_block, &self.mask])
    }

    pub fn commit_hash(&self) -> Hash256 {
        blake2b_256(&[&self.sub_hash(), &self.mask_hash()])
    }

    pub fn preheader(&self) -> [u8; 128] {
        preheader(
            self.nonce,
            self.time,
            &self.prev_block,
            &self.tree_root,
            &self.commit_hash(),
        )
    }

    pub fn share_hash(&self) -> Hash256 {
        share_hash_from_preheader(&self.preheader(), &self.prev_block, &self.tree_root)
    }

    pub fn pow_hash(&self) -> Hash256 {
        xor_hashes(&self.share_hash(), &self.mask)
    }

    pub fn to_miner(&self) -> [u8; MINER_HEADER_SIZE] {
        MinerHeader::from(self).to_bytes()
    }
}

impl From<&HnsHeader> for MinerHeader {
    fn from(header: &HnsHeader) -> Self {
        Self {
            nonce: header.nonce,
            time: header.time,
            prev_block: header.prev_block,
            tree_root: header.tree_root,
            mask_hash: header.mask_hash(),
            extra_nonce: header.extra_nonce,
            reserved_root: header.reserved_root,
            witness_root: header.witness_root,
            merkle_root: header.merkle_root,
            version: header.version,
            bits: header.bits,
        }
    }
}

impl MinerHeader {
    pub fn from_bytes(data: &[u8]) -> Result<Self, HeaderError> {
        if data.len() != MINER_HEADER_SIZE {
            return Err(HeaderError::InvalidLength {
                expected: MINER_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let mut cursor = 0;
        let nonce = read_u32(data, &mut cursor);
        let time = read_u64(data, &mut cursor);
        let padding: [u8; 20] = read_array(data, &mut cursor);
        let prev_block = read_array(data, &mut cursor);
        let tree_root = read_array(data, &mut cursor);

        if padding != deterministic_padding(&prev_block, &tree_root, 20).as_slice() {
            return Err(HeaderError::InvalidPadding);
        }

        Ok(Self {
            nonce,
            time,
            prev_block,
            tree_root,
            mask_hash: read_array(data, &mut cursor),
            extra_nonce: read_array(data, &mut cursor),
            reserved_root: read_array(data, &mut cursor),
            witness_root: read_array(data, &mut cursor),
            merkle_root: read_array(data, &mut cursor),
            version: read_u32(data, &mut cursor),
            bits: read_u32(data, &mut cursor),
        })
    }

    pub fn to_bytes(&self) -> [u8; MINER_HEADER_SIZE] {
        let mut out = [0; MINER_HEADER_SIZE];
        let mut cursor = 0;
        write_u32(&mut out, &mut cursor, self.nonce);
        write_u64(&mut out, &mut cursor, self.time);
        write_bytes(
            &mut out,
            &mut cursor,
            &deterministic_padding(&self.prev_block, &self.tree_root, 20),
        );
        write_bytes(&mut out, &mut cursor, &self.prev_block);
        write_bytes(&mut out, &mut cursor, &self.tree_root);
        write_bytes(&mut out, &mut cursor, &self.mask_hash);
        write_bytes(&mut out, &mut cursor, &self.extra_nonce);
        write_bytes(&mut out, &mut cursor, &self.reserved_root);
        write_bytes(&mut out, &mut cursor, &self.witness_root);
        write_bytes(&mut out, &mut cursor, &self.merkle_root);
        write_u32(&mut out, &mut cursor, self.version);
        write_u32(&mut out, &mut cursor, self.bits);
        debug_assert_eq!(cursor, MINER_HEADER_SIZE);
        out
    }

    pub fn subheader(&self) -> [u8; 128] {
        subheader(
            &self.extra_nonce,
            &self.reserved_root,
            &self.witness_root,
            &self.merkle_root,
            self.version,
            self.bits,
        )
    }

    pub fn sub_hash(&self) -> Hash256 {
        blake2b_256(&[&self.subheader()])
    }

    pub fn commit_hash(&self) -> Hash256 {
        blake2b_256(&[&self.sub_hash(), &self.mask_hash])
    }

    pub fn preheader(&self) -> [u8; 128] {
        preheader(
            self.nonce,
            self.time,
            &self.prev_block,
            &self.tree_root,
            &self.commit_hash(),
        )
    }

    pub fn share_hash(&self) -> Hash256 {
        share_hash_from_preheader(&self.preheader(), &self.prev_block, &self.tree_root)
    }

    pub fn prepare_hasher(&self) -> PreparedMinerHasher {
        PreparedMinerHasher::new(self)
    }
}

impl PreparedMinerHasher {
    pub fn new(header: &MinerHeader) -> Self {
        let padding8 = deterministic_padding(&header.prev_block, &header.tree_root, 8)
            .try_into()
            .expect("fixed eight-byte padding");
        let padding32 = deterministic_padding(&header.prev_block, &header.tree_root, 32)
            .try_into()
            .expect("fixed 32-byte padding");
        Self {
            preheader: header.preheader(),
            padding8,
            padding32,
        }
    }

    /// Hash one nonce without recomputing the immutable subheader commitment.
    pub fn share_hash(&self, nonce: u32) -> Hash256 {
        let mut preheader = self.preheader;
        preheader[..4].copy_from_slice(&nonce.to_le_bytes());
        let left = blake2b_512(&[&preheader]);
        let mut sha3 = Sha3_256::new();
        Digest::update(&mut sha3, preheader);
        Digest::update(&mut sha3, self.padding8);
        let right: Hash256 = sha3.finalize().into();
        blake2b_256(&[&left, &self.padding32, &right])
    }
}

pub fn blake2b_256(parts: &[&[u8]]) -> Hash256 {
    let mut state = Blake2bVar::new(HASH_SIZE).expect("valid BLAKE2b output length");
    for part in parts {
        blake2::digest::Update::update(&mut state, part);
    }
    let mut out = [0; HASH_SIZE];
    state
        .finalize_variable(&mut out)
        .expect("output buffer has configured length");
    out
}

pub fn blake2b_512(parts: &[&[u8]]) -> [u8; 64] {
    let mut state = Blake2bVar::new(64).expect("valid BLAKE2b output length");
    for part in parts {
        blake2::digest::Update::update(&mut state, part);
    }
    let mut out = [0; 64];
    state
        .finalize_variable(&mut out)
        .expect("output buffer has configured length");
    out
}

fn deterministic_padding(prev_block: &Hash256, tree_root: &Hash256, size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| prev_block[index % HASH_SIZE] ^ tree_root[index % HASH_SIZE])
        .collect()
}

fn subheader(
    extra_nonce: &[u8; NONCE_SIZE],
    reserved_root: &Hash256,
    witness_root: &Hash256,
    merkle_root: &Hash256,
    version: u32,
    bits: u32,
) -> [u8; 128] {
    let mut out = [0; 128];
    let mut cursor = 0;
    write_bytes(&mut out, &mut cursor, extra_nonce);
    write_bytes(&mut out, &mut cursor, reserved_root);
    write_bytes(&mut out, &mut cursor, witness_root);
    write_bytes(&mut out, &mut cursor, merkle_root);
    write_u32(&mut out, &mut cursor, version);
    write_u32(&mut out, &mut cursor, bits);
    debug_assert_eq!(cursor, 128);
    out
}

fn preheader(
    nonce: u32,
    time: u64,
    prev_block: &Hash256,
    tree_root: &Hash256,
    commit_hash: &Hash256,
) -> [u8; 128] {
    let mut out = [0; 128];
    let mut cursor = 0;
    write_u32(&mut out, &mut cursor, nonce);
    write_u64(&mut out, &mut cursor, time);
    write_bytes(
        &mut out,
        &mut cursor,
        &deterministic_padding(prev_block, tree_root, 20),
    );
    write_bytes(&mut out, &mut cursor, prev_block);
    write_bytes(&mut out, &mut cursor, tree_root);
    write_bytes(&mut out, &mut cursor, commit_hash);
    debug_assert_eq!(cursor, 128);
    out
}

fn share_hash_from_preheader(
    preheader: &[u8; 128],
    prev_block: &Hash256,
    tree_root: &Hash256,
) -> Hash256 {
    let left = blake2b_512(&[preheader]);
    let mut sha3 = Sha3_256::new();
    Digest::update(&mut sha3, preheader);
    Digest::update(&mut sha3, deterministic_padding(prev_block, tree_root, 8));
    let right: Hash256 = sha3.finalize().into();
    blake2b_256(&[
        &left,
        &deterministic_padding(prev_block, tree_root, 32),
        &right,
    ])
}

fn xor_hashes(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut out = [0; HASH_SIZE];
    for index in 0..HASH_SIZE {
        out[index] = left[index] ^ right[index];
    }
    out
}

fn read_array<const N: usize>(data: &[u8], cursor: &mut usize) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&data[*cursor..*cursor + N]);
    *cursor += N;
    out
}

fn read_u32(data: &[u8], cursor: &mut usize) -> u32 {
    u32::from_le_bytes(read_array(data, cursor))
}

fn read_u64(data: &[u8], cursor: &mut usize) -> u64 {
    u64::from_le_bytes(read_array(data, cursor))
}

fn write_bytes<const N: usize>(out: &mut [u8; N], cursor: &mut usize, data: &[u8]) {
    out[*cursor..*cursor + data.len()].copy_from_slice(data);
    *cursor += data.len();
}

fn write_u32<const N: usize>(out: &mut [u8; N], cursor: &mut usize, value: u32) {
    write_bytes(out, cursor, &value.to_le_bytes());
}

fn write_u64<const N: usize>(out: &mut [u8; N], cursor: &mut usize, value: u64) {
    write_bytes(out, cursor, &value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_and_miner_lengths_are_consensus_exact() {
        let header = HnsHeader::default();
        assert_eq!(header.to_bytes().len(), 236);
        assert_eq!(header.subheader().len(), 128);
        assert_eq!(header.preheader().len(), 128);
        assert_eq!(header.to_miner().len(), 256);
    }

    #[test]
    fn consensus_header_round_trips() {
        let header = HnsHeader {
            nonce: u32::MAX,
            time: u64::MAX,
            prev_block: [0x55; HASH_SIZE],
            tree_root: [0xaa; HASH_SIZE],
            extra_nonce: [0x33; NONCE_SIZE],
            reserved_root: [0x44; HASH_SIZE],
            witness_root: [0x66; HASH_SIZE],
            merkle_root: [0x77; HASH_SIZE],
            version: 0xdead_beef,
            bits: 0x1900_896c,
            mask: [0x88; HASH_SIZE],
        };
        assert_eq!(HnsHeader::from_bytes(&header.to_bytes()), Ok(header));
    }

    #[test]
    fn miner_parser_rejects_wrong_padding() {
        let header = HnsHeader::default();
        let mut miner = header.to_miner();
        miner[12] ^= 1;
        assert_eq!(
            MinerHeader::from_bytes(&miner),
            Err(HeaderError::InvalidPadding)
        );
    }

    #[test]
    fn miner_share_hash_matches_full_header() {
        let header = HnsHeader {
            prev_block: [0x19; HASH_SIZE],
            tree_root: [0xa4; HASH_SIZE],
            mask: [0x5c; HASH_SIZE],
            ..HnsHeader::default()
        };
        let miner = MinerHeader::from_bytes(&header.to_miner()).unwrap();
        assert_eq!(miner.share_hash(), header.share_hash());
    }

    #[test]
    fn prepared_hasher_matches_scalar_nonce_updates() {
        let mut header = MinerHeader {
            nonce: 0,
            time: 1_717_171_717,
            prev_block: [1; 32],
            tree_root: [2; 32],
            mask_hash: [3; 32],
            extra_nonce: [4; 24],
            reserved_root: [5; 32],
            witness_root: [6; 32],
            merkle_root: [7; 32],
            version: 8,
            bits: 0x1c00_ffff,
        };
        let prepared = header.prepare_hasher();
        for nonce in [0, 1, 2, 65_535, u32::MAX] {
            header.nonce = nonce;
            assert_eq!(prepared.share_hash(nonce), header.share_hash());
        }
    }

    #[test]
    fn parses_live_hns_getwork_vector() {
        // Captured read-only from the running HNS node 8.99.0 node at upstream
        // commit 698e252e. The secret mask is intentionally unavailable.
        let data = hex::decode(concat!(
            "00000000b03d5a6a00000000d22bfc353fd1bef18c3ea20978d8f7cce44f67d9",
            "000000000000000e210abcac97e50a15c9373ba1984ace65bf4765930ae6270c",
            "d22bfc353fd1beffad341ea5ef3dfdd92d785c7829283efbbc84007d09ab6458",
            "ca5e999a826300498ff9e2342c648da16a19489ebb04cd7493d52e5509bf4b08",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000567d3209606c1f2d",
            "16f9724cb68ad9f96e402defd7e50e3f6d7679960c0a3ac5ba781e839fb3021c",
            "2aca99ae764d215d3ba32e429fcc4dec4a534b9e0318304c0000000067ae2519"
        ))
        .unwrap();
        let expected: Hash256 =
            hex::decode("b9141e920058d9b2254ef37fe8060ef4941eab6d471b3bc41256e427e2393c35")
                .unwrap()
                .try_into()
                .unwrap();

        let miner = MinerHeader::from_bytes(&data).unwrap();
        assert_eq!(miner.time, 1_784_298_928);
        assert_eq!(miner.bits, 0x1925_ae67);
        assert_eq!(miner.share_hash(), expected);
        assert_eq!(miner.to_bytes().as_slice(), data);
    }
}
