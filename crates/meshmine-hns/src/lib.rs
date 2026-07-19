//! Handshake-native primitives used by MeshMine.
//!
//! This crate mirrors `hsd`'s consensus-sensitive header and proof code. Hash
//! bytes are kept in their canonical HNS wire order and proof comparisons
//! interpret them as unsigned big-endian integers.

mod header;
mod merkle;
mod target;

pub use header::{
    HASH_SIZE, HEADER_SIZE, Hash256, HnsHeader, MINER_HEADER_SIZE, MinerHeader, NONCE_SIZE,
    blake2b_256, blake2b_512,
};
pub use merkle::merkle_root;
pub use target::{
    CaptureParameterError, CaptureParameters, compact_to_target, count_leading_zero_bits,
    derive_capture_parameters, target_to_compact, verify_pow,
};
