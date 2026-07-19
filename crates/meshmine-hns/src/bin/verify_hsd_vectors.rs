use std::{
    error::Error,
    io::{self, BufRead},
};

use meshmine_hns::{
    Hash256, HnsHeader, MinerHeader, compact_to_target, merkle_root, target_to_compact, verify_pow,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Vector {
    index: usize,
    input: Input,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Input {
    nonce: u32,
    time: String,
    prev_block: String,
    tree_root: String,
    extra_nonce: String,
    reserved_root: String,
    witness_root: String,
    merkle_root: String,
    version: u32,
    bits: u32,
    mask: String,
    merkle_leaves: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Expected {
    header: String,
    miner: String,
    padding_8: String,
    padding_20: String,
    padding_32: String,
    subheader: String,
    sub_hash: String,
    mask_hash: String,
    commit_hash: String,
    preheader: String,
    share_hash: String,
    pow_hash: String,
    target_hex: String,
    compact_roundtrip: u32,
    pow_valid: bool,
    merkle_root: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut count = 0usize;
    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let vector: Vector = serde_json::from_str(&line)?;
        verify_vector(&vector).map_err(|message| {
            format!("hsd differential vector {} failed: {message}", vector.index)
        })?;
        count += 1;
    }

    if count == 0 {
        return Err("no hsd vectors received".into());
    }
    println!("verified {count} deterministic hsd vectors with zero mismatches");
    Ok(())
}

fn verify_vector(vector: &Vector) -> Result<(), String> {
    let input = &vector.input;
    let expected = &vector.expected;
    let header = HnsHeader {
        nonce: input.nonce,
        time: input
            .time
            .parse()
            .map_err(|error| format!("invalid time: {error}"))?,
        prev_block: decode_array("prev_block", &input.prev_block)?,
        tree_root: decode_array("tree_root", &input.tree_root)?,
        extra_nonce: decode_array("extra_nonce", &input.extra_nonce)?,
        reserved_root: decode_array("reserved_root", &input.reserved_root)?,
        witness_root: decode_array("witness_root", &input.witness_root)?,
        merkle_root: decode_array("merkle_root", &input.merkle_root)?,
        version: input.version,
        bits: input.bits,
        mask: decode_array("mask", &input.mask)?,
    };

    check_hex("header", &header.to_bytes(), &expected.header)?;
    check_hex("miner", &header.to_miner(), &expected.miner)?;
    check_hex("padding_8", &header.padding(8), &expected.padding_8)?;
    check_hex("padding_20", &header.padding(20), &expected.padding_20)?;
    check_hex("padding_32", &header.padding(32), &expected.padding_32)?;
    check_hex("subheader", &header.subheader(), &expected.subheader)?;
    check_hex("sub_hash", &header.sub_hash(), &expected.sub_hash)?;
    check_hex("mask_hash", &header.mask_hash(), &expected.mask_hash)?;
    check_hex("commit_hash", &header.commit_hash(), &expected.commit_hash)?;
    check_hex("preheader", &header.preheader(), &expected.preheader)?;
    check_hex("share_hash", &header.share_hash(), &expected.share_hash)?;
    check_hex("pow_hash", &header.pow_hash(), &expected.pow_hash)?;

    let decoded = HnsHeader::from_bytes(&header.to_bytes())
        .map_err(|error| format!("consensus header did not parse: {error}"))?;
    if decoded != header {
        return Err("consensus header roundtrip changed fields".into());
    }

    let miner = MinerHeader::from_bytes(&header.to_miner())
        .map_err(|error| format!("miner header did not parse: {error}"))?;
    check_hex("miner_roundtrip", &miner.to_bytes(), &expected.miner)?;
    check_hex(
        "miner_share_hash",
        &miner.share_hash(),
        &expected.share_hash,
    )?;

    let target = compact_to_target(input.bits);
    if target.to_str_radix(16) != expected.target_hex {
        return Err(format!(
            "target_hex mismatch: Rust={}, hsd={}",
            target.to_str_radix(16),
            expected.target_hex
        ));
    }
    let unsigned_target = target
        .to_biguint()
        .ok_or_else(|| "generator unexpectedly emitted a negative target".to_owned())?;
    let compact = target_to_compact(&unsigned_target);
    if compact != expected.compact_roundtrip {
        return Err(format!(
            "compact_roundtrip mismatch: Rust={compact:#010x}, hsd={:#010x}",
            expected.compact_roundtrip
        ));
    }
    if verify_pow(&header.pow_hash(), input.bits) != expected.pow_valid {
        return Err(format!(
            "pow_valid mismatch: Rust={}, hsd={}",
            verify_pow(&header.pow_hash(), input.bits),
            expected.pow_valid
        ));
    }

    let leaves: Result<Vec<Hash256>, String> = input
        .merkle_leaves
        .iter()
        .map(|leaf| decode_array("merkle_leaf", leaf))
        .collect();
    check_hex("merkle_root", &merkle_root(&leaves?), &expected.merkle_root)?;
    Ok(())
}

fn decode_array<const N: usize>(label: &str, value: &str) -> Result<[u8; N], String> {
    let decoded = hex::decode(value).map_err(|error| format!("invalid {label} hex: {error}"))?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        format!("invalid {label} length: expected {N}, got {}", bytes.len())
    })
}

fn check_hex(label: &str, actual: &[u8], expected: &str) -> Result<(), String> {
    let actual = hex::encode(actual);
    if actual != expected {
        return Err(format!("{label} mismatch: Rust={actual}, hsd={expected}"));
    }
    Ok(())
}
