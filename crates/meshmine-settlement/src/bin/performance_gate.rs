use std::error::Error;
use std::time::Instant;

use meshmine_body::{encode_body, reconstruct_body};
use meshmine_hns::Hash256;
use meshmine_settlement::{PayoutProfile, build_payout_plan, verify_payout_plan};
use meshmine_types::{PayoutSnapshotV2, SignatureSet, U512, WorkBucketLeaf};

fn main() {
    if let Err(error) = run() {
        eprintln!("performance_gate: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let body = vec![0x5a; 4 * 1024 * 1024];
    let encoded = encode_body(2, 2, [1; 32], &body, 8, 4, 1_000)?;
    let supplied = encoded.shards[..8].to_vec();
    let started = Instant::now();
    let reconstructed = reconstruct_body(&encoded.descriptor, &supplied)?;
    let body_ms = started.elapsed().as_secs_f64() * 1_000.0;
    if reconstructed != body {
        return Err("4 MB body reconstruction mismatch".into());
    }

    let snapshot = payout_snapshot(100_000);
    let profile = PayoutProfile {
        work_ticket_count: 56,
        service_ticket_count: 0,
        service_basis_points: 0,
        maximum_service_basis_points: 600,
        minimum_ticket_value: 1,
        maximum_coinbase_outputs: 128,
    };
    let plan = build_payout_plan(
        &snapshot,
        101,
        vec![[3; 32], [4; 32], [5; 32]],
        [6; 32],
        profile,
        SignatureSet::empty_ed25519(),
    )?;
    let started = Instant::now();
    verify_payout_plan(&snapshot, &plan, profile)?;
    let payout_ms = started.elapsed().as_secs_f64() * 1_000.0;

    println!("body_reconstruction_bytes={}", body.len());
    println!("body_reconstruction_ms={body_ms:.3}");
    println!("payout_buckets={}", snapshot.work_buckets.len());
    println!("payout_plan_verification_ms={payout_ms:.3}");
    println!("body_target_under_ms=1000");
    println!("payout_target_under_ms=100");
    if body_ms >= 1_000.0 || payout_ms >= 100.0 {
        return Err("one or more MM-0001 prototype performance targets were missed".into());
    }
    Ok(())
}

fn payout_snapshot(count: u32) -> PayoutSnapshotV2 {
    let mut work_buckets = Vec::with_capacity(count as usize);
    for index in 0..count {
        let mut bucket_id = [0; 32];
        bucket_id[28..].copy_from_slice(&index.to_be_bytes());
        let mut credited = [0; 64];
        credited[63] = 1;
        work_buckets.push(WorkBucketLeaf {
            bucket_id,
            operator_pubkey: keyed_hash(index),
            hns_address_version: 0,
            hns_address_hash: keyed_hash(index).to_vec(),
            credited_work: U512(credited),
        });
    }
    let mut total = [0; 64];
    total[60..].copy_from_slice(&count.to_be_bytes());
    PayoutSnapshotV2 {
        protocol_version: 2,
        network_id: 2,
        snapshot_sequence: 1,
        previous_snapshot_id: [0; 32],
        first_session_close_id: [1; 32],
        last_session_close_id: [2; 32],
        close_anchor_height: 100,
        work_window_target: U512(total),
        actual_work_in_window: U512(total),
        work_buckets,
        service_buckets: vec![],
        share_set_root: [7; 32],
        service_set_root: [8; 32],
        settlement_committee_id: [9; 32],
        signer_set: SignatureSet::empty_ed25519(),
    }
}

fn keyed_hash(index: u32) -> Hash256 {
    let mut hash = [0; 32];
    hash[..4].copy_from_slice(&index.to_le_bytes());
    hash[31] = 1;
    hash
}
