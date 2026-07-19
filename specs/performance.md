# Prototype performance gates

Run from the repository root with release optimizations:

```sh
cargo run --locked --release -p meshmine-share --bin performance_gate
cargo run --locked --release -p meshmine-settlement --bin performance_gate
cargo run --locked --release -p meshmine-sim -- capture 1925ae67
```

The first command validates the exact full share path repeatedly: object linkage, operator/body/assignment/bucket signatures, three role certificates, local parent-oracle decision, HNS miner-header reconstruction, raw share hash, and capture target.

The second reconstructs a 4 MiB Reed–Solomon body and recomputes a 56-ticket payout plan against 100,000 exact work buckets. Cumulative weights are built once and each ticket uses binary search, avoiding an `O(bucket_count × ticket_count)` verifier.

Results on the 2026-07-17 aarch64 development host:

| Gate | Result | Target |
|---|---:|---:|
| Share validation/core | 493.943/s | ≥100/s |
| 4 MiB threshold reconstruction | 36.754 ms | <1,000 ms |
| 100,000-bucket payout verification | 70.659 ms | <100 ms |

The `d=15` capture profile at bits `0x1925ae67` models 92.7584 capture shares/s network-wide, above the 50/s baseline target, while the measured validator retains substantial single-core headroom. Production `d` remains configuration-gated and must use actual testnet measurements.

Receipt-finalization latency, public propagation latency, timed-opening latency under real failure domains, and multi-node winner submission are deployment metrics and are not inferred from these local microbenchmarks.
