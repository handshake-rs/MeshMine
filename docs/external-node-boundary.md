# Standalone node boundary

MeshMine's runtime and build-time Handshake authority is the standalone
`hns-node-rs` workspace. `meshmine-hsrd-bridge` consumes `hns-consensus`,
`hns-mining`, `hns-node`, and `hns-primitives` from the exact immutable
`handshake-rs/hns-node-rs` Git revision recorded in its manifest and lockfile.
The current MeshMine pin is
`504d3fed035feb8a637ca09c4e0816b6e1144622`. That revision includes
complete consensus readiness, the qualified stopped-state/retained-rollback
evidence, and the conditional native mainnet canary permit path. Its base
snapshot initializes `release_stage: "pre-authority"`; live native RPC
replaces it with a configuration-specific diagnostic stage.
No package in the MeshMine workspace may resolve those crates through the
embedded `MeshMine/hsrd` tree or an unpinned branch.

The embedded tree is excluded from the Cargo workspace. It is retained as
historical extraction and qualification material while its fixture generators
are reconciled with the standalone repository; it is not a runtime fallback.
If the canonical revision is unavailable or API-incompatible, Cargo fails.
MeshMine must not silently switch back to the embedded copy. A coordination
checkout may use an explicit local Cargo patch for development, but that patch
is never committed as release provenance.

Run the offline boundary check from the MeshMine root:

```sh
python3 scripts/validate-external-node-boundary.py
```

The check resolves locked Cargo metadata, verifies all four bridge dependencies
against the exact canonical URL and revision, rejects any embedded `hsrd`
workspace member, and rejects embedded runtime path dependencies anywhere in
MeshMine.

## Authority division

The standalone node owns the coherent active-chain and mining snapshot:
network, height, block hash, chainwork, median time, next target, mining
generation, exact block body, and solved-candidate validation. The existing
bridge binds one such snapshot and prepared job to MeshMine's durable
assignment, ASIC gateway, stale-work retirement, and publication intent.

MeshMine continues to own its share DAG, work assignments, nonce leases,
masking, MPC, committees, payouts, settlement, receipts, operator services,
gateway, and mining-specific reservations. It does not replace snapshot reads
or name-tree batching with repeated generic RPC calls.

## Fail-closed limits

- A missing, stale, incomplete, or unauthorized standalone-node snapshot
  disables parent-authoritative work.
- A node generation or tip change retires the bound ASIC job before
  publication.
- The node and MeshMine revisions are separate release inputs and must both be
  recorded in final provenance.
- The pinned `504d3fed035feb8a637ca09c4e0816b6e1144622` node does not
  expose the required HIP 76/77/78 transport policy interface. Standalone
  `hns-node-rs` commit
  `42c76a622f2600a833835b4ca737d3350f73af52` adds canonical Denuo
  negotiation and a role-safe HIP-76 live-session boundary, but not HIP-77/78
  integration. MeshMine does not consume those later changes until its manifest
  pin is deliberately advanced and the boundary is requalified. It exposes no
  substitute policy and never silently enables HNSR or provider roles.
- The existing performance commands are useful component gates, but the full
  before/after matrix required by the ecosystem plan remains release-blocking.
