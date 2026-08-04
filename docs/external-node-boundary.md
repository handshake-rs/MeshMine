# Standalone Rust node boundary

MeshMine's Handshake authority is the standalone `handshake-rs/hns-node-rs`
workspace. `meshmine-hsrd-bridge` consumes `hns-consensus`, `hns-mining`,
`hns-node`, and `hns-primitives` from the immutable Git revision recorded in its
manifest and `Cargo.lock`. The current pin is:

```text
77208649d255ffcffc37d788107de8cad23a480f
```

MeshMine contains no embedded full node, node fallback, JavaScript consensus
oracle, or runtime path dependency. If the pinned revision is unavailable or
API-incompatible, the build fails. A coordination checkout may temporarily use
a local Cargo patch, but release provenance must resolve the canonical Git URL
and exact revision.

Run the boundary check from the MeshMine root:

```sh
python3 scripts/validate-external-node-boundary.py
```

The check resolves locked Cargo metadata, verifies the bridge dependencies
against the exact repository and revision, rejects embedded node workspace
members, and rejects local runtime path substitution.

## Authority division

The standalone node owns the coherent active-chain and mining snapshot:

- network and active height;
- block hash, header, chainwork, and median time;
- next target and mining generation;
- exact candidate body and solved-candidate validation;
- durable authority/readiness state; and
- Handshake name and service identity validation.

MeshMine owns overlay objects, assignments, nonce leases, masking, committee
workflows, receipts, payouts, settlement, durable gossip, ASIC ingress, and
operator supervision. It binds one coherent node snapshot to those workflows;
it does not reconstruct node state through repeated generic calls.

## Performance boundary

The external dependency is not permission to add a per-share RPC bottleneck.
The node exports coherent prepared mining state, and MeshMine performs bounded
local checks for repeated share traffic. Node transitions invalidate the bound
job. Candidate publication returns to the authoritative node for complete
validation. Any future refactor must preserve or improve measured job latency,
share throughput, and invalidation time.

## HIP boundary

The companion `handshake-rs` workspace contains the draft HNSA implementation
for HIP pull request 79 and the local version-2 HNSA/HNSR named-route adapter.
Service identity, authorization, endpoint delegation, route validation, and
rendezvous wire behavior remain there. The HNSR/operator dependencies are
locked to `handshake-rs/hns-rs` revision
`29e4b473bd2cfee460b56d5092b7bc28da5ec5dc`. MeshMine owns only its
`pool-stats` profile-specific snapshot and application policy.

HIP pull request 78 remains limited to unnamed-node rendezvous in its submitted
upstream scope. The local companion HIP preserves that route format and adds a
separate named version. MeshMine may consume the adapter after its exact
`handshake-rs` source is committed and pinned; it must not duplicate those
semantics inside the node or silently treat direct HTTP as HNSR.

## Fail-closed limits

- A missing, stale, incomplete, or unauthorized node snapshot disables
  parent-authoritative work.
- A generation or tip change retires the bound ASIC job before publication.
- Node and MeshMine revisions are separate release inputs and both belong in
  release provenance.
- A service-identity or discovery draft change requires deliberate dependency
  advancement, compatibility vectors, and requalification.
- No feature may silently switch to a second consensus implementation.
