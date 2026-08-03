# Portable heterogeneous mining work fabric

Status: portable planner and work-coordinator foundations implemented; `meshmine-workd` currently provides database initialization and status inspection only. End-to-end daemon composition, compiler qualification, and hardware qualification remain open.

## Purpose

The work fabric separates consensus and block-template construction from the
hardware that performs proof-of-work. It is a local coordination layer, not a
global nonce coordinator and not a replacement consensus protocol.

```text
consensus/template authority
        -> signed assignment envelope
        -> local durable work planner
        -> backend adapter
        -> ASIC, GPU, CPU, or external miner
```

The control plane is portable Rust. Architecture-specific hashing is optional
and belongs behind a backend adapter.

## Crates and binaries

- `meshmine-work`: device capabilities, durable leases, generation control,
  backend contract, exact capture verification, durable capture spool, and
  adaptive submission-target control.
- `meshmine-workd`: initializes and inspects the local redb work database.
- `meshmine-corelink-operatord`: the continuous local supervisor for gateway
  serving, safe-mode/fallback handling, durable Core reconciliation, dashboard,
  and signed public statistics; it does not yet compose the `meshmine-work`
  coordinator.
- `meshmine-gateway`: the first real adapter boundary for HandyStratum HNS ASICs,
  including local-lease enforcement and durable downstream acknowledgment.

## Authorization hierarchy

A signed `AssignmentV2` or `GatewayAssignmentV1` is the maximum authorized work
envelope. A local `WorkLease` can only narrow that envelope. It cannot change:

- assignment identity or sequence;
- worker identity;
- mining generation or committed nTime;
- capture target;
- extra-nonce profile;
- authorized extra-nonce, nonce, or stride bounds.

A lease ID is computed from the canonical binary lease body. A prepared device
job is separately identified from its canonical binary body and bound to the
lease ID.

## Allocation rules

### Stock HandyStratum ASICs

Stock ASIC traversal cannot be proven. Their work is partitioned by disjoint
HandyStratum `ExtraNonce2` namespaces under the exact profile:

```text
prefix4 || ExtraNonce2[4] || zero16
```

The ASIC retains the signed nonce envelope. The planner never treats a stock
ASIC disconnect as proof that a range was completed, and it does not rewind the
allocation cursor.

### Programmable CPU/GPU/native workers

Backends that truthfully advertise programmable nonce ranges receive bounded,
stride-aligned leases. Lease size may use locally measured hashrate and a target
lease duration. A completion event is accepted only when the durable capability
record explicitly authorizes range-completion reports.

### Non-programmable exact assignments

A backend that cannot enforce nonce ranges receives the complete exact
assignment exclusively. A second device cannot receive the same exact envelope.

## Generation lifecycle

Backends implement:

```text
PREPARE generation G
ACTIVATE generation G
CANCEL generation G
```

The coordinator persists the lease and prepared device job before delivery.
Native backends can implement a true prepare/activate split. Stock protocol
adapters may cache a translated job and map activation to the protocol's normal
job notification.

Restart recovery is explicit. The caller must supply the current signed
envelope and exact template context. Recovery refuses an expired lease or any
assignment, generation, nTime, header-root, target, or job-ID mismatch.

## Capture handling

For every capture, the coordinator:

1. Requires the backend and generation to be active.
2. Checks lease expiry, nTime, extra nonce, nonce range, and stride.
3. Reconstructs the exact HNS `MinerHeader`.
4. Recomputes the scalar Handshake share hash through `meshmine-hns`.
5. Rejects a hash that fails the advertised edge target.
6. Treats edge-only submissions as telemetry.
7. Persists capture-qualified work before downstream delivery.
8. Calls an idempotent durable downstream consumer.
9. Writes a tombstone and removes the local payload only after durable admission.

The capture identity excludes local receipt time, so a retry of the same work
has the same durable identity even when it is received again later.

Downstream failure leaves the capture in the durable local spool. It is retried
without gateway acknowledgment or local payload compaction.

## Adaptive target control

`capture_target` is the signed forwarding threshold. `edge_target` is an easier
per-device telemetry threshold. The adaptive controller uses integer-only
arithmetic and is bounded by:

- the signed capture target;
- the device's minimum supported target;
- the signed maximum edge target;
- a configured maximum adjustment ratio per observation window.

A local lease can choose an easier edge target inside that interval but can
never suppress capture-qualified work.

## Resource limits

The coordinator has explicit limits for registered backends, events per poll,
pending capture records, and pending capture bytes. Planner batch sizes are
bounded separately for extra-nonce and nonce leases. The simulated backend also
has a bounded event queue.

## Platform policy

The control plane contains no CUDA, ROCm, NEON, AVX, or vendor hashing kernel.
Supported backend categories include:

- HandyStratum ASIC;
- native worker;
- external process;
- CUDA;
- ROCm;
- ARM64 CPU;
- x86-64 CPU;
- simulator.

A backend category is an integration boundary, not a claim that a production
kernel or every vendor protocol is already implemented.

## Current limitations

- `meshmine-corelink-operatord` does not yet drive the `meshmine-work` planner,
  lease lifecycle, or backend contract end to end.
- `meshmine-workd` currently exposes only bounded database initialization and
  status inspection; it does not run a planner or backend service loop.
- No production ARM64, x86, CUDA, or ROCm hash kernel is included.
- No generic external-process transport is implemented yet.
- HandyStratum hardware behavior remains subject to physical device testing.
- Adaptive target control is implemented as a reusable controller; automatic
  telemetry feedback into every real backend remains follow-on integration.
- Cargo compilation, rustfmt, Clippy, and Rust unit tests must pass in CI or a
  Rust-equipped development host before release qualification.

These limitations do not change the core boundary: the work planner coordinates
preauthorized work, while the most efficient available backend may perform the
actual hashing.
