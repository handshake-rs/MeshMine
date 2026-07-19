# Research-only mine-once workflow

`meshmine-node research-mine-once` is a deliberately constrained vertical
slice for one block on an isolated Handshake regtest node. It is not a
production miner. A successful invocation prints `production_eligible=false`,
`research_only=true`, and `acceptance_scope=historical-durable-record`.

Never point `--hsd-cli` at mainnet, testnet, or any live production node. The
command refuses to contact hsd unless
`--acknowledge-research-only-regtest` is present.

## Stock hsd regtest profile

An unmodified stock hsd regtest template uses compact target `0x207fffff`.
Run that path with `--stock-regtest-compat`, which selects exactly:

- network leading-zero count `p = 1`;
- mask leading-zero prefix `q = 1`;
- blind-band width `d = 0`; and
- capture target `T_capture = 2^255 - 1`.

The research mask has its most-significant bit cleared and at least one lower
bit set. This preserves winner-implies-capture for the stock regtest target,
but does not exercise MM-0001's production requirement `p > d > 0`. The `d=0`
exception is accepted only by the explicitly non-production research backend
and only when `--stock-regtest-compat` is present. The command also requires
the serialized miner header to contain exactly `bits=0x207fffff` and requires
hsd's reported target to equal the target decoded from those bits.

Use a disposable endpoint and a fresh state-directory leaf. Both paths must be
absolute and canonical; the state directory's parent must already exist.

```console
cargo run --locked -p meshmine-node -- research-mine-once \
  --acknowledge-research-only-regtest \
  --stock-regtest-compat \
  --dir /absolute/canonical/path/meshmine-regtest-state \
  --hsd-cli /absolute/canonical/path/to/hsw-cli \
  --research-seed 0000000000000000000000000000000000000000000000000000000000000001 \
  --nonce-limit 1000000 \
  --maximum-captures 64
```

`--stock-regtest-compat` implies `--blind-band-bits 0`; supplying a different
value fails closed. Without the stock flag, the command defaults to a one-bit
blind band and therefore needs a harder isolated target. For example, the
deterministic `0x203fffff` fixture supports `q=1,d=1`. It is a separate
synthetic research profile, not a stock hsd regtest configuration.

The nonce scan defaults to 1,000,000 candidates and is hard-capped at
10,000,000. The capture boundary defaults to 64 entries and is hard-capped at
1,024. Both lower bounds are one. The selected bounds are stored in the capture
record and an exact deterministic rescan must reproduce the complete record on
restart; a changed bound or a truncated capture set is rejected.

## Endpoint and filesystem binding

Before binding a fresh endpoint, and again immediately before a submission,
the command requires both:

- `getwork.network == "regtest"`; and
- `getblockhash(0) ==
  ae3895cf597eff05b19e02a70ceeeecb9dc72dbfe6504a50e9343a72f06a87c5`,
  the hsd regtest genesis hash.

The CLI must be an absolute, canonical, regular, non-symlink executable no
larger than 16 MiB. Its canonical path, byte length, and BLAKE2b-256 digest are
stored immutably before work is persisted. Every RPC invocation reopens and
rehashes the executable and rejects a mismatch. On Unix, the CLI may not be
group/world writable; the state directory must be owned by the current user,
is forced to mode `0700`, may not be a symlink, and its non-sticky ancestors may
not be group/world writable.

Each CLI RPC has a five-second deadline and 64 KiB output limit. On Unix it
runs in a dedicated process group that is terminated after the query, so a
helper cannot retain stdout and stall the caller indefinitely. The submitted
miner data and mask are passed as JSON-quoted hex strings, including when a hex
value happens to contain only decimal digits and a JSON-parsing CLI would
otherwise coerce it to a number.

This binding authenticates the CLI file, not the node behind it. `getwork`, the
genesis query, the pre-submit attestation, and `submitwork` are separate CLI
processes. A mutable CLI configuration or endpoint can therefore be swapped
between those calls. This residual cross-process TOCTOU is acceptable only for
the isolated research workflow; it is not endpoint attestation suitable for a
production miner.

## Durable order and replay

The command validates the 256-byte miner header, compact/reported targets, and
hsd's initial zero-mask commitment before persisting work. It creates the
research VSS setup, mines only against the public mask commitment, durably
fixes the accepted-capture boundary, and only then opens and permanently
retires the mask material. The winning `submitwork(data, mask)` intent is
persisted before the RPC.

State is stored in `research-mine-once.redb`. Each durable record is capped at
256 KiB. Record schema version 3 binds the endpoint, work, setup, capture bounds
and results, fixed boundary, opening, submission intent, and acceptance. There
is no migration from earlier research-mine-once schemas: after upgrading to
version 3, use a fresh empty state directory. Exact record replay is accepted
and conflicting or incomplete state fails closed.

If hsd accepted the block but the process stopped before the acceptance record
was committed, a restart accepts a `stale` response only when
`getblockhash(height)` equals the expected PoW/block hash. Once an acceptance
record exists, a restart fully reconstructs and locally revalidates every
durable stage without making an hsd RPC or persisting a new protocol record.
Startup still requires the current CLI file to match the durable path and
digest binding.

That terminal replay is intentionally historical. It proves that the durable
acceptance record still matches the reconstructed submission; it does not
query whether the block remains canonical after a later reorganization.
Operators must perform a separate current-chain check when that distinction
matters.

The deterministic acceptance tests use a bounded mock and never contact an
external hsd:

```console
cargo test --locked -p meshmine-node research_mine_once
```

This slice demonstrates restart-safe ordering for one research block header.
It does not provide a production-secure MPC backend, distributed committee
operation, pool assignment/accounting integration, physical ASIC evidence,
operator-grade endpoint identity, block-body construction, or production
deployment eligibility.
