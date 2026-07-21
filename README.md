# HNS MeshMine

HNS MeshMine is a research implementation of the no-hard-fork, independently templated Handshake mining overlay specified by [MM-0001 Core v2](MeshMine.md). It preserves ordinary HNS consensus. Current qualification paths construct and check candidates through unmodified `hsd`; the lean native Rust mining full node in [`hsrd`](hsrd/README.md) remains pre-authority until historical, invalid-corpus, reorg, state-root, and live-shadow parity gates pass.

The local reference implementation integrates components for WP1–WP13 and a deterministic local WP14 fault harness; the acceptance gaps are listed below rather than treated as completed work. It is not production-ready. The default simulation MPC backend uses a trusted coordinator; a separate artifact-pinned distributed MP-SPDZ research adapter passes WP7 locally but is not integrated into a production daemon or independently audited. Goldshell/HS3 behavior has not been physically verified, the overlay harness is not a public multi-operator deployment, and the object graph has not received independent protocol review.

## What is implemented

| Area | Evidence |
|---|---|
| HNS proof and serialization | 10,000 Rust/`hsd` differential vectors, edge targets, exact 236/256-byte forms |
| Wire objects and signatures | 14 bounded canonical binary objects, acyclic IDs, Ed25519 context binding, Rust/Node vectors |
| Regtest block production | isolated local template, capture, opening, reconstruction, and acceptance by unmodified `hsd`; a separate durable mine-once command supports stock `0x207fffff` regtest only through the explicit non-production `q=1,d=0` compatibility profile |
| Body certification | stable body commitments, no-PoW contextual `hsd` validation, Reed–Solomon recovery and admission limits |
| Shares and receipts | exact validation, mandatory local-parent oracle, DAG reconciliation, `work_key` deduplication, receipt fault proofs, and an independently validated/durably guarded static receipt proposal-sign-assemble workflow |
| Mask protocol | durable trusted-setup simulation backend plus an artifact-allowlisted distributed MP-SPDZ setup: inside-MPC constrained randomness/rejection sampling, exact 209,858-gate BLAKE2b, per-member private Shamir output, durable signed commitments, restart-safe threshold opening, a real three-party MASCOT/Tinier run, and 10,000 HNS hash differentials; `production_eligible` remains false |
| Settlement | complete-session PPLNS snapshots with minimal-suffix retention, a canonical source-fenced recovery checkpoint and monotonic durable head, delayed entropy, unbiased 512-bit tickets, bounded service-credit library arithmetic, exact coinbase layout/reorg rollback, and a strict work-only single-lane static proposal-sign-assemble workflow |
| Gateway | bounded loopback-only HandyStratum HNS adapter plus domain-separated operator/gateway/Core handoff objects, signed capture/disposition/drain evidence, gap-free sequence fencing, atomic evidence/share/work admission, and a live-parent-qualified authenticated Core stream under the unified local supervisor; hardware profiles remain unverified |
| Heterogeneous work fabric | portable durable `meshmine-work` planner with capability discovery, non-overlapping ExtraNonce2 or nonce leases, generation-based prepare/activate/cancel, exact scalar HNS capture verification, stable capture deduplication, durable downstream admission, bounded adaptive edge targets, and HandyStratum/simulator backend boundaries; architecture-specific hash kernels remain optional |
| Operator service and UI | `meshmine-corelink-operatord` combines concurrent loopback HandyStratum sessions, exact signed Core bundle import, Core-side `ShareV2` construction, durable terminal receipts, signed drains, Core reconnect backoff, deterministic safe modes and fallback hysteresis, trust-bound storage, bounded event history, graceful shutdown, read-only health/status API, and the embedded responsive dashboard; production hardware qualification remains open |
| Native mining node | lean `hsrd` workspace with exact HNS network/genesis parameters, unsigned 256-bit chainwork, difficulty/timestamp admission, native pinned secp256k1 verification, bounded witness/script foundations, covenant linkage, contextual non-claim name transitions, exact HSD `NameState` encoding, correctness-first Urkel roots and proofs, durable content-addressed authenticated nodes with path-local immutable mutation and exact proofs, network-interval root pins, validated retained-root compaction with opt-in interval-gated startup scheduling and atomic checkpoints, opt-in HSD-horizon undo retirement with pruning-aware root pins and reorg rejection, root-checked durable materialized snapshots, durable pre/post root binding, sequence-consistent RocksDB snapshots, alternate-branch retention, strict greater-work fork choice, one-batch reorganizations, exact bounded HNS wire codecs, live observation-only peers, headers-first scheduling, stateless body workers, non-active body retention, restart checkpoints, a bounded generation-indexed mempool, deterministic HNS-aware future templates, durable solved-block publication intents, and local-first parallel critical fan-out. The unified operator can use its RPC surface as an optional shadow witness while HSD remains authoritative; complete historical claim/airdrop and contextual consensus parity, deployment-scale compaction priority and RocksDB mid-commit crash qualification, active-state IBD, production contextual transaction admission, and native mainnet authority remain open |
| Committees | exact risk calculator, role-separated delayed sortition, bootstrap phases, roster verification, fault exclusion and liveness replacement |
| Networking and storage | native authenticated QUIC streams with separately reserved fast-path, accounting, availability, and settlement callback, live-queue, replay, and per-peer send capacity; bounded static peers with TLS/transport-key pins and staged certificate rotation, reconnect-supervised signed gossip with bounded durable at-least-once catch-up, exact-wrapper publication-intent recovery, atomic settled-prefix compaction and source suppression, request quotas, exact share ingress with local-`hsd` context evidence, one-transaction share/work/observation/active-index admission, guarded MaskSession inventory generation, one-transaction canonical Disconnect/MMDB/parent/session/head/index effects, source-bound normal/reorg session closure, bounded active-share and open-receipt restart recovery with resumable fail-closed legacy migrations, partition harness, clock policy, immutable redb journal and crash-safe signing guards |
| Observability | bounded schema-v3 JSON evidence for durable work/template/body/payout/reorg/telemetry distributions and static-peer delivery capacity/backlog/intent/migration/compaction/tombstone state, explicit per-metric coverage and unavailable-evidence labels |
| Verification | three TLC-checked finite models, local 1,000-session fault transcript, independent JavaScript Core/body/payout/transcript verification, and performance gates |

Atomic Disconnect transitions do not make restart cost independent of deployment age. Payout-enabled startup still invokes historical receipt recovery before the capped active-receipt path. The sealed payout checkpoint and O(1) head lookup now exist, but atomic source-head advancement, bounded migration, and startup cutover are still open, as is the reversible parent checkpoint/resumable deep-reorg fence. None of the external production-release gates below is changed.

Detailed claim boundaries and gaps are in [implementation-status.md](specs/implementation-status.md), with the specification-wide `MUST` audit in [normative-audit.md](specs/normative-audit.md). The required separation between immediate mining, winner publication, accounting, availability, and settlement is in [latency-lanes-and-fast-path.md](specs/latency-lanes-and-fast-path.md). Package-specific assumptions are in [threat-model.md](specs/threat-model.md), the local metrics schema is in [observability.md](specs/observability.md), the static role runbooks are in [receipt-role.md](specs/receipt-role.md) and [settlement-role.md](specs/settlement-role.md), the implementation-diverse artifact commands are in [independent-audit.md](specs/independent-audit.md), and each research committee role is stated separately in [research-role-profile.md](specs/research-role-profile.md).

## Verify

Requirements are Rust 1.89+, Node.js, and either the pinned oracle dependency or an `hsd` checkout. The oracle package pins `hsd` commit `698e252ebc7b5c1dd0a9587e342fdd153d020ae4`.

The latest complete local gate results and qualification boundary are recorded
in [VERIFICATION.md](VERIFICATION.md).

```sh
npm ci --prefix hsd-oracle --ignore-scripts
npm run audit --prefix hsd-oracle
python3 scripts/validate-hsrd-static.py
python3 scripts/validate-hsrd-source-handoff.py
python3 scripts/validate-work-fabric-source.py
python3 scripts/validate-operator-service-source.py
python3 scripts/validate-core-link-source.py
python3 scripts/validate-live-parent-and-unified-operator-source.py
NODE_BACKEND=js node scripts/verify-operator-receipt-fixture.js
npm run hsrd-script-fixtures --prefix hsd-oracle
npm run hsrd-covenant-fixtures --prefix hsd-oracle
npm run hsrd-name-state-codec-fixtures --prefix hsd-oracle
npm run hsrd-name-state-urkel-fixtures --prefix hsd-oracle
npm run hsrd-urkel-proof-fixtures --prefix hsd-oracle
npm run hsrd-name-policy-fixtures --prefix hsd-oracle
npm run hsrd-p2p-wire-fixtures --prefix hsd-oracle
npm run hsrd-mining-template-fixtures --prefix hsd-oracle
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
NODE_BACKEND=js node hsd-oracle/verify-core-vectors.js
NODE_BACKEND=js ./scripts/differential.sh 10000
cargo run --locked --quiet -p meshmine-mpc-api --bin generate_opened_vectors -- 10000 \
  | NODE_BACKEND=js node hsd-oracle/verify-mpc-opened-vectors.js 10000
NODE_BACKEND=js node hsd-oracle/regtest-driver.js
NODE_BACKEND=js node hsd-oracle/validate-body.js
NODE_BACKEND=js node hsd-oracle/payout-driver.js
cargo run --locked --quiet -p meshmine-sim -- overlay 1000 \
  --output /tmp/meshmine-overlay.json --explorer /tmp/meshmine-overlay.html
NODE_BACKEND=js node hsd-oracle/verify-overlay-transcript.js /tmp/meshmine-overlay.json
```

The local work database can be initialized and inspected independently:

```sh
cargo run --locked -p meshmine-workd -- init /path/to/work.redb
cargo run --locked -p meshmine-workd -- status /path/to/work.redb
```

The work-fabric design, authorization hierarchy, allocation rules, and current
limitations are documented in [work-fabric.md](docs/work-fabric.md). The
unified operator service, safe modes, Core reconnect/fallback behavior, and local
dashboard are documented in [operator-service.md](docs/operator-service.md).
The authenticated Core stream and live parent qualification are documented in
[core-link.md](docs/core-link.md) and
[live-parent-and-unified-operator.md](docs/live-parent-and-unified-operator.md).

The standalone operator service can be started from a strict local configuration after the
referenced job and password files have been prepared:

```sh
cargo run --locked -p meshmine-operatord -- serve \
  --config /absolute/path/operator-service.json
```

The dashboard is then served only on the configured loopback address. Canonical
Core receipts are imported only after external Core admission:

```sh
cargo run --locked -p meshmine-operatord -- import-core-receipt \
  --config /absolute/path/operator-service.json \
  --receipt /absolute/path/core-receipt.json
```

An optional external MPC conformance run can be checked after compiling and
executing the reviewed three-party fixture described in
[mpc/mp-spdz/README.md](mpc/mp-spdz/README.md):

```sh
cargo run --locked --quiet -p meshmine-mpc-api --bin verify_mp_spdz_fixture -- \
  /path/to/MP-SPDZ
```

That command intentionally reads all three private fixture outputs in one
test process. Production members use the local-only import API and never send
private setup output to an assembler.

The body and payout drivers exercise the implementation-diverse JavaScript
artifact verifier as part of their composed `hsd` checks. Commands for auditing
operator-supplied artifacts directly, and the exact distinction between local
implementation diversity and an externally maintained verifier, are in
[independent-audit.md](specs/independent-audit.md).

Performance checks must use release builds:

```sh
cargo run --locked --release -p meshmine-share --bin share_performance_gate
cargo run --locked --release -p meshmine-settlement --bin settlement_performance_gate
```

TLC instructions and checked state counts are in [models/README.md](models/README.md).

## Useful commands

`meshmine-node` validates every invocation against a per-subcommand option
schema before dispatch. Unknown options, dangling values, option-shaped values,
and duplicate non-repeatable arguments fail closed; only the assembly commands'
`--signature` option is repeatable.

For every non-research command, `--hsd-cli` must name an absolute canonical
regular executable. Unix startup rejects symlink components, non-sticky
group/world-writable ancestors, a group/world-writable leaf, and ownership
other than the effective user or root. The executable identity and digest are
re-attested immediately before every bounded invocation. The separate
`research-mine-once` schema-v3 endpoint rules remain documented below.

Commands that launch the JavaScript body/payment adapters apply the same
absolute and canonical Unix traversal to `--hsd-source` or
`--hns-sync-source`. The source leaf must be effective-user/root-owned and
non-writable by group/other; unsafe writable ancestors are rejected. Commands
re-attest the source-directory
identity immediately before each adapter spawn and pass an inherited descriptor
path, so replacement of the configured directory cannot redirect that launch.
This commits only the top-level directory identity: the Node launcher still
imports a mutable descendant source tree, with no full-tree content commitment,
so effective-user/root source mutation remains inside the deployment trust
boundary.

```sh
# Exact capture-rate/load profiles for blind bands d=8..16.
cargo run --locked -p meshmine-sim -- capture 1925ae67

# Evaluate and enforce a committee-risk configuration.
cargo run --locked -p meshmine-committee-risk -- evaluate \
  --config specs/risk-profile.example.json --monte-carlo 100000
cargo run --locked -p meshmine-committee-risk -- evaluate \
  --config specs/risk-profile.example.json --enforce

# Mine an isolated 256-byte HNS miner header with a public capture target.
cargo run --locked -p meshmine-node -- cpu-mine \
  --header HEX --capture-target HEX --start 0 --limit 1000000

# Exercise one unmodified stock-hsd regtest template. The CLI and state paths
# must be absolute and canonical; use a fresh state directory for schema v3.
cargo run --locked -p meshmine-node -- research-mine-once \
  --acknowledge-research-only-regtest --stock-regtest-compat \
  --dir /absolute/path/research-state --hsd-cli /absolute/path/hsw-cli \
  --research-seed 0000000000000000000000000000000000000000000000000000000000000001

# Require a canonical header/height/time/chainwork match from trusted local hsd.
cargo run --locked -p meshmine-node -- verify-parent --hsd-cli /path/to/hsd-cli \
  --hash HEX --height HEIGHT --chainwork HEX --ntime UNIX_TIME

# Create and run a persistent authenticated local QUIC overlay endpoint.
cargo run --locked -p meshmine-node -- overlay-init \
  --dir /absolute/path/node-state --server-name localhost
cargo run --locked -p meshmine-node -- overlay-serve \
  --dir /absolute/path/node-state --listen 127.0.0.1:9443 --network-id 2 \
  --peer-config /absolute/path/static-peers.json \
  --observability-listen 127.0.0.1:9100
cargo run --locked -p meshmine-node -- overlay-audit --dir /absolute/path/node-state

# Export a deterministic, bounded §21 evidence snapshot. Supplying rosters
# adds key-count, threshold, and cross-role overlap evidence.
cargo run --locked -p meshmine-node -- overlay-observe \
  --dir /absolute/path/node-state --network-id 2 \
  --settlement-roster /path/to/settlement.json \
  --mask-roster /path/to/mask.json \
  --availability-roster /path/to/availability.json \
  --receipt-roster /path/to/receipt.json

# A static research-profile share endpoint first imports its complete signed
# context, validated against the participant's running hsd, then enables all
# three committee rosters when serving. See specs/native-transport.md.
cargo run --locked -p meshmine-node -- share-context-import \
  --dir /absolute/path/node-state --network-id 2 \
  --hsd-cli /path/to/hsd-cli --hsd-source /path/to/hsd \
  --settlement-roster /path/to/settlement.json \
  --mask-roster /path/to/mask.json \
  --availability-roster /path/to/availability.json \
  --parent /path/to/parent.bin --body /path/to/body.bin \
  --descriptor /path/to/descriptor.bin \
  --body-certificate /path/to/body-certificate.bin \
  --session /path/to/session.bin --assignment /path/to/assignment.bin \
  --payout-bucket /path/to/payout-bucket.bin

cargo run --locked -p meshmine-node -- overlay-serve \
  --dir /absolute/path/node-state --listen 127.0.0.1:9443 --network-id 2 \
  --hsd-cli /path/to/hsd-cli \
  --settlement-roster /path/to/settlement.json \
  --mask-roster /path/to/mask.json \
  --availability-roster /path/to/availability.json \
  --receipt-roster /path/to/receipt.json \
  --payout-profile specs/payout-profile.example.json \
  --hns-sync-source /path/to/hsd --hns-sync-from-height HEIGHT \
  --hns-sync-interval-ms 10000 --hns-sync-maximum-events 256 \
  --peer-config /absolute/path/static-peers.json \
  --observability-listen 127.0.0.1:9100

# The same reconciler remains available as a bounded one-shot maintenance
# command. The first run requires an explicit retained reorg horizon; later
# runs resume from the immutable event log (and may repeat the same horizon).
cargo run --locked -p meshmine-node -- overlay-sync-hns \
  --dir /absolute/path/node-state --network-id 2 \
  --hsd-cli /path/to/hsd-cli --hsd-source /path/to/hsd \
  --settlement-roster /path/to/settlement.json \
  --receipt-roster /path/to/receipt.json \
  --payout-profile specs/payout-profile.example.json \
  --from-height HEIGHT --maximum-events 256

# Produce a static-committee receipt through independently validated member
# signatures. The full proposal/sign/assemble sequence and exact trust boundary
# are documented in specs/receipt-role.md.
cargo run --locked -p meshmine-node -- committee-key-init --out /secure/receipt.key

# Work-only single-lane payout snapshot/plan production uses the same
# independently validated signature workflow. See specs/settlement-role.md.

# Serve one bounded, loopback-only HandyStratum simulator connection. The
# example job is simulator-only; update its roots, target, nTime, and
# millisecond windows first.
cargo run --locked -p meshmine-gateway-bin --bin meshmine-gateway -- serve \
  --listen 127.0.0.1:3333 --state /absolute/path/gateway.redb \
  --job /absolute/path/job.json --username operator.worker \
  --password-file /absolute/path/gateway.password --profile simulator
```

The password file must be a regular, non-symlink UTF-8 file containing one
line and, on Unix, must have no group/other permissions (for example mode
`0600`). The standalone gateway binary remains a bounded protocol harness rather
than the continuous production mining path.

The unified operator retains the private authenticated Core link and adds
bounded live local HSD active-chain qualification with a current-tip gate for
served jobs, optional or required HSRD shadow agreement, periodic
requalification, Core reconnect backoff, concurrent local sessions, safe-mode
fallback, signed ACK-only receipt reconciliation, the supervisor/dashboard,
and bounded graceful shutdown. The path remains pre-production and local only:

```sh
# Stage one exact signed assignment bundle, then start local Core service.
cargo run --locked -p meshmine-cored -- stage-bundle \
  --config /absolute/path/core-link-core-v9.json \
  --bundle /absolute/path/assignment-bundle.bin
cargo run --locked -p meshmine-cored -- serve \
  --config /absolute/path/core-link-core-v9.json

# Connect the local operator gateway to Core and serve HandyStratum ASICs.
cargo run --locked -p meshmine-corelink-operatord -- serve \
  --config /absolute/path/core-link-operator-v9.json
```

Example configurations are in `specs/core-link-*.example.json`. See
[core-link.md](docs/core-link.md),
[gateway-core-handoff.md](specs/gateway-core-handoff.md), and
[asic-profiles.md](specs/asic-profiles.md). Native mainnet authority and
production eligibility remain disabled.

### Offline active-receipt migration

Receipt-enabled nodes use the v3 active-receipt head and migration formats.
They deliberately refuse service, receipt production, and settlement production
until the exact v3 `Ready` marker, the v2 retirement marker, and the active-share
`MMA4` `Ready` marker are all present. Stop every writer and take a verified
offline backup before advancing an existing database. Status is an existing-only,
descriptor-pinned read and never creates or repairs state:

```sh
cargo run --locked -p meshmine-node -- \
  active-receipt-migration-status \
  --dir /absolute/path/node-state --network-id 0
```

Advance a bounded number of durable units with the same authenticated Core
context used by the node:

```sh
cargo run --locked -p meshmine-node -- \
  active-receipt-migration-advance \
  --dir /absolute/path/node-state --network-id 0 \
  --hsd-cli /absolute/path/hsd-cli \
  --settlement-roster /absolute/path/settlement.json \
  --mask-roster /absolute/path/mask.json \
  --availability-roster /absolute/path/availability.json \
  --receipt-roster /absolute/path/receipt.json \
  --maximum-units 256
```

Repeat the advance and status commands until `ready=true`. Each unit is
CAS-guarded and restart-safe. Migration derives v3 heads from immutable receipt
batches, skips other networks, removes closed sessions, enforces global and
per-session bounds, and validates every nonempty receipt entry against the
fully revalidated active-share DAG before publishing `Ready`. A missing,
malformed, partially advanced, or concurrently changed fence fails closed.

The production `hsd` deployment audit performed on 2026-07-18 is
recorded in [production-hsd-audit-2026-07-18.md](specs/production-hsd-audit-2026-07-18.md).
Its read-only technical checks can be repeated without reading RPC secrets or
wallet contents:

```sh
./scripts/production-hsd-preflight.sh \
  --service-scope user --service hsd.service \
  --state-dir /absolute/path/.hsd \
  --hsd-cli /absolute/path/hsw-cli \
  --hsd-source /absolute/path/hsd \
  --node-runtime /absolute/path/node \
  --expected-commit 698e252ebc7b5c1dd0a9587e342fdd153d020ae4
```

The preflight fails on unsafe path/state modes, foreign state/source ownership,
group/other-writable source entries, insufficient configured disk or inode
reserve, a dirty or unexpected source commit, an inactive service,
missing `NoNewPrivileges`/`UMask=0077`, `Restart=always`, or restart controls
below the default 60-second delay, 600-second rate-limit window, and five-start
burst ceiling. The entire state tree must be owned by the live service UID and
contain only private regular files/directories, with no symlinks, special
entries, or nested filesystems. It must use an explicit `--prefix` in the retained
systemd `ExecStart` record. `WorkingDirectory` must resolve to the reviewed hsd
source root or its `bin` directory. These requirements bind the capacity check
and reviewed launcher to the same stable service PID; hsd itself overwrites its
original `/proc/PID/cmdline` area after startup.

The report records BLAKE2b-512 CLI and Node executable identities, the Git tree,
and the live Node device/inode and digest without executing the candidate Node
binary or printing `ExecStart`, argv, environment, secret names, or contents.
The optional restart and capacity thresholds can only make the policy stricter
or deliberately replace its defaults; use such overrides as reviewed deployment
policy. A pass is a read-only point-in-time result, not a continuous disk guard,
an attestation of ignored dependency trees such as `node_modules`, or proof of
the JavaScript modules already loaded by the process. It also does not prove
backup restoration, public-node reachability, or any MeshMine release gate;
those require separate operational evidence.

The only end-to-end mining command currently present is deliberately confined
to isolated regtest research. Its stock-hsd `q=1,d=0` profile, CLI digest and
genesis checks, bounded subprocesses, durable schema-v3 boundaries, historical
terminal replay semantics, and residual cross-process endpoint TOCTOU are
documented in
[RESEARCH-MINE-ONCE.md](bins/meshmine-node/RESEARCH-MINE-ONCE.md).

Mainnet participation and production security claims remain disabled until every MM-0001 release gate is independently satisfied.
