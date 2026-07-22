# Integration verification

This source tree was verified locally on 2026-07-20 from `main` immediately
before the integration commit.

Environment: `aarch64`, Rust/Cargo 1.89.0, Node.js 24.13.0, and npm 11.6.2.
The 2026-07-22 HSRD follow-up gates used Rust/Cargo 1.92.0 on the same
architecture with Node.js 24.13.0 and npm 11.6.2.

## Results

| Surface | Evidence | Result |
|---|---|---|
| Root Rust workspace | Locked formatting, all-target/all-feature Clippy with warnings denied, all-target/all-feature tests, and optimized all-target/all-feature build | Pass |
| Native HSRD workspace | Locked formatting, strict all-target/all-feature Clippy, 364 all-feature tests, 355 no-default-feature tests, optimized all-target/all-feature build, and the complete pinned-HSD source handoff | Pass (updated 2026-07-22) |
| HSRD fuzz workspace | Locked metadata, formatting, and all-target checks for every fuzz target | Pass |
| Source integrity | Six fail-closed Python validators, manifest/file/digest closure, JSON/TOML and language syntax, executable modes, Markdown links, merge markers, and Git whitespace | Pass |
| Pinned HSD oracle | Sixteen deterministic fixture generators/exporters, signed operator receipt, 14 Core vectors, 10,000 proof differentials, 10,000 MPC-opened vectors, regtest block acceptance, valid/invalid body checks, payout acceptance/audit, and 1,000-session overlay recovery | Pass |
| Native cryptography | Vendored secp256k1 C smoke test plus RIPEMD-160 standard and 55/56/63/64/65-byte padding-boundary vectors checked against OpenSSL and the pinned HSD implementation | Pass |
| Performance | 505.736 shares/second/core (minimum 100); 4 MiB reconstruction in 32.318 ms (maximum 1,000 ms); 100,000-entry payout verification in 62.442 ms (maximum 100 ms) | Pass |
| Dependency audits | Rust lockfiles had no vulnerability advisory; npm reported only the exact isolated-oracle exception described below | Pass with documented exceptions |

The optimized HSRD build used Rust 1.89.0, all workspace targets and features,
and completed in 24 minutes 18 seconds with two build jobs.

## HSRD historical-header and deployment-policy qualification update

On 2026-07-21, fresh temporary RocksDB stores synchronized the complete
canonical mainnet header chain through the native shadow P2P path. Header
packets committed atomically in batches of at most 2,000 and crossed the final
HSD checkpoint. The latest follow-up reached height 339,273, where the external
pinned-source comparator matched this hash in hsrd and HSD:

```text
0000000000000004f8e7b54f716f4d9809b4cd1cd1888c8b013cad8aca5475c2
```

The selected HSD source was clean at revision
`698e252ebc7b5c1dd0a9587e342fdd153d020ae4`. Its local RPC reported the same
tip and `prune: true`. At that coherent tip, hsrd independently replayed all
canonical BIP9 windows. Its four deployment parameters and states matched HSD:
`hardening=failed`, `icannlockup=active`, `airstop=active`, and
`testdummy=failed`. The derived effects also matched pinned HSD: mandatory
script flags `50`, lock flags `0`, name flags `2`, airstop enabled, and next
block version `0`. HSD separately confirmed final checkpoint height 258,026 and
hash `0000000000000004963d20732c58e5a91cb7e1b61ec6709d031f1a5ca8c55b95`.

After a clean hsrd shutdown, the completed store reopened at the same tip and
the strict header/deployment comparator passed again with zero newly received
headers, zero pending bodies, and no runtime error. The runs also exercised
intermediate canonical comparisons while the index was still advancing.

This is qualification evidence for header linkage, mainnet difficulty and
timestamps, hardcoded checkpoints, chainwork/fork selection, canonical
ancestry, BIP9 deployment state, deployment-derived script policy, batching,
and restart recovery. Script *policy* parity does not mean historical script
execution. It is explicitly not full block-body, script-execution, covenant,
UTXO, name-state, Urkel-root, undo, reorganization, or active-state IBD replay
evidence; those gates remain open below.

### Complete pinned-HSD script-corpus qualification

On 2026-07-22, the full script corpus was exported from the clean HSD source at
revision `698e252ebc7b5c1dd0a9587e342fdd153d020ae4`. The exporter first reran
every declared upstream case through HSD 8.99.0 and rejected any declared-result
drift. The resulting schema-1 artifact contained exactly 876 sequential cases:
409 accepted and 467 rejected across 22 normalized result classes. Its
BLAKE2b-256 digest was
`4079e8d0022d7ecbe7524dfa7fc310c7d2ed95a5f1cffb47a24ee5117b5a8991`.

The native Rust verifier matched every execution result and every HSD sigop
count. It now independently pins the oracle repository, revision, version,
source description, exact case count and IDs, transaction witness bytes, and
SHA3 witness-script address commitment before comparing outcomes. This closes
the complete upstream interpreter differential for the pinned revision. It is
not a substitute for full-mainnet block/state replay or independently sourced
invalid corpora at the surrounding contextual boundaries.

## HSRD active-state body scheduling qualification update

On 2026-07-21, a bounded early-mainnet active-state replay used the local
pinned-source `hsd-cli` and native public-peer P2P traffic. The reference HSD
reported version 8.99.0, mainnet height 339,284, and `prune: true`; its source
revision remained `698e252ebc7b5c1dd0a9587e342fdd153d020ae4`.

The live run first reproduced two historical-body scheduling defects. Honest
`notfound` replies from pruned peers were counted as failures and could exhaust
the pending limit, while body work that had moved into validation or orphan
retention no longer occupied a scheduler slot. The latter admitted 8,192
tracked future bodies into a 1,024-block orphan pool and produced 5,116
deterministic evictions by active height 596.

The corrected scheduler keeps one reservation across pending, inflight,
validation, and orphan states; limits canonical acquisition to the configured
orphan-count horizon; treats an assigned peer's `notfound` as separate
connection-local availability evidence; rejects cross-peer cancellation; and
accepts a valid response already in transit during post-timeout backoff. A
follow-up run progressed from active height 684 through at least 869 with
exactly 1,024 tracked bodies, 1,020 retained future bodies, zero orphan
evictions, zero failed bodies, zero scheduler failures, and no contextual
failure.

After clean shutdown, the final optimized binary reopened the same WAL-backed
store under a new runtime instance at active height 873/stored height 874 and
resumed network work through active/stored height 912, including 39 newly
connected blocks. Its first restarted sample again held exactly
1,024 reservations with zero scheduler failures, unavailable-body miscounts,
orphan evictions, failed bodies, contextual failures, or runtime error. A later
remote-peer turnover left the recoverable peer-unavailable supervisor message
and reconnected automatically while all body/contextual failure counters
remained zero.

This qualifies bounded reservation accounting, pruning-aware peer failover,
early historical body retention/import, and active-state restart resumption. It
is deliberately not full historical replay evidence: the bounded WAN run
stopped below mainnet transaction-start height 2,016 and therefore does not
qualify transaction-bearing historical script execution, the complete
checkpoint range, sustained reorganizations, or persistent pruning-horizon
discovery. The fixture and unit differential gates cover those route boundaries
without converting this partial live replay into an authority claim.

### HSD request batching, timeout, and frame-read continuation

On 2026-07-22, the same schema-14 WAL replay was continued from active height
6,496 against eight public mainnet peers and the local pinned-source HSD 8.99.0
oracle. The replay exposed three coupled transport/scheduling differences from
HSD: hsrd sent one `GETDATA` packet per hash, charged every simultaneously
expired hash as a separate peer penalty under 20/15-second block/header
deadlines, and recreated a non-cancellation-safe partial frame read whenever a
ping timer won `select!`. The first two produced redundant unavailable-action
bursts and local disconnect churn; the last could consume part of a large block
payload and then misread its remaining bytes as a frame header.

The corrected runtime batches each poll's selected block hashes into one
bounded `GETDATA` inventory per peer, atomically rolls back the exact batch when
outbound queue admission fails without consuming a retry, and immediately
removes only a transport-stale peer. Queue pressure retains the peer and retries
cleanly. Header admission has the same rollback behavior. Default header and
block deadlines now match HSD's 60-second `GETHEADERS` response and 120-second
block deadlines, and an expired block batch produces one peer disconnect action
rather than one score increment per hash. A frame read remains pinned across
ping, idle, and shutdown maintenance branches so timer activity cannot discard
partially read bytes.

The final optimized replay ran for four minutes, crossing repeated 30-second
ping ticks and both HSD request deadlines. It held all eight peers with exactly
eight initial connection attempts and no reconnects, advanced active/stored
state from 6,614/6,615 to 6,644/6,644, received 1,062 bodies, and connected 39
blocks during the runtime. The final sample retained exactly 1,024 bounded body
reservations with zero scheduler failures, unavailable-body counts, orphan
evictions, stored/contextual failures, rejected messages, or runtime error.
Best-header/target height 339,299 matched the local HSD oracle's canonical
height. The runtime then shut down cleanly.

This extends the bounded early-history and restart qualification through height
6,644 and directly qualifies HSD-shaped request batching, timeout behavior, and
timer-safe frame continuation. It still is not complete checkpoint-range
historical replay, sustained reorganization/pruning evidence, or authority
qualification.

### Restart-durable out-of-order canonical bodies

The same 2026-07-22 replay exposed a restart gap in body retention: a validated
canonical body whose lower parent body had not arrived was held only in the
volatile orphan pool. An IDE restart or power loss therefore discarded most of
the bounded 1,024-body download window even though the storage model already
supported non-active bodies.

Canonical shadow imports now recheck that the body hash is the durable
best-header-path hash at its claimed height, perform strict body/header and
header-ancestry validation, and atomically store the non-active body/index even
when the parent body is absent. Ordinary block acceptance, active-state
connection, and reorganization retain the complete parent body/index
requirement. Non-canonical descendants remain in the bounded in-memory orphan
pool. The contiguous stored tip stays at the first gap, so its bounded download
window advances only after the missing body arrives.

With the optimized binary and the preserved WAL store, the first live sample
advanced active/stored state from 6,644/6,644 to 6,759/6,763 in under one minute,
durably stored 145 bodies, connected 115 blocks, and reported zero orphans,
evictions, scheduler failures, unavailable bodies, stored/contextual failures,
or runtime errors across eight peers. After a clean stop and reopen, retained
future bodies immediately helped advance both tips to 6,815 and then 6,856; the
restarted runtime durably stored 76 new bodies and connected 59 blocks with the
same zero-error counters. Its best-header/target height 339,301 matched the
local pinned-source HSD 8.99.0 oracle.

This qualifies restart persistence and gap recovery for bounded early-mainnet
canonical body scheduling. It is not complete historical replay, sustained
reorganization/pruning evidence, or authority qualification.

### Seed-only plaintext peer discovery

On 2026-07-22, the preserved schema-14 WAL replay was restarted with the final
optimized binary using `--p2p-discovery` and no explicit `--connect` sockets.
The mainnet HSD seeds resolved 20 unique admissible plaintext endpoints with
zero DNS failures. Qualification of the first candidate exposed two bootstrap
ordering defects: seed entries used a later eligibility instant than the
initial reconnect fill, and socket spawning followed potentially expensive
historical active-state/body-queue scans. The corrected runtime uses one
coherent initialization instant, refills eligible discovery slots on every
poll, and spawns due sockets before local replay work. A separate regression
also ensures that TCP connection alone cannot reset failure history; only a
completed VERSION/VERACK Ready handshake does so.

The final seed-only run made eight peers Ready after 11 attempts. Three failed
discovered endpoints rotated without displacing a healthy slot or populating
the runtime error. GETADDR/ADDR exchange accepted 668 HSD announcements and
retained 287 unique addresses within the 4,096-entry configured bound. The
runtime advanced active and contiguous stored state from height 7,232 to 7,416,
received 432 bodies, and durably stored and connected 184 blocks. It retained
exactly 1,024 tracked body reservations with zero failed or unavailable bodies,
stored-body failures, contextual failures, orphan retention/evictions, rejected
messages, or `last_error`. Its best-header/target height 339,304 exactly matched
the local pinned-source HSD 8.99.0 protocol-v3 oracle, which also reported eight
connections and no errors. The runtime then shut down cleanly.

After the final concurrency cleanup and all Cargo gates, the exact optimized
artifact reopened the same store again, relearned 287 unique addresses, made
seven peers Ready with its eighth socket still connecting after eight attempts,
and resumed active/stored state through height 7,438. Failed/unavailable bodies,
stored/contextual failures, orphans/evictions, rejected messages, and
`last_error` all remained zero before another clean shutdown.

This qualifies bounded HSD DNS bootstrap, v3 GETADDR/ADDR learning, failed
target rotation, connection scheduling ahead of historical scan work, and
seed-only restart progress over plaintext transport. Brontide, durable
threshold bans (qualified separately below), long-lived reputation, and broader
adversarial network qualification remained release-blocking at that stage.

### Durable peer-address restart qualification

The bounded discovered-address state now uses the previously reserved `peers`
column family. One checksummed, versioned, network-bound snapshot retains each
IP endpoint's services, advertised time, attempts, last success, last attempt,
and stable selection sequence. Explicit operator peers are never cached. Dirty
state flushes on HSD's 120-second cadence and on runtime shutdown. Restore
applies the same 60-second recent-attempt exception, 30-day address horizon,
three-attempt never-successful rule, and ten-failure/seven-day successful-host
rule as the pinned HSD `HostList`; cooldowns are reconstructed with the local
60-second bound. Malformed cache data warns and falls back to discovery, while
a storage read error still aborts startup.

The preserved mainnet replay at active/stored height 7,438 first bootstrapped
from DNS with no prior cache, reached 279 known addresses, and cleanly flushed
generation 1. The exact optimized binary then reopened the same RocksDB store,
loaded 187 usable addresses before network learning, and pruned 92 stale HSD
advertisements. It made all eight outbound peers Ready after eight attempts and
continued to 285 known addresses with zero decode or flush failures and no
runtime error. Best-header/target height 339,307 remained coherent across the
restart. A second clean shutdown flushed the refreshed cache.

After the TCP-timestamp fidelity regression and complete final-tree gates, the
exact final release reopened generation 4. It loaded 197 entries, pruned 91
stale entries, made all eight peers Ready after eight attempts, and continued
to 296 known addresses. Decode/flush failures and the runtime error remained
zero; active/stored height stayed coherently at 7,438 while best-header/target
advanced to 339,308 before another clean flush.

This qualifies the record codec, HSD stale policy, attempt/cooldown restoration,
clean flush, and real RocksDB restart path. The address book remains
non-consensus operational input; it does not make plaintext peers authoritative
or close the long-lived reputation, broader adversarial diversity, and
Brontide gaps.

### Restart-durable HSD peer-ban qualification

The pinned HSD `Peer`/`Pool`/`HostList` path uses a connection-local score of
100 to ban the normalized host for 24 hours, with the host remaining banned
through the exact expiry second. HSRD now preserves that threshold and expiry
shape while making only the resulting IP ban restart-durable. Subthreshold
scores remain connection-local and are intentionally not promoted into invented
reputation.

The live-manager regression crosses 99 then 100, proves no earlier ban event,
disconnects all live sessions for the IP, and rejects both a new outbound socket
and an accepted inbound socket before peer registration. The node regression
proves every port on a banned IP is excluded from discovery selection and ADDR
relay, that a dormant explicit target cannot consume a discovery slot, and that
learned endpoints are removed without deleting operator configuration.

The separate `peers/ban-list/v1` record is bounded to 16,384 normalized IPs,
checksummed, versioned, generation-counted, and network-bound. Deterministic
tests cover IPv4/IPv6 encoding, checksum and network rejection, earliest-expiry
eviction, exact expiry pruning, clean no-op persistence, and a real RocksDB
close/reopen that restores the active ban. Runtime diagnostics expose loaded,
pruned, expired, active, event, generation, dirty, flush, decode-failure, and
last-error state. New bans and expiry compaction flush immediately, failed
writes remain dirty for the 120-second retry cadence, and shutdown performs a
final flush.

No healthy public peer was deliberately banned to manufacture live evidence.
The local transport, scheduler, persistence, and RocksDB restart regressions
exercise the enforcement boundaries without poisoning the preserved mainnet
address cache. Brontide, long-lived subthreshold reputation, broader
peer-diversity controls, and adversarial WAN qualification remain
release-blocking.

### HSD outbound address-group parity

The pinned HSD `NetAddress#getGroup()` and `Pool#getHost()` paths group IPv4
peers by `/16`, ordinary IPv6 peers by `/32`, Hurricane Electric tunnels by
`/36`, and normalize 6to4, Teredo, RFC6052, and RFC6145 addresses to their
embedded IPv4 prefix. Explicit operator nodes bypass HSD's collision filter,
while each live outbound attempt reserves its group.

HSRD now produces the same canonical group bytes for pinned HSD vectors across
those address families, including local and unroutable classifications.
Discovered target filling greedily selects unique groups, and due socket
attempts reserve groups within the same scheduling pass so simultaneous
connections cannot race into one prefix. Explicit targets retain priority and
may intentionally share a group, while their active or immediately due
attempts exclude colliding discovered targets. Runtime diagnostics report the
distinct groups represented by connected and connecting outbound peers.

Deterministic regressions cover group-byte parity, discovered selection,
simultaneous attempt reservation, and explicit collision bypass. This closes
the concrete HSD network-prefix selection gap; ASN-based diversity, Brontide,
long-lived reputation, and adversarial WAN qualification remain open.

### HSD compact-block wire and reconstruction parity

The pinned HSD `bip152.js`, packet, and pool paths were used as the executable
reference for compact-block version 1. The deterministic oracle now emits exact
SENDCMPCT, CMPCTBLOCK, GETBLOCKTXN, and BLOCKTXN frames for a transaction-bearing
regtest block. Rust decodes and re-encodes every frame byte-for-byte, including
the header/nonce-derived SipHash key, 48-bit witness short IDs, prefilled
coinbase, and differential transaction indexes.

The shadow runtime advertises request-only compact support, selects compact
inventory only after valid peer negotiation, fills short IDs from a bounded
mining-engine mempool snapshot, and requests exactly the missing transactions
from the owning peer. Complete reconstructions enter the same stateless and
ordered validation path as full blocks. Pending state is capped at 15 blocks
per peer and 128 globally, expires on HSD's 30-second block-transaction
response deadline, and is discarded on disconnect. Duplicate IDs or
recoverable response mismatches use
the bounded score-10 full-block fallback; malformed or unavailable requests use
the score-100 path.

A managed-peer raw-TCP regression reserves a native two-transaction block,
invokes the negotiated compact handler, observes the exact GETBLOCKTXN on the
socket, supplies BLOCKTXN, and waits for normal block validation to finish.
Implementation bounds cover randomized compact responses, the recent 15-block
transaction window, peer ownership, and diagnostic accounting. This closes
local wire/reconstruction/serving parity; sustained compact-relay WAN
qualification remains part of broader adversarial network testing.

## HSRD transaction-bearing name-root qualification update

On 2026-07-21 local time (2026-07-22 UTC), a fresh schema-14/profile
`hsrd-mining-v10` WAL store replayed canonical mainnet bodies through active
height 4,551 with five public peers. Targeted in-memory publication of each
committed header/block record replaced the prior full durable-index rebuild on
every successful block, removing the dominant historical replay bottleneck.

The faster run exposed and then qualified HSD's two-stage name-tree timing.
Canonical block 2,024 contains 105 `OPEN` outputs and changes HSD's working
Urkel transaction, but headers continue to commit the last interval root.
Canonical header roots observed by the final binary were:

```text
height 2024  0000000000000000000000000000000000000000000000000000000000000000
height 2025  0000000000000000000000000000000000000000000000000000000000000000
height 2052  0000000000000000000000000000000000000000000000000000000000000000
height 2053  f8cd0cf9ae5c154d7aefbdaed84c6a30951c1707f01f0d86b9e731a73c3db789
```

HSRD now persists the working root separately from the header-visible root,
advances the latter only at the network `treeInterval`, carries both root pairs
through block undo/reorganization, retains both during node compaction, checks
their timing and continuity at startup, and supplies the committed root to
mining snapshots and API-v9 live comparison. The schema/profile and block-undo
version bumps make this an explicit clean-reindex boundary.

Before clean shutdown the run reported active height 4,466/stored height 4,467,
1,024 tracked bodies, five connected outbound peers, zero failed or unavailable
scheduler blocks, zero stored/contextual failed bodies, and zero orphan
evictions. The same store reopened under a new runtime instance, passed startup
root/pin/undo invariants, connected 64 more blocks through active/stored height
4,551, and again reported zero failed, unavailable, contextual-failed, or
evicted bodies. Best-header synchronization independently reached canonical
height 339,289.

This qualifies the transaction-start boundary, the first mainnet OPEN burst,
multiple name-tree commitments, subsequent early auction traffic, targeted
cache publication, and clean restart resumption. It remains bounded WAN
evidence rather than complete checkpoint-range body replay, sustained
reorganization/pruning qualification, an invalid corpus, or authority evidence.

## HSRD canonical genesis qualification update

On 2026-07-22, the pinned HSD oracle exported the complete canonical 452-byte
genesis block for mainnet, testnet, regtest, and simnet directly from
`lib/protocol/genesis-data.json` through `Network.genesisBlock`. HSD decoded
and byte-round-tripped every block, matched each configured genesis hash,
reported a valid body with height zero, and confirmed the shared
2,002,210,000-unit genesis reward transaction.

Native regressions decode those exact bytes and pass every network through the
strict peer-style import path. They require canonical header/hash identity,
body commitments, transaction-start and coinbase-height checks, active UTXO
and undo connection, and a clean durable state-engine restart. Mainnet then
connects the exact canonical block 1 through the same strict path, preserving
HSD's distinction between its non-final-looking coinbase and ordinary
transaction finality. Mutated height-zero rejection remains covered
separately.

## Audit exceptions

- RustSec reports `instant 0.1.13` as unmaintained through
  `reed-solomon-erasure 6.0.0`; it does not report a vulnerability advisory.
- The pinned, loopback-only HSD oracle dependency graph retains the unpatched
  `bsock` advisory `GHSA-jj93-39pf-7mcf`. The audit gate permits only that exact
  package graph and advisory. It remains a production-HSD release blocker.

## Qualification boundary

This result verifies the integrated research source tree and its reproducible
local gates. It does not certify production readiness. HSRD remains
pre-authority, defaults to shadow operation, and cannot provide native mainnet
authority. Hardware, WAN, external protocol review, complete historical and
invalid-corpus parity, and the other gaps in
[HSRD readiness](hsrd/docs/readiness.md) remain release requirements.
