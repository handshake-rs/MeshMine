# Latency lanes and the block-publication fast path

Status date: 2026-07-18. Receive callbacks, live forwarding queues, per-peer
in-flight sends, and durable replay are isolated for the existing authenticated
overlay topics. End-to-end job activation, winner opening, reconstruction, and
multi-path publication are not yet production composed, so the latency
objectives in this document are requirements rather than benchmark claims.

## Architectural invariant

MeshMine separates four operational lanes. Work in a lower-priority lane must
not consume all execution, queue, connection, or storage capacity required by
a higher-priority lane.

| Lane | Required work | May read | Must never wait for |
|---|---|---|---|
| Fast path | canonical tip activation, winner test, mask opening, block reconstruction, publication fan-out | an already authorized job, current tip, current mask session, certified body material, most recently finalized payout state | share-DAG convergence, receipt batching, a new settlement snapshot, payout selection, historical replay |
| Accounting | share disposition, receipts, DAG gossip, reconciliation, close evidence | the signed assignment/session and local validation context | settlement or payout completion |
| Availability | body descriptors, shards, reconstruction, availability certificates | content commitments and bounded retrieval policy | accounting or settlement completion; the winner path may use already local material or threshold reconstruction |
| Settlement | finalized-window accumulation, snapshot certification, payout planning, carry-forward, payment reconciliation | certified closed accounting windows and finalized entropy | job activation or winner publication |

There must be no synchronous dependency edge from the fast path to accounting
or settlement. The fast path may use the latest already finalized immutable
state. Late shares and a snapshot that finalizes after job activation are
reconciled in a later settlement window.

## Implemented overlay boundary

`meshmine-network::ProtocolLane` deterministically maps every existing signed
gossip topic and request protocol to one local lane. It is not a peer-selected
wire field. The QUIC server reserves separate bounded blocking-callback
semaphores for fast-path, accounting, availability, and settlement work. A
blocked settlement callback therefore cannot consume fast-path callback
capacity. The total lane capacity remains bounded by the configured global
callback ceiling.

The current map is:

- fast path: parent, mask-session, mask-opening, fault-proof,
  session-transcript, and committee-roster traffic;
- accounting: operator, share, receipt-batch, session-close, share-object,
  and receipt-proof traffic;
- availability: body-descriptor, body-package, and body-shard traffic; and
- settlement: payout-snapshot, payout-plan, and payout-transcript traffic.

Outbound live forwarding has one bounded queue per lane. A full settlement
queue cannot consume fast-path queue capacity. Each connected peer has one
bounded in-flight permit per lane, so a slow settlement QUIC stream does not
hold the fast-path permit. Durable replay sends through the same object-based
preflight/send/settle path one object at a time; no replay batch holds a common
send lock. ACK metadata is serialized, but no metadata or outbox lock is held
across network I/O. After a send, settlement re-resolves `(topic, object_id)`
to the current locator sequence, so concurrent outbox compaction cannot make a
stale sequence acknowledge a rebased object. The global immutable locator
sequence and contiguous-prefix compaction format remain unchanged.

`MaskOpening` remains disabled at application admission until its canonical
opening-share object, close-intent boundary, and transcript linkage are frozen.
Reserved capacity does not make an undefined payload admissible.

## Required end-to-end composition

Receive-side isolation is only the first boundary. Production composition must
also provide:

1. separate bounded application actor mailboxes for tip/winner, accounting,
   availability, and settlement work;
2. per-lane queue wait, saturation, drop, replay, and send-latency metrics plus
   immediate replay wakeup when a fast-path live enqueue is dropped;
3. reserved disk and database transaction budgets for winner intent and
   publication records;
4. independent supervision, so a settlement failure pauses settlement rather
   than stopping hashing or discarding winner evidence; and
5. overload behavior that sheds or delays replayable low-priority work before
   refusing fast-path work.

Per-lane ordering must remain deterministic. Cross-lane ordering is not a
consensus claim and must not be inferred from local delivery order.

## Local job activation

The production job engine must prepare a future job before a tip transition.
Activation is local and requires exactly:

- a locally accepted deterministic tip;
- an operator-authorized job whose canonical identifier commits to the exact
  parent, header/template roots, coinbase/payment state, mask commitment, body
  commitment, and assignment context; and
- a local gateway transition that prevents old and new assignment ranges from
  earning simultaneously beyond their signed boundary.

The overlay is notified in parallel and does not approve activation. The
authenticated gateway path now uses the lowercase canonical
`GatewayAssignmentV1` object ID, never a caller-selected display ID. The
`meshmine-hsrd-bridge` additionally requires an exact network/generation/parent
match and byte-identical prepared body before constructing any gateway fields.
It persists an immutable assignment-to-generation/prepared-job record and
reloads it before an opened winner can become a generation-bound `hsrd`
candidate. Atomic live-service activation composition and latency evidence
remain release gates.

## Winner publication

The intended fast path is:

```text
gateway capture
  -> local proof/linkage validation
  -> private threshold winner evaluation
  -> component-mask reconstruction
  -> independent block reconstruction and authoritative-node validation
  -> parallel publication attempts
```

Publication attempts must persist an intent before external submission and
record each terminal result independently. One slow or failed target must not
serialize the others. The Core path now uses the pinned external `hns-node-rs`
node as its only runtime parent/permit source; hns-node-rs is retained only as an
offline fixture and differential oracle, not as a shadow or broadcast
fallback. The node's functional readiness is complete; its base
`pre-authority` stage is replaced in live native RPC by a mode-specific
diagnostic label. The deployment should also
support independently administered reconstruction/submission nodes and
authenticated HNS relay paths. A success from one path does not cancel evidence
collection from already-started paths.

Winner publication does not wait for overlay consensus, DAG convergence, a
new snapshot, payout participants, or nonessential body replicas. It still
requires exact HNS validity, the frozen accepted-share/opening boundary, enough
mask material, and enough body material to construct the block.

## Layered masks

The production design target uses independently administered component
committees:

```text
M = M[0] XOR M[1] XOR ... XOR M[k-1]
maskHash = BLAKE2b-256(parentHash || M)
powHash = shareHash XOR M
```

The component count is fixed for an epoch and bounded. Every component binds a
distinct committee identity, threshold, setup transcript, commitment, opening
policy, recovery policy, and retirement state. Membership changes only at a
deterministic epoch boundary; the next epoch must be certified before it can
receive assignments.

Component commitment hashes alone are insufficient to derive or verify the
combined HNS `maskHash`. The setup protocol must therefore jointly certify the
combined hash without publishing any component mask. A production object must
bind the ordered component descriptors, combined mask hash, parent, epoch,
lane/session sequence, accepted-share close boundary, and certificate. These
wire objects are not yet frozen.

All required components normally reconstruct for a winner. Refusal follows a
precommitted state machine:

1. normal threshold opening before the fast deadline;
2. bounded preauthorized or timelocked recovery;
3. terminal job expiration and permanent retirement if recovery fails.

No component or combined mask may be reused after it is opened. Accounting can
close and reconcile a retired job even when its winner could not be published.

Layering improves confidentiality only under the stated independence and
honesty assumptions; it increases liveness dependencies and does not replace a
production MPC/VSS audit.

## hns-node-rs and fork choice

Exactly one local backend supplies the deterministic mining tip. At least one
independent backend should cross-check header, height, chainwork, and genesis.
A disagreement enters an explicit safe mode: pause new assignment activation,
retain authenticated evidence, keep already-started publication attempts
running, and require deterministic reconciliation. A cross-check backend must
not create an ambiguous multi-tip mining policy.

Push-based tip notification is the preferred activation trigger, with bounded
polling as a watchdog. Both paths must deduplicate the same canonical tip
transition.

## Measurement contract

Performance claims require monotonic-clock, end-to-end observations with exact
start/end evidence. At minimum report count, P50, P95, P99, maximum, failure
count, and unavailable-evidence count for:

- local tip observation to gateway job transmission;
- gateway job transmission to device acknowledgment when the device protocol
  exposes it;
- gateway capture receipt to Core terminal disposition;
- candidate capture to threshold result;
- threshold result to reconstructed valid block;
- candidate capture to first accepted publication target; and
- per-target publication latency and outcome.

Also report stale, invalid, duplicate, grace-noncredit, and accepted capture
rates; gateway uptime/reconnects; body/mask reconstruction failures; lane queue
depth, saturation, drops, and wait time; and partition recovery.

A provisional engineering objective is 1--10 ms from an already observed local
tip to LAN job transmission and less than 100 ms from candidate receipt to the
first accepted block publication. These are not release claims. They become
claims only after reproducible production-hardware and WAN evidence satisfies
the percentile and sample-size policy.

An external comparison must use equivalent ASICs, location, time windows, and
network conditions; swap hardware between paths during the trial; and compare
effective accepted hashrate rather than isolated cryptographic throughput. The
project must not claim that another pool is old or slow without such evidence.

## Safe modes

Every failure has a deterministic local result:

| Failure | Fast-path result | Other lanes |
|---|---|---|
| settlement unavailable | continue with latest finalized state | queue bounded settlement recovery |
| accounting/DAG lag | continue authorized jobs and winner handling | retain/replay bounded evidence |
| body threshold unavailable | use valid local body if present; otherwise fail that candidate safely | request missing chunks and record failure |
| mask threshold refusal | run precommitted recovery, then expire and retire job | reconcile accounting without reuse |
| authoritative external-node snapshot unavailable or stale | stop new jobs; continue already-started fan-out only through valid independent targets | preserve evidence |
| offline hns-node-rs audit disagreement | pause promotion and new release claims | reconcile deterministically; do not choose by timeout |
| settlement-lane overload | backpressure/replay settlement only | fast/accounting reserved capacity remains available |

The implementation is not production-ready until these transitions are
durable, supervised, observable, restart-tested, and exercised under fault
injection.
