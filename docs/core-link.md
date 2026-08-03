# Authenticated Core link and live parent qualification

Status: source-complete pre-production handoff. The pinned standalone node has
complete functional readiness and a conditional canary permit path. Its base
snapshot uses `pre-authority`, live native RPC reports a mode-specific stage,
and MeshMine production mode remains disabled.

The explicit native mainnet canary can synchronize and report its gates. Core
accepts work only while `hsrd` reports the synchronized, all-readiness
`mainnet_canary_active` state and the exact durable tip remains authoritative.
This introduces no second node implementation or shadow-authority path.

## Purpose

The private Core/operator transport replaces static parent-certificate
allowlisting with bounded live qualification against one authenticated local
`hsrd` node from the pinned external Rust stack. The Core-link operator is composed with the
continuous supervisor, fallback behavior, event journal, graceful shutdown, and
read-only dashboard.

```text
authenticated native hsrd
    | one coherent authority/tip/header snapshot
    +--------------------------> meshmine-cored
                                     |
                                     | private Unix-domain Core link
                                     | SO_PEERCRED + pinned Ed25519 identities
                                     v
                         meshmine-corelink-operatord
                                     |
                                     | loopback HandyStratum
                                     v
                                  HNS ASICs
```

The link remains local and fail-closed. It does not introduce a public Core
listener, a global work allocator, a universal hash engine, or native mainnet
mining authority.

## Live parent qualification

`meshmine-parent-oracle` implements `ParentChainOracle` through bounded local
JSON-RPC calls.

The authoritative `hsrd` source has two deliberately separate qualification modes.
Every check first calls the hsrd-specific `getparentauthority` method, which
returns authority, active tip, requested header, and durable validation status
from one immutable node snapshot. Core requires all of the following before it
examines the certificate:

- the RPC listener reports that Authorization enforcement is enabled;
- the diagnostic API supports the atomic authority method;
- authority mode is exactly `native` and consensus readiness is complete;
- template and candidate authorization are both enabled with no blockers;
- the durable mining tip is authoritative and no better-chain activation is pending;
- every consensus, state-connection, undo, and active-chain validation bit is
  set and the failed bit is clear.

For historical capture admission it must confirm:

- the configured HNS network;
- an active-chain header with positive confirmations;
- exact parent hash, height, header time, and cumulative chainwork;
- a confirmation count consistent with the node's active height;
- the configured minimum confirmations and maximum certificate depth;
- the configured maximum wall-clock age.

For staging, offering, or continuing an actively served mining assignment it
adds a stricter requirement: the certified parent must be `hsrd`'s current best
block at exactly one confirmation. A bounded canonical ancestor may therefore
remain usable to classify a delayed capture, but it cannot continue authorizing
new ASIC work. Active-tip and canonical-depth results use separate cache keys.

A successful result may be cached only for the configured short TTL. Failed
results are not cached as a different generic error and are checked again on
the next request.

There is no fallback or optional witness. RPC loss, malformed or unauthenticated
responses, incomplete readiness, staged state, and certificate mismatch all
reject the parent. Core and the operator do not invoke a second node or compare
two authorities at runtime.

### RPC boundary

The sole hsrd RPC source is deliberately constrained:

- explicit loopback socket addresses only;
- HTTP/1.0 or HTTP/1.1 POST only;
- a mandatory Authorization value loaded independently by both daemons from a
  mode-private file;
- bounded request path and authorization header;
- bounded connect, read, and write timeouts;
- bounded response and header sizes;
- exact JSON-RPC response ID;
- HTTP 200 only;
- no chunked or other transfer encoding;
- no redirects, proxies, TLS bypasses, or public listeners.

The authorization-header file contains the complete header value, for example
`Bearer ...`. Core requires an absolute, nonsymlink, bounded, user-owned private
file. `hsrd` opens an absolute nonsymlink private file and applies that exact
value to every JSON-RPC and diagnostic route. The value is redacted from Debug
output and never written to diagnostics.

## Qualification points

The parent is checked at every authority-sensitive boundary:

1. Assignment-bundle staging.
2. Core daemon startup against the active bundle.
3. Active and pending assignment delivery.
4. Capture admission through the existing share validator.
5. Periodic Core-link heartbeat/read-timeout processing. The Core read timeout
   is also the parent-requalification interval and is hard-capped at five
   seconds; the example uses one second.
6. Pending assignment drain and transition.

If a previously accepted active parent stops being the current tip, the Core connection closes.
The operator then enters its supervised fallback path instead of continuing to
serve the stale authority context.

## Authenticated Core link

The transport retains these properties:

- private Unix-domain socket;
- Linux `SO_PEERCRED` UID binding;
- pinned mutual Ed25519 challenge authentication;
- bounded, checksummed frames;
- monotonically increasing directional frame sequences;
- exact message kind and canonical payload validation;
- bounded authentication, read, and write timeouts;
- separately signed authority-bearing objects.

An authenticated connection is transport evidence only. Assignments, captures,
receipts, drains, and transitions remain independently signed and canonically
identified.

## Assignment bundle

`CoreAssignmentBundleV1` binds one exact mining context:

- network and protocol versions;
- Core and gateway identities;
- context manifest and gateway assignment;
- mask session and live-qualified parent certificate;
- exact block body and body validation commitment;
- erasure descriptor and availability certificate;
- payout bucket;
- mask, availability, and settlement committee rosters;
- advertised HandyStratum difficulty;
- optional previous-assignment replacement boundary;
- Core signature over the complete unsigned object.

The operator derives the gateway job from the bundle. It does not accept a
second, loosely matched job representation.

## Capture lifecycle

```text
ASIC share
    -> gateway validates assignment and active local job
    -> operator signs and durably spools GatewayCaptureEnvelopeV1
    -> authenticated Core link submits the envelope
    -> Core requalifies the bundle and reconstructs exact ShareV2
    -> Core atomically persists accepted work/share or noncredit disposition
    -> Core signs GatewayCaptureReceiptV1
    -> operator atomically persists receipt and removes pending envelope
    -> gateway acknowledges and compacts the original capture
```

A link interruption does not erase captures. The operator retries stable work
keys and Core returns an existing terminal receipt for an exact retry.

## Assignment replacement and drain

A replacement bundle freezes a credit cutoff and previous submission end.
At the cutoff the operator:

1. Enters supervised `draining` mode.
2. Closes local MeshMine sessions so ASIC fallback slots can take over.
3. Preserves the old assignment for its submission grace interval.
4. Drains remaining durable captures.
5. Signs the final drain and transition.
6. Receives Core's terminal drain receipt.
7. Installs the exact next bundle-derived job.
8. Rotates miner connections onto the new assignment.

The operator does not infer exhaustive ASIC range completion from a disconnect
or drain.

## Daemons

Core:

```text
meshmine-cored stage-bundle --config /absolute/core-v9.json \
  --bundle /absolute/bundle.bin
meshmine-cored serve --config /absolute/core-v9.json
meshmine-cored status --config /absolute/core-v9.json
```

Unified operator:

```text
meshmine-corelink-operatord serve \
  --config /absolute/operator-corelink-v9.json
```

The Core status command reports active and pending parent qualification
separately.

## Example configuration

- `specs/core-link-core.example.json`
- `specs/core-link-operator.example.json`
- `specs/core-link-parent-oracle.example.json`

## Deliberate limitations

- Both daemons reject `production: true`.
- The pinned external Rust node is the sole runtime Handshake authority.
- Mainnet additionally requires hsrd's explicit canary flag, exact
  header/active-state synchronization, every individual readiness bit, and the
  stricter mainnet freshness/cache policy.
- The pinned node revision reports complete source readiness. Any later loss,
  mismatch, stale snapshot, or incomplete durable authority state still makes
  Core reject all authority-bearing work.
- The authenticated hsrd RPC transport is local HTTP; public or remote
  deployment is not part of this profile.
- The Core server accepts one authenticated operator connection at a time.
- Physical ASIC job-switch, stale-work, reconnect, and fallback behavior remain
  unqualified.
- Broader historical/WAN/reorganization campaigns and MeshMine production
  eligibility remain open; they do not rewrite the pinned node's complete
  functional readiness or make any release-stage diagnostic authoritative.
- Rust formatting, compilation, Clippy, unit tests, and release builds remain
  mandatory CI gates.
