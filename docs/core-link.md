# Authenticated Core link and live parent qualification

Status: source-complete pre-production handoff. Native mainnet authority remains disabled.

## Purpose

The private Core/operator transport replaces the
research parent-certificate allowlist with bounded live qualification against a
local HSD node. An optional local HSRD node can act as an independently
implemented shadow witness. The Core-link operator is now composed with the
continuous supervisor, fallback behavior, event journal, graceful shutdown, and
read-only dashboard.

```text
local HSD authority ----+
                        | exact parent hash/height/time/chainwork
optional HSRD shadow ---+----> meshmine-cored
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

The authoritative HSD source has two deliberately separate qualification modes.

For historical capture admission it must confirm:

- the configured HNS network;
- an active-chain header with positive confirmations;
- exact parent hash, height, header time, and cumulative chainwork;
- a confirmation count consistent with the node's active height;
- the configured minimum confirmations and maximum certificate depth;
- the configured maximum wall-clock age.

For staging, offering, or continuing an actively served mining assignment it
adds a stricter requirement: the certified parent must be HSD's current best
block at exactly one confirmation. A bounded canonical ancestor may therefore
remain usable to classify a delayed capture, but it cannot continue authorizing
new ASIC work. Active-tip and canonical-depth results use separate cache keys.

A successful result may be cached only for the configured short TTL. Failed
results are not cached as a different generic error and are checked again on
the next request.

The optional HSRD shadow source must match the HSD-observed parent hash, height,
time, and chainwork, report that header on its active chain, and remain within
the configured block/header-tip lag. For an active assignment it must also
report that exact parent as its own current best block.
When `require_hsrd_match` is true, HSRD failure or disagreement rejects the
parent. When it is false, HSD remains authoritative and HSRD failure is exposed
as an advisory diagnostic rather than silently treated as agreement.

HSRD never grants authority. It can only add a required or optional
implementation-diverse witness to the local HSD qualification.

### RPC boundary

Parent RPC sources are deliberately constrained:

- explicit loopback socket addresses only;
- HTTP/1.0 or HTTP/1.1 POST only;
- bounded request path and authorization header;
- bounded connect, read, and write timeouts;
- bounded response and header sizes;
- exact JSON-RPC response ID;
- HTTP 200 only;
- no chunked or other transfer encoding;
- no redirects, proxies, TLS bypasses, or public listeners.

The optional authorization-header file contains the complete header value, for
example `Basic ...`. It must be an absolute, nonsymlink, bounded, user-owned
private file. The value is never written to diagnostics.

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
- HSD is still the authoritative local parent source.
- HSRD remains pre-authority and may only serve as a shadow witness.
- HSD RPC transport is local plaintext HTTP; public or remote deployment is not
  part of this profile.
- The Core server accepts one authenticated operator connection at a time.
- Physical ASIC job-switch, stale-work, reconnect, and fallback behavior remain
  unqualified.
- Complete historical consensus parity and native mainnet authority remain
  disabled.
- Rust formatting, compilation, Clippy, unit tests, and release builds remain
  mandatory CI gates.
