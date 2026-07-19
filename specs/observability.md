# MM-0001 local observability profile

Status date: 2026-07-18. This profile defines the bounded local evidence
export implemented by `meshmine-node overlay-observe`. It is an operations and
explorer input for the research implementation, not a public monitoring
service and not evidence that independently operated roles exist.

## Operation and schema

```sh
cargo run --locked -p meshmine-node -- overlay-observe \
  --dir /absolute/path/node-state --network-id 2 \
  --settlement-roster /path/to/settlement.json \
  --mask-roster /path/to/mask.json \
  --availability-roster /path/to/availability.json \
  --receipt-roster /path/to/receipt.json
```

The command writes one deterministic, pretty-printed JSON object with
`schema_version = 3`. Its semantic sections are filtered to the requested
network; `journal.scope = "database-wide"` is explicit because the structural
inventory includes every immutable record in the database. Input scanning is
bounded by the same 100,000-record, 4-MiB-per-value, and 512-MiB aggregate
recovery limits as daemon startup. The additional gossip-delivery scan is
bounded to 100,000 locators/index/source records, 4,096 publication intents,
one canonical topic-migration record, one canonical compaction record, at most
64 configured peer acknowledgment records, and the corresponding compact bitmap bytes. Output is capped at 16
MiB. A malformed canonical object, object-ID/key mismatch, invalid
credit link, missing session, unknown availability descriptor/body, repeated
receipt credit, invalid reorg marker, impossible payout winner, misplaced
gossip locator, missing index, counter mismatch, malformed source mapping,
publication intent, migration bitmap, compaction state, or out-of-range peer
acknowledgment makes the entire command fail closed.

All `U512` work and service values are fixed-width 128-character big-endian
hexadecimal strings. Public keys, object IDs, bucket IDs, and worker hashes are
lowercase hexadecimal. Lists and maps are deterministic so successive exports
can be diffed and independently ingested without numeric precision loss.

The same schema can be served while the node is running. The stable HTTP route
remains `/v1/observability`; clients must use the JSON `schema_version` field
rather than infer the schema from the transport path:

```sh
cargo run --locked -p meshmine-node -- overlay-serve \
  --dir /absolute/path/node-state --listen 127.0.0.1:9443 --network-id 2 \
  --observability-listen 127.0.0.1:9100

curl --fail http://127.0.0.1:9100/v1/observability
```

The listener is optional and rejects every non-loopback bind address. It
supports only `GET /v1/observability` over HTTP/1.0 or HTTP/1.1, closes every
connection, sets `Cache-Control: no-store` and `X-Content-Type-Options:
nosniff`, caps request headers at 8 KiB, and bounds reads and writes with a
five-second timeout. Requests are handled serially, and the bounded journal
scan runs on a blocking worker so neither slow storage nor JSON encoding can
stall the QUIC runtime. Unsupported methods and paths receive 405 and 404;
oversized headers receive 431. A temporarily inconsistent or invalid snapshot
receives 503 without leaking the internal error. A listener failure stops the
explicitly configured service, while a bad individual request cannot do so.

The export contains:

- complete journal category counts and value bytes;
- exact durable-gossip locator and remaining-capacity counts, source-mapping
  and pending-publication-intent counts, completed legacy-migration topic
  groups, cumulative retired-object count, compaction generation, counts by
  supported topic, active locally tombstoned object count, and the compact
  delivery state retained for every peer from the most recent configured
  static-peer recovery;
- per tracked transport key, objects settled by either successful remote
  acknowledgment or direct-source suppression, separately counted local
  reorg tombstones that have no peer-settlement bit, pending objects, and the
  rotating next-scan cursor; plus the deliverably settled intersection and
  pending union across all tracked peers;
- body, template-core, template-operator, ordered transaction-set, and unique
  non-coinbase transaction-ID counts;
- erasure-descriptor, availability-certificate, certified-body, and local-shard
  coverage;
- accepted versus receipt-credited shares, exact credited work by operator
  key, and the subset linked to durable orphan-parent/reorg markers;
- mask-session, receipt-batch, close, reorg-close, and raw numeric close-reason
  counts;
- assignment, unique-worker-hash, and telemetry-level counts;
- the latest snapshot's exact work/service bucket and operator distributions,
  plus ticket counts for every stored plan variant referencing that snapshot;
- optional configured roster sizes, thresholds, committee IDs, and pairwise
  member-key overlap.

Stored payout-plan variants are reported separately. The local export does not
silently choose a canonical variant without an HNS oracle, and member-key
overlap is not treated as proof of organizational independence.

The generic journal/export format can report service credits present in stored
snapshots. The implemented static settlement producer itself is work-only and
requires zero service allocation because it has no independently replayable
durable daemon service-event input.

When no configured-peer records exist, the cross-peer settled/pending fields
are JSON `null`, not zero. Static-peer startup persists the canonical empty ACK
state, so a configured peer with no successful delivery appears with zero
settled objects and the full outbox pending. These are exact local delivery
metadata counts, not proof that a remote peer still retains an object and not
an exactly-once receipt protocol.

`pending_publication_intents` counts bounded exact-wrapper admission records
that startup must resolve. A nonzero value may be transient while admission is
in progress; persistence across recovery is an operator-visible fault signal.
`migrated_topic_groups` reports the canonical one-time legacy migration bitmap
using `operator`, `parent`, `share`, `receipt-and-close`, and `payout` labels.
`compaction_generation` counts committed atomic rebase passes and
`retired_objects_total` is their checked cumulative object count. These prove
the local metadata transition, not continued remote retention. Active
`durable_objects` plus `retired_objects_total` is the local lifetime unique
durable-delivery-object count unless the database was restored or externally
rewritten.

## Required-metric coverage

Every MM-0001 §21.2 metric has a `coverage` entry. The status values distinguish
exact local evidence, a deliberately narrower proxy, raw uninterpreted data,
and unavailable deployment evidence.

Exact or exact-distribution evidence is available for template/body counts,
receipt-credited work, stale-parent shares/work, snapshot bucket credits,
per-plan ticket outcomes, service credits, telemetry levels, and durable static
peer delivery backlog. Ordered
transaction-set identity is exposed instead of inventing an unfrozen
"similarity" function. Committee reporting measures keys and thresholds, not
organizations. Availability certification/local-shard coverage does not claim
public retrieval success. Credited work is not divided by an invented time
window and labeled hashrate.

The export intentionally marks these measurements unavailable when the local
journal cannot prove them:

- mask setup/open latency and fast-path abort rate;
- semantic liveness-failure counts until the close-reason registry is frozen;
- capture-share propagation latency without a signed remote send boundary;
- rejected duplicate-share rate, which is not durable protocol evidence;
- durable-gossip retry/rejection counts and live connection health;
- physical ASIC job-switch latency;
- public retrieval success and organizational committee concentration.

The static-peer supervisor emits retry, rejection, and reconnect status only to
process logs; schema v2 does not turn ephemeral log messages into durable
counts. These measurements otherwise require a frozen wire boundary, live
instrumentation, physical hardware, or independently identified operators. A
zero is never substituted for absent evidence.

## Assurance boundary

`overlay-observe` and the loopback HTTP endpoint validate the exported journal
structure and cross-record accounting relationships. They do not replace
`overlay-serve`'s configured committee-signature and local-`hsd` replay or the
separate JavaScript payout/body artifact checks. That verifier is
implementation-diverse local evidence; neither it nor these metrics establish
the independent maintenance, reproduction, or organizational separation
required by the release gates. Remote/public exposure requires an
operator-managed authenticated sidecar; a historical time-series store,
explorer UI, alerting, access control, and incident-transcript publication
remain deployment work.
