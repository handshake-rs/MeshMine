# Static settlement-role workflow

This document describes the implemented Core v2 research workflow for
work-only payout snapshots and delayed-entropy payout plans. It uses the frozen
PayoutSnapshotV2 and PayoutPlanV2 objects and does not add a partial-signature
network message.

## Strict static profile

The payout profile now fixes every input needed for deterministic local
verification:

- snapshot_step_work: a 64-byte big-endian U512 hex value;
- pplns_window_work: a 64-byte big-endian U512 hex value;
- entropy_delay_blocks: the exact delay D after the snapshot anchor;
- entropy_block_count: the exact window length R;
- maximum_entropy_blocks: a parser/resource ceiling at least R;
- prior_beacon: the exact 32-byte research beacon input; and
- ticket, output, and minimum-value policy.

The static daemon currently requires service_ticket_count and
service_basis_points to be zero. The settlement library has bounded service
credit arithmetic, but Core v2 has no daemon-composed durable service-event
record from which an independent signer can reproduce service leaves.
Accepting caller-supplied service credits would make threshold signatures the
only evidence, so this workflow fails closed instead.

Snapshot construction currently supports one complete linked mask-session
lane. Every retained closed session must begin at a zero previous-session ID
and then advance by one session sequence with the exact previous session ID.
Multi-lane snapshot ordering is not frozen in Core v2, so the static producer
rejects it rather than choosing an incompatible ordering.

## Evidence checked by every member

Before signing a snapshot, a member:

- recovers every receipt batch and settlement-certified close;
- verifies the complete receipt and close chains with the configured rosters;
- loads each exact accepted share and active signed payout bucket;
- derives credited work from the share target;
- reconstructs the linked closed-session sequence;
- replays SnapshotAccumulator from sequence zero with the configured step and
  PPLNS window; and
- requires the proposal to equal the exact next unsigned work-only snapshot.

Before signing a plan, a member additionally requires:

- a known certified snapshot;
- the exact configured entropy start and count;
- every entropy height/hash to match its own canonical hsd;
- the exact configured prior beacon; and
- deterministic seed, rejection-sampling transcript, and winners.

## Operator sequence

Stop the process using a state directory before a one-shot command opens it.
Create independent settlement keys with committee-key-init and place their
public keys in the settlement roster.

After enough complete session work exists:

~~~sh
cargo run --locked -p meshmine-node -- payout-snapshot-propose \
  --dir /var/lib/meshmine-settlement-a \
  --network-id 2 \
  --hsd-cli /path/to/hsd-cli \
  --settlement-roster settlement.json \
  --mask-roster mask.json \
  --availability-roster availability.json \
  --receipt-roster receipt.json \
  --payout-profile payout-profile.json \
  --out snapshot.proposal
~~~

Each settlement member signs the empty-certificate proposal:

~~~sh
cargo run --locked -p meshmine-node -- settlement-sign \
  --dir /var/lib/meshmine-settlement-a \
  --network-id 2 \
  --hsd-cli /path/to/hsd-cli \
  --settlement-roster settlement.json \
  --mask-roster mask.json \
  --availability-roster availability.json \
  --receipt-roster receipt.json \
  --payout-profile payout-profile.json \
  --key /secure/settlement-member.key \
  --topic payout-snapshot \
  --proposal snapshot.proposal \
  --out member-a.snapshot-signature
~~~

The assembler supplies the same validation inputs, its exact current static
peer configuration, and at least the roster threshold:

~~~sh
cargo run --locked -p meshmine-node -- settlement-assemble \
  --dir /var/lib/meshmine-settlement-assembler \
  --network-id 2 \
  --hsd-cli /path/to/hsd-cli \
  --settlement-roster settlement.json \
  --mask-roster mask.json \
  --availability-roster availability.json \
  --receipt-roster receipt.json \
  --payout-profile payout-profile.json \
  --peer-config static-peers.json \
  --topic payout-snapshot \
  --proposal snapshot.proposal \
  --signature member-a.snapshot-signature \
  --signature member-b.snapshot-signature \
  --out snapshot.certified
~~~

After the exact entropy window is available on canonical HNS:

~~~sh
cargo run --locked -p meshmine-node -- payout-plan-propose \
  --dir /var/lib/meshmine-settlement-a \
  --network-id 2 \
  --hsd-cli /path/to/hsd-cli \
  --settlement-roster settlement.json \
  --mask-roster mask.json \
  --availability-roster availability.json \
  --receipt-roster receipt.json \
  --payout-profile payout-profile.json \
  --out plan.proposal
~~~

Use settlement-sign and settlement-assemble again with the payout-plan topic.
The assembler durably admits the exact threshold wrapper and creates its
static-peer outbox locator before publishing the atomic certified artifact.

## Reorganizations and signing guards

A snapshot member reserves at most one object for each settlement roster and
snapshot sequence. Snapshot replacement is rejected.

A payout plan is different because its delayed HNS entropy may be reorganized.
The plan guard is bound to the settlement roster, snapshot ID, and exact
entropy branch. It permits an independently verified replacement after the old
entropy is no longer canonical, while still allowing only the deterministic
plan for a given branch. The admission controller removes the noncanonical
eligible plan and installs the new threshold-certified canonical plan.

Exact signature retries survive restart. Proposal, signature, and certified
artifact files are atomic and immutable. Assembly uses the same pre-admission
publication intent as receipt production, so an interrupted journal-to-outbox
transition is recovered.

## What remains

This is an operator-mediated, single-lane, work-only static workflow. The
configured prior beacon is an explicit research input, not a deployed
threshold-beacon service. Automatic proposal rounds, partial-signature
transport, durable service-credit events, multi-lane snapshot ordering,
dynamic rosters, and independent public settlement operators remain absent.
SessionCloseV2 production is also intentionally absent because Core v2 does
not freeze the pre-opening close-intent or mask-opening-share wire boundary.
