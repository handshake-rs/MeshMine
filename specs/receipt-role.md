# Static receipt-role workflow

This document describes the implemented Core v2 research workflow for producing
threshold-certified ReceiptBatchV2 objects. It composes the existing receipt
object, local share validator, immutable journal, durable signing guard, and
static-peer outbox. It does not define a new MeshMine wire object.

## Boundary

Each receipt member operates an independent MeshMine state directory, local
hsd, static committee rosters, and 32-byte Ed25519 role key. A signer accepts
an empty-certificate ReceiptBatchV2 proposal only after it has:

- recovered and revalidated the active share DAG from exact durable share,
  work-key, first-observation, assignment, body, mask-session, availability, and
  parent evidence;
- checked the certified parent through its own hsd;
- verified that the batch extends its complete local certified receipt chain;
- rejected closed or reorganization-closed sessions;
- reconstructed the canonical entries, Merkle root, cumulative share count,
  and cumulative credited work from the proposal's exact durable shares; and
- reserved one object ID for the receipt roster, session, and batch sequence in
  the durable signing guard before producing signature bytes.

The guard is idempotent for the same proposal and rejects a different valid
proposal for the same logical sequence after restart. It is a local
double-signing defense, not a consensus or remote-attestation mechanism.

## Operator sequence

Stop the process using a state directory before opening that directory with one
of these one-shot commands.

Create one role key per receipt member:

~~~sh
cargo run --locked -p meshmine-node -- committee-key-init \
  --out /secure/receipt-member.key
~~~

The command creates a raw 32-byte seed atomically with mode 0600 on Unix and
prints its public key. Add that public key to the static receipt roster. Never
reuse a transport or operator key as a committee key.

After shares have been admitted, one participant can create a deterministic
proposal from the first uncredited active shares in (work_key, share_id)
order:

~~~sh
cargo run --locked -p meshmine-node -- receipt-propose \
  --dir /var/lib/meshmine-receipt-a \
  --network-id 2 \
  --hsd-cli /path/to/hsd-cli \
  --settlement-roster settlement.json \
  --mask-roster mask.json \
  --availability-roster availability.json \
  --receipt-roster receipt.json \
  --session-id SESSION_ID_HEX \
  --maximum-shares 1000 \
  --out batch.proposal
~~~

The output is a canonical ReceiptBatchV2 whose Ed25519 signature set is empty.
The default and hard maximum are 10,000 shares.

Each member validates and signs that same proposal against its independent
state:

~~~sh
cargo run --locked -p meshmine-node -- receipt-sign \
  --dir /var/lib/meshmine-receipt-a \
  --network-id 2 \
  --hsd-cli /path/to/hsd-cli \
  --settlement-roster settlement.json \
  --mask-roster mask.json \
  --availability-roster availability.json \
  --receipt-roster receipt.json \
  --key /secure/receipt-member.key \
  --proposal batch.proposal \
  --out member-a.signature
~~~

The output is the canonical Core v2 SignerSignature entry. Proposal and
signature exchange is an authenticated operator workflow; Core v2 does not
define a gossip topic for partial certificate signatures.

An assembler with the same validated evidence combines at least the configured
threshold:

~~~sh
cargo run --locked -p meshmine-node -- receipt-assemble \
  --dir /var/lib/meshmine-assembler \
  --network-id 2 \
  --hsd-cli /path/to/hsd-cli \
  --settlement-roster settlement.json \
  --mask-roster mask.json \
  --availability-roster availability.json \
  --receipt-roster receipt.json \
  --peer-config static-peers.json \
  --proposal batch.proposal \
  --signature member-a.signature \
  --signature member-b.signature \
  --out batch.certified
~~~

Assembly sorts and deduplicates signer keys, verifies every signature and
roster membership, requires the threshold, persists the certified batch, and
then records it in the durable static-peer outbox before exposing the output
artifact. The peer configuration must be the assembler's exact current static
peer set so ACK recovery remains fail-closed.

batch.certified can also be sent explicitly with overlay-gossip-object using
the receipt-batch topic. The assembler's own outbox will already replay it to
configured peers when overlay-serve restarts.

## Crash and replay behavior

- A crash before the signing reservation produces no signature. Retrying is
  safe.
- A crash after reservation reproduces the same deterministic signature for
  the same proposal; a conflicting proposal remains rejected.
- Proposal, signature, and certified output files use atomic no-overwrite
  publication. An exact retry succeeds; different bytes at the same path fail.
- Assembly writes a publication intent before receipt admission. A crash after
  certified-batch persistence but before locator creation is repaired on the
  next assembly or overlay-serve recovery pass.
- A different threshold-signature wrapper for an already stored unsigned
  object cannot replace the authoritative journal bytes.

## What remains

This is a bounded static-committee operator workflow, not an automatic receipt
service. Core v2 still lacks a frozen partial-signature transport, committee
proposal/round protocol, timer-driven batch supervisor, dynamic roster
distribution, and deployed independent receipt members. Session-close and
mask-opening production are not implemented by these commands. Work-only
single-lane payout snapshot/plan production is a separate bounded workflow
described in settlement-role.md. The remaining boundaries are release gates.
