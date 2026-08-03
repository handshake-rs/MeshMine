# Open implementation questions

## Normative MM-0001 evaluation questions

These remain open and block a mainnet security claim:

1. Independently audit and production-freeze the evaluation-selected MP-SPDZ MASCOT/Tinier setup (or replace it) under an explicit dishonest-majority corruption, synchrony, fairness, abort-attribution, and output-delivery model; local WP7 conformance is not that audit.
2. Derive role-specific committee sizes and thresholds that meet annual capture and liveness targets under measured HNS concentration.
3. Select a finalized-work lookback that prevents a receipt committee from rapidly shaping its successor set.
4. Select a blind-band width from public testnet capture, bandwidth, storage, signature, and MPC measurements.
5. Derive the service fraction and per-event/role caps from measured availability/MPC operating costs and concentration effects.
6. Select the delayed entropy window and prior-beacon construction after analyzing majority-miner payout bias.
7. Select body shard counts and independent failure domains for observed block sizes and provider topology.
8. Physically verify stock HS3 and Goldshell minimum targets, maskHash handling, capture delivery, extraNonce behavior, failover, and job-switch latency.
9. Decide whether a later harder accounting target has a credible anti-filtering mechanism; the Core v2 baseline remains `T_accounting = T_capture`.
10. Establish an independently maintained external verifier using published canonical vectors before mainnet beta.

## Stage-0 wire and implementation freeze questions

The following draft ambiguities were resolved only for the evaluation wire profile and still require independent review before a production freeze:

1. Confirm whether unsigned LEB128 is the intended canonical varint rather than HNS/Bitcoin CompactSize.
2. Confirm the exact signature-suite negotiation and whether direct object signatures should carry their own suite identifier.
3. Confirm the certificate signer representation if a bitmap or aggregate signature suite is introduced.
4. Confirm the omitted version/network fields on erasure descriptors and availability certificates.
5. Confirm the omitted settlement signature sets on payout snapshots and payout plans.
6. Freeze maximum byte/vector bounds per object based on measured deployment limits.
7. Freeze the finalized-work sortition algorithm. The WP13 evaluation profile uses sequential BLAKE2b-512 rejection sampling without replacement; changing this algorithm changes every dynamic roster.
8. Define the normative Phase 1 hybrid composition and the authority that finalizes eligibility roots. The evaluation profile uses an explicit static-seat count and treats a delayed root as an externally finalized input.
9. Assign and freeze the `SessionCloseV2.close_reason` numeric registry, including `NETWORK_WINNER`, timed completion, parent change, early reveal, liveness failure, and reorganization. The evaluation controller uses typed outcomes and does not emit an invented wire value.
10. Define the canonical `/mm/2/mask-opening` payload, object ID, setup-transcript distribution, and signed close-intent/final-receipt boundary. Core v2 currently specifies `OpeningShare` behavior and a post-opening root in `SessionCloseV2`, but no wire object that lets a daemon prove the accepted-share boundary before opening shares are broadcast. The runnable daemon therefore does not invent an incompatible mask-opening gossip encoding.

## Gateway-to-Core production composition

The gateway extension now resolves the former five object/state questions
without reinterpreting `AssignmentV2`: `GatewayAssignmentV1` signs the exact
Handy `prefix4 || ExtraNonce2[4] || zero16` range before mining; a signed
manifest binds the operator, gateway, and Core identities; the assignment
selects Core receipt time or bounded signed gateway time; every capture gets a
Core-signed accepted/rejected/grace/duplicate disposition; and accepted
evidence, cursor, Core work key, and `ShareV2` commit atomically. Durable context
and assignment heads prevent rollback. Capture, drain, and successor-transition
transactions share one active-state CAS, so a drained assignment cannot admit
new work while exact historical retries remain idempotent.

The remaining questions are operational/service boundaries, not permission to
invent new credit semantics:

1. Freeze the continuous Unix-domain peer-credential and mutual-Ed25519 service
   framing, context distribution, rate limits, and spool pressure policy.
2. Atomically orchestrate the implemented durable `hsrd`
   generation/prepared-job/body/assignment record across Core authorization and
   gateway restart/activation; the canonical gateway job ID is already the
   exact assignment object ID and sequence allocation is atomic with
   activation.
3. ACK the ASIC-side capture only after accepted or noncredit terminal state;
   recover the admission-before-ACK crash window without creating another
   disposition.
4. Orchestrate signed drain, Core drain receipt, and successor activation in
   both live processes, with restart tests and physical device evidence.

## Canonical commitment availability and overlay identity

The canonical HNS payment scanner can decide that a commitment is not a valid
payment only after it has the exact current plan and snapshot. Silently
recording a same-network commitment whose object identity is unresolved as
"no payment" would let later evidence change the meaning of an already durable
event. The current implementation therefore stops reconciliation on unresolved
same-network evidence; this is safe for accounting but lets an arbitrary validly
encoded commitment stall an overlay.

1. Define a consensus-visible overlay or committee namespace in addition to the
   HNS network ID. Independent MeshMine overlays on the same HNS network must
   not be able to make one another's commitments appear locally relevant.
2. Define bounded, authenticated plan/snapshot retrieval and an availability
   deadline tied to an explicit HNS finality policy. Every honest participant
   must reach the same answer before persisting either a payment or a
   deterministic non-payment event.
3. Define the terminal disposition when exact evidence remains unavailable:
   continued fail-stop, a threshold-certified unavailability result, or another
   versioned rule. An operator override or a local timeout cannot silently turn
   an unresolved commitment into a canonical non-payment.

## Lifetime-bounded production state

The active-share path now has a capped derived index, source-bound closure
gates, atomic share/work/observation admission, and resumable bounded superseded
migration. The following longer-lived paths still block a claim that restart
cost is independent of deployment age:

1. Add a reversible parent canonical-sequence checkpoint plus block→sequence
   and parent→session indexes. Deep reorganization must be a fenced resumable
   transition; a checkpoint is a local recovery accelerator, never HNS
   finality. Retired outbox history also needs an explicit peer-enrollment
   horizon or verified import workflow.
2. Replace payout replay-from-genesis with a checkpointed closed-credit/PPLNS
   window, expected-snapshot queue, certified snapshot head, bounded active
   obligations/current plans, entropy reverse indexes, and canonical HNS
   height/event state. New payment events must bind the exact paid plan and
   snapshot, not only a plan sequence.
3. Switch observability and operator/response audits from whole-journal
   materialization to paged audit/scrub jobs plus bounded current-state
   indexes. Historical immutable evidence may remain retained, but ordinary
   service startup must not load it all.
4. Define archive manifests, restore verification, incident holds, and the
   exact dependency horizon before physically deleting immutable parent,
   receipt, payout, or canonical-event evidence.
5. Provide bounded maintenance/status commands for every migration and
   checkpoint. A daemon may advance a small fixed work budget, but must refuse
   to listen with an explicit phase/cursor status rather than silently doing a
   history-sized startup scan.

## Ordered payout checkpoint and session disposition

A local payout checkpoint can safely replace replay from genesis only when its
source is an explicitly anchored, contiguous sequence of proven normal closes.
The anchor must bind the exact lane, first eligible session sequence, first
session ID, and expected predecessor; sequence zero or key absence cannot be
assumed. A normal close remains credit-eligible if a parent reorganization is
recorded later, while a reorganization that won the close race contributes no
credit.

1. Define a certified ordered disposition for every session sequence in a
   lane: either an exact normal close or a final reorg-only outcome. Absence of
   a normal-close row is not a disposition because evidence may merely be late.
2. Freeze how a payout cursor crosses a reorg-only sequence. Until this is
   specified, an implementation must stop at the gap rather than skip it based
   on a timeout, local finality assumption, or missing key.
3. Define the canonical merge order if one payout stream covers multiple
   lanes. A static implementation may bind one lane, but must not invent a
   cross-lane ordering rule.
4. Define a source revision or insertion fence that makes checkpoint advance
   atomic with normal-close index admission. A newly repaired row at or behind
   the payout cursor must either be impossible or durably dirty/fail-stop the
   checkpoint before further signing.
5. Freeze bounded expected-snapshot queue and certified-snapshot head semantics,
   including front-only certification, exact retry, overflow behavior, and the
   policy fingerprint that invalidates an incompatible checkpoint.
