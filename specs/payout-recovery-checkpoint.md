# Bounded payout recovery checkpoint

Status: authenticated canonical checkpoint, exact live-source fence, and
monotonic durable head implemented; live-source writer composition and online
migration are not yet production-ready.

`PayoutRecoveryCheckpointV1` is a domain-separated Core-v2 extension that seals
the complete bounded restart state needed by payout admission:

- a deployment payout-policy fingerprint;
- an exact source fence for ordered session dispositions, snapshots, plans, and
  canonical payment events;
- the minimal PPLNS accumulator suffix and its snapshot thresholds;
- the expected payout-plan queue;
- exact canonical plan/snapshot bindings; and
- a settlement certificate field excluded from the checkpoint object ID.

The locally configured committee policy fixes the network, settlement committee
ID, payout-policy fingerprint, eligible Ed25519 members, and nonzero threshold.
Persist and load both verify the exact threshold certificate; checkpoint bytes
cannot select their own trust policy. The per-network `MMCH` durable head
advances by exactly one checkpoint sequence and binds both the unsigned
checkpoint ID and the exact certified-wrapper hash. Alternate, partial, or
unsigned wrappers therefore cannot poison the current immutable slot.

The checkpoint record, `MMCH` update, and exact `MMSF` source-fence condition
share one transaction. Exact retries are explicit; concurrent races are errors.
Before persistence, the complete object must pass structural validation, a
64-MiB encoded-size ceiling, bounded canonical decode, and exact round-trip
equality. Later checkpoints must preserve policy/accumulator parameters and
advance every source component monotonically; equal fences require equal sealed
state. Accumulator reconstruction must reproduce the exact minimal canonical
suffix. Expected plans are contiguous and cannot overlap canonical plan
bindings. Forks, skipped sequences, malformed heads, source races, missing
journal evidence, noncanonical encodings, incoherent source heads, invalid
certificates, and policy substitutions fail closed. Loading the current
checkpoint requires one head read, one exact journal lookup, certificate
verification, and one exact live-fence read rather than a lifetime scan.

The checkpoint is not yet safe as an online restart point merely because this
boundary is authenticated. Normal-close and reorg-only disposition, snapshot,
plan, and payment-event transactions must all advance `MMSF` atomically using
the supplied transition primitive. Migration must validate the historical
prefix in bounded, resumable pages and install an explicit Ready marker under
the new certified-wrapper head format. Until that composition lands,
payout-enabled startup retains the existing historical validation path and
production readiness remains false.
