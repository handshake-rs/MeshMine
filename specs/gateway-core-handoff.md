# Authenticated gateway-to-Core capture handoff

Status: implemented protocol, canonical assignment/job binding, portable local
lease enforcement, atomic admission, native `hsrd` snapshot/body bridge,
fail-closed durable assignment-to-`hsrd` binding, and the authenticated
continuous local Core/operator path. The integrated path includes Linux peer credentials,
pinned Ed25519 mutual authentication, exact signed assignment bundles,
automatic exact `ShareV2` construction, durable terminal receipt reconciliation,
signed assignment drain/transition orchestration, bounded live HSD parent
qualification, optional/required HSRD shadow agreement, reconnect/fallback
supervision, the read-only dashboard, and graceful shutdown. Production context
distribution and physical ASIC evidence remain release gates.

## Safety boundary

The gateway path is a distinct Core-v2 extension. It does not relax or reinterpret
the frozen `AssignmentV2` encoding. A decoder or journal consumer must select
exactly one of the legacy assignment namespace or the gateway-assignment
namespace; decoder fallback is forbidden.

`GatewayAssignmentV1` is operator-signed and binds the network, session, body,
body certificate, payout bucket, worker identity, gateway key, Core handoff key,
targets, assignment sequence, nTime, observation policy, nonce range, and the
HandyStratum extra-nonce profile. The only currently supported profile is:

```text
operator prefix[4] || miner ExtraNonce2[4] || zero[16]
```

The signed inclusive `ExtraNonce2` range is checked as four big-endian bytes.
Legacy exact assignments still require the exact signed 24-byte extra nonce.

For the native path, `meshmine-hsrd-bridge` accepts only an immutable prepared
job bound to the exact committed `hsrd` network and mining generation. It
rechecks parent/height, every header root, version/bits/time, mask commitment,
exact serialized transaction bytes and txids, block weight, and Handy target
representation before constructing `GatewayJob`. The gateway then repeats its
signed session/body/certificate/assignment checks and allocates the signed
sequence in the same atomic batch as job activation.

Before that activation, the bridge can persist an immutable assignment-keyed
record containing the exact `hsrd` network, mining generation, prepared-job ID,
session, body package, parent hash, and parent height. Restart recovery requires
the byte-exact record; missing, malformed, or conflicting rebindings fail
closed. The live Core service must still compose this check with assignment
authorization and gateway activation without an externally visible gap.

After authenticated capture admission and threshold mask opening, the bridge
reloads that same durable record before asking the non-forgeable prepared job to
admit a solution. The result must match the current snapshot generation and
parent and pass full HNS PoW before it becomes an `hsrd` solved-candidate object.
The bridge can then encode that exact candidate as the durable fast-path raw
block publication intent for a strictly bounded target set. This is a local
winning-block path; it does not wait for DAG convergence or settlement.

## Authenticated evidence chain

The handoff uses these domain-separated canonical objects:

1. `GatewayContextManifestV1`: operator authorization for one gateway key and
   one Core handoff key, with validity and frame/in-flight bounds.
2. `GatewayCaptureEnvelopeV1`: gateway-signed capture evidence. It binds the
   assignment, context, monotonic gateway sequence, connection identity,
   gateway receive time, nTime, extra nonce, nonce, and raw share hash.
3. `GatewayCaptureReceiptV1`: Core-signed terminal disposition for the exact
   envelope. Outcomes are accepted, rejected, grace-noncredit, or duplicate.
   Only accepted may contain a nonzero accepted-share ID; every other outcome
   must contain zero.
4. `GatewayAssignmentTransitionV1`: gateway-signed cutoff between two
   assignments.
5. `GatewayAssignmentDrainV1` and `CoreAssignmentDrainReceiptV1`: signed proof
   that no later capture can cross an assignment boundary and that Core has a
   durable disposition through that boundary.

`ShareV2.local_telemetry_hash` must equal the capture-envelope object ID. The
envelope deliberately omits a `ShareV2` ID, avoiding a commitment cycle while
still binding every proof field.

## Observation policy

The assignment freezes one of two policies:

- Core receipt time: Core's local receive time is authoritative and the signed
  maximum clock skew must be zero.
- Delegated signed gateway time: the gateway-signed receive time is eligible
  only when its absolute difference from Core receipt time is within the signed
  bound, which is itself capped at five minutes.

A gateway signature authenticates the observation claim; it does not prove the
physical truth of the gateway clock. Production use therefore still requires
clock operations, monitoring, and measured hardware evidence.

## Atomic admission

For an accepted capture, one storage transaction commits all of:

- exact context manifest and gateway assignment;
- capture envelope and its unique Core disposition;
- gap-free per-assignment sequence cursor;
- global Core work-key reservation; and
- exact accepted `ShareV2`.

The receipt journal is keyed by envelope ID, so a second disposition for one
capture is an immutable conflict. Rejected, grace, and duplicate captures use
the same evidence/cursor transaction but cannot create accepted-share or
accepted-work records. A crash therefore cannot expose credit without its
authenticated source or acknowledge a capture whose terminal state is absent.

## Local service composition

The unified operator composes the continuous local process boundary and its parent authority check:

- `meshmine-cored` stages and validates the exact signed Core assignment bundle,
  serves one private Unix-domain endpoint, constructs exact `ShareV2` objects,
  and returns signed terminal capture/drain dispositions;
- `meshmine-corelink-operatord` authenticates Core, durably imports bundles,
  derives exact gateway jobs, drains captures, triggers ASIC fallback at the
  signed cutoff, and completes the signed transition before job replacement;
- the transport checks Linux `SO_PEERCRED`, expected UID, pinned Core and
  gateway Ed25519 identities, handshake freshness, frame sequence, frame kind,
  size, timeout, and checksum;
- the operator pending-capture spool maintains durable record/byte counters and
  atomically replaces a pending envelope with its terminal receipt.

This is a local pre-production boundary. The Core daemon now checks the exact
parent against a bounded loopback HSD active-chain RPC source and can require an
HSRD shadow source to agree on hash, height, time, and chainwork. HSRD cannot
grant authority by itself. The operator composes the Core link with the local
supervisor, fallback hysteresis, dashboard, event journal, reconnect backoff,
and bounded shutdown drain.

## Remaining production gates

The following remain mandatory:

- compile and fault-test HSD/HSRD disagreement, RPC loss, reconnect, dashboard,
  fallback, and assignment-drain behavior without weakening the signed
  boundary;
- atomically compose the implemented durable `hsrd`
  generation/job-ID-to-assignment-ID binding with live Core authorization and
  gateway activation;
- run restart, socket-loss, spool-capacity, partial-transition, and disk-failure
  drills on the compiled binaries;
- obtain exact physical Goldshell/HS3 capture, reconnect, stale-work, fallback,
  and drain evidence;
- independently review the new bundle, transport, receipt, and transition state
  machines; and
- close every remaining MM-0001 production and native-authority gate.

Until those gates pass, gateway production eligibility remains false.
