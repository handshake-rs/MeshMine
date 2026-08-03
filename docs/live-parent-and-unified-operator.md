# Live parent and unified operator design

This design closes two evaluation gaps:

1. Static parent-certificate allowlisting and runtime hns-node-rs shadowing are replaced
   with authenticated native `hsrd` authority, using one coherent authority,
   tip, validation, and header snapshot plus strict current-tip authorization.
2. The authenticated Core-link bridge is composed with the continuous operator
   supervisor, fallback policy, dashboard, event journal, and graceful shutdown.

## Trust hierarchy

```text
Native hsrd active chain
    sole authenticated runtime parent membership and chainwork source
    must prove complete consensus readiness and an authoritative durable tip

MeshMine Core
    validates and signs exact assignment bundles and terminal receipts

Operator service
    distributes only the exact authorized job and preserves captures

ASIC
    searches its assigned device namespace and submits candidate work
```

The design does not turn the operator dashboard or work coordinator into a
consensus authority. It preserves the portable backend architecture and keeps
hardware-specific hashing below the assignment boundary.

On mainnet, Core additionally requires the explicit native canary flag, an
exact best-header/active-state hash-height-chainwork match, every individual
consensus-readiness bit, a current authoritative tip, and a tightly bounded
freshness/cache window. The pinned node revision has complete source readiness;
gateway activation is still prevented whenever any live readiness, freshness,
synchronization, or durable-authority value is absent or changes. The pinned
node's base snapshot uses `pre-authority`, while live native RPC reports a
configuration-specific diagnostic stage; neither is an authority grant.

## Failure behavior

| Failure | Result |
|---|---|
| hsrd unreachable or authentication fails | Core refuses staging/offering/admission; link fails closed |
| hsrd readiness or durable authority is incomplete | Parent rejected; no authority-bearing job is served |
| hsrd parent is no longer the current tip | Core link closes within the bounded requalification interval; operator enters fallback |
| hsrd reports a pending better-chain activation or invalid tip stage | Parent rejected |
| authoritative hsrd mining event advances or clears | current ASIC job is durably retired at once; no stale candidate can be published |
| Core link unavailable | Durable captures retained; supervised fallback |
| Replacement drain pending | New work stopped; old captures drained within signed window |
| Operator shutdown | Fallback, bounded capture drain, durable residual state |

## Non-goals

The integrated path does not provide:

- bypassing incomplete native hsrd authority;
- public remote Core transport;
- global device work allocation;
- a universal CPU/GPU hash engine;
- physical ASIC certification;
- a claim that a stock ASIC exhaustively traversed a lease;
- production eligibility.

## Native live-template gateway lifecycle

`meshmine-hsrd-bridge` now composes the native mining engine with the
authenticated gateway instead of ending at a detached `GatewayJob` value. An
`AuthoritativeHsrdMiningStream` can only be created by
`NodeService::subscribe_mining_events()`. The observed/staged subscription does
not construct this capability.

For each signed MeshMine assignment, activation:

1. reads the latest authority-permitted native snapshot;
2. validates the immutable `PreparedMiningJob` against that exact generation;
3. validates the exact coinbase, transaction bytes, roots, weight, session,
   body, assignment, and device target;
4. persists the assignment-to-generation/job binding in the same durable store
   that backs the gateway;
5. invokes `Gateway::issue_authorized_job` with the signed manifest,
   assignment, body descriptor, and availability certificate; and
6. checks again for a concurrent tip event before returning the active job.

The event loop consumes the authoritative watch value, which is lossless for
the latest state even if diagnostic broadcast events lag. A generation change,
tip change, authority clear, stream close, restart-time binding mismatch, or
missing binding retires or rejects the ASIC job fail closed. Candidate
publication independently requires the current authoritative snapshot to match
the durable generation and parent, so an old prepared job cannot be published
after a reorganization.

The bridge deliberately does not mint committee signatures or fabricate an
assignment bundle. Those authority objects must already be valid. This is the
continuous native template-to-ASIC composition boundary; enabling a mainnet
canary remains a separate all-readiness gate.
