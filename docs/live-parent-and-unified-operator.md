# Live parent and unified operator design

This design closes two research gaps:

1. Static parent-certificate allowlisting and runtime HSD shadowing are replaced
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

## Failure behavior

| Failure | Result |
|---|---|
| hsrd unreachable or authentication fails | Core refuses staging/offering/admission; link fails closed |
| hsrd readiness or durable authority is incomplete | Parent rejected; no authority-bearing job is served |
| hsrd parent is no longer the current tip | Core link closes within the bounded requalification interval; operator enters fallback |
| hsrd reports a pending better-chain activation or invalid tip stage | Parent rejected |
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
