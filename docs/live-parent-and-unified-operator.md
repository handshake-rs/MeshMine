# Live parent and unified operator design

This design closes two research gaps:

1. Static parent-certificate allowlisting is replaced with live local HSD
   active-chain qualification, strict current-tip authorization for served jobs, and optional HSRD shadow agreement.
2. The authenticated Core-link bridge is composed with the continuous operator
   supervisor, fallback policy, dashboard, event journal, and graceful shutdown.

## Trust hierarchy

```text
HSD active chain
    authoritative local parent membership and chainwork
    current-tip authority for every actively served mining assignment

HSRD shadow node
    optional or required implementation-diverse agreement
    never an independent authority source

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
| HSD unreachable | Core refuses staging/offering/admission; link fails closed |
| HSD parent is no longer the current tip | Core link closes within the bounded requalification interval; operator enters fallback |
| Required HSRD unavailable | Parent rejected |
| Optional HSRD unavailable | HSD result may pass; diagnostic records advisory |
| HSD/HSRD disagreement | Parent rejected when agreement is required; active jobs require both nodes to identify the same tip |
| Core link unavailable | Durable captures retained; supervised fallback |
| Replacement drain pending | New work stopped; old captures drained within signed window |
| Operator shutdown | Fallback, bounded capture drain, durable residual state |

## Non-goals

The integrated path does not provide:

- native HSRD authority;
- public remote Core transport;
- global device work allocation;
- a universal CPU/GPU hash engine;
- physical ASIC certification;
- a claim that a stock ASIC exhaustively traversed a lease;
- production eligibility.
