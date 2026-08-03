# Unified operator service

`meshmine-corelink-operatord` is the supported operator process. It combines the
authenticated Core assignment/capture stream, durable HandyStratum gateway,
continuous supervision, local dashboard, graceful shutdown, and optional
signed public statistics.

```text
authoritative node snapshot
        -> signed Core assignment bundle
        -> authenticated local Core link
        -> durable operator assignment
        -> HandyStratum job and ASIC sessions
        -> durable capture
        -> Core admission and signed terminal receipt
```

The operator cannot create parent certificates, assignments, mask sessions,
block bodies, payout state, or node authority. It installs only exact bundles
offered by the pinned Core identity.

## Start

```sh
meshmine-corelink-operatord serve --config /absolute/operator-corelink.json
```

The three state databases for the gateway, Core link, and service journal must
be different absolute paths. Private key and password files are opened with
strict ownership and mode checks. `production: true` is rejected.

## Core supervision

The service maintains one mutually authenticated Unix-domain Core connection.
Failures use bounded exponential backoff. The first offer after reconnect is
Core's authoritative active bundle; later offers are staged replacements.
Durable captures remain until a valid terminal receipt returns, so a Core
disconnect pauses admission without discarding captured work.

The deterministic service modes are `bootstrapping`, `mining`, `degraded`,
`fallback`, `draining`, and `stopped`. Missing current work, expired assignment,
listener failure, credential failure, Core-link loss, hard capture backlog,
authorization-failure exhaustion, signed drain, or shutdown causes a
fail-closed transition.

## ASIC listener

Loopback is accepted by default. A physical ASIC on a LAN requires both a
non-loopback `gateway_listen` and one or more explicit
`gateway_allowed_cidrs`. Only bounded private, link-local, or loopback networks
are accepted; broad public exposure is rejected.

Each session receives the current assignment-derived nonce prefix and exact
bundle-derived job. Assignment or credential rotation closes affected sessions.
Fallback closes the miner connection so device-configured secondary pool slots
can take over; it does not claim to reconfigure the ASIC.

## Dashboard

The local dashboard must remain on loopback and has no mutation endpoint:

```text
GET /
GET /api/v1/status
GET /api/v1/health
```

It reports supervisor state, active assignment, ASIC sessions, capture backlog,
Core connectivity, listener and credential health, counters, and bounded recent
events.

## Public statistics

The optional public listener is separate from both the ASIC and dashboard
sockets:

```text
GET /
GET /api/v1/pool-stats
```

It publishes short-lived endpoint-signed snapshots and their opaque HNSA proof
objects. The signing key is separate from the gateway key. Snapshot sequences
are reserved in the service database before signing and remain monotonic across
restart. Feed failure or delegation expiry disables the feed without delaying
mining. See
[the pool-statistics profile](../specs/pool-stats-profile.md).

## Shutdown

SIGINT or SIGTERM activates fallback, stops accepting new ASIC sessions,
attempts a bounded 35-second drain of already durable captures, joins all
listeners, and records the final stopped transition. Anything not admitted by
the deadline remains durable for the next start.

## Release limits

- Physical HS3 and Goldshell behavior is not qualified.
- The public multi-operator overlay is not yet composed into this service.
- Device power, temperature, and board telemetry are not integrated.
- Core and operator use a local single-host transport in this profile.
- Independent security review and target-platform endurance testing remain
  required.
