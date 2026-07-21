# Unified operator service

Status: source-complete pre-production handoff. Hardware and authority
qualification remain pending.

## Purpose

The service merges the continuous supervisor and dashboard with the
authenticated Core assignment/capture stream.

```text
live-parent-qualified signed bundle
        -> authenticated local Core link
        -> durable operator assignment state
        -> exact HandyStratum job derivation
        -> concurrent loopback ASIC sessions
        -> durable capture spool
        -> exact Core admission and signed terminal receipt
```

The operator cannot create parent certificates, assignments, mask sessions,
block bodies, payout state, or native authority. It can only install an exact
bundle offered by the pinned Core identity.

## Binary

```text
meshmine-corelink-operatord serve \
  --config /absolute/operator-corelink-v9.json
```

The standalone **ACK-only reconciler** in `meshmine-operatord` remains as a research and
migration utility. The Core-linked daemon is the integrated path.

## Continuous Core supervision

The operator maintains one mutually authenticated Unix-domain Core connection.
Connection failures use bounded exponential backoff:

```text
initial delay -> doubled delay -> configured maximum delay
```

A successful authenticated connection resets the delay. The first assignment
offer on every connection is treated as Core's authoritative active bundle and
is reconciled with durable gateway state. Later offers are staged as pending
replacement bundles.

The Core link is a critical health signal. After the configured consecutive
failure threshold, the supervisor closes MeshMine miner sessions and enters
fallback. Recovery requires separate healthy-sample hysteresis and the minimum
fallback hold interval.

## Supervisor safe modes

The deterministic supervisor exposes:

- `bootstrapping`
- `mining`
- `degraded`
- `fallback`
- `draining`
- `stopped`

Critical conditions include:

- no current job;
- a job outside its signed assignment window;
- unavailable gateway listener;
- unavailable receipt store;
- unreadable or insecure credentials;
- unavailable authenticated Core link;
- hard capture backlog;
- process-wide authorization-failure limit;
- operator shutdown.

A signed assignment drain enters `draining` immediately. When the transition
completes, the service can recover through the normal healthy-sample policy.

## Gateway behavior

The gateway listener is loopback-only and bounded by configured connection and
request limits. Slow ASIC sockets do not hold the shared gateway-state lock.
Each session receives:

- the current durable assignment sequence;
- an assignment-derived nonce prefix;
- the exact bundle-derived job;
- replacement notifications through a separately synchronized writer;
- connection rotation when the assignment or credential epoch changes.

Fallback does not claim to reconfigure an ASIC remotely. It closes the local
session so correctly configured secondary or tertiary pool slots can be used.
Configured fallback endpoints are dashboard expectations and journal evidence,
not proof of physical device switchover.

## Capture durability

Captures remain in the gateway and operator stores until Core returns a valid
terminal receipt. A Core disconnect pauses compaction but does not discard work.
The operator can reconnect, recover the active bundle by assignment sequence,
and continue idempotent admission.

## Graceful shutdown

SIGINT or SIGTERM handling uses the Tokio signal facility in a dedicated small
runtime. Shutdown:

1. Activates fallback and rotates local miner sessions.
2. Stops accepting new local ASIC sessions.
3. Continues draining already durable captures through an existing Core link.
4. Uses a bounded 35-second drain deadline.
5. Records any remaining session count at timeout.
6. Joins the gateway and dashboard listeners.
7. Persists the final `stopped` supervisor transition.

Unadmitted captures remain durable after the deadline.

## Dashboard and API

The embedded dashboard remains loopback-only and read-only. It displays:

- supervisor mode and reason;
- current job and assignment sequence;
- active ASIC session count;
- pending captures;
- Core-link connectivity and last message time;
- active and pending bundle IDs;
- assignment-drain state;
- fallback endpoint expectation;
- gateway and dashboard listener health;
- credential health;
- capture and rejection counters;
- recent durable events;
- explicit pre-authority status.

Endpoints:

```text
GET /
GET /api/v1/status
GET /api/v1/health
```

There is no HTTP mutation endpoint.

## Durable service identity

The service database uses:

```text
schema version: 3
profile:        meshmine-operator-v9
binding:        network ID + pinned Core public key
```

An older service database requires a clean reindex or explicit future migration.
The Core-link, gateway, and service databases must be separate files.

## Event journal

The bounded monotonic journal records:

- Core-link connection and disconnection;
- reconnect failures;
- assignment activation and pending replacement;
- drain transitions;
- mode transitions;
- credential loss and restoration;
- capture drain summaries;
- gateway job, rejection, capture, and fallback summaries;
- shutdown and bounded-drain timeout.

High-rate gateway events are aggregated per supervisor cycle.

## Current limitations

- `production: true` is rejected.
- Physical ASIC behavior remains unqualified.
- Device temperature, power, and board telemetry are not integrated.
- Core and operator are local single-host processes in this profile.
- Mask, settlement, overlay, and solved-block supervision are not yet merged
  into one public release process.
- Native mainnet authority remains disabled.
- Rust compiler and runtime qualification remain mandatory in CI and on target
  ARM64/x86-64 hosts.
