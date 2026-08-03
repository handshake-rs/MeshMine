# MeshMine

MeshMine is a no-hard-fork, independently templated Handshake mining overlay.
It is being rebuilt around the standalone Rust Handshake stack: MeshMine uses
the exact external `handshake-rs/hns-node-rs` revision pinned in `Cargo.lock` and
does not embed a node implementation or JavaScript consensus oracle.

The current code is not production-ready. The Rust protocol components and the
authenticated native node/Core/operator path are substantial, and the local
HNSA/HNSR named-route adapter is specified and implemented in `handshake-rs`.
The public multi-operator daemon and live HNSR reservation/publication/lookup
path are implemented. Independent deployment evidence, security review, and
physical ASIC qualification are still release gates.

## Current architecture

```text
hns-node-rs authoritative mining snapshot
                  |
                  v
          meshmine-cored
          private signed Core link
                  |
                  v
  meshmine-corelink-operatord
       |                     |
       v                     v
HandyStratum ASIC      signed public statistics
private LAN ingress    HTML + bounded JSON feed
                             |
                             v
                 meshmine-operatord peers
             authenticated QUIC + live HNSR
```

The main implemented boundaries are:

- `meshmine-hsrd-bridge`: consumes coherent active-chain and mining state from
  the pinned external Rust node and invalidates work on authority or tip change.
- `meshmine-core-link`: authenticated, signed, durable Core/operator assignment
  and capture transport.
- `meshmine-corelink-operatord`: supervised ASIC ingress, fallback behavior,
  local dashboard, and optional public pool-statistics publisher.
- `meshmine-gateway`: bounded HandyStratum parsing and device profiles. Remote
  ASICs require an explicit private/link-local CIDR allowlist.
- `meshmine-network`: authenticated QUIC transport, lane isolation, bounded
  admission, replay, peer accounting, and a separately bounded HNSR stream.
- `meshmine-operatord`: pinned multi-operator QUIC sessions, durable signed
  operator-record replacement, live HNSR relay/rendezvous service, and optional
  fail-closed reserve/publish/verified-read-back cycles for `pool-stats`.
- `meshmine-pool-stats`: endpoint-signed, bounded statistics objects associated
  with the draft HNSA identity chain implemented in `handshake-rs`.

The protocol specification remains [MeshMine.md](MeshMine.md). The exact native
node ownership boundary is in
[docs/external-node-boundary.md](docs/external-node-boundary.md), and the live
template-to-ASIC path is in
[docs/live-parent-and-unified-operator.md](docs/live-parent-and-unified-operator.md).

## HIP integration

The companion `handshake-rs` workspace implements the draft HNSA proposal from
HIP pull request 79. MeshMine's `pool-stats` profile binds every signed snapshot
to the HNSA service-authorization ID, endpoint-delegation ID, endpoint sequence,
network, and profile ID. The operator serves the opaque HNSA proof objects with
the snapshot so an HNSA-aware client can validate the complete chain.

HIP pull request 78 currently submits unnamed-node rendezvous for upstream
review. The local companion HIP draft now defines version-2 named routes that
carry the exact HNSA authorization and delegation while leaving unnamed route
version 1 unchanged. `handshake-rs` implements that adapter with stable
service-derived route keys, profile-aware tickets, bounded storage admission,
and complete client verification. `meshmine-operatord` pins that
implementation revision and carries canonical HNSR packets only after mutual
QUIC authentication. The public-statistics route publisher reloads the HNSA
authorization, delegation, and current authority context before every cycle,
persists a new route sequence before signing, and requires a verified read-back
from each rendezvous peer.

See [specs/pool-stats-profile.md](specs/pool-stats-profile.md) for the private
profile used while an official HNSA profile assignment is pending.

## Browser-readable public statistics

When `public_stats` is configured, the operator exposes:

- `GET /` — a responsive, read-only view for desktop and mobile browsers;
- `GET /api/v1/pool-stats` — bounded JSON containing the opaque HNSA
  authorization, endpoint delegation, and signed snapshot.

The HTML page labels its decoded values as unverified because JavaScript served
by the operator is not an independent trust root. The browser extension and
mobile native host must validate HNSA and the snapshot signature before showing
the data as verified. Publishing and pinning the new `handshake-rs`
`hns-service-authority` crate is the remaining integration dependency for those
clients.

The public publisher uses a separate secp256k1 endpoint key, short-lived
snapshots, bounded request handling, no cookies, no persistent browser state,
and a sequence counter reserved in the service database before signing. A
public-feed failure disables only that feed; it never blocks the mining path.

Example `public_stats` section:

```json
{
  "listen": "0.0.0.0:8080",
  "network_magic": 1533997779,
  "endpoint_signing_key_file": "/absolute/private/endpoint-key.hex",
  "service_authorization_file": "/absolute/public/service-authorization.hex",
  "endpoint_delegation_file": "/absolute/public/endpoint-delegation.hex",
  "authorization_id": "64 lowercase hex characters",
  "delegation_id": "64 lowercase hex characters",
  "endpoint_sequence": 1,
  "delegation_expires_at": 1800000000,
  "snapshot_lifetime_seconds": 60,
  "publish_interval_ms": 2000
}
```

## Connecting an ASIC

Keep the operator dashboard on loopback. For an ASIC on a private LAN, bind the
gateway to the LAN address and allow only the smallest applicable private
network:

```json
{
  "gateway_listen": "192.168.50.10:3008",
  "gateway_allowed_cidrs": ["192.168.50.0/24"],
  "profile": "hs3"
}
```

The standalone gateway has the equivalent
`--allow-cidrs 192.168.50.0/24` option. Public or overly broad networks are
rejected. The HS3 and generic Goldshell profiles are still experimental until
tested against physical hardware, so begin on an isolated VLAN and confirm job
parsing, nonce layout, stale-job retirement, capture persistence, reconnects,
and accepted shares before any production use.

## Build and verification

Rust 1.97 is required.

```sh
cargo +1.97.0 fmt --all -- --check
cargo +1.97.0 test --workspace --all-targets
cargo +1.97.0 clippy --workspace --all-targets -- -D warnings
python3 scripts/validate-external-node-boundary.py
python3 scripts/validate-core-link-source.py
python3 scripts/validate-live-parent-and-unified-operator-source.py
python3 scripts/validate-work-fabric-source.py
```

Some GPU tests require Vulkan and may skip when no suitable device exists.

## Release gates

Before calling the system production-ready, all of the following remain
required:

- compose and operate the new multi-operator daemon against independent nodes;
- operate live HNSR publication across independent relays/rendezvous nodes and
  measure renewal, expiry, read-back, partition, and authority-rotation behavior;
- publish and pin the HNSA implementation for verified extension/mobile views;
- complete physical ASIC acceptance and sustained-load testing;
- run public-WAN partition, replay, churn, eclipse, and resource-exhaustion
  tests;
- complete independent protocol and implementation security review; and
- deliberately enable production eligibility only after every fail-closed
  authority gate is satisfied.
