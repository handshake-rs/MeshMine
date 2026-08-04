# Multi-operator daemon and live HNSR

`meshmine-operatord` is the public operator-to-operator process. It does not
contain Handshake consensus, create mining templates, or accept ASIC traffic.
Those responsibilities remain with the pinned external Rust node,
`meshmine-cored`, and the private Core-link operator.

The daemon composes:

- mutually authenticated, certificate-pinned QUIC from `meshmine-network`;
- durable, signed `OperatorRecordV2` admission with strictly increasing
  per-operator sequences;
- the live HNSR relay reservation and rendezvous route service pinned from
  `handshake-rs/hns-rs` at
  `29e4b473bd2cfee460b56d5092b7bc28da5ec5dc`;
- profile allowlists and independent relay, route-store, peer-download, and
  transport limits; and
- optional `pool-stats` reservation, publication, and verified read-back
  against every configured peer.

All other MeshMine gossip topics currently fail closed at the daemon
application boundary. Adding a topic requires its complete object-specific
authority and durable recovery workflow; a valid transport signature alone is
not admission.

## Configuration

The process starts with:

```sh
meshmine-operatord serve --config /etc/meshmine/operatord.json
```

Configuration and key paths must be absolute in production operations.
Private files must be regular, non-symlink files with mode `0600` or stricter.
The state database is the durable authority for operator replacement and HNSR
publication sequences.

```json
{
  "schema_version": 1,
  "network_id": 2,
  "network_magic": 1836019566,
  "listen": "0.0.0.0:14439",
  "certificate_file": "/etc/meshmine/tls/certificate.der",
  "certificate_key_file": "/etc/meshmine/tls/private-key.der",
  "transport_signing_key_file": "/etc/meshmine/transport-key.hex",
  "economic_operator_pubkey": null,
  "state_file": "/var/lib/meshmine/operatord.redb",
  "relay": {
    "signing_key_file": "/etc/meshmine/hnsr-relay-key.hex",
    "public_address": "203.0.113.10:14039",
    "allow_private_address": false,
    "supported_profiles": [65280],
    "maximum_reservations": 4096,
    "maximum_reservations_per_source": 64,
    "maximum_bytes_per_circuit": 16777216
  },
  "rendezvous": {
    "allow_private_routes": false,
    "total_records": 50000,
    "records_per_key": 16,
    "records_per_source": 1024
  },
  "publication": {
    "endpoint_signing_key_file": "/etc/meshmine/pool-stats-endpoint-key.hex",
    "service_authorization_file": "/etc/meshmine/hsa1-authorization.hex",
    "endpoint_delegation_file": "/etc/meshmine/hsa1-delegation.hex",
    "authority_context_file": "/run/meshmine/hns-authority-context.json",
    "reservation_lifetime_seconds": 1200,
    "route_lifetime_seconds": 600,
    "reservation_circuits": 8,
    "reservation_bytes": 67108864,
    "publication_interval_ms": 300000
  },
  "peers": [
    {
      "remote": "198.51.100.20:14439",
      "server_name": "operator-b.example",
      "certificate_file": "/etc/meshmine/peers/operator-b.der",
      "expected_transport_pubkey": "64 lowercase hex characters",
      "hnsr_relay_key": "66 lowercase hex characters",
      "reconnect_initial_ms": 1000,
      "reconnect_maximum_ms": 60000
    }
  ]
}
```

`authority_context_file` is re-read before every publication:

```json
{
  "root_key": "66 lowercase hex characters",
  "epoch": 1,
  "current_height": 123456
}
```

It must be produced from authenticated current Handshake name state. A stale
height, root key, epoch, authorization, delegation, endpoint key, capability,
network, or profile disables publication for that peer. There is no direct-web
fallback under the same HNSA identity.

## Live publication transaction

For each pinned peer, one publication cycle:

1. mutually authenticates the QUIC transport and checks the expected Ed25519
   peer identity;
2. sends a profile-allowlisted HNSR reservation signed by the delegated
   secp256k1 endpoint;
3. verifies the relay-signed offer, confirms it, and verifies the final ticket;
4. reserves a new durable route sequence before signing;
5. validates the complete current HNSA authorization and delegation chain;
6. publishes the bounded named route; and
7. performs a keyed lookup and accepts success only when the exact route is
   returned and independently verifies against the same current authority.

Crash gaps in route sequences are safe. Sequence reuse, equal-sequence
conflicts, nonce replay, cross-peer confirmation, stale authority, partial
publication, and unverified read-back fail closed.

This implementation removes the missing-code release gate. It does not replace
independent deployment, public-WAN adversarial testing, HNSA/HNSR standard
review, physical ASIC qualification, or security audit.
