# MeshMine public pool-statistics profile

Status: private experimental profile pending an accepted HNSA assignment.

This document defines the service-specific object layered on the HNSA identity
and delegation chain proposed in HIP pull request 79 and the local
`HNSA Profile for Handshake P2P Rendezvous` draft. It does not assign a HIP
number or create Handshake consensus rules.

## Identity and discovery

- HNSA service name: `pool-stats`
- private profile ID: `0xff00`
- read-statistics capability: bit `0` (`0x00000001`)
- flags: `0`
- detached constraints: absent

An independently trusted HNSA client validates the root-signed service
authorization and service-signed endpoint delegation using the implementation
in `handshake-rs`. The client then passes the validated network, profile,
authorization ID, delegation ID, endpoint sequence, endpoint public key, and
delegation expiry into the MeshMine profile verifier.

Direct HTTPS or an application-configured endpoint can carry the document. An
HNSR deployment uses `NamedRouteRecordV2` from the local HNSA/HNSR adapter with
profile `0xff00`. Its application policy is:

- maximum route lifetime: 900 seconds;
- allowed and required endpoint capabilities: `0x00000001`;
- service-authorization flags: `0`;
- detached constraints hash: 32 zero bytes;
- requester is the inner Brontide initiator;
- endpoint is the responder authenticated by the delegated endpoint key; and
- after inner authentication, the requester sends a bounded HTTP/1.1
  `GET /api/v1/pool-stats` request and accepts only the JSON document specified
  below.

The HNSR route, relay ticket, inner session, request, and response remain
bounded independently. An HNSR failure never authorizes a direct or
conventional-web fallback under the same HNSA identity.

## Snapshot

`PoolStatsSnapshotV1` is a complete, canonical little-endian binary object:

1. version (`u8`, exactly `1`)
2. Handshake network magic (`u32`)
3. profile ID (`u16`, exactly `0xff00`)
4. HNSA service-authorization ID (`[u8; 32]`)
5. HNSA endpoint-delegation ID (`[u8; 32]`)
6. endpoint sequence (`u64`)
7. snapshot sequence (`u64`, nonzero)
8. generated-at Unix seconds (`u64`)
9. expires-at Unix seconds (`u64`)
10. operator ID (`[u8; 32]`, nonzero)
11. tip height (`u32`)
12. tip hash (`[u8; 32]`)
13. connected miners (`u32`)
14. connected mesh peers (`u32`)
15. accepted shares (`u64`)
16. rejected shares (`u64`)
17. pending captures (`u32`)
18. optional last-found block: tag (`u8`), then height and hash when present
19. operator mode (`u8`)
20. production-eligible boolean (`u8`, exactly `0` or `1`)
21. strict-DER secp256k1 signature length (`u8`) and signature bytes

The maximum encoded snapshot is 512 bytes. Its lifetime is nonzero and at most
120 seconds, and it cannot outlive the endpoint delegation. Parsers reject
unknown versions, modes, tags, non-canonical booleans, trailing bytes, zero
identity fields, invalid or high-S signatures, and length-limit violations.

The signature prehash is 32-byte BLAKE2b over:

```text
"HNS-MESHMINE-POOL-STATS-V1\0" || unsigned_snapshot_without_version
```

The endpoint key from the validated HNSA delegation signs the digest using
deterministic ECDSA over secp256k1 and strict DER low-S encoding.

## Replacement and aggregation

Snapshot sequence increases per operator. The operator reserves the next value
durably before signing, so a crash can create a gap but cannot reuse a sequence.
A client keeps the highest valid sequence per operator. Different valid objects
with the same operator and sequence are a conflict and fail closed.

Aggregation sums counters only after every snapshot has independently passed
HNSA and endpoint-signature validation. It reports separate tip groups instead
of hiding chain disagreement. It never treats operator counts, share totals, or
the `production_eligible` bit as consensus authority.

## HTTP document

`GET /api/v1/pool-stats` returns bounded JSON with:

- schema `meshmine-pool-stats-v1`;
- service name `pool-stats`;
- profile ID `0xff00`;
- lowercase hexadecimal HNSA service authorization;
- lowercase hexadecimal HNSA endpoint delegation; and
- lowercase hexadecimal signed snapshot.

The HNSA objects are opaque to MeshMine. The Rust HNSA implementation owns
their canonical parsing and validation. Each is limited to 1,024 decoded bytes;
the snapshot remains limited to 512 bytes.

`GET /` is a convenience view for ordinary mobile and desktop browsers. It may
decode fields but must label them unverified because code delivered by the same
operator cannot independently authenticate that operator. A browser extension
or native host may show a verified state only after validating the complete
HNSA chain and endpoint signature from an independently resolved Handshake
identity.

## Operational constraints

- The endpoint signing key is separate from gateway, Core, transport, and root
  identity keys.
- Public request handling is GET-only, timeout-bounded, connection-bounded, and
  separate from mining ingress.
- The response sets no cookies, keeps no browser state, and allows read-only
  cross-origin retrieval.
- Failure, expiry, or storage error disables the public feed without delaying
  job delivery or candidate capture.
- Rate limiting and an HTTPS reverse proxy remain deployment responsibilities.
- Connected-miner and share counts leak operational information by design;
  operators must explicitly choose whether to publish the feed.

## Compatibility status

The HNSA and HNSA/HNSR proposals are still drafts, and `0xff00` is not an
official profile assignment. Mainnet deployments must not present this profile
as a final standard. Any accepted HIP change to key syntax, authorization or
route encoding, delegation encoding, lifetime rules, or profile assignment
requires a versioned compatibility update and new fixed vectors.
