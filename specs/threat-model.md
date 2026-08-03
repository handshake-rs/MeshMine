# MeshMine threat model

This is the implementation companion to MM-0001. Passing local tests is
evidence about this implementation, not a production security claim.

## Trust boundaries

| Component | Principal risks | Current boundary |
|---|---|---|
| external `hns-node-rs` | stale or incoherent tip, incomplete authority, dependency substitution | Exact Git pin; coherent authenticated snapshot; stale, changed, or incomplete authority stops work |
| Core/operator link | local impersonation, replay, capture loss, conflicting transitions | Unix peer credentials, pinned mutual Ed25519 authentication, bounded frames, monotonic sequences, durable assignment/capture/receipt state |
| ASIC gateway | malformed or stale submissions, target mismatch, nonce reuse, password guessing, hostile LAN clients | Bounded HandyStratum parser, signed assignment limits, durable captures, connection/request/authentication caps, explicit private CIDR allowlist |
| overlay transport | peer impersonation, floods, starvation, duplicate delivery, partition replay | Pinned TLS and transport identities, bounded lane-specific queues/workers, durable at-least-once replay, source suppression, request quotas |
| protocol storage | overwrite, equivocation after crash, sequence reuse, malformed recovery state | immutable records, conditional atomic batches, bounded recovery scans, durable signing and sequence reservations, protected local database paths |
| committees and MPC | capture, censorship, abort, key reuse, false independence | explicit roles and thresholds, domain-separated keys, signed objects, fail-closed transitions; production parameters and independent review remain open |
| public statistics | false identity, replay, operator-controlled page code, scraping, traffic exhaustion, operational leakage | HNSA-bound endpoint signatures, short expiry, durable sequence, bounded GET-only listener, separate key/socket; ordinary HTML is explicitly unverified |

## Node authority

The pinned external Rust node is the only runtime Handshake authority. MeshMine
does not contain a second node or contextual consensus implementation. Repeated
share checks may use locally bound data for throughput, but a node generation
or tip change invalidates that job, and candidate publication returns through
the authoritative validation boundary.

Same-user or root compromise can still alter process inputs, keys, binaries, or
state before startup. Local file checks reduce path substitution; they do not
turn a compromised host into a trusted authority. Database rollback also needs
an external monotonic operations control.

## ASIC claims

Stock devices are operator-controlled Level-0 observers. A valid capture proves
only that the submitted work met the configured target and assignment. It does
not prove exhaustive nonce traversal, absence of withholding, correct thermal
behavior, or firmware identity. Goldshell and HS3 behavior remains unqualified
until captured from physical hardware.

The LAN listener is not safe for public exposure. An allowlisted private source
is still not a cryptographic device identity. Deployment needs network
segmentation, per-device credentials where supported, and process-level rate
monitoring.

## Decentralized transport

Authenticated QUIC, durable replay, and a multi-operator daemon are implemented.
The daemon admits complete signed operator records and carries HNSR through a
separately bounded callback into the profile-aware relay/rendezvous state
machine. Static identity and certificate pins establish trusted channels; they
do not establish automatic revocation, eclipse resistance, organizational
independence, or public-WAN availability. Other gossip topics remain
fail-closed until their complete authority workflows are composed.

Settlement work cannot consume the fast-path reserved capacity. Nevertheless,
application actors, storage budgets, peer discovery, live metrics, and the
winner broadcaster still need composition and sustained adversarial testing.

## Public statistics and HIP drafts

HNSA supplies service identity and delegated endpoint keys, not transport
security. Clients must independently validate the root authorization, endpoint
delegation, profile, network, expiry, and snapshot signature. An operator-served
HTML page is useful for humans but cannot be its own independent verifier.

HIP pull requests 78 and 79 and the local HNSA/HNSR adapter remain drafts. The
adapter specifies version-2 named routes without changing the submitted unnamed
route format. MeshMine uses private profile ID `0xff00` and must migrate
deliberately if the accepted specifications differ.

Publishing counts leaks miner activity, share rate, operating mode, and tip
state. The feed is opt-in. A reverse proxy, HTTPS, request-rate controls, and
traffic privacy remain deployment responsibilities.

## Production blockers

- No physical ASIC qualification or long-duration workload evidence.
- No independent public-WAN operating evidence for the new multi-operator
  daemon and live HNSR route runtime.
- No independently verified extension/mobile HNSA integration.
- No public partition, churn, eclipse, or resource-exhaustion campaign.
- No independent protocol and implementation security review.
- No finalized committee/MPC operating parameters or multi-organization
  deployment evidence.
