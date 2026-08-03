# MPC integration boundary

Two deliberately different backends exist:

- `DeterministicVssBackend` is the deterministic simulation/fault backend. Its
  trusted coordinator constructs the complete mask and is never production
  eligible.
- `distributed` is the WP7 evaluation adapter. An allowlisted MP-SPDZ
  MASCOT/Tinier computation samples the constrained mask, rejection-samples a
  uniformly nonzero blind band, computes exact
  `BLAKE2b-256(parent || mask)`, and privately outputs one GF(256) Shamir share
  to each party. No setup process receives the clear pre-open mask.

Each Rust member verifies frozen source, circuit, bytecode, schedule, runtime,
and shared-library lengths and BLAKE2b digests before accepting its output. It
then rechecks the compiled profile and exact public parent, binds the artifact
identity into the session, persists only its own signed opening share, and
finally releases a signed public share commitment. The assembler consumes
only those commitments. Redb restart tests recover the local contribution and
opening share; any threshold subset reconstructs and verifies the HNS hash.

See [circuits/README.md](circuits/README.md) for the 209,858-gate Boolean
circuit and [mp-spdz/README.md](mp-spdz/README.md) for the executed malicious
protocol fixture and exact output contract.

This is a local evaluation pass, not a production assurance claim. The adapter
reports protocol-level malicious security under MP-SPDZ's stated assumptions,
but `production_eligible` is false: there is no independent implementation
audit, authenticated multi-host runner/attestation, guaranteed output
delivery, identifiable abort, frozen production committee profile, daemon
composition, or canonical mask-opening wire/boundary.
