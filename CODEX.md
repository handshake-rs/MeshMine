# MeshMine implementation rules

`MeshMine.md` is normative. MeshMine is a no-hard-fork Handshake overlay, and every emitted network block must be accepted by canonical Handshake consensus in `handshake-rs/hns-node-rs`.

- Do not import Bitcoin serialization, target, header, coinbase, or Merkle assumptions where Handshake differs.
- Use the external `handshake-rs` crates for HNS-sensitive operations; do not carry an embedded node or duplicate consensus implementation.
- Never use floating point for targets, work, reward allocation, or payout selection.
- Never derive protocol hashes from JSON; use the canonical binary codec.
- Object identifiers exclude their own IDs and signatures.
- Stable body IDs exclude masks, sessions, assignments, DAG parents, and receipts.
- The share DAG aids dissemination; certified receipts and session closes define accepted work.
- Timed threshold opening is the winner-recovery guarantee.
- Assignment commitments do not prove exhaustive work by stock ASICs.
- Mainnet and dynamic committees stay disabled until the specification's release gates pass.

Work packages are sequential. Complete and verify WP1 before starting WP2, and keep each package compiling and tested before proceeding.
