# Integration verification

This source tree was verified locally on 2026-07-20 from `main` immediately
before the integration commit.

Environment: `aarch64`, Rust/Cargo 1.89.0, Node.js 24.13.0, and npm 11.6.2.

## Results

| Surface | Evidence | Result |
|---|---|---|
| Root Rust workspace | Locked formatting, all-target/all-feature Clippy with warnings denied, all-target/all-feature tests, and optimized all-target/all-feature build | Pass |
| Native HSRD workspace | Locked metadata and check, formatting, strict all-target/all-feature Clippy, 211 all-feature tests, 208 no-default-feature tests, and optimized all-target/all-feature build | Pass |
| HSRD fuzz workspace | Locked metadata, formatting, and all-target checks for every fuzz target | Pass |
| Source integrity | Six fail-closed Python validators, manifest/file/digest closure, JSON/TOML and language syntax, executable modes, Markdown links, merge markers, and Git whitespace | Pass |
| Pinned HSD oracle | Seven fixture generators, signed operator receipt, 14 Core vectors, 10,000 proof differentials, 10,000 MPC-opened vectors, regtest block acceptance, valid/invalid body checks, payout acceptance/audit, and 1,000-session overlay recovery | Pass |
| Native cryptography | Vendored secp256k1 C smoke test plus RIPEMD-160 standard and 55/56/63/64/65-byte padding-boundary vectors checked against OpenSSL and the pinned HSD implementation | Pass |
| Performance | 505.736 shares/second/core (minimum 100); 4 MiB reconstruction in 32.318 ms (maximum 1,000 ms); 100,000-entry payout verification in 62.442 ms (maximum 100 ms) | Pass |
| Dependency audits | Rust lockfiles had no vulnerability advisory; npm reported only the exact isolated-oracle exception described below | Pass with documented exceptions |

The optimized HSRD build used Rust 1.89.0, all workspace targets and features,
and completed in 24 minutes 18 seconds with two build jobs.

## Audit exceptions

- RustSec reports `instant 0.1.13` as unmaintained through
  `reed-solomon-erasure 6.0.0`; it does not report a vulnerability advisory.
- The pinned, loopback-only HSD oracle dependency graph retains the unpatched
  `bsock` advisory `GHSA-jj93-39pf-7mcf`. The audit gate permits only that exact
  package graph and advisory. It remains a production-HSD release blocker.

## Qualification boundary

This result verifies the integrated research source tree and its reproducible
local gates. It does not certify production readiness. HSRD remains
pre-authority, defaults to shadow operation, and cannot provide native mainnet
authority. Hardware, WAN, external protocol review, complete historical and
invalid-corpus parity, and the other gaps in
[HSRD readiness](hsrd/docs/readiness.md) remain release requirements.

The pinned fixtures do not currently contain a complete canonical genesis
block, so strict positive full-genesis block import is not covered end to end.
Exact canonical header identity and mutated height-zero rejection are covered.
