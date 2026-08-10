# Changelog

All notable source changes for MeshMine will be recorded here. The project has
not published a tagged release.

## Unreleased

- Pin the external `hns-node-rs` authority to
  `2712d1dbb74934038188637dccf27d58fbc39a48` and the HNSA/HNSR protocol source
  to `b24b66c382de53330ec21dd3137e056a2bea3e2d`.
- Advance the node boundary through the bounded legacy name-tree accumulator
  reconciliation and additive atomic wallet-chain snapshot after confirming
  the MeshMine bridge APIs are unchanged and the exact upstream CI, RustSec,
  and CodeQL gates are green.
- Add an executable check that rejects mixed, mutable, or local substitutions
  for either release-sensitive Git source.
- Add a release-metadata check that keeps all private workspace packages,
  lockfile entries, license metadata, and the pinned Rust toolchain coherent.
- Align local and CI documentation on Rust 1.97.1 and add the matching pinned
  toolchain declaration.
- Supply the MIT license text named by every workspace manifest.
- Correct legacy substitutions that described the Rust node as its own offline
  JavaScript oracle.
- Document the current HNSA/HNSR, wallet, marketplace, packaging, and release
  boundaries without changing production eligibility.
- Define the first private Ubuntu 24.04 x86-64 evaluation bundle, including its
  exact binary/configuration scope and fail-closed install, upgrade, rollback,
  checksum, and provenance boundaries.
- Add a manual credential-free GitHub Actions workflow that retains the
  exact-source evaluation candidate without tagging, signing, publishing, or
  deploying it.

The workspace version remains `0.1.0`. With no tag or published release to
establish whether that version has shipped, the next version is intentionally
not guessed in this change.
