# MeshMine / hsrd Phase 1–3 delivery

This archive contains the complete repository working tree after implementing
the Phase 1 authority-safety work, Phase 2 transaction-authorization foundation,
and Phase 3 covenant-linkage plus durable best-chain-activation work.

It is a source delivery, not a claim of production consensus authority. The
project remains fail-closed and defaults to `shadow` mode.

Detailed implementation notes:

- [`hsrd/docs/phase-1-3-change-report.md`](hsrd/docs/phase-1-3-change-report.md)
- [`hsrd/README.md`](hsrd/README.md)
- [`hsrd/docs/gap-analysis.md`](hsrd/docs/gap-analysis.md)
- [`hsrd/docs/storage-schema.md`](hsrd/docs/storage-schema.md)
- [`hsrd/docs/security-model.md`](hsrd/docs/security-model.md)

## Checks completed before packaging

- Static repository, schema, authority, oracle-pin, and fixture-integrity check.
- Reproduction check for Phase 2 HSD fixtures.
- Reproduction check for Phase 3 HSD fixtures.
- JSON and TOML parse checks through the static validator.
- Strict best-work side-chain storage and atomic activation invariants checked
  by the static validator.
- ZIP inventory and SHA-256 digest generated after packaging.

## Local toolchain limitation

No Rust toolchain was installed in the packaging environment. The source was
therefore not locally formatted, compiled, linted, or Cargo-tested. The archive
includes CI definitions for all of those gates. This limitation does not remove
or defer the source delivery; it is recorded so subsequent work begins with the
correct verification priority.

## Phase 3 durable-chain additions

The delivered tree also contains the next best-chain foundation:

- validated non-active block/header/body retention;
- separate best-header and active-best-block bindings;
- strict greater-work promotion with equal-work first-seen preservation;
- explicit reorganization plans from the active tip to a stored candidate;
- ancestry, canonical-order, body-availability, status, and work checks;
- one-overlay/one-batch multi-block replacement;
- final replacement-work verification before commit;
- gated restart recovery on regtest/simnet native-experimental authority only;
- diagnostics for best header, active block, pending activation, alternate block
  count, chain epoch, storage profile, and durability.

This is source-level Phase 3 implementation work. It does not claim complete HSD
historical fork-choice parity or production mainnet authority.
