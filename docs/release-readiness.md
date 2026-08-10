# Release-readiness inventory

Status date: 2026-08-10. This is a source and packaging inventory, not a
production-readiness assertion or release authorization.

## Current identity

| Item | Current state |
|---|---|
| Branch | `main` |
| Workspace packages | 27 packages at `0.1.0` |
| Rust toolchain and MSRV | 1.97.1 |
| Cargo publication | disabled for every workspace package (`publish = false`) |
| License | MIT; canonical text is in `LICENSE-MIT` |
| Tags and GitHub releases | none |
| Release workflow | none; CI qualifies source but does not sign, package, tag, or publish |
| Artifact contract | not yet selected |

The repository history does not establish that `0.1.0` was released, so it
does not make `0.1.1` or `0.2.0` an unambiguous next version. Choose whether
the first supported artifact is the existing `0.1.0` identity or a newly
defined compatibility milestone before changing all workspace versions.

MeshMine is principally a set of coordinated daemons and libraries. A binary
archive or deployment bundle is likely a better first distribution target than
crates.io, but that is a release-policy decision. Do not remove `publish =
false`, tag a commit, or publish an archive merely to make the current source
look released.

## Immutable ecosystem inputs

| Input | Exact source | Role |
|---|---|---|
| `hns-node-rs` | `9ed129f30c8cd8cd8a07c6872aa4ac40ece5d23b` | sole Rust node, mining, and Handshake authority boundary |
| `hns-rs` | `b24b66c382de53330ec21dd3137e056a2bea3e2d` | draft HNSA service authority and HNSR protocol adapter |

The manifests and complete lock graph must agree on those commits. Run
`python3 scripts/validate-release-source-pins.py`; CI runs the same check before
compilation. Git availability and a green upstream build are necessary inputs,
not evidence that MeshMine itself passed its release gates.

`python3 scripts/validate-release-metadata.py` separately verifies that all 27
members inherit one private version, license, edition, and Rust requirement and
that the lockfile uses that same identity. Keep both checks green when the
eventual version is selected.

## Implemented and unavailable product surfaces

The authenticated local node/Core/operator path, bounded multi-operator QUIC
daemon, HNSR reservation/rendezvous machinery, and read-only signed
`pool-stats` publication path exist in source. Their presence does not enable
production mode.

HNSA/HNSR integration remains limited by all of the following:

- HIP 78 and HIP 79 remain drafts;
- `pool-stats` uses private profile ID `0xff00`, not an accepted assignment;
- no independent public-WAN relay/rendezvous operation has been qualified;
- no independently verified extension/mobile presentation has been qualified;
- HNSR failure does not authorize direct-web fallback under the HNSA identity.

MeshMine has no wallet-control surface, transaction or name-management UI,
exchange settlement, order protocol, order book, or P2P marketplace. Its
coinbase payout planning is mining-overlay accounting, not a general payment or
market service. `hns-denuo-market-relay` appears only through the pinned
external node's transitive lock graph and is not consumed by MeshMine code.
MM-0001 lists work-receipt markets only as a future Stage-5 RFC.

## Release blockers

- Every daemon continues to reject or withhold production eligibility.
- Physical HS3 and Goldshell qualification and sustained-load evidence are
  absent.
- Independent-node multi-operator and HNSR deployment evidence is absent.
- Public-WAN partition, replay, churn, eclipse, and resource-exhaustion
  campaigns are absent.
- The MPC/VSS backend, committee parameters, and production wire choices lack
  the required independent review and operating freeze.
- End-to-end winner publication, bounded recovery, and lifetime-state gates in
  `specs/OPEN-QUESTIONS.md` remain open.
- No independent protocol/implementation security review or target-platform
  endurance campaign authorizes production use.
- No installable artifact format, supported-platform matrix, signing policy,
  upgrade/rollback procedure, or release workflow has been approved.

The authoritative detailed gates remain in [the README](../README.md),
[MM-0001](../MeshMine.md), [the threat model](../specs/threat-model.md), and
[the open-questions inventory](../specs/OPEN-QUESTIONS.md).

## Candidate procedure

Before any first release:

1. Resolve or explicitly scope every blocker above and choose the supported
   artifact contract.
2. Choose the version once, update the workspace and changelog together, and
   keep all packages on that identity unless a split-version policy is adopted.
3. Qualify the exact candidate commit with the full CI and RustSec jobs; retain
   source-pin and artifact provenance.
4. Build reproducible target artifacts in CI, generate checksums, and verify
   their embedded version and exact source identities.
5. Review licenses, operator configuration migrations, install/upgrade/rollback
   instructions, and release notes.
6. Tag, sign, upload, or publish only after explicit release authorization.
