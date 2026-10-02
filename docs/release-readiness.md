# Release-readiness inventory

## Current identity

| Item | Current state |
|---|---|
| Branch | `main` |
| Workspace packages | 27 packages at `0.1.0` |
| Rust toolchain and MSRV | 1.97.1 |
| Cargo publication | disabled for every workspace package (`publish = false`) |
| License | MIT; canonical text is in `LICENSE-MIT` |
| Tags and GitHub releases | none |
| Release workflow | none; CI qualifies source and the manual candidate workflow retains an evaluation artifact, but neither signs, tags, publishes, or deploys |
| Artifact contract | `meshmine-private-evaluation-v1`; pre-production Ubuntu 24.04 x86-64 candidate only |

MeshMine is principally a set of coordinated daemons and libraries. The first
bounded contract is therefore a private binary evaluation archive rather than
crates.io publication. Its exact contents, target, provenance, checksum,
installation, upgrade, and rollback boundaries are defined in
[the private candidate contract](private-candidate-artifact.md). Selecting that
candidate shape does not authorize a release. Do not remove `publish = false`,
tag a commit, or publish an archive merely to make the current source look
released.

## Immutable ecosystem inputs

| Input | Exact source | Role |
|---|---|---|
| `hns-node-rs` | `2712d1dbb74934038188637dccf27d58fbc39a48` | sole Rust node, mining, and Handshake authority boundary |
| `hns-rs` | `b24b66c382de53330ec21dd3137e056a2bea3e2d` | draft HNSA service authority and HNSR protocol adapter |

The manifests and complete lock graph must agree on those commits. Repository
manifest patches, replacements, and local Cargo path/source overrides are
forbidden. Run `python3 scripts/validate-release-source-pins.py`; CI runs the
same check in a clean checkout before compilation. Git availability and a green
upstream build are necessary inputs, not evidence that MeshMine itself passed
its release gates.

`python3 scripts/validate-release-metadata.py` separately verifies that all 27
members inherit one private version, license, edition, and Rust requirement and
that the lockfile uses that same identity. Keep both checks green when the
eventual version is selected.

## Private candidate boundary

The credential-free, manually dispatched
`.github/workflows/private-candidate.yml` builds only `meshmine-cored`,
`meshmine-corelink-operatord`, and `meshmine-operatord` for the exact
`x86_64-unknown-linux-gnu` runner target. It packages credential-free examples,
the exact lock graph, documentation, source provenance, and two checksum layers,
then retains them as a 14-day GitHub Actions artifact.

This is deliberately narrower than the workspace. It excludes the standalone
gateway already embedded by the supported operator, the skeletal work
coordinator, developer tools, `hsrd`, credentials, runtime state, installers,
service units, and deployment policy. It creates no tag, GitHub Release,
registry package, signature, or cloud resource. A successful workflow run is
candidate-build evidence only.

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
market service. MeshMine does not consume the external node's
marketplace-relay surface.
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
- The private candidate covers only Ubuntu 24.04 x86-64 evaluation; no broader
  target-platform matrix or endurance evidence exists.
- No production installer, service-manager integration, credential lifecycle,
  state-migration procedure, signing policy, or release workflow has been
  approved. The candidate contract permits only side-by-side disposable state
  and whole-version rollback.

The authoritative detailed gates remain in [the README](../README.md),
[MM-0001](../MeshMine.md), [the threat model](../specs/threat-model.md), and
[the open-questions inventory](../specs/OPEN-QUESTIONS.md).

## Candidate procedure

Before any first release:

1. Resolve or explicitly scope every blocker above; the current private
   evaluation contract is not a production distribution contract.
2. Choose the version once, update the workspace and changelog together, and
   keep all packages on that identity unless a split-version policy is adopted.
3. Qualify the exact candidate commit with the full CI and RustSec jobs; retain
   source-pin and artifact provenance.
4. Dispatch the credential-free candidate workflow for the exact commit,
   verify both checksum layers and embedded source identities, and retain the
   run URL and artifact digest. Do not infer cross-run binary reproducibility
   until it is separately demonstrated.
5. Review third-party licenses and define any production configuration
   migration, installation, service-management, upgrade, rollback, and signing
   policy beyond the private evaluation boundary.
6. Tag, sign, upload, or publish only after explicit release authorization.
