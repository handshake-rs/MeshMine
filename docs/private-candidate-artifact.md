# Private candidate artifact contract

Status: pre-production evaluation contract. This contract permits CI to retain
an exact-source candidate for review. It is not a release, deployment, signing,
or production authorization.

## Identity and qualified target

The first candidate format is
`meshmine-private-evaluation-v1`. It retains workspace version `0.1.0` until a
release owner deliberately chooses a different first-release identity.

The only target claimed by this contract is
`x86_64-unknown-linux-gnu` built on the GitHub-hosted Ubuntu 24.04 runner with
the repository's pinned Rust 1.97.1 toolchain. ARM64, other Linux distributions,
musl, macOS, Windows, containers, and cross-built packages are outside this
contract until separately qualified.

## Bundle contents

The compressed archive contains exactly these executable surfaces:

- `meshmine-cored`, the local authenticated Core service;
- `meshmine-corelink-operatord`, the supported local Core-link and ASIC
  operator service; and
- `meshmine-operatord`, the separate multi-operator QUIC/HNSR evaluation
  daemon.

It also contains:

- the credential-free Core, operator, parent-oracle, and multi-operator example
  configuration shapes under `config/`;
- the README and the directly applicable operator, Core-link, HNSR,
  pool-statistics, external-node, and release-readiness documents;
- `LICENSE-MIT` and the exact workspace `Cargo.toml` and `Cargo.lock` used by
  the candidate;
- `PROVENANCE.json`, binding the archive to the exact MeshMine commit,
  workspace version, target, and exact `hns-node-rs` and `hns-rs` revisions;
  and
- an internal `SHA256SUMS` covering every other file in the extracted bundle.

The archive name includes the version, target, and first 12 hexadecimal
characters of the MeshMine source commit. A separate `.sha256` file covers the
compressed archive.

The bundle deliberately excludes:

- `hsrd`; operators must obtain the separately versioned node from its own
  canonical repository and match the revision in `PROVENANCE.json`;
- private keys, passwords, authorization headers, certificates, operator
  records, assignment bundles, and HNSA authority objects;
- redb state, logs, captures, payout state, or any other runtime data;
- installers, package-manager metadata, containers, service-manager units,
  default users, filesystem ownership policy, and firewall changes;
- `meshmine-gateway`, because the supported local operator already embeds that
  gateway path;
- `meshmine-workd`, which currently exposes only database initialization and
  inspection; and
- simulation, fixture-generation, committee-risk, and performance-gate tools.

Omission from the first bundle is not removal from the workspace. It prevents
an evaluation archive from implying support for incomplete or developer-only
surfaces.

## Candidate construction and verification

`.github/workflows/private-candidate.yml` is manual and credential-free. It has
read-only repository permission, builds only the three named packages, invokes
`scripts/package-private-candidate.py`, verifies both checksum layers and the
embedded provenance, and retains the result as a GitHub Actions artifact. It
does not create a tag, GitHub Release, package-registry publication, signature,
deployment, or cloud resource.

The packager refuses a dirty checkout or a supplied source revision that does
not equal the checked-out `HEAD`, so `PROVENANCE.json` cannot silently describe
different source bytes.

Before inspecting an extracted candidate, verify the downloaded archive and
then its contents:

```sh
sha256sum -c meshmine-private-evaluation-*.tar.gz.sha256
tar -xzf meshmine-private-evaluation-*.tar.gz
cd meshmine-private-evaluation-*/
sha256sum -c SHA256SUMS
```

Review `PROVENANCE.json` before running any binary. A checksum proves byte
identity only; it is not a maintainer signature or production approval.

## Installation boundary

There is no system installation procedure in this contract. Extract each
candidate into a new, non-privileged, version-and-commit-specific directory and
invoke binaries from that directory for isolated evaluation. Copy the example
configurations before editing them and supply separately created credentials
through the strict paths documented by each daemon. Do not run the examples as
credentials and do not expose their documentation-only addresses.

The archive does not choose service users, privileged paths, startup ordering,
network exposure, firewall rules, hsrd installation, or key generation. Those
remain deployment-policy decisions and release blockers.

## Upgrade and rollback boundary

In-place upgrades and state-schema migration are not supported by this first
contract. For a later candidate:

1. stop the evaluation daemons;
2. retain the old extracted directory, config, credentials, and state as one
   version-specific set;
3. extract and verify the new candidate into a different directory; and
4. use fresh disposable state unless a separately reviewed migration procedure
   explicitly authorizes reuse.

Rollback means stopping the new candidate and restoring the complete old
version-specific set. Do not open irreplaceable state with a newer binary and
then attempt to downgrade it in place. No current candidate authorizes use on
production state.

## Remaining release gates

A retained candidate is useful build evidence, not a release. Target endurance,
physical ASIC behavior, independent HNSR operation, third-party license review,
signing policy, service installation, state migrations, deployment hardening,
and every production gate in the release-readiness inventory remain open.
