# Production hsd deployment audit — 2026-07-18

This is a read-only point-in-time audit of the local `hsd` service used as the
MeshMine HNS oracle. It is deployment evidence, not a MeshMine mainnet release
approval. No process, service, wallet, configuration, source file, or chain
state was changed during the audit.

## Verdict

`hsd` was healthy, authenticated, loopback-scoped, and synchronized when
observed. The deployment is nevertheless **not ready to be a production
MeshMine dependency** until its disk-failure loop, service hardening, secret
permissions, version/dependency disposition, and backup/restore controls are
addressed.

## Healthy observations

- `hsd.service` was enabled and active, using hsd `8.99.0` at commit
  `698e252ebc7b5c1dd0a9587e342fdd153d020ae4` with Node.js `20.19.2`.
- The pruned mainnet chain advanced from height 338749 to 338750 during the
  audit. Reported progress was `1.0`; eight outbound peers reported the same
  best height.
- Authenticated node and wallet RPCs succeeded. Unauthenticated HTTP requests
  to the node and wallet ports returned `401`.
- RPC, wallet, and DNS listeners were loopback-only. Handshake-aware DNS
  queries succeeded on both configured DNS listeners.
- `getwork` and `getblocktemplate` succeeded; the observed template targeted
  height 338751. No submission RPC was invoked.
- The service used approximately 110 MiB RSS and 63 file descriptors. Its data
  directory was approximately 9.0 GiB, with approximately 73 GiB free on the
  containing filesystem at the time of observation.

## Blocking findings

1. The service entered an 84-restart loop earlier the same day. The journal
   showed block-store startup failing with `No space left on device`.
   `Restart=always` retried every ten seconds without a disk-capacity preflight,
   capacity alert, or increasing backoff.
2. `systemd-analyze security --user hsd.service` reported `9.8 UNSAFE`. The
   user unit had no explicit `UMask`, filesystem protections, privilege
   restrictions, or syscall sandbox.
3. The `.hsd` directory was mode `0775`; node configuration/key files were
   mode `0664`; wallet files were observed at `0644` or `0664`. The enclosing
   home directory was mode `0700`, which limits present exposure but is not a
   sufficient production secret-permission policy. The hardened recursive
   check counted 2,627 non-private regular-file/directory entries in the state
   tree; it did not print their names.
4. The tracked checkout matched the locally recorded origin at an untagged
   development commit on mutable `master`, but the worktree was not clean
   because an unrelated untracked wallet debug backup was preserved. Upstream
   freshness was not fetched during this read-only audit.
5. Encrypted off-host backup coverage and a successful restore drill could not
   be verified. Same-disk recovery directories indicate prior wallet repair
   work but do not constitute a backup.
6. Inbound HNS P2P was disabled. That is compatible with a local pruned wallet
   oracle, but not with a deployment intended to provide a publicly reachable
   full node.
7. The audited `hsw-cli`, its `bin` directory, the `hsd` source root, and
   multiple checkout ancestors were mode `0775`. MeshMine's hardened
   non-research CLI and source-directory adapters now reject those
   group-writable components, so this exact deployment cannot be used by the
   overlay or role commands until permissions and ownership are remediated and
   re-attested. A recursive source scan counted 1,878 group/other-writable
   regular-file/directory entries without printing their names.
8. A fresh npm advisory query reported the unpatched critical
   [GHSA-jj93-39pf-7mcf](https://github.com/advisories/GHSA-jj93-39pf-7mcf)
   in `bsock <=0.1.11`, propagated through the pinned hsd dependency graph.
   The audited hsd HTTP/WebSocket listeners are loopback-only and authenticated,
   which narrows exposure, but that deployment control is not an upstream fix
   or an exploitability determination for this service.

## Required operator remediation

`scripts/production-hsd-preflight.sh` now codifies the repeatable read-only
technical subset of these checks: canonical/path permissions, recursive
state/source ownership and modes, state/secret modes, configured disk and inode
reserve, exact clean source commit, CLI/tree
and Node identities, service activity, `NoNewPrivileges`, `UMask`, and bounded
restart policy. It requires the state tree to be a single filesystem without
symlinks and binds that tree to an explicit `--prefix` in systemd's retained
`ExecStart` execution record. It compares the record's PID and launcher, the
live process start time, working directory, and `/proc/PID/exe` device/inode and
digest without emitting command-line or environment values. It deliberately
cannot establish backup restore success, alert delivery, public reachability,
the content identity of ignored dependencies such as `node_modules`, the
identity of JavaScript modules already loaded into Node, or safe rollout of a
hardened unit; those remain recorded operator evidence.

The hardened preflight was run against the same live service and exact
`/usr/bin/node` process runtime. Its latest run reported fifteen failed checks
and one restart-count warning. It confirmed the expected source commit,
active/enabled service, available disk/inodes, single-filesystem and symlink-free
state tree, exact live Node identity/digest, stable PID/start time, and the
systemd launcher/working-directory binding. The recursive checks found 2,627
non-private state entries and 1,878 group/other-writable source entries without
printing their names. In addition to the original hardening failures, it
rejected the now-dirty worktree, the unit's implicit default state prefix, its
ten-second restart delay and rate-limit window, and the current count of 84
restarts. No deployment state was changed. Node
`v20.19.2` remains an independently observed audit fact; the hardened preflight
intentionally does not execute the configured runtime to obtain a version
string.

- Add disk free-space and inode preflight checks, alerting, and a restart-rate
  limit/backoff; test the exact disk-full recovery path.
- Put the absolute canonical state directory in `ExecStart` as an explicit
  `--prefix` argument and retain an absolute source-root or `bin` working
  directory. Do not rely on hsd's implicit home-directory default when using
  capacity evidence for release decisions.
- Move the service to an explicit least-privilege unit profile. Start with
  `UMask=0077`, `NoNewPrivileges=yes`, a private runtime directory, narrowly
  scoped writable paths, and protections validated against hsd's actual file
  access before rollout.
- Set state directories to `0700` and secrets/configuration to `0600`, then
  verify the service and wallet still start and operate normally.
- Pin and attest the reviewed hsd commit/runtime in deployment metadata. Treat
  source or executable changes as controlled upgrades with rollback evidence.
- Remove group/other write access from the reviewed CLI leaf and every
  non-sticky checkout ancestor, retain effective-user or root ownership on the
  leaf, and use an absolute canonical path. Record the executable digest as
  part of each controlled upgrade; do not weaken MeshMine's fail-closed path
  checks.
- Require the same canonical path and ancestor non-writability for the
  configured source directory, with effective-user or root ownership on that
  directory leaf. Because the current launcher pins only the directory
  identity and imports mutable descendants, additionally attest the complete
  reviewed source tree and Node runtime in deployment/release metadata.
- Establish encrypted off-host wallet/node backups and record a restore drill
  on a separate host or isolated state directory.
- Decide explicitly whether the oracle is loopback-only or a public HNS node;
  document and monitor the matching listener policy.
- Obtain and record an upstream/vendor disposition for the `bsock` advisory.
  Until a reviewed fix or replacement exists, keep affected HTTP/WebSocket
  listeners loopback-only, disable unused WebSocket surfaces where supported,
  and treat any public exposure as a release blocker rather than relying on the
  repository's exception for isolated oracle test subprocesses.

## Read-only evidence commands

The audit used `systemctl --user`, `journalctl --user`, `systemd-analyze
security`, `ps`, `ss`, `df`, `du`, permission-only `find`/`stat`, authenticated
`hsd-cli`/`hsw-cli` information and mining queries, bundled Handshake DNS
queries, and read-only Git/npm metadata checks. Credential values and wallet
contents were not recorded.
