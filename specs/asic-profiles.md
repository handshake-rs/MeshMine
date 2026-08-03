# MeshMine Core v2 local ASIC profile status

The local gateway implements the ten-parameter HandyStratum HNS job shape from
HandyOSS/HandyStratum commit `c7c3a488e75c9d147a32aa498c979f8815af0a1c`:

1. job ID;
2. previous block;
3. merkle root;
4. witness root;
5. tree root;
6. reserved root;
7. version;
8. bits;
9. nTime;
10. maskHash.

The secret mask is not a gateway job field. Submissions use the documented
four-byte `ExtraNonce2`, four-byte nTime, and four-byte nonce fields. The local
gateway independently reconstructs the exact HNS miner header and enforces the
configured capture target. Its advertised device target is required to be no
harder than the capture target so a compatible device does not filter captures
that MeshMine needs.

## Evidence and production status

| Profile | Evidence | Telemetry | Production |
|---|---|---:|---|
| MeshMine simulator | Local TCP protocol and exact PoW tests | Level 0 | No |
| HandyMiner reference | Source/wire compatibility | Level 0 | No |
| Goldshell HS3 experimental | No physical-device capture yet | Level 0 | Gated |
| Goldshell generic experimental | No physical-device capture yet | Level 0 | Gated |

The Goldshell entries are deliberately not guessed hardware configurations.
They cannot pass the production gate until a physical-device test records job
receipt, minimum accepted target, maskHash behavior, every returned capture,
job-switch latency, reconnect/failover behavior, and firmware identity. This is
an unresolved deployment gate rather than a software success claim.

Stock devices provide only Level-0 observations. MeshMine records jobs,
submissions, duplicates, delay, and cancellation timing. It never reports
nonce-range completion, exhaustive search, absence of withholding, or a proven
tested-nonce set.

## Executable boundary

The `meshmine-gateway` executable wraps this adapter with a private-network
allowlisted listener, redb state path, bounded connection/request counts, and
a canonical job file. Loopback is the default. A non-loopback bind requires
`--allow-cidrs` with bounded private, link-local, or loopback networks; public
or excessively broad ranges fail closed. State, job, and password paths must be absolute so a
service working-directory change cannot select a fresh nonce namespace or
different credentials. Profile selection is mandatory: `--profile simulator`
selects the deliberately relaxed evaluation target policy, while `handyminer`,
`hs3`, and `goldshell` select exact HandyStratum integer-difficulty target
enforcement. Unknown or duplicate CLI options fail rather than being ignored.
`--production` currently rejects every profile because none has the required
physical capture evidence and the executable has no durable downstream capture
consumer. These are independent gates: adding hardware evidence alone cannot
enable production mode.

Absolute paths do not make a directory controlled by another local user safe.
On Unix the redb state path is traversed one component at a time with retained
directory descriptors and descriptor-relative `openat`; every ancestor and the
leaf use `O_NOFOLLOW`, and their device/inode identities are rechecked before
redb uses the file. Symlink ancestors, `..`, and group/world-writable ancestors
without the sticky bit fail closed, while a sticky shared directory such as
`/tmp` is permitted. The regular database leaf is set to mode `0600` through
its descriptor. This protects the open traversal, not against the same
effective user or root replacing state before startup, supplying a preexisting
database, or rolling durable state back; deployment still needs controlled
ownership and external backup/rollback discipline.

The password and job leaves are separately opened with `O_NOFOLLOW`, checked
against their final path by device/inode, and required to be owned by the
effective user; the job forbids group/other write access and the password
forbids all group/other access. Their ancestor directories are not currently
descriptor-pinned, and ownership of the local JSON does not authenticate its
provenance as a Core assignment. Descriptor-based gateway configuration
opening from a verified service directory and authenticated Core job import
remain production hardening requirements.

[`gateway-job.example.json`](gateway-job.example.json) is intentionally a
synthetic **simulator-only shape example**. In particular, its easy regtest
target and advertised all-ones device target are not valid for a real-device
profile, and all roots, nTime, and millisecond windows are stale placeholders.
They must be replaced with one current gateway job derived from the intended
Core context; that job is not itself an `AssignmentV2`. A real-device job must
also use the exact effective target derived from its advertised integer
difficulty. An optional `previous_job_transition` is a trusted local assertion
of the active job's certified cutoff and grace window, not a certificate that
this executable verifies.

The standalone `meshmine-gateway` executable remains a bounded protocol
harness. `meshmine-corelink-operatord` is the integrated local
operator path: it exchanges exact signed assignment bundles and captures with
`meshmine-cored` over a private Unix-domain connection authenticated by Linux
peer credentials and pinned Ed25519 identities; Core constructs exact `ShareV2`
objects and returns durable signed terminal receipts. The Core daemon performs
bounded authenticated loopback native-`hsrd` parent qualification with no hns-node-rs
runtime dependency, while the operator composes concurrent sessions, reconnect
backoff, fallback hysteresis, assignment draining, the event journal, the
read-only dashboard, and graceful shutdown. Physical hardware qualification is
still absent, so the complete path remains pre-production.

The RPC password comparison has a fixed bounded loop. After eight failed
`mining.authorize` attempts the final negative response is sent and that TCP
connection is closed. The executable also stops after 32 cumulative failed
attempts across connections, so reconnecting cannot multiply guesses for the
lifetime of one process. This counter is not durable across service restart or
shared by multiple gateway processes. LAN deployment therefore still requires
segmentation and is not a production device-identity or rate-limit service.

## Gateway-to-Core boundary status

The integrated path closes the source-level mechanical and local-authority gaps that separated a
durable `ForwardedCapture` from Core admission:

- `CoreAssignmentBundleV1` carries the exact signed context manifest,
  `GatewayAssignmentV1`, mask session, parent certificate, body and body
  certificate, payout bucket, committee rosters, and Handy difficulty. The
  gateway job is derived from this bundle rather than inferred from similar
  header fields.
- The signed gateway assignment authorizes a Handy
  `prefix4 || ExtraNonce2[4] || zero16` range before mining. The operator
  envelope binds the actual selected `ExtraNonce2`, nTime, nonce, raw share
  hash, gateway sequence, connection, and signed observation time.
- The assignment's observation policy selects Core receipt time or bounded
  delegated gateway time. Core applies that policy while constructing the exact
  accepted share.
- Core constructs `ShareV2` itself, setting `local_telemetry_hash` to the exact
  capture-envelope ID. It does not trust a gateway-supplied share ID.
- Accepted and terminal noncredit outcomes use the existing atomic Core handoff
  journal. A terminal signed receipt is durable before the operator removes its
  pending envelope or the gateway compacts its original capture.
- The stable gateway work key retrieves an existing receipt after restart, so a
  crash after Core admission cannot allocate a second gateway sequence for the
  same physical submission.
- Signed replacement, drain, and transition objects fence captures across
  assignment boundaries. The old durable job remains present until the final
  drain and next assignment have been accepted.

The local transport is a private Unix-domain socket with Linux `SO_PEERCRED`, an
expected UID, pinned mutual Ed25519 challenge authentication, bounded frame size
and timeouts, monotonic directional sequence numbers, and checksummed frames.

The remaining boundary gaps are operational and qualification gates rather than
an invitation to infer missing context:

- compile and fault-test every live-parent disagreement, crash point,
  spool-capacity boundary, socket failure, reconnect, and partial transition on
  the target platforms;
- obtain exact physical Goldshell/HS3 job, target, capture, reconnect, fallback,
  stale-work, and drain evidence; and
- independently review and freeze the bundle, transport, receipt, and
  transition state machines.

These remaining gates keep production eligibility false.

## Local work leases

The portable work fabric does not reinterpret `GatewayAssignmentV1`. The signed
gateway assignment remains the maximum authorized envelope. A canonical local
`WorkLease` may divide its ExtraNonce2 interval among physical devices, but may
not expand the signed prefix, ExtraNonce2, nonce, stride, nTime, capture-target,
or worker bounds.

For the Handy profile, local allocation is performed over disjoint
`ExtraNonce2` intervals. Stock devices retain the complete signed nonce range
unless physical evidence proves that narrower nonce controls are honored. A
stock ASIC disconnect is not evidence of exhaustive traversal, and its namespace
cursor is not rewound or reused automatically.

The gateway's lease-aware submission path verifies the local device identity,
canonical lease ID, expiration, ExtraNonce2 bounds, nonce range and stride, and
signed target bounds before invoking the existing signed-assignment submission
path. Gateway capture compaction occurs only after an idempotent downstream
consumer reports durable admission.
