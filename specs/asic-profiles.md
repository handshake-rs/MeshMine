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

The `meshmine-gateway` executable wraps this adapter with an explicit
loopback-only listener, redb state path, bounded connection/request counts, and
a canonical job file. State, job, and password paths must be absolute so a
service working-directory change cannot select a fresh nonce namespace or
different credentials. Profile selection is mandatory: `--profile simulator`
selects the deliberately relaxed research target policy, while `handyminer`,
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

The executable is not yet the continuous production gateway. Accepted captures
are durably retained by the library, but this process only reports their count:
it does not deliver them to the share-admission path or invoke
`acknowledge_capture` after durable downstream admission. Consequently a job
with any capture cannot retire, repeated captures eventually reach the durable
capacity limit, and the process stops on that fatal condition. The listener
also serves connections sequentially and exits after its configured lifetime
connection count. A supervised downstream consumer with at-least-once replay,
durable admission acknowledgment, concurrent connection/job transition
handling, and restart tests is a release blocker.

The RPC password comparison has a fixed bounded loop. After eight failed
`mining.authorize` attempts the final negative response is sent and that TCP
connection is closed. The executable also stops after 32 cumulative failed
attempts across connections, so reconnecting cannot multiply guesses for the
lifetime of one process. This counter is not durable across service restart or
shared by multiple gateway processes; the loopback-only listener therefore
still relies on host isolation and is not a production principal/rate-limit
service.

## Audited gateway-to-Core boundary gaps

The durable `ForwardedCapture` is not a `ShareV2`, and there is currently no
safe mechanical conversion between them:

- HandyStratum submissions carry a miner-selected four-byte `ExtraNonce2`.
  The gateway constructs the HNS 24-byte extra nonce as
  `nonce_prefix[4] || ExtraNonce2[4] || zero[16]`, so different submissions for
  one job can have different values. In contrast, an operator-signed
  `AssignmentV2` commits one exact 24-byte `extra_nonce`, and Core share
  validation requires `ShareV2.extra_nonce == AssignmentV2.extra_nonce`.
  Manufacturing an assignment after seeing a capture would not prove that the
  work was assigned before mining. Production must either constrain/allocate
  `ExtraNonce2` before work, issue an authenticated assignment for each allowed
  value, or adopt an independently reviewed versioned protocol change.
- The gateway job file contains the HNS header roots, target, mask hash, and
  local schedule, but not the authenticated Core context needed to construct
  and verify a share: the exact signed assignment and its ID, session, body
  package/certificate, payout bucket, operator identity/signatures, and
  committee context. `share-context-import` is an operator-mediated file
  boundary; `AssignmentV2` is not a native `GossipTopic` or `RequestProtocol`.
  The gateway must not infer those links from similar-looking header fields.
- `ForwardedCapture.received_ms` is durable local gateway evidence, while Core
  admission uses a participant-local first-observation time and requires it to
  be inside the certified submission window. A delayed consumer can therefore
  replay a capture that was timely at the gateway only after it has become too
  late at Core. No signed/canonical boundary currently authorizes Core to trust
  the gateway timestamp; that observation trust and replay rule must be
  specified rather than silently replacing Core's local clock.
- A transition grace capture can be retained with `credit_eligible=false`, but
  `ShareV2` has no non-credit disposition and an admitted active share normally
  enters receipt accounting. Production must define whether such a capture is
  rejected-and-tombstoned, retained as authenticated telemetry, or represented
  by a versioned non-credit protocol object. It must not be admitted as an
  ordinary credited share merely to clear the gateway queue.
- Gateway and Core work identities use different domain-separated hashes. A
  consumer therefore needs an immutable, exact gateway-work-key to `ShareV2`
  ID/Core-work-key mapping. That mapping and successful Core admission (or an
  explicitly specified durable non-credit disposition) must commit before
  `acknowledge_capture`; a file export, attempted send, or volatile response is
  not an acknowledgment. Recovery must replay the same mapping and tolerate a
  crash after Core admission but before the gateway tombstone is written.

A bounded **ACK-only reconciler** is achievable for captures whose exact mapping
and downstream admission already exist: it can verify that immutable evidence
and idempotently call `acknowledge_capture` after a crash. It cannot turn the
current executable into a continuous production gateway, construct missing
Core context, resolve the `ExtraNonce2`/assignment conflict, assign non-credit
semantics, or authenticate `received_ms`. Those are protocol and service
composition gates, not reconciler implementation details.
