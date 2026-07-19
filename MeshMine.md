# HNS MeshMine — MM-0001 Core v2

## A no-hard-fork, independently templated mining overlay for Handshake

**Document type:** Implementation specification  
**Specification ID:** MM-0001  
**Revision:** Core v2.0-draft  
**Status:** Implementable architecture for staged regtest and adversarial simulation; not a production security claim  
**Date:** July 17, 2026  
**Canonical project name:** **HNS MeshMine**  

---

## 0. Executive decision

HNS MeshMine is a decentralized mining overlay for Handshake. It is designed to replace the conventional arrangement in which one pool server constructs blocks, controls the work sent to many independently owned ASICs, maintains the authoritative share database, and takes custody of mining proceeds.

MeshMine Core v2 is built around five decisions:

1. **Every mining operator constructs its own Handshake block with its own `hsd` node.**
2. **Concurrent weak work is disseminated through a share DAG rather than serialized into a linear P2Pool sharechain.** The authoritative payout set is a certified, append-only set of accepted shares; the DAG is used for gossip, causality, and partition reconciliation.
3. **Handshake's XOR mining mask is generated through a proper distributed MPC/VSS protocol.** No single dealer learns the mask. Timed threshold opening is the block-recovery guarantee. A private immediate winner test is an optimization, not the liveness foundation.
4. **Each MeshMine block pays a fixed number of probabilistically selected PPLNS work and service tickets directly in an ordinary HNS coinbase transaction.** Transaction and claim/airdrop fees remain with the independent template operator unless a later profile explicitly changes that rule.
5. **ASIC search is divided into committed assignments with auditable job issuance and worker telemetry.** Core v2 does not claim that stock ASICs cryptographically prove exhaustive nonce-range traversal.

MeshMine Core v2 does **not** require a Handshake hard fork. Every network block produced by MeshMine must be accepted by an unmodified `hsd` full node.

The initial project goal is narrower than defeating an attacker that physically owns most HNS ASICs. No voluntary overlay can make genuine majority ownership harmless. MeshMine is intended to remove avoidable coordinator concentration:

- remote control of independent miners' block templates;
- centralized custody of pool proceeds;
- a centralized share-accounting database;
- a pool operator's ability to redirect customer hashrate onto a private branch;
- selective withholding of network winners while collecting ordinary pool credit;
- dependence on one public pool endpoint;
- opaque job assignment and duplicate nonce-space use.

The implementation must keep two validity domains separate:

```text
Handshake-valid:
    Accepted by an ordinary, unmodified hsd full node.

MeshMine-valid:
    Handshake-valid and compliant with MM-0001 overlay rules.

A block may be Handshake-valid and MeshMine-invalid.
Such a block remains a valid HNS block; it simply receives no
MeshMine overlay status beyond whatever HNS consensus gives it.
```

---

## 1. Status, scope, and non-goals

### 1.1 What Core v2 specifies

Core v2 specifies:

- exact compatibility boundaries with `hsd`;
- an acyclic object and identifier graph;
- independently constructed block bodies;
- stable, content-addressed body packages;
- body availability and reconstruction;
- parent certification;
- mask-safe weak-work capture;
- a share DAG and certified accepted-share set;
- mask generation, commitment, private evaluation, and timed opening;
- deterministic PPLNS snapshot closure;
- fixed-count probabilistic coinbase payouts;
- direct operator fee incentives;
- committed work assignments and telemetry levels;
- network messages, persistence, recovery, testing, and implementation stages.

### 1.2 What Core v2 does not specify as production-ready

The following remain parameterized research or deployment decisions:

- production committee sizes and thresholds;
- a production-audited malicious-secure MPC implementation;
- the final sortition and anti-capture parameter set;
- a cryptographic proof that a stock ASIC searched every assigned nonce;
- a trustless economic slashing system;
- HNS consensus recognition of MeshMine receipts, payouts, or weak work;
- HNS fork-choice changes;
- protection against an entity that truly owns or rents a majority of HNS hashrate.

### 1.3 Normative terminology

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative within this document.

A production implementation MUST NOT claim a stronger property than the relevant section establishes. In particular:

- “malicious-secure MPC” does not automatically mean guaranteed output delivery;
- assignment commitments do not prove physical nonce traversal;
- the share DAG does not independently determine payout consensus;
- a pool label does not prove common hardware ownership.

---

## 2. Handshake primitives that constrain the design

Codex MUST treat `hsd` as the byte-level and contextual-validity oracle. Bitcoin serialization or mining assumptions MUST NOT be imported where Handshake differs.

### 2.1 Consensus header

The HNS consensus header is 236 bytes:

```text
nonce          u32
ntime          u64
prevBlock      32 bytes
treeRoot       32 bytes
extraNonce     24 bytes
reservedRoot   32 bytes
witnessRoot    32 bytes
merkleRoot     32 bytes
version        u32
bits           u32
mask           32 bytes
```

The miner-oriented serialization is 256 bytes. It contains a 128-byte preheader and 128-byte subheader and substitutes `maskHash` for the actual mask.

### 2.2 Exact HNS proof-of-work construction

The implementation MUST reproduce the current `hsd` operations byte-for-byte:

```text
subheader =
    extraNonce   ||
    reservedRoot ||
    witnessRoot  ||
    merkleRoot   ||
    version      ||
    bits

subHash = BLAKE2b-256(subheader)

maskHash = BLAKE2b-256(prevBlock || mask)

commitHash = BLAKE2b-256(subHash || maskHash)

preheader =
    nonce       ||
    ntime       ||
    padding20   ||
    prevBlock   ||
    treeRoot    ||
    commitHash

left      = BLAKE2b-512(preheader)
right     = SHA3-256(preheader || padding8)
shareHash = BLAKE2b-256(left || padding32 || right)

powHash = shareHash XOR mask
```

`padding20`, `padding32`, and `padding8` MUST use the exact deterministic padding rule in `hsd`: repeating bytes derived from `prevBlock XOR treeRoot`.

`powHash` is interpreted as a big-endian unsigned 256-bit integer for target comparison, matching `hsd`.

### 2.3 Miner serialization

The miner representation MUST match `AbstractBlock.toMiner()` exactly:

```text
nonce
ntime
padding20
prevBlock
treeRoot
maskHash
extraNonce
reservedRoot
witnessRoot
merkleRoot
version
bits
```

The ASIC or compatibility gateway can calculate `shareHash` while remaining unable to calculate `powHash` without the mask.

### 2.4 No-fork settlement boundary

MeshMine MUST emit ordinary HNS blocks. It MUST NOT add or require:

- a new header field;
- a new transaction type;
- a new covenant;
- a new opcode;
- a changed block-weight rule;
- a changed chainwork rule;
- a changed coinbase maturity rule;
- a changed proof-of-work algorithm.

Any additional MeshMine commitments are carried in otherwise valid coinbase witness data and ordinary coinbase outputs.

### 2.5 Contextual validation without proof of work

Before a body package can receive a MeshMine availability certificate, it MUST be validated by an unmodified or minimally wrapped `hsd` contextual validator with proof-of-work checking disabled. The preferred oracle is the same path used by `chain.verifyBlock(block)` with `VERIFY_POW` removed.

A separate reimplementation of HNS covenant, claim, airdrop, name-tree, fee, sigops, and contextual validation is not sufficient for certification until it has been differentially tested against `hsd`.

---

## 3. Security model

### 3.1 Adversary capabilities

The protocol assumes adversaries may:

- operate miners and full nodes;
- create unlimited overlay identities unless work, bonds, or admission policy constrain them;
- send malformed or conflicting objects;
- withhold blocks, shares, body chunks, signatures, MPC messages, and opening shares;
- eclipse selected participants;
- delay and reorder network traffic within the deployment's synchrony model;
- corrupt committee participants up to a stated threshold;
- construct valid but censoring HNS templates;
- mine on stale or private HNS parents;
- attempt payout grinding and duplicate-credit attacks;
- restart nodes and exploit crash-recovery gaps;
- control the local gateway attached to their own ASICs.

### 3.2 Properties Core v2 can provide

Under the stated thresholds and network assumptions, Core v2 is intended to provide:

- independent block-template sovereignty;
- noncustodial direct coinbase payment;
- public, duplicate-resistant weak-work accounting;
- recoverability of an accepted share and its body after the submitting miner disconnects;
- subthreshold secrecy of the HNS mask before opening;
- eventual detection of accepted network-winning shares after timed opening;
- fixed-count probabilistic payouts with deterministic selection;
- bounded protocol-service compensation;
- observable assignment and worker telemetry.

### 3.3 Properties Core v2 cannot provide

Core v2 cannot by itself guarantee:

- safety against an entity controlling a majority of physical HNS work;
- liveness if enough members of the relevant role committee refuse to act;
- secrecy if the mask reconstruction threshold colludes;
- immediate release under arbitrary MPC aborts;
- exhaustive nonce-search proof from untrusted stock firmware;
- on-chain slashing without a future consensus or escrow mechanism;
- HNS-wide enforcement of MeshMine payout rules.

### 3.4 Minimum honest-participant assumptions

Each committee role MUST state separately:

- committee size `n`;
- certificate threshold `t_sign`;
- reconstruction threshold `t_open` where applicable;
- maximum corrupt members for secrecy;
- maximum unavailable members for liveness;
- network synchrony assumption;
- selection lookback;
- rotation interval;
- annualized capture and liveness-failure targets.

No implementation may infer that one `n/t` pair has identical security for signatures, VSS reconstruction, MPC execution, availability, and settlement.

---

## 4. System architecture

```text
                             HNS peer network
                                    ^
                                    |
                           submit ordinary block
                                    |
+----------------+        +---------------------+
| local HNS ASIC |<------>| local MeshMine node |
+----------------+        +---------------------+
        ^                         ^       ^
        | local legacy/native     |       |
        | gateway protocol        |       +--> local hsd
        |                         |
        |                         +--> MeshMine overlay
        |                                 |
        |       +-------------------------+-------------------------+
        |       |                         |                         |
        |       v                         v                         v
        |  share DAG / receipts     mask MPC/VSS             body availability
        |       |                         |                         |
        |       +-------------------------+-------------------------+
        |                                 |
        |                                 v
        |                         settlement snapshots
        |                                 |
        +---------------------------------+
                         new independently built job
```

The local node owns the operator's economic and policy decisions. No remote MeshMine peer is authorized to choose the operator's:

- HNS parent;
- transaction set;
- claim or airdrop inclusion;
- name-operation policy;
- fee policy;
- operator fee address;
- payout bucket;
- ASIC allocation among mask lanes.

The overlay supplies cooperative services: mask secrecy, accepted-share receipts, body recovery, payout snapshots, and direct payout plans.

---

## 5. Canonical encoding, hashing, and signatures

### 5.1 No self-referential identifiers

Every object identifier MUST be acyclic.

```text
object_id =
    BLAKE2b-256(
        domain_tag ||
        canonical_encode(object_body_without_id_and_signatures)
    )
```

An object MUST NOT contain its own identifier inside the preimage used to calculate that identifier.

Signatures SHOULD sign the completed object ID and explicit context rather than being included in the ID preimage.

### 5.2 Encoding rules

Overlay objects MUST use a versioned binary encoding, not JSON, for identifiers and signatures.

Core v2 encoding rules:

- unsigned integers are little-endian unless a field is explicitly a 256-bit target/hash integer;
- HNS hashes and roots retain their canonical 32-byte wire representation;
- 256-bit target comparisons use big-endian integer interpretation exactly as `hsd` does;
- byte arrays are length-prefixed with canonical unsigned varints;
- vectors are length-prefixed and preserve specified ordering;
- maps are forbidden in hashed objects unless represented as sorted vectors;
- Unicode text is forbidden in consensus-relevant object bodies except normalized diagnostic metadata that is explicitly excluded from identifiers;
- domain tags are ASCII and length-delimited;
- every object begins with `protocol_version` and `network_id`.

### 5.3 Signature suites

Core v2 MUST support algorithm agility.

The first implementation SHOULD use individually verifiable Ed25519 signatures with a sorted signer bitmap/list for certificates. Aggregate or threshold BLS signatures MAY be added in a later version only after rogue-key handling, proof of possession, domain separation, and independent audit are complete.

### 5.4 Domain tags

At minimum, define unique domain tags for:

```text
meshmine/operator/v2
meshmine/payout-bucket/v2
meshmine/payout-snapshot/v2
meshmine/payout-plan/v2
meshmine/template-core/v2
meshmine/body-package/v2
meshmine/body-erasure/v2
meshmine/body-certificate/v2
meshmine/parent-certificate/v2
meshmine/mask-session/v2
meshmine/assignment/v2
meshmine/share/v2
meshmine/share-work-key/v2
meshmine/receipt-batch/v2
meshmine/session-close/v2
meshmine/service-credit/v2
meshmine/committee-seed/v2
meshmine/payout-ticket/v2
```

---

## 6. Core object model

The object graph MUST remain one-way:

```text
finalized share history
        |
        v
payout snapshot
        |
        v
delayed entropy
        |
        v
payout plan
        |
        v
template core
        |
        v
coinbase and block body
        |
        v
body package and availability certificate
        |
        v
mask session and maskHash
        |
        v
assignment
        |
        v
ASIC result / signed share
        |
        v
receipt batch
        |
        v
session close
```

No dynamic share, assignment, DAG-parent, or mask-session object may be required to construct an earlier payout plan or body-package identifier.

### 6.1 `OperatorRecordV2`

```text
OperatorRecordV2 {
    protocol_version: u16
    network_id: u8
    operator_pubkey: [u8; 32]
    sequence: u64
    supported_features: u64
    payout_bucket_ids: Vec<Hash256>
    contact_metadata_hash: Option<Hash256>
    signature_suite: u16
    signature: Signature
}
```

`operator_id` is the hash of the body excluding `signature`.

An operator record is an overlay identity, not proof that one human or company controls one identity.

### 6.2 `PayoutBucketV2`

```text
PayoutBucketV2 {
    protocol_version: u16
    network_id: u8
    operator_pubkey: [u8; 32]
    bucket_sequence: u64
    hns_address_version: u8
    hns_address_hash: Bytes
    activation_height: u32
    retirement_height: Option<u32>
    signature: Signature
}
```

The bucket ID selects an exact HNS output destination. Address rotation creates a new bucket. Historical credited work never silently migrates to a new address.

### 6.3 `PayoutSnapshotV2`

```text
PayoutSnapshotV2 {
    protocol_version: u16
    network_id: u8
    snapshot_sequence: u64
    previous_snapshot_id: Hash256
    first_session_close_id: Hash256
    last_session_close_id: Hash256
    close_anchor_height: u32
    work_window_target: U512
    actual_work_in_window: U512
    work_buckets: Vec<WorkBucketLeaf>
    service_buckets: Vec<ServiceBucketLeaf>
    share_set_root: Hash256
    service_set_root: Hash256
    settlement_committee_id: Hash256
}
```

Leaves MUST be sorted by bucket ID. `snapshot_id` excludes signatures and its own ID.

### 6.4 `PayoutPlanV2`

```text
PayoutPlanV2 {
    protocol_version: u16
    network_id: u8
    plan_sequence: u64
    snapshot_id: Hash256
    entropy_anchor_start: u32
    entropy_anchor_count: u16
    entropy_hashes: Vec<Hash256>
    prior_beacon: Hash256
    plan_seed: Hash256
    work_ticket_count: u16
    service_ticket_count: u16
    work_winners: Vec<PayoutBucketID>
    service_winners: Vec<PayoutBucketID>
    selection_transcript_hash: Hash256
}
```

The plan identifies winners, not final output values. Final values depend on the subsidy and fee allocation of the exact HNS height being mined.

### 6.5 `TemplateCoreV2`

`TemplateCoreV2` is the stable, noncircular commitment placed in the coinbase witness.

```text
TemplateCoreV2 {
    protocol_version: u16
    network_id: u8
    hns_parent_hash: Hash256
    hns_parent_height: u32
    operator_pubkey: [u8; 32]
    operator_fee_bucket_id: Hash256
    payout_snapshot_id: Hash256
    payout_plan_id: Hash256
    plan_sequence: u64
    ordered_non_coinbase_txids: Vec<Hash256>
    ordered_claim_ids: Vec<Hash256>
    ordered_airdrop_ids: Vec<Hash256>
    block_version: u32
    bits: u32
    minimum_ntime: u64
    policy_commitment: Hash256
}
```

```text
template_core_id =
    H("meshmine/template-core/v2" || encode(TemplateCoreV2))
```

The coinbase witness MAY contain `template_core_id`; it MUST NOT contain `body_package_id`.

### 6.6 `BlockBodyPackageV2`

```text
BlockBodyPackageV2 {
    protocol_version: u16
    network_id: u8
    template_core: TemplateCoreV2
    template_core_id: Hash256
    coinbase_raw: Bytes
    transactions_raw: Vec<Bytes>
    merkle_root: Hash256
    witness_root: Hash256
    tree_root: Hash256
    reserved_root: Hash256
    block_weight: u32
    block_sigops: u32
    miner_subsidy: u64
    ordinary_transaction_fees: u64
    claim_airdrop_principal: u64
    claim_airdrop_fees: u64
    operator_fee_value: u64
    work_service_subsidy_value: u64
    hsd_validation_result_hash: Hash256
    operator_signature: Signature
}
```

`body_package_id` hashes the package excluding `operator_signature` and excluding the ID itself.

The body package does not contain:

- a mask;
- `maskHash`;
- a mask-session ID;
- DAG parents;
- assignment roots;
- share receipts;
- transient job IDs.

The same package MAY be reused across multiple mask sessions and lanes while it remains valid for the certified HNS parent.

### 6.7 `BodyErasureDescriptorV2`

```text
BodyErasureDescriptorV2 {
    body_package_id: Hash256
    original_size: u32
    data_shards: u16
    parity_shards: u16
    shard_size: u32
    shard_merkle_root: Hash256
    expiry_height: u32
    compression: u16
}
```

The body ID is always calculated over canonical uncompressed package bytes. Compression is transport-only.

### 6.8 `BodyAvailabilityCertificateV2`

```text
BodyAvailabilityCertificateV2 {
    descriptor_id: Hash256
    parent_hash: Hash256
    parent_height: u32
    hsd_validation_result_hash: Hash256
    challenge_round: u64
    challenge_transcript_root: Hash256
    signer_set: SignatureSet
}
```

This certificate means a threshold of the availability role validated the exact body and completed the required shard possession/retrieval challenge. It does not certify any mask session or share.

### 6.9 `SessionParentCertificateV2`

```text
SessionParentCertificateV2 {
    protocol_version: u16
    network_id: u8
    parent_hash: Hash256
    parent_height: u32
    parent_chainwork: U256
    observed_ntime: u64
    certificate_sequence: u64
    previous_parent_certificate_id: Hash256
    signer_set: SignatureSet
}
```

Every participant independently verifies that the parent is a valid HNS header and that the stated chainwork matches its local `hsd` view before accepting the certificate.

### 6.10 `MaskSessionV2`

```text
MaskSessionV2 {
    protocol_version: u16
    network_id: u8
    lane_id: u16
    session_sequence: u64
    parent_certificate_id: Hash256
    parent_hash: Hash256
    hns_network_target: U256
    capture_target: U256
    accounting_target: U256
    leading_zero_prefix_q: u16
    blind_band_bits_d: u16
    mask_hash: Hash256
    mask_commitment_root: Hash256
    mask_committee_id: Hash256
    fast_eval_policy: u16
    assignment_start_ms: u64
    assignment_end_ms: u64
    submission_end_ms: u64
    timed_open_after_ms: u64
    previous_session_id: Hash256
    signer_set: SignatureSet
}
```

`session_id` excludes signatures and its own ID.

### 6.11 `AssignmentV2`

```text
AssignmentV2 {
    protocol_version: u16
    network_id: u8
    session_id: Hash256
    body_package_id: Hash256
    body_certificate_id: Hash256
    operator_pubkey: [u8; 32]
    worker_id_hash: Hash256
    payout_bucket_id: Hash256
    assignment_sequence: u64
    ntime: u64
    extra_nonce: [u8; 24]
    nonce_start: u32
    nonce_end: u32
    nonce_stride: u32
    edge_target: U256
    capture_target: U256
    telemetry_level: u8
    operator_signature: Signature
}
```

Stock ASIC profiles MAY set `nonce_start`, `nonce_end`, and `nonce_stride` to advisory values. A field being committed does not mean the hardware obeyed it.

### 6.12 `ShareV2`

```text
ShareV2 {
    protocol_version: u16
    network_id: u8
    session_id: Hash256
    assignment_id: Hash256
    body_package_id: Hash256
    operator_pubkey: [u8; 32]
    payout_bucket_id: Hash256
    nonce: u32
    ntime: u64
    extra_nonce: [u8; 24]
    raw_share_hash: Hash256
    declared_target: U256
    gossip_parent_hashes: Vec<Hash256>
    local_telemetry_hash: Option<Hash256>
    operator_signature: Signature
}
```

The share ID includes DAG parents. Credit does not.

### 6.13 Work deduplication key

```text
work_key = H(
    "meshmine/share-work-key/v2" ||
    session_id ||
    body_package_id ||
    ntime ||
    extra_nonce ||
    nonce ||
    raw_share_hash
)
```

A valid `work_key` may receive credit only once. Rewrapping the same proof with different DAG parents, identities, or network routes does not create additional work.

### 6.14 `ReceiptBatchV2`

```text
ReceiptBatchV2 {
    protocol_version: u16
    network_id: u8
    session_id: Hash256
    batch_sequence: u64
    previous_batch_id: Hash256
    accepted_share_ids: Vec<Hash256>
    accepted_work_keys: Vec<Hash256>
    credited_work: Vec<U512>
    share_merkle_root: Hash256
    cumulative_share_count: u64
    cumulative_credited_work: U512
    signer_set: SignatureSet
}
```

Lists MUST be sorted by `work_key`, with a deterministic tie-break by share ID.

A share is **accepted** only when it appears in a valid receipt batch or equivalent per-share threshold receipt.

### 6.15 `SessionCloseV2`

```text
SessionCloseV2 {
    protocol_version: u16
    network_id: u8
    session_id: Hash256
    final_receipt_batch_id: Hash256
    accepted_share_merkle_root: Hash256
    accepted_work_key_root: Hash256
    accepted_share_count: u64
    total_credited_work: U512
    close_reason: u16
    mask_opening_transcript_root: Hash256
    discovered_hns_block_ids: Vec<Hash256>
    signer_set: SignatureSet
}
```

The settlement layer uses close certificates, not an informal local view of the DAG.

---

## 7. Every miner constructs its own block

### 7.1 Local template sovereignty

Each operator MUST run or explicitly connect to its own trusted `hsd`. The local MeshMine node obtains a template and constructs the final coinbase locally.

The node MUST independently choose:

- HNS parent;
- transaction ordering;
- claim and airdrop entries;
- name-auction and covenant transactions;
- block version within HNS rules;
- operator fee destination;
- current payable MeshMine payout plan;
- local policy commitment.

No remote committee supplies the transaction list.

### 7.2 Coinbase commitment

The first ordinary coinbase input witness SHOULD contain a compact commitment:

```text
magic                    "HNSM"
protocol_version         u16
network_id               u8
template_core_id         32 bytes
payout_snapshot_id       32 bytes
payout_plan_id           32 bytes
plan_sequence            u64
operator_key_hash        32 bytes
flags                     u32
```

This commitment is stable for the body package. It deliberately excludes:

- `body_package_id`;
- mask-session ID;
- `maskHash`;
- DAG tips;
- assignment roots;
- receipt roots.

The exact preimage MUST be retrievable from the body package.

### 7.3 Fee ownership

Core v2 separates template incentives from pooled subsidy smoothing:

```text
HNS block subsidy:
    split between probabilistic work tickets and bounded service tickets.

Ordinary transaction fees:
    paid to the independent template operator.

Claim and airdrop fees:
    paid to the independent template operator unless hsd's exact
    contextual rules require another treatment.

Claim and airdrop principal:
    paid to the mandatory corresponding outputs.
```

This is intentional. An operator that includes better fee-paying transactions receives the benefit, while prior PPLNS participants receive subsidy smoothing.

### 7.4 Exact block-body construction sequence

```text
1. Resolve the canonical parent and current payable payout plan.
2. Calculate exact work-ticket and service-ticket subsidy outputs.
3. Calculate the exact operator-fee output policy.
4. Construct the coinbase inputs and required claim/airdrop outputs.
5. Insert the TemplateCore commitment into coinbase input 0 witness.
6. Reserve the exact coinbase base size, witness size, weight, and sigops.
7. Select non-coinbase transactions within remaining HNS limits.
8. Construct final coinbase and ordered transaction vector.
9. Calculate merkleRoot and witnessRoot with hsd-compatible algorithms.
10. Build TemplateCoreV2 and verify its ID matches the committed witness.
11. Build BlockBodyPackageV2.
12. Ask hsd to contextually validate the complete body without PoW.
13. Publish/erasure-code the body and obtain availability certification.
14. Reuse the certified body across compatible mask sessions.
```

The payout plan MUST be known before transaction selection because its outputs affect block and transaction weight.

### 7.5 Lazy and proactive body certification

An operator MAY begin hashing before body certification, but such work is not eligible for an accepted MeshMine receipt until the body has a valid availability certificate.

Recommended production behavior:

- prepublish and certify the active body proactively;
- reuse it across short mask sessions;
- construct a replacement body asynchronously;
- switch only after the replacement is validated and available.

This removes the previous design's requirement to redownload and recertify an entire block every few seconds.

---

## 8. Share DAG and authoritative accepted-share set

### 8.1 Why a DAG

A linear sharechain forces concurrent weak shares to compete for one next pointer. MeshMine instead allows a share to reference several recently observed tips:

```text
       S4 -----+
      /         \
S1 -- S2         S7
 \     \        /
  S3 --- S5 -- S6
```

The DAG provides:

- concurrent dissemination;
- causal references;
- efficient anti-entropy requests;
- partition reconciliation;
- missing-share discovery;
- a visible topology for propagation analysis.

### 8.2 What the DAG does not decide

Core v2 does not use a GHOST, heaviest-subtree, or longest-DAG rule for payout finality.

The authoritative payout set is:

```text
valid shares
    included in valid receipt batches
    committed by a valid session close certificate
```

The receipt and settlement committees therefore remain explicit overlay authorities under their stated thresholds. The specification MUST NOT describe the DAG alone as decentralized settlement consensus.

### 8.3 Parent selection

A share SHOULD reference two to four recent DAG tips from the same session. Parent choice MUST NOT change credited work.

A node MUST reject:

- cross-session DAG parents;
- duplicate parent hashes;
- more than the configured maximum parents;
- cycles;
- parents whose referenced share is invalid;
- parent sets that violate maximum age or depth policy.

### 8.4 Deduplication

Receipt validation MUST deduplicate by `work_key`, not share ID.

If two valid envelopes contain the same `work_key`:

- the first accepted receipt wins;
- later envelopes are duplicate observations;
- equivocation or theft attempts are logged;
- no second payout credit is created.

### 8.5 Capture-rate baseline

The baseline profile SHOULD make every public capture share an accounting share. This avoids creating a profitable rule in which a miner can submit only harder public accounting shares while silently discarding easier mask-safe capture shares.

An optional harder accounting target MAY be introduced only after the implementation demonstrates a mechanism that preserves reliable capture-share delivery and does not let an operator collect near-normal credit while filtering most potential winners. Acceptable future mechanisms may include:

- trusted or attestable local gateways;
- delayed secret promotion of capture shares to credited shares;
- a bonded service rule with independently testable omission evidence;
- a protocol profile that still gives economically meaningful credit to every capture share.

Core v2 default:

```text
T_accounting = T_capture
```

Private edge-health shares may use an easier target and remain local.

---

## 9. Mask-safe capture target

### 9.1 Exact derivation

Let:

```text
T_net = exact HNS target decoded from bits
p     = count_leading_zero_bits(encode_uint256_be(T_net))
d     = blind-band width in bits
q     = p - d
```

The session is invalid if `q < 1` or `d` is outside the configured profile.

Define:

```text
T_capture = 2^(256-q) - 1
```

The mask MUST satisfy:

```text
mask[0:q] = 0
```

For any network winner:

```text
powHash <= T_net
```

therefore `powHash[0:q] = 0`, and because those mask bits are zero:

```text
shareHash[0:q] = 0
shareHash <= T_capture
```

Thus every HNS winner is a public capture share.

### 9.2 Blind band

The mask bits in `[q, p)` form the blind band.

Core v2 requires a uniformly sampled nonzero blind band:

```text
repeat inside MPC:
    blind = secret_random_bits(d)
until blind != 0
```

The implementation MUST NOT map the zero value into a one-hot or other identifiable subset because that biases the distribution.

The suffix `mask[p:256]` is independently secret random data.

### 9.3 Rate implications

The total expected capture-share rate is determined by the target gap, not by the number of operators.

A blind band around 12 bits implies at least approximately 4096 capture shares per expected HNS block, or roughly 6.8 shares per second at a ten-minute block interval, with the exact rate depending on the target's position inside its leading-zero interval.

That rate is acceptable for the baseline and SHOULD be measured rather than prematurely optimized away.

Production `d` MUST be selected through simulation and testnet measurement. It MUST NOT be hard-coded solely from an aesthetic target such as “one share per second.”

### 9.4 Edge target

The local gateway MUST configure the ASIC or controller so it submits every capture share:

```text
T_edge >= T_capture
```

A gateway MAY also collect easier private health shares:

```text
T_health >= T_edge
```

Only capture shares are sent to the MeshMine overlay.

---

## 10. MPC/VSS mask protocol

### 10.1 Required role separation

Core v2 defines at least four independently selected roles:

```text
Mask Committee:
    distributed mask generation, maskHash computation,
    private winner evaluation, timed opening.

Receipt Committee:
    validates shares, deduplicates work, certifies receipt batches.

Availability Committee:
    validates body packages, stores erasure shards,
    performs retrieval challenges.

Settlement Committee:
    certifies parents, closes sessions, closes payout snapshots,
    certifies payout plans and service credits.
```

A deployment MAY allow one operator to participate in several roles, but role selection seeds and risk calculations MUST be independent.

### 10.2 Committee selection

Production committee parameters are generated, not guessed.

For each role, a parameter tool MUST calculate at least:

- probability of an adversary reaching `t_sign`;
- probability of an adversary reaching `t_open`;
- probability of an adversarial blocking minority;
- probability that too few honest members are online;
- cumulative probability over one year;
- sensitivity to correlated hosting and jurisdiction failures;
- risk across parallel lanes;
- effect of work concentration and delayed eligibility.

The tool MUST accept:

```text
adversarial_work_fraction
committee_size
certificate_threshold
opening_threshold
member_online_probability
correlation_groups
rotation_interval
lookback_window
parallel_lanes
annual_security_target
annual_liveness_target
```

No normative mainnet `16/11` default exists in Core v2.

### 10.3 Selection seed

A role committee seed SHOULD combine:

```text
seed = H(
    delayed_hns_entropy_window ||
    prior_threshold_beacon ||
    finalized_eligibility_root ||
    role_tag ||
    epoch_number
)
```

This does not make selection immune to every entropy-bias attack. It reduces dependence on one current block producer and domain-separates roles.

Eligibility MUST use work finalized far enough in the past that the current committee cannot trivially censor its immediate replacement set.

### 10.4 Bootstrap

Core v2 deployment phases:

```text
Phase 0: static, publicly named bootstrap committees on regtest/testnet.
Phase 1: hybrid static + finalized-work committees.
Phase 2: finalized-work sortition with static emergency observation only.
```

The temporary trust in Phase 0 MUST be explicit in user interfaces and documentation.

### 10.5 Distributed mask generation requirements

A production mask backend MUST provide:

- malicious-secure distributed random generation;
- verifiable secret sharing;
- no single full-mask holder;
- a public commitment to the shared mask state;
- exact computation of `maskHash = BLAKE2b-256(prevBlock || mask)` without revealing `mask`;
- enforcement of zero-prefix and nonzero uniformly sampled blind-band constraints;
- persistently stored, verifiable opening shares;
- replay protection and unique session binding;
- crash recovery;
- transcript commitment;
- explicit corruption and synchrony assumptions.

A research implementation MAY use MP-SPDZ or another framework as a circuit and benchmarking backend. Such a backend MUST NOT be described as production-audited merely because it implements a named malicious-secure protocol.

### 10.6 Exact BLAKE2b circuit

The MPC implementation MUST reproduce standard BLAKE2b-256 as used by `hsd`, including:

- 64-bit little-endian words;
- initialization vector;
- parameter block for a 32-byte digest;
- 12 rounds;
- exact message length and final-block flags;
- modulo-`2^64` additions;
- XOR and rotation operations;
- input `prevBlock || mask` in canonical byte order.

The differential test suite MUST compare at least 10,000 generated MPC/opened masks against `hsd` or `bcrypto` outputs.

### 10.7 Session setup

For each lane and parent:

```text
1. Select Mask Committee.
2. Establish authenticated channels.
3. Run distributed randomness/VSS setup.
4. Construct the constrained secret mask.
5. Compute maskHash inside MPC.
6. Commit to VSS/opening metadata.
7. Persist opening shares before signing session setup.
8. Publish MaskSessionV2 and threshold certificate.
9. Begin assignment window only after session setup is final.
```

A member MUST NOT sign a session setup certificate until it has durable recovery material sufficient for its role in timed opening.

### 10.8 Timed threshold opening — normative guarantee

The timed path is the non-withholding guarantee.

A session has distinct windows:

```text
assignment window:
    new jobs may be issued.

submission grace window:
    no new jobs; in-flight capture shares may be submitted.

receipt-finalization window:
    Receipt Committee finalizes accepted-share set.

opening time:
    Mask Committee releases verifiable opening shares.
```

The mask MUST NOT open until the accepted-share boundary is fixed by the final receipt batch or close-intent certificate.

After `timed_open_after_ms`:

1. committee members broadcast signed opening shares;
2. any observer reconstructs the mask after `t_open` valid shares;
3. observers verify `maskHash`;
4. observers evaluate every accepted capture share;
5. any network-winning block is reconstructed from its body package;
6. multiple independent nodes submit the ordinary HNS block to their local `hsd` peers.

The original miner is not required after the share has both:

- a valid body availability certificate; and
- inclusion in a valid receipt batch.

### 10.9 Immediate private winner evaluation — optimization

For each accepted capture share, the Mask Committee MAY evaluate:

```text
powHash = rawShareHash XOR secretMask
winner  = uint256_be(powHash) <= T_net
```

Normal public output:

```text
winner == false:
    reveal only false.

winner == true:
    release enough material to reconstruct the mask or full powHash,
    and terminate the session immediately.
```

The implementation MUST document whether the chosen MPC protocol provides:

- guaranteed output delivery;
- fairness;
- identifiable abort;
- abort only;
- honest-majority or dishonest-majority security.

If the fast path aborts, the protocol falls back to timed opening. The system MUST NOT lose an accepted network winner permanently because a fast evaluation aborted.

### 10.10 Winner-triggered close

When a valid fast-path winner is released:

1. stop new assignments for that session;
2. stop accepting new shares after a deterministic in-flight cutoff;
3. publish the mask and verify `maskHash`;
4. reconstruct and submit the winning block;
5. close the session with reason `NETWORK_WINNER`;
6. retire the mask permanently;
7. start a fresh session for the new HNS parent or current parent if the candidate becomes stale.

### 10.11 Parallel lanes

A deployment MAY operate several independent mask lanes. Lanes MUST use:

- distinct session IDs;
- distinct masks;
- independently derived role-selection seeds;
- separately calculated overlap and failure risk;
- separate assignment namespaces.

An early reveal or liveness failure invalidates only the affected lane. “Three lanes” is an example, not a normative production constant.

### 10.12 Early reveal

If a valid mask is publicly revealed before the authorized opening boundary:

- the session immediately stops issuing assignments;
- only shares accepted before the first verifiable reveal observation remain eligible;
- all accepted shares are evaluated immediately;
- the revealing member is excluded from future role eligibility under overlay policy;
- no on-chain slashing claim is made unless a later enforceable bond system exists.

---

## 11. Body availability and recovery

### 11.1 Availability objective

Once a share is accepted, the network must be able to reconstruct its full HNS block body without cooperation from the original operator.

A signature that says “I stored it” is insufficient by itself. Core v2 uses erasure coding, commitments, and retrieval challenges.

### 11.2 Encoding and distribution

Recommended sequence:

```text
1. Canonically serialize BlockBodyPackageV2.
2. Compute body_package_id over uncompressed bytes.
3. Optionally compress for transport.
4. Split into k data shards and m parity shards.
5. Commit to ordered shards with a BLAKE2b Merkle root.
6. Assign shards across availability members and failure domains.
7. Challenge members to return pseudorandom byte ranges or whole shards.
8. Issue BodyAvailabilityCertificateV2 only after threshold validation.
```

`k`, `m`, signer threshold, and geographic/failure-domain policy are deployment parameters.

### 11.3 Retrieval

Any node MUST be able to request shards by:

```text
/body/2/<body_package_id>/<shard_index>
```

After collecting `k` valid shards, it reconstructs the canonical body package and verifies:

- shard Merkle proofs;
- body package ID;
- operator signature;
- exact HNS roots;
- contextual validation result;
- availability certificate.

### 11.4 Expiry

Availability obligations MUST be tied to HNS height and session settlement state. A body SHOULD remain available until the later of:

- the associated session is closed and its mask opened;
- any discovered block is safely propagated;
- the parent is beyond the configured reorganization horizon;
- service compensation for storage has ended.

### 11.5 Admission control

Full-body certification is a denial-of-service surface. Availability nodes MUST apply:

- per-peer and per-operator quotas;
- duplicate body suppression;
- maximum package size checks before download;
- cheap header/descriptor validation first;
- work-backed request stamps, refundable bonds, service payments, or configured bootstrap allowlists;
- bandwidth accounting;
- temporary bans for invalid bodies.

No public endpoint is required to download and validate every arbitrary package request.

---

## 12. Share validation and receipts

### 12.1 Validation order

Receipt nodes SHOULD validate in this order, stopping at the first failure:

```text
1. Parse bounded object.
2. Verify network and protocol version.
3. Verify session exists and is open for submission.
4. Verify operator signature.
5. Verify assignment signature and session/body linkage.
6. Verify body availability certificate.
7. Reconstruct miner header from assignment and body.
8. Recompute raw share hash exactly.
9. Verify declared raw_share_hash.
10. Verify raw share meets capture target.
11. Calculate work_key and reject duplicates.
12. Verify payout bucket was active for the assignment.
13. Validate DAG parent syntax and availability.
14. Add to pending receipt batch.
```

### 12.2 Credited work

For a share target `T`, credited work is:

```text
work(T) = floor(2^256 / (T + 1))
```

Use arbitrary-precision integer arithmetic. Do not use floating-point difficulty.

Baseline Core v2 credits every accepted capture share at `work(T_capture)`.

### 12.3 Receipt batching

Receipt committees SHOULD batch shares over short intervals to reduce signature overhead. A batch is accepted only after threshold certification.

Nodes MUST retain the exact accepted share objects, not merely the root, until the session is settled and the audit retention period expires.

### 12.4 Conflicting receipts

Receipt members MUST NOT sign conflicting batch sequences for the same session and sequence number.

A proof of double-signing is an overlay fault and MUST be included in eligibility/reputation calculations. Core v2 does not claim enforceable on-chain confiscation.

---

## 13. Fixed-size probabilistic coinbase payouts

### 13.1 Goals

The payout mechanism must provide:

- noncustodial direct HNS outputs;
- bounded coinbase-output count;
- expected payout proportional to accepted work;
- deterministic verification;
- entropy unavailable before snapshot closure;
- independent template-fee incentives;
- explicit service funding;
- correct claim/airdrop output indexing.

### 13.2 Snapshot sequencing

Settlement committees maintain a monotonic snapshot sequence.

A new snapshot closes after the first complete session close that causes cumulative new accepted work since the previous snapshot to meet or exceed `SNAPSHOT_STEP_WORK`.

The boundary session is included in full. The snapshot records actual included work rather than pretending the threshold was exact.

The PPLNS work window includes the newest complete closed sessions until accumulated work meets or exceeds `PPLNS_WINDOW_WORK`. The oldest boundary session is included in full.

The committee MUST sign at most one snapshot root per `snapshot_sequence`.

### 13.3 Delayed entropy

Ticket entropy is not available until after snapshot closure.

Recommended seed:

```text
plan_seed = H(
    "meshmine/payout-plan/v2" ||
    snapshot_id ||
    canonical_hashes_of_HNS_blocks[h+D .. h+D+R-1] ||
    prior_threshold_beacon
)
```

Where:

- `h` is the snapshot close anchor height;
- `D` is a delay;
- `R` is an entropy-window length.

The precise `D` and `R` are deployment parameters. Combining several delayed HNS hashes with a prior threshold beacon reduces reliance on one block hash, but it does not eliminate every majority-miner bias.

### 13.4 Exact payout buckets

Ticket selection operates on exact `PayoutBucketV2` leaves, not abstract operators.

Each work leaf contains:

```text
bucket_id
operator_pubkey
canonical HNS address bytes
credited_work
```

Each service leaf contains the same destination information and bounded certified service credit.

### 13.5 Rejection-sampling ticket selection

Use sampling with replacement. For total weight `W` and 512-bit candidate space:

```text
L = 512
limit = floor(2^L / W) * W

for ticket_index in 0 .. ticket_count-1:
    counter = 0

    loop:
        x = H512(
            "meshmine/payout-ticket/v2" ||
            plan_seed ||
            ticket_class ||
            ticket_index ||
            counter
        )

        if x < limit:
            r = x mod W
            break

        counter += 1

    select the first sorted cumulative bucket interval containing r
```

`H512` MAY be BLAKE2b-512 with explicit domain separation.

This avoids modulo bias and supports work totals larger than 256 bits.

### 13.6 Ticket counts

The total number of probabilistic outputs is fixed for a deployment profile.

Illustrative profile:

```text
K_total   = 64
K_work    = 56
K_service = 8
```

These are not normative mainnet constants. Ticket counts MUST adapt if future subsidy halvings make per-ticket values uneconomic or violate policy limits.

### 13.7 Subsidy and service allocation

Let:

```text
S = HNS block subsidy at candidate height
alpha = bounded service fraction
```

Then:

```text
service_pool = floor(S * alpha)
work_pool    = S - service_pool
```

Transaction and claim/airdrop fees are not included in these pools under the Core v2 baseline; they go to the template operator.

`alpha` MUST be bounded by profile and justified through cost measurement. Illustrative research range: 2%–6%.

### 13.8 Ticket values and remainders

For pool value `V` and `K` tickets:

```text
base = floor(V / K)
rem  = V mod K
```

Tickets with index `< rem` receive `base + 1`; remaining tickets receive `base`.

Duplicate destination winners are combined before serialization.

### 13.9 Service credits

Service credits MAY be issued for externally observable actions:

- valid mask-session setup participation;
- timely verifiable opening shares;
- valid receipt-batch signatures;
- successful body retrieval challenges;
- valid settlement signatures.

Service credit MUST be capped per event and per role. A committee cannot create unlimited value by signing arbitrary internal chatter.

### 13.10 Coinbase output ordering

The body builder MUST use exact `hsd` coinbase semantics.

Recommended ordering:

```text
coinbase output 0:
    first work-ticket payment, or deterministic fallback if no work ticket exists.

outputs 1..C:
    mandatory claim/airdrop outputs corresponding to coinbase inputs 1..C.

remaining work-ticket outputs:
    sorted by canonical destination bytes.

service-ticket outputs:
    sorted by canonical destination bytes.

template-operator fee output:
    ordinary transaction fees plus eligible claim/airdrop fees.
```

If duplicate destinations occur across classes, combining is permitted only if doing so does not disturb required claim/airdrop index matching.

### 13.11 Maximum coinbase value

The implementation MUST distinguish:

```text
miner reward:
    subsidy + ordinary transaction fees + eligible claim/airdrop fees

claim/airdrop principal:
    conjured/input value required to be paid to corresponding outputs

maximum total coinbase outputs:
    miner reward + claim/airdrop principal
```

The final byte sequence MUST be validated through `hsd`; MeshMine must not rely on a simplified independent formula.

### 13.12 Current payable plan

A MeshMine-valid block MUST pay the lowest unpaid eligible plan sequence visible in its certified HNS parent ancestry.

If an HNS reorganization removes a MeshMine block, plan-payment state rolls back with the HNS chain. A later canonical MeshMine block repays the now-unpaid plan.

Non-MeshMine HNS blocks do not advance MeshMine plan sequence.

### 13.13 Bootstrap payout

Before the first finalized work snapshot exists, a bootstrap profile MAY pay the subsidy to the local template operator or a published bootstrap allocation. The exact transition height/session MUST be explicit. Bootstrap rules MUST NOT silently persist after normal snapshots become available.

---

## 14. Committed nonce assignments and worker telemetry

### 14.1 Purpose

Core v2 uses assignments to:

- avoid duplicate work among cooperating local devices;
- bind a share to one body and mask session;
- assign unique extra-nonce namespaces;
- measure job delivery and response latency;
- identify duplicate submissions;
- support future auditable hardware.

It does not assume stock ASICs prove complete search.

### 14.2 Extra-nonce allocation

A local node SHOULD derive unique 24-byte HNS extra nonces:

```text
extra_nonce = first_24_bytes(
    H(
      "meshmine/extra-nonce/v2" ||
      operator_pubkey ||
      session_id ||
      worker_id_hash ||
      assignment_sequence ||
      local_randomness
    )
)
```

The node MUST persist assignment sequence state before issuing a job to prevent reuse after crash.

### 14.3 Telemetry levels

#### Level 0 — stock ASIC

Can establish:

- job issued;
- returned nonce/time/extraNonce;
- validity of returned share;
- observed share rate;
- duplicate work;
- submission delay;
- job-switch latency.

Cannot establish:

- full interval completion;
- nonce search ordering;
- absence of withheld shares;
- exact tested nonce set.

#### Level 1 — observable controller

Adds:

- board and chip status;
- restart/error events;
- reported nonce progress;
- temperature and clock telemetry;
- controller-reported hashrate.

These are operational observations, not cryptographic proof.

#### Level 2 — range-programmable firmware

May enforce:

- nonoverlapping assigned intervals;
- deterministic chip strides;
- work-unit identifiers;
- signed controller transcripts.

Without trustworthy attestation, a signed firmware transcript remains an operator-controlled statement.

#### Level 3 — auditable hardware/protocol

May support stronger evidence through:

- trusted execution and remote attestation;
- verifiable hardware transcripts;
- a fully specified APoW-derived construction;
- challengeable productive re-search;
- consensus or firmware integration.

No Level 3 claim exists until a complete protocol and security proof are published.

### 14.4 No completion penalties in Core v2

Core v2 MUST NOT reduce payout, exclude work, or accuse a miner of withholding merely because an auditor later finds a qualifying nonce inside an assigned interval.

Such a finding proves only that the interval contains the nonce, not that untrusted hardware reached and tested it.

---

## 15. Parent selection, stale work, and reorganizations

### 15.1 Objective parent certificate

Every session is bound to a `SessionParentCertificateV2`.

A participant MUST reject a session if its local `hsd` cannot verify the parent header and chainwork.

The parent certificate is an overlay agreement on which currently observed HNS tip a session mines. It is not an HNS checkpoint and cannot override HNS consensus.

### 15.2 Tip change

When a newer certified parent appears:

1. stop new assignments for old-parent sessions;
2. preserve a bounded submission grace period for already-issued work;
3. check all accepted old-parent capture shares for full HNS validity;
4. close old-parent sessions deterministically;
5. start sessions for the new parent;
6. apply the profile's stale-work credit rule.

### 15.3 Stale-work credit

Core v2 baseline:

- shares submitted before the certified tip-change cutoff receive normal credit if they were based on the previously certified parent;
- shares from assignments issued after the cutoff receive zero credit;
- shares arriving after submission grace receive zero credit but MAY still be checked for a network block if technically valid;
- an operator's private claim that an obsolete parent was still local-canonical is not sufficient.

Profiles MAY apply a bounded stale discount, but the rule must be objective and simulatable.

### 15.4 HNS reorganization

Nodes MUST maintain an overlay view keyed by the canonical HNS chain.

On reorganization:

- roll back MeshMine plan-payment state carried by orphaned blocks;
- invalidate parent certificates whose parents are no longer canonical;
- close affected sessions;
- retain share and body evidence for audit;
- recompute the current payable payout plan;
- never alter already mature HNS outputs on the orphaned branch except as ordinary HNS consensus does.

---

## 16. Networking

### 16.1 Transport

The native overlay SHOULD use authenticated QUIC or libp2p over QUIC. Large body data MUST use request/response streams, not unrestricted gossip.

Legacy Stratum, if used, terminates locally between an ASIC and its own MeshMine gateway. It is not the MeshMine peer protocol.

### 16.2 Gossip topics

Suggested topics:

```text
/mm/2/parent
/mm/2/operator
/mm/2/body-descriptor
/mm/2/mask-session
/mm/2/share
/mm/2/receipt-batch
/mm/2/session-close
/mm/2/mask-opening
/mm/2/payout-snapshot
/mm/2/payout-plan
/mm/2/fault-proof
```

### 16.3 Request/response protocols

Suggested protocols:

```text
/mm/2/body-shard
/mm/2/body-package
/mm/2/share-object
/mm/2/receipt-proof
/mm/2/session-transcript
/mm/2/payout-transcript
/mm/2/committee-roster
```

### 16.4 Peer scoring and limits

Nodes MUST enforce:

- maximum object sizes;
- per-topic rate limits;
- signature-before-expensive-validation where safe;
- per-peer pending-validation budgets;
- duplicate suppression;
- body-download quotas;
- invalid-object penalties;
- bounded orphan-share caches;
- bounded DAG-parent fetch depth;
- separate scoring for availability and gossip behavior.

A peer's economic work identity and transport identity SHOULD be separate to permit network rotation without changing payout identity.

### 16.5 Clock assumptions

Short mask sessions require bounded clock skew. Nodes SHOULD use multiple time sources and monotonic local clocks.

A deployment MUST publish:

- maximum accepted wall-clock skew;
- assignment window duration;
- submission grace;
- receipt finalization duration;
- timed-opening delay;
- behavior during detected skew.

A session is invalid if its schedule is internally inconsistent or exceeds profile bounds.

---

## 17. Persistence and crash consistency

### 17.1 Durable state

A node MUST persist before acknowledging or issuing externally visible state:

- operator sequence numbers;
- payout bucket records;
- body package IDs and validation results;
- erasure descriptors and stored shards;
- parent certificates;
- mask-session state;
- local MPC transcript references;
- verifiable opening shares;
- assignment sequence and extra-nonce allocation;
- accepted shares and work keys;
- receipt batches;
- session closes;
- payout snapshots and plans;
- canonical HNS plan-payment state.

### 17.2 Write ordering

Examples:

```text
Before issuing an assignment:
    persist assignment and extraNonce allocation, then send job.

Before signing a mask session:
    persist opening material, then sign setup certificate.

Before acknowledging a share receipt:
    persist share object and work_key, then include in signed batch.

Before publishing a payout plan:
    persist selection transcript and winners, then sign plan.
```

### 17.3 Mask erasure

After a session is opened and retained for the configured audit period:

- erase live secret-sharing state no longer needed;
- retain public mask, transcript commitments, and fault evidence;
- prevent session ID or mask reuse;
- test erasure behavior on restart and backup restore.

### 17.4 Storage engine

The implementation SHOULD define a storage trait and begin with a transactional embedded database. RocksDB, redb, or SQLite are acceptable prototype backends if crash-consistency tests cover the selected implementation.

---

## 18. State machines

### 18.1 Body state

```text
LOCAL_DRAFT
    -> HSD_VALIDATED
    -> ERASURE_PUBLISHED
    -> AVAILABILITY_CERTIFIED
    -> ACTIVE
    -> EXPIRED
    -> PRUNED
```

### 18.2 Mask-session state

```text
SELECTING_COMMITTEE
    -> MPC_SETUP
    -> MASK_COMMITTED
    -> ASSIGNING
    -> SUBMISSION_GRACE
    -> RECEIPT_FINALIZING
    -> OPENING
    -> OPENED
    -> CLOSED

Any pre-open state may move to:
    ABORTED

ABORTED with accepted shares must still move to:
    TIMED_RECOVERY
    -> OPENED or FAILED_THRESHOLD
```

### 18.3 Share state

```text
RECEIVED
    -> SYNTAX_VALID
    -> POW_VALID
    -> BODY_AVAILABLE
    -> DEDUP_VALID
    -> PENDING_RECEIPT
    -> ACCEPTED
    -> SETTLED

or -> REJECTED(reason)
```

### 18.4 Payout state

```text
ACCUMULATING_WORK
    -> SNAPSHOT_CLOSED
    -> WAITING_FOR_ENTROPY
    -> PLAN_READY
    -> PAYABLE
    -> INCLUDED_IN_HNS_BLOCK
    -> CANONICAL

On reorg:
    INCLUDED_IN_HNS_BLOCK/CANONICAL
    -> PAYABLE
```

---

## 19. Core algorithms

### 19.1 Derive capture parameters

```text
function derive_capture(bits, blind_bits):
    T_net = hsd_decode_compact(bits)
    bytes = encode_uint256_be(T_net)
    p = count_leading_zero_bits(bytes)

    require blind_bits > 0
    require p > blind_bits

    q = p - blind_bits
    T_capture = (1 << (256 - q)) - 1

    return {
        T_net,
        p,
        q,
        blind_bits,
        T_capture
    }
```

### 19.2 Validate a capture share

```text
function validate_share(share, assignment, session, body):
    require share.session_id == assignment.session_id
    require share.body_package_id == assignment.body_package_id
    require assignment.session_id == session.id
    require body.id == assignment.body_package_id
    require valid_signatures(share, assignment)
    require valid_body_certificate(body)

    miner_header = build_hsd_miner_header(
        body.static_roots,
        session.mask_hash,
        share.nonce,
        share.ntime,
        share.extra_nonce,
        body.version,
        body.bits
    )

    raw = hsd_share_hash(miner_header)
    require raw == share.raw_share_hash
    require uint256_be(raw) <= session.capture_target

    key = work_key(share)
    require key not previously accepted

    return VALID(key, work(session.capture_target))
```

### 19.3 Open and evaluate session

```text
function open_session(close, opening_shares):
    require valid_close_certificate(close)
    mask = reconstruct_and_verify(opening_shares)
    require blake2b256(parent_hash || mask) == session.mask_hash
    require mask_has_zero_prefix_and_valid_blind_band(mask, session)

    winners = []

    for share in close.accepted_shares:
        pow = share.raw_share_hash XOR mask
        if uint256_be(pow) <= session.hns_network_target:
            block = reconstruct_block(share, mask)
            require hsd_verify_full_block(block)
            winners.push(block)

    gossip_and_submit_all(winners)
    return winners
```

### 19.4 Build payout plan

```text
function build_plan(snapshot, entropy_hashes, prior_beacon, profile):
    seed = H(
        payout_plan_domain ||
        snapshot.id ||
        concat(entropy_hashes) ||
        prior_beacon
    )

    work_winners = rejection_sample_with_replacement(
        seed,
        class="work",
        buckets=snapshot.work_buckets,
        count=profile.work_ticket_count
    )

    service_winners = rejection_sample_with_replacement(
        seed,
        class="service",
        buckets=snapshot.service_buckets,
        count=profile.service_ticket_count
    )

    return PayoutPlanV2(...)
```

---

## 20. Attack analysis

### 20.1 Pool operator redirects independent miners

Conventional pool:

```text
one remote server changes parent/template
    -> all connected ASICs follow
```

MeshMine:

```text
local hsd and local template constructor choose body
    -> no remote template command exists
```

A malicious overlay peer can advertise an invalid parent or plan, but local validation rejects it.

### 20.2 Miner selectively withholds network winners

The miner sees `shareHash`, not the mask. Under the capture-target rule, every network winner is a capture share.

If the miner submits and receives a receipt, timed mask opening eventually identifies the winner without further miner cooperation.

The claim is limited:

> Under the stated mask-secrecy, capture-target, body-availability, receipt, and threshold-opening assumptions, a miner cannot selectively suppress a network-winning share that it has already submitted and had accepted.

A malicious miner can still suppress all shares or accept reduced income to sabotage the network.

### 20.3 Committee withholds fast-path output

Fast path may abort. Timed threshold opening remains the recovery path. If the opening threshold also refuses, the session fails under the stated liveness assumption. The protocol MUST report this as committee failure, not as an impossible event.

### 20.4 Committee reveals mask early

Only the affected lane/session is stopped. Accepted pre-reveal shares are evaluated; later work is not credited. The mask is permanently retired.

### 20.5 Body withholding

An accepted share requires a valid availability certificate. Reconstruction uses committed erasure shards. If fewer than the assumed honest/online availability members serve data, recovery can fail; this is an explicit availability-threshold failure.

### 20.6 Duplicate credit

`work_key` is independent of DAG parents and operator relabeling. First accepted receipt wins. All later copies receive no credit.

### 20.7 Payout grinding

The snapshot boundary is certified before delayed entropy exists. Ticket selection is deterministic with rejection sampling. Template operators cannot choose alternate valid winner sets for the same snapshot and entropy.

Residual risks include HNS entropy bias and settlement-committee double-signing. Both are measurable and must be simulated.

### 20.8 Empty-block and censorship incentives

Ordinary transaction and claim/airdrop fees go to the template operator, internalizing the cost of stale or empty templates. MeshMine does not force transaction inclusion; it removes a single coordinator's power to impose one policy on everyone.

### 20.9 Stale-parent mining

Eligibility is based on certified parent transitions, not private local claims. Work issued after the cutoff receives no credit.

### 20.10 Physical 51% ownership

MeshMine does not stop an entity that owns or rents enough physical HNS hashrate to outwork the honest network. It reduces coordinator concentration only to the extent independently owned miners adopt it.

---

## 21. Performance budgets and observability

### 21.1 Initial measurable targets

Prototype targets are engineering goals, not security constants:

- HNS proof differential test: 10,000 randomized vectors with zero mismatch;
- share validation: sustain at least 100 capture shares/second/core in Rust prototype;
- public baseline capture rate: support at least 50 shares/second network-wide with headroom;
- body reconstruction: reconstruct a 4 MB package from threshold shards in under one second on commodity hardware;
- receipt finalization: median under 500 ms on testnet;
- timed mask opening: complete within profile grace under expected online conditions;
- winner submission: multiple nodes submit within one network round after mask availability;
- no extra full-body certification per short mask session;
- deterministic payout-plan verification under 100 ms for 100,000 payout buckets.

### 21.2 Required metrics

Nodes and explorers SHOULD expose:

- hashrate and credited-work distribution by operator key;
- independent template-core count;
- body-package diversity;
- transaction-set similarity;
- receipt committee concentration;
- mask committee concentration and overlap;
- availability success rate;
- mask setup/open latency;
- fast-path abort rate;
- session liveness failures;
- capture-share propagation latency;
- duplicate share rate;
- stale-parent work rate;
- payout variance by bucket;
- service-reward concentration;
- ASIC job-switch latency;
- telemetry level distribution.

A block explorer SHOULD distinguish “MeshMine produced this block” from “one entity controlled all MeshMine work.”

---

## 22. Implementation architecture

### 22.1 Language and process split

Recommended architecture:

```text
Rust workspace:
    protocol types, HNS serialization, networking, storage,
    share validation, payout math, gateway, simulation.

Node.js hsd oracle harness:
    imports hsd directly for differential vectors and contextual validation tests.

MPC backend process:
    isolated process with a versioned RPC interface;
    research backend first, independently audited backend required later.
```

### 22.2 Repository layout

```text
HNS-MeshMine/
├── CODEX.md
├── README.md
├── Cargo.toml
├── specs/
│   ├── MM-0001-Core-v2.md
│   ├── wire-vectors/
│   └── threat-model.md
├── crates/
│   ├── meshmine-types/
│   ├── meshmine-codec/
│   ├── meshmine-hns/
│   ├── meshmine-crypto/
│   ├── meshmine-mpc-api/
│   ├── meshmine-body/
│   ├── meshmine-share/
│   ├── meshmine-settlement/
│   ├── meshmine-network/
│   ├── meshmine-storage/
│   ├── meshmine-gateway/
│   ├── meshmine-committee-risk/
│   └── meshmine-sim/
├── bins/
│   ├── meshmine-node/
│   ├── meshmine-cli/
│   ├── meshmine-gateway/
│   └── meshmine-sim/
├── hsd-oracle/
│   ├── package.json
│   ├── generate-vectors.js
│   ├── validate-body.js
│   └── regtest-driver.js
├── mpc/
│   ├── README.md
│   ├── circuits/
│   ├── adapters/
│   └── test-vectors/
├── models/
│   ├── mask-session.tla
│   ├── receipt-close.tla
│   └── payout-snapshot.tla
└── tests/
    ├── differential/
    ├── adversarial/
    ├── integration/
    └── hardware/
```

### 22.3 Coding rules

- No floating-point arithmetic for targets, work, rewards, or payout selection.
- No JSON-derived hashes.
- No `unsafe` Rust outside narrowly reviewed FFI modules.
- Every parser has explicit size bounds.
- Every state transition is idempotent.
- Every network object is versioned.
- Every certificate verifies signer eligibility for that exact role and epoch.
- Every write path has crash-recovery tests.
- Every HNS-sensitive calculation has an `hsd` differential oracle test.
- Mainnet support remains disabled until an explicit release gate is met.

---

## 23. Codex work packages

Codex SHOULD implement one package at a time. It MUST NOT jump directly to dynamic mainnet committees or a production MPC claim.

### WP1 — HNS proof and serialization oracle

Implement:

- 236-byte HNS header;
- 256-byte miner serialization;
- deterministic padding;
- `subHash`;
- `maskHash`;
- `commitHash`;
- `shareHash`;
- `powHash`;
- compact target conversion;
- proof comparison;
- coinbase and root test helpers.

Acceptance:

- 10,000 randomized vectors match `hsd` byte-for-byte;
- all current `hsd` edge vectors pass;
- endian and boundary tests include zero, maximum, and compact-target transition cases.

### WP2 — Acyclic object model and codec

Implement every Core v2 object and canonical codec.

Acceptance:

- dependency graph test proves no ID depends on itself;
- signatures are excluded exactly as specified;
- golden vectors exist in Rust and Node.js;
- malformed lengths and noncanonical encodings are rejected.

### WP3 — Local regtest miner

Build:

```text
hsd regtest
    + local MeshMine node
    + CPU proof simulator
```

Acceptance:

- node constructs its own block body;
- creates a constrained mask locally for test only;
- finds a capture share and network winner on regtest;
- opens mask;
- reconstructs ordinary HNS block;
- unmodified `hsd` accepts it.

### WP4 — Stable body package and contextual validation

Implement:

- TemplateCore commitment;
- exact coinbase payout skeleton;
- body-package ID;
- `hsd` contextual validation adapter;
- body reuse across mask sessions.

Acceptance:

- changing DAG parents, assignments, or masks does not change body ID;
- changing a transaction, payout destination, or operator fee does change body ID;
- invalid covenant/claim/airdrop bodies fail through `hsd`.

### WP5 — Erasure availability

Implement:

- erasure coding;
- shard Merkle proofs;
- retrieval challenge;
- availability certificates;
- body reconstruction;
- request admission controls.

Acceptance:

- reconstruct after configured shard failures;
- fail on corrupted shard/proof;
- recover body after original operator disconnects;
- enforce package and bandwidth limits.

### WP6 — Share DAG and certified accepted set

Use a static regtest Receipt Committee.

Implement:

- share validation;
- DAG gossip parents;
- `work_key` deduplication;
- receipt batches;
- session close;
- partition reconciliation.

Acceptance:

- concurrent branches all remain eligible if receipt-certified;
- same proof with different parents receives one credit;
- deterministic roots match across nodes;
- conflicting receipt batches produce fault proofs.

### WP7 — Timed VSS mask opening

Implement a research-grade distributed mask setup with verifiable threshold opening. Do not implement fast winner MPC first.

Acceptance:

- no individual process receives the full pre-open mask;
- fewer than secrecy threshold cannot reconstruct in tests;
- opening threshold reconstructs after member failures within model;
- exact maskHash matches HNS oracle;
- restart recovery works;
- an accepted winner is recovered after original miner exits.

### WP8 — Private fast winner evaluation

Add the optimization behind the `MpcBackend` interface.

Acceptance:

- normal losing output reveals only `false` and public transcript metadata;
- winning output releases enough to reconstruct immediately;
- forced abort falls back to timed opening;
- no accepted winner is permanently lost by fast-path abort;
- backend security properties are documented precisely.

### WP9 — Capture-target measurement

Implement parameter simulator and live metrics.

Acceptance:

- exact expected rates calculated from target;
- 8–16 blind-bit profiles tested;
- bandwidth, signature, storage, and MPC load measured;
- production profile remains configuration-gated.

### WP10 — Fixed-count payouts

Implement:

- payout buckets;
- deterministic snapshot closure;
- delayed entropy;
- 512-bit rejection sampling;
- work and service tickets;
- fee separation;
- claim/airdrop ordering;
- payout weight reservation;
- reorg rollback.

Acceptance:

- Monte Carlo payout means converge to work proportions;
- no modulo bias in exhaustive small-domain tests;
- total outputs never exceed HNS-valid value;
- unmodified `hsd` accepts generated blocks;
- duplicate winners combine deterministically.

### WP11 — Local ASIC compatibility gateway

Implement:

- HandyStratum-compatible HNS job delivery where useful;
- HS3 and Goldshell profiles discovered through hardware testing;
- maskHash delivery;
- capture-target enforcement;
- share submission parsing;
- job cancellation and failover;
- telemetry levels.

Acceptance:

- real device mines regtest/simulated target through local gateway;
- gateway never exposes secret mask;
- gateway submits all shares meeting configured capture target;
- no unsupported range-completion claim appears in UI or logs.

### WP12 — Committee-risk simulator

Implement exact/binomial/hypergeometric and Monte Carlo models.

Acceptance:

- reports annual capture and blocking risk;
- models online failure and correlated groups;
- models role overlap and parallel lanes;
- rejects parameter profiles exceeding configured risk bounds.

### WP13 — Dynamic role committees

Implement only after WP12.

Acceptance:

- role-domain-separated selection;
- delayed eligibility root;
- bootstrap transition;
- committee roster verification;
- simulated censorship and replacement recovery.

### WP14 — Public overlay testnet

Acceptance gates:

- at least two independent node implementations or one implementation plus an independent verifier;
- deliberate network partitions;
- early mask reveal;
- body unavailability;
- receipt equivocation;
- HNS reorgs;
- committee liveness failures;
- thousands of sessions without unrecoverable accepted winners under assumed threshold;
- public explorer and reproducible incident transcripts.

---

## 24. Testing strategy

### 24.1 Differential HNS tests

Compare Rust against `hsd` for:

- every header field;
- miner serialization;
- roots;
- proof hashes;
- target conversions;
- coinbase reward/value handling;
- claim and airdrop indexing;
- contextual block validity.

### 24.2 Property tests

Properties include:

```text
network winner implies capture share
ID changes on every included field mutation
ID does not change on excluded signature mutation
work_key unaffected by DAG-parent changes
rejection sampling always selects a valid cumulative interval
payout outputs sum exactly to allocated values
mask opens to committed maskHash
body reconstructs from any valid threshold shard set
```

### 24.3 Adversarial tests

Inject:

- malformed headers;
- invalid targets;
- duplicate work under many identities;
- DAG cycles;
- receipt double-signs;
- body shard corruption;
- body withholding;
- MPC abort at each round;
- missing opening shares;
- early mask reveal;
- stale-parent jobs;
- entropy-window reorg;
- payout-plan equivocation;
- crash after every durable-write boundary;
- replayed assignments and extra nonces;
- oversized package requests;
- eclipse and clock-skew conditions.

### 24.4 Formal models

At minimum, model in TLA+ or an equivalent state-machine framework:

#### Mask session

Safety:

- no assignment before committed mask;
- no authorized opening before accepted-share boundary;
- no mask reuse;
- any opened mask matches session `maskHash`;
- an accepted winner is detectable after successful threshold opening.

Liveness under assumptions:

- setup eventually either commits or aborts;
- receipt finalization eventually closes;
- enough opening shares eventually produce public mask.

#### Receipt close

Safety:

- one work key receives at most one credit;
- batch sequence is append-only;
- one final close root per session sequence.

#### Payout snapshot

Safety:

- snapshot closes before entropy;
- one snapshot root per sequence;
- plan winners are deterministic;
- paid-plan sequence follows canonical HNS ancestry.

### 24.5 Hardware tests

Maintain a capability matrix rather than assuming controller behavior:

```text
Device / firmware
job format
maskHash support
minimum target behavior
ntime mutation	extraNonce behavior
nonce range support
job-switch latency
share submission quirks
telemetry level
```

---

## 25. Deployment plan

### Stage 0 — specification and oracle

- freeze Core v2 object graph;
- complete WP1–WP2;
- publish vectors;
- obtain independent protocol review.

### Stage 1 — local regtest

- single node;
- local CPU simulator;
- local test mask backend;
- ordinary HNS block submission.

### Stage 2 — static-committee regtest network

- separate mask, receipt, availability, and settlement processes;
- timed VSS opening;
- body erasure recovery;
- probabilistic payouts.

### Stage 3 — public testnet overlay

- static public bootstrap committees;
- real network latency;
- real ASIC gateways where possible;
- adversarial drills;
- no mainnet reward claims.

### Stage 4 — mainnet opt-in beta

Required gates:

- explicit security review;
- published committee-risk parameters;
- independently reproduced HNS vectors;
- body and payout audit tools;
- clear failure-mode UI;
- multiple availability providers;
- no production claim for unaudited MPC backend;
- kill switch limited to local participation, never HNS consensus.

### Stage 5 — dynamic committees and scale

Only after stable operation:

- finalized-work sortition;
- independent role seeds;
- service-ticket economics;
- work-receipt markets as a separate RFC;
- measurable migration of independently owned hashrate from centralized pools.

### Stage 6 — possible HNS consensus proposal

No hardfork is requested until MeshMine is operating at material scale with several independent implementations.

Future proposals may include:

- consensus-recognized payout roots;
- a payout-tree covenant;
- proof-carrying coinbase accounting;
- weak-share commitments for monitoring or finality research;
- hybrid external-security checkpoints.

Those are out of scope for MM-0001.

---

## 26. Release gates

A release MUST NOT be labeled production-ready unless all of the following are true:

- exact HNS oracle tests pass;
- object graph is frozen and independently reviewed;
- a production MPC/VSS backend has a stated theorem-level model and implementation audit;
- committee capture/liveness probabilities meet published targets;
- accepted-winner recovery succeeds under fault injection;
- body recovery succeeds under assumed failures;
- payout plan and coinbase outputs have independent verifier tooling;
- reorg behavior is tested;
- real ASIC target behavior is documented;
- UI does not overstate nonce-audit evidence;
- at least two organizations operate each critical role;
- incident response and transcript publication procedures exist.

---

## 27. Codex master implementation instruction

The following block may be copied into the repository as `CODEX.md`.

```text
You are implementing HNS MeshMine MM-0001 Core v2.

Treat specs/MM-0001-Core-v2.md as normative. The project is a
no-hard-fork overlay. Every emitted network block must be accepted by an
unmodified hsd node.

Absolute rules:

1. Do not import Bitcoin header, coinbase, target, or merkle assumptions
   where Handshake differs.
2. Match hsd byte-for-byte for header serialization, miner serialization,
   padding, subHash, maskHash, commitHash, shareHash, powHash, compact
   targets, coinbase construction, merkle root, witness root, and full
   contextual block validity.
3. Never use floating point for targets, work, reward allocation, or
   payout selection.
4. Never hash JSON. Use the canonical binary codec.
5. Every object ID excludes its own ID and signatures. Reject any circular
   dependency in tests.
6. The body package is stable and does not include a mask session, DAG
   parents, assignment root, or receipt state.
7. The share DAG is for dissemination and reconciliation. Receipt batches
   and session-close certificates define the authoritative accepted set.
8. Timed threshold opening is the mask-recovery guarantee. Fast private
   winner evaluation is optional and may abort only into timed recovery.
9. Do not claim that committed nonce assignments prove exhaustive search
   on stock ASIC hardware.
10. Mainnet and dynamic committees remain disabled until explicit release
    gates are satisfied.

Implementation order:

- Complete WP1 only.
- Run Rust and Node.js differential vectors.
- Do not begin WP2 until WP1 is green.
- Continue one work package at a time, preserving compilation and tests.
- For each package, update threat-model notes, wire vectors, and recovery
  tests before moving on.

Required first deliverable:

- crates/meshmine-hns with exact HNS primitives;
- hsd-oracle vector generator;
- 10,000 deterministic randomized vectors;
- compact-target boundary tests;
- CI that fails on any Rust/hsd mismatch.

When a specification detail is ambiguous, stop implementation of that
specific detail, add an OPEN-QUESTION entry with the exact dependency and
security consequence, and continue only on independent work. Do not invent
consensus-sensitive behavior.
```

---

## 28. Normative invariants

### HNS compatibility

```text
H1 Every submitted MeshMine block is valid to unmodified hsd.
H2 All HNS-sensitive byte operations match hsd.
H3 MeshMine does not change HNS fork choice or chainwork.
```

### Object graph

```text
O1 No identifier is self-referential.
O2 Signatures are excluded from object IDs unless explicitly specified.
O3 Dynamic session/share state does not alter a stable body ID.
```

### Work capture

```text
W1 Every HNS winner under a valid session meets T_capture.
W2 T_edge is never harder than T_capture.
W3 One work_key receives at most one payout credit.
W4 Baseline accounting credits every accepted capture share.
```

### Mask

```text
M1 No single mask participant receives the full pre-open mask.
M2 The public maskHash is exact HNS BLAKE2b(prevBlock || mask).
M3 The zero prefix and blind-band distribution are verified after opening.
M4 Timed opening begins only after the accepted-share boundary is fixed.
M5 Fast-path abort cannot permanently lose an accepted winner under the
   timed-opening liveness assumption.
M6 A mask is never reused.
```

### Availability

```text
A1 An accepted share references a contextually valid body package.
A2 An accepted share references a valid availability certificate.
A3 The body reconstructs from the stated threshold of valid shards.
```

### Payout

```text
P1 Snapshot closes before ticket entropy exists.
P2 One snapshot root exists per snapshot sequence.
P3 Ticket selection uses deterministic rejection sampling.
P4 Work tickets are proportional in expectation to credited work.
P5 Service compensation is bounded.
P6 Transaction fees remain with the template operator in Core v2.
P7 Coinbase output values and ordering pass hsd contextual validation.
```

### Telemetry

```text
T1 Assignment commitments prove job issuance, not exhaustive search.
T2 No Core v2 penalty depends on unproven range completion.
```

---

## 29. Open questions requiring explicit resolution

These questions do not block WP1–WP6 but block a mainnet security claim:

1. Which audited MPC/VSS protocol and implementation will satisfy the chosen honest-majority, synchrony, and output-delivery model?
2. What committee sizes and thresholds meet annual capture and liveness targets at observed HNS work concentration?
3. What selection lookback prevents a receipt committee from rapidly shaping its successor eligibility set?
4. What blind-band width best balances capture rate, withholding resistance, and MPC load?
5. What service fraction covers real availability/MPC costs without centralizing service rewards?
6. Which entropy window and prior-beacon construction best limits payout grinding under concentrated HNS mining?
7. How many body shards and independent failure domains are required at expected block sizes?
8. Can stock HS3 and Goldshell controllers reliably submit every configured capture share, and what is their actual minimum target behavior?
9. Should a later profile use a harder accounting target, and what cryptographic or economic mechanism prevents profitable filtering of capture-only shares?
10. What independent verifier implementation will be maintained before mainnet beta?

Open questions MUST remain visible in issue tracking and release documentation.

---

## 30. Reference implementation anchors

The implementation should be continuously checked against these upstream sources:

- Handshake header and mask construction:  
  `https://github.com/handshake-org/hsd/blob/master/lib/primitives/abstractblock.js`
- Handshake block-template and coinbase construction:  
  `https://github.com/handshake-org/hsd/blob/master/lib/mining/template.js`
- Handshake block and root validation:  
  `https://github.com/handshake-org/hsd/blob/master/lib/primitives/block.js`
- Handshake transaction and coinbase witness behavior:  
  `https://github.com/handshake-org/hsd/blob/master/lib/primitives/tx.js`
- Handshake contextual block validation:  
  `https://github.com/handshake-org/hsd/blob/master/lib/blockchain/chain.js`
- HandyStratum HNS job compatibility reference:  
  `https://github.com/HandyOSS/HandyStratum/blob/master/docs/spec.md`
- MP-SPDZ research and benchmarking backend:  
  `https://github.com/data61/MP-SPDZ`
- Fairness/output-delivery distinction in MPC literature:  
  `https://eprint.iacr.org/2015/574`
- Auditable proof-of-work research reference:  
  `https://arxiv.org/abs/2601.02496`

---

## 31. Final implementation thesis

HNS MeshMine Core v2 is not “a pool with more servers.” It is a no-hard-fork mining overlay with four explicit cooperative authorities—mask, receipt, availability, and settlement—whose powers are narrow, independently selected, auditable, and replaceable.

The central Handshake-native advantage remains the committed XOR mask:

> A miner can identify and submit mask-safe weak work without knowing which accepted share is a full HNS block. After the accepted-share boundary is fixed, a threshold can open the mask and let every observer recover any network winner.

The design is credible only when its claims remain bounded:

- miners independently construct blocks;
- the share DAG improves concurrent dissemination but does not magically remove committee authority;
- timed threshold opening, not a vague “malicious MPC” label, provides recovery;
- fixed-count ticket payouts smooth subsidy without custodial pooling;
- transaction fees preserve template quality incentives;
- assignment records provide telemetry, not fictional exhaustive-search proofs;
- no hardfork is requested until the overlay is built, measured, independently implemented, and operating at material scale.

That is the implementation baseline Codex should build.