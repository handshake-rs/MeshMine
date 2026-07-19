# Independent JavaScript artifact audit

The repository includes a bounded JavaScript verifier that does not import
Rust code, generated bindings, or node state. It independently implements the
snapshot, plan, nested TemplateCore/body codecs, their object IDs and signature
contexts, Ed25519 certificate checks, committee-roster IDs, strict static
payout policy, 512-bit rejection sampling, payout transcript, body validation
commitment, and HNSM linkage. A separate JavaScript generator fixes the exact
canonical bytes and IDs for every Core v2 object. The artifact verifier uses
the pinned `hsd` only for HNS parsing, canonical-chain queries, and contextual
block verification.

This is implementation-diverse local evidence. It is not a second MeshMine
node implementation, an external audit, or proof of independent organizational
maintenance.

## Distributed MPC setup fixture

The reviewed MP-SPDZ fixture has a separate artifact-identity and output
verifier:

~~~sh
cargo run --locked --quiet -p meshmine-mpc-api --bin verify_mp_spdz_fixture -- \
  /path/to/MP-SPDZ
~~~

It verifies the allowlisted setup source, generated Bristol circuit, compiled
bytecode/schedule, MASCOT executable, and shared library before decoding the
three exact 824-byte party outputs. It then exercises independent local share
imports, signed public commitments, public-only assembly, and threshold HNS
hash reconstruction. Exact build commands, digests, and the observed mask/hash
are in `../mpc/mp-spdz/README.md`.

This command is a conformance auditor, not the production architecture: it
deliberately reads every fixture share in one process to check reconstruction.
A deployed member imports only its own file. The verifier is Rust from the same
repository, the runtime has not received a MeshMine-specific independent
security audit, and there is no remote attestation or live multi-operator
evidence.

## Payout snapshot, plan, entropy, and paid block

Audit a certified snapshot and plan against a participant's own running `hsd`:

~~~sh
NODE_BACKEND=js HSD_DIR=/path/to/hsd \
node hsd-oracle/verify-payout-artifacts.js \
  --snapshot snapshot.certified \
  --plan plan.certified \
  --settlement-roster settlement.json \
  --payout-profile payout-profile.json \
  --hsd /path/to/hsd
~~~

The command rejects noncanonical encodings, wrong object/roster IDs, outsider
or invalid signatures, insufficient thresholds, profile substitutions,
incorrect work totals, nonzero static service credits, wrong entropy
delay/count/beacon, noncanonical HNS entropy, biased or otherwise incorrect
ticket draws, and transcript substitutions.

The payout audit begins at a threshold-certified snapshot. It does not consume
receipt/share evidence or independently prove that the settlement signers
derived the snapshot from the complete receipt prefix; the static Rust signer
workflow performs that earlier check. Present the two checks as complementary,
not as duplicate end-to-end settlement implementations.

If the plan has been paid, add its canonical HNS height:

~~~sh
  --block-height 338700
~~~

The verifier fetches the block twice by canonical height, decodes it through
`hsd`, requires exactly one HNSM commitment for the supplied snapshot/plan,
reconstructs work-ticket values and destination aggregation from the actual
subsidy, preserves the mandatory claim/airdrop slots, checks NONE covenants on
ordinary payouts, and enforces the output bound. An optional final operator-fee
output remains separate from the subsidy-funded work outputs.

`--skip-canonical-entropy` and the `--block-file` offline mode exist only for
deterministic cross-language/regtest tests. Their JSON report explicitly says
that canonical entropy or a canonical paid block was not checked; they must not
be presented as live-chain audit evidence.

## Body package and candidate block

Audit a signed body package and the exact candidate block assembled from it:

~~~sh
NODE_BACKEND=js HSD_DIR=/path/to/hsd \
node hsd-oracle/verify-body-artifacts.js \
  --body body-package.bin \
  --candidate-block candidate-block.bin \
  --hsd /path/to/hsd
~~~

The verifier independently decodes the nested TemplateCore and body, checks
both IDs and the operator signature, recomputes the exact validation-result
commitment, compares every transaction byte/ID and stable header/body root,
checks block weight, verifies the unique HNSM commitment against TemplateCore,
and sends the complete candidate to the running unmodified `hsd` `verifyblock`
path. A non-null `hsd` rejection is an audit failure.

`--body-only` and `--skip-contextual-hsd` are test-only partial modes. The
report exposes `candidate_block_checked` and `contextual_hsd_checked` so a
partial check cannot be silently reported as a complete one.

## Cross-language regression corpus

`specs/wire-vectors/core-v2.json` contains unsigned bytes, canonical bytes, and
object IDs for every one of the 14 Core v2 objects, plus the share work key.
The Node generator and Rust consumer both require the exact 14-name set.

~~~sh
NODE_BACKEND=js node hsd-oracle/verify-core-vectors.js
cargo test --locked -p meshmine-types --test core_vectors
~~~

The isolated body and payout drivers provide composed evidence:

~~~sh
NODE_BACKEND=js node hsd-oracle/validate-body.js
NODE_BACKEND=js node hsd-oracle/payout-driver.js
~~~

The first independently audits a signed body/candidate pair and then exercises
`hsd`'s full contextual no-PoW path. The second has `hsd` accept a solved
threshold-certified work-only payout block and independently rechecks its
snapshot, plan, commitment, and coinbase outputs. Rust tests additionally
resign fraudulent body commitments and payout entropy substitutions with valid
keys and require the JavaScript verifier to reject them.
