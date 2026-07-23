#!/usr/bin/env python3
"""Fail-fast static integrity checks for the pre-authority hsrd workspace.

These checks deliberately avoid compiling Rust. They validate repository
metadata, pinned oracle provenance, fixture integrity, storage migration
boundaries, and fail-closed authority invariants before CI starts native
builds. They complement, but never replace, rustfmt, Clippy, Cargo tests,
fuzzing, historical replay, or live differential validation.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path, PurePosixPath
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
HSD_REVISION = "698e252ebc7b5c1dd0a9587e342fdd153d020ae4"
HSD_REPOSITORY = "handshake-org/hsd"
MANIFEST_PATH = ROOT / "hsrd/fixtures/hsd/manifest-v1.json"
EXPECTED_STORE_SCHEMA = 14
EXPECTED_STORAGE_PROFILE = "hsrd-mining-v10"
SKIP_PARTS = {".git", "node_modules", "target", "__pycache__"}


def fail(message: str) -> NoReturn:
    print(f"hsrd static validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def repository_files(pattern: str):
    for path in ROOT.rglob(pattern):
        if not any(part in SKIP_PARTS for part in path.parts):
            yield path


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {path.relative_to(ROOT)}: {error}")


def require_tokens(source: str, tokens: tuple[str, ...], label: str) -> None:
    for token in tokens:
        if token not in source:
            fail(f"{label} token {token!r} is missing")


def parse_metadata() -> None:
    for path in repository_files("Cargo.toml"):
        try:
            with path.open("rb") as file:
                tomllib.load(file)
        except (OSError, tomllib.TOMLDecodeError) as error:
            fail(f"invalid TOML at {path.relative_to(ROOT)}: {error}")

    for path in repository_files("*.json"):
        try:
            with path.open("r", encoding="utf-8") as file:
                json.load(file)
        except (OSError, json.JSONDecodeError) as error:
            fail(f"invalid JSON at {path.relative_to(ROOT)}: {error}")


def validate_component_naming() -> None:
    """Prevent completed rollout labels from returning to current HSRD surfaces."""
    rollout_word = "ph" + "ase"
    checkpoint_word = "mile" + "stone"
    forbidden_paths = [
        *ROOT.glob(f"{rollout_word.upper()}*_IMPLEMENTATION_REPORT.md"),
        *ROOT.glob(f"{rollout_word.upper()}*_VERIFICATION_LOG.txt"),
        *(ROOT / "hsd-oracle").glob(f"generate-hsrd-{rollout_word}*-fixtures.js"),
        *(ROOT / "hsrd/docs").glob(f"{rollout_word}-*-change-report.md"),
        *(ROOT / "hsrd/crates/hns-node/src").glob(f"{rollout_word}*.rs"),
        ROOT / "hsrd/docs" / f"{checkpoint_word}s.md",
        *(ROOT / "hsrd/fixtures/hsd").rglob(f"{checkpoint_word}[0-9]*"),
    ]
    forbidden_paths = [path for path in forbidden_paths if path.exists()]
    old_validator = ROOT / f"scripts/validate-{rollout_word}9-source.py"
    if old_validator.exists():
        forbidden_paths.append(old_validator)
    if forbidden_paths:
        rendered = ", ".join(
            str(path.relative_to(ROOT)) for path in sorted(forbidden_paths)
        )
        fail(f"rollout-labeled files remain: {rendered}")

    numbered_rollout = re.compile(
        rf"\b(?:{rollout_word}|{checkpoint_word})(?:[ _-]?\d+(?:[ _-]?\d+)?)\b",
        re.I,
    )
    text_suffixes = {".json", ".md", ".rs", ".toml"}
    for path in (ROOT / "hsrd").rglob("*"):
        if (
            not path.is_file()
            or path.suffix not in text_suffixes
            or any(part in SKIP_PARTS for part in path.parts)
        ):
            continue
        source = read_text(path)
        match = numbered_rollout.search(source)
        if match:
            line = source.count("\n", 0, match.start()) + 1
            fail(
                f"rollout label {match.group(0)!r} remains at "
                f"{path.relative_to(ROOT)}:{line}"
            )

    package = json.loads((ROOT / "hsd-oracle/package.json").read_text())
    for name, command in package.get("scripts", {}).items():
        if numbered_rollout.search(name) or numbered_rollout.search(str(command)):
            fail(f"rollout-labeled npm script remains: {name!r}")


def validate_fixture_manifest() -> None:
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot load {MANIFEST_PATH.relative_to(ROOT)}: {error}")

    if manifest.get("schema") != 1:
        fail("hsrd fixture manifest schema must be 1")

    oracle = manifest.get("oracle")
    if oracle != {"repository": HSD_REPOSITORY, "revision": HSD_REVISION}:
        fail("hsrd fixture manifest is not pinned to the declared hsd oracle")

    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        fail("hsrd fixture manifest must contain at least one case")

    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    fixture_root = MANIFEST_PATH.parent
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            fail(f"fixture case {index} is not an object")

        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            fail(f"fixture case {index} has no non-empty id")
        if case_id in seen_ids:
            fail(f"duplicate fixture case id {case_id!r}")
        seen_ids.add(case_id)

        raw_path = case.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            fail(f"fixture {case_id!r} has no path")
        pure_path = PurePosixPath(raw_path)
        if pure_path.is_absolute() or ".." in pure_path.parts or "." in pure_path.parts:
            fail(f"fixture {case_id!r} path escapes the fixture root: {raw_path!r}")
        normalized_path = pure_path.as_posix()
        if normalized_path in seen_paths:
            fail(f"duplicate fixture path {normalized_path!r}")
        seen_paths.add(normalized_path)

        digest = case.get("blake2b256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            fail(f"fixture {case_id!r} has an invalid BLAKE2b-256 digest")

        path = fixture_root.joinpath(*pure_path.parts)
        if not path.is_file():
            fail(f"fixture {case_id!r} is missing at {path.relative_to(ROOT)}")
        actual = hashlib.blake2b(path.read_bytes(), digest_size=32).hexdigest()
        if actual != digest:
            fail(
                f"fixture {case_id!r} digest mismatch: expected {digest}, got {actual}"
            )

    actual_paths = {
        path.relative_to(fixture_root).as_posix()
        for path in fixture_root.rglob("*.json")
        if path != MANIFEST_PATH
    }
    if actual_paths != seen_paths:
        unlisted = sorted(actual_paths - seen_paths)
        missing = sorted(seen_paths - actual_paths)
        details = []
        if unlisted:
            details.append(f"unlisted files: {', '.join(unlisted)}")
        if missing:
            details.append(f"missing files: {', '.join(missing)}")
        fail(f"fixture manifest/file set mismatch ({'; '.join(details)})")

    required = {
        "header-codec-v1",
        "transaction-codec-v1",
        "block-codec-v1",
        "covenant-codec-v1",
        "resource-codec-v1",
        "name-hash-v1",
        "compact-targets-v1",
        "sighash-v1",
        "sequence-locks-v1",
        "covenant-linkage-v1",
        "name-state-codec-v1",
        "name-state-urkel-v1",
        "urkel-proofs-v1",
        "name-policy-v1",
        "p2p-wire-v1",
        "mining-template-v1",
        "mainnet-claim-history-v1",
        "mainnet-claim-replacements-v1",
        "name-transitions-v1",
    }
    missing = sorted(required - seen_ids)
    if missing:
        fail(f"fixture manifest is missing required cases: {', '.join(missing)}")


def validate_authority_safety() -> None:
    deprecated = re.compile(
        r"\b(header_valid|body_valid|tx_valid|state_connected|"
        r"BlockValidated|block_validated)\b"
    )
    for path in repository_files("*.rs"):
        if "hsrd" not in path.parts:
            continue
        text = read_text(path)
        match = deprecated.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            fail(
                f"deprecated coarse validation token {match.group(0)!r} remains at "
                f"{path.relative_to(ROOT)}:{line}"
            )

    node_path = ROOT / "hsrd/crates/hns-node/src/lib.rs"
    node_source = read_text(node_path)
    test_module = node_source.rfind("#[cfg(test)]\nmod tests")
    production_source = node_source if test_module < 0 else node_source[:test_module]

    if not re.search(r"#\[cfg\(test\)\]\s*fn fixture\s*\(", node_source):
        fail("NodeBlockImport fixture constructor is not restricted to test builds")
    if re.search(r"pub(?:\([^)]*\))?\s+fn fixture\s*\(", node_source):
        fail("NodeBlockImport fixture constructor must not be public")

    forbidden_literal_completions = (
        ".tree_root_valid = true",
        ".claims_and_airdrops_valid = true",
    )
    for token in forbidden_literal_completions:
        if token in production_source:
            fail(f"production node path prematurely asserts {token[1:]}")

    require_tokens(
        node_source,
        (
            "AuthorityMode::Shadow",
            "AuthorityMode::NativeExperimental",
            'feature = "experimental-authority"',
            "acknowledge_incomplete_consensus",
            "struct MiningAuthorityPermit",
            "fn issue_authority_permit",
            "mark_unclean_start",
            "mark_node_store_clean",
            "STARTUP_AUDIT_CHECKPOINT_KEY",
            "failed to stage clean-shutdown marker",
            "let deployments = self.deployment_state_for_block(",
            "write_deployment_state(",
            "name_flags: deployments.name_flags",
            "status.deployment_state_valid = true",
            'b"deployment-state/v1/"',
        ),
        "authority safety",
    )

    if "pub struct MiningAuthorityPermit" in node_source:
        fail("MiningAuthorityPermit must remain private to hns-node")

    permit_position = node_source.find("issue_authority_permit(&self.config, &durable)")
    candidate_position = node_source.find("pub fn submit_mining_candidate")
    if permit_position < candidate_position:
        # Locate the permit check after the candidate entrypoint, not an earlier use.
        permit_position = node_source.find(
            "issue_authority_permit(&self.config, &durable)", candidate_position
        )
    if candidate_position < 0 or permit_position < candidate_position:
        fail("mining candidate admission is not guarded by an authority permit")


def validate_schema_coordination() -> None:
    store_source = read_text(ROOT / "hsrd/crates/hns-store/src/lib.rs")
    match = re.search(r"pub const SCHEMA_VERSION:\s*u32\s*=\s*(\d+)\s*;", store_source)
    if not match:
        fail("cannot find hns-store SCHEMA_VERSION")
    actual = int(match.group(1))
    if actual != EXPECTED_STORE_SCHEMA:
        fail(
            f"hns-store schema must be {EXPECTED_STORE_SCHEMA} after hardening, got {actual}"
        )

    profile = re.search(r'pub const STORAGE_PROFILE:\s*&\[u8\]\s*=\s*b"([^"]+)";', store_source)
    if not profile or profile.group(1) != EXPECTED_STORAGE_PROFILE:
        fail(
            f"hns-store storage profile must be {EXPECTED_STORAGE_PROFILE!r}"
        )

    require_tokens(
        store_source,
        (
            "pub enum DurabilityPolicy",
            "options.disable_wal(false)",
            "RocksSnapshot<'a>",
            "snapshot: rocksdb::Snapshot<'a>",
            "pub struct StagingOverlay",
            "schema marker exists without a storage-profile marker",
            "schema marker exists without a durable name-tree-root binding",
            "schema marker exists without a durable airdrop-field binding",
            "database contains data but has no schema marker",
            "invalid clean-shutdown marker",
            "NameTreeRoot",
            "NameTreeNodes",
            "AirdropField",
            "SyncCheckpoint",
            "sync-checkpoint",
        ),
        "storage",
    )

    chain_source = read_text(ROOT / "hsrd/crates/hns-chain/src/lib.rs")
    require_tokens(
        chain_source,
        (
            "covenant_links_valid",
            "covenants_context_valid",
            "COVENANT_LINKS_VALID",
            "COVENANTS_CONTEXT_VALID",
            "plan_reorg_between",
            "plan_failed_branch",
            "MissingBestHeaderBinding",
            "InconsistentFailureAncestry",
            "record.chainwork > best.chainwork",
        ),
        "chain/status safety",
    )

    node_source = read_text(ROOT / "hsrd/crates/hns-node/src/lib.rs")
    require_tokens(
        node_source,
        (
            "HSRD_DIAGNOSTIC_API_VERSION: u32 = 10",
            "store_validated_alternate",
            "store_failed_block",
            "best_chain_activation_plan",
            "apply_reorg_classified",
            "ContextualActivationFailure",
            "StateConnectError",
            "validate_reorg_plan",
            "validate_reorg_request_shape",
            "stage_best_header_if_more_work",
            "cache_committed_block_records",
            "next_chain_epoch",
            "validate_durable_chain_invariants",
            "previous_retained_tree_root",
            "previous_retained_committed_tree_root",
            "tip_resulting_tree_root",
            "tip_resulting_committed_tree_root",
            "breaks retained name-tree root continuity",
            "active tip's resulting root",
            'b"undo-pruning/v1"',
            "prune_undo_history_to_policy",
            "crosses pruned undo history",
            "replacement tip chainwork",
            "failed_block_count",
            "active_state_sync_enabled",
            "active_state_connect_batch",
            "active_state_resulting_root",
            "active_state_resulting_root_height",
            "invalid_branch_is_durable_falls_back_and_taints_descendants",
            "shadow_active_state_connector_resumes_in_bounded_batches_without_authority",
            "shadow_active_state_runtime_updates_scheduler_and_diagnostics",
            "shadow_active_state_connector_reorganizes_a_stored_best_branch",
            "contextual_invalid_ancestor_is_durable_and_exact",
            "local_state_fault_does_not_poison_a_stored_branch",
            "valid_block_commit_publishes_targeted_caches_without_full_index_rescan",
            "mining_snapshot_uses_interval_committed_name_root",
            "mainnet_canary: bool",
            "validate_mainnet_canary_config",
            "authority_can_mine_with_readiness",
            "best header and active-state tip are not synchronized",
            "mainnet_canary_requires_explicit_hardened_config_and_complete_readiness",
            "native_functional_readiness_leaves_only_external_qualification_gates",
        ),
        "best-chain activation",
    )

    state_source = read_text(ROOT / "hsrd/crates/hns-state/src/lib.rs")
    require_tokens(
        state_source,
        (
            "pub fn is_consensus_invalid(&self)",
            "consensus_invalid_classifier_excludes_local_state_faults",
            "Self::HeaderTreeRootMismatch",
            "Self::MissingCoin",
        ),
        "contextual invalid/local fault separation",
    )

    testkit_source = read_text(ROOT / "hsrd/crates/hns-testkit/src/lib.rs")
    require_tokens(
        testkit_source,
        ("pub blake2b256: String", "DigestMismatch", "blake2b_256(&bytes)"),
        "fixture integrity",
    )


def validate_oracle_revision() -> None:
    package = json.loads((ROOT / "hsd-oracle/package.json").read_text(encoding="utf-8"))
    dependency = package.get("devDependencies", {}).get("hsd")
    if dependency != f"github:{HSD_REPOSITORY}#{HSD_REVISION}":
        fail("hsd-oracle/package.json does not pin the declared hsd revision")

    package_lock = json.loads(
        (ROOT / "hsd-oracle/package-lock.json").read_text(encoding="utf-8")
    )
    root_dependency = (
        package_lock.get("packages", {}).get("", {}).get("devDependencies", {}).get("hsd")
    )
    if root_dependency != dependency:
        fail("hsd-oracle/package-lock.json root dependency does not match package.json")
    resolved = package_lock.get("packages", {}).get("node_modules/hsd", {}).get("resolved", "")
    if not isinstance(resolved, str) or not resolved.endswith(f"#{HSD_REVISION}"):
        fail("hsd-oracle/package-lock.json resolved hsd checkout is not pinned")

    exact_revision_files = [
        ROOT / "hsd-oracle/generate-hsrd-script-fixtures.js",
        ROOT / "hsd-oracle/generate-hsrd-genesis-fixtures.js",
        ROOT / "hsd-oracle/generate-hsrd-airdrop-fixtures.js",
        ROOT / "hsd-oracle/generate-hsrd-claim-fixtures.js",
        ROOT / "hsd-oracle/export-hsrd-mainnet-claim-history.js",
        ROOT / "hsd-oracle/export-hsrd-mainnet-claim-replacements.js",
        ROOT / "hsd-oracle/export-hsrd-mainnet-deployment-history.js",
        ROOT / "hsd-oracle/generate-hsrd-covenant-fixtures.js",
        ROOT / "hsd-oracle/generate-hsrd-name-state-codec-fixtures.js",
        ROOT / "hsd-oracle/generate-hsrd-name-transition-fixtures.js",
        ROOT / "hsd-oracle/generate-hsrd-name-state-urkel-fixtures.js",
        ROOT / "hsd-oracle/generate-hsrd-urkel-proof-fixtures.js",
        ROOT / "hsd-oracle/generate-hsrd-name-policy-fixtures.js",
        ROOT / "hsd-oracle/generate-hsrd-p2p-wire-fixtures.js",
        ROOT / "hsd-oracle/generate-hsrd-mining-template-fixtures.js",
        ROOT / "hsrd/fixtures/hsd/scripts/sighash-v1.json",
        ROOT / "hsrd/fixtures/hsd/blocks/genesis-v1.json",
        ROOT / "hsrd/fixtures/hsd/airdrops/codec-v1.json",
        ROOT / "hsrd/fixtures/hsd/claims/codec-v1.json",
        ROOT / "hsrd/fixtures/hsd/claims/mainnet-history-v1.json",
        ROOT / "hsrd/fixtures/hsd/claims/mainnet-replacements-v1.json",
        ROOT / "hsrd/fixtures/hsd/chains/mainnet-deployment-history-v1.json",
        ROOT / "hsrd/fixtures/hsd/covenants/linkage-v1.json",
        ROOT / "hsrd/fixtures/hsd/name-states/codec-v1.json",
        ROOT / "hsrd/fixtures/hsd/name-states/transitions-v1.json",
        ROOT / "hsrd/fixtures/hsd/name-states/state-urkel-v1.json",
        ROOT / "hsrd/fixtures/hsd/name-states/urkel-proofs-v1.json",
        ROOT / "hsrd/fixtures/hsd/name-states/name-policy-v1.json",
        ROOT / "hsrd/fixtures/hsd/p2p/wire-v1.json",
        ROOT / "hsrd/fixtures/hsd/mining/template-v1.json",
    ]
    for path in exact_revision_files:
        if HSD_REVISION not in read_text(path):
            fail(f"declared oracle revision is missing from {path.relative_to(ROOT)}")

    replacement_exporter = read_text(
        ROOT / "hsd-oracle/export-hsrd-mainnet-claim-replacements.js"
    )
    require_tokens(
        replacement_exporter,
        (
            "const LIFECYCLE_HEIGHTS = [55798, 177097, 178235]",
            "const TERMINAL_HEIGHT = 210237",
            "const CLAIM_PERIOD_HEIGHT = 210240",
        ),
        "mainnet claim lifecycle exporter",
    )

    package_scripts = package.get("scripts", {})
    check_scripts = (
        "hsrd-script-fixtures",
        "hsrd-genesis-fixtures",
        "hsrd-airdrop-fixtures",
        "hsrd-claim-fixtures",
        "hsrd-mainnet-claim-history",
        "hsrd-mainnet-claim-replacements",
        "hsrd-mainnet-deployment-history",
        "hsrd-covenant-fixtures",
        "hsrd-name-state-codec-fixtures",
        "hsrd-name-transition-fixtures",
        "hsrd-name-state-urkel-fixtures",
        "hsrd-urkel-proof-fixtures",
        "hsrd-name-policy-fixtures",
        "hsrd-p2p-wire-fixtures",
        "hsrd-mining-template-fixtures",
    )
    for script in check_scripts:
        command = package_scripts.get(script)
        if not isinstance(command, str) or "--check" not in command:
            fail(f"npm script {script!r} must reproduce and check committed fixtures")


def validate_consensus_boundaries() -> None:
    consensus_source = read_text(ROOT / "hsrd/crates/hns-consensus/src/lib.rs")
    require_tokens(
        consensus_source,
        (
            "verify_transaction_covenant_links",
            "TransactionInputVerifier",
            "NativeAirdropSignatureVerifier",
            "RejectUnverifiedInputs",
            "NativeSignatureVerifier",
            "is_consensus_complete",
            "block_finality_does_not_apply_to_the_coinbase",
            "validate_coinbase_height",
            "coinbase_height_is_a_separate_contextual_commitment",
        ),
        "consensus boundary",
    )

    script_source = read_text(ROOT / "hsrd/crates/hns-consensus/src/script.rs")
    require_tokens(
        script_source,
        (
            "Secp256k1Verifier",
            "SignatureBackendUnavailable",
            "verify_witness_program",
            "count_script_sigops",
            "transaction_sigops",
            "sigop_count_matches_hsd_witness_program_rules",
        ),
        "script authorization",
    )

    full_script_verifier = read_text(
        ROOT
        / "hsrd/crates/hns-consensus/examples/verify_hsd_script_corpus.rs"
    )
    require_tokens(
        full_script_verifier,
        (
            "const HSD_SCRIPT_CASES: usize = 876",
            "oracle.revision != HSD_REVISION",
            "address does not commit to its HSD witness script",
            "count_script_sigops(&script)",
            "full_corpus_rejects_unpinned_oracle_metadata",
            "full_corpus_requires_the_exact_pinned_case_count",
        ),
        "complete HSD script corpus verifier",
    )

    deployment_source = read_text(
        ROOT / "hsrd/crates/hns-consensus/src/deployment.rs"
    )
    require_tokens(
        deployment_source,
        (
            "pub struct HistoricalValidationPlan",
            "HistoricalValidationPlan::hsd_checkpointed()",
            "compute_block_version_from_state",
            "historical_validation_plan_matches_hsd_routes_and_fails_closed",
            "mainnet-block-1-coinbase-finality-exemption",
            "pub coinbase_height: bool",
            "pub block_sigops: bool",
        ),
        "historical deployment validation",
    )

    claim_source = read_text(ROOT / "hsrd/crates/hns-consensus/src/claim.rs")
    gost_source = read_text(ROOT / "hsrd/crates/hns-consensus/src/gost94.rs")
    require_tokens(
        claim_source,
        (
            "digest_type == 3",
            "crate::gost94::digest",
            "ALG_ED448",
            "proof.verify_time(parent_time)",
            "parent block time",
            "native_claim_validation_matches_terminal_and_third_generation_history",
        ),
        "DNSSEC claim cryptography",
    )
    require_tokens(
        gost_source,
        ("S_CRYPTOPRO", "fn compress", "fn psi", "fn add_block"),
        "GOST94 DS digest",
    )

    state_source = read_text(ROOT / "hsrd/crates/hns-state/src/lib.rs")
    ordered_tokens = (
        "verify_transaction_sequence_locks(",
        "transaction_sigops(transaction, &input_coins)",
        "verify_transaction_inputs(",
        "verify_transaction_covenant_links(transaction",
        "apply_transaction_name_covenants(",
        "stage_transaction_spends(",
    )
    positions = [state_source.find(token) for token in ordered_tokens]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        fail(
            "sigop limits, relative locks, input authorization, covenant linkage, "
            "name transitions, and spend staging are not ordered fail-closed"
        )

    require_tokens(
        state_source,
        (
            "DeploymentStateUnavailable",
            "name_flags_valid",
            "rebuild_name_tree_root",
            "rebuild_name_tree_root_with_overrides",
            "verify_stored_name_tree_root",
            "stage_name_tree_with_overrides",
            "prove_persisted_name_tree",
            "validate_persisted_name_tree",
            "validate_persisted_name_trees",
            "validate_persisted_name_tree_root",
            "MetaKey::NameTreeRoot",
            "MetaKey::NameTreeCommitRoot",
            "load_stored_name_tree_commit_root",
            "HeaderTreeRootMismatch",
            "previous_tree_root",
            "resulting_tree_root",
            "previous_committed_tree_root",
            "resulting_committed_tree_root",
            "RejectSpecialCoinbaseIssuance",
            "AirdropCoinbaseIssuanceVerifier",
            "NativeAirdropSignatureVerifier::new()",
            "chain_context.block_time(request.height - 1)?",
            "BlockSigopsExceeded",
            "block_sigop_limit_is_contextual_and_atomic",
            "canonical_mainnet_terminal_and_third_generation_claims_replay",
            "mainnet_2024_open_state_waits_for_tree_interval_commitment",
        ),
        "state transition",
    )

    node_source = read_text(ROOT / "hsrd/crates/hns-node/src/lib.rs")
    require_tokens(
        node_source,
        (
            "AirdropCoinbaseIssuanceVerifier::native(deployments)",
            "validate_coinbase_height(&request.block, request.height)",
            "peer_block_rejects_wrong_coinbase_height_before_storage",
            "strict_mainnet_block_one_keeps_coinbase_finality_and_height_distinct",
        ),
        "active-node contextual verification",
    )

    goosig_source = read_text(ROOT / "hsrd/crates/hns-goosig/src/lib.rs")
    require_tokens(
        goosig_source,
        ("GOO_RSA2048", "goo_create", "goo_verify", "thread_local!"),
        "Goosig verification wrapper",
    )
    for relative in (
        "LICENSE",
        "src/goo/goo.c",
        "src/goo/goo.h",
        "src/goo/mini-gmp.c",
        "src/goo/mini-gmp.h",
        "src/goo/primes.h",
    ):
        if not (ROOT / "hsrd/vendor/goosig" / relative).is_file():
            fail(f"vendored Goosig source is missing {relative}")

    connect_root_check = state_source.find("let inherited_tree_root = load_stored_name_tree_root")
    root_record_check = state_source.find(
        "validate_persisted_name_tree_root(snapshot, inherited_tree_root)"
    )
    commit_root_check = state_source.find(
        "let inherited_committed_tree_root = load_stored_name_tree_commit_root"
    )
    transition_start = state_source.find("for (transaction_index, transaction)")
    if (
        connect_root_check < 0
        or root_record_check < connect_root_check
        or commit_root_check < root_record_check
        or transition_start < commit_root_check
    ):
        fail("block header name-tree commitment is not verified before state mutation")

    if "if state.is_null()" not in state_source or "ColumnFamily::NameState" not in state_source:
        fail("null name states are not deleted from durable authenticated state")

    node_source = read_text(ROOT / "hsrd/crates/hns-node/src/lib.rs")
    require_tokens(
        node_source,
        (
            "verify_stored_name_tree_root(&snapshot)",
            "load_stored_name_tree_commit_root(&snapshot)",
            "validate_persisted_name_trees(",
            ".chain(name_tree_pins.values().map(|pin| pin.root))",
            "status.tree_root_valid = state_summary.validation.tree_root_valid",
            "block.header.tree_root != *undo.previous_committed_tree_root.as_bytes()",
        ),
        "node name-tree binding",
    )

    if re.search(
        r"self\.store\.commit\(batch\)\?;\s*self\.store\.commit\(batch\)\?;",
        node_source,
    ):
        fail("duplicate consecutive store commit expression detected")

    covenant_source = read_text(ROOT / "hsrd/crates/hns-consensus/src/covenant.rs")
    if "hsd/lib/covenants/rules.js::verifyCovenants" not in covenant_source:
        fail("covenant implementation does not identify the exact HSD oracle boundary")
    if "CoinbaseRequiresIssuanceVerifier" not in covenant_source:
        fail("covenant verifier must fail closed on coinbase issuance")

    name_source = read_text(ROOT / "hsrd/crates/hns-consensus/src/name.rs")
    require_tokens(
        name_source,
        (
            "verify_and_apply_name_covenant",
            "is_reserved",
            "is_locked_up",
            "verify_renewal_commitment",
            "CLAIM requires the DNSSEC ownership-proof verifier",
        ),
        "name-state transition",
    )

    urkel_source = read_text(ROOT / "hsrd/crates/hns-urkel/src/lib.rs")
    require_tokens(
        urkel_source,
        (
            "pub struct MemoryUrkel",
            "pub fn root_from_entries",
            "pub enum UrkelNodeRecord",
            "pub struct UrkelRecordUpdate",
            "pub fn update_record_tree",
            "pub fn prove_hsd_from_records",
            "pub fn validate_record_root",
            "pub fn validate_record_tree",
            "pub fn reachable_record_roots",
            "pub struct UnavailableNameTree",
            "pub struct NativeUrkelVerifier",
            "exact_roots_match_the_pinned_hsd_urkel_fixture",
            "exact_proofs_match_the_pinned_hsd_urkel_fixture",
            "record_updates_and_removals_are_path_local_and_history_independent",
            "deterministic_mixed_record_mutations_match_rebuild_oracle",
        ),
        "Urkel foundation",
    )

    require_tokens(
        state_source,
        (
            "pub struct MaterializedNameTreeSnapshot",
            "pub struct NameTreeSnapshotPin",
            "pub struct NameTreeCompactionSummary",
            "pub fn materialize_name_tree_snapshot",
            "pub fn load_name_tree_snapshot_pins",
            "pub fn stage_name_tree_node_compaction",
            "pub fn compact_name_tree_nodes",
            "NAME_TREE_SNAPSHOT_PIN_PREFIX",
            "materialized_name_tree_proofs_are_snapshot_and_restart_stable",
            "persisted_name_tree_proofs_survive_restart_and_reject_node_faults",
            "staged_name_tree_mutation_is_path_local_and_matches_rebuild_oracle",
            "multi_step_overlay_reads_incremental_nodes_and_retains_historical_roots",
            "interval_pins_and_compaction_preserve_only_retained_proof_roots",
            "malformed_snapshot_pin_aborts_compaction_without_deleting_nodes",
            "failed_compaction_commit_preserves_all_nodes",
        ),
        "durable name-tree proofs",
    )

    require_tokens(
        node_source,
        (
            "load_name_tree_snapshot_pins",
            "active interval height",
            "startup_rejects_missing_or_corrupt_name_tree_snapshot_pin",
            "pub struct NameTreeCompactionConfig",
            "pub struct NameTreeCompactionCheckpoint",
            "NAME_TREE_COMPACTION_CHECKPOINT_KEY",
            "compact_name_tree_nodes_if_due",
            "load_name_tree_compaction_checkpoint",
            "startup_name_tree_compaction_is_due_bounded_and_checksummed",
            "startup_name_tree_compaction_survives_unclean_rocksdb_reopen",
        ),
        "durable name-tree snapshot and compaction startup",
    )

    rpc_source = read_text(ROOT / "hsrd/crates/hns-rpc/src/lib.rs")
    require_tokens(
        rpc_source,
        ("pub struct RpcNameTreeCompactionInfo", "pub name_tree_compaction:"),
        "name-tree compaction diagnostics",
    )


def validate_shadow_sync() -> None:
    p2p_root = ROOT / "hsrd/crates/hns-p2p/src"
    sync_root = ROOT / "hsrd/crates/hns-sync/src"
    required_files = (
        p2p_root / "constants.rs",
        p2p_root / "handshake.rs",
        p2p_root / "manager.rs",
        p2p_root / "runtime.rs",
        p2p_root / "wire.rs",
        sync_root / "checkpoint.rs",
        sync_root / "orphan.rs",
        sync_root / "scheduler.rs",
        sync_root / "validation.rs",
        ROOT / "hsrd/crates/hns-node/src/shadow_sync.rs",
        ROOT / "hsrd/docs/p2p-sync.md",
    )
    for path in required_files:
        if not path.is_file():
            fail(f"Shadow sync file is missing: {path.relative_to(ROOT)}")

    p2p_lib = read_text(p2p_root / "lib.rs")
    require_tokens(
        p2p_lib,
        (
            "pub mod constants;",
            "pub mod handshake;",
            "pub mod manager;",
            "pub mod runtime;",
            "pub mod wire;",
            "LivePeerManager",
            "PeerTrafficTotals",
            "MalformedFrame",
            "QueueFull",
        ),
        "Shadow sync P2P composition",
    )

    wire = read_text(p2p_root / "wire.rs")
    require_tokens(
        wire,
        (
            "FRAME_HEADER_SIZE",
            "MAX_FRAME_PAYLOAD_SIZE",
            "decode_hsd_ascii",
            "no_relay = primitive(reader.read_u8())? == 1",
            "hsd_oracle_wire_frames_match_byte_for_byte",
            "../../../fixtures/hsd/p2p/wire-v1.json",
        ),
        "Shadow sync wire compatibility",
    )

    runtime = read_text(p2p_root / "runtime.rs")
    require_tokens(
        runtime,
        (
            "OutboundPriority::Critical",
            "OutboundPriority::Control",
            "OutboundPriority::Normal",
            "handshake_timeout",
            "idle_timeout",
            "pong_timeout",
            "PeerEvent::Ready",
            "let mut frame_read = Box::pin(reader.read_frame());",
            "maintenance_tick_does_not_cancel_a_partial_frame_read",
        ),
        "Shadow sync peer runtime",
    )

    manager = read_text(p2p_root / "manager.rs")
    require_tokens(
        manager,
        (
            "retired_bytes_sent",
            "retired_bytes_received",
            "pub async fn traffic_totals",
            "let final_snapshot = handle.snapshot().await;",
            "atomic_saturating_add",
        ),
        "Shadow sync lifetime traffic accounting",
    )

    sync_lib = read_text(sync_root / "lib.rs")
    require_tokens(
        sync_lib,
        (
            "Synced,",
            "ValidationPipelineClosed",
            "pub mod checkpoint;",
            "pub mod orphan;",
            "pub mod scheduler;",
            "pub mod validation;",
        ),
        "Shadow sync composition",
    )

    validation = read_text(sync_root / "validation.rs")
    require_tokens(
        validation,
        (
            "ValidationFailureKind::InvalidBlock",
            "ValidationFailureKind::InvalidResponse",
            "ValidationFailureKind::WorkerFailure",
            "ValidationRejection::invalid_response",
        ),
        "Shadow sync validation failure classification",
    )

    scheduler = read_text(sync_root / "scheduler.rs")
    require_tokens(
        scheduler,
        (
            "retry_validation_failure",
            "note_block_unavailable",
            "requeue_tracked_block",
            "tracked_blocks",
            "local_validation_failure_retries_without_blaming_peer",
            "bad_validation_response_fails_over_and_blames_only_its_peer",
            "permanent_rejection_removes_pending_descendant",
            "unavailable_block_fails_over_without_blaming_or_reselecting_peer",
            "unsolicited_notfound_cannot_cancel_another_peers_request",
            "body_reservation_survives_validation_and_retry_without_capacity_overflow",
            "late_block_response_is_accepted_during_request_backoff",
            "rollback_header_dispatch",
            "rollback_block_dispatch",
            "expired_block_batch_disconnects_peer_once",
            "progressive_block_batch_uses_an_inactivity_deadline",
            "new_peers_prove_body_availability_before_using_the_full_window",
            "block_request_timeout: Duration::from_secs(120)",
            "headers_request_timeout: Duration::from_secs(60)",
        ),
        "Shadow sync validation, availability, and work-reservation accounting",
    )

    shadow_sync = read_text(ROOT / "hsrd/crates/hns-node/src/shadow_sync.rs")
    require_tokens(
        shadow_sync,
        (
            "native sync live P2P requires disabled, shadow, or native authority mode",
            "MAX_SHADOW_SYNC_PEERS",
            "MAX_SHADOW_SYNC_VALIDATION_WORKERS",
            "MAX_SHADOW_SYNC_VALIDATION_QUEUE",
            "MAX_VALIDATED_BODY_COMMIT_BATCH",
            "state.bytes_received = traffic.bytes_received",
            "MAX_SHADOW_SYNC_ORPHAN_BLOCKS",
            "MAX_SHADOW_SYNC_ORPHAN_BYTES",
            "MAX_KNOWN_PEER_ADDRESSES",
            "MAX_ACTIVE_STATE_CONNECT_BATCH",
            "MAX_ACTIVE_STATE_DIRECT_CONNECT_SLICE",
            "MAX_SHADOW_SYNC_HEADER_IMPORT_SLICE",
            "MIN_SHADOW_SYNC_POLL_INTERVAL",
            "store_validated_alternates",
            "shadow_sync_store_validated_blocks",
            "shadow_sync_queue_missing_canonical_bodies",
            "note_block_unavailable",
            "requeue_tracked_block",
            "spawn_validation_pipeline",
            "stored_failed_bodies",
            "discard_orphan_descendants",
            "shadow_sync_connect_stored_state",
            "connect_stored_active_state",
            "contextual_failed_bodies",
            "body_validator_only_marks_header_committed_invalidity_permanent",
            "canonical_body_queue_is_bounded_to_orphan_horizon",
            "resolve_hsd_dns_seeds",
            "fill_discovery_slots",
            "Packet::Addr(items)",
            "discovery_uses_pinned_hsd_key_bearing_seeds",
            "addr_exchange_requires_v3_and_serves_one_inbound_request",
            "bounded_address_book_applies_hsd_admission_and_eviction_rules",
            "failed_discovery_targets_rotate_without_displacing_configured_peers",
            "if parent_available || canonical",
            "canonical_body_is_stored_out_of_parent_body_order",
            "validated_body_batch_is_all_or_nothing_before_durable_commit",
            "out_of_order_canonical_body_survives_rocksdb_reopen",
            "maximum_header_packet_imports_as_one_durable_batch",
            "shadow_header_slice_validation_is_atomic",
            "canonical_headers_derive_hsd_deployment_and_script_policy",
            "batch_sync_actions",
            "Packet::GetData(inventory)",
            "dispatch_failure_is_stale",
            "block_download_actions_batch_by_peer_without_crossing_action_boundaries",
            "headers_only: shadow_sync_config.headers_only",
            "PersistCheckpoint",
            "observation_only: !shadow_sync_config.connect_active_state",
            "runtime_instance: runtime_instance_id()",
            "/api/v1/native-sync",
            "handle_shadow_sync_diagnostics",
            '"/api/v1/header-deployments"',
            "handle_header_deployments",
            '"/api/v1/mining-engine"',
            "handle_mining_engine_diagnostics",
        ),
        "Native sync node supervisor",
    )
    if "submit_mining_candidate" in shadow_sync:
        fail("Shadow sync path contains a mining-authority entrypoint")

    comparison = read_text(ROOT / "scripts/compare-hsrd-hsd-shadow.py")
    require_tokens(
        comparison,
        (
            "MINIMUM_HSRD_API_VERSION = 9",
            "probe_header_once",
            "compare_header_deployments",
            '"deployments-script-policy"',
            "active_state_resulting_root",
            'root_source = "next-header"',
            'root_source = "next-template"',
            "root_confirmed_by_next_header",
            "previous_still_canonical",
            "hsrd_restart_observed",
            "validate_hsd_source",
            "observation_id",
            "checkpoint_id",
            "write_evidence_state",
            "--allow-remote-hsrd",
            "--self-test",
        ),
        "live hsrd/HSD shadow comparison",
    )

    node_lib = read_text(ROOT / "hsrd/crates/hns-node/src/lib.rs")
    require_tokens(
        node_lib,
        (
            "mod shadow_sync;",
            "NativeSyncConfig, NativeSyncDiagnostics",
            "pub shadow_sync: ShadowSyncConfig",
            "run_shadow_sync_until_shutdown",
            "validate_prevalidated_shadow_import",
            "StatelessBodyValidation",
            "require_parent_body",
            "shadow_active_state_direct_progress_yields_between_small_atomic_slices",
            "shadow_active_state_reorg_keeps_the_full_configured_atomic_bound",
        ),
        "Native sync node integration",
    )

    main_source = read_text(ROOT / "hsrd/crates/hns-node/src/main.rs")
    require_tokens(
        main_source,
        (
            "native_sync: bool",
            "native_sync_headers_only: bool",
            "native_sync_observe_only: bool",
            "p2p_discovery: bool",
            "maximum_known_addresses: usize",
            "active_state_connect_batch: usize",
            "native_sync_poll_ms: u64",
            "compact_name_tree_on_startup: bool",
            "name_tree_compaction_interval: u32",
            "mining_engine: bool",
            "p2p_listen: Option<SocketAddr>",
            'long = "connect"',
            "validation_workers: usize",
            "orphan_bytes: usize",
        ),
        "Native sync CLI",
    )
    for stale_option in ("config_file", "metrics_bind"):
        if stale_option in main_source:
            fail(f"hsrd CLI retains unused option field {stale_option!r}")



def validate_mining_engine() -> None:
    required_files = (
        ROOT / "hsrd/crates/hns-mining/src/template.rs",
        ROOT / "hsrd/crates/hns-mining/src/publication.rs",
        ROOT / "hsrd/crates/hns-node/src/mining_engine.rs",
        ROOT / "hsrd/docs/mining-engine.md",
    )
    for path in required_files:
        if not path.is_file():
            fail(f"Mining engine file is missing: {path.relative_to(ROOT)}")

    mining_oracle = read_text(
        ROOT / "hsd-oracle/generate-hsrd-mining-template-fixtures.js"
    )
    require_tokens(
        mining_oracle,
        (
            "policy.MAX_TX_SIGOPS",
            "policy.BYTES_PER_SIGOP",
            "tx.getSigopsSize(sigops)",
            "policy.getMinFee(policySize, rate)",
        ),
        "HSD mining and mempool policy oracle",
    )

    mempool = read_text(ROOT / "hsrd/crates/hns-mempool/src/lib.rs")
    require_tokens(
        mempool,
        (
            "pub struct MempoolLimits",
            "pub struct MempoolSnapshot",
            "pub fn submit_with_context",
            "pub const MAX_TX_SIGOPS",
            "pub fn sigop_adjusted_virtual_size",
            "pub fn minimum_policy_fee",
            "transaction_sigops(&transaction, &input_coins)",
            "bad-txns-too-many-sigops",
            "native_sigop_accounting_enforces_hsd_transaction_policy",
            "sigop_adjusted_policy_size_sets_minimum_relay_fee",
            "consensus-verifier-incomplete",
            "orphan-capacity",
            "pub fn remove_confirmed",
            "pub fn clear(&mut self)",
            "package_for",
            "maximum_ancestors",
            "maximum_descendants",
        ),
        "Mining engine mempool",
    )
    submit_start = mempool.find("fn submit_checked")
    submit_end = mempool.find("fn promote_orphans", submit_start)
    if submit_start < 0 or submit_end < 0:
        fail("Mining engine mempool admission boundary is missing")
    admission = mempool[submit_start:submit_end]
    ordered_admission = (
        "verify_sequence_locks(",
        "transaction_sigops(&transaction, &input_coins)",
        "input_verifier.verify_input",
        "verify_transaction_covenant_links",
        "contextual_verifier.verify",
    )
    admission_positions = [admission.find(token) for token in ordered_admission]
    if any(position < 0 for position in admission_positions) or admission_positions != sorted(
        admission_positions
    ):
        fail(
            "Mempool relative locks, sigops, authorization, covenant linkage, and "
            "contextual validation are not ordered fail-closed"
        )

    template = read_text(ROOT / "hsrd/crates/hns-mining/src/template.rs")
    require_tokens(
        template,
        (
            "pub struct TemplatePolicy",
            "pub struct TemplateCoordinator",
            "pub struct TemplateVariant",
            "pub struct FutureTemplateCache",
            "snapshot.next_tree_root",
            "minimum_package_fee_rate",
            "package.policy_size",
            "package_ranking_uses_hsd_sigop_size_but_block_fit_uses_weight",
            "block_merkle_root",
            "block_witness_root",
            "../../../fixtures/hsd/mining/template-v1.json",
        ),
        "Mining template engine",
    )

    publication = read_text(ROOT / "hsrd/crates/hns-mining/src/publication.rs")
    require_tokens(
        publication,
        (
            "pub struct SolvedBlockPublicationIntent",
            "PUBLICATION_KEY_PREFIX",
            "PUBLICATION_INTENT_VERSION",
            "blake2b_256(&payload)",
            "candidate.block().header.verify_pow()",
        ),
        "Mining engine publication intent",
    )

    mining_engine = read_text(ROOT / "hsrd/crates/hns-node/src/mining_engine.rs")
    require_tokens(
        mining_engine,
        (
            "pub struct MiningEngineConfig",
            "pub struct MiningEngineDiagnostics",
            "pub struct MiningTemplateRequest",
            "pub struct MiningPublicationAttempt",
            "pub struct MiningPublicationResult",
            "mining_engine_rebuild_templates",
            "mining_engine_prepare_cached_job",
            "mining_engine_reconcile_connected_transactions",
            "mining_engine_reconcile_chain_transition",
            "mining_engine_stage_publication",
            "mining_engine_retry_pending_publications",
            "mining_engine_locally_accepted_record",
            "publication_pending",
            "local_admission_warning",
            "mining_engine_locally_accepted_record(intent.block_hash)?",
            "issue_authority_permit",
        ),
        "Mining engine node composition",
    )
    publish_start = mining_engine.find("pub async fn mining_engine_publish_solved_candidate")
    publish_end = mining_engine.find("fn mining_engine_locally_accepted_record", publish_start)
    if publish_start < 0 or publish_end < publish_start:
        fail("Mining engine solved-candidate publication method is missing")
    publish_body = mining_engine[publish_start:publish_end]
    connect_position = publish_body.find("self.submit_mining_candidate")
    fanout_position = publish_body.find("broadcast_critical_parallel")
    if connect_position < 0 or fanout_position < 0 or connect_position > fanout_position:
        fail("Mining engine broadcasts a solved block before local candidate admission")

    manager = read_text(ROOT / "hsrd/crates/hns-p2p/src/manager.rs")
    require_tokens(
        manager,
        (
            "broadcast_critical_parallel",
            "JoinSet::new",
            "complete the socket write",
        ),
        "Mining engine critical fan-out",
    )

    runtime = read_text(ROOT / "hsrd/crates/hns-p2p/src/runtime.rs")
    require_tokens(
        runtime,
        (
            "struct CriticalOutbound",
            "oneshot::channel",
            "completion_rx.await",
            "completion.send(Ok(()))",
            "critical_completion_waits_for_peer_writer_socket_write",
        ),
        "Mining engine critical writer completion",
    )

    node = read_text(ROOT / "hsrd/crates/hns-node/src/lib.rs")
    require_tokens(
        node,
        (
            "mod mining_engine;",
            "pub mining_engine: MiningEngineConfig",
            "mining_engine_templates: Mutex<TemplateCoordinator>",
            "mining_engine_publish_mempool_reconciled",
            '"/api/v1/mining-engine"',
        ),
        "Mining engine node integration",
    )

    rpc = read_text(ROOT / "hsrd/crates/hns-rpc/src/lib.rs")
    require_tokens(
        rpc,
        (
            "pub network_active: bool",
            '"networkactive": self.snapshot.network_active',
            "getpeerinfo requires the live peer diagnostics service",
        ),
        "Mining engine RPC truthfulness",
    )

    shadow_sync = read_text(ROOT / "hsrd/crates/hns-node/src/shadow_sync.rs")
    require_tokens(
        shadow_sync,
        (
            "Packet::Tx(transaction)",
            "Packet::Mempool",
            "mining_engine_accept_peer_transaction",
            "mining_engine_mempool_inventory",
        ),
        "Mining engine transaction relay integration",
    )


def validate_native_performance() -> None:
    sampler_path = ROOT / "scripts/measure-hsrd-native-sync.py"
    gate_path = ROOT / "hsrd/crates/hns-node/src/bin/hsrd_performance_gate.rs"
    documentation_path = ROOT / "hsrd/docs/performance.md"
    for path in (sampler_path, gate_path, documentation_path):
        if not path.is_file():
            fail(f"Native performance file is missing: {path.relative_to(ROOT)}")

    sampler = read_text(sampler_path)
    require_tokens(
        sampler,
        (
            'SCHEMA = 1',
            "/api/v1/native-sync",
            '"runtime_instance"',
            '"interval_rates_per_second"',
            '"active_stall_intervals"',
            '"minimum_ready_peers"',
            '"zero_ready_peer_samples"',
            'payload.get("bytes_received")',
            '"failure_count"',
            '"unavailable_evidence"',
            '--allow-remote-hsrd',
            '--self-test',
        ),
        "Native mainnet performance sampler",
    )

    gate = read_text(gate_path)
    require_tokens(
        gate,
        (
            "WARMUP_BLOCKS: usize = 10",
            "MEASURED_BLOCKS: usize = 100",
            "TIP_TO_JOB_P99_TARGET_MICROS",
            "CANDIDATE_VALIDATION_P99_TARGET_MICROS",
            "LOCAL_CONNECT_P99_TARGET_MICROS",
            "canonical_regtest_genesis",
            "mining_engine_build_template",
            "mining_engine_prepare_cached_job",
            "admit_solution",
            "NodeBlockImport::from_mining_candidate",
            'println!("failure_count=0")',
            'println!("unavailable_evidence=0")',
        ),
        "Native mining-path performance gate",
    )

    documentation = read_text(documentation_path)
    require_tokens(
        documentation,
        (
            "measure-hsrd-native-sync.py",
            "hsrd-performance-gate",
            "47.667 blocks/s",
            "3,015 us",
            "not a full-mainnet IBD completion claim",
        ),
        "Native performance evidence",
    )


def validate_mainnet_canary_deployment() -> None:
    service_path = ROOT / "hsrd/deploy/meshmine-hsrd-mainnet-canary.service"
    documentation_path = ROOT / "hsrd/docs/mainnet-canary.md"
    if not service_path.is_file():
        fail(f"Mainnet canary service is missing: {service_path.relative_to(ROOT)}")

    service = read_text(service_path)
    require_tokens(
        service,
        (
            "--authority-mode native --mainnet-canary --native-sync",
            "--rpc-bind 127.0.0.1:12047",
            "Restart=on-failure",
            "KillSignal=SIGTERM",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "ReadWritePaths=%h/.local/share/hsrd/mainnet-canary",
        ),
        "Native mainnet canary service",
    )
    documentation = read_text(documentation_path)
    require_tokens(
        documentation,
        (
            "meshmine-hsrd-mainnet-canary.service",
            "systemctl --user enable --now",
            "delivers SIGTERM for a clean checkpoint",
        ),
        "Native mainnet canary deployment documentation",
    )
    node = read_text(ROOT / "hsrd/crates/hns-node/src/lib.rs")
    require_tokens(
        node,
        ("SignalKind::terminate()", "SIGTERM shutdown stream closed unexpectedly"),
        "Native mainnet canary shutdown handling",
    )


def main() -> None:
    parse_metadata()
    validate_component_naming()
    validate_fixture_manifest()
    validate_authority_safety()
    validate_schema_coordination()
    validate_oracle_revision()
    validate_consensus_boundaries()
    validate_shadow_sync()
    validate_mining_engine()
    validate_native_performance()
    validate_mainnet_canary_deployment()
    print("hsrd static validation passed")


if __name__ == "__main__":
    main()
