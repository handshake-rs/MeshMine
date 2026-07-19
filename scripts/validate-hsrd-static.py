#!/usr/bin/env python3
"""Fail-fast static integrity checks for the pre-authority hsrd workspace.

The checks deliberately avoid compiling Rust. They validate repository metadata,
fixture provenance, schema coordination, and authority-safety invariants before
CI starts native builds. They complement, but never replace, rustfmt, Clippy,
Cargo tests, fuzzing, historical replay, or live differential validation.
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
EXPECTED_STORE_SCHEMA = 5
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

    required = {
        "phase2-sighash-v1",
        "phase2-sequence-locks-v1",
        "phase3-covenant-linkage-v1",
    }
    missing = sorted(required - seen_ids)
    if missing:
        fail(f"fixture manifest is missing required phase cases: {', '.join(missing)}")


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

    if ".covenants_context_valid = true" in production_source:
        fail("production node path prematurely marks contextual covenants valid")
    if ".name_state_valid = true" in production_source:
        fail("production node path prematurely marks name-state transitions valid")
    if ".tree_root_valid = true" in production_source:
        fail("production node path prematurely marks the Urkel tree root valid")
    if ".claims_valid = true" in production_source:
        fail("production node path prematurely marks claims/airdrops valid")
    if ".covenant_links_valid = true" not in production_source:
        fail("production state-connect path does not record covenant-linkage completion")

    required_tokens = (
        'AuthorityMode::Shadow',
        'AuthorityMode::NativeExperimental',
        'feature = "experimental-authority"',
        'acknowledge_incomplete_consensus',
    )
    for token in required_tokens:
        if token not in node_source:
            fail(f"authority safety token {token!r} is missing from hns-node")


def validate_schema_coordination() -> None:
    store_source = read_text(ROOT / "hsrd/crates/hns-store/src/lib.rs")
    match = re.search(r"pub const SCHEMA_VERSION:\s*u32\s*=\s*(\d+)\s*;", store_source)
    if not match:
        fail("cannot find hns-store SCHEMA_VERSION")
    actual = int(match.group(1))
    if actual != EXPECTED_STORE_SCHEMA:
        fail(
            f"hns-store schema must be {EXPECTED_STORE_SCHEMA} after Phase 3, got {actual}"
        )

    chain_source = read_text(ROOT / "hsrd/crates/hns-chain/src/lib.rs")
    for token in (
        "covenant_links_valid",
        "covenants_context_valid",
        "COVENANT_LINKS_VALID",
        "COVENANTS_CONTEXT_VALID",
        "plan_reorg_between",
        "MissingBestHeaderBinding",
        "record.chainwork > best.chainwork",
    ):
        if token not in chain_source:
            fail(f"chain/status safety token {token!r} is missing")

    for token in (
        'pub const STORAGE_PROFILE: &[u8] = b"hsrd-mining-v1"',
        "pub enum DurabilityPolicy",
        "options.disable_wal(false)",
        "RocksSnapshot<'a>",
        "snapshot: rocksdb::Snapshot<'a>",
        "pub struct StagingOverlay",
    ):
        if token not in store_source:
            fail(f"Phase 3 storage token {token!r} is missing")

    node_source = read_text(ROOT / "hsrd/crates/hns-node/src/lib.rs")
    for token in (
        "store_validated_alternate",
        "best_chain_activation_plan",
        "validate_reorg_plan",
        "validate_reorg_request_shape",
        "stage_best_header_if_more_work",
        "next_chain_epoch",
        "validate_durable_chain_invariants",
        "replacement tip chainwork",
    ):
        if token not in node_source:
            fail(f"Phase 3 best-chain token {token!r} is missing")

    testkit_source = read_text(ROOT / "hsrd/crates/hns-testkit/src/lib.rs")
    for token in ("pub blake2b256: String", "DigestMismatch", "blake2b_256(&bytes)"):
        if token not in testkit_source:
            fail(f"fixture integrity token {token!r} is missing from hns-testkit")


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
    resolved = (
        package_lock.get("packages", {})
        .get("node_modules/hsd", {})
        .get("resolved", "")
    )
    if not isinstance(resolved, str) or not resolved.endswith(f"#{HSD_REVISION}"):
        fail("hsd-oracle/package-lock.json resolved hsd checkout is not pinned")

    exact_revision_files = [
        ROOT / "hsd-oracle/generate-hsrd-phase2-fixtures.js",
        ROOT / "hsd-oracle/generate-hsrd-phase3-fixtures.js",
        ROOT / "hsrd/fixtures/hsd/scripts/sighash-v1.json",
        ROOT / "hsrd/fixtures/hsd/covenants/linkage-v1.json",
    ]
    for path in exact_revision_files:
        if HSD_REVISION not in read_text(path):
            fail(f"declared oracle revision is missing from {path.relative_to(ROOT)}")

    package_scripts = package.get("scripts", {})
    for script in ("hsrd-phase2-fixtures", "hsrd-phase3-fixtures"):
        command = package_scripts.get(script)
        if not isinstance(command, str) or "--check" not in command:
            fail(f"npm script {script!r} must reproduce and check committed fixtures")


def validate_phase_boundaries() -> None:
    consensus_source = read_text(ROOT / "hsrd/crates/hns-consensus/src/lib.rs")
    for token in (
        "verify_transaction_covenant_links",
        "TransactionInputVerifier",
        "RejectUnverifiedInputs",
    ):
        if token not in consensus_source:
            fail(f"Phase 2/3 consensus boundary {token!r} is missing")

    state_source = read_text(ROOT / "hsrd/crates/hns-state/src/lib.rs")
    linkage_position = state_source.find("verify_transaction_covenant_links(transaction")
    stage_position = state_source.find("stage_transaction_spends(")
    if linkage_position < 0 or stage_position < 0 or linkage_position > stage_position:
        fail("covenant linkage must complete before transaction spends are staged")

    covenant_source = read_text(ROOT / "hsrd/crates/hns-consensus/src/covenant.rs")
    if "hsd/lib/covenants/rules.js::verifyCovenants" not in covenant_source:
        fail("Phase 3 implementation does not identify the exact HSD oracle boundary")
    if "CoinbaseRequiresIssuanceVerifier" not in covenant_source:
        fail("Phase 3 covenant verifier must fail closed on coinbase issuance")


def main() -> None:
    parse_metadata()
    validate_fixture_manifest()
    validate_authority_safety()
    validate_schema_coordination()
    validate_oracle_revision()
    validate_phase_boundaries()
    print("hsrd static validation passed")


if __name__ == "__main__":
    main()
