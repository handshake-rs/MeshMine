#!/usr/bin/env python3
"""Compare consensus/mining state projections exported by pinned HSD and hsrd.

Producer-native undo encodings are deliberately not equated here. Undo parity
is an operational property and is qualified by the separate rollback campaign.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn

SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
HEX_32 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_PROJECTION = [
    "outpoint",
    "value",
    "height",
    "coinbase",
    "address",
    "covenant",
]
EXPECTED_EXCLUSIONS = ["origin_transaction_version"]
NETWORKS = {"main": "mainnet", "mainnet": "mainnet"}


class ComparisonError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    print(f"compare-hsrd-hsd-state-manifests: {message}", file=sys.stderr)
    raise SystemExit(2)


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ComparisonError(f"{label} must be an object")
    return value


def require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ComparisonError(f"{label} must be a non-negative integer")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComparisonError(f"{label} must be a non-empty string")
    return value


def require_hash(value: Any, label: str) -> str:
    value = require_string(value, label).lower()
    if not HEX_32.fullmatch(value):
        raise ComparisonError(f"{label} must be a lowercase 32-byte hex value")
    return value


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ComparisonError(f"failed to read {path}: {exc}") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ComparisonError(f"{path} exceeds {MAX_MANIFEST_BYTES} bytes")
    try:
        manifest = require_object(json.loads(raw), str(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ComparisonError(f"{path} is not valid JSON: {exc}") from exc
    return manifest, hashlib.sha256(raw).hexdigest()


def normalize(manifest: dict[str, Any], expected_producer: str) -> dict[str, Any]:
    if require_int(manifest.get("schema_version"), "schema_version") != SCHEMA_VERSION:
        raise ComparisonError("unsupported state-manifest schema")
    producer = require_string(manifest.get("producer"), "producer")
    if producer != expected_producer:
        raise ComparisonError(
            f"expected {expected_producer} manifest, got producer {producer!r}"
        )
    network = require_string(manifest.get("network"), f"{producer} network")
    try:
        network = NETWORKS[network]
    except KeyError as exc:
        raise ComparisonError(f"unsupported {producer} network {network!r}") from exc

    components = require_object(manifest.get("components"), f"{producer} components")
    utxo = require_object(components.get("utxo"), f"{producer} UTXO component")
    projection = utxo.get("semantic_projection")
    exclusions = utxo.get("excluded_hsd_archival_fields")
    if projection != EXPECTED_PROJECTION:
        raise ComparisonError(f"{producer} UTXO semantic projection is not canonical")
    if exclusions != EXPECTED_EXCLUSIONS:
        raise ComparisonError(f"{producer} UTXO exclusion declaration is not canonical")

    names = require_object(components.get("names"), f"{producer} name component")
    roots = require_object(components.get("roots"), f"{producer} root component")
    return {
        "network": network,
        "height": require_int(manifest.get("height"), f"{producer} height"),
        "block_hash": require_hash(
            manifest.get("block_hash"), f"{producer} block hash"
        ),
        "genesis_hash": require_hash(
            manifest.get("genesis_hash"), f"{producer} genesis hash"
        ),
        "utxo": {
            "count": require_int(utxo.get("count"), f"{producer} UTXO count"),
            "digest": require_hash(utxo.get("digest"), f"{producer} UTXO digest"),
            "total_value": require_int(
                utxo.get("total_value"), f"{producer} UTXO total"
            ),
        },
        "names": {
            "count": require_int(names.get("count"), f"{producer} name count"),
            "digest": require_hash(names.get("digest"), f"{producer} name digest"),
        },
        "roots": {
            "working": require_hash(
                roots.get("working"), f"{producer} working root"
            ),
            "committed": require_hash(
                roots.get("committed"), f"{producer} committed root"
            ),
        },
    }


def compare(
    hsrd_manifest: dict[str, Any],
    hsd_manifest: dict[str, Any],
    hsrd_sha256: str,
    hsd_sha256: str,
) -> dict[str, Any]:
    hsrd = normalize(hsrd_manifest, "hsrd")
    hsd = normalize(hsd_manifest, "hsd")
    comparisons = {
        "network": hsrd["network"] == hsd["network"],
        "height": hsrd["height"] == hsd["height"],
        "block_hash": hsrd["block_hash"] == hsd["block_hash"],
        "genesis_hash": hsrd["genesis_hash"] == hsd["genesis_hash"],
        "utxo_count": hsrd["utxo"]["count"] == hsd["utxo"]["count"],
        "utxo_digest": hsrd["utxo"]["digest"] == hsd["utxo"]["digest"],
        "utxo_total_value": (
            hsrd["utxo"]["total_value"] == hsd["utxo"]["total_value"]
        ),
        "name_count": hsrd["names"]["count"] == hsd["names"]["count"],
        "name_digest": hsrd["names"]["digest"] == hsd["names"]["digest"],
        "working_name_root": hsrd["roots"]["working"] == hsd["roots"]["working"],
        "committed_name_root": (
            hsrd["roots"]["committed"] == hsd["roots"]["committed"]
        ),
    }
    failures = [name for name, matched in comparisons.items() if not matched]
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "pass" if not failures else "mismatch",
        "height": hsrd["height"],
        "block_hash": hsrd["block_hash"],
        "inputs": {
            "hsrd_manifest_sha256": hsrd_sha256,
            "hsd_manifest_sha256": hsd_sha256,
        },
        "comparisons": comparisons,
        "mismatches": failures,
        "not_qualified_by_manifest_digest": {
            "deployments": "qualified by the pinned live deployment comparison",
            "undo": "requires the cross-implementation rollback campaign",
        },
    }


def self_test() -> None:
    digest = "11" * 32
    root = "22" * 32
    base = {
        "schema_version": 1,
        "network": "mainnet",
        "height": 7,
        "block_hash": "33" * 32,
        "genesis_hash": "44" * 32,
        "components": {
            "utxo": {
                "count": 2,
                "digest": digest,
                "total_value": 5,
                "semantic_projection": EXPECTED_PROJECTION,
                "excluded_hsd_archival_fields": EXPECTED_EXCLUSIONS,
            },
            "names": {"count": 1, "digest": digest},
            "roots": {"working": root, "committed": root},
            "undo": {},
        },
    }
    hsrd = copy.deepcopy({**base, "producer": "hsrd"})
    hsd = copy.deepcopy({**base, "producer": "hsd", "network": "main"})
    evidence = compare(hsrd, hsd, "aa" * 32, "bb" * 32)
    assert evidence["status"] == "pass"
    hsd["components"]["utxo"]["count"] = 3
    evidence = compare(hsrd, hsd, "aa" * 32, "bb" * 32)
    assert evidence["status"] == "mismatch"
    assert evidence["mismatches"] == ["utxo_count"]
    print(json.dumps({"ok": True}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hsrd-manifest", type=Path)
    parser.add_argument("--hsd-manifest", type=Path)
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
        return
    if arguments.hsrd_manifest is None or arguments.hsd_manifest is None:
        fail("--hsrd-manifest and --hsd-manifest are required")
    try:
        hsrd, hsrd_sha256 = load_manifest(arguments.hsrd_manifest)
        hsd, hsd_sha256 = load_manifest(arguments.hsd_manifest)
        evidence = compare(hsrd, hsd, hsrd_sha256, hsd_sha256)
    except ComparisonError as exc:
        fail(str(exc))
    print(json.dumps(evidence, indent=2, sort_keys=True))
    if evidence["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
