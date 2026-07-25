#!/usr/bin/env python3
"""Compare normalized retained-horizon transitions from stopped hsrd and HSD.

An already-qualified full-state anchor inside the common transcript makes
exact transitions sufficient to prove every disconnect and reconnect state in
the retained horizon without mutating either database.
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
MAX_MANIFEST_BYTES = 256 * 1024 * 1024
HEX_32 = re.compile(r"^[0-9a-f]{64}$")
HEX_BYTES = re.compile(r"^(?:[0-9a-f]{2})+$")
EXPECTED_HSD_REVISION = "698e252ebc7b5c1dd0a9587e342fdd153d020ae4"


class ComparisonError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    print(f"compare-hsrd-hsd-rollback-manifests: {message}", file=sys.stderr)
    raise SystemExit(2)


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ComparisonError(f"{label} must be an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ComparisonError(f"{label} must be an array")
    return value


def require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ComparisonError(f"{label} must be a non-negative integer")
    return value


def require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ComparisonError(f"{label} must be a boolean")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComparisonError(f"{label} must be a non-empty string")
    return value


def require_hash(value: Any, label: str) -> str:
    value = require_string(value, label)
    if not HEX_32.fullmatch(value):
        raise ComparisonError(f"{label} must be a lowercase 32-byte hex value")
    return value


def require_bytes(value: Any, label: str) -> str:
    value = require_string(value, label)
    if not HEX_BYTES.fullmatch(value):
        raise ComparisonError(f"{label} must be non-empty lowercase byte hex")
    return value


def optional_bytes(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return require_bytes(value, label)


def load_json(path: Path, maximum: int = MAX_MANIFEST_BYTES) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ComparisonError(f"failed to read {path}: {exc}") from exc
    if len(raw) > maximum:
        raise ComparisonError(f"{path} exceeds {maximum} bytes")
    try:
        value = require_object(json.loads(raw), str(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ComparisonError(f"{path} is not valid JSON: {exc}") from exc
    return value, hashlib.sha256(raw).hexdigest()


def normalize_coin(value: Any, label: str) -> dict[str, str]:
    coin = require_object(value, label)
    outpoint = require_bytes(coin.get("outpoint"), f"{label} outpoint")
    if len(outpoint) != 72:
        raise ComparisonError(f"{label} outpoint must encode exactly 36 bytes")
    raw = require_bytes(coin.get("coin"), f"{label} coin")
    if not raw.startswith(outpoint):
        raise ComparisonError(f"{label} coin is not bound to its outpoint")
    return {"outpoint": outpoint, "coin": raw}


def normalize_name(value: Any, label: str) -> dict[str, Any]:
    name = require_object(value, label)
    return {
        "name_hash": require_hash(name.get("name_hash"), f"{label} hash"),
        "before": optional_bytes(name.get("before"), f"{label} before state"),
        "after": optional_bytes(name.get("after"), f"{label} after state"),
    }


def require_strictly_sorted(
    values: list[dict[str, Any]], key: str, label: str
) -> None:
    keys = [value[key] for value in values]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise ComparisonError(f"{label} must be strictly sorted by {key}")


def normalize_transition(value: Any, producer: str, expected_height: int) -> dict[str, Any]:
    label = f"{producer} transition {expected_height}"
    record = require_object(value, label)
    height = require_int(record.get("height"), f"{label} height")
    if height != expected_height:
        raise ComparisonError(
            f"{producer} transition height {height} is not contiguous at {expected_height}"
        )
    roots = require_object(record.get("roots"), f"{label} roots")
    spent = [
        normalize_coin(item, f"{label} spent coin {index}")
        for index, item in enumerate(
            require_list(record.get("spent_coins"), f"{label} spent coins")
        )
    ]
    created = [
        normalize_coin(item, f"{label} created coin {index}")
        for index, item in enumerate(
            require_list(record.get("created_coins"), f"{label} created coins")
        )
    ]
    names = [
        normalize_name(item, f"{label} name {index}")
        for index, item in enumerate(
            require_list(record.get("names"), f"{label} names")
        )
    ]
    require_strictly_sorted(spent, "outpoint", f"{label} spent coins")
    require_strictly_sorted(created, "outpoint", f"{label} created coins")
    require_strictly_sorted(names, "name_hash", f"{label} names")
    positions = [
        require_int(position, f"{label} airdrop position {index}")
        for index, position in enumerate(
            require_list(
                record.get("airdrop_positions"), f"{label} airdrop positions"
            )
        )
    ]
    if positions != sorted(positions) or len(positions) != len(set(positions)):
        raise ComparisonError(f"{label} airdrop positions must be strictly sorted")
    return {
        "height": height,
        "block_hash": require_hash(record.get("block_hash"), f"{label} block hash"),
        "previous_block_hash": require_hash(
            record.get("previous_block_hash"), f"{label} previous block hash"
        ),
        "raw_block_size": require_int(
            record.get("raw_block_size"), f"{label} raw block size"
        ),
        "raw_block_digest": require_hash(
            record.get("raw_block_digest"), f"{label} raw block digest"
        ),
        "roots": {
            "previous_committed": require_hash(
                roots.get("previous_committed"), f"{label} previous committed root"
            ),
            "resulting_committed": require_hash(
                roots.get("resulting_committed"), f"{label} resulting committed root"
            ),
            "interval_boundary": require_bool(
                roots.get("interval_boundary"), f"{label} interval flag"
            ),
        },
        "spent_coins": spent,
        "created_coins": created,
        "airdrop_positions": positions,
        "names": names,
    }


def normalize_manifest(
    manifest: dict[str, Any], expected_producer: str
) -> dict[str, Any]:
    if require_int(manifest.get("schema_version"), "schema_version") != SCHEMA_VERSION:
        raise ComparisonError("unsupported rollback-manifest schema")
    producer = require_string(manifest.get("producer"), "producer")
    if producer != expected_producer:
        raise ComparisonError(
            f"expected {expected_producer} manifest, got producer {producer!r}"
        )
    if producer == "hsd":
        revision = require_string(manifest.get("oracle_revision"), "HSD revision")
        if revision != EXPECTED_HSD_REVISION:
            raise ComparisonError(f"unexpected HSD revision {revision}")
    network = require_string(manifest.get("network"), f"{producer} network")
    if network != "mainnet":
        raise ComparisonError(f"unsupported {producer} network {network!r}")
    source_height = require_int(
        manifest.get("source_height"), f"{producer} source height"
    )
    first_height = require_int(
        manifest.get("first_height"), f"{producer} first height"
    )
    keep_blocks = require_int(
        manifest.get("keep_blocks"), f"{producer} keep blocks"
    )
    tree_interval = require_int(
        manifest.get("tree_interval"), f"{producer} tree interval"
    )
    source_airdrop_field_size = require_int(
        manifest.get("source_airdrop_field_size"),
        f"{producer} source airdrop field size",
    )
    source_airdrop_field_digest = require_hash(
        manifest.get("source_airdrop_field_digest"),
        f"{producer} source airdrop field digest",
    )
    source_airdrop_spent = require_int(
        manifest.get("source_airdrop_spent"),
        f"{producer} source airdrop spent count",
    )
    if first_height < 1 or first_height > source_height:
        raise ComparisonError(f"{producer} retained horizon is invalid")
    if source_height - first_height + 1 != keep_blocks:
        raise ComparisonError(
            f"{producer} transcript does not cover its complete retained horizon"
        )
    records_raw = require_list(manifest.get("records"), f"{producer} records")
    if len(records_raw) != keep_blocks:
        raise ComparisonError(
            f"{producer} has {len(records_raw)} records, expected {keep_blocks}"
        )
    records = [
        normalize_transition(record, producer, first_height + offset)
        for offset, record in enumerate(records_raw)
    ]
    for previous, current in zip(records, records[1:]):
        if current["previous_block_hash"] != previous["block_hash"]:
            raise ComparisonError(
                f"{producer} transcript is disconnected at height {current['height']}"
            )
    source_hash = require_hash(
        manifest.get("source_block_hash"), f"{producer} source block hash"
    )
    if records[-1]["block_hash"] != source_hash:
        raise ComparisonError(f"{producer} source hash does not match final record")
    return {
        "network": network,
        "source_height": source_height,
        "source_block_hash": source_hash,
        "first_height": first_height,
        "keep_blocks": keep_blocks,
        "tree_interval": tree_interval,
        "source_airdrop_field_size": source_airdrop_field_size,
        "source_airdrop_field_digest": source_airdrop_field_digest,
        "source_airdrop_spent": source_airdrop_spent,
        "records": records,
    }


def first_difference(left: Any, right: Any, path: str = "") -> dict[str, Any] | None:
    if type(left) is not type(right):
        return {"path": path, "hsrd": type(left).__name__, "hsd": type(right).__name__}
    if isinstance(left, dict):
        if left.keys() != right.keys():
            return {
                "path": path,
                "hsrd_keys": sorted(left),
                "hsd_keys": sorted(right),
            }
        for key in left:
            found = first_difference(left[key], right[key], f"{path}.{key}".lstrip("."))
            if found:
                return found
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return {"path": path, "hsrd_length": len(left), "hsd_length": len(right)}
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            found = first_difference(
                left_item, right_item, f"{path}[{index}]"
            )
            if found:
                return found
        return None
    if left != right:
        def shorten(value: Any) -> Any:
            if isinstance(value, str) and len(value) > 160:
                return value[:157] + "..."
            return value

        return {"path": path, "hsrd": shorten(left), "hsd": shorten(right)}
    return None


def require_anchor(
    qualification: dict[str, Any], transcript: dict[str, Any]
) -> dict[str, Any]:
    if qualification.get("result") != "pass":
        raise ComparisonError("anchor qualification did not pass")
    if qualification.get("qualification") != "mainnet-historical-replay-stopped-state":
        raise ComparisonError("anchor has an unexpected qualification type")
    if qualification.get("historical_replay_readiness_promoted") is not False:
        raise ComparisonError("anchor readiness state is not the expected pre-rollback state")
    anchor_height = require_int(qualification.get("height"), "anchor height")
    anchor_hash = require_hash(qualification.get("block_hash"), "anchor block hash")
    if not transcript["first_height"] <= anchor_height <= transcript["source_height"]:
        raise ComparisonError("full-state anchor is outside the retained transcript")
    record = transcript["records"][anchor_height - transcript["first_height"]]
    if record["block_hash"] != anchor_hash:
        raise ComparisonError("full-state anchor hash is not on the transcript")
    stopped = require_object(
        qualification.get("stopped_state_comparison"), "anchor stopped comparison"
    )
    if stopped.get("status") != "pass" or stopped.get("all_comparisons_matched") is not True:
        raise ComparisonError("anchor stopped-state comparison is not a complete pass")
    deployment = require_object(
        qualification.get("pinned_deployment_comparison"),
        "anchor deployment comparison",
    )
    if deployment.get("status") != "pass":
        raise ComparisonError("anchor deployment comparison did not pass")
    return {"height": anchor_height, "block_hash": anchor_hash}


def compare(
    hsrd_manifest: dict[str, Any],
    hsd_manifest: dict[str, Any],
    qualification: dict[str, Any],
    hsrd_sha256: str,
    hsd_sha256: str,
    anchor_sha256: str,
) -> dict[str, Any]:
    hsrd = normalize_manifest(hsrd_manifest, "hsrd")
    hsd = normalize_manifest(hsd_manifest, "hsd")
    metadata_fields = [
        "network",
        "source_height",
        "source_block_hash",
        "first_height",
        "keep_blocks",
        "tree_interval",
        "source_airdrop_field_size",
        "source_airdrop_field_digest",
        "source_airdrop_spent",
    ]
    metadata = {field: hsrd[field] == hsd[field] for field in metadata_fields}
    metadata_mismatches = [field for field, matched in metadata.items() if not matched]
    if metadata_mismatches:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "mismatch",
            "metadata_comparisons": metadata,
            "mismatches": metadata_mismatches,
            "inputs": {
                "hsrd_manifest_sha256": hsrd_sha256,
                "hsd_manifest_sha256": hsd_sha256,
                "anchor_qualification_sha256": anchor_sha256,
            },
        }

    anchor = require_anchor(qualification, hsrd)
    difference = first_difference(hsrd["records"], hsd["records"], "records")
    counts = {
        "blocks": len(hsrd["records"]),
        "spent_coins": sum(len(record["spent_coins"]) for record in hsrd["records"]),
        "created_coins": sum(
            len(record["created_coins"]) for record in hsrd["records"]
        ),
        "name_transitions": sum(len(record["names"]) for record in hsrd["records"]),
        "airdrop_positions": sum(
            len(record["airdrop_positions"]) for record in hsrd["records"]
        ),
        "interval_boundaries": sum(
            record["roots"]["interval_boundary"] for record in hsrd["records"]
        ),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "pass" if difference is None else "mismatch",
        "network": hsrd["network"],
        "first_height": hsrd["first_height"],
        "height": hsrd["source_height"],
        "block_hash": hsrd["source_block_hash"],
        "anchor": anchor,
        "metadata_comparisons": metadata,
        "transition_counts": counts,
        "comparisons": {
            "raw_active_blocks": difference is None,
            "committed_root_transitions": difference is None,
            "spent_coin_resurrections": difference is None,
            "created_coin_removals": difference is None,
            "airdrop_bit_reversions": difference is None,
            "full_name_state_reversions": difference is None,
            "disconnect_transitions": difference is None,
            "reconnect_transitions": difference is None,
        },
        "first_mismatch": difference,
        "proof": {
            "method": "full-state anchor plus exact normalized bidirectional transitions",
            "database_mutation": False,
            "disconnect": "inverse transition from the anchor toward the horizon floor",
            "reconnect": "forward transition from the horizon floor through the anchor to the tip",
        },
        "inputs": {
            "hsrd_manifest_sha256": hsrd_sha256,
            "hsd_manifest_sha256": hsd_sha256,
            "anchor_qualification_sha256": anchor_sha256,
        },
    }


def self_test() -> None:
    hashes = {
        "six": "06" * 32,
        "seven": "07" * 32,
        "eight": "08" * 32,
        "root": "11" * 32,
        "next_root": "12" * 32,
        "raw": "13" * 32,
        "name": "14" * 32,
    }
    outpoint = "15" * 32 + "01000000"
    records = [
        {
            "height": 7,
            "block_hash": hashes["seven"],
            "previous_block_hash": hashes["six"],
            "raw_block_size": 100,
            "raw_block_digest": hashes["raw"],
            "roots": {
                "previous_committed": hashes["root"],
                "resulting_committed": hashes["root"],
                "interval_boundary": False,
            },
            "spent_coins": [{"outpoint": outpoint, "coin": outpoint + "00"}],
            "created_coins": [],
            "airdrop_positions": [],
            "names": [
                {
                    "name_hash": hashes["name"],
                    "before": None,
                    "after": "00",
                }
            ],
        },
        {
            "height": 8,
            "block_hash": hashes["eight"],
            "previous_block_hash": hashes["seven"],
            "raw_block_size": 101,
            "raw_block_digest": hashes["raw"],
            "roots": {
                "previous_committed": hashes["root"],
                "resulting_committed": hashes["next_root"],
                "interval_boundary": True,
            },
            "spent_coins": [],
            "created_coins": [{"outpoint": outpoint, "coin": outpoint + "00"}],
            "airdrop_positions": [3],
            "names": [],
        },
    ]
    base = {
        "schema_version": 1,
        "network": "mainnet",
        "source_height": 8,
        "source_block_hash": hashes["eight"],
        "first_height": 7,
        "keep_blocks": 2,
        "tree_interval": 2,
        "source_airdrop_field_size": 4,
        "source_airdrop_field_digest": "16" * 32,
        "source_airdrop_spent": 1,
        "records": records,
    }
    hsrd = {**copy.deepcopy(base), "producer": "hsrd"}
    hsd = {
        **copy.deepcopy(base),
        "producer": "hsd",
        "oracle_revision": EXPECTED_HSD_REVISION,
    }
    qualification = {
        "qualification": "mainnet-historical-replay-stopped-state",
        "result": "pass",
        "height": 7,
        "block_hash": hashes["seven"],
        "historical_replay_readiness_promoted": False,
        "stopped_state_comparison": {
            "status": "pass",
            "all_comparisons_matched": True,
        },
        "pinned_deployment_comparison": {"status": "pass"},
    }
    evidence = compare(hsrd, hsd, qualification, "aa", "bb", "cc")
    assert evidence["status"] == "pass"
    hsd["records"][1]["airdrop_positions"] = [4]
    evidence = compare(hsrd, hsd, qualification, "aa", "bb", "cc")
    assert evidence["status"] == "mismatch"
    assert evidence["first_mismatch"]["path"].endswith("airdrop_positions[0]")
    print(json.dumps({"ok": True}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hsrd-manifest", type=Path)
    parser.add_argument("--hsd-manifest", type=Path)
    parser.add_argument("--anchor-qualification", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
        return
    if (
        arguments.hsrd_manifest is None
        or arguments.hsd_manifest is None
        or arguments.anchor_qualification is None
    ):
        fail(
            "--hsrd-manifest, --hsd-manifest, and --anchor-qualification "
            "are required"
        )
    try:
        hsrd, hsrd_sha256 = load_json(arguments.hsrd_manifest)
        hsd, hsd_sha256 = load_json(arguments.hsd_manifest)
        qualification, anchor_sha256 = load_json(
            arguments.anchor_qualification, maximum=4 * 1024 * 1024
        )
        evidence = compare(
            hsrd,
            hsd,
            qualification,
            hsrd_sha256,
            hsd_sha256,
            anchor_sha256,
        )
    except ComparisonError as exc:
        fail(str(exc))
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        print(rendered, end="")
    else:
        arguments.output.write_text(rendered)
    if evidence["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
