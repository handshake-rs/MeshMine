#!/usr/bin/env python3
"""Offline structural validation for the portable MeshMine work fabric.

This check is compiler-independent. It validates main-workspace lock coverage,
local path dependencies, source lexical balance, and critical fail-closed work
coordination invariants. Cargo/rustfmt/Clippy remain mandatory release gates.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", "node_modules", "target", "__pycache__", "hsrd"}


def fail(message: str) -> NoReturn:
    print(f"work-fabric source validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_toml(path: Path) -> dict:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse {path.relative_to(ROOT)}: {error}")


def manifests() -> list[Path]:
    root = load_toml(ROOT / "Cargo.toml")
    members = root.get("workspace", {}).get("members")
    if not isinstance(members, list) or not members:
        fail("main workspace contains no members")
    output = []
    for member in members:
        if not isinstance(member, str):
            fail("workspace member is not a string")
        manifest = ROOT / member / "Cargo.toml"
        if not manifest.is_file():
            fail(f"missing workspace manifest {manifest.relative_to(ROOT)}")
        output.append(manifest)
    return output


def validate_lock(manifest_paths: list[Path]) -> None:
    lock = load_toml(ROOT / "Cargo.lock")
    packages = lock.get("package")
    if not isinstance(packages, list):
        fail("Cargo.lock contains no package list")
    locked = {
        package.get("name")
        for package in packages
        if isinstance(package, dict) and isinstance(package.get("name"), str)
    }
    missing = []
    for manifest in manifest_paths:
        data = load_toml(manifest)
        package = data.get("package", {})
        name = package.get("name")
        if not isinstance(name, str) or name not in locked:
            missing.append(f"workspace package:{manifest.relative_to(ROOT)}")
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                fail(f"{manifest.relative_to(ROOT)} has invalid {section}")
            for alias, spec in deps.items():
                dependency = alias
                if isinstance(spec, dict):
                    if isinstance(spec.get("package"), str):
                        dependency = spec["package"]
                    if isinstance(spec.get("path"), str):
                        target = (manifest.parent / spec["path"] / "Cargo.toml").resolve()
                        if not target.is_file():
                            fail(
                                f"missing path dependency {alias!r} from "
                                f"{manifest.relative_to(ROOT)}"
                            )
                if dependency not in locked:
                    missing.append(
                        f"{manifest.relative_to(ROOT)}:{section}:{dependency}"
                    )
    if missing:
        fail("missing lockfile coverage: " + ", ".join(missing))


def raw_string_start(source: str, index: int) -> tuple[int, str] | None:
    cursor = index
    if source.startswith("br", cursor) or source.startswith("rb", cursor):
        cursor += 2
    elif source.startswith("r", cursor):
        cursor += 1
    else:
        return None
    hashes = 0
    while cursor < len(source) and source[cursor] == "#":
        hashes += 1
        cursor += 1
    if cursor >= len(source) or source[cursor] != '"':
        return None
    return cursor + 1, '"' + ("#" * hashes)


def char_literal(source: str, start: int) -> bool:
    cursor = start + 1
    if cursor >= len(source) or source[cursor] in "\r\n":
        return False
    if source[cursor] == "\\":
        cursor += 2
    else:
        cursor += 1
    return cursor < len(source) and source[cursor] == "'"


def validate_rust(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    stack: list[tuple[str, int]] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    state = "normal"
    raw_end = ""
    block_depth = 0
    line = 1
    index = 0
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if char == "\n":
            line += 1
        if state == "line":
            if char == "\n":
                state = "normal"
            index += 1
            continue
        if state == "block":
            if char == "/" and next_char == "*":
                block_depth += 1
                index += 2
                continue
            if char == "*" and next_char == "/":
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "normal"
                continue
            index += 1
            continue
        if state in {"string", "char"}:
            delimiter = '"' if state == "string" else "'"
            if char == "\\":
                index += 2
                continue
            if char == delimiter:
                state = "normal"
            index += 1
            continue
        if state == "raw":
            if source.startswith(raw_end, index):
                index += len(raw_end)
                state = "normal"
            else:
                index += 1
            continue
        if char == "/" and next_char == "/":
            state = "line"
            index += 2
            continue
        if char == "/" and next_char == "*":
            state = "block"
            block_depth = 1
            index += 2
            continue
        raw = raw_string_start(source, index)
        if raw is not None:
            index, raw_end = raw
            state = "raw"
            continue
        if char == '"' or (char == "b" and next_char == '"'):
            if char == "b":
                index += 1
            state = "string"
            index += 1
            continue
        if char == "'" and char_literal(source, index):
            state = "char"
            index += 1
            continue
        if char == "b" and next_char == "'" and char_literal(source, index + 1):
            index += 2
            state = "char"
            continue
        if char in "([{":
            stack.append((char, line))
        elif char in ")]}":
            if not stack or stack[-1][0] != pairs[char]:
                fail(f"unmatched {char!r} at {path.relative_to(ROOT)}:{line}")
            stack.pop()
        index += 1
    if state in {"block", "string", "char", "raw"}:
        fail(f"unterminated {state} in {path.relative_to(ROOT)}")
    if stack:
        delimiter, opening_line = stack[-1]
        fail(f"unclosed {delimiter!r} at {path.relative_to(ROOT)}:{opening_line}")


def validate_invariants() -> None:
    work = ROOT / "crates" / "meshmine-work" / "src"
    required = {
        "backend.rs": [
            "pub trait MiningBackend",
            "pub struct HandyStratumBackend",
            "RangeCompleted",
        ],
        "planner.rs": [
            "apply_batch_if_all",
            "EXCLUSIVE_NAMESPACE",
            "encode_exhausted_cursor",
            "InvalidExpiration",
            "same_static_contract",
            "selected_steps.saturating_mul(stride)",
        ],
        "coordinator.rs": [
            "admit_capture",
            "CAPTURE_TOMBSTONE_NAMESPACE",
            "header.share_hash()",
            "prepare_generation",
            "activate_generation",
            "CoordinatorLimits",
            "recover_backend",
            "maximum_events_per_poll",
        ],
        "lease.rs": [
            "lease expands beyond its signed assignment envelope",
            "GatewayAssignmentV1",
            "AssignmentV2",
        ],
        "target.rs": [
            "capture_target",
            "device_minimum_target",
            "maximum_edge_target",
            "desired_submission_interval_ms",
        ],
        "record.rs": [
            "WORK_SCHEMA_VERSION: u16 = 2",
            "MESHMINE/WORK_CAPTURE/V2",
            "CAPTURE_TOMBSTONE_NAMESPACE",
        ],
    }
    for name, needles in required.items():
        path = work / name
        if not path.is_file():
            fail(f"missing work-fabric source {path.relative_to(ROOT)}")
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                fail(f"{path.relative_to(ROOT)} is missing invariant marker {needle!r}")

    gateway = (ROOT / "crates" / "meshmine-gateway" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    for needle in (
        "submit_authorized_lease",
        "drain_captures_durably",
        "DurableCaptureConsumer",
        ".expires_at_ms",
        "lease.edge_target.0 > assignment.edge_target.0",
    ):
        if needle not in gateway:
            fail(f"gateway integration is missing {needle}")


def validate_capture_identity() -> None:
    path = ROOT / "crates" / "meshmine-work" / "src" / "record.rs"
    text = path.read_text(encoding="utf-8")
    start = text.find("impl CaptureRecord")
    if start < 0:
        fail("capture record implementation is missing")
    end = text.find("impl CanonicalEncode for CaptureRecord", start)
    if end < 0:
        fail("capture record canonical encoder is missing")
    identity = text[start:end]
    if "received_at_ms" in identity:
        fail("stable capture identity includes local receipt time")

    documentation = ROOT / "docs" / "work-fabric.md"
    if not documentation.is_file():
        fail("missing work-fabric documentation")
    docs = documentation.read_text(encoding="utf-8")
    for needle in (
        "signed assignment envelope",
        "Stock HandyStratum ASICs",
        "Downstream failure",
        "Current limitations",
    ):
        if needle not in docs:
            fail(f"work-fabric documentation is missing {needle!r}")


def main() -> None:
    manifest_paths = manifests()
    validate_lock(manifest_paths)
    rust_files = [
        path
        for path in ROOT.rglob("*.rs")
        if not any(part in SKIP for part in path.relative_to(ROOT).parts)
    ]
    if not rust_files:
        fail("no main-workspace Rust files found")
    for path in sorted(rust_files):
        validate_rust(path)
    validate_invariants()
    validate_capture_identity()
    print(
        "work-fabric source validation passed "
        f"({len(manifest_paths)} crates, {len(rust_files)} Rust files)"
    )


if __name__ == "__main__":
    main()
