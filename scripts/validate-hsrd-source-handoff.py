#!/usr/bin/env python3
"""Offline structural checks for an hsrd source handoff.

This validator is intentionally compiler-independent. It checks the nested
workspace's direct dependency lock coverage, path dependencies, and Rust source
lexical balance. It complements `validate-hsrd-static.py`; neither script is a
substitute for rustfmt, Clippy, Cargo tests, or historical consensus replay.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT / "hsrd"
SKIP_PARTS = {".git", "node_modules", "target", "__pycache__"}


def fail(message: str) -> NoReturn:
    print(f"hsrd source handoff validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_toml(path: Path) -> dict:
    try:
        with path.open("rb") as file:
            return tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot parse {path.relative_to(ROOT)}: {error}")


def workspace_manifests() -> list[Path]:
    root = load_toml(WORKSPACE / "Cargo.toml")
    members = root.get("workspace", {}).get("members")
    if not isinstance(members, list) or not members:
        fail("hsrd workspace has no members")

    manifests: list[Path] = []
    for member in members:
        if not isinstance(member, str) or not member:
            fail("hsrd workspace contains an invalid member")
        manifest = WORKSPACE / member / "Cargo.toml"
        if not manifest.is_file():
            fail(f"workspace member manifest is missing: {manifest.relative_to(ROOT)}")
        manifests.append(manifest)
    return manifests


def validate_lock_coverage(manifests: list[Path]) -> None:
    lock = load_toml(WORKSPACE / "Cargo.lock")
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        fail("hsrd/Cargo.lock contains no packages")
    locked_names = {
        package.get("name")
        for package in packages
        if isinstance(package, dict) and isinstance(package.get("name"), str)
    }

    missing: list[str] = []
    for manifest in manifests:
        data = load_toml(manifest)
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            dependencies = data.get(section, {})
            if not isinstance(dependencies, dict):
                fail(f"{manifest.relative_to(ROOT)} has a non-table {section}")
            for alias, specification in dependencies.items():
                package_name = alias
                if isinstance(specification, dict):
                    renamed = specification.get("package")
                    if isinstance(renamed, str):
                        package_name = renamed
                    path = specification.get("path")
                    if isinstance(path, str):
                        target = (manifest.parent / path / "Cargo.toml").resolve()
                        if not target.is_file():
                            fail(
                                f"path dependency {alias!r} from "
                                f"{manifest.relative_to(ROOT)} is missing"
                            )
                if package_name not in locked_names:
                    missing.append(
                        f"{manifest.relative_to(ROOT)}:{section}:{package_name}"
                    )

    if missing:
        fail("direct dependencies missing from hsrd/Cargo.lock: " + ", ".join(missing))


def rust_files() -> list[Path]:
    files = []
    for path in WORKSPACE.rglob("*.rs"):
        if not any(part in SKIP_PARTS for part in path.parts):
            files.append(path)
    if not files:
        fail("no Rust source files found under hsrd")
    return sorted(files)


def looks_like_char_literal(source: str, start: int) -> bool:
    """Distinguish short Rust char literals from lifetimes such as `'a`."""
    index = start + 1
    if index >= len(source) or source[index] in "\r\n":
        return False
    if source[index] == "\\":
        index += 1
        if index >= len(source):
            return False
        if source[index] == "u" and index + 1 < len(source) and source[index + 1] == "{":
            end = source.find("}", index + 2, min(len(source), index + 12))
            return end >= 0 and end + 1 < len(source) and source[end + 1] == "'"
        index += 1
    else:
        index += 1
    return index < len(source) and source[index] == "'"


def raw_string_start(source: str, index: int) -> tuple[int, str] | None:
    """Return `(body_start, terminator)` for r/br raw strings."""
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


def validate_rust_lexically(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    stack: list[tuple[str, int]] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    line = 1
    index = 0
    block_comment_depth = 0
    state = "normal"
    raw_terminator = ""

    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""

        if char == "\n":
            line += 1

        if state == "line-comment":
            if char == "\n":
                state = "normal"
            index += 1
            continue

        if state == "block-comment":
            if char == "/" and next_char == "*":
                block_comment_depth += 1
                index += 2
                continue
            if char == "*" and next_char == "/":
                block_comment_depth -= 1
                index += 2
                if block_comment_depth == 0:
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

        if state == "raw-string":
            if source.startswith(raw_terminator, index):
                index += len(raw_terminator)
                state = "normal"
                raw_terminator = ""
            else:
                index += 1
            continue

        if char == "/" and next_char == "/":
            state = "line-comment"
            index += 2
            continue
        if char == "/" and next_char == "*":
            state = "block-comment"
            block_comment_depth = 1
            index += 2
            continue

        raw = raw_string_start(source, index)
        if raw is not None:
            index, raw_terminator = raw
            state = "raw-string"
            continue

        if char == '"' or (char == "b" and next_char == '"'):
            if char == "b":
                index += 1
            state = "string"
            index += 1
            continue
        if char == "'" and looks_like_char_literal(source, index):
            state = "char"
            index += 1
            continue
        if char == "b" and next_char == "'" and looks_like_char_literal(source, index + 1):
            index += 1
            state = "char"
            index += 1
            continue

        if char in "([{":
            stack.append((char, line))
        elif char in ")]}":
            if not stack or stack[-1][0] != pairs[char]:
                fail(
                    f"unmatched {char!r} at {path.relative_to(ROOT)}:{line}"
                )
            stack.pop()
        index += 1

    if state == "block-comment":
        fail(f"unterminated block comment in {path.relative_to(ROOT)}")
    if state in {"string", "char", "raw-string"}:
        fail(f"unterminated {state} in {path.relative_to(ROOT)}")
    if stack:
        delimiter, opening_line = stack[-1]
        fail(
            f"unclosed {delimiter!r} from {path.relative_to(ROOT)}:{opening_line}"
        )


def main() -> None:
    manifests = workspace_manifests()
    validate_lock_coverage(manifests)
    files = rust_files()
    for path in files:
        validate_rust_lexically(path)
    print(
        f"hsrd source handoff validation passed "
        f"({len(manifests)} crates, {len(files)} Rust files)"
    )


if __name__ == "__main__":
    main()
