#!/usr/bin/env python3
"""Validate the private workspace identity used by release candidates."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> NoReturn:
    print(f"release-metadata validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_toml(path: Path) -> dict:
    try:
        value = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read {path.relative_to(ROOT)}: {error}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} is not a TOML table")
    return value


def main() -> None:
    root = load_toml(ROOT / "Cargo.toml")
    workspace = root.get("workspace")
    if not isinstance(workspace, dict):
        fail("Cargo.toml has no workspace table")
    package = workspace.get("package")
    members = workspace.get("members")
    if not isinstance(package, dict) or not isinstance(members, list):
        fail("Cargo.toml has incomplete workspace metadata")

    version = package.get("version")
    rust_version = package.get("rust-version")
    if not isinstance(version, str) or re.fullmatch(r"0\.[0-9]+\.[0-9]+", version) is None:
        fail("workspace version must be an explicit pre-1.0 semantic version")
    if package.get("license") != "MIT":
        fail("workspace license must remain MIT")
    if package.get("publish") is not False:
        fail("workspace packages must remain private until release policy changes explicitly")
    if not isinstance(rust_version, str):
        fail("workspace rust-version is missing")

    toolchain = load_toml(ROOT / "rust-toolchain.toml").get("toolchain")
    if not isinstance(toolchain, dict) or toolchain.get("channel") != rust_version:
        fail("rust-toolchain channel and workspace rust-version differ")
    if set(toolchain.get("components", [])) != {"clippy", "rustfmt"}:
        fail("release toolchain must include clippy and rustfmt")

    license_text = (ROOT / "LICENSE-MIT").read_text()
    if not license_text.startswith("MIT License\n") or "Permission is hereby granted" not in license_text:
        fail("LICENSE-MIT is missing the canonical MIT grant")

    package_names: set[str] = set()
    inherited = {key: {"workspace": True} for key in (
        "version", "edition", "license", "rust-version", "publish"
    )}
    for member in members:
        if not isinstance(member, str):
            fail("workspace member is not a string")
        manifest_path = ROOT / member / "Cargo.toml"
        member_package = load_toml(manifest_path).get("package")
        if not isinstance(member_package, dict):
            fail(f"{manifest_path.relative_to(ROOT)} has no package table")
        name = member_package.get("name")
        if not isinstance(name, str) or name in package_names:
            fail(f"{manifest_path.relative_to(ROOT)} has a missing or duplicate package name")
        package_names.add(name)
        for key, expected in inherited.items():
            if member_package.get(key) != expected:
                fail(f"{manifest_path.relative_to(ROOT)} does not inherit package.{key}")

    lock_packages = load_toml(ROOT / "Cargo.lock").get("package")
    if not isinstance(lock_packages, list):
        fail("Cargo.lock has no package list")
    local_versions = {
        entry.get("name"): entry.get("version")
        for entry in lock_packages
        if isinstance(entry, dict)
        and entry.get("name") in package_names
        and "source" not in entry
    }
    missing = sorted(package_names - local_versions.keys())
    if missing:
        fail("Cargo.lock omits workspace packages: " + ", ".join(missing))
    wrong = sorted(name for name, locked in local_versions.items() if locked != version)
    if wrong:
        fail("Cargo.lock has mixed workspace versions: " + ", ".join(wrong))

    print(
        f"release-metadata validation passed ({len(package_names)} packages at {version})"
    )


if __name__ == "__main__":
    main()
