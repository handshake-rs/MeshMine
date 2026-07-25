#!/usr/bin/env python3
"""Verify that MeshMine consumes only the standalone Rust node at runtime.

The historical ``hsrd`` source tree remains excluded from this Cargo
workspace.  It may retain qualification fixtures, but no MeshMine package may
resolve an HNS runtime dependency from that tree.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_NODE = (ROOT.parent / "hns-node-rs").resolve()
EMBEDDED_NODE = (ROOT / "hsrd").resolve()
BRIDGE = (ROOT / "crates" / "meshmine-hsrd-bridge" / "Cargo.toml").resolve()
REQUIRED_NODE_CRATES = {
    "hns-consensus",
    "hns-mining",
    "hns-node",
    "hns-primitives",
}


def fail(message: str) -> NoReturn:
    print(f"external-node boundary validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def cargo_metadata() -> dict:
    try:
        completed = subprocess.run(
            [
                "cargo",
                "metadata",
                "--locked",
                "--offline",
                "--no-deps",
                "--format-version",
                "1",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        value = json.loads(completed.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        details = getattr(error, "stderr", "") or str(error)
        fail(f"cargo metadata failed: {details.strip()}")
    if not isinstance(value, dict):
        fail("cargo metadata was not an object")
    return value


def main() -> None:
    if not (EXTERNAL_NODE / "Cargo.toml").is_file():
        fail(f"standalone node workspace is missing at {EXTERNAL_NODE}")

    metadata = cargo_metadata()
    packages = metadata.get("packages")
    members = metadata.get("workspace_members")
    if not isinstance(packages, list) or not isinstance(members, list):
        fail("cargo metadata omitted packages or workspace members")

    by_id = {
        package.get("id"): package
        for package in packages
        if isinstance(package, dict) and isinstance(package.get("id"), str)
    }
    for member_id in members:
        package = by_id.get(member_id)
        if package is None:
            fail(f"workspace member {member_id!r} has no package record")
        manifest = Path(package["manifest_path"]).resolve()
        if is_within(manifest, EMBEDDED_NODE):
            fail(f"embedded hsrd package became a workspace member: {manifest}")

    bridge = next(
        (
            package
            for package in packages
            if Path(package.get("manifest_path", "")).resolve() == BRIDGE
        ),
        None,
    )
    if bridge is None:
        fail("meshmine-hsrd-bridge is absent from the main workspace")

    dependencies = bridge.get("dependencies")
    if not isinstance(dependencies, list):
        fail("bridge dependency metadata is malformed")
    node_dependencies = {
        dependency.get("name"): Path(dependency["path"]).resolve()
        for dependency in dependencies
        if isinstance(dependency, dict)
        and dependency.get("name") in REQUIRED_NODE_CRATES
        and isinstance(dependency.get("path"), str)
    }
    missing = sorted(REQUIRED_NODE_CRATES - node_dependencies.keys())
    if missing:
        fail("bridge lacks standalone path dependencies: " + ", ".join(missing))
    for name, path in sorted(node_dependencies.items()):
        expected = EXTERNAL_NODE / "crates" / name
        if path != expected:
            fail(f"{name} resolves to {path}, expected {expected}")
        if is_within(path, EMBEDDED_NODE):
            fail(f"{name} still resolves through embedded hsrd")

    for package in packages:
        manifest = Path(package.get("manifest_path", "")).resolve()
        if not is_within(manifest, ROOT):
            continue
        for dependency in package.get("dependencies", []):
            path_text = dependency.get("path") if isinstance(dependency, dict) else None
            if isinstance(path_text, str) and is_within(Path(path_text).resolve(), EMBEDDED_NODE):
                fail(
                    f"{manifest.relative_to(ROOT)} retains embedded runtime dependency "
                    f"{dependency.get('name')}"
                )

    print("external-node boundary validation passed")


if __name__ == "__main__":
    main()
