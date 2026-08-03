#!/usr/bin/env python3
"""Verify that MeshMine consumes only the standalone Rust node at runtime."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
EMBEDDED_NODE = (ROOT / "hsrd").resolve()
BRIDGE = (ROOT / "crates" / "meshmine-hsrd-bridge" / "Cargo.toml").resolve()
EXPECTED_NODE_REVISION = "3d346e3dadc716b5c367eee050308e71a0693a64"
EXPECTED_NODE_DEPENDENCY_SOURCE = (
    "git+https://github.com/handshake-rs/hns-node-rs.git"
    f"?rev={EXPECTED_NODE_REVISION}"
)
EXPECTED_NODE_RESOLVED_SOURCE = (
    f"{EXPECTED_NODE_DEPENDENCY_SOURCE}#{EXPECTED_NODE_REVISION}"
)
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
        dependency.get("name"): dependency
        for dependency in dependencies
        if isinstance(dependency, dict)
        and dependency.get("name") in REQUIRED_NODE_CRATES
    }
    missing = sorted(REQUIRED_NODE_CRATES - node_dependencies.keys())
    if missing:
        fail("bridge lacks standalone node dependencies: " + ", ".join(missing))
    for name, dependency in sorted(node_dependencies.items()):
        source = dependency.get("source")
        if source != EXPECTED_NODE_DEPENDENCY_SOURCE:
            fail(
                f"{name} resolves from {source!r}, expected "
                f"{EXPECTED_NODE_DEPENDENCY_SOURCE!r}"
            )
        if dependency.get("path") is not None:
            fail(f"{name} retains a mutable path override")

    resolved_node_packages = {
        package.get("name")
        for package in packages
        if isinstance(package, dict)
        and package.get("name") in REQUIRED_NODE_CRATES
        and package.get("source") == EXPECTED_NODE_RESOLVED_SOURCE
    }
    unresolved = sorted(REQUIRED_NODE_CRATES - resolved_node_packages)
    if unresolved:
        fail(
            "lock graph does not resolve the exact canonical node revision: "
            + ", ".join(unresolved)
        )

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
