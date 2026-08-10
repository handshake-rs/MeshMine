#!/usr/bin/env python3
"""Verify MeshMine's release-sensitive Git inputs are immutable and coherent."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]

SOURCES = {
    "hns-node-rs": {
        "url": "https://github.com/handshake-rs/hns-node-rs.git",
        "revision": "9ed129f30c8cd8cd8a07c6872aa4ac40ece5d23b",
        "manifest": ROOT / "crates" / "meshmine-hsrd-bridge" / "Cargo.toml",
        "direct": {"hns-consensus", "hns-mining", "hns-node", "hns-primitives"},
    },
    "hns-rs": {
        "url": "https://github.com/handshake-rs/hns-rs.git",
        "revision": "b24b66c382de53330ec21dd3137e056a2bea3e2d",
        "manifest": ROOT / "bins" / "meshmine-operatord" / "Cargo.toml",
        "direct": {"hns-hnsr-protocol", "hns-service-authority"},
    },
}


def fail(message: str) -> NoReturn:
    print(f"release-source validation failed: {message}", file=sys.stderr)
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
    lock = load_toml(ROOT / "Cargo.lock")
    packages = lock.get("package")
    if not isinstance(packages, list):
        fail("Cargo.lock has no package list")

    for label, policy in SOURCES.items():
        manifest_path = policy["manifest"]
        manifest = load_toml(manifest_path)
        dependencies = manifest.get("dependencies")
        if not isinstance(dependencies, dict):
            fail(f"{manifest_path.relative_to(ROOT)} has no dependency table")

        url = policy["url"]
        revision = policy["revision"]
        for name in sorted(policy["direct"]):
            dependency = dependencies.get(name)
            if not isinstance(dependency, dict):
                fail(f"{manifest_path.relative_to(ROOT)} lacks table dependency {name}")
            if dependency.get("git") != url or dependency.get("rev") != revision:
                fail(f"{name} is not pinned to {label} revision {revision}")
            if "path" in dependency or "branch" in dependency or "tag" in dependency:
                fail(f"{name} retains a mutable or local source selector")

        prefix = f"git+{url}"
        expected = f"{prefix}?rev={revision}#{revision}"
        resolved = [
            (package.get("name"), package.get("source"))
            for package in packages
            if isinstance(package, dict)
            and isinstance(package.get("source"), str)
            and package["source"].startswith(prefix)
        ]
        resolved_names = {name for name, _source in resolved}
        missing = sorted(policy["direct"] - resolved_names)
        if missing:
            fail(f"Cargo.lock omits {label} packages: {', '.join(missing)}")
        mismatched = sorted(
            name for name, source in resolved if source != expected
        )
        if mismatched:
            fail(
                f"Cargo.lock mixes {label} revisions for: {', '.join(mismatched)}"
            )

    print("release-source pin validation passed")


if __name__ == "__main__":
    main()
