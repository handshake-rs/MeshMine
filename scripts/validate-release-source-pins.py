#!/usr/bin/env python3
"""Verify MeshMine's release-sensitive Git inputs are immutable and coherent."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
FULL_REVISION = re.compile(r"[0-9a-f]{40}")

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


def dependency_tables(manifest: dict) -> list[dict]:
    output = []
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = manifest.get(key, {})
        if not isinstance(value, dict):
            fail(f"invalid {key} table")
        output.append(value)
    targets = manifest.get("target", {})
    if not isinstance(targets, dict):
        fail("invalid target table")
    for target in targets.values():
        if not isinstance(target, dict):
            fail("invalid target selector table")
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            value = target.get(key, {})
            if not isinstance(value, dict):
                fail(f"invalid target {key} table")
            output.append(value)
    return output


def declared_git_sources() -> set[str]:
    root_manifest = load_toml(ROOT / "Cargo.toml")
    workspace = root_manifest.get("workspace")
    if not isinstance(workspace, dict):
        fail("Cargo.toml has no workspace table")
    members = workspace.get("members")
    workspace_dependencies = workspace.get("dependencies", {})
    if not isinstance(members, list) or not isinstance(workspace_dependencies, dict):
        fail("Cargo.toml has incomplete workspace dependency metadata")
    manifests = [ROOT / "Cargo.toml"]
    manifests.extend(ROOT / member / "Cargo.toml" for member in members)

    expected = set()
    for manifest_path in manifests:
        manifest = load_toml(manifest_path)
        for key in ("patch", "replace"):
            value = manifest.get(key, {})
            if not isinstance(value, dict) or value:
                fail(
                    f"{manifest_path.relative_to(ROOT)} contains a forbidden {key} override"
                )
        tables = dependency_tables(manifest)
        if manifest_path == ROOT / "Cargo.toml":
            tables.append(workspace_dependencies)
        for dependencies in tables:
            for name, dependency in dependencies.items():
                if not isinstance(dependency, dict) or "git" not in dependency:
                    continue
                url = dependency.get("git")
                revision = dependency.get("rev")
                if not isinstance(url, str) or not url.startswith("https://"):
                    fail(
                        f"{manifest_path.relative_to(ROOT)}:{name} uses a non-HTTPS Git source"
                    )
                if not isinstance(revision, str) or FULL_REVISION.fullmatch(revision) is None:
                    fail(
                        f"{manifest_path.relative_to(ROOT)}:{name} lacks a full Git revision"
                    )
                if "path" in dependency or "branch" in dependency or "tag" in dependency:
                    fail(f"{manifest_path.relative_to(ROOT)}:{name} mixes source selectors")
                expected.add(f"git+{url}?rev={revision}#{revision}")
    return expected


def validate_local_cargo_config() -> None:
    for path in (ROOT / ".cargo" / "config.toml", ROOT / ".cargo" / "config"):
        if not path.exists():
            continue
        config = load_toml(path)
        paths = config.get("paths", [])
        sources = config.get("source", {})
        if not isinstance(paths, list) or paths:
            fail(f"{path.relative_to(ROOT)} contains a Cargo path override")
        if not isinstance(sources, dict) or sources:
            fail(f"{path.relative_to(ROOT)} contains a Cargo source override")
        for key in ("patch", "replace"):
            value = config.get(key, {})
            if not isinstance(value, dict) or value:
                fail(f"{path.relative_to(ROOT)} contains a Cargo {key} override")


def main() -> None:
    validate_local_cargo_config()
    lock = load_toml(ROOT / "Cargo.lock")
    packages = lock.get("package")
    if not isinstance(packages, list):
        fail("Cargo.lock has no package list")

    declared = declared_git_sources()
    locked = {
        package.get("source")
        for package in packages
        if isinstance(package, dict)
        and isinstance(package.get("source"), str)
        and package["source"].startswith("git+")
    }
    missing_sources = sorted(declared - locked)
    unexpected_sources = sorted(locked - declared)
    if missing_sources:
        fail("Cargo.lock omits declared Git sources: " + ", ".join(missing_sources))
    if unexpected_sources:
        fail(
            "Cargo.lock contains undeclared Git sources: "
            + ", ".join(unexpected_sources)
        )

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
