#!/usr/bin/env python3
"""Assemble the bounded, nonpublishing MeshMine evaluation candidate."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "meshmine-private-evaluation-v1"
SUPPORTED_TARGET = "x86_64-unknown-linux-gnu"
BINARIES = (
    "meshmine-cored",
    "meshmine-corelink-operatord",
    "meshmine-operatord",
)
PAYLOADS = {
    "LICENSE-MIT": "LICENSE-MIT",
    "README.md": "README.md",
    "Cargo.toml": "provenance/Cargo.toml",
    "Cargo.lock": "provenance/Cargo.lock",
    "docs/private-candidate-artifact.md": "docs/private-candidate-artifact.md",
    "docs/release-readiness.md": "docs/release-readiness.md",
    "docs/external-node-boundary.md": "docs/external-node-boundary.md",
    "docs/core-link.md": "docs/core-link.md",
    "docs/operator-service.md": "docs/operator-service.md",
    "docs/multi-operator-daemon.md": "docs/multi-operator-daemon.md",
    "specs/pool-stats-profile.md": "docs/pool-stats-profile.md",
    "specs/core-link-core.example.json": "config/core-link-core.example.json",
    "specs/core-link-operator.example.json": "config/core-link-operator.example.json",
    "specs/core-link-parent-oracle.example.json": "config/core-link-parent-oracle.example.json",
    "specs/multi-operator.example.json": "config/multi-operator.example.json",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"private candidate packaging failed: {message}")


def load_toml(path: Path) -> dict:
    try:
        value = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read {path.relative_to(ROOT)}: {error}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} is not a TOML table")
    return value


def source_revision(manifest_path: str, dependencies: tuple[str, ...]) -> str:
    manifest = load_toml(ROOT / manifest_path)
    table = manifest.get("dependencies")
    if not isinstance(table, dict):
        fail(f"{manifest_path} has no dependency table")
    revisions = set()
    for dependency in dependencies:
        value = table.get(dependency)
        if not isinstance(value, dict) or not isinstance(value.get("rev"), str):
            fail(f"{manifest_path} lacks an exact revision for {dependency}")
        revisions.add(value["rev"])
    if len(revisions) != 1:
        fail(f"{manifest_path} mixes revisions for {', '.join(dependencies)}")
    revision = revisions.pop()
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        fail(f"{manifest_path} does not use a full lowercase Git revision")
    return revision


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_exact_source(source_commit: str) -> None:
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=normal"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"cannot verify exact Git source: {error}")
    if head != source_commit:
        fail(f"--source-commit {source_commit} does not match checked-out HEAD {head}")
    if status:
        fail("the checked-out source is dirty; provenance would not identify its contents")


def write_internal_checksums(bundle_root: Path) -> None:
    lines = []
    for path in sorted(item for item in bundle_root.rglob("*") if item.is_file()):
        relative = path.relative_to(bundle_root).as_posix()
        if relative == "SHA256SUMS":
            continue
        lines.append(f"{sha256(path)}  {relative}\n")
    (bundle_root / "SHA256SUMS").write_text("".join(lines))


def normalized_tar_info(tar: tarfile.TarFile, path: Path, arcname: str) -> tarfile.TarInfo:
    info = tar.gettarinfo(str(path), arcname=arcname)
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    if info.isfile():
        info.mode = 0o755 if path.parent.name == "bin" else 0o644
    elif info.isdir():
        info.mode = 0o755
    return info


def write_archive(bundle_root: Path, archive: Path) -> None:
    with archive.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
                paths = [bundle_root, *sorted(bundle_root.rglob("*"))]
                for path in paths:
                    arcname = path.relative_to(bundle_root.parent).as_posix()
                    info = normalized_tar_info(tar, path, arcname)
                    if info.isfile():
                        with path.open("rb") as source:
                            tar.addfile(info, source)
                    else:
                        tar.addfile(info)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--target", required=True)
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    if re.fullmatch(r"[0-9a-f]{40}", arguments.source_commit) is None:
        fail("--source-commit must be a full lowercase Git revision")
    if arguments.target != SUPPORTED_TARGET:
        fail(f"unsupported target {arguments.target!r}; expected {SUPPORTED_TARGET}")
    verify_exact_source(arguments.source_commit)

    root_manifest = load_toml(ROOT / "Cargo.toml")
    version = root_manifest.get("workspace", {}).get("package", {}).get("version")
    if not isinstance(version, str) or re.fullmatch(r"0\.\d+\.\d+", version) is None:
        fail("workspace version is not an explicit pre-1.0 semantic version")

    for binary in BINARIES:
        source = arguments.binary_dir / binary
        if not source.is_file() or not os.access(source, os.X_OK):
            fail(f"missing executable candidate binary: {source}")
    for source_path in PAYLOADS:
        if not (ROOT / source_path).is_file():
            fail(f"missing bundle payload: {source_path}")

    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"meshmine-private-evaluation-{version}-{arguments.target}-{arguments.source_commit[:12]}"
    archive = arguments.output_dir / f"{stem}.tar.gz"
    archive_checksum = arguments.output_dir / f"{archive.name}.sha256"
    if archive.exists() or archive_checksum.exists():
        fail(f"candidate output already exists for {stem}")

    with tempfile.TemporaryDirectory(prefix="meshmine-candidate-", dir=arguments.output_dir) as temporary:
        bundle_root = Path(temporary) / stem
        (bundle_root / "bin").mkdir(parents=True)
        for binary in BINARIES:
            destination = bundle_root / "bin" / binary
            shutil.copyfile(arguments.binary_dir / binary, destination)
            destination.chmod(0o755)
        for source_path, destination_path in PAYLOADS.items():
            destination = bundle_root / destination_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / source_path, destination)
            destination.chmod(0o644)

        provenance = {
            "artifact_contract": CONTRACT,
            "binaries": list(BINARIES),
            "build_runner": "ubuntu-24.04",
            "hns_node_revision": source_revision(
                "crates/meshmine-hsrd-bridge/Cargo.toml",
                ("hns-consensus", "hns-mining", "hns-node", "hns-primitives"),
            ),
            "hns_rs_revision": source_revision(
                "bins/meshmine-operatord/Cargo.toml",
                ("hns-hnsr-protocol", "hns-service-authority"),
            ),
            "production_eligible": False,
            "schema_version": 1,
            "source_commit": arguments.source_commit,
            "source_repository": "https://github.com/handshake-rs/MeshMine",
            "target": arguments.target,
            "version": version,
        }
        (bundle_root / "PROVENANCE.json").write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n"
        )
        write_internal_checksums(bundle_root)
        write_archive(bundle_root, archive)

    archive_checksum.write_text(f"{sha256(archive)}  {archive.name}\n")
    print(archive)
    print(archive_checksum)


if __name__ == "__main__":
    main()
