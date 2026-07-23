#!/usr/bin/env python3
"""Measure one uninterrupted hsrd native-sync runtime without an HSD process."""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import pathlib
import stat
import tempfile
import time
import urllib.parse
import urllib.request
from typing import Any


SCHEMA = 3
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_AUTHORIZATION_BYTES = 4_096


class MeasurementError(RuntimeError):
    pass


def require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MeasurementError(f"{name} must be a non-negative integer")
    return value


def optional_tip_height(sync: dict[str, Any], name: str) -> int:
    tip = sync.get(name)
    if tip is None:
        return -1
    if not isinstance(tip, dict):
        raise MeasurementError(f"sync.{name} must be an object or null")
    return require_int(tip.get("height"), f"sync.{name}.height")


def read_json(url: str, timeout: float, authorization: str | None = None) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if authorization is not None:
        headers["Authorization"] = authorization
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise MeasurementError("hsrd diagnostics exceed the response-size bound")
    decoded = json.loads(payload)
    if not isinstance(decoded, dict):
        raise MeasurementError("hsrd diagnostics must be a JSON object")
    return decoded


def read_authorization_header(path: pathlib.Path | None) -> str | None:
    if path is None:
        return None
    if not path.is_absolute() or ".." in path.parts:
        raise MeasurementError(
            "--authorization-header-file must be absolute without parent traversal"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_AUTHORIZATION_BYTES:
            raise MeasurementError(
                "authorization header must be a bounded mode-0600 regular file"
            )
        if metadata.st_mode & 0o077:
            raise MeasurementError(
                "authorization header must not be accessible by group or other users"
            )
        raw = os.read(descriptor, MAX_AUTHORIZATION_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_AUTHORIZATION_BYTES:
        raise MeasurementError("authorization header exceeds the hard byte limit")
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise MeasurementError("authorization header is not valid UTF-8") from error
    if not value or "\r" in value or "\n" in value:
        raise MeasurementError("authorization header must be one bounded nonempty line")
    return value


def validate_url(url: str, allow_remote: bool) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "http" or not parsed.hostname or parsed.path not in {"", "/"}:
        raise MeasurementError("--hsrd-url must be an HTTP origin without a path")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise MeasurementError("--hsrd-url must not contain credentials, query, or fragment")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as error:
        raise MeasurementError("--hsrd-url must use a literal IP address") from error
    if not allow_remote and not address.is_loopback:
        raise MeasurementError("remote hsrd measurement requires --allow-remote-hsrd")
    return url.rstrip("/")


def extract_sample(payload: dict[str, Any], elapsed: float) -> dict[str, Any]:
    if not payload.get("enabled"):
        raise MeasurementError("native-sync diagnostics report the runtime disabled")
    if payload.get("headers_only") or payload.get("observation_only"):
        raise MeasurementError("measurement requires native active-state synchronization")
    if not payload.get("active_state"):
        raise MeasurementError("native active-state synchronization is disabled")
    runtime_instance = payload.get("runtime_instance")
    if not isinstance(runtime_instance, str) or not runtime_instance:
        raise MeasurementError("native-sync runtime instance is unavailable")
    last_error = payload.get("last_error")
    if last_error is not None:
        raise MeasurementError(f"native-sync runtime reported an error: {last_error}")
    sync = payload.get("sync")
    peers = payload.get("peers")
    if not isinstance(sync, dict) or not isinstance(peers, list):
        raise MeasurementError("native-sync scheduler or peer diagnostics are malformed")
    target = sync.get("target_height")
    if target is not None:
        target = require_int(target, "sync.target_height")
    peer_failures = 0
    for peer in sync.get("peers", []):
        if not isinstance(peer, dict):
            raise MeasurementError("native-sync peer scheduler entry is malformed")
        peer_failures += require_int(peer.get("failures"), "sync peer failures")
    for peer in peers:
        if not isinstance(peer, dict):
            raise MeasurementError("native-sync peer entry is malformed")
        require_int(peer.get("bytes_received"), "peer bytes_received")
    return {
        "elapsed_seconds": round(elapsed, 6),
        "unix_time": int(time.time()),
        "runtime_instance": runtime_instance,
        "target_height": target,
        "best_header_height": optional_tip_height(sync, "best_header"),
        "stored_height": optional_tip_height(sync, "stored_tip"),
        "active_height": optional_tip_height(sync, "active_tip"),
        "received_headers": require_int(payload.get("received_headers"), "received_headers"),
        "received_blocks": require_int(payload.get("received_blocks"), "received_blocks"),
        "stored_bodies": require_int(payload.get("stored_bodies"), "stored_bodies"),
        "connected_blocks": require_int(payload.get("connected_blocks"), "connected_blocks"),
        "active_state_slices": require_int(
            payload.get("active_state_slices"), "active_state_slices"
        ),
        "active_state_last_slice_blocks": require_int(
            payload.get("active_state_last_slice_blocks"),
            "active_state_last_slice_blocks",
        ),
        "active_state_last_slice_millis": require_int(
            payload.get("active_state_last_slice_millis"),
            "active_state_last_slice_millis",
        ),
        "active_state_max_slice_millis": require_int(
            payload.get("active_state_max_slice_millis"),
            "active_state_max_slice_millis",
        ),
        "active_state_last_planning_micros": require_int(
            payload.get("active_state_last_planning_micros"),
            "active_state_last_planning_micros",
        ),
        "active_state_last_commit_micros": require_int(
            payload.get("active_state_last_commit_micros"),
            "active_state_last_commit_micros",
        ),
        "active_state_last_post_commit_micros": require_int(
            payload.get("active_state_last_post_commit_micros"),
            "active_state_last_post_commit_micros",
        ),
        "active_state_last_transactions": require_int(
            payload.get("active_state_last_transactions"),
            "active_state_last_transactions",
        ),
        "active_state_last_non_coinbase_inputs": require_int(
            payload.get("active_state_last_non_coinbase_inputs"),
            "active_state_last_non_coinbase_inputs",
        ),
        "active_state_last_outputs": require_int(
            payload.get("active_state_last_outputs"),
            "active_state_last_outputs",
        ),
        "active_state_last_name_actions": require_int(
            payload.get("active_state_last_name_actions"),
            "active_state_last_name_actions",
        ),
        "peer_event_backlog": require_int(
            payload.get("peer_event_backlog"), "peer_event_backlog"
        ),
        "validation_result_backlog": require_int(
            payload.get("validation_result_backlog"), "validation_result_backlog"
        ),
        "pending_blocks": require_int(sync.get("pending_blocks"), "sync.pending_blocks"),
        "inflight_blocks": require_int(sync.get("inflight_blocks"), "sync.inflight_blocks"),
        "tracked_blocks": require_int(sync.get("tracked_blocks"), "sync.tracked_blocks"),
        "failed_blocks": require_int(sync.get("failed_blocks"), "sync.failed_blocks"),
        "unavailable_blocks": require_int(
            sync.get("unavailable_blocks"), "sync.unavailable_blocks"
        ),
        "peer_failures": peer_failures,
        "ready_peers": sum(peer.get("state") == "ready" for peer in peers if isinstance(peer, dict)),
        "received_bytes": require_int(payload.get("bytes_received"), "bytes_received"),
    }


def nearest_rank(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = math.ceil(percentile * len(ordered) / 100)
    return ordered[max(0, rank - 1)]


def distribution(values: list[float]) -> dict[str, Any]:
    return {
        "count": len(values),
        "p50": round(nearest_rank(values, 50), 3),
        "p95": round(nearest_rank(values, 95), 3),
        "p99": round(nearest_rank(values, 99), 3),
        "maximum": round(max(values, default=0.0), 3),
    }


def summarize(samples: list[dict[str, Any]], interval: float) -> dict[str, Any]:
    if len(samples) < 2:
        raise MeasurementError("at least two native-sync samples are required")
    runtime = samples[0]["runtime_instance"]
    if any(sample["runtime_instance"] != runtime for sample in samples):
        raise MeasurementError("native-sync runtime changed during measurement")

    rate_fields = [
        "best_header_height",
        "stored_height",
        "active_height",
        "received_blocks",
        "stored_bodies",
        "connected_blocks",
        "active_state_slices",
        "received_bytes",
    ]
    rates: dict[str, list[float]] = {field: [] for field in rate_fields}
    observed_slice_millis: list[float] = []
    observed_slice_phases: dict[str, list[float]] = {
        "planning": [],
        "state_commit": [],
        "post_commit": [],
    }
    workload_fields = (
        "transactions",
        "non_coinbase_inputs",
        "outputs",
        "name_actions",
    )
    observed_workloads: dict[str, list[float]] = {
        field: [] for field in workload_fields
    }
    commit_micros_per_work: dict[str, list[float]] = {
        field: [] for field in workload_fields
    }
    unobserved_slices = 0
    active_stall_intervals = 0
    for before, after in zip(samples, samples[1:]):
        elapsed = after["elapsed_seconds"] - before["elapsed_seconds"]
        if elapsed <= 0:
            raise MeasurementError("sample elapsed time did not advance")
        for field in rate_fields:
            delta = after[field] - before[field]
            if delta < 0:
                raise MeasurementError(f"native-sync counter {field} regressed")
            rates[field].append(delta / elapsed)
        slice_delta = after["active_state_slices"] - before["active_state_slices"]
        if slice_delta > 0:
            observed_slice_millis.append(float(after["active_state_last_slice_millis"]))
            observed_slice_phases["planning"].append(
                float(after["active_state_last_planning_micros"])
            )
            observed_slice_phases["state_commit"].append(
                float(after["active_state_last_commit_micros"])
            )
            observed_slice_phases["post_commit"].append(
                float(after["active_state_last_post_commit_micros"])
            )
            commit_micros = float(after["active_state_last_commit_micros"])
            for field in workload_fields:
                value = after[f"active_state_last_{field}"]
                observed_workloads[field].append(float(value))
                if value > 0:
                    commit_micros_per_work[field].append(commit_micros / value)
            unobserved_slices += max(0, slice_delta - 1)
        target = after["target_height"]
        if (
            after["active_height"] == before["active_height"]
            and target is not None
            and after["active_height"] < target
        ):
            active_stall_intervals += 1

    first = samples[0]
    last = samples[-1]
    elapsed = last["elapsed_seconds"] - first["elapsed_seconds"]
    totals = {
        field: round((last[field] - first[field]) / elapsed, 3) for field in rate_fields
    }
    return {
        "schema": SCHEMA,
        "runtime_instance": runtime,
        "duration_seconds": round(elapsed, 3),
        "requested_interval_seconds": interval,
        "sample_count": len(samples),
        "starting": first,
        "ending": last,
        "overall_rates_per_second": totals,
        "interval_rates_per_second": {
            field: distribution(values) for field, values in rates.items()
        },
        "active_stall_intervals": active_stall_intervals,
        "active_state_slice_millis": distribution(observed_slice_millis),
        "active_state_phase_micros": {
            phase: distribution(values) for phase, values in observed_slice_phases.items()
        },
        "active_state_workload_per_slice": {
            field: distribution(values) for field, values in observed_workloads.items()
        },
        "active_state_commit_micros_per_work": {
            field: distribution(values) for field, values in commit_micros_per_work.items()
        },
        "unobserved_active_state_slices": unobserved_slices,
        "peer_event_backlog": distribution(
            [float(sample["peer_event_backlog"]) for sample in samples]
        ),
        "validation_result_backlog": distribution(
            [float(sample["validation_result_backlog"]) for sample in samples]
        ),
        "stored_active_buffer": distribution(
            [
                float(max(0, sample["stored_height"] - sample["active_height"]))
                for sample in samples
            ]
        ),
        "starting_ready_peers": first["ready_peers"],
        "ending_ready_peers": last["ready_peers"],
        "minimum_ready_peers": min(sample["ready_peers"] for sample in samples),
        "zero_ready_peer_samples": sum(sample["ready_peers"] == 0 for sample in samples),
        "failure_count": last["failed_blocks"],
        "unavailable_evidence": last["unavailable_blocks"],
        "peer_failure_count": last["peer_failures"],
        "samples": samples,
    }


def write_report(path: pathlib.Path, report: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as output:
        temporary = pathlib.Path(output.name)
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def self_test() -> None:
    base = {
        "runtime_instance": "test",
        "target_height": 100,
        "best_header_height": 0,
        "stored_height": 0,
        "active_height": 0,
        "received_headers": 0,
        "received_blocks": 0,
        "stored_bodies": 0,
        "connected_blocks": 0,
        "active_state_slices": 0,
        "active_state_last_slice_blocks": 0,
        "active_state_last_slice_millis": 0,
        "active_state_max_slice_millis": 0,
        "active_state_last_planning_micros": 0,
        "active_state_last_commit_micros": 0,
        "active_state_last_post_commit_micros": 0,
        "active_state_last_transactions": 0,
        "active_state_last_non_coinbase_inputs": 0,
        "active_state_last_outputs": 0,
        "active_state_last_name_actions": 0,
        "peer_event_backlog": 0,
        "validation_result_backlog": 0,
        "pending_blocks": 1,
        "inflight_blocks": 0,
        "tracked_blocks": 1,
        "failed_blocks": 0,
        "unavailable_blocks": 0,
        "peer_failures": 0,
        "ready_peers": 2,
        "received_bytes": 0,
        "unix_time": 1,
    }
    samples = []
    for index in range(3):
        sample = dict(base)
        sample["elapsed_seconds"] = float(index)
        sample["best_header_height"] = index * 20
        sample["stored_height"] = index * 10
        sample["active_height"] = index * 10
        sample["received_blocks"] = index * 10
        sample["stored_bodies"] = index * 10
        sample["connected_blocks"] = index * 10
        sample["active_state_slices"] = index
        sample["active_state_last_slice_blocks"] = 10
        sample["active_state_last_slice_millis"] = 125 + index
        sample["active_state_max_slice_millis"] = 125 + index
        sample["active_state_last_planning_micros"] = 10 + index
        sample["active_state_last_commit_micros"] = 100 + index
        sample["active_state_last_post_commit_micros"] = 15 + index
        sample["active_state_last_transactions"] = 20
        sample["active_state_last_non_coinbase_inputs"] = 10
        sample["active_state_last_outputs"] = 30
        sample["active_state_last_name_actions"] = 5
        sample["received_bytes"] = index * 1000
        samples.append(sample)
    report = summarize(samples, 1.0)
    assert report["overall_rates_per_second"]["active_height"] == 10.0
    assert report["interval_rates_per_second"]["received_bytes"]["p99"] == 1000.0
    assert report["active_stall_intervals"] == 0
    assert report["active_state_slice_millis"]["p99"] == 127.0
    assert report["active_state_phase_micros"]["state_commit"]["p99"] == 102.0
    assert (
        report["active_state_commit_micros_per_work"]["transactions"]["p99"] == 5.1
    )
    assert report["unobserved_active_state_slices"] == 0
    assert report["stored_active_buffer"]["maximum"] == 0.0
    assert report["starting_ready_peers"] == 2
    assert report["ending_ready_peers"] == 2
    assert report["minimum_ready_peers"] == 2
    assert report["zero_ready_peer_samples"] == 0
    with tempfile.TemporaryDirectory() as directory:
        authorization_path = pathlib.Path(directory) / "authorization"
        authorization_path.write_text("Bearer measurement-test\n", encoding="utf-8")
        authorization_path.chmod(0o600)
        assert read_authorization_header(authorization_path) == "Bearer measurement-test"
        authorization_path.chmod(0o640)
        try:
            read_authorization_header(authorization_path)
        except MeasurementError:
            pass
        else:
            raise AssertionError("group-readable authorization file was accepted")
    print("hsrd native-sync measurement self-test passed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hsrd-url", default="http://127.0.0.1:12037")
    parser.add_argument("--duration-seconds", type=float, default=60.0)
    parser.add_argument("--interval-seconds", type=float, default=1.0)
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--authorization-header-file", type=pathlib.Path)
    parser.add_argument("--allow-remote-hsrd", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.self_test:
        self_test()
        return
    if not 1.0 <= args.duration_seconds <= 86_400.0:
        raise MeasurementError("duration must be within 1..=86400 seconds")
    if not 0.1 <= args.interval_seconds <= 60.0:
        raise MeasurementError("interval must be within 0.1..=60 seconds")
    if args.timeout_seconds <= 0:
        raise MeasurementError("timeout must be positive")
    base_url = validate_url(args.hsrd_url, args.allow_remote_hsrd)
    authorization = read_authorization_header(args.authorization_header_file)
    endpoint = f"{base_url}/api/v1/native-sync"
    started = time.monotonic()
    deadline = started + args.duration_seconds
    samples = [
        extract_sample(read_json(endpoint, args.timeout_seconds, authorization), 0.0)
    ]
    while True:
        next_sample = min(deadline, started + len(samples) * args.interval_seconds)
        remaining = next_sample - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        now = time.monotonic()
        samples.append(
            extract_sample(
                read_json(endpoint, args.timeout_seconds, authorization), now - started
            )
        )
        if now >= deadline:
            break
    report = summarize(samples, args.interval_seconds)
    if args.output:
        write_report(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (MeasurementError, OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"hsrd native-sync measurement failed: {error}") from error
