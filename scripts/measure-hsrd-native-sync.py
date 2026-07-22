#!/usr/bin/env python3
"""Measure one uninterrupted hsrd native-sync runtime without an HSD process."""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import pathlib
import tempfile
import time
import urllib.parse
import urllib.request
from typing import Any


SCHEMA = 1
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


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


def read_json(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise MeasurementError("hsrd diagnostics exceed the response-size bound")
    decoded = json.loads(payload)
    if not isinstance(decoded, dict):
        raise MeasurementError("hsrd diagnostics must be a JSON object")
    return decoded


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
    received_bytes = 0
    for peer in peers:
        if not isinstance(peer, dict):
            raise MeasurementError("native-sync peer entry is malformed")
        received_bytes += require_int(peer.get("bytes_received"), "peer bytes_received")
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
        "tracked_blocks": require_int(sync.get("tracked_blocks"), "sync.tracked_blocks"),
        "failed_blocks": require_int(sync.get("failed_blocks"), "sync.failed_blocks"),
        "unavailable_blocks": require_int(
            sync.get("unavailable_blocks"), "sync.unavailable_blocks"
        ),
        "peer_failures": peer_failures,
        "ready_peers": sum(peer.get("state") == "ready" for peer in peers if isinstance(peer, dict)),
        "received_bytes": received_bytes,
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
        "received_bytes",
    ]
    rates: dict[str, list[float]] = {field: [] for field in rate_fields}
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
        sample["received_bytes"] = index * 1000
        samples.append(sample)
    report = summarize(samples, 1.0)
    assert report["overall_rates_per_second"]["active_height"] == 10.0
    assert report["interval_rates_per_second"]["received_bytes"]["p99"] == 1000.0
    assert report["active_stall_intervals"] == 0
    print("hsrd native-sync measurement self-test passed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hsrd-url", default="http://127.0.0.1:12037")
    parser.add_argument("--duration-seconds", type=float, default=60.0)
    parser.add_argument("--interval-seconds", type=float, default=1.0)
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument("--output", type=pathlib.Path)
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
    endpoint = f"{base_url}/api/v1/native-sync"
    started = time.monotonic()
    deadline = started + args.duration_seconds
    samples = [extract_sample(read_json(endpoint, args.timeout_seconds), 0.0)]
    while True:
        next_sample = min(deadline, started + len(samples) * args.interval_seconds)
        remaining = next_sample - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        now = time.monotonic()
        samples.append(extract_sample(read_json(endpoint, args.timeout_seconds), now - started))
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
