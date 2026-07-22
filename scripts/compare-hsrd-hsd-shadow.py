#!/usr/bin/env python3
"""Compare an hsrd active tip and next header name root with a live HSD node.

The comparison is deliberately external to hsrd's authority boundary.  HSD is
queried through an operator-selected ``hsd-cli`` executable and hsrd is read
through its loopback diagnostics.  A match is qualification evidence only; it
never grants mining authority.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, NoReturn

SCHEMA_VERSION = 1
MINIMUM_HSRD_API_VERSION = 9
MAX_HTTP_BYTES = 2 * 1024 * 1024
MAX_COMMAND_BYTES = 8 * 1024 * 1024
MAX_STATE_BYTES = 1024 * 1024
HEX_32 = re.compile(r"^[0-9a-fA-F]{64}$")
NETWORK_MAP = {
    "mainnet": "main",
    "testnet": "testnet",
    "regtest": "regtest",
    "simnet": "simnet",
}
# Pinned HSD revision 698e252e exposes these consensus effects from
# DeploymentState: mandatory script flags are MINIMALDATA|MINIMALIF|NULLFAIL,
# and no deployed version bit changes transaction lock flags.
HSD_MANDATORY_SCRIPT_FLAGS = 50
HSD_DEPLOYMENT_LOCK_FLAGS = 0


class ProbeError(RuntimeError):
    """A transient, incoherent, or unsafe comparison probe."""


def error(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProbeError(f"{label} must be a JSON object")
    return value


def require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ProbeError(f"{label} must be a boolean")
    return value


def require_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ProbeError(f"{label} must be an integer >= {minimum}")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise ProbeError(f"{label} must be a non-empty control-free string")
    return value


def normalize_hash(value: Any, label: str) -> str:
    if isinstance(value, str) and HEX_32.fullmatch(value):
        return value.lower()
    if (
        isinstance(value, list)
        and len(value) == 32
        and all(
            isinstance(byte, int)
            and not isinstance(byte, bool)
            and 0 <= byte <= 255
            for byte in value
        )
    ):
        return bytes(value).hex()
    raise ProbeError(f"{label} must be a 32-byte hash")


def read_http_json(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "meshmine-hsrd-parity/1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise ProbeError(f"{url} returned HTTP {response.status}")
            body = response.read(MAX_HTTP_BYTES + 1)
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        raise ProbeError(f"failed to read {url}: {exc}") from exc
    if len(body) > MAX_HTTP_BYTES:
        raise ProbeError(f"{url} response exceeds {MAX_HTTP_BYTES} bytes")
    try:
        return require_object(json.loads(body), url)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeError(f"{url} returned invalid JSON: {exc}") from exc


class HsdCli:
    def __init__(
        self,
        executable: Path,
        prefix_arguments: list[str],
        timeout: float,
        source_revision: str,
    ) -> None:
        self.executable = executable
        self.prefix_arguments = prefix_arguments
        self.timeout = timeout
        self.source_revision = source_revision

    def _run(self, arguments: list[str]) -> str:
        command = [str(self.executable), *self.prefix_arguments, *arguments]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=False,
                timeout=self.timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProbeError(f"hsd-cli invocation failed: {exc}") from exc
        if len(completed.stdout) > MAX_COMMAND_BYTES or len(completed.stderr) > MAX_COMMAND_BYTES:
            raise ProbeError(f"hsd-cli output exceeds {MAX_COMMAND_BYTES} bytes")
        stdout = completed.stdout.decode("utf-8", errors="replace").strip()
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        if completed.returncode != 0:
            detail = stderr or stdout or "no diagnostic output"
            raise ProbeError(f"hsd-cli exited {completed.returncode}: {detail[:1000]}")
        if not stdout:
            raise ProbeError("hsd-cli returned an empty response")
        return stdout

    def json(self, arguments: list[str], label: str) -> dict[str, Any]:
        output = self._run(arguments)
        try:
            return require_object(json.loads(output), label)
        except json.JSONDecodeError as exc:
            raise ProbeError(f"{label} returned invalid JSON: {exc}") from exc

    def info(self) -> dict[str, Any]:
        return self.json(["info"], "hsd info")

    def blockchain_info(self) -> dict[str, Any]:
        return self.json(["rpc", "getblockchaininfo"], "HSD blockchain info")

    def block_hash(self, height: int) -> str:
        output = self._run(["rpc", "getblockhash", str(height)])
        if output.startswith('"'):
            try:
                output = json.loads(output)
            except json.JSONDecodeError as exc:
                raise ProbeError(f"HSD block hash returned invalid JSON: {exc}") from exc
        return normalize_hash(output, f"HSD block hash at height {height}")

    def block_header(self, block_hash: str) -> dict[str, Any]:
        return self.json(
            ["rpc", "getblockheader", block_hash, "true"],
            f"HSD block header {block_hash}",
        )

    def block_template(self) -> dict[str, Any]:
        return self.json(["rpc", "getblocktemplate"], "HSD block template")


def extract_hsrd(status: dict[str, Any], shadow: dict[str, Any]) -> dict[str, Any]:
    api_version = require_int(status.get("api_version"), "hsrd api_version", minimum=1)
    if api_version < MINIMUM_HSRD_API_VERSION:
        raise ProbeError(
            f"hsrd diagnostic API {api_version} is older than required API "
            f"{MINIMUM_HSRD_API_VERSION}"
        )
    network = require_string(status.get("network"), "hsrd network")
    if network not in NETWORK_MAP:
        raise ProbeError(f"unsupported hsrd network {network!r}")
    height = require_int(status.get("height"), "hsrd active height")
    root_height = require_int(
        status.get("active_state_resulting_root_height"),
        "hsrd resulting-root height",
    )
    if root_height != height:
        raise ProbeError(
            f"hsrd resulting-root height {root_height} does not match active height {height}"
        )
    if not require_bool(
        status.get("active_state_sync_enabled"), "hsrd active-state sync flag"
    ):
        raise ProbeError("hsrd active-state synchronization is not enabled")

    authority = require_object(status.get("authority"), "hsrd authority")
    authority_mode = require_string(authority.get("mode"), "hsrd authority mode")
    if authority_mode not in {"disabled", "shadow"}:
        raise ProbeError(
            f"live comparison requires disabled or shadow authority, got {authority_mode!r}"
        )
    if require_bool(
        authority.get("can_authorize_mining_templates"),
        "hsrd mining-template authority",
    ):
        raise ProbeError("live comparison refuses a mining-authoritative hsrd instance")

    if not require_bool(shadow.get("enabled"), "shadow-sync enabled flag"):
        raise ProbeError("shadow-sync diagnostics report the runtime disabled")
    if not require_bool(shadow.get("active_state"), "shadow-sync active-state flag"):
        raise ProbeError("shadow-sync diagnostics report active-state connection disabled")
    if require_bool(shadow.get("observation_only"), "shadow-sync observation flag"):
        raise ProbeError("shadow-sync diagnostics still report observation-only mode")

    block_hash = normalize_hash(status.get("best_block_hash"), "hsrd active block hash")
    sync = require_object(shadow.get("sync"), "shadow-sync scheduler snapshot")
    active_tip = require_object(sync.get("active_tip"), "shadow-sync active tip")
    sync_hash = normalize_hash(active_tip.get("hash"), "shadow-sync active-tip hash")
    sync_height = require_int(active_tip.get("height"), "shadow-sync active-tip height")
    if sync_hash != block_hash or sync_height != height:
        raise ProbeError("hsrd status and shadow scheduler active tips are not one snapshot")

    parity = require_object(status.get("parity"), "hsrd parity status")
    return {
        "api_version": api_version,
        "network": network,
        "height": height,
        "block_hash": block_hash,
        "resulting_root": normalize_hash(
            status.get("active_state_resulting_root"), "hsrd resulting state root"
        ),
        "chain_epoch": require_int(status.get("chain_epoch"), "hsrd chain epoch"),
        "mining_generation": require_int(
            status.get("mining_generation"), "hsrd mining generation"
        ),
        "authority_mode": authority_mode,
        "runtime_instance": require_string(
            shadow.get("runtime_instance"), "shadow-sync runtime instance"
        ),
        "oracle_revision": require_string(
            parity.get("oracle_revision"), "hsrd HSD oracle revision"
        ),
    }


def extract_hsrd_header(status: dict[str, Any], shadow: dict[str, Any]) -> dict[str, Any]:
    api_version = require_int(status.get("api_version"), "hsrd api_version", minimum=1)
    if api_version < MINIMUM_HSRD_API_VERSION:
        raise ProbeError(
            f"hsrd diagnostic API {api_version} is older than required API "
            f"{MINIMUM_HSRD_API_VERSION}"
        )
    network = require_string(status.get("network"), "hsrd network")
    if network not in NETWORK_MAP:
        raise ProbeError(f"unsupported hsrd network {network!r}")

    authority = require_object(status.get("authority"), "hsrd authority")
    authority_mode = require_string(authority.get("mode"), "hsrd authority mode")
    if authority_mode not in {"disabled", "shadow"}:
        raise ProbeError(
            f"header comparison requires disabled or shadow authority, got {authority_mode!r}"
        )
    if require_bool(
        authority.get("can_authorize_mining_templates"),
        "hsrd mining-template authority",
    ):
        raise ProbeError("header comparison refuses a mining-authoritative hsrd instance")
    if not require_bool(shadow.get("enabled"), "shadow-sync enabled flag"):
        raise ProbeError("shadow-sync diagnostics report the runtime disabled")
    if not require_bool(shadow.get("headers_only"), "shadow-sync headers-only flag"):
        raise ProbeError("header comparison requires --shadow-sync-headers-only")

    sync = require_object(shadow.get("sync"), "shadow-sync scheduler snapshot")
    sync_tip = require_object(sync.get("best_header"), "shadow-sync best header")
    height = require_int(sync_tip.get("height"), "shadow-sync best-header height")
    block_hash = normalize_hash(sync_tip.get("hash"), "shadow-sync best-header hash")
    if require_int(status.get("best_header_height"), "hsrd best-header height") != height:
        raise ProbeError("hsrd status and shadow scheduler best-header heights disagree")
    if normalize_hash(status.get("best_header_hash"), "hsrd best-header hash") != block_hash:
        raise ProbeError("hsrd status and shadow scheduler best-header hashes disagree")

    parity = require_object(status.get("parity"), "hsrd parity status")
    return {
        "api_version": api_version,
        "network": network,
        "height": height,
        "block_hash": block_hash,
        "authority_mode": authority_mode,
        "runtime_instance": require_string(
            shadow.get("runtime_instance"), "shadow-sync runtime instance"
        ),
        "received_headers": require_int(
            shadow.get("received_headers"), "shadow-sync received headers"
        ),
        "oracle_revision": require_string(
            parity.get("oracle_revision"), "hsrd HSD oracle revision"
        ),
    }


def extract_hsrd_header_deployments(value: dict[str, Any]) -> dict[str, Any]:
    best = require_object(value.get("best_header"), "header deployment best header")
    height = require_int(best.get("height"), "header deployment best-header height")
    block_hash = normalize_hash(
        best.get("hash"), "header deployment best-header hash"
    )
    next_height = require_int(value.get("next_height"), "deployment next height")
    if next_height != height + 1:
        raise ProbeError("header deployment next height is not contiguous")

    raw_deployments = value.get("deployments")
    if not isinstance(raw_deployments, list) or not raw_deployments:
        raise ProbeError("header deployments must be a non-empty array")
    deployments: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_deployments):
        item = require_object(raw, f"header deployment {index}")
        name = require_string(item.get("name"), f"header deployment {index} name")
        state = require_string(
            item.get("state"), f"header deployment {name} state"
        ).lower()
        if state not in {"defined", "started", "locked_in", "active", "failed"}:
            raise ProbeError(f"header deployment {name} has unknown state {state!r}")
        if name in deployments:
            raise ProbeError(f"header deployment {name!r} is duplicated")
        bit = require_int(item.get("bit"), f"header deployment {name} bit")
        if bit > 31:
            raise ProbeError(f"header deployment {name} bit exceeds 31")
        deployments[name] = {
            "state": state,
            "bit": bit,
            "start_time": require_int(
                item.get("start_time"), f"header deployment {name} start time"
            ),
            "timeout": require_int(
                item.get("timeout"), f"header deployment {name} timeout"
            ),
        }

    checkpoint_value = value.get("final_checkpoint")
    checkpoint = None
    if checkpoint_value is not None:
        checkpoint_value = require_object(checkpoint_value, "header final checkpoint")
        checkpoint = {
            "height": require_int(
                checkpoint_value.get("height"), "header final checkpoint height"
            ),
            "hash": normalize_hash(
                checkpoint_value.get("hash"), "header final checkpoint hash"
            ),
            "anchored": require_bool(
                checkpoint_value.get("anchored"), "header final checkpoint anchor"
            ),
        }
    historical_through = value.get("historical_script_assumption_through")
    if historical_through is not None:
        historical_through = require_int(
            historical_through, "historical script assumption height"
        )

    return {
        "height": height,
        "block_hash": block_hash,
        "next_height": next_height,
        "deployments": deployments,
        "script_flags": require_int(value.get("script_flags"), "script flags"),
        "lock_flags": require_int(value.get("lock_flags"), "lock flags"),
        "name_flags": require_int(value.get("name_flags"), "name flags"),
        "has_airstop": require_bool(value.get("has_airstop"), "airstop flag"),
        "next_block_version": require_int(
            value.get("next_block_version"), "next block version"
        ),
        "final_checkpoint": checkpoint,
        "historical_script_assumption_through": historical_through,
    }


def extract_hsd_info(info: dict[str, Any]) -> dict[str, Any]:
    network = require_string(info.get("network"), "HSD network")
    chain = require_object(info.get("chain"), "HSD chain info")
    return {
        "version": require_string(info.get("version"), "HSD version"),
        "network": network,
        "height": require_int(chain.get("height"), "HSD height"),
        "tip": normalize_hash(chain.get("tip"), "HSD tip hash"),
        "pruned": require_bool(
            require_object(chain.get("options"), "HSD chain options").get("prune"),
            "HSD prune flag",
        ),
    }


def extract_hsd_blockchain_info(value: dict[str, Any]) -> dict[str, Any]:
    height = require_int(value.get("blocks"), "HSD blockchain height")
    if require_int(value.get("headers"), "HSD blockchain header height") != height:
        raise ProbeError("HSD block and header heights disagree")
    raw_forks = require_object(value.get("softforks"), "HSD softforks")
    deployments: dict[str, dict[str, Any]] = {}
    for name, raw in raw_forks.items():
        if not isinstance(name, str) or not name:
            raise ProbeError("HSD softfork name is invalid")
        item = require_object(raw, f"HSD softfork {name}")
        state = require_string(item.get("status"), f"HSD softfork {name} state")
        if state not in {"defined", "started", "locked_in", "active", "failed"}:
            raise ProbeError(f"HSD softfork {name} has unknown state {state!r}")
        bit = require_int(item.get("bit"), f"HSD softfork {name} bit")
        if bit > 31:
            raise ProbeError(f"HSD softfork {name} bit exceeds 31")
        deployments[name] = {
            "state": state,
            "bit": bit,
            "start_time": require_int(
                item.get("startTime"), f"HSD softfork {name} start time"
            ),
            "timeout": require_int(
                item.get("timeout"), f"HSD softfork {name} timeout"
            ),
        }
    return {
        "height": height,
        "block_hash": normalize_hash(
            value.get("bestblockhash"), "HSD blockchain tip hash"
        ),
        "deployments": deployments,
        "pruned": require_bool(value.get("pruned"), "HSD blockchain prune flag"),
    }


def compare_header_deployments(
    hsrd: dict[str, Any], hsd: dict[str, Any]
) -> dict[str, Any]:
    parameters_match = set(hsrd["deployments"]) == set(hsd["deployments"])
    states_match = parameters_match
    if parameters_match:
        for name, actual in hsrd["deployments"].items():
            expected = hsd["deployments"][name]
            parameters_match = parameters_match and all(
                actual[field] == expected[field]
                for field in ("bit", "start_time", "timeout")
            )
            states_match = states_match and actual["state"] == expected["state"]

    expected_version = 0
    for deployment in hsd["deployments"].values():
        if deployment["state"] in {"started", "locked_in"}:
            expected_version |= 1 << deployment["bit"]
    expected_name_flags = 0
    if hsd["deployments"].get("hardening", {}).get("state") == "active":
        expected_name_flags |= 1
    if hsd["deployments"].get("icannlockup", {}).get("state") == "active":
        expected_name_flags |= 2
    expected_airstop = (
        hsd["deployments"].get("airstop", {}).get("state") == "active"
    )
    effects_match = (
        hsrd["script_flags"] == HSD_MANDATORY_SCRIPT_FLAGS
        and hsrd["lock_flags"] == HSD_DEPLOYMENT_LOCK_FLAGS
        and hsrd["name_flags"] == expected_name_flags
        and hsrd["has_airstop"] == expected_airstop
        and hsrd["next_block_version"] == expected_version
    )
    checkpoint = hsrd["final_checkpoint"]
    checkpoint_anchored = checkpoint is None or (
        hsrd["height"] < checkpoint["height"]
        or (
            checkpoint["anchored"]
            and hsrd["historical_script_assumption_through"] == checkpoint["height"]
            and hsd.get("final_checkpoint_hash") == checkpoint["hash"]
        )
    )
    return {
        "matched": parameters_match
        and states_match
        and effects_match
        and checkpoint_anchored,
        "parameters_matched": parameters_match,
        "states_matched": states_match,
        "effects_matched": effects_match,
        "checkpoint_anchored": checkpoint_anchored,
        "hsrd": hsrd,
        "hsd": hsd,
    }


def build_observation(
    hsrd: dict[str, Any],
    hsd: dict[str, Any],
    oracle_block_hash: str,
    oracle_root: str,
    root_source: str,
    root_confirmed: bool,
) -> dict[str, Any]:
    expected_network = NETWORK_MAP[hsrd["network"]]
    if hsd["network"] != expected_network:
        raise ProbeError(
            f"network mismatch: hsrd {hsrd['network']!r} expects HSD "
            f"{expected_network!r}, got {hsd['network']!r}"
        )
    if hsrd["height"] > hsd["height"]:
        raise ProbeError(
            f"HSD oracle height {hsd['height']} is behind hsrd height {hsrd['height']}"
        )

    mismatches = []
    if hsrd["block_hash"] != oracle_block_hash:
        mismatches.append(
            {
                "field": "active_block_hash",
                "hsrd": hsrd["block_hash"],
                "hsd": oracle_block_hash,
            }
        )
    if hsrd["resulting_root"] != oracle_root:
        mismatches.append(
            {
                "field": "active_state_resulting_root",
                "hsrd": hsrd["resulting_root"],
                "hsd": oracle_root,
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "observed_at": int(time.time()),
        "matched": not mismatches,
        "mismatches": mismatches,
        "network": hsrd["network"],
        "height": hsrd["height"],
        "block_hash": hsrd["block_hash"],
        "active_state_resulting_root": hsrd["resulting_root"],
        "root_source": root_source,
        "root_confirmed_by_next_header": root_confirmed,
        "hsrd_api_version": hsrd["api_version"],
        "hsrd_chain_epoch": hsrd["chain_epoch"],
        "hsrd_mining_generation": hsrd["mining_generation"],
        "hsrd_authority_mode": hsrd["authority_mode"],
        "hsrd_runtime_instance": hsrd["runtime_instance"],
        "expected_hsd_oracle_revision": hsrd["oracle_revision"],
        "hsd_source_revision": hsd["source_revision"],
        "hsd_version": hsd["version"],
        "hsd_tip_height": hsd["height"],
        "hsd_tip_hash": hsd["tip"],
        "hsd_pruned": hsd["pruned"],
    }


def probe_once(
    hsrd_url: str,
    cli: HsdCli,
    timeout: float,
    previous_observation: dict[str, Any] | None,
) -> tuple[dict[str, Any], bool | None]:
    status_url = f"{hsrd_url}/api/v1/status"
    shadow_url = f"{hsrd_url}/api/v1/shadow-sync"
    hsrd_before = extract_hsrd(
        read_http_json(status_url, timeout),
        read_http_json(shadow_url, timeout),
    )
    hsd_before = extract_hsd_info(cli.info())
    hsd_before["source_revision"] = cli.source_revision
    if cli.source_revision != hsrd_before["oracle_revision"]:
        raise ProbeError(
            "pinned HSD source revision does not match hsrd's expected oracle revision"
        )
    if hsrd_before["height"] > hsd_before["height"]:
        raise ProbeError(
            f"HSD oracle height {hsd_before['height']} is behind hsrd height "
            f"{hsrd_before['height']}"
        )

    oracle_block_hash = cli.block_hash(hsrd_before["height"])
    if hsrd_before["height"] < hsd_before["height"]:
        next_height = hsrd_before["height"] + 1
        next_hash = cli.block_hash(next_height)
        header = cli.block_header(next_hash)
        if require_int(header.get("height"), "HSD next-header height") != next_height:
            raise ProbeError("HSD next-header height is incoherent")
        if normalize_hash(header.get("hash"), "HSD next-header hash") != next_hash:
            raise ProbeError("HSD next-header hash is incoherent")
        if (
            normalize_hash(header.get("previousblockhash"), "HSD next-header parent")
            != oracle_block_hash
        ):
            raise ProbeError("HSD next header does not extend the compared block")
        oracle_root = normalize_hash(header.get("treeroot"), "HSD next-header tree root")
        root_source = "next-header"
        root_confirmed = True
    else:
        template = cli.block_template()
        if require_int(template.get("height"), "HSD template height") != hsrd_before["height"] + 1:
            raise ProbeError("HSD template height is incoherent")
        if (
            normalize_hash(template.get("previousblockhash"), "HSD template parent")
            != oracle_block_hash
        ):
            raise ProbeError("HSD template does not extend the compared block")
        oracle_root = normalize_hash(template.get("treeroot"), "HSD template tree root")
        root_source = "next-template"
        root_confirmed = False

    previous_still_canonical = None
    if previous_observation is not None:
        previous_height = require_int(
            previous_observation.get("height"), "previous observation height"
        )
        previous_hash = normalize_hash(
            previous_observation.get("block_hash"), "previous observation block hash"
        )
        if previous_height <= hsd_before["height"]:
            previous_still_canonical = cli.block_hash(previous_height) == previous_hash
        else:
            previous_still_canonical = False

    hsd_after = extract_hsd_info(cli.info())
    hsd_after["source_revision"] = cli.source_revision
    if hsd_after != hsd_before:
        raise ProbeError("HSD tip changed during the comparison probe")
    hsrd_after = extract_hsrd(
        read_http_json(status_url, timeout),
        read_http_json(shadow_url, timeout),
    )
    if hsrd_after != hsrd_before:
        raise ProbeError("hsrd active state changed during the comparison probe")

    return (
        build_observation(
            hsrd_before,
            hsd_before,
            oracle_block_hash,
            oracle_root,
            root_source,
            root_confirmed,
        ),
        previous_still_canonical,
    )


def probe_header_once(hsrd_url: str, cli: HsdCli, timeout: float) -> dict[str, Any]:
    status_url = f"{hsrd_url}/api/v1/status"
    shadow_url = f"{hsrd_url}/api/v1/shadow-sync"
    deployments_url = f"{hsrd_url}/api/v1/header-deployments"
    hsrd_before = extract_hsrd_header(
        read_http_json(status_url, timeout),
        read_http_json(shadow_url, timeout),
    )
    hsrd_deployments_before = extract_hsrd_header_deployments(
        read_http_json(deployments_url, timeout)
    )
    if (
        hsrd_deployments_before["height"] != hsrd_before["height"]
        or hsrd_deployments_before["block_hash"] != hsrd_before["block_hash"]
    ):
        raise ProbeError("hsrd header and deployment diagnostics are not one snapshot")
    hsd_before = extract_hsd_info(cli.info())
    hsd_before["source_revision"] = cli.source_revision
    hsd_chain_before = extract_hsd_blockchain_info(cli.blockchain_info())
    if (
        hsd_chain_before["height"] != hsd_before["height"]
        or hsd_chain_before["block_hash"] != hsd_before["tip"]
        or hsd_chain_before["pruned"] != hsd_before["pruned"]
    ):
        raise ProbeError("HSD info and blockchain RPC are not one snapshot")
    if cli.source_revision != hsrd_before["oracle_revision"]:
        raise ProbeError(
            "pinned HSD source revision does not match hsrd's expected oracle revision"
        )
    if hsrd_before["height"] > hsd_before["height"]:
        raise ProbeError(
            f"HSD oracle height {hsd_before['height']} is behind hsrd best-header "
            f"height {hsrd_before['height']}"
        )

    canonical_hash = cli.block_hash(hsrd_before["height"])
    hsd_deployment_view = dict(hsd_chain_before)
    final_checkpoint = hsrd_deployments_before["final_checkpoint"]
    if final_checkpoint is not None and hsd_before["height"] >= final_checkpoint["height"]:
        hsd_deployment_view["final_checkpoint_hash"] = cli.block_hash(
            final_checkpoint["height"]
        )
    hsd_after = extract_hsd_info(cli.info())
    hsd_after["source_revision"] = cli.source_revision
    if hsd_after != hsd_before:
        raise ProbeError("HSD tip changed during the header comparison probe")
    hsd_chain_after = extract_hsd_blockchain_info(cli.blockchain_info())
    if hsd_chain_after != hsd_chain_before:
        raise ProbeError("HSD deployment state changed during the header comparison probe")
    hsrd_after = extract_hsrd_header(
        read_http_json(status_url, timeout),
        read_http_json(shadow_url, timeout),
    )
    if hsrd_after != hsrd_before:
        raise ProbeError("hsrd best header changed during the header comparison probe")
    hsrd_deployments_after = extract_hsrd_header_deployments(
        read_http_json(deployments_url, timeout)
    )
    if hsrd_deployments_after != hsrd_deployments_before:
        raise ProbeError("hsrd header deployment state changed during the comparison probe")

    caught_up = hsrd_before["height"] == hsd_before["height"]
    deployment_comparison = (
        compare_header_deployments(hsrd_deployments_before, hsd_deployment_view)
        if caught_up
        else None
    )
    header_matched = hsrd_before["block_hash"] == canonical_hash
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "header-sync",
        "observed_at": int(time.time()),
        "matched": header_matched
        and (deployment_comparison is None or deployment_comparison["matched"]),
        "header_matched": header_matched,
        "deployment_parameters_matched": (
            None if deployment_comparison is None else deployment_comparison["parameters_matched"]
        ),
        "deployment_states_matched": (
            None if deployment_comparison is None else deployment_comparison["states_matched"]
        ),
        "deployment_effects_matched": (
            None if deployment_comparison is None else deployment_comparison["effects_matched"]
        ),
        "checkpoint_anchored": (
            None if deployment_comparison is None else deployment_comparison["checkpoint_anchored"]
        ),
        "caught_up": caught_up,
        "network": hsrd_before["network"],
        "height": hsrd_before["height"],
        "block_hash": hsrd_before["block_hash"],
        "hsd_canonical_hash": canonical_hash,
        "received_headers": hsrd_before["received_headers"],
        "hsrd_api_version": hsrd_before["api_version"],
        "hsrd_authority_mode": hsrd_before["authority_mode"],
        "hsrd_runtime_instance": hsrd_before["runtime_instance"],
        "expected_hsd_oracle_revision": hsrd_before["oracle_revision"],
        "hsd_source_revision": hsd_before["source_revision"],
        "hsd_version": hsd_before["version"],
        "hsd_tip_height": hsd_before["height"],
        "hsd_tip_hash": hsd_before["tip"],
        "hsd_pruned": hsd_before["pruned"],
        "header_deployments": hsrd_deployments_before,
        "hsd_softforks": hsd_chain_before["deployments"],
        "scope": (
            "headers-difficulty-time-checkpoints-chainwork-ancestry-"
            "deployments-script-policy"
        ),
    }


def empty_evidence_state() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "sequence": 0,
        "observations": 0,
        "matches": 0,
        "confirmed_matches": 0,
        "template_matches": 0,
        "divergences": 0,
        "reorganizations": 0,
        "hsrd_restarts": 0,
        "highest_compared_height": None,
        "last_observation": None,
        "checkpoint_id": None,
    }


def validate_evidence_state(state: Any) -> dict[str, Any]:
    state = require_object(state, "comparison state")
    if state.get("schema_version") != SCHEMA_VERSION:
        raise ProbeError("comparison state has an unsupported schema version")
    for field in (
        "sequence",
        "observations",
        "matches",
        "confirmed_matches",
        "template_matches",
        "divergences",
        "reorganizations",
        "hsrd_restarts",
    ):
        require_int(state.get(field), f"comparison state {field}")
    if state["sequence"] != state["observations"]:
        raise ProbeError("comparison state sequence/observation counts disagree")
    if state["matches"] + state["divergences"] != state["observations"]:
        raise ProbeError("comparison state match/divergence counts disagree")
    if state["confirmed_matches"] + state["template_matches"] != state["matches"]:
        raise ProbeError("comparison state root-source counts disagree")
    if (
        state["reorganizations"] > state["observations"]
        or state["hsrd_restarts"] > state["observations"]
    ):
        raise ProbeError("comparison state transition counts exceed observations")
    highest = state.get("highest_compared_height")
    if highest is not None:
        require_int(highest, "comparison state highest height")
    last = state.get("last_observation")
    if (last is None) != (state["sequence"] == 0):
        raise ProbeError("comparison state last observation is inconsistent")
    stored_checkpoint_id = state.get("checkpoint_id")
    if state["sequence"] == 0:
        if stored_checkpoint_id is not None:
            raise ProbeError("empty comparison state has a checkpoint checksum")
    else:
        stored_checkpoint_id = normalize_hash(
            stored_checkpoint_id, "comparison state checkpoint id"
        )
        checkpoint_material = dict(state)
        del checkpoint_material["checkpoint_id"]
        if checkpoint_id(checkpoint_material) != stored_checkpoint_id:
            raise ProbeError("comparison state checkpoint checksum is invalid")
    if last is not None:
        last = require_object(last, "comparison state last observation")
        last_height = require_int(last.get("height"), "last observation height")
        if require_int(last.get("sequence"), "last observation sequence") != state["sequence"]:
            raise ProbeError("comparison state last observation sequence disagrees")
        normalize_hash(last.get("block_hash"), "last observation block hash")
        stored_id = normalize_hash(last.get("observation_id"), "last observation id")
        id_material = dict(last)
        del id_material["observation_id"]
        if observation_id(id_material) != stored_id:
            raise ProbeError("comparison state last observation checksum is invalid")
        require_string(last.get("hsrd_runtime_instance"), "last hsrd runtime instance")
        if highest is None or highest < last_height:
            raise ProbeError("comparison state highest height is inconsistent")
    return state


def load_evidence_state(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return empty_evidence_state()
    if path.is_symlink() or not path.is_file():
        raise ProbeError(f"comparison state path is not a regular file: {path}")
    if path.stat().st_size > MAX_STATE_BYTES:
        raise ProbeError(f"comparison state exceeds {MAX_STATE_BYTES} bytes")
    try:
        with path.open("r", encoding="utf-8") as file:
            return validate_evidence_state(json.load(file))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProbeError(f"cannot load comparison state {path}: {exc}") from exc


def observation_id(observation: dict[str, Any]) -> str:
    encoded = json.dumps(
        observation, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.blake2b(encoded, digest_size=32).hexdigest()


def checkpoint_id(state: dict[str, Any]) -> str:
    encoded = json.dumps(
        state, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.blake2b(encoded, digest_size=32).hexdigest()


def advance_evidence_state(
    state: dict[str, Any],
    observation: dict[str, Any],
    previous_still_canonical: bool | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    state = validate_evidence_state(dict(state))
    previous = state.get("last_observation")
    sequence = state["sequence"] + 1
    reorganization = False
    restart = False
    previous_id = None
    if previous is not None:
        previous_id = previous["observation_id"]
        reorganization = (
            previous_still_canonical is False
            or observation["height"] < previous["height"]
            or (
                observation["height"] == previous["height"]
                and observation["block_hash"] != previous["block_hash"]
            )
        )
        restart = (
            observation["hsrd_runtime_instance"]
            != previous["hsrd_runtime_instance"]
        )

    recorded = dict(observation)
    recorded["sequence"] = sequence
    recorded["previous_observation_id"] = previous_id
    recorded["reorganization_observed"] = reorganization
    recorded["hsrd_restart_observed"] = restart
    recorded["observation_id"] = observation_id(recorded)

    state["sequence"] = sequence
    state["observations"] += 1
    if recorded["matched"]:
        state["matches"] += 1
        if recorded["root_confirmed_by_next_header"]:
            state["confirmed_matches"] += 1
        else:
            state["template_matches"] += 1
    else:
        state["divergences"] += 1
    if reorganization:
        state["reorganizations"] += 1
    if restart:
        state["hsrd_restarts"] += 1
    highest = state["highest_compared_height"]
    state["highest_compared_height"] = (
        recorded["height"] if highest is None else max(highest, recorded["height"])
    )
    state["last_observation"] = recorded
    checkpoint_material = dict(state)
    del checkpoint_material["checkpoint_id"]
    state["checkpoint_id"] = checkpoint_id(checkpoint_material)
    return state, recorded


def write_evidence_state(path: Path, state: dict[str, Any]) -> None:
    parent = path.parent
    if not parent.is_dir():
        raise ProbeError(f"comparison state parent does not exist: {parent}")
    if path.exists() and path.is_symlink():
        raise ProbeError(f"comparison state path is a symlink: {path}")
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as file:
            temporary_name = file.name
            os.chmod(temporary_name, 0o600)
            json.dump(state, file, sort_keys=True, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_name, path)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
        raise ProbeError(f"cannot commit comparison state {path}: {exc}") from exc


def normalize_hsrd_url(value: str, allow_remote: bool) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ProbeError("--hsrd-url must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ProbeError("--hsrd-url must not contain credentials, a query, or a fragment")
    if parsed.path not in {"", "/"}:
        raise ProbeError("--hsrd-url must not contain a path")
    if not allow_remote:
        host = parsed.hostname
        loopback = host == "localhost"
        if not loopback:
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = False
        if not loopback:
            raise ProbeError(
                "remote hsrd diagnostics require the explicit --allow-remote-hsrd acknowledgement"
            )
    return value.rstrip("/")


def validate_hsd_source(source: Path, executable: Path, timeout: float) -> str:
    if not source.is_absolute() or not source.is_dir():
        raise ProbeError("--hsd-source must name an absolute directory")
    resolved_source = source.resolve()
    resolved_executable = executable.resolve()
    try:
        resolved_executable.relative_to(resolved_source)
    except ValueError as exc:
        raise ProbeError("--hsd-cli must be contained by --hsd-source") from exc

    def git(arguments: list[str]) -> str:
        try:
            completed = subprocess.run(
                ["git", "-C", str(resolved_source), *arguments],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProbeError(f"failed to inspect HSD source: {exc}") from exc
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise ProbeError(f"failed to inspect HSD source: {detail[:1000]}")
        return completed.stdout.strip()

    revision = git(["rev-parse", "--verify", "HEAD"])
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ProbeError("HSD source revision is not a canonical 40-character commit")
    tracked_status = git(["status", "--porcelain=v1", "--untracked-files=no"])
    if tracked_status:
        raise ProbeError("HSD source has tracked modifications and is not a pinned oracle")
    return revision


def self_test() -> None:
    marker = lambda byte: f"{byte:02x}" * 32
    status = {
        "api_version": MINIMUM_HSRD_API_VERSION,
        "network": "mainnet",
        "height": 100,
        "best_block_hash": [1] * 32,
        "active_state_resulting_root": marker(2),
        "active_state_resulting_root_height": 100,
        "active_state_sync_enabled": True,
        "chain_epoch": 7,
        "mining_generation": 8,
        "authority": {
            "mode": "shadow",
            "can_authorize_mining_templates": False,
        },
        "parity": {"oracle_revision": marker(3)[:40]},
    }
    shadow = {
        "enabled": True,
        "active_state": True,
        "observation_only": False,
        "runtime_instance": "runtime-a",
        "sync": {"active_tip": {"hash": [1] * 32, "height": 100}},
    }
    extracted = extract_hsrd(status, shadow)
    assert extracted["block_hash"] == marker(1)
    assert extracted["resulting_root"] == marker(2)

    header_status = dict(status)
    header_status["best_header_height"] = 101
    header_status["best_header_hash"] = [4] * 32
    header_shadow = {
        "enabled": True,
        "headers_only": True,
        "runtime_instance": "runtime-header",
        "received_headers": 100,
        "sync": {"best_header": {"hash": [4] * 32, "height": 101}},
    }
    header_extracted = extract_hsrd_header(header_status, header_shadow)
    assert header_extracted["height"] == 101
    assert header_extracted["block_hash"] == marker(4)
    assert header_extracted["received_headers"] == 100

    header_deployments = extract_hsrd_header_deployments(
        {
            "best_header": {"hash": [4] * 32, "height": 101, "chainwork": [5] * 32},
            "next_height": 102,
            "deployments": [
                {
                    "name": "hardening",
                    "state": "FAILED",
                    "bit": 0,
                    "start_time": 1,
                    "timeout": 2,
                },
                {
                    "name": "icannlockup",
                    "state": "ACTIVE",
                    "bit": 1,
                    "start_time": 3,
                    "timeout": 4,
                },
                {
                    "name": "airstop",
                    "state": "ACTIVE",
                    "bit": 2,
                    "start_time": 5,
                    "timeout": 6,
                },
            ],
            "script_flags": 50,
            "lock_flags": 0,
            "name_flags": 2,
            "has_airstop": True,
            "next_block_version": 0,
            "final_checkpoint": {
                "height": 100,
                "hash": [6] * 32,
                "anchored": True,
            },
            "historical_script_assumption_through": 100,
        }
    )
    hsd_deployments = extract_hsd_blockchain_info(
        {
            "blocks": 101,
            "headers": 101,
            "bestblockhash": marker(4),
            "pruned": True,
            "softforks": {
                "hardening": {
                    "status": "failed",
                    "bit": 0,
                    "startTime": 1,
                    "timeout": 2,
                },
                "icannlockup": {
                    "status": "active",
                    "bit": 1,
                    "startTime": 3,
                    "timeout": 4,
                },
                "airstop": {
                    "status": "active",
                    "bit": 2,
                    "startTime": 5,
                    "timeout": 6,
                },
            },
        }
    )
    hsd_deployments["final_checkpoint_hash"] = marker(6)
    deployment_comparison = compare_header_deployments(
        header_deployments, hsd_deployments
    )
    assert deployment_comparison["matched"]
    mismatched_deployments = dict(header_deployments)
    mismatched_deployments["script_flags"] = 0
    assert not compare_header_deployments(
        mismatched_deployments, hsd_deployments
    )["matched"]
    mismatched_checkpoint = dict(hsd_deployments)
    mismatched_checkpoint["final_checkpoint_hash"] = marker(7)
    assert not compare_header_deployments(
        header_deployments, mismatched_checkpoint
    )["checkpoint_anchored"]

    hsrd = {
        "api_version": MINIMUM_HSRD_API_VERSION,
        "network": "mainnet",
        "height": 100,
        "block_hash": marker(1),
        "resulting_root": marker(2),
        "chain_epoch": 7,
        "mining_generation": 8,
        "authority_mode": "shadow",
        "runtime_instance": "runtime-a",
        "oracle_revision": marker(3)[:40],
    }
    hsd = {
        "version": "8.99.0",
        "source_revision": marker(3)[:40],
        "network": "main",
        "height": 101,
        "tip": marker(4),
        "pruned": True,
    }
    matched = build_observation(
        hsrd, hsd, marker(1), marker(2), "next-header", True
    )
    assert matched["matched"]
    assert matched["root_confirmed_by_next_header"]

    divergent = build_observation(
        hsrd, hsd, marker(9), marker(8), "next-header", True
    )
    assert not divergent["matched"]
    assert {item["field"] for item in divergent["mismatches"]} == {
        "active_block_hash",
        "active_state_resulting_root",
    }
    assert normalize_hash([1] * 32, "array hash") == marker(1)

    state, first = advance_evidence_state(empty_evidence_state(), matched, None)
    assert state["confirmed_matches"] == 1
    assert first["sequence"] == 1
    assert not first["reorganization_observed"]
    assert not first["hsrd_restart_observed"]

    next_match = dict(matched)
    next_match["height"] = 101
    next_match["block_hash"] = marker(5)
    next_match["root_source"] = "next-template"
    next_match["root_confirmed_by_next_header"] = False
    next_match["hsrd_runtime_instance"] = "runtime-b"
    state, second = advance_evidence_state(state, next_match, False)
    assert state["template_matches"] == 1
    assert state["reorganizations"] == 1
    assert state["hsrd_restarts"] == 1
    assert second["previous_observation_id"] == first["observation_id"]
    assert second["reorganization_observed"]
    assert second["hsrd_restart_observed"]
    validate_evidence_state(state)
    corrupt = json.loads(json.dumps(state))
    corrupt["last_observation"]["height"] += 1
    try:
        validate_evidence_state(corrupt)
    except ProbeError:
        pass
    else:
        raise AssertionError("corrupt evidence checkpoint was accepted")

    try:
        build_observation(
            hsrd,
            {**hsd, "network": "regtest"},
            marker(1),
            marker(2),
            "next-header",
            True,
        )
    except ProbeError:
        pass
    else:
        raise AssertionError("network mismatch was accepted")
    print("hsrd/HSD shadow comparison self-test passed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hsrd-url", help="hsrd diagnostic base URL, without a path")
    parser.add_argument("--hsd-cli", help="absolute path to the pinned hsd-cli executable")
    parser.add_argument("--hsd-source", help="absolute path to the pinned HSD source tree")
    parser.add_argument(
        "--hsd-cli-arg",
        action="append",
        default=[],
        help="argument inserted before the hsd-cli command; repeat as needed",
    )
    parser.add_argument("--state-file", type=Path, help="optional bounded evidence checkpoint")
    parser.add_argument(
        "--samples",
        type=int,
        default=1,
        help="number of comparisons; zero follows indefinitely",
    )
    parser.add_argument("--interval-seconds", type=float, default=15.0)
    parser.add_argument("--maximum-attempts", type=int, default=3)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    parser.add_argument("--allow-remote-hsrd", action="store_true")
    parser.add_argument(
        "--headers-only",
        action="store_true",
        help="compare hsrd's best header without requiring active-state sync",
    )
    parser.add_argument(
        "--require-current-tip",
        action="store_true",
        help="in headers-only mode, fail unless hsrd reached the coherent HSD tip",
    )
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.hsrd_url or not args.hsd_cli or not args.hsd_source:
        error(
            "--hsrd-url, --hsd-cli, and --hsd-source are required unless --self-test is used"
        )
    if args.samples < 0:
        error("--samples must be non-negative")
    if not 1 <= args.maximum_attempts <= 20:
        error("--maximum-attempts must be within 1..=20")
    if not 0 < args.timeout_seconds <= 300:
        error("--timeout-seconds must be within (0, 300]")
    if args.interval_seconds < 0:
        error("--interval-seconds must be non-negative")
    if args.samples != 1 and args.interval_seconds < 0.1:
        error("multi-sample comparison requires --interval-seconds >= 0.1")
    if args.require_current_tip and not args.headers_only:
        error("--require-current-tip requires --headers-only")
    if args.headers_only and args.state_file is not None:
        error("--state-file records active-state evidence and cannot be used with --headers-only")

    try:
        hsrd_url = normalize_hsrd_url(args.hsrd_url, args.allow_remote_hsrd)
        executable = Path(args.hsd_cli)
        if (
            not executable.is_absolute()
            or not executable.is_file()
            or not os.access(executable, os.X_OK)
        ):
            raise ProbeError("--hsd-cli must name an absolute executable file")
        source_revision = validate_hsd_source(
            Path(args.hsd_source), executable, args.timeout_seconds
        )
        state_file = args.state_file
        if state_file is not None:
            state_file = state_file.expanduser()
            if not state_file.is_absolute():
                raise ProbeError("--state-file must be an absolute path")
            state_file = state_file.parent.resolve() / state_file.name
        state = load_evidence_state(state_file) if not args.headers_only else None
        cli = HsdCli(
            executable,
            list(args.hsd_cli_arg),
            args.timeout_seconds,
            source_revision,
        )
    except ProbeError as exc:
        error(str(exc))

    completed_samples = 0
    while args.samples == 0 or completed_samples < args.samples:
        previous = state.get("last_observation") if state is not None else None
        last_error = None
        for attempt in range(args.maximum_attempts):
            try:
                if args.headers_only:
                    observation = probe_header_once(
                        hsrd_url,
                        cli,
                        args.timeout_seconds,
                    )
                    previous_canonical = None
                else:
                    observation, previous_canonical = probe_once(
                        hsrd_url,
                        cli,
                        args.timeout_seconds,
                        previous,
                    )
                break
            except ProbeError as exc:
                last_error = exc
                if attempt + 1 < args.maximum_attempts:
                    time.sleep(min(0.25 * (2**attempt), 2.0))
        else:
            print(
                json.dumps(
                    {"status": "probe-error", "error": str(last_error)},
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 2

        if args.headers_only:
            recorded = observation
        else:
            try:
                next_state, recorded = advance_evidence_state(
                    state, observation, previous_canonical
                )
                if state_file is not None:
                    write_evidence_state(state_file, next_state)
                state = next_state
            except ProbeError as exc:
                print(
                    json.dumps(
                        {"status": "state-error", "error": str(exc)}, sort_keys=True
                    ),
                    file=sys.stderr,
                )
                return 2

        print(json.dumps(recorded, sort_keys=True, separators=(",", ":")), flush=True)
        if not recorded["matched"]:
            return 1
        if args.require_current_tip and not recorded["caught_up"]:
            return 1
        completed_samples += 1
        if args.samples == 0 or completed_samples < args.samples:
            time.sleep(args.interval_seconds)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
