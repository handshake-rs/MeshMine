#!/usr/bin/env python3
"""Compiler-independent operator-service invariant validation."""

from pathlib import Path
import hashlib
import json
import struct
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"operator-service source validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(path: str, needles: tuple[str, ...]) -> None:
    file = ROOT / path
    if not file.is_file():
        fail(f"missing {path}")
    text = file.read_text(encoding="utf-8")
    for needle in needles:
        if needle not in text:
            fail(f"{path} is missing {needle!r}")


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        out.append(byte)
        if not value:
            return bytes(out)


def domain_hash(domain: bytes, body: bytes) -> bytes:
    return hashlib.blake2b(varint(len(domain)) + domain + body, digest_size=32).digest()


def receipt_id(receipt: dict) -> bytes:
    body = struct.pack("<H", receipt["version"])
    body += bytes([receipt["network_id"]])
    for field in ("work_key", "downstream_id", "core_context_id"):
        value = bytes(receipt[field])
        if len(value) != 32 or value == bytes(32):
            fail(f"receipt example {field} is not a nonzero 32-byte value")
        body += value
    body += struct.pack("<Q", receipt["admitted_at_ms"])
    public_key = bytes(receipt["core_receipt_pubkey"])
    if len(public_key) != 32 or public_key == bytes(32):
        fail("receipt example Core public key is invalid")
    body += public_key
    body += struct.pack("<H", receipt["signature_suite"])
    return domain_hash(b"meshmine/operator-core-capture-receipt/v1", body)


def main() -> None:
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    members = set(workspace["workspace"]["members"])
    for member in ("crates/meshmine-service", "bins/meshmine-operatord"):
        if member not in members:
            fail(f"workspace omits {member}")

    require(
        "crates/meshmine-service/src/supervisor.rs",
        (
            "pub enum ServiceMode",
            "Fallback",
            "minimum_fallback_hold_ms",
            "healthy_samples_before_restore",
            "capture_backlog_hard_limit",
            "CredentialUnavailable",
        ),
    )
    require(
        "crates/meshmine-service/src/receipt.rs",
        (
            "CoreCaptureReceiptV1",
            "ACK-only consumer",
            "canonical_id",
            "CORE_CAPTURE_RECEIPT_NAMESPACE",
            "put_if_absent",
            "verify_object",
            "UntrustedSigner",
        ),
    )
    require(
        "crates/meshmine-service/src/journal.rs",
        (
            "ServiceEventJournal",
            "apply_batch_if",
            "SERVICE_EVENT_NAMESPACE",
            "MAX_SERVICE_EVENT_CAPACITY",
            "MAX_READ_RETRIES",
            "MAX_APPEND_RETRIES",
        ),
    )
    require(
        "crates/meshmine-service/src/schema.rs",
        (
            "initialize_service_store",
            "apply_batch_if_all",
            "SERVICE_SCHEMA_VERSION",
            "SERVICE_PROFILE",
            "IncompatibleTrustBinding",
        ),
    )
    require(
        "crates/meshmine-service/src/dashboard.rs",
        (
            "OperatorSnapshot",
            "OperatorCountersView",
            "Authority boundary",
            "gateway_listener_alive",
        ),
    )
    require(
        "crates/meshmine-gateway/src/lib.rs",
        (
            "serve_rpc_connection_shared",
            "connection_epoch",
            "rotate_connections",
            "GatewayStatus",
            "drain_events",
            "SharedRpcControl",
        ),
    )
    require(
        "bins/meshmine-operatord/src/main.rs",
        (
            "PRODUCTION_ELIGIBLE: bool = false",
            "import-core-receipt",
            "validate_loopback",
            "drain_captures_durably",
            "rotate_connections",
            '"/api/v1/status"',
            '"/api/v1/health"',
            "gateway_listener_alive",
            "credentials_available",
            "initialize_service_store",
            "core_receipt_pubkey",
        ),
    )
    require(
        "scripts/verify-operator-receipt-fixture.js",
        (
            "operator signed Core receipt fixture verification passed",
            "meshmine/signature-context/v2",
            "crypto.verify",
        ),
    )
    require(
        "docs/operator-service.md",
        (
            "ACK-only reconciler",
            "safe modes",
            "loopback",
            "Current limitations",
        ),
    )

    example = ROOT / "specs/operator-service.example.json"
    try:
        config = json.loads(example.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot parse operator-service example: {error}")
    if config.get("production") is not False:
        fail("operator-service example must remain pre-production")
    for key in ("gateway_listen", "dashboard_listen"):
        if not str(config.get(key, "")).startswith("127.0.0.1:"):
            fail(f"{key} is not loopback-only")
    for key in ("gateway_state", "service_state", "job_file", "password_file"):
        if not str(config.get(key, "")).startswith("/"):
            fail(f"{key} is not absolute")
    try:
        configured_core_key = bytes.fromhex(str(config["core_receipt_pubkey"]))
    except (KeyError, ValueError) as error:
        fail(f"operator Core receipt key is invalid: {error}")
    if len(configured_core_key) != 32 or configured_core_key == bytes(32):
        fail("operator Core receipt key is not a nonzero 32-byte key")
    if not isinstance(config.get("network_id"), int) or not 0 <= config["network_id"] <= 255:
        fail("operator network_id is not a byte")

    receipt_path = ROOT / "specs/core-capture-receipt.example.json"
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot parse Core receipt example: {error}")
    expected = receipt_id(receipt)
    if bytes(receipt.get("receipt_id", [])) != expected:
        fail("Core receipt example has an invalid canonical receipt_id")
    if bytes(receipt.get("core_receipt_pubkey", [])) != configured_core_key:
        fail("Core receipt example does not use the configured trusted key")
    if receipt.get("network_id") != config["network_id"]:
        fail("Core receipt example does not use the configured network")
    if receipt.get("signature_suite") != 1 or len(receipt.get("core_signature", [])) != 64:
        fail("Core receipt example does not contain one Ed25519 signature")

    binary = (ROOT / "bins/meshmine-operatord/src/main.rs").read_text(encoding="utf-8")
    if "POST /api" in binary or 'method == "POST"' in binary:
        fail("operator dashboard unexpectedly exposes a mutation endpoint")
    if "record-core-receipt" in binary:
        fail("unsafe raw receipt recording command remains")
    if "gateway_available: true" in binary:
        fail("gateway health is hard-coded instead of listener-derived")

    print("operator-service source validation passed")


if __name__ == "__main__":
    main()
