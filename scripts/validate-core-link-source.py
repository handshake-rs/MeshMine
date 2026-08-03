#!/usr/bin/env python3
"""Offline structural checks for the authenticated Core-link foundation."""
from __future__ import annotations
import json
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
required = {
    'crates/meshmine-core-link/src/admission.rs': [
        'CoreAdmissionEngine', 'accept_gateway_durable',
        'persist_noncredit_capture_disposition', 'complete_pending_transition',
        'CORE_BUNDLE_ACTIVE_KEY', 'CORE_BUNDLE_PENDING_KEY',
    ],
    'crates/meshmine-core-link/src/bundle.rs': [
        'CoreAssignmentBundleV1', 'pinned Core handoff identity',
        'previous_job_transition',
    ],
    'crates/meshmine-core-link/src/client.rs': [
        'OperatorCoreLinkClient', 'DurableCaptureConsumer',
        'complete_drain', 'prepare_envelope', 'terminal_receipt_id',
    ],
    'crates/meshmine-core-link/src/protocol.rs': [
        'CoreLinkServerChallengeV1', 'CaptureSubmissionV1',
        'DrainSubmissionV1', 'MAX_CORE_LINK_FRAME_BYTES',
    ],
    'crates/meshmine-core-link/src/spool.rs': [
        'OperatorCaptureSpool', 'GatewaySequenceHeadV1',
        'OperatorCaptureCapacityV1', 'OPERATOR_CAPTURE_CAPACITY_NAMESPACE',
        'persist_drain_and_transition', 'validate_capture_assignment',
        'validate_capture_context', 'miner_header.share_hash()',
        'assignment.accepts_extra_nonce',
        'BatchOperation::delete(OPERATOR_CAPTURE_ENVELOPE_NAMESPACE',
    ],
    'crates/meshmine-core-link/src/transport.rs': [
        'SO_PEERCRED', 'authenticate_server', 'authenticate_client',
        'FRAME_CHECKSUM_BYTES', 'receive_sequence',
    ],
    'bins/meshmine-cored/src/main.rs': [
        'stage-bundle', 'LiveParentOracle', 'bind_secure_listener',
        'production=false', 'parent_oracle_file',
        'hsrd RPC authorization header',
    ],
    'bins/meshmine-corelink-operatord/src/main.rs': [
        'connect_authenticated', 'drain_captures_durably',
        'issue_authorized_job', 'authorized_assignment_nonce_prefix',
        'RpcSession::new_authorized', 'production=false',
        'Supervisor', 'dashboard_html',
    ],
}
for relative, needles in required.items():
    path = root / relative
    if not path.is_file():
        raise SystemExit(f'missing Core-link source: {relative}')
    text = path.read_text()
    for needle in needles:
        if needle not in text:
            raise SystemExit(f'{relative} is missing required token: {needle}')

workspace = tomllib.loads((root / 'Cargo.toml').read_text())['workspace']['members']
for member in (
    'crates/meshmine-core-link', 'crates/meshmine-parent-oracle',
    'bins/meshmine-cored', 'bins/meshmine-corelink-operatord',
):
    if member not in workspace:
        raise SystemExit(f'workspace omits {member}')
lock = (root / 'Cargo.lock').read_text()
for package in (
    'meshmine-core-link', 'meshmine-parent-oracle',
    'meshmine-cored', 'meshmine-corelink-operatord',
):
    if f'name = "{package}"' not in lock:
        raise SystemExit(f'Cargo.lock omits {package}')

combined = '\n'.join((root / relative).read_text() for relative in required)
for forbidden in (
    'production: true',
    'TcpListener::bind(core',
    'accept_all_parents',
    'allow_unverified_capture',
    'AllowlistedParentOracle',
):
    if forbidden in combined:
        raise SystemExit(f'forbidden Core-link shortcut found: {forbidden}')

operator = (root / 'bins/meshmine-corelink-operatord/src/main.rs').read_text()
if '.assignment_nonce_prefix(' in operator:
    raise SystemExit('Core-linked operator uses the test nonce-prefix allocator')

for example in (
    'specs/core-link-core.example.json',
    'specs/core-link-operator.example.json',
    'specs/core-link-parent-oracle.example.json',
):
    with (root / example).open('rb') as handle:
        json.load(handle)

obsolete = root / 'specs/core-link-parent-allowlist.example.json'
if obsolete.exists():
    raise SystemExit('obsolete parent allowlist example remains present')

print('authenticated Core-link source validation passed')
