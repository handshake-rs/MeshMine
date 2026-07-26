#!/usr/bin/env python3
"""Fail-closed structural checks for live-parent and unified supervision."""
from __future__ import annotations
import json
import subprocess
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
expected_node_revision = '504d3fed035feb8a637ca09c4e0816b6e1144622'
expected_node_source = (
    'git+https://github.com/handshake-rs/hns-node-rs.git'
    f'?rev={expected_node_revision}#{expected_node_revision}'
)


def canonical_node_package_roots() -> dict[str, Path]:
    try:
        completed = subprocess.run(
            [
                'cargo', 'metadata', '--locked', '--offline',
                '--format-version', '1',
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
        metadata = json.loads(completed.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        details = getattr(error, 'stderr', '') or str(error)
        raise SystemExit(
            f'cannot resolve canonical hns-node-rs packages: {details.strip()}'
        )
    wanted = {'hns-node', 'hns-rpc'}
    packages = {
        package.get('name'): package
        for package in metadata.get('packages', [])
        if isinstance(package, dict) and package.get('name') in wanted
    }
    missing = sorted(wanted - packages.keys())
    if missing:
        raise SystemExit(
            'canonical hns-node-rs packages are missing: ' + ', '.join(missing)
        )
    roots: dict[str, Path] = {}
    for name, package in packages.items():
        source = package.get('source')
        if source != expected_node_source:
            raise SystemExit(
                f'{name} resolves from {source!r}, expected {expected_node_source!r}'
            )
        roots[name] = Path(package['manifest_path']).resolve().parent
    return roots


node_package_roots = canonical_node_package_roots()
external_files = {
    '../hns-node-rs/crates/hns-node/src/lib.rs':
        node_package_roots['hns-node'] / 'src/lib.rs',
    '../hns-node-rs/crates/hns-node/src/shadow_sync.rs':
        node_package_roots['hns-node'] / 'src/shadow_sync.rs',
    '../hns-node-rs/crates/hns-rpc/src/lib.rs':
        node_package_roots['hns-rpc'] / 'src/lib.rs',
}
files = {
    'crates/meshmine-parent-oracle/src/lib.rs': [
        'LiveParentOracle', 'ParentRpcSource', 'LiveParentPolicy',
        'verify_header_and_chainwork', 'getparentauthority',
        'confirmations', 'maximum_certificate_depth', 'maximum_header_age',
        'rpc_authentication_required', 'consensus_complete',
        'ParentConsensusReadinessView', 'readiness.complete()',
        'mainnet_canary_enabled', 'mainnet_canary_active',
        'MAX_MAINNET_CANARY_HEADER_AGE', 'MAX_MAINNET_CANARY_CACHE_TTL',
        'can_authorize_mining_templates', 'is_loopback', 'connect_timeout',
        'Content-Length', 'transfer-encoding', 'Noncanonical',
        'AuthorityUnavailable', 'qualify_active',
        'authenticated_native_hsrd_active_tip_qualification_passes',
        'active_tip_qualification_rejects_a_deep_canonical_parent',
        'mainnet_requires_the_explicit_synchronized_hsrd_canary_gate',
    ],
    '../hns-node-rs/crates/hns-node/src/lib.rs': [
        'RpcAuthorizationHeader', 'serve_rpc_listener_with_authorization',
        'require_rpc_authorization', 'rpc_authentication_required',
        'rpc_authorization_rejects_missing_and_wrong_values',
    ],
    '../hns-node-rs/crates/hns-node/src/shadow_sync.rs': [
        'parent_authority_value', 'getparentauthority',
        'best_block_tip_from_snapshot', 'read_canonical_hash',
        'parent_authority_fast_path_is_coherent_and_fail_closed',
    ],
    '../hns-node-rs/crates/hns-rpc/src/lib.rs': [
        'GetParentAuthority', 'getparentauthority',
        'parent_authority_is_one_coherent_snapshot',
    ],
    'crates/meshmine-hsrd-bridge/src/lib.rs': [
        'AuthoritativeHsrdMiningStream', 'subscribe_mining_events',
        'HsrdGatewayActivationRequest', 'activate_gateway_job',
        'gateway.durable_store()', 'reconcile_authoritative_tip',
        'HsrdGatewayTipReconciliation', 'borrow_and_update',
        'AuthorityStreamClosed', 'StaleAuthority',
        'exact_native_job_is_durably_bound_and_activated_idempotently',
        'authoritative_tip_reconciliation_retires_stale_asic_work',
    ],
    'bins/meshmine-cored/src/main.rs': [
        'parent_oracle_file', 'load_parent_oracle', 'ensure_active_parent',
        'active_parent_qualification', 'pending_parent_qualification',
        'MAX_PARENT_REQUALIFICATION_INTERVAL_MS', 'qualify_active',
        'oracle.qualify_active(&active.parent_certificate)',
        'oracle.qualify_active(&pending.parent_certificate)',
        'production=false',
    ],
    'bins/meshmine-corelink-operatord/src/main.rs': [
        'Supervisor::new', 'ServiceEventJournal', 'dashboard_html',
        'connect_authenticated', 'reconnect_initial_ms', 'reconnect_maximum_ms',
        'let core_ready = core_connected && !expect_authoritative_active_offer;',
        'core_link_available: core_ready', 'drain_pending', 'set_fallback(true)',
        'spawn_shutdown_watcher', 'GRACEFUL_SHUTDOWN_TIMEOUT',
        'authorized_assignment_nonce_prefix', 'RpcSession::new_authorized',
        'production=false',
    ],
    'crates/meshmine-service/src/supervisor.rs': [
        'SERVICE_SCHEMA_VERSION: u16 = 3', 'meshmine-operator-v9',
        'CoreLinkUnavailable', 'AssignmentDrainPending',
        'core_link_available', 'drain_pending',
    ],
    'crates/meshmine-service/src/dashboard.rs': [
        'core_link_connected', 'active_bundle_id', 'pending_bundle_id',
        'assignment_drain_pending', 'Core link', 'Assignment drain',
    ],
}
for relative, needles in files.items():
    path = external_files.get(relative, root / relative)
    if not path.is_file():
        raise SystemExit(f'missing live-parent/unified-operator source: {relative}')
    text = path.read_text()
    for needle in needles:
        if needle not in text:
            raise SystemExit(f'{relative} is missing live-parent/unified-operator token: {needle}')

parent = (root / 'crates/meshmine-parent-oracle/src/lib.rs').read_text()
for forbidden in (
    '0.0.0.0', '[::]:', 'reqwest', 'hyper', 'ureq', 'danger_accept_invalid',
    'request.push_str("Transfer-Encoding', 'qualified: result.is_ok()',
    'ParentSourceKind', 'require_hsrd_match', 'ShadowDisagreement',
):
    if forbidden in parent:
        raise SystemExit(f'forbidden parent-oracle shortcut found: {forbidden}')

operator = (root / 'bins/meshmine-corelink-operatord/src/main.rs').read_text()
for forbidden in (
    'production: true', 'core_link_available: true', 'shutdown_requested: false',
    '.assignment_nonce_prefix(',
):
    if forbidden in operator:
        raise SystemExit(f'forbidden unified-operator shortcut found: {forbidden}')

core_config = json.loads((root / 'specs/core-link-core.example.json').read_text())
operator_config = json.loads((root / 'specs/core-link-operator.example.json').read_text())
parent_config = json.loads((root / 'specs/core-link-parent-oracle.example.json').read_text())
if core_config.get('schema_version') != 2 or core_config.get('production') is not False:
    raise SystemExit('Core example must be schema 2 and pre-production')
if operator_config.get('schema_version') != 2 or operator_config.get('production') is not False:
    raise SystemExit('operator example must be schema 2 and pre-production')
if parent_config.get('schema_version') != 2:
    raise SystemExit('parent-oracle example must use schema 2')
if 'parent_oracle_file' not in core_config or 'parent_allowlist_file' in core_config:
    raise SystemExit('Core example does not use the live parent-oracle file')
for listener in ('gateway_listen', 'dashboard_listen'):
    value = operator_config.get(listener, '')
    if not (value.startswith('127.0.0.1:') or value.startswith('[::1]:')):
        raise SystemExit(f'{listener} must be loopback in the example')
if 'hsd' in parent_config or set(parent_config).intersection(
    {'require_hsrd_match', 'maximum_tip_lag_blocks'}
):
    raise SystemExit('parent-oracle example retains a runtime HSD/shadow field')
source = parent_config.get('hsrd', {})
address = source.get('address', '')
if not (address.startswith('127.0.0.1:') or address.startswith('[::1]:')):
    raise SystemExit('hsrd RPC source must be loopback')
authorization_file = source.get('authorization_header_file')
if not isinstance(authorization_file, str) or not authorization_file.startswith('/'):
    raise SystemExit('hsrd RPC source requires an absolute authorization-header file')

workspace = tomllib.loads((root / 'Cargo.toml').read_text())['workspace']['members']
if 'crates/meshmine-parent-oracle' not in workspace:
    raise SystemExit('workspace omits meshmine-parent-oracle')
lock = tomllib.loads((root / 'Cargo.lock').read_text())
packages = {package['name']: package for package in lock['package']}
if 'meshmine-parent-oracle' not in packages:
    raise SystemExit('Cargo.lock omits meshmine-parent-oracle')
if 'meshmine-parent-oracle' not in packages['meshmine-cored'].get('dependencies', []):
    raise SystemExit('meshmine-cored lock entry omits meshmine-parent-oracle')
for dependency in ('hns-node', 'meshmine-gateway', 'meshmine-handoff'):
    if dependency not in packages['meshmine-hsrd-bridge'].get('dependencies', []):
        raise SystemExit(f'meshmine-hsrd-bridge lock entry omits {dependency}')
if 'meshmine-service' not in packages['meshmine-corelink-operatord'].get('dependencies', []):
    raise SystemExit('unified operator lock entry omits meshmine-service')
if 'tokio' not in packages['meshmine-corelink-operatord'].get('dependencies', []):
    raise SystemExit('unified operator lock entry omits bounded signal runtime')

print('live-parent and unified-supervisor source validation passed')
