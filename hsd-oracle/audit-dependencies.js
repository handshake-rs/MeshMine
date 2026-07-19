#!/usr/bin/env node
'use strict';

const assert = require('assert');
const {spawnSync} = require('child_process');

const result = spawnSync(
  'npm',
  ['audit', '--audit-level=moderate', '--json'],
  {
    cwd: __dirname,
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe']
  }
);

if (result.error)
  throw result.error;

let report;
try {
  report = JSON.parse(result.stdout);
} catch (error) {
  const detail = result.stderr.trim().slice(0, 512);
  throw new Error(`npm audit did not return bounded JSON: ${detail}`, {cause: error});
}

assert.strictEqual(report.auditReportVersion, 2);
const vulnerabilities = report.vulnerabilities || {};
const names = Object.keys(vulnerabilities).sort();

if (names.length === 0) {
  assert.strictEqual(result.status, 0);
  console.log('npm dependency audit found no advisories');
  process.exit(0);
}

// hsd's pinned dependency graph has one unpatched upstream advisory. It is in
// bsock's vendored WebSocket handshake, while MeshMine's oracle processes are
// isolated, loopback-only test subprocesses and do not expose that transport.
// Keep this exception exact and fail closed if npm reports any other package,
// advisory URL, dependency path, count, or severity.
const allowedNames = ['bcurl', 'bsock', 'bweb', 'hsd'];
assert.deepStrictEqual(names, allowedNames);
assert.strictEqual(result.status, 1);

const bsock = vulnerabilities.bsock;
assert.strictEqual(bsock.name, 'bsock');
assert.strictEqual(bsock.severity, 'critical');
assert.strictEqual(bsock.fixAvailable, false);
assert.strictEqual(bsock.via.length, 1);
assert.strictEqual(
  bsock.via[0].url,
  'https://github.com/advisories/GHSA-jj93-39pf-7mcf'
);
assert.strictEqual(bsock.via[0].name, 'bsock');

for (const name of ['bcurl', 'bweb', 'hsd']) {
  const item = vulnerabilities[name];
  assert.strictEqual(item.name, name);
  assert.strictEqual(item.severity, 'critical');
  assert(item.via.every((dependency) =>
    typeof dependency === 'string' && allowedNames.includes(dependency)));
}
assert.strictEqual(vulnerabilities.hsd.isDirect, true);
assert.strictEqual(report.metadata.vulnerabilities.critical, 4);
assert.strictEqual(report.metadata.vulnerabilities.total, 4);

console.warn(
  'npm dependency audit: allowing only GHSA-jj93-39pf-7mcf for the isolated ' +
  'pinned hsd oracle; no upstream fix is available'
);
