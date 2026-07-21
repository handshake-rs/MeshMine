'use strict';

// Generates deterministic HSD name-policy fixtures.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const BLAKE2b = require('bcrypto/lib/blake2b');
const SHA3 = require('bcrypto/lib/sha3');
const Network = require('hsd/lib/protocol/network');
const rules = require('hsd/lib/covenants/rules');
const reserved = require('hsd/lib/covenants/reserved');
const locked = require('hsd/lib/covenants/locked').locked;

const REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(ROOT, 'hsrd/fixtures/hsd/name-states/name-policy-v1.json');
const NAMES_DB = path.join(__dirname, 'node_modules/hsd/lib/covenants/names.db');
const LOCKUP_DB = path.join(__dirname, 'node_modules/hsd/lib/covenants/lockup.db');
const CHAIN_JS = path.join(__dirname, 'node_modules/hsd/lib/blockchain/chain.js');

function digest(file) {
  return BLAKE2b.digest(fs.readFileSync(file), 32).toString('hex');
}

function verifyRenewalSource() {
  const source = fs.readFileSync(CHAIN_JS, 'utf8');
  const match = source.match(/  async verifyRenewal\(hash, height\) \{[\s\S]*?\n  \}/);
  assert(match, 'could not extract Chain.verifyRenewal from pinned hsd source');
  return match[0];
}

function renewalExpectation(height, committedHeight, params) {
  if (height < params.renewalMaturity)
    return true;

  if (committedHeight == null)
    return false;

  if (committedHeight > height - params.renewalMaturity)
    return false;

  if (committedHeight < height - params.renewalPeriod)
    return false;

  return true;
}

function makeFixture() {
  const network = Network.get('main');
  const heights = [
    0,
    network.names.claimPeriod - 1,
    network.names.claimPeriod,
    network.names.alexaLockupPeriod - 1,
    network.names.alexaLockupPeriod
  ];
  const names = ['com', 'google', 'cloudflare', 'example', 'test', 'localhost'];
  const cases = [];

  for (const name of names) {
    const hash = SHA3.digest(Buffer.from(name, 'ascii'));
    for (const height of heights) {
      cases.push({
        name,
        nameHash: hash.toString('hex'),
        height,
        reserved: rules.isReserved(hash, height, network),
        locked: rules.isLockedUp(hash, height, network)
      });
    }
  }

  const renewalHeights = [
    network.names.renewalMaturity - 1,
    network.names.renewalMaturity,
    network.names.renewalMaturity + 1,
    network.names.renewalPeriod,
    network.names.renewalPeriod + network.names.renewalMaturity
  ];
  const renewalCommitmentCases = [];

  for (const height of renewalHeights) {
    const candidates = new Set([
      null,
      0,
      Math.max(0, height - network.names.renewalPeriod - 1),
      Math.max(0, height - network.names.renewalPeriod),
      Math.max(0, height - network.names.renewalMaturity),
      Math.max(0, height - network.names.renewalMaturity + 1)
    ]);

    for (const committedHeight of candidates) {
      renewalCommitmentCases.push({
        height,
        committedHeight,
        accepted: renewalExpectation(height, committedHeight, network.names)
      });
    }
  }

  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: REVISION
    },
    network: 'main',
    parameters: {
      claimPeriod: network.names.claimPeriod,
      alexaLockupPeriod: network.names.alexaLockupPeriod,
      renewalMaturity: network.names.renewalMaturity,
      renewalPeriod: network.names.renewalPeriod
    },
    datasets: {
      reservedCount: reserved.size,
      lockedCount: locked.size,
      namesDbBlake2b256: digest(NAMES_DB),
      lockupDbBlake2b256: digest(LOCKUP_DB)
    },
    verifyRenewalSourceBlake2b256: BLAKE2b.digest(
      Buffer.from(verifyRenewalSource(), 'utf8'),
      32
    ).toString('hex'),
    renewalCommitmentCases,
    cases
  };
}

function stable(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function main() {
  const write = process.argv.includes('--write');
  const check = process.argv.includes('--check');
  assert(write || check, 'use --write and/or --check');
  const expected = stable(makeFixture());

  if (write) {
    fs.mkdirSync(path.dirname(OUTPUT), {recursive: true});
    fs.writeFileSync(OUTPUT, expected);
    console.log(`wrote ${path.relative(ROOT, OUTPUT)}`);
  }

  if (check) {
    const actual = fs.readFileSync(OUTPUT, 'utf8');
    assert.strictEqual(actual, expected, `${OUTPUT} is not reproducible`);
    console.log(`verified ${path.relative(ROOT, OUTPUT)}`);
  }
}

main();
