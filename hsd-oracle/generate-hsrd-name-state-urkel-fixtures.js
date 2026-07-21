#!/usr/bin/env node
'use strict';

// Generates deterministic HSD NameState and Urkel-root fixtures.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const BLAKE2b = require('bcrypto/lib/blake2b');
const {Tree} = require('urkel');
const NameState = require('hsd/lib/covenants/namestate');
const Outpoint = require('hsd/lib/primitives/outpoint');
const Network = require('hsd/lib/protocol/network');
const rules = require('hsd/lib/covenants/rules');

const ORACLE_REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const TARGET = path.resolve(
  __dirname,
  '..',
  'hsrd',
  'fixtures',
  'hsd',
  'name-states',
  'state-urkel-v1.json'
);
const WRITE = process.argv.includes('--write');
const CHECK = process.argv.includes('--check') || !WRITE;

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function makeState(nameText, height, marker) {
  const name = Buffer.from(nameText, 'ascii');
  const state = new NameState();
  state.name = name;
  state.nameHash = rules.hashName(name);
  state.height = height;
  state.renewal = height + 3;
  state.owner = new Outpoint(Buffer.alloc(32, marker), marker);
  state.value = 1000 + marker;
  state.highest = 2000 + marker;
  state.data = Buffer.from([marker, marker + 1, marker + 2]);
  state.transfer = marker % 2 === 0 ? height + 1 : 0;
  state.revoked = 0;
  state.claimed = marker % 3 === 0 ? height : 0;
  state.renewals = marker;
  state.registered = marker % 2 === 1;
  state.expired = false;
  state.weak = marker % 2 === 0;
  return state;
}

async function buildFixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hsrd-urkel-'));
  const tree = new Tree({
    hash: BLAKE2b,
    bits: 256,
    prefix: directory
  });

  await tree.open();
  const states = [
    makeState('alpha', 10, 1),
    makeState('bravo', 20, 2),
    makeState('charlie', 30, 3),
    makeState('delta', 40, 4)
  ];
  const roots = [];

  try {
    for (const state of states) {
      const headerRoot = tree.rootHash();
      const transaction = tree.transaction();
      await transaction.insert(state.nameHash, state.encode());
      const resultingRoot = await transaction.commit();
      roots.push({
        insertedName: state.name.toString('ascii'),
        headerRoot: headerRoot.toString('hex'),
        resultingRoot: resultingRoot.toString('hex'),
        // Retained for compatibility with the first fixture consumer. New code
        // should use the explicit pre-state/resulting-state fields above.
        root: resultingRoot.toString('hex')
      });
    }
  } finally {
    await tree.close();
    fs.rmSync(directory, {recursive: true, force: true});
  }

  const regtest = Network.get('regtest');
  const lifecycle = new NameState();
  lifecycle.name = Buffer.from('echo', 'ascii');
  lifecycle.nameHash = rules.hashName(lifecycle.name);
  lifecycle.height = 100;
  lifecycle.renewal = 100;
  lifecycle.owner = new Outpoint(Buffer.alloc(32, 0x55), 0);

  const lifecycleHeights = [100, 105, 106, 110, 111, 120, 121].map(height => ({
    height,
    state: lifecycle.state(height, regtest),
    expired: lifecycle.isExpired(height, regtest)
  }));

  const expiring = new NameState();
  expiring.name = Buffer.from('foxtrot', 'ascii');
  expiring.nameHash = rules.hashName(expiring.name);
  expiring.height = 1;
  expiring.renewal = 1;
  expiring.owner = new Outpoint(Buffer.alloc(32, 0x66), 0);
  expiring.data = Buffer.from('01020304', 'hex');
  const expirationHeight = expiring.renewal + regtest.names.renewalWindow;
  assert.strictEqual(expiring.maybeExpire(expirationHeight, regtest), true);

  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: ORACLE_REVISION
    },
    network: 'regtest',
    states: states.map(state => ({
      name: state.name.toString('ascii'),
      nameHash: state.nameHash.toString('hex'),
      encoded: state.encode().toString('hex')
    })),
    incrementalRoots: roots,
    lifecycle: lifecycleHeights,
    expiredState: {
      height: expirationHeight,
      encoded: expiring.encode().toString('hex'),
      dataPreserved: expiring.data.toString('hex'),
      expired: expiring.expired
    },
    parameters: {
      auctionStart: regtest.names.auctionStart,
      rolloutInterval: regtest.names.rolloutInterval,
      lockupPeriod: regtest.names.lockupPeriod,
      renewalWindow: regtest.names.renewalWindow,
      renewalPeriod: regtest.names.renewalPeriod,
      renewalMaturity: regtest.names.renewalMaturity,
      biddingPeriod: regtest.names.biddingPeriod,
      revealPeriod: regtest.names.revealPeriod,
      treeInterval: regtest.names.treeInterval,
      transferLockup: regtest.names.transferLockup,
      auctionMaturity: regtest.names.auctionMaturity
    }
  };
}

(async () => {
  const generated = canonicalJson(await buildFixture());
  if (WRITE) {
    fs.mkdirSync(path.dirname(TARGET), {recursive: true});
    fs.writeFileSync(TARGET, generated);
  }
  if (CHECK) {
    const existing = fs.readFileSync(TARGET, 'utf8');
    assert.strictEqual(existing, generated, `${TARGET} is not reproducible`);
  }
  process.stdout.write(`verified ${path.relative(process.cwd(), TARGET)}\n`);
})().catch(error => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
