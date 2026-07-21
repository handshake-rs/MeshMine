#!/usr/bin/env node
'use strict';

// Generates deterministic HSD mining-template fixtures.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const random = require('bcrypto/lib/random');
const Address = require('hsd/lib/primitives/address');
const BlockTemplate = require('hsd/lib/mining/template');
const consensus = require('hsd/lib/protocol/consensus');
const Network = require('hsd/lib/protocol/network');

const ORACLE_REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const TARGET = path.resolve(
  __dirname,
  '..',
  'hsrd',
  'fixtures',
  'hsd',
  'mining',
  'template-v1.json'
);
const WRITE = process.argv.includes('--write');
const CHECK = process.argv.includes('--check') || !WRITE;

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function deterministicCoinbase() {
  const network = Network.get('regtest');
  const address = new Address();
  address.fromPubkeyhash(Buffer.alloc(20, 0x09));

  const originalRandomInt = random.randomInt;
  const originalRandomBytes = random.randomBytes;
  random.randomInt = () => 7;
  random.randomBytes = size => Buffer.alloc(size, 0x00);
  try {
    const attempt = new BlockTemplate({
      height: 11,
      interval: network.halvingInterval,
      fees: 60,
      coinbaseFlags: Buffer.from('hsrd', 'ascii'),
      address
    });
    const tx = attempt.createCoinbase();
    return {
      network: 'regtest',
      height: attempt.height,
      generationAsSequence: 7,
      interval: attempt.interval,
      fees: attempt.fees,
      reward: attempt.getReward(),
      coinbaseFlags: attempt.coinbaseFlags.toString('hex'),
      payoutAddressHash: Buffer.alloc(20, 0x09).toString('hex'),
      raw: tx.encode().toString('hex'),
      txid: tx.txid(),
      witnessHash: tx.witnessHash().toString('hex'),
      baseSize: tx.getBaseSize(),
      witnessSize: tx.getSizes().witness,
      weight: tx.getWeight()
    };
  } finally {
    random.randomInt = originalRandomInt;
    random.randomBytes = originalRandomBytes;
  }
}

function subsidyCases() {
  const intervals = [
    ['main', Network.get('main').halvingInterval],
    ['regtest', Network.get('regtest').halvingInterval]
  ];
  const cases = [];
  for (const [network, interval] of intervals) {
    for (const height of [
      0,
      interval - 1,
      interval,
      (2 * interval) - 1,
      2 * interval,
      (51 * interval),
      (52 * interval)
    ]) {
      cases.push({
        network,
        interval,
        height,
        reward: consensus.getReward(height, interval)
      });
    }
  }
  return cases;
}

function buildFixture() {
  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: ORACLE_REVISION
    },
    constants: {
      baseReward: consensus.BASE_REWARD,
      maximumCoinbaseWitnessSize: 1000
    },
    subsidyCases: subsidyCases(),
    deterministicCoinbase: deterministicCoinbase()
  };
}

const generated = canonicalJson(buildFixture());

if (WRITE) {
  fs.mkdirSync(path.dirname(TARGET), {recursive: true});
  fs.writeFileSync(TARGET, generated);
}

if (CHECK) {
  const existing = fs.readFileSync(TARGET, 'utf8');
  assert.strictEqual(existing, generated, `${TARGET} is not reproducible`);
}

process.stdout.write(`verified ${path.relative(process.cwd(), TARGET)}\n`);
