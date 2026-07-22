#!/usr/bin/env node
'use strict';

// Generates deterministic HSD mining-template fixtures.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const random = require('bcrypto/lib/random');
const Address = require('hsd/lib/primitives/address');
const Output = require('hsd/lib/primitives/output');
const BlockTemplate = require('hsd/lib/mining/template');
const consensus = require('hsd/lib/protocol/consensus');
const Network = require('hsd/lib/protocol/network');
const policy = require('hsd/lib/protocol/policy');
const TX = require('hsd/lib/primitives/tx');

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

function mempoolSigopPolicy(transactionRaw) {
  const tx = TX.decode(Buffer.from(transactionRaw, 'hex'));
  return {
    transactionRaw,
    transactionWeight: tx.getWeight(),
    maxTxSigops: policy.MAX_TX_SIGOPS,
    bytesPerSigop: policy.BYTES_PER_SIGOP,
    cases: [0, 1, 40, 4000, 16000, 16001].map(sigops => ({
      sigops,
      policySize: tx.getSigopsSize(sigops),
      accepted: sigops <= policy.MAX_TX_SIGOPS
    })),
    minimumFeeCases: [
      [0, 3],
      [88, 0],
      [88, 3],
      [20000, 3],
      [80005, 3]
    ].map(([policySize, rate]) => ({
      policySize,
      rate,
      minimumFee: policy.getMinFee(policySize, rate)
    }))
  };
}

function mempoolStandardPolicy(transactionRaw) {
  const baseline = () => TX.decode(Buffer.from(transactionRaw, 'hex'));
  const cases = [];
  let tx = baseline();
  cases.push({name: 'baseline', accepted: tx.checkStandard()[0]});
  tx = baseline();
  tx.version = 1;
  cases.push({name: 'version-one', accepted: tx.checkStandard()[0]});
  tx = baseline();
  tx.outputs[0].address = new Address().fromProgram(1, Buffer.alloc(20, 1));
  cases.push({name: 'unknown-address', accepted: tx.checkStandard()[0]});
  tx = baseline();
  tx.outputs[0].value = 1;
  cases.push({name: 'dust', accepted: tx.checkStandard()[0]});
  tx = baseline();
  const nulldata = new Output();
  nulldata.address.fromNulldata(Buffer.alloc(2, 1));
  tx.outputs = [nulldata, nulldata.clone()];
  cases.push({name: 'multiple-nulldata', accepted: tx.checkStandard()[0]});

  const output = new Output();
  output.value = 1;
  output.address.fromPubkeyhash(Buffer.alloc(20, 2));
  return {
    maximumVersion: policy.MAX_TX_VERSION,
    maximumWeight: policy.MAX_TX_WEIGHT,
    maximumWitnessStack: policy.MAX_P2WSH_STACK,
    maximumWitnessPush: policy.MAX_P2WSH_PUSH,
    maximumWitnessScript: policy.MAX_P2WSH_SIZE,
    absurdFeeFactor: policy.ABSURD_FEE_FACTOR,
    dustThreshold: output.getDustThreshold(policy.MIN_RELAY),
    requireStandard: ['main', 'testnet', 'regtest', 'simnet'].map(name => ({
      network: name,
      required: Network.get(name).requireStandard
    })),
    cases
  };
}

function mempoolDynamicPolicy() {
  const source = fs.readFileSync(
    require.resolve('hsd/lib/mempool/mempool'),
    'utf8'
  );
  assert.match(source, /const threshold = maxSize - \(maxSize \/ 10\);/);
  assert.match(source, /if \(this\.hasDepends\(entry\.tx\)\)\s+continue;/);
  assert.match(source, /now >= entry\.time \+ expiryTime/);
  assert.match(source, /if \(useDesc\(a\)\) \{\s+xf = a\.descFee;/);
  assert.match(source, /if \(x === y\) \{\s+x = a\.time;\s+y = b\.time;/);
  return {
    maximumSize: policy.MEMPOOL_MAX_SIZE,
    expiryTime: policy.MEMPOOL_EXPIRY_TIME,
    trimTarget: {numerator: 9, denominator: 10},
    dependencyRootsOnly: true,
    descendantPackageRate: true,
    equalRateOldestFirst: true
  };
}

function buildFixture() {
  const coinbase = deterministicCoinbase();
  return {
    schema: 4,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: ORACLE_REVISION
    },
    constants: {
      baseReward: consensus.BASE_REWARD,
      maximumCoinbaseWitnessSize: 1000
    },
    subsidyCases: subsidyCases(),
    deterministicCoinbase: coinbase,
    mempoolSigopPolicy: mempoolSigopPolicy(coinbase.raw),
    mempoolStandardPolicy: mempoolStandardPolicy(coinbase.raw),
    mempoolDynamicPolicy: mempoolDynamicPolicy()
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
