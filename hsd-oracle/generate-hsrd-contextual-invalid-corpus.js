#!/usr/bin/env node
'use strict';

// Generate deterministic, independently constructed state-boundary block
// mutations, then execute pinned HSD's exact Chain.verifyInputs composition
// against an immutable synthetic UTXO/header snapshot. No upstream invalid
// vector or test case is copied into this corpus.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const hsdRoot = path.dirname(require.resolve('hsd/package.json'));
const hsdPackage = require(path.join(hsdRoot, 'package.json'));
const Address = require(path.join(hsdRoot, 'lib/primitives/address'));
const Block = require(path.join(hsdRoot, 'lib/primitives/block'));
const Coin = require(path.join(hsdRoot, 'lib/primitives/coin'));
const Covenant = require(path.join(hsdRoot, 'lib/primitives/covenant'));
const Input = require(path.join(hsdRoot, 'lib/primitives/input'));
const Outpoint = require(path.join(hsdRoot, 'lib/primitives/outpoint'));
const Output = require(path.join(hsdRoot, 'lib/primitives/output'));
const Script = require(path.join(hsdRoot, 'lib/script/script'));
const TX = require(path.join(hsdRoot, 'lib/primitives/tx'));
const Witness = require(path.join(hsdRoot, 'lib/script/witness'));
const CoinEntry = require(path.join(hsdRoot, 'lib/coins/coinentry'));
const {BitField} = require(path.join(hsdRoot, 'lib/covenants/bitfield'));
const common = require(path.join(hsdRoot, 'lib/blockchain/common'));
const consensus = require(path.join(hsdRoot, 'lib/protocol/consensus'));
const Network = require(path.join(hsdRoot, 'lib/protocol/network'));
const scriptCommon = require(path.join(hsdRoot, 'lib/script/common'));
const rules = require(path.join(hsdRoot, 'lib/covenants/rules'));

// Loading Chain normally also loads the persistent database implementation.
// This oracle calls only the pure contextual verifier with a purpose-built,
// immutable database facade.
const chainDBPath = require.resolve('hsd/lib/blockchain/chaindb');
require.cache[chainDBPath] = {
  id: chainDBPath,
  filename: chainDBPath,
  loaded: true,
  exports: class UnusedChainDB {}
};
const Chain = require(path.join(hsdRoot, 'lib/blockchain/chain'));
delete require.cache[chainDBPath];

const ORACLE_REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const ROOT = path.resolve(__dirname, '..');
const TARGET = path.join(
  ROOT,
  'hsrd/fixtures/hsd/chains/invalid-contextual-v1.json'
);
const WRITE = process.argv.includes('--write');
const CHECK = process.argv.includes('--check') || !WRITE;
const network = Network.get('regtest');
const PARENT_HEIGHT = 200;
const CANDIDATE_HEIGHT = PARENT_HEIGHT + 1;
const EARLY_TIME = 1_000;
const LATE_TIME = 3_000;

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function address(byte, version = 1, size = 32) {
  return new Address({version, hash: Buffer.alloc(size, byte)});
}

function output(value, destination = address(0x31)) {
  return new Output({
    value,
    address: destination,
    covenant: new Covenant()
  });
}

function outpoint(byte, index = 0) {
  return new Outpoint(Buffer.alloc(32, byte), index);
}

function coin(byte, {
  value = 1_000,
  height = 100,
  coinbase = false,
  destination = address(byte)
} = {}) {
  const previous = outpoint(byte);
  return new Coin({
    version: 1,
    height,
    value,
    address: destination,
    covenant: new Covenant(),
    coinbase,
    hash: previous.hash,
    index: previous.index
  });
}

function spend(
  previous,
  {
    value = 900,
    sequence = 0xffffffff,
    witness = new Witness(),
    destination = address(0x41)
  } = {}
) {
  return new TX({
    version: 1,
    inputs: [new Input({
      prevout: new Outpoint(previous.hash, previous.index),
      sequence,
      witness
    })],
    outputs: [output(value, destination)],
    locktime: 0
  });
}

function coinbase(value) {
  return new TX({
    version: 1,
    inputs: [new Input()],
    outputs: [output(value, address(0x21))],
    locktime: CANDIDATE_HEIGHT
  });
}

function block(transactions, claimed = consensus.getReward(
  CANDIDATE_HEIGHT,
  network.halvingInterval
)) {
  const candidate = new Block();
  candidate.txs = [coinbase(claimed), ...transactions];
  for (const transaction of candidate.txs)
    transaction.refresh();
  candidate.merkleRoot = candidate.createMerkleRoot();
  candidate.witnessRoot = candidate.createWitnessRoot();
  candidate.refresh();
  const [valid, reason] = candidate.checkBody();
  assert.strictEqual(valid, true, `contextual candidate body: ${reason}`);
  return candidate;
}

function contextHeaders() {
  const headers = [];
  for (let height = 179; height <= PARENT_HEIGHT; height++) {
    headers.push({
      height,
      time: height <= 189 ? EARLY_TIME : LATE_TIME
    });
  }
  return headers;
}

const HEADERS = contextHeaders();

function medianTime(height) {
  const times = HEADERS
    .filter(header => header.height <= height)
    .slice(-consensus.MEDIAN_TIMESPAN)
    .map(header => header.time)
    .sort((left, right) => left - right);
  assert(times.length > 0, `missing median-time context at ${height}`);
  return times[times.length >>> 1];
}

function coinKey(hash, index) {
  return `${hash.toString('hex')}:${index}`;
}

function oracleChain(inputCoins) {
  const coins = new Map(inputCoins.map(item => [
    coinKey(item.hash, item.index),
    item
  ]));
  const chain = Object.create(Chain.prototype);
  chain.network = network;
  chain.height = PARENT_HEIGHT;
  chain.workers = null;
  chain.isHistoricalHeight = () => false;
  chain.db = {
    field: new BitField(),
    treeRoot() {
      return Buffer.alloc(32);
    },
    async readCoin(previous) {
      const item = coins.get(coinKey(previous.hash, previous.index));
      return item ? CoinEntry.fromCoin(item) : null;
    },
    async getNameState() {
      return null;
    },
    async getEntry() {
      return null;
    },
    async isMainChain() {
      return false;
    }
  };
  chain.getAncestor = async (_previous, height) => ({height});
  chain.getMedianTime = async entry => medianTime(entry.height);
  return chain;
}

function coinJson(item) {
  return {
    outpointTxid: item.hash.toString('hex'),
    outpointIndex: item.index,
    value: item.value,
    height: item.height,
    coinbase: item.coinbase,
    addressVersion: item.address.version,
    addressHash: item.address.hash.toString('hex'),
    covenantType: item.covenant.type,
    covenantItems: item.covenant.items.map(value => value.toString('hex'))
  };
}

async function runCase(id, mutationClass, candidate, inputCoins, expectedReason) {
  const state = {
    flags: scriptCommon.flags.MANDATORY_VERIFY_FLAGS,
    lockFlags: common.MANDATORY_LOCKTIME_FLAGS,
    nameFlags: rules.MANDATORY_VERIFY_COVENANT_FLAGS
  };
  let accepted = true;
  let reason = 'valid';
  let score = 0;
  try {
    await Chain.prototype.verifyInputs.call(
      oracleChain(inputCoins),
      candidate,
      {height: PARENT_HEIGHT},
      state
    );
  } catch (error) {
    assert.strictEqual(error.type, 'VerifyError', `${id}: non-consensus exception`);
    accepted = false;
    reason = error.reason;
    score = error.score;
  }
  assert.strictEqual(reason, expectedReason, `${id}: pinned HSD reason`);
  assert.strictEqual(accepted, reason === 'valid', `${id}: inconsistent outcome`);
  if (accepted)
    assert.strictEqual(score, 0, `${id}: valid candidate ban score`);

  const raw = candidate.encode();
  assert(
    Block.decode(raw).encode().equals(raw),
    `${id}: candidate block does not round-trip`
  );
  return {
    id,
    target: 'block-context',
    mutationClass,
    raw: raw.toString('hex'),
    inputCoins: inputCoins.map(coinJson),
    oracle: {accepted, reason, score}
  };
}

async function cases() {
  const ordinary = coin(0x01);
  const missing = coin(0x02);
  const double = coin(0x03);
  const immature = coin(0x04, {height: PARENT_HEIGHT, coinbase: true});
  const below = coin(0x05);
  const heightLock = coin(0x06, {height: PARENT_HEIGHT});
  const timeLock = coin(0x07, {height: 190});
  const trueScript = Script.fromRaw(Buffer.from([scriptCommon.opcodes.OP_1]));
  const scriptAddress = Address.fromScripthash(trueScript.sha3());
  const scripted = coin(0x08, {destination: scriptAddress});
  const trueWitness = new Witness();
  trueWitness.items = [trueScript.encode()];
  const falseWitness = new Witness();
  falseWitness.items = [Buffer.from([scriptCommon.opcodes.OP_0])];
  const subsidy = consensus.getReward(CANDIDATE_HEIGHT, network.halvingInterval);

  return [
    await runCase(
      'context-valid-future-program-control',
      'valid-future-program',
      block([spend(ordinary)]),
      [ordinary],
      'valid'
    ),
    await runCase(
      'context-missing-input',
      'missing-input',
      block([spend(missing)]),
      [],
      'bad-txns-inputs-missingorspent'
    ),
    await runCase(
      'context-in-block-double-spend',
      'in-block-double-spend',
      block([
        spend(double, {value: 900, destination: address(0x42)}),
        spend(double, {value: 800, destination: address(0x43)})
      ]),
      [double],
      'bad-txns-inputs-missingorspent'
    ),
    await runCase(
      'context-premature-coinbase-spend',
      'premature-coinbase-spend',
      block([spend(immature)]),
      [immature],
      'bad-txns-premature-spend-of-coinbase'
    ),
    await runCase(
      'context-input-value-below-output',
      'input-value-below-output',
      block([spend(below, {value: below.value + 1})]),
      [below],
      'bad-txns-in-belowout'
    ),
    await runCase(
      'context-height-sequence-lock',
      'height-sequence-lock',
      block([spend(heightLock, {sequence: 2})]),
      [heightLock],
      'bad-txns-nonfinal'
    ),
    await runCase(
      'context-height-sequence-control',
      'valid-height-sequence',
      block([spend(heightLock, {sequence: 1})]),
      [heightLock],
      'valid'
    ),
    await runCase(
      'context-time-sequence-lock',
      'time-sequence-lock',
      block([spend(timeLock, {
        sequence: consensus.SEQUENCE_TYPE_FLAG | 4
      })]),
      [timeLock],
      'bad-txns-nonfinal'
    ),
    await runCase(
      'context-time-sequence-control',
      'valid-time-sequence',
      block([spend(timeLock, {
        sequence: consensus.SEQUENCE_TYPE_FLAG | 3
      })]),
      [timeLock],
      'valid'
    ),
    await runCase(
      'context-mandatory-script-mismatch',
      'mandatory-script-mismatch',
      block([spend(scripted, {witness: falseWitness})]),
      [scripted],
      'mandatory-script-verify-flag-failed'
    ),
    await runCase(
      'context-mandatory-script-control',
      'valid-mandatory-script',
      block([spend(scripted, {witness: trueWitness})]),
      [scripted],
      'valid'
    ),
    await runCase(
      'context-coinbase-overclaim',
      'coinbase-overclaim',
      block([], subsidy + 1),
      [],
      'bad-cb-amount'
    )
  ];
}

async function fixture() {
  const generated = await cases();
  assert.strictEqual(generated.length, 12);
  assert.strictEqual(
    generated.filter(item => !item.oracle.accepted).length,
    8
  );
  assert.strictEqual(medianTime(189), EARLY_TIME);
  assert.strictEqual(medianTime(PARENT_HEIGHT), LATE_TIME);
  return {
    schema: 1,
    network: 'regtest',
    oracle: {
      repository: 'handshake-org/hsd',
      revision: ORACLE_REVISION,
      hsdVersion: hsdPackage.version,
      route: 'Chain.verifyInputs'
    },
    generation: {
      method: 'independent-fixed-state-boundary-mutations',
      seedDomain: 'meshmine/hsrd-invalid-contextual/v1',
      upstreamInvalidVectorsCopied: false,
      candidateHeight: CANDIDATE_HEIGHT,
      parentHeight: PARENT_HEIGHT,
      coinbaseMaturity: network.coinbaseMaturity,
      invalidCases: 8,
      validControls: 4
    },
    contextHeaders: HEADERS,
    cases: generated
  };
}

async function main() {
  const expected = canonicalJson(await fixture());

  if (WRITE) {
    fs.mkdirSync(path.dirname(TARGET), {recursive: true});
    fs.writeFileSync(TARGET, expected, {encoding: 'utf8', mode: 0o644});
    console.log(`wrote ${path.relative(ROOT, TARGET)}`);
  }

  if (CHECK) {
    const actual = fs.readFileSync(TARGET, 'utf8');
    assert.strictEqual(
      actual,
      expected,
      `${path.relative(ROOT, TARGET)} is not reproducible; run with --write`
    );
    console.log(`verified ${path.relative(ROOT, TARGET)}`);
  }
}

main().catch(error => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
