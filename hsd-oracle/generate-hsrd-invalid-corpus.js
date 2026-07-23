#!/usr/bin/env node
'use strict';

// Generate deterministic, independently constructed invalid transaction and
// block mutations, then record the exact non-contextual outcome from pinned
// HSD. No upstream invalid vector is copied into this corpus.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const hsdRoot = path.dirname(require.resolve('hsd/package.json'));
const hsdPackage = require(path.join(hsdRoot, 'package.json'));
const Address = require(path.join(hsdRoot, 'lib/primitives/address'));
const Block = require(path.join(hsdRoot, 'lib/primitives/block'));
const Covenant = require(path.join(hsdRoot, 'lib/primitives/covenant'));
const Input = require(path.join(hsdRoot, 'lib/primitives/input'));
const Outpoint = require(path.join(hsdRoot, 'lib/primitives/outpoint'));
const Output = require(path.join(hsdRoot, 'lib/primitives/output'));
const TX = require(path.join(hsdRoot, 'lib/primitives/tx'));
const Witness = require(path.join(hsdRoot, 'lib/script/witness'));
const consensus = require(path.join(hsdRoot, 'lib/protocol/consensus'));
const Network = require(path.join(hsdRoot, 'lib/protocol/network'));
const rules = require(path.join(hsdRoot, 'lib/covenants/rules'));

const ORACLE_REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const ROOT = path.resolve(__dirname, '..');
const TARGET = path.join(
  ROOT,
  'hsrd/fixtures/hsd/chains/invalid-noncontextual-v1.json'
);
const WRITE = process.argv.includes('--write');
const CHECK = process.argv.includes('--check') || !WRITE;

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function address(byte, size = 20) {
  return new Address({version: 0, hash: Buffer.alloc(size, byte)});
}

function invalidAddress(byte) {
  const value = new Address();
  value.version = 0;
  value.hash = Buffer.alloc(1, byte);
  return value;
}

function input(byte, index = 0) {
  return new Input({
    prevout: new Outpoint(Buffer.alloc(32, byte), index),
    sequence: 0xffffffff,
    witness: new Witness()
  });
}

function indexedInput(index) {
  const hash = Buffer.alloc(32, 0x18);
  hash.writeUInt32LE(index, 0);
  return new Input({
    prevout: new Outpoint(hash, index),
    sequence: 0xffffffff,
    witness: new Witness()
  });
}

function output(value, byte = 0x22) {
  return new Output({
    value,
    address: address(byte),
    covenant: new Covenant()
  });
}

function ordinaryTransaction() {
  return new TX({
    version: 1,
    inputs: [input(0x11)],
    outputs: [output(1)],
    locktime: 0
  });
}

function coinbaseTransaction() {
  return new TX({
    version: 1,
    inputs: [new Input()],
    outputs: [output(1)],
    locktime: 1
  });
}

function u32(value) {
  const raw = Buffer.allocUnsafe(4);
  raw.writeUInt32LE(value >>> 0, 0);
  return raw;
}

function openOutput(index) {
  const name = Buffer.from(`invalid-corpus-${index.toString().padStart(3, '0')}`);
  return new Output({
    value: 1,
    address: address(0x40 + (index % 32)),
    covenant: new Covenant(rules.types.OPEN, [
      rules.hashName(name),
      u32(0),
      name
    ])
  });
}

function linkedNameOutput(index, type) {
  const items = [
    Buffer.alloc(32, 0x50 + (index % 32)),
    u32(1),
    type === rules.types.UPDATE ? Buffer.alloc(0) : Buffer.alloc(32, 0x70)
  ];
  return new Output({
    value: 1,
    address: address(0x60 + (index % 32)),
    covenant: new Covenant(type, items)
  });
}

function mutateTransaction(id, expectedReason, mutation) {
  const transaction = mutation();
  transaction.refresh();
  const [valid, reason, score] = transaction.checkSanity();
  assert.strictEqual(
    reason,
    expectedReason,
    `${id}: pinned HSD returned an unexpected reason`
  );
  assert.strictEqual(valid, reason === 'valid', `${id}: inconsistent HSD result`);
  if (valid)
    assert.strictEqual(score, 0, `${id}: valid transaction has a ban score`);
  else
    assert(score > 0, `${id}: invalid transaction has no ban score`);
  const raw = transaction.encode();
  if (reason === 'bad-txns-address-size') {
    assert.throws(
      () => TX.decode(raw),
      undefined,
      `${id}: malformed address unexpectedly decoded`
    );
  } else {
    assert(
      TX.decode(raw).encode().equals(raw),
      `${id}: transaction does not round-trip`
    );
  }
  return {
    id,
    target: 'transaction-sanity',
    raw: raw.toString('hex'),
    oracle: {
      accepted: valid,
      reason,
      score,
      semanticViolation: semanticViolation(reason)
    }
  };
}

function refreshBodyRoots(block) {
  for (const transaction of block.txs)
    transaction.refresh();
  block.merkleRoot = block.createMerkleRoot();
  block.witnessRoot = block.createWitnessRoot();
  block.refresh();
  return block;
}

function mutateBlock(base, id, expectedReason, mutation) {
  const block = mutation(base.clone());
  const [valid, reason, score] = block.checkBody();
  assert.strictEqual(
    reason,
    expectedReason,
    `${id}: pinned HSD returned an unexpected reason`
  );
  assert.strictEqual(valid, reason === 'valid', `${id}: inconsistent HSD result`);
  const raw = block.encode();
  assert(Block.decode(raw).encode().equals(raw), `${id}: block does not round-trip`);
  return {
    id,
    target: 'block-body',
    raw: raw.toString('hex'),
    oracle: {
      accepted: valid,
      reason,
      score,
      semanticViolation: semanticViolation(reason)
    }
  };
}

function semanticViolation(reason) {
  switch (reason) {
    case 'valid':
      return 'valid';
    case 'bad-txns-vin-empty':
      return 'transaction-inputs-empty';
    case 'bad-txns-vout-empty':
      return 'transaction-outputs-empty';
    case 'bad-txns-vout-toolarge':
    case 'bad-txns-txouttotal-toolarge':
      return 'transaction-output-value-range';
    case 'bad-txns-address-size':
      return 'transaction-output-address';
    case 'bad-txns-inputs-duplicate':
      return 'transaction-input-duplicate';
    case 'bad-txns-prevout-null':
      return 'transaction-null-prevout';
    case 'bad-cb-outpoint':
      return 'coinbase-outpoint';
    case 'bad-cb-length':
      return 'coinbase-witness-size';
    case 'bad-cb-witness':
      return 'coinbase-witness-shape';
    case 'bad-txns-covenants':
      return 'transaction-covenant-shape';
    case 'bad-txns-opens':
      return 'transaction-open-limit';
    case 'bad-txns-updates':
      return 'transaction-update-limit';
    case 'bad-txns-renewals':
      return 'transaction-renewal-limit';
    case 'bad-blk-length':
      return 'block-length';
    case 'bad-txnmrklroot':
      return 'block-merkle-commitment';
    case 'bad-witnessroot':
      return 'block-witness-commitment';
    case 'bad-cb-missing':
      return 'block-coinbase-missing';
    case 'bad-cb-multiple':
      return 'block-coinbase-multiple';
    default:
      throw new Error(`unclassified HSD rejection ${reason}`);
  }
}

function transactionCases() {
  return [
    mutateTransaction('tx-valid-control', 'valid', ordinaryTransaction),
    mutateTransaction('tx-inputs-empty', 'bad-txns-vin-empty', () => {
      const transaction = ordinaryTransaction();
      transaction.inputs = [];
      return transaction;
    }),
    mutateTransaction('tx-outputs-empty', 'bad-txns-vout-empty', () => {
      const transaction = ordinaryTransaction();
      transaction.outputs = [];
      return transaction;
    }),
    mutateTransaction('tx-output-value-too-large', 'bad-txns-vout-toolarge', () => {
      const transaction = ordinaryTransaction();
      transaction.outputs[0].value = consensus.MAX_MONEY + 1;
      return transaction;
    }),
    mutateTransaction(
      'tx-output-total-too-large',
      'bad-txns-txouttotal-toolarge',
      () => {
        const transaction = ordinaryTransaction();
        transaction.outputs = [output(consensus.MAX_MONEY), output(1, 0x23)];
        return transaction;
      }
    ),
    mutateTransaction('tx-output-address-invalid', 'bad-txns-address-size', () => {
      const transaction = ordinaryTransaction();
      transaction.outputs[0].address = invalidAddress(0x24);
      return transaction;
    }),
    mutateTransaction('tx-input-duplicate', 'bad-txns-inputs-duplicate', () => {
      const transaction = ordinaryTransaction();
      transaction.inputs.push(transaction.inputs[0].clone());
      return transaction;
    }),
    mutateTransaction('tx-null-prevout', 'bad-txns-prevout-null', () => {
      const transaction = ordinaryTransaction();
      transaction.inputs.push(new Input());
      return transaction;
    }),
    mutateTransaction('coinbase-nonnull-outpoint', 'bad-cb-outpoint', () => {
      const transaction = coinbaseTransaction();
      transaction.inputs.push(input(0x25));
      return transaction;
    }),
    mutateTransaction('coinbase-witness-too-large', 'bad-cb-length', () => {
      const transaction = coinbaseTransaction();
      transaction.inputs[0].witness.items = [Buffer.alloc(1001, 0x26)];
      return transaction;
    }),
    mutateTransaction('coinbase-claim-witness-shape', 'bad-cb-witness', () => {
      const transaction = coinbaseTransaction();
      transaction.inputs.push(new Input());
      return transaction;
    }),
    mutateTransaction('coinbase-claim-witness-too-large', 'bad-cb-length', () => {
      const transaction = coinbaseTransaction();
      const claimInput = new Input();
      claimInput.witness.items = [Buffer.alloc(10001, 0x27)];
      transaction.inputs.push(claimInput);
      return transaction;
    }),
    mutateTransaction('tx-covenant-malformed', 'bad-txns-covenants', () => {
      const transaction = ordinaryTransaction();
      transaction.outputs[0].covenant = new Covenant(rules.types.OPEN, []);
      return transaction;
    }),
    mutateTransaction('tx-open-limit-exceeded', 'bad-txns-opens', () => {
      const transaction = ordinaryTransaction();
      transaction.outputs = Array.from(
        {length: consensus.MAX_BLOCK_OPENS + 1},
        (_, index) => openOutput(index)
      );
      return transaction;
    }),
    mutateTransaction('tx-update-limit-exceeded', 'bad-txns-updates', () => {
      const count = consensus.MAX_BLOCK_UPDATES + 1;
      const transaction = ordinaryTransaction();
      transaction.inputs = Array.from({length: count}, (_, index) =>
        indexedInput(index)
      );
      transaction.outputs = Array.from({length: count}, (_, index) =>
        linkedNameOutput(index, rules.types.UPDATE)
      );
      return transaction;
    }),
    mutateTransaction('tx-renewal-limit-exceeded', 'bad-txns-renewals', () => {
      const count = consensus.MAX_BLOCK_RENEWALS + 1;
      const transaction = ordinaryTransaction();
      transaction.inputs = Array.from({length: count}, (_, index) =>
        indexedInput(index)
      );
      transaction.outputs = Array.from({length: count}, (_, index) =>
        linkedNameOutput(index, rules.types.RENEW)
      );
      return transaction;
    })
  ];
}

function blockCases() {
  const base = Block.decode(Network.get('main').genesisBlock);
  return [
    mutateBlock(base, 'block-valid-control', 'valid', block => block),
    mutateBlock(base, 'block-transactions-empty', 'bad-blk-length', block => {
      block.txs = [];
      block.refresh(true);
      return block;
    }),
    mutateBlock(base, 'block-merkle-mismatch', 'bad-txnmrklroot', block => {
      block.merkleRoot = Buffer.alloc(32, 0x31);
      block.refresh();
      return block;
    }),
    mutateBlock(base, 'block-witness-mismatch', 'bad-witnessroot', block => {
      block.witnessRoot = Buffer.alloc(32, 0x32);
      block.refresh();
      return block;
    }),
    mutateBlock(base, 'block-coinbase-missing', 'bad-cb-missing', block => {
      block.txs = [ordinaryTransaction()];
      return refreshBodyRoots(block);
    }),
    mutateBlock(base, 'block-coinbase-multiple', 'bad-cb-multiple', block => {
      const second = block.txs[0].clone();
      second.locktime += 1;
      second.outputs[0].value -= 1;
      block.txs.push(second);
      return refreshBodyRoots(block);
    }),
    mutateBlock(base, 'block-coinbase-witness-too-large', 'bad-cb-length', block => {
      block.txs[0].inputs[0].witness.items = [Buffer.alloc(1001, 0x33)];
      return refreshBodyRoots(block);
    }),
    mutateBlock(
      base,
      'block-contains-invalid-transaction',
      'bad-txns-inputs-duplicate',
      block => {
        const transaction = ordinaryTransaction();
        transaction.inputs.push(transaction.inputs[0].clone());
        block.txs.push(transaction);
        return refreshBodyRoots(block);
      }
    )
  ];
}

function fixture() {
  const cases = [...transactionCases(), ...blockCases()];
  assert.strictEqual(cases.length, 24);
  assert.strictEqual(cases.filter(item => !item.oracle.accepted).length, 22);
  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: ORACLE_REVISION,
      hsdVersion: hsdPackage.version
    },
    generation: {
      method: 'independent-fixed-mutations',
      seedDomain: 'meshmine/hsrd-invalid-noncontextual/v1',
      upstreamInvalidVectorsCopied: false,
      transactionCases: 16,
      blockCases: 8,
      invalidCases: 22
    },
    cases
  };
}

function main() {
  const expected = canonicalJson(fixture());

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

main();
