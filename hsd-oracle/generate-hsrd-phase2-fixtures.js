#!/usr/bin/env node
'use strict';

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const {installMemoryOnlyDatabaseShim} = require('./memory-db-shim');
const hsdRoot = path.dirname(require.resolve('hsd/package.json'));
installMemoryOnlyDatabaseShim(hsdRoot);
const hsdPackage = require('hsd/package.json');
const Chain = require('hsd/lib/blockchain/chain');
const common = require('hsd/lib/script/common');
const consensus = require('hsd/lib/protocol/consensus');
const Address = require('hsd/lib/primitives/address');
const Covenant = require('hsd/lib/primitives/covenant');
const Input = require('hsd/lib/primitives/input');
const Outpoint = require('hsd/lib/primitives/outpoint');
const Output = require('hsd/lib/primitives/output');
const Script = require('hsd/lib/script/script');
const TX = require('hsd/lib/primitives/tx');
const Witness = require('hsd/lib/script/witness');

const ORACLE_REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const FIXTURE_ROOT = path.resolve(__dirname, '..', 'hsrd', 'fixtures', 'hsd', 'scripts');
const WRITE = process.argv.includes('--write');
const CHECK = process.argv.includes('--check') || !WRITE;

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function writeOrCheck(filename, value) {
  const target = path.join(FIXTURE_ROOT, filename);
  const expected = canonicalJson(value);

  if (WRITE) {
    fs.mkdirSync(path.dirname(target), {recursive: true});
    fs.writeFileSync(target, expected, {encoding: 'utf8', mode: 0o644});
  }

  if (CHECK) {
    const actual = fs.readFileSync(target, 'utf8');
    assert.strictEqual(
      actual,
      expected,
      `${path.relative(process.cwd(), target)} is not reproducible; run with --write`
    );
  }
}

function address(byte, size = 20) {
  return new Address({version: 0, hash: Buffer.alloc(size, byte)});
}

function noneCovenant() {
  return new Covenant();
}

function input(byte, index, sequence) {
  return new Input({
    prevout: new Outpoint(Buffer.alloc(32, byte), index),
    sequence: sequence >>> 0,
    witness: new Witness()
  });
}

function output(value, byte, size = 20) {
  return new Output({value, address: address(byte, size), covenant: noneCovenant()});
}

function createSignatureHashFixture() {
  const tx = new TX({
    version: 2,
    inputs: [
      input(0x11, 3, 0x12345678),
      input(0x22, 5, 0x87654321)
    ],
    outputs: [
      output(111111, 0xaa, 20),
      output(222222, 0xbb, 32),
      output(333333, 0xcc, 20)
    ],
    locktime: 0x34567890
  });
  const previousScript = Script.fromString('OP_2 OP_3 OP_ADD OP_5 OP_EQUAL');
  const previousValue = 987654321;
  const types = [];

  for (const modifier of [0, common.hashType.NOINPUT, common.hashType.ANYONECANPAY,
    common.hashType.NOINPUT | common.hashType.ANYONECANPAY]) {
    for (const base of [common.hashType.ALL, common.hashType.NONE,
      common.hashType.SINGLE, common.hashType.SINGLEREVERSE]) {
      types.push(modifier | base);
    }
  }

  const vectors = [];
  for (let inputIndex = 0; inputIndex < tx.inputs.length; inputIndex++) {
    for (const type of types) {
      vectors.push({
        inputIndex,
        type,
        hash: tx.signatureHash(inputIndex, previousScript, previousValue, type).toString('hex')
      });
    }
  }

  const signatureTypes = [];
  for (const type of [
    0, 1, 2, 3, 4, 5, 0x20, 0x21, 0x40, 0x41, 0x44, 0x45,
    0x80, 0x81, 0x84, 0x85, 0xc1, 0xc4, 0xc5, 0xff
  ]) {
    const signature = Buffer.alloc(65, 0);
    signature[64] = type;
    // isSignatureEncoding also enforces low-S. A zero compact signature is
    // low-S, which isolates the hash-type rule exercised by this vector.
    signatureTypes.push({type, valid: common.isSignatureEncoding(signature)});
  }

  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: ORACLE_REVISION,
      hsdVersion: hsdPackage.version
    },
    transactionRaw: tx.encode().toString('hex'),
    previousScriptRaw: previousScript.encode().toString('hex'),
    previousValue,
    vectors,
    signatureTypes
  };
}

async function createSequenceLockFixture() {
  const nextHeight = 250;
  const tip = {height: nextHeight - 1, marker: 'tip'};
  const ancestorTimes = new Map([
    [0, 1000000],
    [9, 1009000],
    [10, 1010000],
    [24, 1024000],
    [25, 1025000],
    [99, 1099000],
    [100, 1100000],
    [248, 1248000],
    [249, 1249000]
  ]);
  const chain = {
    height: tip.height,
    getLocks: Chain.prototype.getLocks,
    async getAncestor(_tip, height) {
      return {height};
    },
    async getMedianTime(entry) {
      if (entry === tip)
        return ancestorTimes.get(249);
      const time = ancestorTimes.get(entry.height);
      assert.notStrictEqual(time, undefined, `missing fixture MTP for ${entry.height}`);
      return time;
    }
  };

  const cases = [
    {
      id: 'disabled-sequence',
      sequences: [consensus.SEQUENCE_DISABLE_FLAG | 123],
      coinHeights: [10]
    },
    {
      id: 'height-relative-confirmed',
      sequences: [5],
      coinHeights: [100]
    },
    {
      id: 'height-relative-unconfirmed',
      sequences: [2],
      coinHeights: [-1]
    },
    {
      id: 'time-relative-confirmed',
      sequences: [consensus.SEQUENCE_TYPE_FLAG | 3],
      coinHeights: [25]
    },
    {
      id: 'mixed-maxima',
      sequences: [7, consensus.SEQUENCE_TYPE_FLAG | 4, 2],
      coinHeights: [10, 100, 24]
    }
  ];

  const vectors = [];
  for (const item of cases) {
    const inputs = item.sequences.map((sequence, index) => input(0x30 + index, index, sequence));
    const tx = new TX({
      version: 2,
      inputs,
      outputs: [output(1, 0xdd, 20)],
      locktime: 0
    });
    const heights = new Map(
      inputs.map((txInput, index) => [txInput.prevout.toKey().toString('hex'), item.coinHeights[index]])
    );
    const view = {
      getHeight(prevout) {
        const height = heights.get(prevout.toKey().toString('hex'));
        assert.notStrictEqual(height, undefined, 'missing coin height');
        return height;
      }
    };
    const [minimumHeight, minimumTime] = await Chain.prototype.getLocks.call(
      chain,
      tip,
      tx,
      view,
      0
    );
    const valid = await Chain.prototype.verifyLocks.call(chain, tip, tx, view, 0);
    vectors.push({
      id: item.id,
      transactionRaw: tx.encode().toString('hex'),
      coinHeights: item.coinHeights,
      nextHeight,
      tipMedianTime: ancestorTimes.get(249),
      ancestorMedianTimes: Object.fromEntries(
        [...ancestorTimes.entries()].map(([height, time]) => [String(height), time])
      ),
      minimumHeight,
      minimumTime,
      valid
    });
  }

  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: ORACLE_REVISION,
      source: 'lib/blockchain/chain.js#getLocks/verifyLocks'
    },
    vectors
  };
}

async function main() {
  writeOrCheck('sighash-v1.json', createSignatureHashFixture());
  writeOrCheck('sequence-locks-v1.json', await createSequenceLockFixture());
  process.stdout.write(
    `${WRITE ? 'wrote' : 'verified'} hsrd phase-2 hsd fixtures at ${FIXTURE_ROOT}\n`
  );
}

main().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
