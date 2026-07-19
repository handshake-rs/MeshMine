#!/usr/bin/env node
'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const path = require('node:path');

const options = parseArgs(process.argv.slice(2));
const hsd = resolveHsd(options.hsd);
const Headers = require(path.join(hsd, 'lib/primitives/headers'));
const consensus = require(path.join(hsd, 'lib/protocol/consensus'));
const BLAKE2b = require(resolveFromHsd(hsd, 'bcrypto/lib/blake2b'));
const BN = require(resolveFromHsd(hsd, 'bcrypto/lib/bn.js'));
const merkle = require(resolveFromHsd(hsd, 'bcrypto/lib/mrkl'));

class DeterministicBytes {
  constructor(seed) {
    this.seed = crypto.createHash('sha256').update(seed, 'utf8').digest();
    this.counter = 0n;
    this.buffer = Buffer.alloc(0);
  }

  bytes(size) {
    while (this.buffer.length < size) {
      const counter = Buffer.alloc(8);
      counter.writeBigUInt64LE(this.counter++);
      const block = crypto.createHash('sha256')
        .update(this.seed)
        .update(counter)
        .digest();
      this.buffer = Buffer.concat([this.buffer, block]);
    }
    const out = this.buffer.subarray(0, size);
    this.buffer = this.buffer.subarray(size);
    return out;
  }

  u32() {
    return this.bytes(4).readUInt32LE();
  }

  safeU64() {
    return this.bytes(6).readUIntLE(0, 6);
  }
}

const edgeTargets = [
  '0',
  '1',
  '7f',
  '80',
  '7fff',
  '8000',
  '7fffff',
  '800000',
  'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
];

async function main() {
  const random = new DeterministicBytes(options.seed);

  for (let index = 0; index < options.count; index++) {
    const target = index < edgeTargets.length
      ? new BN(edgeTargets[index], 16)
      : new BN(random.bytes(32), 'be');
    const bits = consensus.toCompact(target);
    const decodedTarget = consensus.fromCompact(bits);
    assert(!decodedTarget.isNeg());

    const header = new Headers({
      nonce: random.u32(),
      time: random.safeU64(),
      prevBlock: random.bytes(32),
      treeRoot: random.bytes(32),
      extraNonce: random.bytes(24),
      reservedRoot: random.bytes(32),
      witnessRoot: random.bytes(32),
      merkleRoot: random.bytes(32),
      version: random.u32(),
      bits,
      mask: random.bytes(32)
    });

    const leafCount = index % 9;
    const leaves = [];
    for (let leaf = 0; leaf < leafCount; leaf++)
      leaves.push(random.bytes(32));

    const vector = {
      index,
      input: {
        nonce: header.nonce,
        time: String(header.time),
        prev_block: hex(header.prevBlock),
        tree_root: hex(header.treeRoot),
        extra_nonce: hex(header.extraNonce),
        reserved_root: hex(header.reservedRoot),
        witness_root: hex(header.witnessRoot),
        merkle_root: hex(header.merkleRoot),
        version: header.version,
        bits: header.bits,
        mask: hex(header.mask),
        merkle_leaves: leaves.map(hex)
      },
      expected: {
        header: hex(header.toHead()),
        miner: hex(header.toMiner()),
        padding_8: hex(header.padding(8)),
        padding_20: hex(header.padding(20)),
        padding_32: hex(header.padding(32)),
        subheader: hex(header.toSubhead()),
        sub_hash: hex(header.subHash()),
        mask_hash: hex(header.maskHash()),
        commit_hash: hex(header.commitHash()),
        preheader: hex(header.toPrehead()),
        share_hash: hex(header.shareHash()),
        pow_hash: hex(header.powHash()),
        target_hex: decodedTarget.toString(16),
        compact_roundtrip: consensus.toCompact(decodedTarget),
        pow_valid: consensus.verifyPOW(header.powHash(), bits),
        merkle_root: hex(merkle.createRoot(BLAKE2b, leaves))
      }
    };

    if (!process.stdout.write(`${JSON.stringify(vector)}\n`))
      await new Promise(resolve => process.stdout.once('drain', resolve));
  }
}

function hex(value) {
  return value.toString('hex');
}

function resolveHsd(argument) {
  const configured = argument || process.env.HSD_DIR;
  if (configured)
    return path.resolve(configured);

  try {
    return path.dirname(require.resolve('hsd/package.json'));
  } catch (error) {
    throw new Error(
      'hsd was not found; set HSD_DIR, pass --hsd, or run npm install in hsd-oracle',
      {cause: error}
    );
  }
}

function resolveFromHsd(hsd, module) {
  return require.resolve(module, {paths: [hsd]});
}

function parseArgs(args) {
  const result = {
    count: 10000,
    seed: 'meshmine/mm-0001/wp1/v1',
    hsd: null
  };

  for (let index = 0; index < args.length; index++) {
    const name = args[index];
    const value = args[++index];
    if (value == null)
      throw new Error(`missing value for ${name}`);
    switch (name) {
      case '--count':
        result.count = Number(value);
        break;
      case '--seed':
        result.seed = value;
        break;
      case '--hsd':
        result.hsd = value;
        break;
      default:
        throw new Error(`unknown argument: ${name}`);
    }
  }

  if (!Number.isSafeInteger(result.count) || result.count < 1 || result.count > 1000000)
    throw new Error('--count must be an integer from 1 through 1000000');
  return result;
}

process.stdout.on('error', error => {
  if (error.code === 'EPIPE')
    process.exit(1);
  throw error;
});

main().catch(error => {
  console.error(error.stack || error.message);
  process.exit(1);
});
