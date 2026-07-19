#!/usr/bin/env node
'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const path = require('node:path');
const {installMemoryOnlyDatabaseShim} = require('./memory-db-shim');
const {spawnSync} = require('node:child_process');

const hsd = resolveHsd();
installMemoryOnlyDatabaseShim(hsd);
const FullNode = require(path.join(hsd, 'lib/node/fullnode'));
const Headers = require(path.join(hsd, 'lib/primitives/headers'));
const consensus = require(path.join(hsd, 'lib/protocol/consensus'));
const walletPlugin = require(path.join(hsd, 'lib/wallet/plugin'));
const BLAKE2b = require(require.resolve('bcrypto/lib/blake2b', {paths: [hsd]}));

const repo = path.resolve(__dirname, '..');

async function main() {
  const node = new FullNode({
    memory: true,
    network: 'regtest',
    apiKey: 'meshmine-regtest',
    workers: false,
    plugins: [walletPlugin]
  });

  try {
    await node.open();
    const walletdb = node.require('walletdb').wdb;
    const wallet = await walletdb.create();
    node.miner.addresses.length = 0;
    node.miner.addAddress(await wallet.receiveAddress());

    // updateWork both builds the operator's local body and makes that exact
    // template available to hsd's unmodified work-submission path.
    const attempt = await node.rpc.updateWork();
    assert.strictEqual(attempt.height, 1);
    assert(attempt.coinbase);
    assert.strictEqual(attempt.bits, 0x207fffff);

    const mask = crypto.createHash('sha256')
      .update('meshmine/mm-0001/wp3/regtest-mask', 'utf8')
      .digest();
    mask[0] &= 0x7f;
    assert(!mask.equals(consensus.ZERO_HASH));

    const extraNonce = Buffer.alloc(consensus.NONCE_SIZE, 0);
    const minerHeader = attempt.getHeader(
      0,
      attempt.time,
      extraNonce,
      mask
    );
    const captureTarget = Buffer.alloc(32, 0xff);
    captureTarget[0] = 0x7f;

    let start = 0;
    let capture = null;
    let powHash = null;

    for (let observation = 0; observation < 1024; observation++) {
      capture = runCpuMiner(minerHeader, captureTarget, start);
      const raw = Buffer.from(capture.shareHash, 'hex');
      assert(raw.compare(captureTarget) <= 0);
      powHash = xor(raw, mask);
      if (powHash.compare(attempt.target) <= 0)
        break;
      start = capture.nonce + 1;
      capture = null;
    }
    assert(capture, 'failed to find a captured regtest network winner');

    // The CPU process has exited and never received the mask. Opening it here
    // is sufficient to discover and reconstruct the accepted winning proof.
    const solved = Buffer.from(minerHeader);
    solved.writeUInt32LE(capture.nonce, 0);
    const parsed = Headers.fromMiner(solved);
    assert(parsed.maskHash().equals(BLAKE2b.multi(parsed.prevBlock, mask)));
    assert.strictEqual(parsed.shareHash().toString('hex'), capture.shareHash);

    const proof = attempt.getProof(
      capture.nonce,
      attempt.time,
      extraNonce,
      mask
    );
    assert(proof.verify(attempt.target));
    const reconstructed = attempt.commit(proof);
    assert(reconstructed.verify(), 'reconstructed block must pass hsd checks');

    const [accepted, reason] = await node.rpc.handleWork(solved, mask);
    assert.strictEqual(accepted, true);
    assert.strictEqual(reason, 'valid');
    assert.strictEqual(node.chain.height, 1);
    assert(node.chain.tip.hash.equals(reconstructed.hash()));

    console.log(JSON.stringify({
      status: 'accepted',
      hsd_network: node.network.type,
      height: node.chain.height,
      block_hash: reconstructed.hash().toString('hex'),
      capture_nonce: capture.nonce,
      share_hash: capture.shareHash,
      pow_hash: powHash.toString('hex'),
      mask_opened_after_capture: true,
      cpu_miner_received_mask: false
    }, null, 2));
  } finally {
    if (node.opened)
      await node.close();
  }
}

function runCpuMiner(header, target, start) {
  const result = spawnSync('cargo', [
    'run', '--locked', '--quiet',
    '--manifest-path', path.join(repo, 'Cargo.toml'),
    '-p', 'meshmine-node', '--',
    'cpu-mine',
    '--header', header.toString('hex'),
    '--capture-target', target.toString('hex'),
    '--start', String(start),
    '--limit', '1000000'
  ], {
    cwd: repo,
    encoding: 'utf8',
    env: process.env
  });
  if (result.status !== 0)
    throw new Error(result.stderr || result.stdout || 'CPU miner failed');
  const fields = Object.fromEntries(
    result.stdout.trim().split('\n').map(line => line.split('='))
  );
  return {
    nonce: Number(fields.nonce),
    shareHash: fields.share_hash
  };
}

function xor(left, right) {
  const out = Buffer.alloc(32);
  for (let index = 0; index < 32; index++)
    out[index] = left[index] ^ right[index];
  return out;
}

function resolveHsd() {
  if (process.env.HSD_DIR)
    return path.resolve(process.env.HSD_DIR);
  try {
    return path.dirname(require.resolve('hsd/package.json'));
  } catch (error) {
    throw new Error('hsd was not found; set HSD_DIR or run npm install', {cause: error});
  }
}

main().catch(error => {
  console.error(error.stack || error.message);
  process.exit(1);
});
