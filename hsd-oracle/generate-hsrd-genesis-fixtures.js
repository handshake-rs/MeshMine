#!/usr/bin/env node
'use strict';

// Export and independently sanity-check the canonical serialized genesis block
// for every HSD network. These bytes originate in HSD's checked-in
// lib/protocol/genesis-data.json and are exposed through Network.genesisBlock.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const childProcess = require('child_process');
const fs = require('fs');
const path = require('path');

const externalHsdRoot = process.env.HSD_DIR;
const hsdRoot = externalHsdRoot
  ? fs.realpathSync(path.resolve(externalHsdRoot))
  : path.dirname(require.resolve('hsd/package.json'));
const hsdPackage = require(path.join(hsdRoot, 'package.json'));
const Block = require(path.join(hsdRoot, 'lib/primitives/block'));
const Network = require(path.join(hsdRoot, 'lib/protocol/network'));

const REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(ROOT, 'hsrd/fixtures/hsd/blocks/genesis-v1.json');
const NETWORKS = ['main', 'testnet', 'regtest', 'simnet'];

if (externalHsdRoot) {
  const revision = childProcess.execFileSync(
    'git',
    ['-C', hsdRoot, 'rev-parse', 'HEAD'],
    {encoding: 'utf8'}
  ).trim();
  assert.strictEqual(
    revision,
    REVISION,
    `HSD source must be pinned to ${REVISION}`
  );
}

function exportNetwork(name) {
  const network = Network.get(name);
  const raw = network.genesisBlock;
  const block = Block.decode(raw);
  const [valid, reason, score] = block.checkBody();

  assert(block.encode().equals(raw), `${name}: genesis bytes do not round-trip`);
  assert(block.hash().equals(network.genesis.hash), `${name}: genesis hash mismatch`);
  assert.strictEqual(block.txs.length, 1, `${name}: unexpected transaction count`);
  assert.strictEqual(block.getCoinbaseHeight(), 0, `${name}: unexpected coinbase height`);
  assert.strictEqual(valid, true, `${name}: HSD rejected genesis body: ${reason}`);
  assert.strictEqual(reason, 'valid', `${name}: unexpected HSD body result`);
  assert.strictEqual(score, 0, `${name}: valid genesis has a ban score`);

  const coinbase = block.txs[0];
  assert.strictEqual(coinbase.inputs.length, 1, `${name}: unexpected coinbase inputs`);
  assert.strictEqual(coinbase.outputs.length, 1, `${name}: unexpected coinbase outputs`);
  const output = coinbase.outputs[0];

  return {
    network: name,
    raw: raw.toString('hex'),
    size: raw.length,
    hash: block.hash().toString('hex'),
    transactionCount: block.txs.length,
    coinbaseHeight: block.getCoinbaseHeight(),
    coinbaseTxid: coinbase.txid().toString('hex'),
    output: {
      value: output.value,
      addressVersion: output.address.version,
      addressHash: output.address.hash.toString('hex'),
      covenantType: output.covenant.type
    },
    bodyValidation: {valid, reason, score}
  };
}

function stable(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function fixture() {
  const networks = NETWORKS.map(exportNetwork);
  const canonicalBody = Buffer.from(networks[0].raw, 'hex').subarray(236);
  for (const entry of networks.slice(1)) {
    const body = Buffer.from(entry.raw, 'hex').subarray(236);
    assert(body.equals(canonicalBody), `${entry.network}: genesis body differs from mainnet`);
  }

  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: REVISION,
      hsdVersion: hsdPackage.version
    },
    source: 'lib/protocol/genesis-data.json via Network.genesisBlock',
    networks
  };
}

function main() {
  const write = process.argv.includes('--write');
  const check = process.argv.includes('--check');
  assert(write || check, 'use --write and/or --check');
  const value = fixture();
  const expected = stable(value);

  if (write) {
    fs.mkdirSync(path.dirname(OUTPUT), {recursive: true});
    fs.writeFileSync(OUTPUT, expected, {encoding: 'utf8', mode: 0o644});
    console.log(`wrote ${path.relative(ROOT, OUTPUT)}`);
  }

  if (check) {
    const actual = fs.readFileSync(OUTPUT, 'utf8');
    assert.strictEqual(actual, expected, `${OUTPUT} is not reproducible`);
    console.log(`verified ${path.relative(ROOT, OUTPUT)}`);
  }
}

main();
