#!/usr/bin/env node
'use strict';

// Read one canonical block from the configured running hsd, decode it with
// hsd's own Block implementation, and return only the bounded fields needed
// by MeshMine's durable payment/reorg controller.

const path = require('node:path');

const COMMITMENT_SIZE = 147;
const MAGIC = Buffer.from('HNSM', 'ascii');

async function main() {
  const hsd = process.argv[2];
  const heightText = process.argv[3];
  if (!hsd || !/^(0|[1-9][0-9]*)$/.test(heightText || ''))
    throw new Error('usage: rpc-block-payment.js /absolute/path/to/hsd HEIGHT');

  const height = Number(heightText);
  if (!Number.isSafeInteger(height) || height > 0xffffffff)
    throw new Error('height is outside the uint32 range');

  const Config = require(path.join(hsd, 'node_modules/bcfg'));
  const {NodeClient} = require(path.join(hsd, 'lib/client'));
  const Block = require(path.join(hsd, 'lib/primitives/block'));
  const consensus = require(path.join(hsd, 'lib/protocol/consensus'));
  const Network = require(path.join(hsd, 'lib/protocol/network'));
  const ports = {main: 12037, testnet: 13037, regtest: 14037, simnet: 15037};
  const config = new Config('hsd', {
    suffix: 'network',
    fallback: 'main',
    alias: {
      n: 'network',
      u: 'url',
      uri: 'url',
      k: 'apikey',
      s: 'ssl',
      h: 'httphost',
      p: 'httpport'
    }
  });
  config.load({env: true});
  config.open('hsd.conf');
  const network = config.str('network', 'main');
  const client = new NodeClient({
    url: config.str('url'),
    apiKey: config.str('api-key'),
    ssl: config.bool('ssl'),
    host: config.str('http-host'),
    port: config.uint('http-port') || ports[network] || ports.main,
    timeout: config.uint('timeout') || 5000,
    limit: config.uint('limit')
  });

  // Resolve by canonical height both before and after reading the body. This
  // turns a concurrent reorg into a retryable adapter failure, not a mixed
  // chain event.
  const expected = await client.execute('getblockhash', [height]);
  const rawHex = await client.execute('getblock', [expected, false]);
  const confirmed = await client.execute('getblockhash', [height]);
  if (expected !== confirmed)
    throw new Error('canonical block changed during the bounded query');

  const block = Block.fromRaw(Buffer.from(rawHex, 'hex'));
  const hash = block.hash().toString('hex');
  if (hash !== expected)
    throw new Error('hsd block decoding did not reproduce the canonical hash');
  if (block.txs.length === 0 || block.txs[0].inputs.length === 0)
    throw new Error('canonical block has no coinbase input');

  const candidates = block.txs[0].inputs[0].witness.items.filter((item) =>
    item.length === COMMITMENT_SIZE && item.subarray(0, 4).equals(MAGIC));
  const commitment = candidates.length === 1 ? candidates[0].toString('hex') : null;
  const configuredNetwork = Network.get(network);
  const coinbase = block.txs[0];
  const outputs = commitment === null ? [] : coinbase.outputs.map((output) => ({
    value: output.value.toString(10),
    address_version: output.address.version,
    address_hash: output.address.hash.toString('hex'),
    covenant_type: output.covenant.type,
    covenant_items: output.covenant.items.length
  }));
  process.stdout.write(JSON.stringify({
    height,
    hash,
    previous_block_hash: block.prevBlock.toString('hex'),
    commitment,
    ambiguous_commitments: candidates.length > 1,
    subsidy: consensus.getReward(height, configuredNetwork.halvingInterval).toString(10),
    coinbase_input_count: coinbase.inputs.length,
    coinbase_outputs: outputs
  }) + '\n');
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
