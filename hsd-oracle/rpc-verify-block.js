#!/usr/bin/env node
'use strict';

// Bounded stdin adapter for hsd's no-PoW `verifyblock` RPC. Passing a full
// block as an argv hex string exceeds common ARG_MAX limits near the MM-0001
// body bound, so the Rust daemon streams raw block bytes to this helper.

const path = require('node:path');

const MAX_BLOCK_BYTES = 4 * 1024 * 1024 + 4096;

async function main() {
  const hsd = process.argv[2];
  if (!hsd)
    throw new Error('usage: rpc-verify-block.js /absolute/path/to/hsd');

  const Config = require(path.join(hsd, 'node_modules/bcfg'));
  const {NodeClient} = require(path.join(hsd, 'lib/client'));
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
  const block = await readStdin();
  const reason = await client.execute('verifyblock', [block.toString('hex')]);
  process.stdout.write(JSON.stringify({valid: reason === null, reason}) + '\n');
}

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    process.stdin.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BLOCK_BYTES) {
        reject(new Error('block input exceeds bound'));
        process.stdin.destroy();
        return;
      }
      chunks.push(chunk);
    });
    process.stdin.on('end', () => resolve(Buffer.concat(chunks, size)));
    process.stdin.on('error', reject);
  });
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
