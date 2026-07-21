'use strict';

// Export and verify a canonical mainnet block containing real DNSSEC CLAIM
// witnesses. Refresh combines raw archival block bytes with the canonical
// header chain served by a locally synchronized HSD node. Offline checking
// replays the bytes and claims through the pinned HSD implementation.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const https = require('https');
const path = require('path');

const blake2b = require('bcrypto/lib/blake2b');
const Block = require('hsd/lib/primitives/block');
const ChainEntry = require('hsd/lib/blockchain/chainentry');
const Headers = require('hsd/lib/primitives/headers');
const Network = require('hsd/lib/protocol/network');
const OwnershipProof = require('hsd/lib/covenants/ownership').Proof;
const consensus = require('hsd/lib/protocol/consensus');

const REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(
  ROOT,
  'hsrd/fixtures/hsd/claims/mainnet-history-v1.json'
);
const BLOCK_HEIGHT = 62517;
const CHECKPOINT_HEIGHT = 61043;
const MEDIAN_TIMESPAN = 11;
const DEFAULT_ARCHIVE_BASE = 'https://hsd.hns.au/api/v1';
const MAX_ARCHIVE_RESPONSE = 4 * 1024 * 1024;

function hasFlag(name) {
  return process.argv.includes(name);
}

function option(name) {
  const index = process.argv.indexOf(name);
  if (index === -1)
    return null;
  assert(index + 1 < process.argv.length, `${name} requires a value`);
  return process.argv[index + 1];
}

function parseConfig(prefix) {
  const values = Object.create(null);
  const file = path.join(prefix, 'hsd.conf');
  const source = fs.readFileSync(file, 'utf8');
  for (const original of source.split(/\r?\n/)) {
    const line = original.replace(/#.*$/, '').trim();
    if (!line)
      continue;
    const separator = line.search(/[:=]/);
    if (separator === -1)
      continue;
    values[line.slice(0, separator).trim()] =
      line.slice(separator + 1).trim();
  }
  return values;
}

function stable(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function median(values) {
  const sorted = values.slice().sort((left, right) => left - right);
  return sorted[sorted.length >>> 1];
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, response => {
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`${url} returned HTTP ${response.statusCode}`));
        return;
      }
      let size = 0;
      const chunks = [];
      response.on('data', chunk => {
        size += chunk.length;
        if (size > MAX_ARCHIVE_RESPONSE) {
          request.destroy(new Error(`${url} exceeds the response bound`));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch (error) {
          reject(error);
        }
      });
    });
    request.setTimeout(60_000, () => {
      request.destroy(new Error(`${url} timed out`));
    });
    request.on('error', reject);
  });
}

function headerJson(entry) {
  const header = entry.toHeaders();
  assert(header.hash().equals(entry.hash), `header hash mismatch at ${entry.height}`);
  return {
    height: entry.height,
    hash: entry.hash.toString('hex'),
    raw: header.encode().toString('hex'),
    time: entry.time
  };
}

function claimVector(block, outputIndex, parentTime, network) {
  const coinbase = block.txs[0];
  const input = coinbase.inputs[outputIndex];
  const output = coinbase.outputs[outputIndex];
  assert(input, `claim output ${outputIndex} has no matching input`);
  assert(output.covenant.isClaim(), `output ${outputIndex} is not CLAIM`);
  assert.strictEqual(input.witness.items.length, 1,
    `claim input ${outputIndex} witness count`);

  const proofRaw = input.witness.items[0];
  const proof = OwnershipProof.decode(proofRaw);
  assert(proof.isSane(), `claim output ${outputIndex} proof sanity`);
  assert(proof.verifySignatures(),
    `claim output ${outputIndex} DNSSEC signatures`);
  assert(proof.verifyTimes(parentTime),
    `claim output ${outputIndex} parent-time window`);
  const data = proof.getData(network);
  assert(data, `claim output ${outputIndex} ownership TXT data`);

  const name = output.covenant.get(2).toString('binary');
  assert.strictEqual(data.name, name, `claim output ${outputIndex} name`);
  assert.strictEqual(output.covenant.getU32(1), BLOCK_HEIGHT,
    `claim output ${outputIndex} height`);
  assert.strictEqual(output.covenant.getU8(3) & 1, Number(data.weak),
    `claim output ${outputIndex} weak flag`);
  assert(output.covenant.getHash(4).equals(data.commitHash),
    `claim output ${outputIndex} commit hash`);
  assert.strictEqual(output.covenant.getU32(5), data.commitHeight,
    `claim output ${outputIndex} commit height`);
  assert.strictEqual(output.address.version, data.version,
    `claim output ${outputIndex} address version`);
  assert(output.address.hash.equals(data.hash),
    `claim output ${outputIndex} address hash`);
  assert.strictEqual(output.value, data.value - data.fee,
    `claim output ${outputIndex} value`);

  let conjured = data.value;
  if (BLOCK_HEIGHT >= network.deflationHeight && data.commitHeight !== 1)
    conjured = output.value;
  if (BLOCK_HEIGHT >= network.deflationHeight && data.commitHeight === 1)
    assert(data.fee <= 1000 * consensus.COIN,
      `claim output ${outputIndex} initial fee`);

  const [inception, expiration] = proof.getWindow();
  return {
    outputIndex,
    name,
    target: proof.getTarget(),
    nameHash: output.covenant.getHash(0).toString('hex'),
    weak: data.weak,
    proofRaw: proofRaw.toString('hex'),
    proofBlake2b256: blake2b.digest(proofRaw, 32).toString('hex'),
    proofSize: proofRaw.length,
    inception,
    expiration,
    signaturesValid: true,
    timesValidAtParent: true,
    commitHash: data.commitHash.toString('hex'),
    commitHeight: data.commitHeight,
    version: data.version,
    address: data.hash.toString('hex'),
    reservedValue: data.value,
    fee: data.fee,
    outputValue: output.value,
    conjured
  };
}

function blockClaims(block, parentTime, network) {
  const claims = [];
  const coinbase = block.txs[0];
  for (let index = 1; index < coinbase.outputs.length; index++) {
    if (coinbase.outputs[index].covenant.isClaim())
      claims.push(claimVector(block, index, parentTime, network));
  }
  return claims;
}

function decodeContextHeader(expected) {
  const raw = Buffer.from(expected.raw, 'hex');
  const header = Headers.decode(raw);
  assert.strictEqual(header.encode().toString('hex'), expected.raw,
    `context header ${expected.height} round trip`);
  assert.strictEqual(header.hash().toString('hex'), expected.hash,
    `context header ${expected.height} hash`);
  assert.strictEqual(header.time, expected.time,
    `context header ${expected.height} time`);
  return header;
}

function validateFixture(fixture) {
  assert.strictEqual(fixture.schema, 1);
  assert.deepStrictEqual(fixture.oracle, {
    repository: 'handshake-org/hsd',
    revision: REVISION,
    nodeVersion: fixture.oracle.nodeVersion,
    archivalApi: fixture.oracle.archivalApi
  });
  assert.strictEqual(fixture.network, 'main');

  const network = Network.get('main');
  const checkpoint = network.checkpointMap[CHECKPOINT_HEIGHT];
  assert(checkpoint, `missing HSD checkpoint ${CHECKPOINT_HEIGHT}`);
  assert.strictEqual(fixture.canonicalContext.checkpointHeight,
    CHECKPOINT_HEIGHT);
  assert.strictEqual(fixture.canonicalContext.checkpointHash,
    checkpoint.toString('hex'));
  assert.strictEqual(fixture.canonicalContext.linkedHeaderCount,
    BLOCK_HEIGHT - CHECKPOINT_HEIGHT + 1);

  const context = fixture.canonicalContext.contextHeaders;
  assert.strictEqual(context.length, MEDIAN_TIMESPAN + 1);
  const commit = context[0];
  assert.strictEqual(commit.height, 1);
  decodeContextHeader(commit);

  const parents = context.slice(1);
  assert.strictEqual(parents[0].height,
    BLOCK_HEIGHT - MEDIAN_TIMESPAN);
  assert.strictEqual(parents.at(-1).height, BLOCK_HEIGHT - 1);
  let previous = null;
  for (const expected of parents) {
    const header = decodeContextHeader(expected);
    if (previous)
      assert(header.prevBlock.equals(previous.hash()),
        `context header link at ${expected.height}`);
    previous = header;
  }
  assert.strictEqual(fixture.canonicalContext.parentTime,
    parents.at(-1).time);
  assert.strictEqual(fixture.canonicalContext.parentMedianTime,
    median(parents.map(item => item.time)));

  const block = Block.decode(Buffer.from(fixture.block.raw, 'hex'));
  assert.strictEqual(block.encode().toString('hex'), fixture.block.raw);
  assert.strictEqual(block.hash().toString('hex'), fixture.block.hash);
  assert.strictEqual(fixture.block.height, BLOCK_HEIGHT);
  assert.strictEqual(block.getCoinbaseHeight(), BLOCK_HEIGHT);
  assert(block.verifyBody(), 'HSD mainnet claim block body');
  assert(block.prevBlock.equals(previous.hash()), 'claim block parent link');
  assert.strictEqual(block.getSize(), fixture.block.size);
  assert.strictEqual(block.getBaseSize(), fixture.block.baseSize);
  assert.strictEqual(block.getWeight(), fixture.block.weight);
  assert.strictEqual(block.txs.length, fixture.block.transactionCount);

  const claims = blockClaims(
    block,
    fixture.canonicalContext.parentTime,
    network
  );
  assert.deepStrictEqual(claims, fixture.block.claims);
  assert.strictEqual(claims.length, 2);
  assert.deepStrictEqual(claims.map(claim => claim.name),
    ['jinronghd', 'namecheap']);
  assert(claims.some(claim => claim.weak), 'historical weak claim evidence');
  assert(claims.every(claim => claim.commitHash === commit.hash),
    'claim commitments bind to canonical height 1');
}

async function fetchFixture(prefix, archiveBase) {
  const {NodeClient} = require('hsd/lib/client');
  const settings = parseConfig(prefix);
  assert((settings.network || 'main') === 'main',
    'claim-history export requires a mainnet HSD node');
  const host = option('--rpc-host') || settings['http-host'] || '127.0.0.1';
  const port = Number(option('--rpc-port') || settings['http-port'] || 12037);
  const apiKey = process.env.HSD_API_KEY || settings['api-key'];
  assert(apiKey, 'HSD API key is missing from the selected prefix');
  assert(Number.isSafeInteger(port) && port > 0 && port <= 65535,
    'HSD RPC port is invalid');

  const url = `${archiveBase.replace(/\/$/, '')}/block/${BLOCK_HEIGHT}`;
  const json = await fetchJson(url);
  assert.strictEqual(json.height, BLOCK_HEIGHT,
    'archival API returned the wrong height');
  const block = Block.fromJSON(json);
  assert.strictEqual(block.hash().toString('hex'), json.hash,
    'archival block JSON hash');
  for (const [index, tx] of block.txs.entries()) {
    assert.strictEqual(tx.toHex(), json.txs[index].hex,
      `archival transaction ${index} bytes`);
  }
  assert(block.verifyBody(), 'archival HSD block body');

  const client = new NodeClient({host, port, apiKey});
  await client.open();
  try {
    const info = await client.getInfo();
    assert(info && info.network === 'main', 'HSD RPC network must be mainnet');
    assert(info.chain && info.chain.height >= BLOCK_HEIGHT,
      `HSD must be synchronized through height ${BLOCK_HEIGHT}`);

    const raws = await client.getEntries(CHECKPOINT_HEIGHT, BLOCK_HEIGHT);
    assert.strictEqual(raws.length, BLOCK_HEIGHT - CHECKPOINT_HEIGHT + 1,
      'HSD returned an incomplete checkpoint-to-claim header chain');
    const entries = raws.map(raw => ChainEntry.decode(raw));
    const network = Network.get('main');
    const checkpoint = network.checkpointMap[CHECKPOINT_HEIGHT];
    assert(entries[0].hash.equals(checkpoint),
      'canonical chain does not begin at the pinned HSD checkpoint');
    for (let index = 0; index < entries.length; index++) {
      const entry = entries[index];
      assert.strictEqual(entry.height, CHECKPOINT_HEIGHT + index,
        `canonical header height ${index}`);
      if (index !== 0)
        assert(entry.prevBlock.equals(entries[index - 1].hash),
          `canonical header link at ${entry.height}`);
    }
    assert(entries.at(-1).hash.equals(block.hash()),
      'archival block is not the local HSD canonical block');

    const commitRaw = await client.getEntries(1, 1);
    assert.strictEqual(commitRaw.length, 1, 'HSD commit header');
    const commit = ChainEntry.decode(commitRaw[0]);
    const parents = entries.slice(-MEDIAN_TIMESPAN - 1, -1);
    assert.strictEqual(parents.length, MEDIAN_TIMESPAN,
      'HSD parent-time context');
    const parentTime = parents.at(-1).time;
    const parentMedianTime = median(parents.map(entry => entry.time));
    const claims = blockClaims(block, parentTime, network);

    return {
      schema: 1,
      oracle: {
        repository: 'handshake-org/hsd',
        revision: REVISION,
        nodeVersion: info.version,
        archivalApi: archiveBase.replace(/\/$/, '')
      },
      network: 'main',
      canonicalContext: {
        checkpointHeight: CHECKPOINT_HEIGHT,
        checkpointHash: checkpoint.toString('hex'),
        linkedHeaderCount: entries.length,
        parentTime,
        parentMedianTime,
        contextHeaders: [commit, ...parents].map(headerJson)
      },
      block: {
        height: BLOCK_HEIGHT,
        hash: block.hash().toString('hex'),
        raw: block.encode().toString('hex'),
        size: block.getSize(),
        baseSize: block.getBaseSize(),
        weight: block.getWeight(),
        transactionCount: block.txs.length,
        claims
      }
    };
  } finally {
    await client.close();
  }
}

async function main() {
  const refresh = hasFlag('--refresh');
  const write = hasFlag('--write');
  const check = hasFlag('--check');
  assert(check || (refresh && write),
    'use --check, or --refresh --write [--check]');
  assert(!write || refresh, '--write requires --refresh');

  let fixture;
  if (refresh) {
    const prefix = option('--hsd-prefix') || process.env.HSD_PREFIX;
    assert(prefix, '--refresh requires --hsd-prefix or HSD_PREFIX');
    const archiveBase = option('--archive-base') || DEFAULT_ARCHIVE_BASE;
    fixture = await fetchFixture(path.resolve(prefix), archiveBase);
    validateFixture(fixture);
    if (write) {
      fs.mkdirSync(path.dirname(OUTPUT), {recursive: true});
      fs.writeFileSync(OUTPUT, stable(fixture));
      console.log(`wrote ${path.relative(ROOT, OUTPUT)}`);
    }
  }

  if (check) {
    const committed = JSON.parse(fs.readFileSync(OUTPUT, 'utf8'));
    validateFixture(committed);
    if (refresh) {
      assert.strictEqual(
        stable(committed),
        stable(fixture),
        `${OUTPUT} differs from the selected live HSD history`
      );
    }
    console.log(`verified ${path.relative(ROOT, OUTPUT)}`);
  }
}

main().catch(error => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
