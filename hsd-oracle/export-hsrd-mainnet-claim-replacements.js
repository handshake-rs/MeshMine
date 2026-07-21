'use strict';

// Export and verify a bounded canonical mainnet history containing ten
// initial DNSSEC claims and the later coinbase which replaced all ten. The
// refresh path combines archival block bytes with checkpoint-linked headers
// from a locally synchronized HSD node. Offline checking replays every byte
// and ownership proof through the pinned HSD implementation.

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
  'hsrd/fixtures/hsd/claims/mainnet-replacements-v1.json'
);
const MEDIAN_TIMESPAN = 11;
const DEFAULT_ARCHIVE_BASE = 'https://hsd.hns.au/api/v1';
const MAX_ARCHIVE_RESPONSE = 8 * 1024 * 1024;
const INITIAL_HEIGHTS = [39086, 39090, 39092, 39095, 39098, 39099, 39101];
const REPLACEMENT_HEIGHT = 76722;
const BLOCK_HEIGHTS = [...INITIAL_HEIGHTS, REPLACEMENT_HEIGHT];
const SEGMENTS = [
  {checkpointHeight: 30000, endHeight: 39101},
  {checkpointHeight: 61043, endHeight: REPLACEMENT_HEIGHT}
];
const REPLACEMENTS = [
  {name: 'pinoynewsfeed', initialHeight: 39090, initialIndex: 6, replacementIndex: 1},
  {name: 'bluraytorrent', initialHeight: 39090, initialIndex: 5, replacementIndex: 2},
  {name: 'appdownloadcity', initialHeight: 39086, initialIndex: 6, replacementIndex: 3},
  {name: 'colegiomaturana', initialHeight: 39098, initialIndex: 6, replacementIndex: 4},
  {name: 'globalsystools', initialHeight: 39101, initialIndex: 5, replacementIndex: 5},
  {name: 'mp3pleer', initialHeight: 39092, initialIndex: 4, replacementIndex: 6},
  {name: 'heavenmanga', initialHeight: 39095, initialIndex: 1, replacementIndex: 7},
  {name: 'e-health', initialHeight: 39092, initialIndex: 9, replacementIndex: 8},
  {name: 'tamilgun', initialHeight: 39092, initialIndex: 8, replacementIndex: 9},
  {name: 'iranpipe', initialHeight: 39099, initialIndex: 10, replacementIndex: 10}
];

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
  const source = fs.readFileSync(path.join(prefix, 'hsd.conf'), 'utf8');
  for (const original of source.split(/\r?\n/)) {
    const line = original.replace(/#.*$/, '').trim();
    if (!line)
      continue;
    const separator = line.search(/[:=]/);
    if (separator === -1)
      continue;
    values[line.slice(0, separator).trim()] = line.slice(separator + 1).trim();
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
    request.setTimeout(60_000, () => request.destroy(new Error(`${url} timed out`)));
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

function decodeHeader(expected) {
  const header = Headers.decode(Buffer.from(expected.raw, 'hex'));
  assert.strictEqual(header.encode().toString('hex'), expected.raw,
    `context header ${expected.height} round trip`);
  assert.strictEqual(header.hash().toString('hex'), expected.hash,
    `context header ${expected.height} hash`);
  assert.strictEqual(header.time, expected.time,
    `context header ${expected.height} time`);
  return header;
}

function claimVector(block, outputIndex, parentTime, network) {
  const height = block.getCoinbaseHeight();
  const coinbase = block.txs[0];
  const input = coinbase.inputs[outputIndex];
  const output = coinbase.outputs[outputIndex];
  assert(input, `claim output ${outputIndex} has no matching input`);
  assert(output.covenant.isClaim(), `output ${outputIndex} is not CLAIM`);
  assert.strictEqual(input.witness.items.length, 1,
    `claim output ${outputIndex} witness count`);

  const proofRaw = input.witness.items[0];
  const proof = OwnershipProof.decode(proofRaw);
  assert(proof.isSane(), `claim output ${outputIndex} proof sanity`);
  assert(proof.verifySignatures(), `claim output ${outputIndex} signatures`);
  assert(proof.verifyTimes(parentTime), `claim output ${outputIndex} parent time`);
  const data = proof.getData(network);
  assert(data, `claim output ${outputIndex} ownership TXT data`);

  const name = output.covenant.get(2).toString('binary');
  assert.strictEqual(data.name, name, `claim output ${outputIndex} name`);
  assert.strictEqual(output.covenant.getU32(1), height,
    `claim output ${outputIndex} covenant height`);
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
  if (height >= network.deflationHeight && data.commitHeight !== 1)
    conjured = output.value;
  if (height >= network.deflationHeight && data.commitHeight === 1)
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

function contextRecord(height, entries, checkpointHeight) {
  const index = height - checkpointHeight;
  const parents = entries.slice(index - MEDIAN_TIMESPAN, index);
  assert.strictEqual(parents.length, MEDIAN_TIMESPAN,
    `parent context at ${height}`);
  return {
    blockHeight: height,
    parentTime: parents.at(-1).time,
    parentMedianTime: median(parents.map(entry => entry.time)),
    contextHeaders: parents.map(headerJson)
  };
}

function blockRecord(block, context, network) {
  return {
    role: block.getCoinbaseHeight() === REPLACEMENT_HEIGHT
      ? 'replacement'
      : 'initial',
    height: block.getCoinbaseHeight(),
    hash: block.hash().toString('hex'),
    raw: block.encode().toString('hex'),
    size: block.getSize(),
    baseSize: block.getBaseSize(),
    weight: block.getWeight(),
    transactionCount: block.txs.length,
    coinbaseTxid: block.txs[0].txid(),
    claims: blockClaims(block, context.parentTime, network)
  };
}

function buildHistory(blocks) {
  const byHeight = new Map(blocks.map(block => [block.height, block]));
  const replacementBlock = byHeight.get(REPLACEMENT_HEIGHT);
  assert(replacementBlock, 'replacement block');
  return REPLACEMENTS.map(expected => {
    const initialBlock = byHeight.get(expected.initialHeight);
    assert(initialBlock, `initial block for ${expected.name}`);
    const initial = initialBlock.claims.find(claim =>
      claim.outputIndex === expected.initialIndex && claim.name === expected.name);
    const replacement = replacementBlock.claims.find(claim =>
      claim.outputIndex === expected.replacementIndex && claim.name === expected.name);
    assert(initial, `initial claim for ${expected.name}`);
    assert(replacement, `replacement claim for ${expected.name}`);
    assert.strictEqual(initial.outputValue, replacement.outputValue,
      `${expected.name} replacement value`);
    assert.strictEqual(initial.nameHash, replacement.nameHash,
      `${expected.name} replacement name hash`);
    return {
      name: expected.name,
      nameHash: initial.nameHash,
      initial: {
        blockHeight: initialBlock.height,
        coinbaseTxid: initialBlock.coinbaseTxid,
        outputIndex: initial.outputIndex,
        outputValue: initial.outputValue,
        commitHeight: initial.commitHeight
      },
      replacement: {
        blockHeight: replacementBlock.height,
        coinbaseTxid: replacementBlock.coinbaseTxid,
        outputIndex: replacement.outputIndex,
        outputValue: replacement.outputValue,
        commitHeight: replacement.commitHeight
      }
    };
  });
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
  assert.deepStrictEqual(
    fixture.canonicalContext.checkpoints,
    SEGMENTS.map(segment => ({
      height: segment.checkpointHeight,
      hash: network.checkpointMap[segment.checkpointHeight].toString('hex'),
      linkedHeaderCount: segment.endHeight - segment.checkpointHeight + 1
    }))
  );

  assert.deepStrictEqual(
    fixture.canonicalContext.commitHeaders.map(header => header.height),
    [1, 2]
  );
  const commits = fixture.canonicalContext.commitHeaders.map(decodeHeader);

  assert.deepStrictEqual(
    fixture.canonicalContext.blocks.map(context => context.blockHeight),
    BLOCK_HEIGHTS
  );
  const contexts = new Map();
  for (const context of fixture.canonicalContext.blocks) {
    assert.strictEqual(context.contextHeaders.length, MEDIAN_TIMESPAN,
      `context length at ${context.blockHeight}`);
    const headers = context.contextHeaders.map(decodeHeader);
    assert.strictEqual(headers[0].time, context.contextHeaders[0].time);
    for (let index = 1; index < headers.length; index++) {
      assert(headers[index].prevBlock.equals(headers[index - 1].hash()),
        `context header link at ${context.contextHeaders[index].height}`);
    }
    assert.strictEqual(context.parentTime, headers.at(-1).time,
      `parent time at ${context.blockHeight}`);
    assert.strictEqual(
      context.parentMedianTime,
      median(headers.map(header => header.time)),
      `parent MTP at ${context.blockHeight}`
    );
    contexts.set(context.blockHeight, {context, parent: headers.at(-1)});
  }

  assert.deepStrictEqual(fixture.blocks.map(block => block.height), BLOCK_HEIGHTS);
  const rebuilt = [];
  for (const expected of fixture.blocks) {
    const linked = contexts.get(expected.height);
    assert(linked, `context for block ${expected.height}`);
    const block = Block.decode(Buffer.from(expected.raw, 'hex'));
    assert.strictEqual(block.encode().toString('hex'), expected.raw,
      `block ${expected.height} round trip`);
    assert.strictEqual(block.hash().toString('hex'), expected.hash,
      `block ${expected.height} hash`);
    assert.strictEqual(block.getCoinbaseHeight(), expected.height,
      `block ${expected.height} coinbase height`);
    assert(block.verifyBody(), `block ${expected.height} body`);
    assert(block.prevBlock.equals(linked.parent.hash()),
      `block ${expected.height} parent link`);
    assert.strictEqual(block.getSize(), expected.size);
    assert.strictEqual(block.getBaseSize(), expected.baseSize);
    assert.strictEqual(block.getWeight(), expected.weight);
    assert.strictEqual(block.txs.length, expected.transactionCount);
    assert.strictEqual(block.txs[0].txid(), expected.coinbaseTxid);
    const actual = blockRecord(block, linked.context, network);
    assert.deepStrictEqual(actual, expected);
    rebuilt.push(actual);
  }

  const initial = rebuilt.filter(block => block.role === 'initial');
  assert.strictEqual(initial.length, INITIAL_HEIGHTS.length);
  assert(initial.every(block => block.height < network.deflationHeight));
  assert(initial.every(block => block.claims.length > 0));
  assert(initial.every(block => block.claims.every(claim =>
    claim.commitHeight === 1 && claim.commitHash === commits[0].hash().toString('hex'))));

  const replacement = rebuilt.find(block => block.role === 'replacement');
  assert(replacement, 'replacement block');
  assert.strictEqual(replacement.claims.length, REPLACEMENTS.length);
  assert.deepStrictEqual(
    replacement.claims.map(claim => claim.name),
    REPLACEMENTS.map(item => item.name)
  );
  assert(replacement.claims.every(claim => claim.commitHeight === 2));
  assert(replacement.claims.every(claim =>
    claim.commitHash === commits[1].hash().toString('hex')));
  assert(replacement.claims.every(claim => claim.conjured === claim.outputValue));

  assert.deepStrictEqual(fixture.history, buildHistory(rebuilt));
  assert.strictEqual(fixture.history.length, REPLACEMENTS.length);
  assert(fixture.history.every(item => item.initial.commitHeight === 1));
  assert(fixture.history.every(item => item.replacement.commitHeight === 2));
}

async function fetchFixture(prefix, archiveBase) {
  const {NodeClient} = require('hsd/lib/client');
  const settings = parseConfig(prefix);
  assert((settings.network || 'main') === 'main',
    'claim replacement export requires a mainnet HSD node');
  const host = option('--rpc-host') || settings['http-host'] || '127.0.0.1';
  const port = Number(option('--rpc-port') || settings['http-port'] || 12037);
  const apiKey = process.env.HSD_API_KEY || settings['api-key'];
  assert(apiKey, 'HSD API key is missing from the selected prefix');
  assert(Number.isSafeInteger(port) && port > 0 && port <= 65535,
    'HSD RPC port is invalid');

  const base = archiveBase.replace(/\/$/, '');
  const jsonBlocks = await Promise.all(BLOCK_HEIGHTS.map(height =>
    fetchJson(`${base}/block/${height}`)));
  const blocks = jsonBlocks.map((json, blockIndex) => {
    const height = BLOCK_HEIGHTS[blockIndex];
    assert.strictEqual(json.height, height,
      `archival API returned the wrong height for ${height}`);
    const block = Block.fromJSON(json);
    assert.strictEqual(block.hash().toString('hex'), json.hash,
      `archival block ${height} hash`);
    for (const [index, tx] of block.txs.entries()) {
      assert.strictEqual(tx.toHex(), json.txs[index].hex,
        `archival block ${height} transaction ${index} bytes`);
    }
    assert(block.verifyBody(), `archival block ${height} body`);
    return block;
  });

  const client = new NodeClient({host, port, apiKey});
  await client.open();
  try {
    const info = await client.getInfo();
    assert(info && info.network === 'main', 'HSD RPC network must be mainnet');
    assert(info.chain && info.chain.height >= REPLACEMENT_HEIGHT,
      `HSD must be synchronized through height ${REPLACEMENT_HEIGHT}`);
    const network = Network.get('main');

    const segments = [];
    for (const expected of SEGMENTS) {
      const raws = await client.getEntries(
        expected.checkpointHeight,
        expected.endHeight
      );
      assert.strictEqual(
        raws.length,
        expected.endHeight - expected.checkpointHeight + 1,
        `HSD checkpoint segment ${expected.checkpointHeight}`
      );
      const entries = raws.map(raw => ChainEntry.decode(raw));
      const checkpoint = network.checkpointMap[expected.checkpointHeight];
      assert(entries[0].hash.equals(checkpoint),
        `canonical checkpoint ${expected.checkpointHeight}`);
      for (let index = 0; index < entries.length; index++) {
        assert.strictEqual(entries[index].height,
          expected.checkpointHeight + index,
          `canonical header height in segment ${expected.checkpointHeight}`);
        if (index !== 0)
          assert(entries[index].prevBlock.equals(entries[index - 1].hash),
            `canonical header link at ${entries[index].height}`);
      }
      segments.push({...expected, entries, checkpoint});
    }

    for (const block of blocks) {
      const height = block.getCoinbaseHeight();
      const segment = segments.find(item =>
        height >= item.checkpointHeight && height <= item.endHeight);
      assert(segment, `canonical segment for block ${height}`);
      const entry = segment.entries[height - segment.checkpointHeight];
      assert(entry.hash.equals(block.hash()),
        `archival block ${height} is not locally canonical`);
    }

    const commitRaws = await client.getEntries(1, 2);
    assert.strictEqual(commitRaws.length, 2, 'HSD commit headers');
    const commitHeaders = commitRaws.map(raw => ChainEntry.decode(raw));
    const contexts = BLOCK_HEIGHTS.map(height => {
      const segment = segments.find(item =>
        height >= item.checkpointHeight && height <= item.endHeight);
      return contextRecord(height, segment.entries, segment.checkpointHeight);
    });
    const records = blocks.map((block, index) =>
      blockRecord(block, contexts[index], network));

    return {
      schema: 1,
      oracle: {
        repository: 'handshake-org/hsd',
        revision: REVISION,
        nodeVersion: info.version,
        archivalApi: base
      },
      network: 'main',
      canonicalContext: {
        checkpoints: segments.map(segment => ({
          height: segment.checkpointHeight,
          hash: segment.checkpoint.toString('hex'),
          linkedHeaderCount: segment.entries.length
        })),
        commitHeaders: commitHeaders.map(headerJson),
        blocks: contexts
      },
      history: buildHistory(records),
      blocks: records
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
