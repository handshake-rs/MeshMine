#!/usr/bin/env node
'use strict';

const assert = require('assert');
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const SCHEMA_VERSION = 1;
const EXPECTED_HSD_REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const AUDIT_COPY_MARKER = '.hsd-state-audit-copy';
const AUDIT_COPY_MARKER_BODY = 'hsd-state-audit-copy-v1\n';
const DIGEST_DOMAIN = Buffer.from('meshmine-state-manifest-v1\0', 'ascii');
const UTXO_PROJECTION = [
  'outpoint',
  'value',
  'height',
  'coinbase',
  'address',
  'covenant'
];
const EXCLUDED_HSD_UTXO_FIELDS = ['origin_transaction_version'];

class OrderedDigest {
  constructor(blake2b, component) {
    this.hasher = new blake2b();
    this.hasher.init(32);
    this.hasher.update(DIGEST_DOMAIN);
    this.hasher.update(Buffer.from(component, 'ascii'));
    this.count = 0;
    this.previousKey = null;
  }

  push(key, value) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(value));

    if (this.previousKey && Buffer.compare(this.previousKey, key) >= 0)
      throw new Error('state manifest input is not in strict key order');

    const keyLength = Buffer.allocUnsafe(4);
    keyLength.writeUInt32BE(key.length);
    const valueLength = Buffer.allocUnsafe(8);
    valueLength.writeBigUInt64BE(BigInt(value.length));
    this.hasher.update(Buffer.from([0x01]));
    this.hasher.update(keyLength);
    this.hasher.update(key);
    this.hasher.update(valueLength);
    this.hasher.update(value);
    this.count += 1;
    if (!Number.isSafeInteger(this.count))
      throw new Error('manifest record count overflow');
    this.previousKey = Buffer.from(key);
  }

  finish() {
    const count = Buffer.allocUnsafe(8);
    count.writeBigUInt64BE(BigInt(this.count));
    this.hasher.update(Buffer.from([0x02]));
    this.hasher.update(count);
    return {
      count: this.count,
      digest: this.hasher.final().toString('hex')
    };
  }
}

function fail(message) {
  process.stderr.write(`export-hsd-state-manifest: ${message}\n`);
  process.exit(1);
}

function parseArguments(argv) {
  const options = {
    hsdSource: null,
    prefix: null,
    network: 'main',
    prune: true,
    selfTest: false,
    integrationSelfTest: false
  };

  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index];
    switch (argument) {
      case '--hsd-source':
        options.hsdSource = argv[++index] || null;
        break;
      case '--prefix':
        options.prefix = argv[++index] || null;
        break;
      case '--network':
        options.network = argv[++index] || null;
        break;
      case '--prune':
        options.prune = true;
        break;
      case '--no-prune':
        options.prune = false;
        break;
      case '--self-test':
        options.selfTest = true;
        break;
      case '--integration-self-test':
        options.integrationSelfTest = true;
        break;
      default:
        fail(`unknown argument ${argument}`);
    }
  }
  return options;
}

function resolveModule(hsdSource, name) {
  return require.resolve(name, {paths: [hsdSource]});
}

function requirePinnedSource(source) {
  const canonical = fs.realpathSync(source);
  const revision = childProcess.execFileSync(
    'git',
    ['-C', canonical, 'rev-parse', 'HEAD'],
    {encoding: 'utf8', maxBuffer: 1024 * 1024}
  ).trim();
  if (revision !== EXPECTED_HSD_REVISION) {
    throw new Error(
      `HSD source revision ${revision} does not match ${EXPECTED_HSD_REVISION}`
    );
  }
  const tracked = childProcess.execFileSync(
    'git',
    ['-C', canonical, 'status', '--porcelain', '--untracked-files=no'],
    {encoding: 'utf8', maxBuffer: 1024 * 1024}
  );
  if (tracked !== '')
    throw new Error('HSD source has tracked modifications');
  return canonical;
}

function requireAuditCopy(prefix) {
  const canonical = fs.realpathSync(prefix);
  if (!fs.statSync(canonical).isDirectory())
    throw new Error(`${canonical} is not a directory`);
  const marker = path.join(canonical, AUDIT_COPY_MARKER);
  if (fs.readFileSync(marker, 'utf8') !== AUDIT_COPY_MARKER_BODY)
    throw new Error(`offline-copy marker ${marker} is missing or invalid`);
  return canonical;
}

function canonicalCoin(coin) {
  if (!Number.isSafeInteger(coin.output.value) || coin.output.value < 0)
    throw new Error('HSD coin value is outside the safe uint64 range');
  if (!Number.isInteger(coin.height) || coin.height < 0)
    throw new Error('HSD persisted UTXO has an invalid height');

  const value = Buffer.allocUnsafe(8);
  value.writeBigUInt64LE(BigInt(coin.output.value));
  const height = Buffer.allocUnsafe(4);
  height.writeUInt32LE(coin.height);
  return Buffer.concat([
    value,
    height,
    Buffer.from([coin.coinbase ? 1 : 0]),
    coin.output.address.encode(),
    coin.output.covenant.encode()
  ]);
}

async function auditUtxos(chain, layout, CoinEntry, blake2b) {
  const digest = new OrderedDigest(blake2b, 'utxo');
  const iterator = chain.db.db.iterator({
    gte: layout.c.min(),
    lte: layout.c.max(),
    keys: true,
    values: true,
    fillCache: false
  });
  let totalValue = 0n;

  await iterator.each((rawKey, rawValue) => {
    const [hash, index] = layout.c.decode(rawKey);
    const coin = CoinEntry.decode(rawValue);
    const key = Buffer.allocUnsafe(36);
    hash.copy(key, 0);
    key.writeUInt32BE(index, 32);
    digest.push(key, canonicalCoin(coin));
    totalValue += BigInt(coin.output.value);
  });

  const component = digest.finish();
  if (component.count !== chain.db.state.coin) {
    throw new Error(
      `UTXO scan count ${component.count} disagrees with HSD chain state `
      + `${chain.db.state.coin}`
    );
  }
  if (totalValue !== BigInt(chain.db.state.value)) {
    throw new Error(
      `UTXO value ${totalValue} disagrees with HSD chain state `
      + `${chain.db.state.value}`
    );
  }
  return {
    ...component,
    total_value: Number(totalValue),
    semantic_projection: UTXO_PROJECTION,
    excluded_hsd_archival_fields: EXCLUDED_HSD_UTXO_FIELDS
  };
}

async function auditNames(chain, blake2b) {
  const digest = new OrderedDigest(blake2b, 'name-state');
  const iterator = chain.db.txn.iterator(true);
  while (await iterator.next())
    digest.push(iterator.key, iterator.value);
  return digest.finish();
}

async function auditUndo(chain, layout, blake2b) {
  const nameDigest = new OrderedDigest(blake2b, 'hsd-name-undo');
  const nameIterator = chain.db.db.iterator({
    gte: layout.w.min(),
    lte: layout.w.max(),
    keys: true,
    values: true,
    fillCache: false
  });
  let minimumNameHeight = null;
  let maximumNameHeight = null;
  await nameIterator.each((key, value) => {
    const [height] = layout.w.decode(key);
    const canonicalKey = Buffer.allocUnsafe(4);
    canonicalKey.writeUInt32BE(height);
    nameDigest.push(canonicalKey, value);
    minimumNameHeight = minimumNameHeight === null
      ? height
      : Math.min(minimumNameHeight, height);
    maximumNameHeight = maximumNameHeight === null
      ? height
      : Math.max(maximumNameHeight, height);
  });

  const coinDigest = new OrderedDigest(blake2b, 'hsd-coin-undo');
  let minimumCoinHeight = null;
  let maximumCoinHeight = null;
  let unavailable = 0;
  const first = Math.max(1, chain.height - chain.network.block.keepBlocks + 1);
  for (let height = first; height <= chain.height; height++) {
    const entry = await chain.getEntry(height);
    if (!entry)
      throw new Error(`missing active HSD entry at height ${height}`);
    const raw = await chain.db.blocks.readUndo(entry.hash);
    if (!raw) {
      unavailable += 1;
      continue;
    }
    const key = Buffer.allocUnsafe(36);
    key.writeUInt32BE(height, 0);
    entry.hash.copy(key, 4);
    coinDigest.push(key, raw);
    minimumCoinHeight = minimumCoinHeight === null ? height : minimumCoinHeight;
    maximumCoinHeight = height;
  }

  return {
    coin: {
      ...coinDigest.finish(),
      minimum_height: minimumCoinHeight,
      maximum_height: maximumCoinHeight,
      unavailable_in_reorg_horizon: unavailable
    },
    name: {
      ...nameDigest.finish(),
      minimum_height: minimumNameHeight,
      maximum_height: maximumNameHeight
    },
    comparison: 'producer-native-digests; qualify cross-implementation undo by rollback campaign'
  };
}

async function exportManifest(options) {
  if (!options.hsdSource)
    throw new Error('--hsd-source is required');
  if (!options.prefix)
    throw new Error('--prefix is required');

  const hsdSource = requirePinnedSource(options.hsdSource);
  const prefix = requireAuditCopy(options.prefix);
  const Chain = require(path.join(hsdSource, 'lib/blockchain/chain'));
  const CoinEntry = require(path.join(hsdSource, 'lib/coins/coinentry'));
  const Layout = require(path.join(hsdSource, 'lib/blockchain/layout'));
  const Network = require(path.join(hsdSource, 'lib/protocol/network'));
  const blockstore = require(path.join(hsdSource, 'lib/blockstore'));
  const Logger = require(resolveModule(hsdSource, 'blgr'));
  const blake2b = require(resolveModule(hsdSource, 'bcrypto/lib/js/blake2b'));
  const network = Network.get(options.network);
  const logger = new Logger({
    console: false,
    filename: null,
    level: 'none'
  });
  const blocks = blockstore.create({
    prefix,
    network,
    logger,
    cacheSize: 32 << 20,
    memory: false
  });
  const chain = new Chain({
    prefix,
    network,
    logger,
    blocks,
    memory: false,
    prune: options.prune,
    checkpoints: true,
    indexTX: false,
    indexAddress: false,
    compactTreeOnInit: false
  });

  let blocksOpened = false;
  let chainOpened = false;
  try {
    await blocks.open();
    blocksOpened = true;
    await chain.open();
    chainOpened = true;

    const utxo = await auditUtxos(chain, Layout, CoinEntry, blake2b);
    const names = await auditNames(chain, blake2b);
    const undo = await auditUndo(chain, Layout, blake2b);
    const workingRoot = chain.db.txn.rootHash();
    const committedRoot = chain.db.tree.rootHash();

    return {
      schema_version: SCHEMA_VERSION,
      producer: 'hsd',
      oracle_revision: EXPECTED_HSD_REVISION,
      network: network.type,
      height: chain.height,
      block_hash: chain.tip.hash.toString('hex'),
      genesis_hash: network.genesis.hash.toString('hex'),
      components: {
        utxo,
        names,
        roots: {
          working: workingRoot.toString('hex'),
          committed: committedRoot.toString('hex')
        },
        undo
      }
    };
  } finally {
    if (chainOpened)
      await chain.close();
    if (blocksOpened)
      await blocks.close();
  }
}

function selfTest() {
  const hsdSource = path.resolve(__dirname, 'node_modules/hsd');
  const blake2b = require(resolveModule(hsdSource, 'bcrypto/lib/js/blake2b'));
  const left = new OrderedDigest(blake2b, 'utxo');
  left.push(Buffer.from('a'), Buffer.from('one'));
  left.push(Buffer.from('b'), Buffer.from('two'));
  const result = left.finish();
  assert.strictEqual(result.count, 2);
  assert.strictEqual(
    result.digest,
    '52bd2bf297d56178e215aa204234faaa0fbe8efc03caa28ac8b059401894fc7b'
  );

  const other = new OrderedDigest(blake2b, 'name-state');
  other.push(Buffer.from('a'), Buffer.from('one'));
  other.push(Buffer.from('b'), Buffer.from('two'));
  assert.notStrictEqual(result.digest, other.finish().digest);

  const reversed = new OrderedDigest(blake2b, 'utxo');
  reversed.push(Buffer.from('b'), Buffer.from('one'));
  assert.throws(() => reversed.push(Buffer.from('a'), Buffer.from('two')));
  process.stdout.write(JSON.stringify({ok: true, digest: result.digest}) + '\n');
}

async function integrationSelfTest(options) {
  if (!options.hsdSource)
    throw new Error('--hsd-source is required for --integration-self-test');
  const prefix = fs.mkdtempSync(path.join(os.tmpdir(), 'hsd-state-manifest-test-'));
  try {
    fs.mkdirSync(path.join(prefix, 'blocks'), {mode: 0o700});
    fs.writeFileSync(
      path.join(prefix, AUDIT_COPY_MARKER),
      AUDIT_COPY_MARKER_BODY,
      {mode: 0o600}
    );
    const manifest = await exportManifest({
      ...options,
      prefix,
      network: 'regtest',
      prune: false
    });
    assert.strictEqual(manifest.producer, 'hsd');
    assert.strictEqual(manifest.network, 'regtest');
    assert.strictEqual(manifest.height, 0);
    assert.strictEqual(manifest.components.names.count, 0);
    process.stdout.write(JSON.stringify({
      ok: true,
      height: manifest.height,
      utxo_count: manifest.components.utxo.count
    }) + '\n');
  } finally {
    fs.rmSync(prefix, {recursive: true, force: true});
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.selfTest) {
    selfTest();
    return;
  }
  if (options.integrationSelfTest) {
    await integrationSelfTest(options);
    return;
  }
  const manifest = await exportManifest(options);
  process.stdout.write(JSON.stringify(manifest, null, 2) + '\n');
}

main().catch((error) => fail(error.stack || error.message));
