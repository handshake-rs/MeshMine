#!/usr/bin/env node
'use strict';

const assert = require('assert');
const childProcess = require('child_process');
const fs = require('fs');
const path = require('path');

const SCHEMA_VERSION = 1;
const EXPECTED_HSD_REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';

function fail(message) {
  process.stderr.write(`export-hsd-rollback-manifest: ${message}\n`);
  process.exit(1);
}

function parseArguments(argv) {
  const options = {
    hsdSource: null,
    prefix: null,
    network: 'main',
    prune: true,
    selfTest: false,
    output: null
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
      case '--output':
        options.output = argv[++index] || null;
        break;
      default:
        fail(`unknown argument ${argument}`);
    }
  }
  return options;
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

function resolveModule(hsdSource, name) {
  return require.resolve(name, {paths: [hsdSource]});
}

function canonicalCoin(bio, prevout, coin) {
  const covenant = coin.output.covenant.encode();
  const size = 36
    + 8
    + 4
    + 1
    + coin.output.address.getSize()
    + bio.encoding.sizeVarlen(covenant.length);
  const bw = bio.write(size);
  prevout.write(bw);
  bw.writeU64(coin.output.value);
  bw.writeU32(coin.height);
  bw.writeU8(coin.coinbase ? 1 : 0);
  coin.output.address.write(bw);
  bw.writeVarBytes(covenant);
  return bw.render();
}

function coinTransition(bio, prevout, coin) {
  return {
    outpoint: prevout.encode().toString('hex'),
    coin: canonicalCoin(bio, prevout, coin).toString('hex')
  };
}

function digest(blake2b, raw) {
  return blake2b.digest(raw, 32).toString('hex');
}

function networkName(network) {
  return network.type === 'main' ? 'mainnet' : network.type;
}

function normalizeCoins(item, UndoCoins, CoinEntry, bio) {
  const undo = item.rawCoinUndo
    ? UndoCoins.decode(item.rawCoinUndo)
    : new UndoCoins();
  const surviving = new Map();
  const external = new Map();
  let undoIndex = 0;

  for (let transactionIndex = 0;
    transactionIndex < item.block.txs.length;
    transactionIndex++) {
    const tx = item.block.txs[transactionIndex];
    if (transactionIndex > 0) {
      for (const input of tx.inputs) {
        const coin = undo.items[undoIndex++];
        if (!coin) {
          throw new Error(
            `coin undo is shorter than block inputs at height ${item.height}`
          );
        }
        const key = input.prevout.encode();
        const keyHex = key.toString('hex');
        const created = surviving.get(keyHex);
        if (created) {
          const expected = canonicalCoin(bio, input.prevout, created.coin);
          const actual = canonicalCoin(bio, input.prevout, coin);
          if (!expected.equals(actual)) {
            throw new Error(
              `within-block coin undo mismatch ${keyHex} at height ${item.height}`
            );
          }
          surviving.delete(keyHex);
        } else {
          if (external.has(keyHex)) {
            throw new Error(
              `duplicate external spend ${keyHex} at height ${item.height}`
            );
          }
          external.set(keyHex, {
            key,
            transition: coinTransition(bio, input.prevout, coin)
          });
        }
      }
    }

    const txid = tx.hash();
    for (let outputIndex = 0; outputIndex < tx.outputs.length; outputIndex++) {
      const output = tx.outputs[outputIndex];
      if (output.isUnspendable())
        continue;
      const prevout = {
        hash: txid,
        index: outputIndex,
        encode() {
          const raw = Buffer.allocUnsafe(36);
          this.hash.copy(raw, 0);
          raw.writeUInt32LE(this.index, 32);
          return raw;
        },
        write(bw) {
          bw.writeHash(this.hash);
          bw.writeU32(this.index);
          return bw;
        }
      };
      const key = prevout.encode();
      const keyHex = key.toString('hex');
      if (surviving.has(keyHex)) {
        throw new Error(
          `duplicate created outpoint ${keyHex} at height ${item.height}`
        );
      }
      surviving.set(keyHex, {
        key,
        prevout,
        coin: CoinEntry.fromTX(tx, outputIndex, item.height)
      });
    }
  }

  if (undoIndex !== undo.items.length) {
    throw new Error(
      `coin undo has ${undo.items.length - undoIndex} unbound items`
      + ` at height ${item.height}`
    );
  }

  const spentCoins = [...external.values()]
    .sort((left, right) => Buffer.compare(left.key, right.key))
    .map(item => item.transition);
  const createdCoins = [...surviving.values()]
    .sort((left, right) => Buffer.compare(left.key, right.key))
    .map(item => coinTransition(bio, item.prevout, item.coin));
  return {spentCoins, createdCoins};
}

function airdropPositions(item, AirdropProof) {
  const positions = [];
  const coinbase = item.block.txs[0];
  assert(coinbase && coinbase.isCoinbase());
  for (let index = 1; index < coinbase.inputs.length; index++) {
    const input = coinbase.inputs[index];
    const output = coinbase.outputs[index];
    if (!output || input.witness.items.length !== 1) {
      throw new Error(
        `invalid coinbase proof shape at height ${item.height} index ${index}`
      );
    }
    if (!output.covenant.isNone())
      continue;
    positions.push(AirdropProof.decode(input.witness.items[0]).position());
  }
  positions.sort((left, right) => left - right);
  for (let index = 1; index < positions.length; index++) {
    if (positions[index - 1] === positions[index]) {
      throw new Error(
        `duplicate airdrop position at height ${item.height}`
      );
    }
  }
  return positions;
}

function reverseNames(item, overlay) {
  const names = [];
  for (const [nameHash, delta] of item.nameUndo.names) {
    const key = nameHash.toString('hex');
    const state = overlay.get(key);
    if (!state) {
      throw new Error(
        `name overlay is missing ${key} at height ${item.height}`
      );
    }
    const after = state.isNull() ? null : state.encode().toString('hex');
    state.applyState(delta);
    const before = state.isNull() ? null : state.encode().toString('hex');
    if (before === after)
      continue;
    names.push({name_hash: key, before, after});
  }
  names.sort((left, right) => left.name_hash.localeCompare(right.name_hash));
  for (let index = 1; index < names.length; index++) {
    if (names[index - 1].name_hash === names[index].name_hash) {
      throw new Error(`duplicate name undo at height ${item.height}`);
    }
  }
  return names;
}

function applyAirdropPositions(field, positions, spend, height) {
  for (const position of positions) {
    const byte = position >>> 3;
    if (byte >= field.length) {
      throw new Error(
        `airdrop position ${position} is out of range at height ${height}`
      );
    }
    const mask = 1 << (7 - (position & 7));
    const currentlySpent = (field[byte] & mask) !== 0;
    if (currentlySpent !== !spend) {
      throw new Error(
        `airdrop position ${position} has invalid`
        + ` ${spend ? 'reconnect' : 'disconnect'} state at height ${height}`
      );
    }
    if (spend)
      field[byte] |= mask;
    else
      field[byte] &= ~mask;
  }
}

async function exportManifest(options) {
  if (!options.hsdSource)
    throw new Error('--hsd-source is required');
  if (!options.prefix)
    throw new Error('--prefix is required');

  const hsdSource = requirePinnedSource(options.hsdSource);
  const prefix = fs.realpathSync(options.prefix);
  const Chain = require(path.join(hsdSource, 'lib/blockchain/chain'));
  const Block = require(path.join(hsdSource, 'lib/primitives/block'));
  const Layout = require(path.join(hsdSource, 'lib/blockchain/layout'));
  const NameUndo = require(path.join(hsdSource, 'lib/covenants/undo'));
  const NameState = require(path.join(hsdSource, 'lib/covenants/namestate'));
  const UndoCoins = require(path.join(hsdSource, 'lib/coins/undocoins'));
  const CoinEntry = require(path.join(hsdSource, 'lib/coins/coinentry'));
  const AirdropProof =
    require(path.join(hsdSource, 'lib/primitives/airdropproof'));
  const Network = require(path.join(hsdSource, 'lib/protocol/network'));
  const blockstore = require(path.join(hsdSource, 'lib/blockstore'));
  const Logger = require(resolveModule(hsdSource, 'blgr'));
  const blake2b = require(resolveModule(hsdSource, 'bcrypto/lib/js/blake2b'));
  const bio = require(resolveModule(hsdSource, 'bufio'));
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

    const sourceHeight = chain.height;
    const keepBlocks = network.block.keepBlocks;
    const treeInterval = network.names.treeInterval;
    const firstHeight =
      Math.max(1, sourceHeight - keepBlocks + 1);
    const loaded = [];
    const changedNames = new Map();

    for (let height = firstHeight; height <= sourceHeight; height++) {
      const entry = await chain.getEntry(height);
      if (!entry)
        throw new Error(`missing active HSD entry at height ${height}`);
      const raw = await chain.db.getRawBlock(height);
      if (!raw)
        throw new Error(`raw block at height ${height} is not retained`);
      const block = Block.decode(raw);
      if (!block.hash().equals(entry.hash))
        throw new Error(`active raw block hash mismatch at height ${height}`);
      const rawCoinUndo = await chain.db.blocks.readUndo(entry.hash);
      const rawNameUndo = await chain.db.db.get(Layout.w.encode(height));
      const nameUndo = rawNameUndo
        ? NameUndo.decode(rawNameUndo)
        : new NameUndo();
      for (const [nameHash] of nameUndo.names)
        changedNames.set(nameHash.toString('hex'), nameHash);
      loaded.push({
        height,
        entry,
        raw,
        block,
        rawCoinUndo,
        nameUndo
      });
    }

    const overlay = new Map();
    for (const [key, nameHash] of changedNames) {
      let state = await chain.db.getNameState(nameHash);
      if (!state) {
        state = new NameState();
        state.nameHash = nameHash;
      }
      overlay.set(key, state);
    }

    const records = [];
    const currentCommitted = chain.db.tree.rootHash();
    const sourceAirdropField = Buffer.from(chain.db.field.field);
    const reversedAirdropField = Buffer.from(sourceAirdropField);
    for (let offset = loaded.length - 1; offset >= 0; offset--) {
      const item = loaded[offset];
      const boundary = (item.height % treeInterval) === 0;
      const resulting = boundary
        ? (loaded[offset + 1]
          ? loaded[offset + 1].block.treeRoot
          : currentCommitted)
        : item.block.treeRoot;
      const {spentCoins, createdCoins} =
        normalizeCoins(item, UndoCoins, CoinEntry, bio);
      const positions = airdropPositions(item, AirdropProof);
      applyAirdropPositions(
        reversedAirdropField,
        positions,
        false,
        item.height
      );
      records.push({
        height: item.height,
        block_hash: item.entry.hash.toString('hex'),
        previous_block_hash: item.block.prevBlock.toString('hex'),
        raw_block_size: item.raw.length,
        raw_block_digest: digest(blake2b, item.raw),
        roots: {
          previous_committed: item.block.treeRoot.toString('hex'),
          resulting_committed: resulting.toString('hex'),
          interval_boundary: boundary
        },
        spent_coins: spentCoins,
        created_coins: createdCoins,
        airdrop_positions: positions,
        names: reverseNames(item, overlay)
      });
    }
    records.reverse();
    const reconnectedAirdropField = Buffer.from(reversedAirdropField);
    for (const record of records) {
      applyAirdropPositions(
        reconnectedAirdropField,
        record.airdrop_positions,
        true,
        record.height
      );
    }
    if (!reconnectedAirdropField.equals(sourceAirdropField))
      throw new Error('airdrop field did not round-trip through transitions');
    let sourceAirdropSpent = 0;
    for (const byte of sourceAirdropField) {
      let value = byte;
      while (value !== 0) {
        sourceAirdropSpent += value & 1;
        value >>>= 1;
      }
    }

    return {
      schema_version: SCHEMA_VERSION,
      producer: 'hsd',
      oracle_revision: EXPECTED_HSD_REVISION,
      network: networkName(network),
      source_height: sourceHeight,
      source_block_hash: chain.tip.hash.toString('hex'),
      first_height: firstHeight,
      keep_blocks: keepBlocks,
      tree_interval: treeInterval,
      source_airdrop_field_size: sourceAirdropField.length,
      source_airdrop_field_digest: digest(blake2b, sourceAirdropField),
      source_airdrop_spent: sourceAirdropSpent,
      records
    };
  } finally {
    if (chainOpened)
      await chain.close();
    if (blocksOpened)
      await blocks.close();
  }
}

function selfTest(options) {
  if (!options.hsdSource)
    throw new Error('--hsd-source is required for --self-test');
  const hsdSource = requirePinnedSource(options.hsdSource);
  const Outpoint = require(path.join(hsdSource, 'lib/primitives/outpoint'));
  const Output = require(path.join(hsdSource, 'lib/primitives/output'));
  const Address = require(path.join(hsdSource, 'lib/primitives/address'));
  const Covenant = require(path.join(hsdSource, 'lib/primitives/covenant'));
  const CoinEntry = require(path.join(hsdSource, 'lib/coins/coinentry'));
  const bio = require(resolveModule(hsdSource, 'bufio'));
  const prevout = new Outpoint(Buffer.alloc(32, 0x42), 7);
  const coin = new CoinEntry();
  coin.height = 9;
  coin.coinbase = false;
  coin.output = new Output({
    value: 11,
    address: new Address({version: 0, hash: Buffer.alloc(20, 0x51)}),
    covenant: new Covenant()
  });
  const expected = Buffer.from(
    '42'.repeat(32)
      + '07000000'
      + '0b00000000000000'
      + '09000000'
      + '00'
      + '0014'
      + '51'.repeat(20)
      + '020000',
    'hex'
  );
  assert(canonicalCoin(bio, prevout, coin).equals(expected));
  process.stdout.write(JSON.stringify({ok: true}) + '\n');
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.selfTest) {
    selfTest(options);
    return;
  }
  const manifest = await exportManifest(options);
  const raw = JSON.stringify(manifest, null, 2) + '\n';
  if (options.output)
    fs.writeFileSync(options.output, raw, {mode: 0o600});
  else
    process.stdout.write(raw);
}

main().catch(error => fail(error.stack || error.message));
