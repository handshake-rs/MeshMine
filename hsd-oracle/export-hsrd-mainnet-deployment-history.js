'use strict';

// Export and verify compact deployment-period evidence from a live mainnet
// HSD node. The committed fixture contains one summary per completed miner
// window, not the full header chain. Offline verification replays every summary
// through the pinned HSD Chain methods.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const {installMemoryOnlyDatabaseShim} = require('./memory-db-shim');
const hsdRoot = path.dirname(require.resolve('hsd/package.json'));
installMemoryOnlyDatabaseShim(hsdRoot);

const Chain = require('hsd/lib/blockchain/chain');
const ChainEntry = require('hsd/lib/blockchain/chainentry');
const Block = require('hsd/lib/primitives/block');
const Network = require('hsd/lib/protocol/network');

const REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(
  ROOT,
  'hsrd/fixtures/hsd/chains/mainnet-deployment-history-v1.json'
);
const THROUGH_HEIGHT = 338688;
const FINALITY_HEIGHT = 1;
const STATE_NAMES = Object.freeze([
  'DEFINED',
  'STARTED',
  'LOCKED_IN',
  'ACTIVE',
  'FAILED'
]);

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
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    values[key] = value;
  }
  return values;
}

function stateName(state) {
  assert(Number.isInteger(state) && state >= 0 && state < STATE_NAMES.length,
    `unknown HSD threshold state ${state}`);
  return STATE_NAMES[state];
}

function deploymentJson(deployment) {
  return {
    name: deployment.name,
    bit: deployment.bit,
    startTime: deployment.startTime,
    timeout: deployment.timeout,
    threshold: deployment.threshold,
    window: deployment.window,
    required: deployment.required,
    force: deployment.force
  };
}

function stateCache() {
  const values = new Map();
  const key = (bit, entry) => `${bit}:${entry.height}`;
  return {
    get(bit, entry) {
      return values.has(key(bit, entry)) ? values.get(key(bit, entry)) : -1;
    },
    set(bit, entry, state) {
      values.set(key(bit, entry), state);
    }
  };
}

function chainView(network, entryAt, medianTime) {
  const view = {
    network,
    options: {checkpoints: true},
    db: {stateCache: stateCache()},
    async getAncestor(_tip, height) {
      if (height < 0)
        return null;
      return entryAt(height);
    },
    async getPrevious(entry) {
      if (entry.height === 0)
        return null;
      return entryAt(entry.height - 1);
    },
    async getMedianTime(entry) {
      return medianTime(entry);
    },
    async getState(previous, deployment) {
      return Chain.prototype.getState.call(this, previous, deployment);
    },
    async isActive(previous, deployment) {
      return Chain.prototype.isActive.call(this, previous, deployment);
    }
  };
  return view;
}

function effectJson(state) {
  return {
    scriptFlags: state.flags,
    lockFlags: state.lockFlags,
    nameFlags: state.nameFlags,
    hasAirstop: state.hasAirstop
  };
}

async function deploymentResult(chain, previous, candidateTime) {
  const states = {};
  for (const deployment of chain.network.deploys) {
    const state = await Chain.prototype.getState.call(
      chain,
      previous,
      deployment
    );
    states[deployment.name] = stateName(state);
  }
  const effects = await Chain.prototype.getDeployments.call(
    chain,
    candidateTime,
    previous
  );
  const blockVersion = await Chain.prototype.computeBlockVersion.call(
    chain,
    previous
  );
  return {states, effects: effectJson(effects), blockVersion};
}

function historicalResult(network, candidateHeight) {
  const chain = {network, options: {checkpoints: true}};
  return {
    historicalHeight: Chain.prototype.isHistoricalHeight.call(
      chain,
      candidateHeight
    ),
    historicalBlock: candidateHeight === 0
      ? false
      : Chain.prototype.isHistorical.call(
        chain,
        {height: candidateHeight - 1}
      )
  };
}

function compactEntry(entry) {
  return {
    hash: entry.hash,
    height: entry.height,
    version: entry.version,
    time: entry.time,
    medianTimePast: null,
    hasBit(bit) {
      return (this.version & (1 << bit)) !== 0;
    }
  };
}

function median(values) {
  const sorted = values.slice().sort((left, right) => left - right);
  return sorted[sorted.length >>> 1];
}

async function fetchFixture(prefix) {
  // Keep the HTTP/socket client out of the deterministic offline verifier. In
  // restricted CI environments merely loading its network-interface helper is
  // intentionally unavailable.
  const {NodeClient} = require('hsd/lib/client');
  const settings = parseConfig(prefix);
  assert((settings.network || 'main') === 'main',
    'historical deployment export requires a mainnet HSD node');
  const host = option('--rpc-host') || settings['http-host'] || '127.0.0.1';
  const port = Number(option('--rpc-port') || settings['http-port'] || 12037);
  const apiKey = process.env.HSD_API_KEY || settings['api-key'];
  assert(apiKey, 'HSD API key is missing from the selected prefix');
  assert(Number.isSafeInteger(port) && port > 0 && port <= 65535,
    'HSD RPC port is invalid');

  const network = Network.get('main');
  const window = network.minerWindow;
  assert.strictEqual(THROUGH_HEIGHT % window, 0,
    'fixture height must be a deployment boundary');

  const client = new NodeClient({host, port, apiKey});
  await client.open();
  try {
    const info = await client.getInfo();
    assert(info && info.network === 'main', 'HSD RPC network must be mainnet');
    assert(info.chain && info.chain.height >= THROUGH_HEIGHT,
      `HSD must be synchronized through height ${THROUGH_HEIGHT}`);

    const boundaries = new Map();
    let current = new Map();
    const entryAt = height => current.get(height) || boundaries.get(height) || null;
    const medianTime = entry => {
      const times = [];
      let height = entry.height;
      while (height >= 0 && times.length < 11) {
        const item = entryAt(height);
        assert(item, `missing entry ${height} for median time`);
        times.push(item.time);
        height -= 1;
      }
      return median(times);
    };
    const chain = chainView(network, entryAt, medianTime);
    const periods = [];

    for (let nextHeight = window;
      nextHeight <= THROUGH_HEIGHT;
      nextHeight += window) {
      const start = nextHeight - window;
      const end = nextHeight - 1;
      const rawEntries = await client.getEntries(start, end);
      assert.strictEqual(rawEntries.length, window,
        `HSD returned an incomplete period ${start}-${end}`);
      current = new Map();
      for (const raw of rawEntries) {
        const entry = compactEntry(ChainEntry.decode(raw));
        current.set(entry.height, entry);
      }
      for (let height = start; height <= end; height++)
        assert(current.has(height), `HSD omitted canonical entry ${height}`);

      const first = current.get(start);
      const previous = current.get(end);
      previous.medianTimePast = medianTime(previous);
      const signalling = {};
      for (const deployment of network.deploys) {
        let count = 0;
        for (const entry of current.values()) {
          if (entry.hasBit(deployment.bit))
            count += 1;
        }
        signalling[deployment.name] = count;
      }
      const result = await deploymentResult(chain, previous, previous.time);
      periods.push({
        nextHeight,
        periodStartHeight: start,
        periodEndHeight: end,
        periodStartHash: first.hash.toString('hex'),
        periodEndHash: previous.hash.toString('hex'),
        medianTimePast: previous.medianTimePast,
        signalling,
        states: result.states,
        effects: result.effects,
        nextBlockVersion: result.blockVersion,
        ...historicalResult(network, nextHeight)
      });
      boundaries.set(end, previous);
    }

    const boundaryHeights = [
      0,
      1,
      network.lastCheckpoint - 1,
      network.lastCheckpoint,
      network.lastCheckpoint + 1,
      THROUGH_HEIGHT
    ];
    const historicalBoundaries = [];
    for (const height of boundaryHeights) {
      const header = await client.getBlockHeader(height);
      assert(header && header.height === height,
        `HSD omitted historical boundary header ${height}`);
      historicalBoundaries.push({
        height,
        hash: header.hash,
        ...historicalResult(network, height)
      });
    }

    const anchor = historicalBoundaries.at(-1);
    const finalityHeader = await client.getBlockHeader(FINALITY_HEIGHT);
    const finalityParent = await client.getBlockHeader(FINALITY_HEIGHT - 1);
    assert(finalityHeader && finalityHeader.height === FINALITY_HEIGHT,
      'HSD omitted historical finality header');
    assert(finalityParent && finalityParent.height === FINALITY_HEIGHT - 1,
      'HSD omitted historical finality parent');
    const finalityRaw = await client.execute(
      'getblock',
      [finalityHeader.hash, false]
    );
    assert(typeof finalityRaw === 'string',
      'HSD omitted historical finality block bytes');
    const finalityBlock = Block.decode(Buffer.from(finalityRaw, 'hex'));
    // The parent is genesis, so its timestamp is also its one-entry MTP.
    const parentMedianTimePast = finalityParent.time;
    const transactionFinality = finalityBlock.txs.map(tx =>
      tx.isFinal(FINALITY_HEIGHT, parentMedianTimePast));
    const checkedTransactionIndexes = finalityBlock.txs
      .map((_tx, index) => index)
      .slice(1);
    assert(transactionFinality.some(final => !final),
      'historical finality case must expose a non-final coinbase');
    assert(checkedTransactionIndexes.every(index => transactionFinality[index]),
      'historical finality case contains a non-final ordinary transaction');

    return {
      schema: 3,
      oracle: {
        repository: 'handshake-org/hsd',
        revision: REVISION,
        nodeVersion: info.version
      },
      network: 'main',
      activationThreshold: network.activationThreshold,
      minerWindow: window,
      lastCheckpoint: network.lastCheckpoint,
      throughHeight: THROUGH_HEIGHT,
      anchorHash: anchor.hash,
      deployments: network.deploys.map(deploymentJson),
      historicalBoundaries,
      historicalFinalityCases: [{
        id: 'mainnet-block-1-coinbase-finality-exemption',
        height: FINALITY_HEIGHT,
        hash: finalityHeader.hash,
        parentMedianTimePast,
        raw: finalityRaw,
        transactionFinality,
        checkedTransactionIndexes,
        accepted: true
      }],
      periods
    };
  } finally {
    await client.close();
  }
}

function syntheticPeriod(period, deployments, window) {
  const entries = new Map();
  const start = period.nextHeight - window;
  for (let offset = 0; offset < window; offset++) {
    let version = 0;
    for (const deployment of deployments) {
      if (offset < period.signalling[deployment.name])
        version |= 1 << deployment.bit;
    }
    const height = start + offset;
    entries.set(height, {
      height,
      version: version >>> 0,
      medianTimePast: period.medianTimePast,
      hasBit(bit) {
        return (this.version & (1 << bit)) !== 0;
      }
    });
  }
  return entries;
}

async function validateFixture(fixture) {
  assert.strictEqual(fixture.schema, 3);
  assert.deepStrictEqual(fixture.oracle, {
    repository: 'handshake-org/hsd',
    revision: REVISION,
    nodeVersion: fixture.oracle.nodeVersion
  });
  assert.strictEqual(fixture.network, 'main');
  assert.strictEqual(fixture.throughHeight, THROUGH_HEIGHT);
  assert(/^[0-9a-f]{64}$/.test(fixture.anchorHash), 'invalid anchor hash');

  const network = Network.get('main');
  assert.strictEqual(fixture.activationThreshold, network.activationThreshold);
  assert.strictEqual(fixture.minerWindow, network.minerWindow);
  assert.strictEqual(fixture.lastCheckpoint, network.lastCheckpoint);
  assert.deepStrictEqual(fixture.deployments, network.deploys.map(deploymentJson));
  assert.strictEqual(
    fixture.periods.length,
    THROUGH_HEIGHT / network.minerWindow
  );

  const boundaries = new Map();
  let current = new Map();
  const entryAt = height => current.get(height) || boundaries.get(height) || null;
  const chain = chainView(
    network,
    entryAt,
    entry => entry.medianTimePast
  );

  for (const [index, period] of fixture.periods.entries()) {
    const nextHeight = (index + 1) * network.minerWindow;
    assert.strictEqual(period.nextHeight, nextHeight);
    assert.strictEqual(period.periodStartHeight,
      nextHeight - network.minerWindow);
    assert.strictEqual(period.periodEndHeight, nextHeight - 1);
    assert(/^[0-9a-f]{64}$/.test(period.periodStartHash),
      `period ${nextHeight} has an invalid start hash`);
    assert(/^[0-9a-f]{64}$/.test(period.periodEndHash),
      `period ${nextHeight} has an invalid end hash`);
    assert(Number.isSafeInteger(period.medianTimePast),
      `period ${nextHeight} has an invalid median time`);
    for (const deployment of network.deploys) {
      const count = period.signalling[deployment.name];
      assert(Number.isSafeInteger(count) && count >= 0
        && count <= network.minerWindow,
      `period ${nextHeight} has an invalid ${deployment.name} count`);
    }

    current = syntheticPeriod(period, network.deploys, network.minerWindow);
    const previous = current.get(period.periodEndHeight);
    const result = await deploymentResult(chain, previous, previous.time || 0);
    assert.deepStrictEqual(
      result.states,
      period.states,
      `deployment state mismatch at height ${nextHeight}`
    );
    assert.deepStrictEqual(
      result.effects,
      period.effects,
      `deployment effects mismatch at height ${nextHeight}`
    );
    assert.strictEqual(
      result.blockVersion,
      period.nextBlockVersion,
      `next block version mismatch at height ${nextHeight}`
    );
    assert.deepStrictEqual(
      {
        historicalHeight: period.historicalHeight,
        historicalBlock: period.historicalBlock
      },
      historicalResult(network, nextHeight),
      `historical policy mismatch at height ${nextHeight}`
    );
    boundaries.set(period.periodEndHeight, previous);
  }

  assert.strictEqual(fixture.historicalBoundaries.length, 6);
  for (const boundary of fixture.historicalBoundaries) {
    assert(/^[0-9a-f]{64}$/.test(boundary.hash),
      `historical boundary ${boundary.height} has an invalid hash`);
    assert.deepStrictEqual(
      {
        historicalHeight: boundary.historicalHeight,
        historicalBlock: boundary.historicalBlock
      },
      historicalResult(network, boundary.height),
      `historical boundary mismatch at height ${boundary.height}`
    );
  }
  const anchor = fixture.historicalBoundaries.at(-1);
  assert.strictEqual(anchor.height, THROUGH_HEIGHT);
  assert.strictEqual(anchor.hash, fixture.anchorHash);

  assert.strictEqual(fixture.historicalFinalityCases.length, 1);
  for (const item of fixture.historicalFinalityCases) {
    assert.strictEqual(item.id,
      'mainnet-block-1-coinbase-finality-exemption');
    assert.strictEqual(item.height, FINALITY_HEIGHT);
    assert(/^[0-9a-f]{64}$/.test(item.hash),
      `${item.id} has an invalid block hash`);
    assert(Number.isSafeInteger(item.parentMedianTimePast),
      `${item.id} has an invalid parent median time`);
    assert(typeof item.raw === 'string' && /^[0-9a-f]+$/.test(item.raw),
      `${item.id} has invalid block bytes`);
    const block = Block.decode(Buffer.from(item.raw, 'hex'));
    assert.strictEqual(block.hash().toString('hex'), item.hash);
    assert.strictEqual(block.encode().toString('hex'), item.raw);
    const transactionFinality = block.txs.map(tx =>
      tx.isFinal(item.height, item.parentMedianTimePast));
    assert.deepStrictEqual(transactionFinality, item.transactionFinality);
    assert.deepStrictEqual(
      block.txs.map((_tx, index) => index).slice(1),
      item.checkedTransactionIndexes
    );
    assert.strictEqual(transactionFinality[0], false,
      `${item.id} must retain its non-final coinbase evidence`);
    assert.strictEqual(
      item.checkedTransactionIndexes.every(index => transactionFinality[index]),
      item.accepted,
      `${item.id} HSD block-finality route mismatch`
    );
    assert.strictEqual(item.accepted, true);
  }
}

function stable(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
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
    fixture = await fetchFixture(path.resolve(prefix));
    await validateFixture(fixture);
    if (write) {
      fs.mkdirSync(path.dirname(OUTPUT), {recursive: true});
      fs.writeFileSync(OUTPUT, stable(fixture));
      console.log(`wrote ${path.relative(ROOT, OUTPUT)}`);
    }
  }

  if (check) {
    const committed = JSON.parse(fs.readFileSync(OUTPUT, 'utf8'));
    await validateFixture(committed);
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
