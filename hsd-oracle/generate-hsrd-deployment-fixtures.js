'use strict';

// Generates deterministic HSD deployment, checkpoint, and historical-policy
// fixtures. The synthetic histories are evaluated by HSD's own Chain methods;
// they are intentionally small so the Rust fixture remains reviewable.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const {installMemoryOnlyDatabaseShim} = require('./memory-db-shim');
const hsdRoot = path.dirname(require.resolve('hsd/package.json'));
installMemoryOnlyDatabaseShim(hsdRoot);

const Chain = require('hsd/lib/blockchain/chain');
const chainCommon = require('hsd/lib/blockchain/common');
const Network = require('hsd/lib/protocol/network');
const scriptCommon = require('hsd/lib/script/common');

const REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(ROOT, 'hsrd/fixtures/hsd/chains/deployments-v1.json');

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

function entry(height, version, medianTimePast) {
  return {
    height,
    version: version >>> 0,
    medianTimePast,
    hash: Buffer.alloc(32, height & 0xff),
    hasBit(bit) {
      return (this.version & (1 << bit)) !== 0;
    }
  };
}

function fakeChain(entries, options = {}) {
  const network = {
    activationThreshold: options.activationThreshold || 3,
    minerWindow: options.minerWindow || 4,
    deploys: options.deploys || []
  };

  return {
    network,
    db: {
      stateCache: {
        get() {
          return -1;
        },
        set() {}
      }
    },
    async getAncestor(_tip, height) {
      if (height < 0 || height >= entries.length)
        return null;
      return entries[height];
    },
    async getMedianTime(item) {
      return item.medianTimePast;
    },
    async getPrevious(item) {
      if (item.height === 0)
        return null;
      return entries[item.height - 1];
    },
    async getState(previous, deployment) {
      return Chain.prototype.getState.call(this, previous, deployment);
    }
  };
}

function makeHistory(length, boundaryTimes, signalling = {}) {
  const entries = [];
  for (let height = 0; height < length; height++) {
    const period = Math.floor(height / 4);
    const medianTimePast = boundaryTimes[period] || boundaryTimes.at(-1) || 0;
    let version = 0;
    for (const [bit, heights] of Object.entries(signalling)) {
      if (heights.includes(height))
        version |= 1 << Number(bit);
    }
    entries.push(entry(height, version, medianTimePast));
  }
  return entries;
}

async function thresholdVector(id, history, deployment, options = {}) {
  const chain = fakeChain(history, options);
  const state = await Chain.prototype.getState.call(
    chain,
    history[history.length - 1],
    deployment
  );
  return {
    id,
    activationThreshold: chain.network.activationThreshold,
    minerWindow: chain.network.minerWindow,
    deployment: deploymentJson(deployment),
    history: history.map(item => ({
      version: item.version,
      medianTimePast: item.medianTimePast
    })),
    expectedState: Object.keys(chainCommon.thresholdStates)
      .find(name => chainCommon.thresholdStates[name] === state)
  };
}

async function makeThresholdVectors() {
  const base = {
    name: 'fixture',
    bit: 0,
    startTime: 100,
    timeout: 200,
    threshold: -1,
    window: -1,
    required: false,
    force: false
  };
  const signalled = {0: [4, 5, 6]};

  return Promise.all([
    thresholdVector('incomplete-period-defined', makeHistory(2, [99]), base),
    thresholdVector('defined-before-start', makeHistory(4, [99]), base),
    thresholdVector('started-at-boundary', makeHistory(4, [100]), base),
    thresholdVector(
      'locked-in-after-threshold',
      makeHistory(8, [100, 110], signalled),
      base
    ),
    thresholdVector(
      'locked-in-through-partial-period',
      makeHistory(10, [100, 110, 120], signalled),
      base
    ),
    thresholdVector(
      'active-one-period-after-lock-in',
      makeHistory(12, [100, 110, 120], signalled),
      base
    ),
    thresholdVector('failed-at-timeout', makeHistory(4, [200]), base),
    thresholdVector(
      'timeout-wins-over-signalling',
      makeHistory(8, [100, 200], {0: [4, 5, 6, 7]}),
      base
    ),
    thresholdVector(
      'deployment-window-override',
      makeHistory(4, [100], {1: [2]}),
      {...base, bit: 1, threshold: 1, window: 2},
      {activationThreshold: 3, minerWindow: 4}
    )
  ]);
}

async function makeBlockVersionCase() {
  const deployments = [
    {name: 'active', bit: 0, startTime: 100, timeout: 1000,
      threshold: -1, window: -1, required: false, force: false},
    {name: 'locked-in', bit: 1, startTime: 100, timeout: 1000,
      threshold: -1, window: -1, required: false, force: false},
    {name: 'started', bit: 2, startTime: 100, timeout: 1000,
      threshold: -1, window: -1, required: false, force: false},
    {name: 'failed', bit: 3, startTime: 0, timeout: 1,
      threshold: -1, window: -1, required: false, force: false}
  ];
  const history = makeHistory(12, [100, 110, 120], {
    0: [4, 5, 6],
    1: [8, 9, 10]
  });
  const chain = fakeChain(history, {deploys: deployments});
  const version = await Chain.prototype.computeBlockVersion.call(
    chain,
    history[history.length - 1]
  );
  return {
    activationThreshold: chain.network.activationThreshold,
    minerWindow: chain.network.minerWindow,
    deployments: deployments.map(deploymentJson),
    history: history.map(item => ({
      version: item.version,
      medianTimePast: item.medianTimePast
    })),
    expectedVersion: version
  };
}

async function makeDeploymentEffectCases() {
  const network = Network.get('main');
  const cases = [];
  for (const active of [[], ['hardening'], ['icannlockup'], ['airstop'],
    ['hardening', 'icannlockup', 'airstop']]) {
    const chain = {
      network,
      async isActive(_previous, deployment) {
        return active.includes(deployment.name);
      }
    };
    const state = await Chain.prototype.getDeployments.call(
      chain,
      network.genesis.time,
      {hash: network.genesis.hash}
    );
    cases.push({
      active,
      scriptFlags: state.flags,
      lockFlags: state.lockFlags,
      nameFlags: state.nameFlags,
      hasAirstop: state.hasAirstop
    });
  }
  return cases;
}

function networkJson(name) {
  const network = Network.get(name);
  return {
    name,
    activationThreshold: network.activationThreshold,
    minerWindow: network.minerWindow,
    lastCheckpoint: network.lastCheckpoint,
    checkpoints: network.checkpoints.map(checkpoint => ({
      height: checkpoint.height,
      hash: checkpoint.hash.toString('hex')
    })),
    deployments: network.deploys.map(deploymentJson)
  };
}

function historicalCases() {
  const network = Network.get('main');
  const heights = [0, 1, network.lastCheckpoint - 1,
    network.lastCheckpoint, network.lastCheckpoint + 1];
  const cases = [];
  for (const checkpoints of [false, true]) {
    const chain = {options: {checkpoints}, network};
    for (const height of heights) {
      cases.push({
        checkpoints,
        height,
        historicalHeight: Chain.prototype.isHistoricalHeight.call(chain, height),
        historicalBlock: height === 0
          ? false
          : Chain.prototype.isHistorical.call(chain, {height: height - 1})
      });
    }
  }
  return cases;
}

async function makeFixture() {
  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: REVISION
    },
    scriptFlags: {
      mandatory: scriptCommon.flags.MANDATORY_VERIFY_FLAGS,
      standard: scriptCommon.flags.STANDARD_VERIFY_FLAGS
    },
    networks: ['main', 'testnet', 'regtest', 'simnet'].map(networkJson),
    thresholdVectors: await makeThresholdVectors(),
    blockVersionCase: await makeBlockVersionCase(),
    deploymentEffectCases: await makeDeploymentEffectCases(),
    historicalCases: historicalCases()
  };
}

function stable(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

async function main() {
  const write = process.argv.includes('--write');
  const check = process.argv.includes('--check');
  assert(write || check, 'use --write and/or --check');
  const expected = stable(await makeFixture());

  if (write) {
    fs.mkdirSync(path.dirname(OUTPUT), {recursive: true});
    fs.writeFileSync(OUTPUT, expected);
    console.log(`wrote ${path.relative(ROOT, OUTPUT)}`);
  }

  if (check) {
    const actual = fs.readFileSync(OUTPUT, 'utf8');
    assert.strictEqual(actual, expected, `${OUTPUT} is not reproducible`);
    console.log(`verified ${path.relative(ROOT, OUTPUT)}`);
  }
}

main().catch(error => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
