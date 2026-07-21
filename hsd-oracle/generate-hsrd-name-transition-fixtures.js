#!/usr/bin/env node
'use strict';

// Generate deterministic contextual NameState transition fixtures by running
// the exact pinned HSD Chain.verifyCovenants implementation. The companion
// Rust test separately replays every pre-state, transaction, active-chain
// renewal lookup, historical bypass, and expected post-state.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const Address = require('hsd/lib/primitives/address');
const CoinView = require('hsd/lib/coins/coinview');
const Covenant = require('hsd/lib/primitives/covenant');
const Input = require('hsd/lib/primitives/input');
const NameState = require('hsd/lib/covenants/namestate');
const Network = require('hsd/lib/protocol/network');
const Outpoint = require('hsd/lib/primitives/outpoint');
const Output = require('hsd/lib/primitives/output');
const TX = require('hsd/lib/primitives/tx');
const hsdPackage = require('hsd/package.json');
const rules = require('hsd/lib/covenants/rules');

// Loading Chain normally also loads the native LevelDB binding even though
// this oracle calls only its pure contextual verifier. Stub that unused
// constructor before requiring Chain so fixture checks stay portable across
// Node ABIs and still execute the exact pinned Chain.verifyCovenants method.
const chainDBPath = require.resolve('hsd/lib/blockchain/chaindb');
require.cache[chainDBPath] = {
  id: chainDBPath,
  filename: chainDBPath,
  loaded: true,
  exports: class UnusedChainDB {}
};
const Chain = require('hsd/lib/blockchain/chain');
delete require.cache[chainDBPath];

const ORACLE_REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const ROOT = path.resolve(__dirname, '..');
const TARGET = path.join(
  ROOT,
  'hsrd/fixtures/hsd/name-states/transitions-v1.json'
);
const WRITE = process.argv.includes('--write');
const CHECK = process.argv.includes('--check') || !WRITE;
const network = Network.get('regtest');
const {types} = rules;

function stable(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function u32(value) {
  const bytes = Buffer.allocUnsafe(4);
  bytes.writeUInt32LE(value >>> 0, 0);
  return bytes;
}

function address(byte, size = 20, version = 0) {
  return new Address({version, hash: Buffer.alloc(size, byte)});
}

function covenant(type, items = []) {
  return new Covenant(type, items.map(item => Buffer.from(item)));
}

function none() {
  return covenant(types.NONE);
}

function open(nameHash, name) {
  return covenant(types.OPEN, [nameHash, u32(0), name]);
}

function bid(nameHash, name, start, value, nonce) {
  return covenant(types.BID, [
    nameHash,
    u32(start),
    name,
    rules.blind(value, nonce)
  ]);
}

function reveal(nameHash, start, nonce) {
  return covenant(types.REVEAL, [nameHash, u32(start), nonce]);
}

function redeem(nameHash, start) {
  return covenant(types.REDEEM, [nameHash, u32(start)]);
}

function claim(nameHash, name, start) {
  return covenant(types.CLAIM, [
    nameHash,
    u32(start),
    name,
    Buffer.from([1]),
    Buffer.alloc(32, 0x91),
    u32(1)
  ]);
}

function register(nameHash, start, data, renewalHash) {
  return covenant(types.REGISTER, [nameHash, u32(start), data, renewalHash]);
}

function update(nameHash, start, data) {
  return covenant(types.UPDATE, [nameHash, u32(start), data]);
}

function renew(nameHash, start, renewalHash) {
  return covenant(types.RENEW, [nameHash, u32(start), renewalHash]);
}

function transfer(nameHash, start, destination) {
  return covenant(types.TRANSFER, [
    nameHash,
    u32(start),
    Buffer.from([destination.version]),
    destination.hash
  ]);
}

function finalize(nameHash, start, name, weak, claimed, renewals, renewalHash) {
  return covenant(types.FINALIZE, [
    nameHash,
    u32(start),
    name,
    Buffer.from([Number(weak)]),
    u32(claimed),
    u32(renewals),
    renewalHash
  ]);
}

function revoke(nameHash, start) {
  return covenant(types.REVOKE, [nameHash, u32(start)]);
}

function cloneState(state, nameHash) {
  const copy = NameState.decode(state.encode());
  copy.nameHash = Buffer.from(nameHash);
  return copy;
}

function nullState(nameHash) {
  const state = new NameState();
  state.nameHash = Buffer.from(nameHash);
  return state;
}

function funding(byte, value, owner = address(byte)) {
  return {
    outpoint: new Outpoint(Buffer.alloc(32, byte), 0),
    output: new Output({value, address: owner, covenant: none()})
  };
}

function transaction(inputCoin, outputCovenant, options = {}) {
  const outputValue = options.value == null
    ? inputCoin.output.value
    : options.value;
  const outputAddress = options.address || inputCoin.output.address;
  const tx = new TX({
    version: 1,
    inputs: [new Input({
      prevout: inputCoin.outpoint,
      sequence: 0xffffffff
    })],
    outputs: [new Output({
      value: outputValue,
      address: outputAddress,
      covenant: outputCovenant
    })],
    locktime: 0
  });
  return tx;
}

function produced(tx) {
  return {
    outpoint: new Outpoint(tx.hash(), 0),
    output: tx.outputs[0]
  };
}

function coinJson(inputCoin) {
  return {
    outpointTxid: inputCoin.outpoint.hash.toString('hex'),
    outpointIndex: inputCoin.outpoint.index,
    value: inputCoin.output.value,
    height: 1,
    coinbase: false,
    addressVersion: inputCoin.output.address.version,
    addressHash: inputCoin.output.address.hash.toString('hex'),
    covenantType: inputCoin.output.covenant.type,
    covenantItems: inputCoin.output.covenant.items.map(item => item.toString('hex'))
  };
}

function contextJson(entries) {
  return entries.map(entry => ({
    hash: entry.hash.toString('hex'),
    height: entry.height,
    main: entry.main !== false
  }));
}

async function runCase({
  id,
  height,
  nameFlags = 0,
  historical = false,
  nameHash,
  preState,
  tx,
  inputCoin,
  contextEntries = [],
  expected,
  expectedReason = null
}) {
  const view = new CoinView();
  const state = cloneState(preState, nameHash);
  view.names.set(nameHash, state);
  view.addOutput(inputCoin.outpoint, inputCoin.output);

  const linkageResult = tx.verifyCovenants(view, height, network);
  assert(linkageResult >= 0, `${id}: linkage rejected with ${linkageResult}`);

  const entries = new Map(contextEntries.map(entry => [
    entry.hash.toString('hex'),
    {height: entry.height, main: entry.main !== false}
  ]));
  const chain = Object.create(Chain.prototype);
  chain.network = network;
  chain.isHistoricalHeight = () => historical;
  chain.db = {
    async getNameState() {
      return null;
    },
    async getEntry(hash) {
      const entry = entries.get(hash.toString('hex'));
      return entry ? {...entry} : null;
    },
    async isMainChain(entry) {
      return entry.main;
    }
  };

  let accepted = true;
  let reason = null;
  try {
    await Chain.prototype.verifyCovenants.call(
      chain,
      tx,
      view,
      height,
      nameFlags
    );
  } catch (error) {
    accepted = false;
    reason = error.reason || error.message;
  }

  assert.strictEqual(
    accepted,
    expected,
    `${id}: contextual result${reason ? ` (${reason})` : ''}`
  );
  if (expectedReason != null)
    assert.strictEqual(reason, expectedReason, `${id}: rejection reason`);

  const postState = view.names.get(nameHash);
  return {
    record: {
      id,
      height,
      nameFlags,
      historical,
      nameHash: nameHash.toString('hex'),
      preStateRaw: preState.encode().toString('hex'),
      transactionRaw: tx.encode().toString('hex'),
      inputCoins: [coinJson(inputCoin)],
      activeChain: contextJson(contextEntries),
      linkageResult,
      accepted,
      reason,
      postStateRaw: accepted ? postState.encode().toString('hex') : null
    },
    postState: accepted ? cloneState(postState, nameHash) : null,
    outputCoin: produced(tx)
  };
}

async function buildCases() {
  const name = Buffer.from('meshminetest', 'ascii');
  const nameHash = rules.hashName(name);
  const start = 120;
  const owner1 = address(0x31);
  const owner2 = address(0x32);
  const destination = address(0x33, 32);
  const nonce1 = Buffer.alloc(32, 0x41);
  const nonce2 = Buffer.alloc(32, 0x42);
  const renewalHash = Buffer.alloc(32, 0x51);
  const renewalEntry = {hash: renewalHash, height: 90, main: true};
  const cases = [];
  const snapshots = new Map();

  let state = nullState(nameHash);
  snapshots.set('null', cloneState(state, nameHash));

  let result = await runCase({
    id: 'open-absent-name',
    height: start,
    nameHash,
    preState: state,
    inputCoin: funding(0x01, 1_000, owner1),
    tx: transaction(funding(0x01, 1_000, owner1), open(nameHash, name), {
      value: 0,
      address: owner1
    }),
    expected: true
  });
  cases.push(result.record);
  state = result.postState;
  snapshots.set('opened', cloneState(state, nameHash));

  const bidCoin1 = funding(0x02, 2_000, owner1);
  const bidTx1 = transaction(
    bidCoin1,
    bid(nameHash, name, start, 2_000, nonce1),
    {value: 2_000, address: owner1}
  );
  result = await runCase({
    id: 'first-bid-does-not-mutate-name-state',
    height: 126,
    nameHash,
    preState: state,
    inputCoin: bidCoin1,
    tx: bidTx1,
    expected: true
  });
  cases.push(result.record);
  state = result.postState;
  const bidOutput1 = result.outputCoin;

  const bidCoin2 = funding(0x03, 5_000, owner2);
  const bidTx2 = transaction(
    bidCoin2,
    bid(nameHash, name, start, 5_000, nonce2),
    {value: 5_000, address: owner2}
  );
  result = await runCase({
    id: 'second-bid-does-not-mutate-name-state',
    height: 127,
    nameHash,
    preState: state,
    inputCoin: bidCoin2,
    tx: bidTx2,
    expected: true
  });
  cases.push(result.record);
  state = result.postState;
  const bidOutput2 = result.outputCoin;

  const revealTx1 = transaction(
    bidOutput1,
    reveal(nameHash, start, nonce1),
    {value: 2_000, address: owner1}
  );
  result = await runCase({
    id: 'first-reveal-establishes-high-bid',
    height: 131,
    nameHash,
    preState: state,
    inputCoin: bidOutput1,
    tx: revealTx1,
    expected: true
  });
  cases.push(result.record);
  state = result.postState;
  const revealOutput1 = result.outputCoin;
  snapshots.set('first-reveal', cloneState(state, nameHash));

  const revealTx2 = transaction(
    bidOutput2,
    reveal(nameHash, start, nonce2),
    {value: 5_000, address: owner2}
  );
  result = await runCase({
    id: 'second-reveal-establishes-second-price',
    height: 132,
    nameHash,
    preState: state,
    inputCoin: bidOutput2,
    tx: revealTx2,
    expected: true
  });
  cases.push(result.record);
  state = result.postState;
  const revealOutput2 = result.outputCoin;
  snapshots.set('revealed', cloneState(state, nameHash));

  const registerTx = transaction(
    revealOutput2,
    register(nameHash, start, Buffer.from('010203', 'hex'), renewalHash),
    {value: 2_000, address: owner2}
  );
  result = await runCase({
    id: 'winning-reveal-registers-at-second-price',
    height: 141,
    nameHash,
    preState: state,
    inputCoin: revealOutput2,
    tx: registerTx,
    contextEntries: [renewalEntry],
    expected: true
  });
  cases.push(result.record);
  state = result.postState;
  let ownerCoin = result.outputCoin;
  snapshots.set('registered', cloneState(state, nameHash));

  const updateTx = transaction(
    ownerCoin,
    update(nameHash, start, Buffer.from('040506', 'hex')),
    {value: 2_000, address: owner2}
  );
  result = await runCase({
    id: 'update-replaces-resource-and-owner-outpoint',
    height: 142,
    nameHash,
    preState: state,
    inputCoin: ownerCoin,
    tx: updateTx,
    expected: true
  });
  cases.push(result.record);
  state = result.postState;
  ownerCoin = result.outputCoin;

  const renewTx = transaction(
    ownerCoin,
    renew(nameHash, start, renewalHash),
    {value: 2_000, address: owner2}
  );
  result = await runCase({
    id: 'renew-uses-mature-active-chain-commitment',
    height: 146,
    nameHash,
    preState: state,
    inputCoin: ownerCoin,
    tx: renewTx,
    contextEntries: [renewalEntry],
    expected: true
  });
  cases.push(result.record);
  state = result.postState;
  ownerCoin = result.outputCoin;
  snapshots.set('renewed', cloneState(state, nameHash));

  const transferTx = transaction(
    ownerCoin,
    transfer(nameHash, start, destination),
    {value: 2_000, address: owner2}
  );
  result = await runCase({
    id: 'transfer-starts-lockup',
    height: 147,
    nameHash,
    preState: state,
    inputCoin: ownerCoin,
    tx: transferTx,
    expected: true
  });
  cases.push(result.record);
  state = result.postState;
  const transferCoin = result.outputCoin;
  snapshots.set('transferred', cloneState(state, nameHash));

  const finalizeTx = transaction(
    transferCoin,
    finalize(nameHash, start, name, false, 0, 1, renewalHash),
    {value: 2_000, address: destination}
  );
  result = await runCase({
    id: 'finalize-mature-transfer-and-state-commitment',
    height: 157,
    nameHash,
    preState: state,
    inputCoin: transferCoin,
    tx: finalizeTx,
    contextEntries: [renewalEntry],
    expected: true
  });
  cases.push(result.record);
  state = result.postState;
  ownerCoin = result.outputCoin;
  snapshots.set('finalized', cloneState(state, nameHash));

  const revokeTx = transaction(ownerCoin, revoke(nameHash, start), {
    value: 2_000,
    address: destination
  });
  result = await runCase({
    id: 'revoke-clears-resource-and-transfer',
    height: 158,
    nameHash,
    preState: state,
    inputCoin: ownerCoin,
    tx: revokeTx,
    expected: true
  });
  cases.push(result.record);
  state = result.postState;
  snapshots.set('revoked', cloneState(state, nameHash));

  const reopenCoin = funding(0x04, 1_000, owner1);
  result = await runCase({
    id: 'reopen-after-revoke-auction-maturity',
    height: 223,
    nameHash,
    preState: state,
    inputCoin: reopenCoin,
    tx: transaction(reopenCoin, open(nameHash, name), {
      value: 0,
      address: owner1
    }),
    expected: true
  });
  cases.push(result.record);

  const historicalBidCoin = funding(0x05, 3_000, owner1);
  result = await runCase({
    id: 'historical-bid-bypasses-absent-name-read',
    height: 50,
    historical: true,
    nameHash,
    preState: snapshots.get('null'),
    inputCoin: historicalBidCoin,
    tx: transaction(
      historicalBidCoin,
      bid(nameHash, name, 10, 3_000, nonce1),
      {value: 3_000, address: owner1}
    ),
    expected: true
  });
  cases.push(result.record);

  const historicalReveal = {
    outpoint: new Outpoint(Buffer.alloc(32, 0x06), 0),
    output: new Output({
      value: 2_000,
      address: owner1,
      covenant: reveal(nameHash, 10, nonce1)
    })
  };
  result = await runCase({
    id: 'historical-redeem-bypasses-absent-name-read',
    height: 50,
    historical: true,
    nameHash,
    preState: snapshots.get('null'),
    inputCoin: historicalReveal,
    tx: transaction(historicalReveal, redeem(nameHash, 10), {
      value: 2_000,
      address: owner1
    }),
    expected: true
  });
  cases.push(result.record);

  const multipleOpenCoin = funding(0x07, 1_000, owner1);
  result = await runCase({
    id: 'reject-second-open-before-expiration',
    height: 121,
    nameHash,
    preState: snapshots.get('opened'),
    inputCoin: multipleOpenCoin,
    tx: transaction(multipleOpenCoin, open(nameHash, name), {
      value: 0,
      address: owner1
    }),
    expected: false,
    expectedReason: 'bad-open-multiple'
  });
  cases.push(result.record);

  const earlyBidCoin = funding(0x08, 2_000, owner1);
  result = await runCase({
    id: 'reject-bid-before-bidding-state',
    height: 125,
    nameHash,
    preState: snapshots.get('opened'),
    inputCoin: earlyBidCoin,
    tx: transaction(
      earlyBidCoin,
      bid(nameHash, name, start, 2_000, nonce1),
      {value: 2_000, address: owner1}
    ),
    expected: false,
    expectedReason: 'bad-bid-state'
  });
  cases.push(result.record);

  const wrongStartBid = {
    outpoint: new Outpoint(Buffer.alloc(32, 0x09), 0),
    output: new Output({
      value: 2_000,
      address: owner1,
      covenant: bid(nameHash, name, start + 1, 2_000, nonce1)
    })
  };
  result = await runCase({
    id: 'reject-reveal-with-nonlocal-start',
    height: 131,
    nameHash,
    preState: snapshots.get('opened'),
    inputCoin: wrongStartBid,
    tx: transaction(
      wrongStartBid,
      reveal(nameHash, start + 1, nonce1),
      {value: 2_000, address: owner1}
    ),
    expected: false,
    expectedReason: 'bad-reveal-nonlocal'
  });
  cases.push(result.record);

  result = await runCase({
    id: 'reject-winning-reveal-redemption',
    height: 141,
    nameHash,
    preState: snapshots.get('revealed'),
    inputCoin: revealOutput2,
    tx: transaction(revealOutput2, redeem(nameHash, start), {
      value: 5_000,
      address: owner2
    }),
    expected: false,
    expectedReason: 'bad-redeem-owner'
  });
  cases.push(result.record);

  result = await runCase({
    id: 'reject-losing-reveal-registration',
    height: 141,
    nameHash,
    preState: snapshots.get('revealed'),
    inputCoin: revealOutput1,
    tx: transaction(
      revealOutput1,
      register(nameHash, start, Buffer.alloc(0), renewalHash),
      {value: 2_000, address: owner1}
    ),
    contextEntries: [renewalEntry],
    expected: false,
    expectedReason: 'bad-register-owner'
  });
  cases.push(result.record);

  result = await runCase({
    id: 'reject-register-value-above-second-price',
    height: 141,
    nameHash,
    preState: snapshots.get('revealed'),
    inputCoin: revealOutput2,
    tx: transaction(
      revealOutput2,
      register(nameHash, start, Buffer.alloc(0), renewalHash),
      {value: 2_001, address: owner2}
    ),
    contextEntries: [renewalEntry],
    expected: false,
    expectedReason: 'bad-register-value'
  });
  cases.push(result.record);

  const immatureHash = Buffer.alloc(32, 0x52);
  result = await runCase({
    id: 'reject-register-immature-renewal-commitment',
    height: 141,
    nameHash,
    preState: snapshots.get('revealed'),
    inputCoin: revealOutput2,
    tx: transaction(
      revealOutput2,
      register(nameHash, start, Buffer.alloc(0), immatureHash),
      {value: 2_000, address: owner2}
    ),
    contextEntries: [{hash: immatureHash, height: 100, main: true}],
    expected: false,
    expectedReason: 'bad-register-renewal'
  });
  cases.push(result.record);

  const registeredCoin = {
    outpoint: new Outpoint(Buffer.alloc(32, 0x0a), 0),
    output: new Output({
      value: 2_000,
      address: owner2,
      covenant: register(nameHash, start, Buffer.alloc(0), renewalHash)
    })
  };
  result = await runCase({
    id: 'reject-update-before-closed-state',
    height: 135,
    nameHash,
    preState: snapshots.get('revealed'),
    inputCoin: registeredCoin,
    tx: transaction(
      registeredCoin,
      update(nameHash, start, Buffer.alloc(0)),
      {value: 2_000, address: owner2}
    ),
    expected: false,
    expectedReason: 'bad-update-state'
  });
  cases.push(result.record);

  result = await runCase({
    id: 'reject-premature-renewal',
    height: 145,
    nameHash,
    preState: snapshots.get('registered'),
    inputCoin: registeredCoin,
    tx: transaction(registeredCoin, renew(nameHash, start, renewalHash), {
      value: 2_000,
      address: owner2
    }),
    contextEntries: [renewalEntry],
    expected: false,
    expectedReason: 'bad-renewal-premature'
  });
  cases.push(result.record);

  const futureHash = Buffer.alloc(32, 0x53);
  result = await runCase({
    id: 'reject-renewal-commitment-inside-reorg-window',
    height: 146,
    nameHash,
    preState: snapshots.get('registered'),
    inputCoin: registeredCoin,
    tx: transaction(registeredCoin, renew(nameHash, start, futureHash), {
      value: 2_000,
      address: owner2
    }),
    contextEntries: [{hash: futureHash, height: 97, main: true}],
    expected: false,
    expectedReason: 'bad-renewal'
  });
  cases.push(result.record);

  result = await runCase({
    id: 'reject-finalize-before-transfer-maturity',
    height: 156,
    nameHash,
    preState: snapshots.get('transferred'),
    inputCoin: transferCoin,
    tx: finalizeTx,
    contextEntries: [renewalEntry],
    expected: false,
    expectedReason: 'bad-finalize-maturity'
  });
  cases.push(result.record);

  result = await runCase({
    id: 'reject-finalize-state-transfer-mismatch',
    height: 157,
    nameHash,
    preState: snapshots.get('transferred'),
    inputCoin: transferCoin,
    tx: transaction(
      transferCoin,
      finalize(nameHash, start, name, false, 0, 0, renewalHash),
      {value: 2_000, address: destination}
    ),
    contextEntries: [renewalEntry],
    expected: false,
    expectedReason: 'bad-finalize-statetransfer'
  });
  cases.push(result.record);

  const claimedName = Buffer.from('claimed-alpha', 'ascii');
  const claimedHash = rules.hashName(claimedName);
  const claimOutpoint = new Outpoint(Buffer.alloc(32, 0x0b), 0);
  const claimedState = nullState(claimedHash);
  claimedState.name = claimedName;
  claimedState.height = 100;
  claimedState.renewal = 100;
  claimedState.owner = claimOutpoint;
  claimedState.claimed = 1;
  claimedState.weak = true;
  const claimCoin = {
    outpoint: claimOutpoint,
    output: new Output({
      value: 0,
      address: owner1,
      covenant: claim(claimedHash, claimedName, 100)
    })
  };
  const claimedRenewalHash = Buffer.alloc(32, 0x54);
  const claimedRegister = transaction(
    claimCoin,
    register(claimedHash, 100, Buffer.alloc(0), claimedRenewalHash),
    {value: 0, address: owner1}
  );
  result = await runCase({
    id: 'weak-claimed-register-before-hardening',
    height: 103,
    nameHash: claimedHash,
    preState: claimedState,
    inputCoin: claimCoin,
    tx: claimedRegister,
    contextEntries: [{hash: claimedRenewalHash, height: 50, main: true}],
    expected: true
  });
  cases.push(result.record);

  result = await runCase({
    id: 'reject-weak-claimed-register-after-hardening',
    height: 103,
    nameFlags: rules.nameFlags.VERIFY_COVENANTS_HARDENED,
    nameHash: claimedHash,
    preState: claimedState,
    inputCoin: claimCoin,
    tx: claimedRegister,
    contextEntries: [{hash: claimedRenewalHash, height: 50, main: true}],
    expected: false,
    expectedReason: 'bad-register-state'
  });
  cases.push(result.record);

  return cases;
}

async function main() {
  const fixture = {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: ORACLE_REVISION,
      hsdVersion: hsdPackage.version
    },
    network: 'regtest',
    parameters: {
      auctionStart: network.names.auctionStart,
      rolloutInterval: network.names.rolloutInterval,
      lockupPeriod: network.names.lockupPeriod,
      renewalWindow: network.names.renewalWindow,
      renewalPeriod: network.names.renewalPeriod,
      renewalMaturity: network.names.renewalMaturity,
      claimPeriod: network.names.claimPeriod,
      alexaLockupPeriod: network.names.alexaLockupPeriod,
      claimFrequency: network.names.claimFrequency,
      biddingPeriod: network.names.biddingPeriod,
      revealPeriod: network.names.revealPeriod,
      treeInterval: network.names.treeInterval,
      transferLockup: network.names.transferLockup,
      auctionMaturity: network.names.auctionMaturity,
      noRollout: network.names.noRollout,
      noReserved: network.names.noReserved
    },
    scope: 'HSD contextual NameState transitions with independently rechecked covenant linkage',
    cases: await buildCases()
  };
  const expected = stable(fixture);

  if (WRITE) {
    fs.mkdirSync(path.dirname(TARGET), {recursive: true});
    fs.writeFileSync(TARGET, expected, {encoding: 'utf8', mode: 0o644});
  }

  if (CHECK) {
    const actual = fs.readFileSync(TARGET, 'utf8');
    assert.strictEqual(
      actual,
      expected,
      `${path.relative(process.cwd(), TARGET)} is not reproducible; run with --write`
    );
  }

  const accepted = fixture.cases.filter(item => item.accepted).length;
  const rejected = fixture.cases.length - accepted;
  console.log(
    `${path.relative(process.cwd(), TARGET)}: `
    + `${accepted} accepted and ${rejected} rejected HSD name transitions verified`
  );
}

main().catch(error => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
