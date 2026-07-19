#!/usr/bin/env node
'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {installMemoryOnlyDatabaseShim} = require('./memory-db-shim');
const {signatureMessage} = require('./core-v2-audit');

const hsd = resolveHsd();
installMemoryOnlyDatabaseShim(hsd);
const FullNode = require(path.join(hsd, 'lib/node/fullnode'));
const Output = require(path.join(hsd, 'lib/primitives/output'));
const consensus = require(path.join(hsd, 'lib/protocol/consensus'));
const mine = require(path.join(hsd, 'lib/mining/mine'));
const walletPlugin = require(path.join(hsd, 'lib/wallet/plugin'));
const BLAKE2b = require(require.resolve('bcrypto/lib/blake2b', {paths: [hsd]}));
const merkle = require(require.resolve('bcrypto/lib/mrkl', {paths: [hsd]}));

async function main() {
  const node = new FullNode({
    memory: true,
    network: 'regtest',
    apiKey: 'meshmine-payout-regtest',
    workers: false,
    plugins: [walletPlugin]
  });

  try {
    await node.open();
    const wallet = await node.require('walletdb').wdb.create();
    node.miner.addresses.length = 0;
    node.miner.addAddress(await wallet.receiveAddress());

    const destinations = [];
    for (let i = 0; i < 5; i++)
      destinations.push((await wallet.createReceive()).getAddress());

    const attempt = await node.miner.createBlock();
    assert.strictEqual(attempt.height, 1);
    assert.strictEqual(attempt.claims.length, 0);
    assert.strictEqual(attempt.airdrops.length, 0);

    const subsidy = consensus.getReward(attempt.height, attempt.interval);
    const operatorFees = attempt.fees;
    assert.strictEqual(attempt.getReward(), subsidy + operatorFees);

    // Four work tickets include a duplicate destination; two service tickets
    // exercise the class ordering. Core v2 fees remain a separate final output
    // when present (this empty regtest template has no transaction fees).
    const servicePool = Math.floor(subsidy * 400 / 10000);
    const workPool = subsidy - servicePool;
    const workTickets = ticketValues(workPool, 4);
    const serviceTickets = ticketValues(servicePool, 2);
    const workWinners = [
      destinations[0],
      destinations[0],
      destinations[1],
      destinations[2]
    ];
    const serviceWinners = [destinations[3], destinations[4]];
    const combinedWork = combineTickets(workWinners, workTickets);
    const combinedService = combineTickets(serviceWinners, serviceTickets);
    const firstKey = addressKey(workWinners[0]);
    const firstWork = combinedWork.get(firstKey);
    assert(firstWork, 'first ticket destination was not retained');

    const outputs = [toOutput(firstWork.address, firstWork.value)];
    for (const [key, payment] of sortedPayments(combinedWork)) {
      if (key !== firstKey)
        outputs.push(toOutput(payment.address, payment.value));
    }
    for (const [, payment] of sortedPayments(combinedService))
      outputs.push(toOutput(payment.address, payment.value));
    if (operatorFees > 0)
      outputs.push(toOutput(destinations[0], operatorFees));

    attempt.coinbase.outputs = outputs;
    attempt.coinbase.refresh();
    refreshAttemptRoots(attempt);

    assert.strictEqual(attempt.coinbase.getOutputValue(), attempt.getReward());
    assert.strictEqual(outputs.length, 5);
    assert(outputs[0].address.equals(destinations[0]));
    assert.strictEqual(outputs[0].value, workTickets[0] + workTickets[1]);
    assert(outputs.slice(1, 3).every(output =>
      workWinners.slice(2).some(address => output.address.equals(address))));
    assert(outputs.slice(3).every(output =>
      serviceWinners.some(address => output.address.equals(address))));

    // Exercise the exact unmodified contextual body path before PoW.
    await node.chain.verifyBlock(attempt.toBlock());

    const extraNonce = Buffer.alloc(consensus.NONCE_SIZE, 0x5a);
    const mask = Buffer.alloc(32, 0);
    const raw = attempt.getHeader(0, attempt.time, extraNonce, mask);
    const [nonce, solved] = mine(raw, attempt.target, 1_000_000);
    assert(solved, 'failed to solve regtest payout block');
    const proof = attempt.getProof(nonce, attempt.time, extraNonce, mask);
    assert(proof.verify(attempt.target));
    const block = attempt.commit(proof);
    assert(block.verify(), 'generated payout block failed hsd non-contextual checks');

    const entry = await node.chain.add(block);
    assert(entry, 'unmodified hsd rejected generated payout block');
    assert.strictEqual(node.chain.height, 1);
    assert(node.chain.tip.hash.equals(block.hash()));

    const independentAudit = await runIndependentStaticPayoutAudit(
      node,
      destinations[0],
      hsd
    );

    console.log(JSON.stringify({
      status: 'hsd-payout-accepted',
      height: 1,
      block_hash: block.hash().toString('hex'),
      subsidy,
      operator_fees: operatorFees,
      work_pool: workPool,
      service_pool: servicePool,
      work_ticket_count: workTickets.length,
      service_ticket_count: serviceTickets.length,
      serialized_output_count: outputs.length,
      duplicate_work_winners_combined: true,
      independent_static_payout_audit: independentAudit,
      coinbase_output_value: block.txs[0].getOutputValue(),
      coinbase_base_size: block.txs[0].getBaseSize(),
      coinbase_weight: block.txs[0].getWeight()
    }, null, 2));
  } finally {
    if (node.opened)
      await node.close();
  }
}

async function runIndependentStaticPayoutAudit(node, destination, hsdRoot) {
  const first = ed25519Key(0x71);
  const second = ed25519Key(0x72);
  const members = [first, second].sort((left, right) =>
    Buffer.compare(left.publicKey, right.publicKey));
  const rosterId = domainHash('meshmine/committee-roster/v2', Buffer.concat([
    u16(2), Buffer.from([2]), u16(4), u64(0), u16(2),
    ...members.map(member => member.publicKey)
  ]));
  const bucketId = BLAKE2b.digest(Buffer.from('meshmine-independent-work-bucket'));
  const closeId = BLAKE2b.digest(Buffer.from('meshmine-independent-session-close'));
  const oneWork = encodeU512(1n);
  const snapshotUnsigned = Buffer.concat([
    u16(2), Buffer.from([2]), u64(0), Buffer.alloc(32), closeId, closeId,
    u32(0), oneWork, oneWork,
    vector([Buffer.concat([
      bucketId,
      first.publicKey,
      Buffer.from([destination.version]),
      variable(destination.hash),
      oneWork
    ])]),
    vector([]),
    BLAKE2b.digest(closeId),
    BLAKE2b.digest(Buffer.alloc(0)),
    rosterId
  ]);
  const snapshotId = domainHash('meshmine/payout-snapshot/v2', snapshotUnsigned);
  const snapshot = Buffer.concat([
    snapshotUnsigned,
    certificateSet(members, 2, 'meshmine/payout-snapshot/v2', snapshotId)
  ]);

  const entropyHash = node.chain.tip.hash;
  const priorBeacon = Buffer.alloc(32, 0x51);
  const planSeed = domainHash('meshmine/payout-plan/v2', Buffer.concat([
    snapshotId,
    entropyHash,
    priorBeacon
  ]));
  // A single unit-weight bucket accepts the first 512-bit draw and is always
  // selected. The transcript still exercises the exact counter encoding.
  const transcriptHash = domainHash('meshmine/payout-transcript/v2', Buffer.concat([
    planSeed,
    varint(1),
    u64(0),
    varint(0),
    bucketId
  ]));
  const planUnsigned = Buffer.concat([
    u16(2), Buffer.from([2]), u64(0), snapshotId, u32(1), u16(1),
    vector([entropyHash]), priorBeacon, planSeed, u16(1), u16(0),
    vector([bucketId]), vector([]), transcriptHash
  ]);
  const planId = domainHash('meshmine/payout-plan/v2', planUnsigned);
  const plan = Buffer.concat([
    planUnsigned,
    certificateSet(members, 2, 'meshmine/payout-plan/v2', planId)
  ]);

  const attempt = await node.miner.createBlock();
  assert.strictEqual(attempt.height, 2);
  attempt.coinbaseFlags = encodeCoinbaseCommitment({
    protocolVersion: 2,
    networkId: 2,
    templateId: BLAKE2b.digest(Buffer.from('meshmine-independent-template')),
    snapshotId,
    planId,
    planSequence: 0,
    operatorKeyHash: BLAKE2b.digest(first.publicKey),
    flags: 1
  });
  attempt.refresh();
  const subsidy = consensus.getReward(attempt.height, attempt.interval);
  attempt.coinbase.outputs = [toOutput(destination, subsidy)];
  attempt.coinbase.refresh();
  refreshAttemptRoots(attempt);
  await node.chain.verifyBlock(attempt.toBlock());
  const extraNonce = Buffer.alloc(consensus.NONCE_SIZE, 0x6a);
  const mask = Buffer.alloc(32, 0);
  const raw = attempt.getHeader(0, attempt.time, extraNonce, mask);
  const [nonce, solved] = mine(raw, attempt.target, 1_000_000);
  assert(solved, 'failed to solve independent-audit regtest payout block');
  const block = attempt.commit(attempt.getProof(nonce, attempt.time, extraNonce, mask));
  const entry = await node.chain.add(block);
  assert(entry && entry.height === 2);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'meshmine-payout-audit-'));
  try {
    const files = {
      snapshot: path.join(directory, 'snapshot.bin'),
      plan: path.join(directory, 'plan.bin'),
      roster: path.join(directory, 'settlement.json'),
      profile: path.join(directory, 'payout-profile.json'),
      block: path.join(directory, 'block.bin')
    };
    fs.writeFileSync(files.snapshot, snapshot);
    fs.writeFileSync(files.plan, plan);
    fs.writeFileSync(files.roster, `${JSON.stringify({
      protocol_version: 2,
      network_id: 2,
      role: 'settlement',
      epoch: 0,
      threshold: 2,
      members: members.map(member => member.publicKey.toString('hex'))
    })}\n`);
    fs.writeFileSync(files.profile, `${JSON.stringify({
      protocol_version: 2,
      network_id: 2,
      work_ticket_count: 1,
      service_ticket_count: 0,
      service_basis_points: 0,
      maximum_service_basis_points: 600,
      minimum_ticket_value: 1,
      maximum_coinbase_outputs: 16,
      maximum_entropy_blocks: 8,
      snapshot_step_work: oneWork.toString('hex'),
      pplns_window_work: oneWork.toString('hex'),
      entropy_delay_blocks: 1,
      entropy_block_count: 1,
      prior_beacon: priorBeacon.toString('hex')
    })}\n`);
    fs.writeFileSync(files.block, block.encode());
    const result = spawnSync(process.execPath, [
      path.join(__dirname, 'verify-payout-artifacts.js'),
      '--snapshot', files.snapshot,
      '--plan', files.plan,
      '--settlement-roster', files.roster,
      '--payout-profile', files.profile,
      '--skip-canonical-entropy',
      '--hsd', hsdRoot,
      '--block-height', '2',
      '--block-file', files.block,
      '--network', 'regtest'
    ], {
      env: {...process.env, NODE_BACKEND: 'js', HSD_DIR: hsdRoot},
      encoding: 'utf8',
      maxBuffer: 1024 * 1024
    });
    assert.strictEqual(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.strictEqual(report.valid, true);
    assert.strictEqual(report.coinbase_outputs_checked, true);
    return {
      block_height: 2,
      block_hash: block.hash().toString('hex'),
      snapshot_id: snapshotId.toString('hex'),
      plan_id: planId.toString('hex'),
      coinbase_outputs_checked: report.coinbase_outputs_checked
    };
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
}

function ed25519Key(seedByte) {
  const privateKey = require('node:crypto').createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.alloc(32, seedByte)
    ]),
    format: 'der',
    type: 'pkcs8'
  });
  const publicKey = require('node:crypto').createPublicKey(privateKey)
    .export({format: 'der', type: 'spki'})
    .subarray(-32);
  return {privateKey, publicKey};
}

function certificateSet(members, networkId, domain, objectId) {
  const signatures = members.map(member => Buffer.concat([
    member.publicKey,
    variable(crypto.sign(
      null,
      signatureMessage(networkId, domain, objectId),
      member.privateKey
    ))
  ]));
  return Buffer.concat([u16(1), vector(signatures)]);
}

function encodeU512(value) {
  const out = Buffer.alloc(64);
  const encoded = Buffer.from(value.toString(16).padStart(2, '0'), 'hex');
  encoded.copy(out, out.length - encoded.length);
  return out;
}

function encodeCoinbaseCommitment(value) {
  return Buffer.concat([
    Buffer.from('HNSM', 'ascii'),
    u16(value.protocolVersion),
    Buffer.from([value.networkId]),
    value.templateId,
    value.snapshotId,
    value.planId,
    u64(value.planSequence),
    value.operatorKeyHash,
    u32(value.flags)
  ]);
}

function domainHash(domain, body) {
  return BLAKE2b.digest(Buffer.concat([
    variable(Buffer.from(domain, 'ascii')),
    body
  ]));
}

function ticketValues(pool, count) {
  assert(Number.isSafeInteger(pool) && pool >= 0);
  assert(Number.isSafeInteger(count) && count > 0);
  const base = Math.floor(pool / count);
  const remainder = pool % count;
  return Array.from({length: count}, (_, index) =>
    base + (index < remainder ? 1 : 0));
}

function addressKey(address) {
  return `${address.version}:${address.hash.toString('hex')}`;
}

function combineTickets(winners, values) {
  const combined = new Map();
  for (let i = 0; i < winners.length; i++) {
    const address = winners[i];
    const key = addressKey(address);
    const payment = combined.get(key) || {address, value: 0};
    payment.value += values[i];
    assert(Number.isSafeInteger(payment.value));
    combined.set(key, payment);
  }
  return combined;
}

function sortedPayments(payments) {
  return [...payments.entries()].sort((left, right) =>
    left[1].address.compare(right[1].address));
}

function toOutput(address, value) {
  const output = new Output();
  output.address = address.clone();
  output.value = value;
  return output;
}

function refreshAttemptRoots(attempt) {
  const txs = [attempt.coinbase, ...attempt.items.map(item => item.tx)];
  attempt.merkleRoot = merkle.createRoot(BLAKE2b, txs.map(tx => tx.hash()));
  attempt.witnessRoot = merkle.createRoot(
    BLAKE2b,
    txs.map(tx => tx.witnessHash())
  );
}

function vector(values, encode = value => value) {
  return Buffer.concat([varint(values.length), ...values.map(encode)]);
}

function variable(value) {
  return Buffer.concat([varint(value.length), value]);
}

function varint(input) {
  let value = BigInt(input);
  const out = [];
  do {
    let byte = Number(value & 0x7fn);
    value >>= 7n;
    if (value !== 0n)
      byte |= 0x80;
    out.push(byte);
  } while (value !== 0n);
  return Buffer.from(out);
}

function u16(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16LE(value);
  return out;
}

function u32(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(value);
  return out;
}

function u64(value) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(BigInt(value));
  return out;
}

function resolveHsd() {
  if (process.env.HSD_DIR)
    return path.resolve(process.env.HSD_DIR);
  try {
    return path.dirname(require.resolve('hsd/package.json'));
  } catch (error) {
    throw new Error('hsd was not found; set HSD_DIR or run npm install', {cause: error});
  }
}

main().catch(error => {
  console.error(error.stack || error.message);
  process.exit(1);
});
