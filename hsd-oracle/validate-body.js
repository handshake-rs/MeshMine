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
const Input = require(path.join(hsd, 'lib/primitives/input'));
const consensus = require(path.join(hsd, 'lib/protocol/consensus'));
const walletPlugin = require(path.join(hsd, 'lib/wallet/plugin'));
const BLAKE2b = require(require.resolve('bcrypto/lib/blake2b', {paths: [hsd]}));

async function main() {
  const node = new FullNode({
    memory: true,
    network: 'regtest',
    apiKey: 'meshmine-body-regtest',
    workers: false,
    plugins: [walletPlugin]
  });

  try {
    await node.open();
    const wallet = await node.require('walletdb').wdb.create();
    node.miner.addresses.length = 0;
    node.miner.addAddress(await wallet.receiveAddress());

    const attempt = await node.miner.createBlock();
    const operatorPrivateKey = crypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        fill(32, 0x21)
      ]),
      format: 'der',
      type: 'pkcs8'
    });
    const operatorKey = crypto.createPublicKey(operatorPrivateKey)
      .export({format: 'der', type: 'spki'})
      .subarray(-32);
    const templateBytes = encodeTemplateCore({
      protocolVersion: 2,
      networkId: 2,
      parentHash: attempt.prevBlock,
      parentHeight: attempt.height - 1,
      operatorKey,
      operatorFeeBucketId: fill(32, 0x22),
      snapshotId: Buffer.alloc(32),
      planId: Buffer.alloc(32),
      planSequence: 0,
      txids: attempt.items.map(item => item.tx.hash()),
      claimIds: [],
      airdropIds: [],
      blockVersion: attempt.version,
      bits: attempt.bits,
      minimumNtime: attempt.time,
      policyCommitment: BLAKE2b.digest(Buffer.from('wp4-regtest-policy'))
    });
    const templateId = domainHash('meshmine/template-core/v2', templateBytes);
    const commitment = encodeCoinbaseCommitment({
      protocolVersion: 2,
      networkId: 2,
      templateId,
      snapshotId: Buffer.alloc(32),
      planId: Buffer.alloc(32),
      planSequence: 0,
      operatorKeyHash: BLAKE2b.digest(operatorKey),
      flags: 1
    });
    assert.strictEqual(commitment.length, 147);

    attempt.coinbaseFlags = commitment;
    attempt.refresh();
    const block = attempt.toBlock();
    assert(block.txs[0].inputs[0].witness.getData(0).equals(commitment));

    // This is hsd's full contextual path with only VERIFY_POW removed.
    await node.chain.verifyBlock(block);

    const coinbaseRaw = block.txs[0].encode();
    const transactionsRaw = block.txs.slice(1).map(tx => tx.encode());
    const validationHash = validationResultHash(
      2,
      templateId,
      coinbaseRaw,
      transactionsRaw
    );
    const bodyUnsigned = encodeBodyPackageUnsigned({
      protocolVersion: 2,
      networkId: 2,
      templateBytes,
      templateId,
      coinbaseRaw,
      transactionsRaw,
      merkleRoot: block.merkleRoot,
      witnessRoot: block.witnessRoot,
      treeRoot: block.treeRoot,
      reservedRoot: block.reservedRoot,
      blockWeight: block.getWeight(),
      blockSigops: 0,
      minerSubsidy: consensus.getReward(attempt.height, attempt.interval),
      ordinaryTransactionFees: attempt.fees,
      claimAirdropPrincipal: 0,
      claimAirdropFees: 0,
      operatorFeeValue: attempt.fees,
      workServiceSubsidyValue: consensus.getReward(attempt.height, attempt.interval),
      validationHash
    });
    const bodyId = domainHash('meshmine/body-package/v2', bodyUnsigned);
    const operatorSignature = crypto.sign(
      null,
      signatureMessage(2, 'meshmine/body-package/v2', bodyId),
      operatorPrivateKey
    );
    const bodyCanonical = Buffer.concat([bodyUnsigned, variable(operatorSignature)]);
    const independentBodyReport = runIndependentBodyVerifier(
      bodyCanonical,
      block.encode(),
      hsd
    );
    assert.strictEqual(independentBodyReport.valid, true);
    assert.strictEqual(independentBodyReport.body_package_id, bodyId.toString('hex'));
    assert.strictEqual(independentBodyReport.candidate_block_checked, true);

    const firstMask = fill(32, 0x31);
    const secondMask = fill(32, 0x32);
    const first = attempt.commit(attempt.getProof(1, attempt.time, fill(24, 1), firstMask));
    const second = attempt.commit(attempt.getProof(2, attempt.time, fill(24, 2), secondMask));
    assert(!first.mask.equals(second.mask));
    assert(first.merkleRoot.equals(second.merkleRoot));
    assert(first.witnessRoot.equals(second.witnessRoot));
    assert.deepStrictEqual(
      first.txs.map(tx => tx.encode()),
      second.txs.map(tx => tx.encode())
    );
    await node.chain.verifyBlock(first);
    await node.chain.verifyBlock(second);

    const invalidCovenant = block.clone();
    invalidCovenant.txs[0].outputs[0].covenant.setOpen(
      fill(32, 0x41),
      Buffer.from('invalid-covenant')
    );
    refreshBodyRoots(invalidCovenant);
    const covenantReason = await rejectionReason(node, invalidCovenant);

    const invalidAirdrop = block.clone();
    addMalformedProof(invalidAirdrop, false);
    const airdropReason = await rejectionReason(node, invalidAirdrop);

    const invalidClaim = block.clone();
    addMalformedProof(invalidClaim, true);
    const claimReason = await rejectionReason(node, invalidClaim);

    assert([
      'bad-txns-covenants',
      'bad-claim-notreserved',
      'bad-open-name'
    ].includes(covenantReason), covenantReason);
    assert([
      'bad-txns-covenants',
      'bad-airdrop-format',
      'bad-airdrop-sanity'
    ].includes(airdropReason), airdropReason);
    assert([
      'bad-txns-covenants',
      'bad-dnssec-format',
      'bad-claim-notreserved'
    ].includes(claimReason), claimReason);

    console.log(JSON.stringify({
      status: 'hsd-context-valid',
      template_core_id: templateId.toString('hex'),
      body_package_id: bodyId.toString('hex'),
      commitment_size: commitment.length,
      validation_result_hash: validationHash.toString('hex'),
      independent_candidate_body_checked: true,
      body_reused_across_masks: true,
      invalid_covenant_rejected: covenantReason,
      invalid_airdrop_rejected: airdropReason,
      invalid_claim_rejected: claimReason
    }, null, 2));
  } finally {
    if (node.opened)
      await node.close();
  }
}

function encodeBodyPackageUnsigned(value) {
  return Buffer.concat([
    u16(value.protocolVersion),
    Buffer.from([value.networkId]),
    value.templateBytes,
    value.templateId,
    variable(value.coinbaseRaw),
    vector(value.transactionsRaw, variable),
    value.merkleRoot,
    value.witnessRoot,
    value.treeRoot,
    value.reservedRoot,
    u32(value.blockWeight),
    u32(value.blockSigops),
    u64(value.minerSubsidy),
    u64(value.ordinaryTransactionFees),
    u64(value.claimAirdropPrincipal),
    u64(value.claimAirdropFees),
    u64(value.operatorFeeValue),
    u64(value.workServiceSubsidyValue),
    value.validationHash
  ]);
}

function runIndependentBodyVerifier(body, block, hsdRoot) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'meshmine-body-audit-'));
  const bodyPath = path.join(directory, 'body.bin');
  const blockPath = path.join(directory, 'candidate-block.bin');
  try {
    fs.writeFileSync(bodyPath, body);
    fs.writeFileSync(blockPath, block);
    const result = spawnSync(process.execPath, [
      path.join(__dirname, 'verify-body-artifacts.js'),
      '--body', bodyPath,
      '--candidate-block', blockPath,
      '--hsd', hsdRoot,
      '--skip-contextual-hsd'
    ], {
      env: {...process.env, NODE_BACKEND: 'js', HSD_DIR: hsdRoot},
      encoding: 'utf8',
      maxBuffer: 1024 * 1024
    });
    assert.strictEqual(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
}

function addMalformedProof(block, claim) {
  const coinbase = block.txs[0];
  const input = new Input();
  input.witness.items.push(Buffer.from([0xff, 0x00, 0x01]));
  coinbase.inputs.push(input);
  const output = coinbase.outputs[0].clone();
  output.value = 0;
  if (claim) {
    output.covenant.setClaim(
      fill(32, 0x51),
      1,
      Buffer.from('invalid-claim'),
      0,
      fill(32, 0x52),
      1
    );
  } else {
    output.covenant.setNone();
  }
  coinbase.outputs.push(output);
  refreshBodyRoots(block);
}

function refreshBodyRoots(block) {
  block.txs[0].refresh();
  block.merkleRoot = block.createMerkleRoot();
  block.witnessRoot = block.createWitnessRoot();
  block.refresh();
}

async function rejectionReason(node, block) {
  try {
    await node.chain.verifyBlock(block);
  } catch (error) {
    assert.strictEqual(error.type, 'VerifyError');
    return error.reason;
  }
  assert.fail('invalid body unexpectedly passed hsd contextual validation');
}

function encodeTemplateCore(value) {
  return Buffer.concat([
    u16(value.protocolVersion),
    Buffer.from([value.networkId]),
    value.parentHash,
    u32(value.parentHeight),
    value.operatorKey,
    value.operatorFeeBucketId,
    value.snapshotId,
    value.planId,
    u64(value.planSequence),
    vector(value.txids),
    vector(value.claimIds),
    vector(value.airdropIds),
    u32(value.blockVersion),
    u32(value.bits),
    u64(value.minimumNtime),
    value.policyCommitment
  ]);
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

function validationResultHash(networkId, templateId, coinbase, transactions) {
  const body = Buffer.concat([
    u16(2),
    Buffer.from([networkId]),
    templateId,
    variable(coinbase),
    vector(transactions, variable)
  ]);
  return domainHash('meshmine/hsd-validation-result/v2', body);
}

function domainHash(domain, body) {
  return BLAKE2b.digest(Buffer.concat([
    variable(Buffer.from(domain, 'ascii')),
    body
  ]));
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

function fill(length, byte) {
  return Buffer.alloc(length, byte);
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

if (require.main === module) {
  main().catch(error => {
    console.error(error.stack || error.message);
    process.exit(1);
  });
}

module.exports = {
  encodeCoinbaseCommitment,
  encodeTemplateCore,
  validationResultHash
};
