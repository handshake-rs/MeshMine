#!/usr/bin/env node
'use strict';

const path = require('node:path');

const {
  blake256,
  decodeBlockBodyPackage,
  domainHash,
  readBounded,
  resolveHsd,
  u8,
  u16,
  varint,
  variable,
  verifyDirectSignature
} = require('./core-v2-audit');

const MAX_BLOCK_BYTES = 4 * 1024 * 1024 + 4096;
const COMMITMENT_SIZE = 147;
const MAGIC = Buffer.from('HNSM', 'ascii');

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const body = decodeBlockBodyPackage(readBounded(options.body));
  verifyDirectSignature(body, body.template.operatorPubkey, body.operatorSignature);
  verifyValidationCommitment(body);

  let contextualChecked = false;
  let candidateChecked = false;
  let blockHash = null;
  if (!options.bodyOnly) {
    if (!options.candidateBlock || !options.hsd)
      throw new Error('--candidate-block and --hsd are required without --body-only');
    const raw = readBounded(options.candidateBlock, MAX_BLOCK_BYTES);
    const hsdRoot = resolveHsd(options.hsd);
    const Block = require(path.join(hsdRoot, 'lib/primitives/block'));
    const block = Block.fromRaw(raw);
    if (!block.encode().equals(raw))
      throw new Error('candidate block is not canonically encoded by hsd');
    verifyCandidate(body, block);
    candidateChecked = true;
    if (!options.skipContextualHsd) {
      await verifyContextualHsd(hsdRoot, raw);
      contextualChecked = true;
    }
    blockHash = block.hash().toString('hex');
  }

  process.stdout.write(`${JSON.stringify({
    valid: true,
    verifier: 'meshmine-independent-js-body-v2',
    network_id: body.networkId,
    template_core_id: body.template.id.toString('hex'),
    body_package_id: body.id.toString('hex'),
    block_hash: blockHash,
    candidate_block_checked: candidateChecked,
    contextual_hsd_checked: contextualChecked
  })}\n`);
}

function verifyValidationCommitment(body) {
  const subject = Buffer.concat([
    u16(2),
    u8(body.networkId),
    body.template.id,
    variable(body.coinbaseRaw),
    varint(body.transactionsRaw.length),
    ...body.transactionsRaw.map(variable)
  ]);
  const expected = domainHash('meshmine/hsd-validation-result/v2', subject);
  if (!body.hsdValidationResultHash.equals(expected))
    throw new Error('body hsd validation-result commitment is inconsistent');
}

function verifyCandidate(body, block) {
  const template = body.template;
  if (!block.prevBlock.equals(template.parentHash)
      || block.version !== template.blockVersion
      || block.bits !== template.bits
      || BigInt(block.time) < template.minimumNtime
      || !block.merkleRoot.equals(body.merkleRoot)
      || !block.witnessRoot.equals(body.witnessRoot)
      || !block.treeRoot.equals(body.treeRoot)
      || !block.reservedRoot.equals(body.reservedRoot)) {
    throw new Error('candidate header differs from its body and TemplateCore');
  }
  if (block.getWeight() !== body.blockWeight)
    throw new Error('candidate block weight differs from the body package');
  if (block.txs.length !== body.transactionsRaw.length + 1
      || !block.txs[0].encode().equals(body.coinbaseRaw)) {
    throw new Error('candidate coinbase or transaction count differs from the body package');
  }
  for (let index = 0; index < body.transactionsRaw.length; index++) {
    const transaction = block.txs[index + 1];
    if (!transaction.encode().equals(body.transactionsRaw[index]))
      throw new Error(`candidate transaction bytes differ at index ${index}`);
    if (!transaction.hash().equals(template.transactionIds[index]))
      throw new Error(`candidate transaction ID differs at index ${index}`);
  }
  if (template.transactionIds.length !== body.transactionsRaw.length)
    throw new Error('TemplateCore transaction count differs from the body package');
  verifyCoinbaseCommitment(body, block);
}

function verifyCoinbaseCommitment(body, block) {
  if (block.txs.length === 0 || block.txs[0].inputs.length === 0)
    throw new Error('candidate block has no coinbase witness');
  const candidates = block.txs[0].inputs[0].witness.items.filter(item =>
    item.length === COMMITMENT_SIZE && item.subarray(0, 4).equals(MAGIC));
  if (candidates.length !== 1)
    throw new Error('candidate coinbase does not contain exactly one HNSM commitment');
  const commitment = decodeCommitment(candidates[0]);
  if (commitment.protocolVersion !== body.protocolVersion
      || commitment.networkId !== body.networkId
      || !commitment.templateId.equals(body.template.id)
      || !commitment.snapshotId.equals(body.template.payoutSnapshotId)
      || !commitment.planId.equals(body.template.payoutPlanId)
      || commitment.planSequence !== body.template.planSequence
      || !commitment.operatorKeyHash.equals(blake256(body.template.operatorPubkey))) {
    throw new Error('candidate HNSM commitment differs from TemplateCore');
  }
}

function decodeCommitment(bytes) {
  let offset = 4;
  const take = size => {
    const value = Buffer.from(bytes.subarray(offset, offset + size));
    offset += size;
    return value;
  };
  const protocolVersion = take(2).readUInt16LE();
  const networkId = take(1)[0];
  const templateId = take(32);
  const snapshotId = take(32);
  const planId = take(32);
  const planSequence = take(8).readBigUInt64LE();
  const operatorKeyHash = take(32);
  const flags = take(4).readUInt32LE();
  if (offset !== COMMITMENT_SIZE)
    throw new Error('HNSM commitment length is inconsistent');
  return {
    protocolVersion,
    networkId,
    templateId,
    snapshotId,
    planId,
    planSequence,
    operatorKeyHash,
    flags
  };
}

async function verifyContextualHsd(hsdRoot, raw) {
  const Config = require(path.join(hsdRoot, 'node_modules/bcfg'));
  const {NodeClient} = require(path.join(hsdRoot, 'lib/client'));
  const ports = {main: 12037, testnet: 13037, regtest: 14037, simnet: 15037};
  const config = new Config('hsd', {
    suffix: 'network',
    fallback: 'main',
    alias: {
      n: 'network', u: 'url', uri: 'url', k: 'apikey', s: 'ssl',
      h: 'httphost', p: 'httpport'
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
  const reason = await client.execute('verifyblock', [raw.toString('hex')]);
  if (reason !== null)
    throw new Error(`unmodified hsd contextually rejected the candidate body: ${reason}`);
}

function parseArgs(args) {
  const options = {bodyOnly: false, skipContextualHsd: false};
  const values = new Map([
    ['--body', 'body'],
    ['--candidate-block', 'candidateBlock'],
    ['--hsd', 'hsd']
  ]);
  for (let index = 0; index < args.length; index++) {
    const name = args[index];
    if (name === '--body-only') {
      if (options.bodyOnly)
        throw new Error('duplicate --body-only');
      options.bodyOnly = true;
      continue;
    }
    if (name === '--skip-contextual-hsd') {
      if (options.skipContextualHsd)
        throw new Error('duplicate --skip-contextual-hsd');
      options.skipContextualHsd = true;
      continue;
    }
    const field = values.get(name);
    if (!field || options[field] !== undefined || index + 1 >= args.length)
      throw new Error(`unknown, duplicate, or valueless argument: ${name}`);
    options[field] = args[++index];
  }
  if (!options.body)
    throw new Error('missing required body verifier argument: body');
  if (options.bodyOnly && options.skipContextualHsd)
    throw new Error('--body-only and --skip-contextual-hsd are mutually exclusive');
  return options;
}

main().catch(error => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
