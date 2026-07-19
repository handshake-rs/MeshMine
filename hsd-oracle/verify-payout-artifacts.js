#!/usr/bin/env node
'use strict';

const path = require('node:path');

const {
  blake512,
  bytesToBigInt,
  decodePayoutPlan,
  decodePayoutSnapshot,
  domainHash,
  fixedHex,
  loadStaticRoster,
  readBounded,
  readJson,
  requireObjectKeys,
  safeInteger,
  u8,
  u16,
  u64,
  variable,
  varint,
  verifyCertificate
} = require('./core-v2-audit');

const PLAN_SEED_DOMAIN = 'meshmine/payout-plan/v2';
const TICKET_DOMAIN = 'meshmine/payout-ticket/v2';
const TRANSCRIPT_DOMAIN = 'meshmine/payout-transcript/v2';
const DRAW_SPACE = 1n << 512n;
const MAX_REJECTION_COUNTER = 1000000n;

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const snapshot = decodePayoutSnapshot(readBounded(options.snapshot));
  const plan = decodePayoutPlan(readBounded(options.plan));
  if (snapshot.networkId !== plan.networkId)
    throw new Error('snapshot and plan networks differ');

  const roster = loadStaticRoster(
    options.settlementRoster,
    snapshot.networkId,
    'settlement'
  );
  const profile = loadProfile(options.payoutProfile, snapshot.networkId);

  if (!snapshot.settlementCommitteeId.equals(roster.id))
    throw new Error('snapshot settlement committee ID does not match the roster');
  verifyCertificate(snapshot, roster);
  verifyCertificate(plan, roster);
  verifySnapshot(snapshot, profile);
  const expected = verifyPlan(snapshot, plan, profile);

  let coinbaseChecked = false;
  let canonicalBlockChecked = false;
  if (!options.skipCanonicalEntropy) {
    if (!options.hsd)
      throw new Error('--hsd is required unless --skip-canonical-entropy is explicit');
    await verifyCanonicalEntropy(options.hsd, plan);
  }
  if (options.blockFile) {
    if (!options.hsd || options.blockHeight === undefined || !options.network)
      throw new Error('--block-file requires --hsd, --block-height, and --network');
    const hsdRoot = path.resolve(options.hsd);
    const Block = require(path.join(hsdRoot, 'lib/primitives/block'));
    const raw = readBounded(options.blockFile, 4 * 1024 * 1024 + 4096);
    const block = Block.fromRaw(raw);
    if (!block.encode().equals(raw))
      throw new Error('offline payout block is not canonically encoded by hsd');
    verifyPayoutBlockObject(
      hsdRoot,
      options.network,
      options.blockHeight,
      block,
      snapshot,
      plan,
      profile
    );
    coinbaseChecked = true;
  } else if (options.blockHeight !== undefined) {
    if (!options.hsd)
      throw new Error('--hsd is required when --block-height is supplied');
    await verifyPayoutBlock(
      options.hsd,
      options.blockHeight,
      snapshot,
      plan,
      profile
    );
    coinbaseChecked = true;
    canonicalBlockChecked = true;
  }

  process.stdout.write(`${JSON.stringify({
    valid: true,
    verifier: 'meshmine-independent-js-payout-v2',
    network_id: snapshot.networkId,
    snapshot_sequence: snapshot.snapshotSequence.toString(10),
    snapshot_id: snapshot.id.toString('hex'),
    plan_id: plan.id.toString('hex'),
    work_tickets: expected.workWinners.length,
    service_tickets: expected.serviceWinners.length,
    canonical_entropy_checked: !options.skipCanonicalEntropy,
    coinbase_outputs_checked: coinbaseChecked,
    canonical_payout_block_checked: canonicalBlockChecked
  })}\n`);
}

function verifySnapshot(snapshot, profile) {
  if (!snapshot.workWindowTarget.equals(profile.pplnsWindowWork))
    throw new Error('snapshot PPLNS work target differs from the strict profile');
  if (snapshot.workBuckets.length === 0)
    throw new Error('snapshot has no credited work buckets');
  if (profile.serviceTicketCount !== 0 || profile.serviceBasisPoints !== 0
      || snapshot.serviceBuckets.length !== 0) {
    throw new Error('the static independent verifier accepts only work-only snapshots');
  }
  let work = 0n;
  for (const bucket of snapshot.workBuckets) {
    verifyAddress(bucket.addressVersion, bucket.addressHash);
    work += bytesToBigInt(bucket.weight);
  }
  if (work === 0n || work >= DRAW_SPACE
      || work !== bytesToBigInt(snapshot.actualWorkInWindow)) {
    throw new Error('snapshot actual work does not equal its exact bucket sum');
  }
}

function verifyPlan(snapshot, plan, profile) {
  if (!plan.snapshotId.equals(snapshot.id)
      || plan.planSequence !== snapshot.snapshotSequence) {
    throw new Error('plan does not identify the supplied snapshot and sequence');
  }
  const expectedStart = snapshot.closeAnchorHeight + profile.entropyDelayBlocks;
  if (!Number.isSafeInteger(expectedStart) || expectedStart > 0xffffffff
      || plan.entropyAnchorStart !== expectedStart
      || plan.entropyAnchorCount !== profile.entropyBlockCount
      || plan.entropyHashes.length !== profile.entropyBlockCount
      || plan.entropyHashes.length > profile.maximumEntropyBlocks
      || !plan.priorBeacon.equals(profile.priorBeacon)) {
    throw new Error('plan entropy delay, count, bound, or beacon differs from policy');
  }
  if (plan.workTicketCount !== profile.workTicketCount
      || plan.serviceTicketCount !== profile.serviceTicketCount
      || plan.workWinners.length !== profile.workTicketCount
      || plan.serviceWinners.length !== profile.serviceTicketCount) {
    throw new Error('plan ticket counts differ from the strict profile');
  }

  const seedBody = Buffer.concat([
    snapshot.id,
    ...plan.entropyHashes,
    profile.priorBeacon
  ]);
  const planSeed = domainHash(PLAN_SEED_DOMAIN, seedBody);
  if (!plan.planSeed.equals(planSeed))
    throw new Error('plan seed does not match the snapshot, entropy, and beacon');

  const work = selectWeighted(
    planSeed,
    0,
    profile.workTicketCount,
    snapshot.workBuckets
  );
  const service = profile.serviceTicketCount === 0
    ? {winners: [], counters: []}
    : selectWeighted(
      planSeed,
      1,
      profile.serviceTicketCount,
      snapshot.serviceBuckets
    );
  requireBufferVectorEqual(plan.workWinners, work.winners, 'work winners');
  requireBufferVectorEqual(plan.serviceWinners, service.winners, 'service winners');

  const transcript = Buffer.concat([
    planSeed,
    varint(work.counters.length),
    ...work.counters.map(u64),
    varint(service.counters.length),
    ...service.counters.map(u64),
    ...work.winners,
    ...service.winners
  ]);
  const transcriptHash = domainHash(TRANSCRIPT_DOMAIN, transcript);
  if (!plan.selectionTranscriptHash.equals(transcriptHash))
    throw new Error('plan selection transcript does not match deterministic draws');
  return {workWinners: work.winners, serviceWinners: service.winners};
}

function selectWeighted(seed, ticketClass, count, buckets) {
  if (count === 0)
    return {winners: [], counters: []};
  if (buckets.length === 0)
    throw new Error('nonempty ticket class has no buckets');
  const weights = buckets.map(bucket => bytesToBigInt(bucket.weight));
  const total = weights.reduce((sum, weight) => sum + weight, 0n);
  if (total <= 0n || total >= DRAW_SPACE)
    throw new Error('ticket class total weight is outside the 512-bit draw space');
  const limit = (DRAW_SPACE / total) * total;
  const cumulative = [];
  let running = 0n;
  for (const weight of weights) {
    running += weight;
    cumulative.push(running);
  }
  const winners = [];
  const counters = [];
  for (let ticket = 0; ticket < count; ticket++) {
    let counter = 0n;
    let residue;
    for (;;) {
      if (counter > MAX_REJECTION_COUNTER)
        throw new Error('payout rejection counter exceeds the audit resource bound');
      const candidate = blake512(Buffer.concat([
        variable(Buffer.from(TICKET_DOMAIN, 'ascii')),
        seed,
        u8(ticketClass),
        u16(ticket),
        u64(counter)
      ]));
      const number = bytesToBigInt(candidate);
      if (number < limit) {
        residue = number % total;
        break;
      }
      counter++;
    }
    let winner = 0;
    while (winner < cumulative.length && residue >= cumulative[winner])
      winner++;
    if (winner === buckets.length)
      throw new Error('weighted ticket draw has no bucket');
    winners.push(buckets[winner].bucketId);
    counters.push(counter);
  }
  return {winners, counters};
}

function loadProfile(filename, networkId) {
  const value = readJson(filename, 1024 * 1024);
  requireObjectKeys(value, [
    'protocol_version', 'network_id', 'work_ticket_count',
    'service_ticket_count', 'service_basis_points',
    'maximum_service_basis_points', 'minimum_ticket_value',
    'maximum_coinbase_outputs', 'maximum_entropy_blocks',
    'snapshot_step_work', 'pplns_window_work', 'entropy_delay_blocks',
    'entropy_block_count', 'prior_beacon'
  ], 'static payout profile');
  const integerFields = [
    ['work_ticket_count', 1, 65535],
    ['service_ticket_count', 0, 65535],
    ['service_basis_points', 0, 10000],
    ['maximum_service_basis_points', 0, 10000],
    ['minimum_ticket_value', 0, Number.MAX_SAFE_INTEGER],
    ['maximum_coinbase_outputs', 1, 65535],
    ['maximum_entropy_blocks', 1, 65535],
    ['entropy_delay_blocks', 1, 0xffffffff],
    ['entropy_block_count', 1, 65535]
  ];
  if (value.protocol_version !== 2 || value.network_id !== networkId)
    throw new Error('payout profile protocol or network differs from the artifacts');
  for (const [field, minimum, maximum] of integerFields) {
    if (!safeInteger(value[field], minimum, maximum))
      throw new Error(`payout profile ${field} is outside its bound`);
  }
  if (value.service_ticket_count !== 0 || value.service_basis_points !== 0
      || value.service_basis_points > value.maximum_service_basis_points
      || value.entropy_block_count > value.maximum_entropy_blocks) {
    throw new Error('payout profile is not the strict work-only static policy');
  }
  const snapshotStepWork = fixedHex(value.snapshot_step_work, 64, 'snapshot step work');
  const pplnsWindowWork = fixedHex(value.pplns_window_work, 64, 'PPLNS window work');
  if (bytesToBigInt(snapshotStepWork) === 0n || bytesToBigInt(pplnsWindowWork) === 0n)
    throw new Error('payout work thresholds must be nonzero');
  return {
    workTicketCount: value.work_ticket_count,
    serviceTicketCount: value.service_ticket_count,
    serviceBasisPoints: value.service_basis_points,
    maximumEntropyBlocks: value.maximum_entropy_blocks,
    minimumTicketValue: BigInt(value.minimum_ticket_value),
    maximumCoinbaseOutputs: value.maximum_coinbase_outputs,
    snapshotStepWork,
    pplnsWindowWork,
    entropyDelayBlocks: value.entropy_delay_blocks,
    entropyBlockCount: value.entropy_block_count,
    priorBeacon: fixedHex(value.prior_beacon, 32, 'prior beacon')
  };
}

function verifyAddress(version, hash) {
  if (version > 31 || hash.length < 2 || hash.length > 40
      || (version === 0 && hash.length !== 20 && hash.length !== 32)) {
    throw new Error('snapshot contains an invalid HNS payout address');
  }
}

async function verifyCanonicalEntropy(hsdRoot, plan) {
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
  for (let index = 0; index < plan.entropyHashes.length; index++) {
    const height = plan.entropyAnchorStart + index;
    const first = await client.execute('getblockhash', [height]);
    const second = await client.execute('getblockhash', [height]);
    const expected = fixedHex(first, 32, `canonical HNS hash at ${height}`);
    if (first !== second || !plan.entropyHashes[index].equals(expected))
      throw new Error(`payout entropy is noncanonical or changed at height ${height}`);
  }
}

async function verifyPayoutBlock(hsdRoot, height, snapshot, plan, profile) {
  const context = loadHsdContext(hsdRoot);
  const Block = require(path.join(hsdRoot, 'lib/primitives/block'));
  const expectedHash = await context.client.execute('getblockhash', [height]);
  const rawHex = await context.client.execute('getblock', [expectedHash, false]);
  const confirmedHash = await context.client.execute('getblockhash', [height]);
  if (expectedHash !== confirmedHash)
    throw new Error('canonical payout block changed during the bounded query');
  const block = Block.fromRaw(Buffer.from(rawHex, 'hex'));
  if (block.hash().toString('hex') !== expectedHash)
    throw new Error('hsd block decoding did not reproduce the canonical payout hash');
  verifyPayoutBlockObject(
    hsdRoot,
    context.network,
    height,
    block,
    snapshot,
    plan,
    profile
  );
}

function verifyPayoutBlockObject(
  hsdRoot,
  networkName,
  height,
  block,
  snapshot,
  plan,
  profile
) {
  const consensus = require(path.join(hsdRoot, 'lib/protocol/consensus'));
  const Network = require(path.join(hsdRoot, 'lib/protocol/network'));
  if (block.txs.length === 0 || block.txs[0].inputs.length === 0)
    throw new Error('canonical payout block has no coinbase');
  const coinbase = block.txs[0];
  const commitments = coinbase.inputs[0].witness.items.filter(item =>
    item.length === 147 && item.subarray(0, 4).equals(Buffer.from('HNSM')));
  if (commitments.length !== 1)
    throw new Error('payout coinbase does not contain exactly one HNSM commitment');
  verifyPayoutCommitment(commitments[0], snapshot, plan);

  const network = Network.get(networkName);
  const subsidy = BigInt(consensus.getReward(height, network.halvingInterval));
  const expectedOutputs = buildWorkOutputs(snapshot, plan, subsidy, profile);
  const mandatoryCount = coinbase.inputs.length - 1;
  if (coinbase.outputs.length > profile.maximumCoinbaseOutputs
      || (coinbase.outputs.length !== expectedOutputs.length + mandatoryCount
      && coinbase.outputs.length !== expectedOutputs.length + mandatoryCount + 1)) {
    throw new Error('payout coinbase output count differs from deterministic policy');
  }
  const first = coinbase.outputs[0];
  requireOutput(first, expectedOutputs[0], true, 'first work output');
  for (let index = 1; index < expectedOutputs.length; index++) {
    requireOutput(
      coinbase.outputs[mandatoryCount + index],
      expectedOutputs[index],
      true,
      `remaining work output ${index}`
    );
  }
  const optionalOperator = coinbase.outputs[mandatoryCount + expectedOutputs.length];
  if (optionalOperator)
    verifyHnsOutputAddress(optionalOperator, true, 'operator fee output');
}

function verifyPayoutCommitment(bytes, snapshot, plan) {
  let offset = 4;
  const take = size => {
    const value = Buffer.from(bytes.subarray(offset, offset + size));
    offset += size;
    return value;
  };
  const protocol = take(2).readUInt16LE();
  const network = take(1)[0];
  take(32); // TemplateCore ID is checked by the independent body verifier.
  const snapshotId = take(32);
  const planId = take(32);
  const sequence = take(8).readBigUInt64LE();
  take(32); // Operator key hash is bound to TemplateCore/body verification.
  take(4);
  if (offset !== 147 || protocol !== 2 || network !== snapshot.networkId
      || !snapshotId.equals(snapshot.id) || !planId.equals(plan.id)
      || sequence !== plan.planSequence) {
    throw new Error('payout coinbase commitment differs from the certified plan');
  }
}

function buildWorkOutputs(snapshot, plan, subsidy, profile) {
  if (profile.serviceBasisPoints !== 0 || profile.serviceTicketCount !== 0)
    throw new Error('independent static coinbase verification is work-only');
  const values = ticketValues(subsidy, profile.workTicketCount);
  if (values.length === 0 || values[values.length - 1] < profile.minimumTicketValue)
    throw new Error('payout ticket value is below the profile minimum');
  const destinations = new Map(snapshot.workBuckets.map(bucket => [
    bucket.bucketId.toString('hex'),
    {version: bucket.addressVersion, hash: bucket.addressHash, value: 0n}
  ]));
  const combined = new Map();
  for (let index = 0; index < plan.workWinners.length; index++) {
    const destination = destinations.get(plan.workWinners[index].toString('hex'));
    if (!destination)
      throw new Error('work winner has no snapshot destination');
    const key = destinationKey(destination);
    const existing = combined.get(key) || {...destination};
    existing.value += values[index];
    combined.set(key, existing);
  }
  const firstDestination = destinations.get(plan.workWinners[0].toString('hex'));
  const firstKey = destinationKey(firstDestination);
  const first = combined.get(firstKey);
  const remaining = [...combined.entries()]
    .filter(([key]) => key !== firstKey)
    .sort((left, right) => compareDestinations(left[1], right[1]))
    .map(([, output]) => output);
  const outputs = [first, ...remaining];
  if (outputs.length > profile.maximumCoinbaseOutputs)
    throw new Error('deterministic payout exceeds the profile output bound');
  return outputs;
}

function ticketValues(pool, count) {
  if (count === 0)
    return [];
  const divisor = BigInt(count);
  const base = pool / divisor;
  const remainder = pool % divisor;
  return Array.from({length: count}, (_, index) =>
    base + (BigInt(index) < remainder ? 1n : 0n));
}

function destinationKey(output) {
  return `${output.version.toString(16).padStart(2, '0')}:${output.hash.toString('hex')}`;
}

function compareDestinations(left, right) {
  if (left.version !== right.version)
    return left.version - right.version;
  return Buffer.compare(left.hash, right.hash);
}

function requireOutput(actual, expected, ordinary, field) {
  if (!actual || BigInt(actual.value) !== expected.value
      || actual.address.version !== expected.version
      || !actual.address.hash.equals(expected.hash)) {
    throw new Error(`${field} differs from deterministic payout`);
  }
  verifyHnsOutputAddress(actual, ordinary, field);
}

function verifyHnsOutputAddress(output, ordinary, field) {
  const size = output.address.hash.length;
  if (output.address.version > 31 || size < 2 || size > 40
      || (output.address.version === 0 && size !== 20 && size !== 32)
      || (ordinary && (output.covenant.type !== 0 || output.covenant.items.length !== 0))) {
    throw new Error(`${field} has an invalid HNS address or covenant`);
  }
}

function loadHsdContext(hsdRoot) {
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
  return {
    network,
    client: new NodeClient({
      url: config.str('url'),
      apiKey: config.str('api-key'),
      ssl: config.bool('ssl'),
      host: config.str('http-host'),
      port: config.uint('http-port') || ports[network] || ports.main,
      timeout: config.uint('timeout') || 5000,
      limit: config.uint('limit')
    })
  };
}

function requireBufferVectorEqual(actual, expected, field) {
  if (actual.length !== expected.length
      || actual.some((value, index) => !value.equals(expected[index]))) {
    throw new Error(`${field} differ from independent deterministic selection`);
  }
}

function parseArgs(args) {
  const options = {skipCanonicalEntropy: false};
  const values = new Map([
    ['--snapshot', 'snapshot'],
    ['--plan', 'plan'],
    ['--settlement-roster', 'settlementRoster'],
    ['--payout-profile', 'payoutProfile'],
    ['--hsd', 'hsd'],
    ['--block-height', 'blockHeightText'],
    ['--block-file', 'blockFile'],
    ['--network', 'network']
  ]);
  for (let index = 0; index < args.length; index++) {
    const name = args[index];
    if (name === '--skip-canonical-entropy') {
      if (options.skipCanonicalEntropy)
        throw new Error('duplicate --skip-canonical-entropy');
      options.skipCanonicalEntropy = true;
      continue;
    }
    const field = values.get(name);
    if (!field || options[field] !== undefined || index + 1 >= args.length)
      throw new Error(`unknown, duplicate, or valueless argument: ${name}`);
    options[field] = args[++index];
  }
  for (const field of ['snapshot', 'plan', 'settlementRoster', 'payoutProfile']) {
    if (!options[field])
      throw new Error(`missing required payout verifier argument: ${field}`);
  }
  if (options.blockHeightText !== undefined) {
    if (!/^(0|[1-9][0-9]*)$/.test(options.blockHeightText))
      throw new Error('--block-height is not canonical uint32 decimal');
    options.blockHeight = Number(options.blockHeightText);
    if (!safeInteger(options.blockHeight, 0, 0xffffffff))
      throw new Error('--block-height is outside uint32');
  }
  if (options.network !== undefined
      && !['main', 'testnet', 'regtest', 'simnet'].includes(options.network)) {
    throw new Error('--network is not a recognized hsd network');
  }
  if (options.blockFile && !options.skipCanonicalEntropy)
    throw new Error('--block-file is offline evidence and requires --skip-canonical-entropy');
  return options;
}

main().catch(error => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
