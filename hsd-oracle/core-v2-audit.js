'use strict';

// Independent JavaScript decoder and cryptographic verifier for the frozen
// Core v2 research wire profile. This deliberately does not import Rust output
// or generated bindings: every length, field order, object ID, signature
// context, and payout draw is reproduced here from MM-0001.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const CORE_V2 = 2;
const ED25519_SUITE = 1;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_BUCKETS = 100000;
const MAX_HASHES = 100000;
const MAX_SIGNERS = 4096;
const MAX_ADDRESS_BYTES = 64;
const MAX_SIGNATURE_BYTES = 128;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const hsd = resolveHsd(process.env.HSD_DIR);
const BLAKE2b = require(require.resolve('bcrypto/lib/blake2b', {paths: [hsd]}));

class Reader {
  constructor(data) {
    if (!Buffer.isBuffer(data) || data.length > MAX_FILE_BYTES)
      throw new Error('canonical object exceeds the independent verifier bound');
    this.data = data;
    this.offset = 0;
  }

  take(size, field = 'field') {
    if (!Number.isSafeInteger(size) || size < 0 || this.offset + size > this.data.length)
      throw new Error(`${field} is truncated or exceeds its bound`);
    const value = this.data.subarray(this.offset, this.offset + size);
    this.offset += size;
    return value;
  }

  u8() {
    return this.take(1, 'u8')[0];
  }

  u16() {
    return this.take(2, 'u16').readUInt16LE();
  }

  u32() {
    return this.take(4, 'u32').readUInt32LE();
  }

  u64() {
    return this.take(8, 'u64').readBigUInt64LE();
  }

  fixed(size, field = 'fixed field') {
    return Buffer.from(this.take(size, field));
  }

  varint() {
    let value = 0n;
    let shift = 0n;
    for (let index = 0; index < 10; index++) {
      const byte = this.u8();
      const group = BigInt(byte & 0x7f);
      if (shift === 63n && group > 1n)
        throw new Error('LEB128 value overflows u64');
      value |= group << shift;
      if ((byte & 0x80) === 0) {
        if (index > 0 && group === 0n)
          throw new Error('LEB128 value is not minimally encoded');
        return value;
      }
      shift += 7n;
    }
    throw new Error('LEB128 value is unterminated');
  }

  length(maximum, field = 'vector') {
    const value = this.varint();
    if (value > BigInt(maximum) || value > BigInt(Number.MAX_SAFE_INTEGER))
      throw new Error(`${field} length exceeds its bound`);
    return Number(value);
  }

  bytes(maximum, field = 'bytes') {
    return this.fixed(this.length(maximum, field), field);
  }

  vector(maximum, decode, field = 'vector') {
    const count = this.length(maximum, field);
    const values = [];
    for (let index = 0; index < count; index++)
      values.push(decode(this, index));
    return values;
  }

  finish() {
    if (this.offset !== this.data.length)
      throw new Error('canonical object has trailing bytes');
  }
}

function decodePayoutSnapshot(data) {
  const reader = new Reader(data);
  const snapshot = {
    domain: 'meshmine/payout-snapshot/v2',
    protocolVersion: reader.u16(),
    networkId: reader.u8(),
    snapshotSequence: reader.u64(),
    previousSnapshotId: reader.fixed(32),
    firstSessionCloseId: reader.fixed(32),
    lastSessionCloseId: reader.fixed(32),
    closeAnchorHeight: reader.u32(),
    workWindowTarget: reader.fixed(64),
    actualWorkInWindow: reader.fixed(64),
    workBuckets: reader.vector(MAX_BUCKETS, decodeWorkBucket, 'work buckets'),
    serviceBuckets: reader.vector(MAX_BUCKETS, decodeServiceBucket, 'service buckets'),
    shareSetRoot: reader.fixed(32),
    serviceSetRoot: reader.fixed(32),
    settlementCommitteeId: reader.fixed(32)
  };
  snapshot.unsigned = Buffer.from(data.subarray(0, reader.offset));
  snapshot.signerSet = decodeSignatureSet(reader);
  reader.finish();
  requirePrefix(snapshot);
  requireStrictOrder(snapshot.workBuckets.map(bucket => bucket.bucketId), 'work buckets');
  requireStrictOrder(snapshot.serviceBuckets.map(bucket => bucket.bucketId), 'service buckets');
  snapshot.id = objectId(snapshot.domain, snapshot.unsigned);
  return snapshot;
}

function decodePayoutPlan(data) {
  const reader = new Reader(data);
  const plan = {
    domain: 'meshmine/payout-plan/v2',
    protocolVersion: reader.u16(),
    networkId: reader.u8(),
    planSequence: reader.u64(),
    snapshotId: reader.fixed(32),
    entropyAnchorStart: reader.u32(),
    entropyAnchorCount: reader.u16(),
    entropyHashes: reader.vector(MAX_HASHES, item => item.fixed(32), 'entropy hashes'),
    priorBeacon: reader.fixed(32),
    planSeed: reader.fixed(32),
    workTicketCount: reader.u16(),
    serviceTicketCount: reader.u16(),
    workWinners: reader.vector(MAX_HASHES, item => item.fixed(32), 'work winners'),
    serviceWinners: reader.vector(MAX_HASHES, item => item.fixed(32), 'service winners'),
    selectionTranscriptHash: reader.fixed(32)
  };
  plan.unsigned = Buffer.from(data.subarray(0, reader.offset));
  plan.signerSet = decodeSignatureSet(reader);
  reader.finish();
  requirePrefix(plan);
  if (plan.entropyAnchorCount !== plan.entropyHashes.length)
    throw new Error('entropy count does not match its vector');
  plan.id = objectId(plan.domain, plan.unsigned);
  return plan;
}

function decodeBlockBodyPackage(data) {
  const reader = new Reader(data);
  const body = {
    domain: 'meshmine/body-package/v2',
    protocolVersion: reader.u16(),
    networkId: reader.u8(),
    template: decodeTemplateCoreFrom(reader),
    templateId: reader.fixed(32),
    coinbaseRaw: reader.bytes(4 * 1024 * 1024, 'coinbase transaction'),
    transactionsRaw: reader.vector(
      MAX_HASHES,
      item => item.bytes(4 * 1024 * 1024, 'body transaction'),
      'body transactions'
    ),
    merkleRoot: reader.fixed(32),
    witnessRoot: reader.fixed(32),
    treeRoot: reader.fixed(32),
    reservedRoot: reader.fixed(32),
    blockWeight: reader.u32(),
    blockSigops: reader.u32(),
    minerSubsidy: reader.u64(),
    ordinaryTransactionFees: reader.u64(),
    claimAirdropPrincipal: reader.u64(),
    claimAirdropFees: reader.u64(),
    operatorFeeValue: reader.u64(),
    workServiceSubsidyValue: reader.u64(),
    hsdValidationResultHash: reader.fixed(32)
  };
  body.unsigned = Buffer.from(data.subarray(0, reader.offset));
  body.operatorSignature = reader.bytes(MAX_SIGNATURE_BYTES, 'body operator signature');
  reader.finish();
  requirePrefix(body);
  if (body.networkId !== body.template.networkId
      || body.protocolVersion !== body.template.protocolVersion
      || !body.templateId.equals(body.template.id)) {
    throw new Error('body package and TemplateCore linkage is invalid');
  }
  body.id = objectId(body.domain, body.unsigned);
  return body;
}

function decodeTemplateCoreFrom(reader) {
  const start = reader.offset;
  const template = {
    domain: 'meshmine/template-core/v2',
    protocolVersion: reader.u16(),
    networkId: reader.u8(),
    parentHash: reader.fixed(32),
    parentHeight: reader.u32(),
    operatorPubkey: reader.fixed(32),
    operatorFeeBucketId: reader.fixed(32),
    payoutSnapshotId: reader.fixed(32),
    payoutPlanId: reader.fixed(32),
    planSequence: reader.u64(),
    transactionIds: reader.vector(MAX_HASHES, item => item.fixed(32), 'template transactions'),
    claimIds: reader.vector(MAX_HASHES, item => item.fixed(32), 'template claims'),
    airdropIds: reader.vector(MAX_HASHES, item => item.fixed(32), 'template airdrops'),
    blockVersion: reader.u32(),
    bits: reader.u32(),
    minimumNtime: reader.u64(),
    policyCommitment: reader.fixed(32)
  };
  requirePrefix(template);
  template.unsigned = Buffer.from(reader.data.subarray(start, reader.offset));
  template.id = objectId(template.domain, template.unsigned);
  return template;
}

function decodeWorkBucket(reader) {
  return {
    bucketId: reader.fixed(32),
    operatorPubkey: reader.fixed(32),
    addressVersion: reader.u8(),
    addressHash: reader.bytes(MAX_ADDRESS_BYTES, 'work payout address'),
    weight: reader.fixed(64)
  };
}

function decodeServiceBucket(reader) {
  return {
    bucketId: reader.fixed(32),
    operatorPubkey: reader.fixed(32),
    addressVersion: reader.u8(),
    addressHash: reader.bytes(MAX_ADDRESS_BYTES, 'service payout address'),
    weight: reader.fixed(64)
  };
}

function decodeSignatureSet(reader) {
  const suite = reader.u16();
  const signatures = reader.vector(MAX_SIGNERS, item => ({
    publicKey: item.fixed(32, 'signer public key'),
    signature: item.bytes(MAX_SIGNATURE_BYTES, 'certificate signature')
  }), 'certificate signers');
  requireStrictOrder(signatures.map(signature => signature.publicKey), 'certificate signers');
  return {suite, signatures};
}

function loadStaticRoster(filename, expectedNetwork, expectedRole) {
  const roster = readJson(filename, 1024 * 1024);
  requireObjectKeys(roster, [
    'protocol_version', 'network_id', 'role', 'epoch', 'threshold', 'members'
  ], 'static roster');
  if (roster.protocol_version !== CORE_V2 || roster.network_id !== expectedNetwork
      || roster.role !== expectedRole || !safeInteger(roster.epoch, 0)
      || !safeInteger(roster.threshold, 1, 65535) || !Array.isArray(roster.members)
      || roster.members.length === 0 || roster.members.length > 4096
      || roster.threshold > roster.members.length) {
    throw new Error('static roster context or bounds are invalid');
  }
  const roleCodes = {mask: 1, receipt: 2, availability: 3, settlement: 4};
  const members = roster.members.map((member, index) => fixedHex(member, 32,
    `roster member ${index}`)).sort(Buffer.compare);
  requireStrictOrder(members, 'roster members');
  const body = Buffer.concat([
    u16(CORE_V2), u8(expectedNetwork), u16(roleCodes[expectedRole]),
    u64(BigInt(roster.epoch)), u16(roster.threshold), ...members
  ]);
  return {
    networkId: expectedNetwork,
    role: expectedRole,
    threshold: roster.threshold,
    members,
    id: domainHash('meshmine/committee-roster/v2', body)
  };
}

function verifyCertificate(object, roster) {
  const signerSet = object.signerSet;
  if (object.networkId !== roster.networkId || signerSet.suite !== ED25519_SUITE
      || signerSet.signatures.length < roster.threshold) {
    throw new Error('certificate suite, network, or threshold is invalid');
  }
  const eligible = new Set(roster.members.map(member => member.toString('hex')));
  const message = signatureMessage(object.networkId, object.domain, object.id);
  for (const entry of signerSet.signatures) {
    if (!eligible.has(entry.publicKey.toString('hex')))
      throw new Error('certificate contains an ineligible signer');
    if (entry.signature.length !== 64)
      throw new Error('Ed25519 certificate signature has the wrong length');
    const publicKey = crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, entry.publicKey]),
      format: 'der',
      type: 'spki'
    });
    if (!crypto.verify(null, message, publicKey, entry.signature))
      throw new Error('Ed25519 certificate signature does not verify');
  }
}

function verifyDirectSignature(object, publicKey, signature) {
  if (signature.length !== 64)
    throw new Error('direct Ed25519 signature has the wrong length');
  const key = crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
    format: 'der',
    type: 'spki'
  });
  const message = signatureMessage(object.networkId, object.domain, object.id);
  if (!crypto.verify(null, message, key, signature))
    throw new Error('direct Ed25519 object signature does not verify');
}

function signatureMessage(networkId, objectDomain, id) {
  const body = Buffer.concat([
    u16(CORE_V2), u8(networkId), variable(Buffer.from(objectDomain, 'ascii')), id
  ]);
  return domainHash('meshmine/signature-context/v2', body);
}

function objectId(domain, unsigned) {
  return domainHash(domain, unsigned);
}

function domainHash(domain, body) {
  if (!/^[\x00-\x7f]*$/.test(domain))
    throw new Error('domain tag is not ASCII');
  return blake256(Buffer.concat([variable(Buffer.from(domain, 'ascii')), body]));
}

function blake256(data) {
  return BLAKE2b.digest(data, 32);
}

function blake512(data) {
  return BLAKE2b.digest(data, 64);
}

function readBounded(filename, maximum = MAX_FILE_BYTES) {
  const stat = fs.statSync(filename);
  if (!stat.isFile() || stat.size > maximum)
    throw new Error(`${filename} is not a bounded regular file`);
  return fs.readFileSync(filename);
}

function readJson(filename, maximum) {
  return JSON.parse(readBounded(filename, maximum).toString('utf8'));
}

function fixedHex(text, size, field) {
  if (typeof text !== 'string' || text.length !== size * 2
      || !/^[0-9a-f]+$/.test(text)) {
    throw new Error(`${field} is not canonical ${size}-byte lowercase hex`);
  }
  return Buffer.from(text, 'hex');
}

function requirePrefix(object) {
  if (object.protocolVersion !== CORE_V2)
    throw new Error('object protocol version is not Core v2');
}

function requireStrictOrder(values, field) {
  for (let index = 1; index < values.length; index++) {
    if (Buffer.compare(values[index - 1], values[index]) >= 0)
      throw new Error(`${field} are not strictly sorted and unique`);
  }
}

function requireObjectKeys(value, expected, field) {
  if (value === null || Array.isArray(value) || typeof value !== 'object')
    throw new Error(`${field} is not an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index]))
    throw new Error(`${field} has missing or unknown fields`);
}

function safeInteger(value, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function bytesToBigInt(bytes) {
  const text = bytes.toString('hex');
  return text.length === 0 ? 0n : BigInt(`0x${text}`);
}

function u8(value) {
  return Buffer.from([value]);
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

function varint(input) {
  let value = BigInt(input);
  if (value < 0n || value > 0xffffffffffffffffn)
    throw new Error('cannot encode an out-of-range u64 LEB128 value');
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

function variable(value) {
  return Buffer.concat([varint(value.length), value]);
}

function resolveHsd(explicit) {
  if (explicit)
    return path.resolve(explicit);
  try {
    return path.dirname(require.resolve('hsd/package.json', {paths: [__dirname]}));
  } catch (error) {
    throw new Error('hsd was not found; set HSD_DIR or run npm install', {cause: error});
  }
}

module.exports = {
  CORE_V2,
  MAX_HASHES,
  Reader,
  blake256,
  blake512,
  bytesToBigInt,
  decodeBlockBodyPackage,
  decodePayoutPlan,
  decodePayoutSnapshot,
  domainHash,
  fixedHex,
  loadStaticRoster,
  objectId,
  readBounded,
  readJson,
  requireObjectKeys,
  resolveHsd,
  safeInteger,
  signatureMessage,
  u8,
  u16,
  u32,
  u64,
  variable,
  varint,
  verifyCertificate,
  verifyDirectSignature
};
