#!/usr/bin/env node
'use strict';

const assert = require('assert');
const crypto = require('crypto');
process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';
const BLAKE2b = require('../hsd-oracle/node_modules/bcrypto/lib/blake2b');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const receipt = JSON.parse(fs.readFileSync(
  path.join(ROOT, 'specs', 'core-capture-receipt.example.json'),
  'utf8'
));
const config = JSON.parse(fs.readFileSync(
  path.join(ROOT, 'specs', 'operator-service.example.json'),
  'utf8'
));

function varint(value) {
  assert(Number.isSafeInteger(value) && value >= 0);
  const out = [];
  do {
    let byte = value & 0x7f;
    value = Math.floor(value / 128);
    if (value !== 0)
      byte |= 0x80;
    out.push(byte);
  } while (value !== 0);
  return Buffer.from(out);
}

function u16(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16LE(value);
  return out;
}

function u64(value) {
  const number = BigInt(value);
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(number);
  return out;
}

function vector(value, expected, name) {
  const out = Buffer.from(value);
  assert.strictEqual(out.length, expected, `${name} length`);
  return out;
}

function domainHash(domain, body) {
  const tag = Buffer.from(domain, 'ascii');
  return BLAKE2b.digest(Buffer.concat([
    varint(tag.length),
    tag,
    body,
  ]), 32);
}

assert.strictEqual(receipt.version, 1);
assert.strictEqual(receipt.signature_suite, 1);
assert.strictEqual(receipt.network_id, config.network_id);

const publicKey = vector(receipt.core_receipt_pubkey, 32, 'Core public key');
assert(publicKey.equals(Buffer.from(config.core_receipt_pubkey, 'hex')));
const unsignedBody = Buffer.concat([
  u16(receipt.version),
  Buffer.from([receipt.network_id]),
  vector(receipt.work_key, 32, 'work key'),
  vector(receipt.downstream_id, 32, 'downstream id'),
  vector(receipt.core_context_id, 32, 'Core context id'),
  u64(receipt.admitted_at_ms),
  publicKey,
  u16(receipt.signature_suite),
]);
const receiptId = domainHash(
  'meshmine/operator-core-capture-receipt/v1',
  unsignedBody
);
assert(receiptId.equals(vector(receipt.receipt_id, 32, 'receipt id')));

const receiptDomain = Buffer.from(
  'meshmine/operator-core-capture-receipt/v1',
  'ascii'
);
const signatureContextBody = Buffer.concat([
  u16(2),
  Buffer.from([receipt.network_id]),
  varint(receiptDomain.length),
  receiptDomain,
  receiptId,
]);
const signatureMessage = domainHash(
  'meshmine/signature-context/v2',
  signatureContextBody
);
const signature = vector(receipt.core_signature, 64, 'Core signature');
const spki = Buffer.concat([
  Buffer.from('302a300506032b6570032100', 'hex'),
  publicKey,
]);
const key = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
assert(crypto.verify(null, signatureMessage, key, signature));

console.log('operator signed Core receipt fixture verification passed');
console.log(`receipt_id=${receiptId.toString('hex')}`);
console.log(`signature_message=${signatureMessage.toString('hex')}`);
