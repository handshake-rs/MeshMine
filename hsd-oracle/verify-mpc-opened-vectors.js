#!/usr/bin/env node
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const hsd = resolveHsd(process.env.HSD_DIR);
const BLAKE2b = require(resolveFromHsd(hsd, 'bcrypto/lib/blake2b'));
const expectedCount = Number(process.argv[2] || 10000);
const lines = fs.readFileSync(0, 'utf8').trim().split('\n');

assert.strictEqual(lines.length, expectedCount, 'opened vector count');
for (let expectedIndex = 0; expectedIndex < lines.length; expectedIndex++) {
  const fields = lines[expectedIndex].split('\t');
  assert.strictEqual(fields.length, 6, `field count at ${expectedIndex}`);
  const [indexText, parentText, maskText, hashText, qText, dText] = fields;
  assert.strictEqual(Number(indexText), expectedIndex, 'ordered vector index');
  const parent = fixedHex(parentText, 32);
  const mask = fixedHex(maskText, 32);
  const maskHash = fixedHex(hashText, 32);
  const q = Number(qText);
  const d = Number(dText);
  assert(BLAKE2b.multi(parent, mask).equals(maskHash),
    `hsd/bcrypto maskHash mismatch at ${expectedIndex}`);
  assert(rangeAll(mask, 0, q, false), `nonzero prefix at ${expectedIndex}`);
  assert(rangeSome(mask, q, q + d, true), `zero blind band at ${expectedIndex}`);
}

process.stdout.write(`verified ${lines.length} opened research-VSS masks against hsd/bcrypto\n`);

function getBit(bytes, bit) {
  return (bytes[bit >>> 3] & (1 << (7 - (bit & 7)))) !== 0;
}

function rangeAll(bytes, start, end, value) {
  for (let bit = start; bit < end; bit++) {
    if (getBit(bytes, bit) !== value)
      return false;
  }
  return true;
}

function rangeSome(bytes, start, end, value) {
  for (let bit = start; bit < end; bit++) {
    if (getBit(bytes, bit) === value)
      return true;
  }
  return false;
}

function fixedHex(text, size) {
  assert.strictEqual(text.length, size * 2);
  assert(/^[0-9a-f]+$/.test(text));
  return Buffer.from(text, 'hex');
}

function resolveHsd(explicit) {
  if (explicit)
    return path.resolve(explicit);
  return path.dirname(require.resolve('hsd/package.json', {paths: [__dirname]}));
}

function resolveFromHsd(hsdRoot, request) {
  return require.resolve(request, {paths: [hsdRoot]});
}
