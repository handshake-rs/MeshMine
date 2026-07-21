#!/usr/bin/env node
'use strict';

// Generate exact canonical Urkel proof bytes and bounded malformed/wrong-root
// cases through the pinned implementation used by HSD.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const BLAKE2b = require('bcrypto/lib/blake2b');
const {Proof, Tree} = require('urkel');
const rules = require('hsd/lib/covenants/rules');

const ORACLE_REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const ROOT = path.resolve(__dirname, '..');
const TARGET = path.join(
  ROOT,
  'hsrd/fixtures/hsd/name-states/urkel-proofs-v1.json'
);
const WRITE = process.argv.includes('--write');
const CHECK = process.argv.includes('--check') || !WRITE;
const BITS = 256;

function stable(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function key(name) {
  return rules.hashName(Buffer.from(name, 'ascii'));
}

function digest(raw) {
  return BLAKE2b.digest(raw, 32).toString('hex');
}

function proofRecord(id, root, query, proof, expectedValue) {
  const raw = proof.encode(BLAKE2b, BITS);
  const decoded = Proof.decode(raw, BLAKE2b, BITS);
  const canonical = decoded.encode(BLAKE2b, BITS);
  const [code, value] = decoded.verify(root, query, BLAKE2b, BITS);
  assert.strictEqual(code, Proof.codes.PROOF_OK, `${id}: proof verification`);
  assert.deepStrictEqual(value, expectedValue, `${id}: proof value`);
  assert.deepStrictEqual(canonical, raw, `${id}: canonical proof bytes`);
  return {
    id,
    root: root.toString('hex'),
    key: query.toString('hex'),
    kind: value == null ? 'nonInclusion' : 'inclusion',
    type: Proof.type(proof.type),
    depth: proof.depth,
    nodeCount: proof.nodes.length,
    json: proof.toJSON(),
    raw: raw.toString('hex'),
    rawBlake2b256: digest(raw),
    value: value == null ? null : value.toString('hex'),
    verifyCode: code,
    verifyCodeName: Proof.code(code)
  };
}

function mutationRecord(id, raw, root, query) {
  let decoded = null;
  let decodeAccepted = true;
  let canonicalRaw = null;
  let verifyCode = null;
  let verifyCodeName = null;
  let value = null;
  try {
    decoded = Proof.decode(raw, BLAKE2b, BITS);
    canonicalRaw = decoded.encode(BLAKE2b, BITS).toString('hex');
    [verifyCode, value] = decoded.verify(root, query, BLAKE2b, BITS);
    verifyCodeName = Proof.code(verifyCode);
  } catch (error) {
    decodeAccepted = false;
  }
  return {
    id,
    root: root.toString('hex'),
    key: query.toString('hex'),
    raw: raw.toString('hex'),
    decodeAccepted,
    canonicalRaw,
    verifyCode,
    verifyCodeName,
    value: value == null ? null : value.toString('hex')
  };
}

function setField(raw, offset, value) {
  const copy = Buffer.from(raw);
  copy.writeUInt16LE(value, offset);
  return copy;
}

async function findAbsenceProof(snapshot, wantedType) {
  for (let index = 0; index < 100_000; index++) {
    const query = key(`missing-${index}`);
    const proof = await snapshot.prove(query);
    if (proof.type === wantedType)
      return {query, proof};
  }
  throw new Error(`could not find deterministic proof type ${Proof.type(wantedType)}`);
}

async function buildFixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hsrd-urkel-proofs-'));
  const tree = new Tree({
    hash: BLAKE2b,
    bits: BITS,
    prefix: directory
  });
  const entries = [
    ['alpha-proof', Buffer.from('00010203', 'hex')],
    ['bravo-proof', Buffer.from('handshake', 'ascii')],
    ['charlie-proof', Buffer.alloc(33, 0x33)],
    ['delta-proof', Buffer.from('deadbeef00', 'hex')],
    ['echo-proof', Buffer.alloc(64, 0x55)],
    ['foxtrot-proof', Buffer.from('urkel-proof-wire', 'ascii')],
    ['golf-proof', Buffer.alloc(1, 0x77)],
    ['hotel-proof', Buffer.alloc(257, 0x88)]
  ].map(([name, value]) => ({name, key: key(name), value}));

  await tree.open();
  try {
    const emptyRoot = tree.rootHash();
    const emptyKey = key('empty-proof');
    const emptyProof = await tree.prove(emptyKey);
    assert.strictEqual(emptyProof.type, Proof.types.TYPE_DEADEND);
    const proofs = [
      proofRecord('empty-tree-deadend', emptyRoot, emptyKey, emptyProof, null)
    ];

    const transaction = tree.transaction();
    for (const entry of entries)
      await transaction.insert(entry.key, entry.value);
    const root = await transaction.commit();
    const snapshot = tree.snapshot(root);

    for (const entry of entries) {
      const proof = await snapshot.prove(entry.key);
      assert.strictEqual(proof.type, Proof.types.TYPE_EXISTS);
      proofs.push(proofRecord(
        `included-${entry.name}`,
        root,
        entry.key,
        proof,
        entry.value
      ));
    }

    const short = await findAbsenceProof(snapshot, Proof.types.TYPE_SHORT);
    proofs.push(proofRecord(
      'missing-short-prefix',
      root,
      short.query,
      short.proof,
      null
    ));
    const collision = await findAbsenceProof(snapshot, Proof.types.TYPE_COLLISION);
    proofs.push(proofRecord(
      'missing-leaf-collision',
      root,
      collision.query,
      collision.proof,
      null
    ));

    const collisionRaw = collision.proof.encode(BLAKE2b, BITS);
    const collisionField = collisionRaw.readUInt16LE(0);
    const corrupted = Buffer.from(collisionRaw);
    corrupted[corrupted.length - 1] ^= 0x01;
    const wrongRoot = Buffer.alloc(32, 0xa5);
    const wrongKey = key('wrong-proof-key');
    const mutations = [
      mutationRecord(
        'truncated-terminal',
        collisionRaw.subarray(0, collisionRaw.length - 1),
        root,
        collision.query
      ),
      mutationRecord(
        'trailing-byte-is-ignored-by-upstream-decoder',
        Buffer.concat([collisionRaw, Buffer.from([0xff])]),
        root,
        collision.query
      ),
      mutationRecord(
        'depth-exceeds-key-bits',
        setField(collisionRaw, 0, (collisionField & 0xc000) | 257),
        root,
        collision.query
      ),
      mutationRecord(
        'node-count-exceeds-key-bits',
        setField(collisionRaw, 2, 257),
        root,
        collision.query
      ),
      mutationRecord(
        'corrupted-terminal-hash',
        corrupted,
        root,
        collision.query
      ),
      mutationRecord(
        'valid-proof-against-wrong-root',
        collisionRaw,
        wrongRoot,
        collision.query
      ),
      mutationRecord(
        'valid-proof-against-wrong-key',
        collisionRaw,
        root,
        wrongKey
      )
    ];

    assert.strictEqual(mutations[0].decodeAccepted, false);
    assert.strictEqual(mutations[1].decodeAccepted, true);
    assert.strictEqual(mutations[1].verifyCode, Proof.codes.PROOF_OK);
    assert.strictEqual(mutations[2].decodeAccepted, false);
    assert.strictEqual(mutations[3].decodeAccepted, false);
    for (const item of mutations.slice(4)) {
      assert.strictEqual(item.decodeAccepted, true, item.id);
      assert.notStrictEqual(item.verifyCode, Proof.codes.PROOF_OK, item.id);
    }

    return {
      schema: 1,
      oracle: {
        repository: 'handshake-org/hsd',
        revision: ORACLE_REVISION,
        dependency: 'urkel',
        proofSource: 'urkel/lib/proof.js'
      },
      hash: 'BLAKE2b-256',
      bits: BITS,
      entries: entries.map(entry => ({
        name: entry.name,
        key: entry.key.toString('hex'),
        value: entry.value.toString('hex')
      })),
      root: root.toString('hex'),
      proofs,
      mutations
    };
  } finally {
    await tree.close();
    fs.rmSync(directory, {recursive: true, force: true});
  }
}

async function main() {
  const fixture = await buildFixture();
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
  console.log(
    `${path.relative(process.cwd(), TARGET)}: `
    + `${fixture.proofs.length} canonical proofs and `
    + `${fixture.mutations.length} mutations verified`
  );
}

main().catch(error => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
