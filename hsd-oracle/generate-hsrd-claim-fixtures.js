'use strict';

// Generates deterministic vectors for HSD's Claim envelope, binary ownership
// TXT payload, and complete upstream DNSSEC ownership-proof corpus.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const bio = require('bufio');
const base32 = require('bcrypto/lib/encoding/base32');
const blake2b = require('bcrypto/lib/blake2b');
const dnssec = require('bns/lib/dnssec');
const {types, hashes} = require('bns/lib/constants');
const GOST94 = require('bcrypto/lib/gost94');

const Claim = require('hsd/lib/primitives/claim');
const Network = require('hsd/lib/protocol/network');
const {OwnershipProof, ownership} = require('hsd/lib/covenants/ownership');
const reserved = require('hsd/lib/covenants/reserved');
const consensus = require('hsd/lib/protocol/consensus');

const REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(ROOT, 'hsrd/fixtures/hsd/claims/codec-v1.json');
const PROOF_SOURCES = [
  ['upstream-ownership-cloudflare', 'ownership-cloudflare.zone'],
  ['upstream-ownership-fr', 'ownership-fr.zone'],
  ['upstream-ownership-nl', 'ownership-nl.zone'],
  ['upstream-ownership-xn--ogbpf8fl', 'ownership-xn--ogbpf8fl.zone']
];
const COMMIT_HASH = Buffer.from(
  '0025f4480dadc61f13f507af9c9c9d06373fed38727ea467b6b2d5b09d522164',
  'hex'
);

function claimVector(id, blob) {
  const claim = Claim.fromBlob(blob);
  const raw = claim.encode();
  const decoded = Claim.decode(raw);
  assert.deepStrictEqual(decoded.encode(), raw);
  return {
    id,
    blob: blob.toString('hex'),
    raw: raw.toString('hex'),
    hash: decoded.hash().toString('hex'),
    size: decoded.getSize()
  };
}

function dataVector(name, ordinal) {
  const network = Network.get(name);
  const address = {
    version: ordinal % 2,
    hash: Buffer.alloc(ordinal % 2 === 0 ? 20 : 32, 0x40 + ordinal)
  };
  const fee = 20_960 + ordinal;
  const commitHeight = ordinal + 1;
  const txt = ownership.createData(
    address,
    fee,
    COMMIT_HASH,
    commitHeight,
    network
  );
  const raw = base32.decode(txt.substring(network.claimPrefix.length));
  const decoded = ownership.decodeData(txt, network);
  assert.strictEqual(decoded.address.version, address.version);
  assert.strictEqual(decoded.address.hash, address.hash.toString('hex'));
  assert.strictEqual(decoded.fee, fee);
  assert.strictEqual(decoded.commitHash, COMMIT_HASH.toString('hex'));
  assert.strictEqual(decoded.commitHeight, commitHeight);
  assert(strictDataDecode(raw), 'HSD payload must pass strict parseData codec rules');
  return {
    network: name,
    prefix: network.claimPrefix,
    txt,
    raw: raw.toString('hex'),
    version: address.version,
    address: address.hash.toString('hex'),
    fee,
    commitHash: COMMIT_HASH.toString('hex'),
    commitHeight
  };
}

function strictDataDecode(raw) {
  try {
    const br = bio.read(raw);
    const version = br.readU8();
    if (version > 31)
      return false;
    const size = br.readU8();
    if (size < 2 || size > 40)
      return false;
    br.readBytes(size);
    const fee = br.readVarint();
    if (fee > consensus.MAX_MONEY)
      return false;
    br.readHash();
    br.readU32();
    br.verifyChecksum(blake2b.digest);
    return br.left() === 0;
  } catch (error) {
    return false;
  }
}

function claimDecodeMutation(id, raw) {
  let accepted = true;
  try {
    Claim.decode(raw);
  } catch (error) {
    accepted = false;
  }
  return {id, raw: raw.toString('hex'), accepted};
}

function dataDecodeMutation(id, raw) {
  return {id, raw: raw.toString('hex'), accepted: strictDataDecode(raw)};
}

function anchorVector(name, anchor, valid) {
  return {
    name,
    keyTag: anchor.data.keyTag,
    algorithm: anchor.data.algorithm,
    digestType: anchor.data.digestType,
    digest: anchor.data.digest.toString('hex'),
    signaturesValidWithHistoricalTestPolicy: valid
  };
}

function proofVector(id, filename) {
  const sourcePath = path.join(__dirname, 'fixtures', filename);
  const source = fs.readFileSync(sourcePath, 'utf8');
  const proof = OwnershipProof.fromString(source);
  const raw = proof.encode();
  const decoded = OwnershipProof.decode(raw);
  const [inception, expiration] = decoded.getWindow();

  assert.strictEqual(decoded.encode().toString('hex'), raw.toString('hex'));
  assert(decoded.isSane(), 'upstream proof sanity');
  assert(decoded.getTarget(), 'upstream proof target');
  assert(decoded.getName(), 'upstream proof name');

  const root = decoded.zones[0];
  const rootSig = root.keys.find(rr => rr.type === types.RRSIG);
  assert(rootSig, 'upstream root DNSKEY signature');
  const rootKey = root.keys.find(rr =>
    rr.type === types.DNSKEY && rr.data.keyTag() === rootSig.data.keyTag);
  assert(rootKey, 'upstream root signing key');
  const sha256Anchor = dnssec.createDS(rootKey, hashes.SHA256);
  const gost94Anchor = dnssec.createDS(rootKey, hashes.GOST94);
  assert(sha256Anchor, 'upstream proof SHA-256 root anchor');
  assert(gost94Anchor, 'upstream proof GOST94 root anchor');

  const signaturesValid = decoded.verifySignatures();
  const savedAnchors = ownership.anchors;
  const savedIgnore = ownership.ignore;
  let sha256Valid;
  let gost94Valid;
  try {
    ownership.ignore = true;
    ownership.anchors = [sha256Anchor];
    sha256Valid = decoded.verifySignatures();
    ownership.anchors = [gost94Anchor];
    gost94Valid = decoded.verifySignatures();
  } finally {
    ownership.anchors = savedAnchors;
    ownership.ignore = savedIgnore;
  }
  assert.strictEqual(signaturesValid, false,
    'historical proof must not match HSD current root anchor');
  assert(sha256Valid,
    'historical proof signatures under its SHA-256 test anchor policy');
  assert(gost94Valid,
    'historical proof signatures under its GOST94 test anchor policy');
  const reservedItem = reserved.getByName(decoded.getName());
  assert(reservedItem, 'upstream proof reserved name');

  return {
    id,
    source: `handshake-org/hsd test/data/${filename}`,
    sourceBlake2b256: blake2b.digest(Buffer.from(source), 32).toString('hex'),
    raw: raw.toString('hex'),
    size: raw.length,
    zones: decoded.zones.length,
    target: decoded.getTarget(),
    name: decoded.getName(),
    reservedTarget: reservedItem.target,
    reservedValue: reservedItem.value,
    sane: decoded.isSane(),
    signaturesValid,
    rootAnchors: [
      anchorVector('SHA256', sha256Anchor, sha256Valid),
      anchorVector('GOST94', gost94Anchor, gost94Valid)
    ],
    weak: decoded.isWeak(),
    inception,
    expiration
  };
}

function gostDigestVector(id, data) {
  return {
    id,
    data: data.toString('hex'),
    digest: GOST94.digest(data).toString('hex')
  };
}

function makeFixture() {
  const claims = [
    claimVector('empty', Buffer.alloc(0)),
    claimVector('deterministic-64', Buffer.from(Array.from({length: 64}, (_, i) => i)))
  ];
  const data = ['main', 'testnet', 'regtest', 'simnet'].map(dataVector);
  const knownRegtest =
    'hns-regtest:aakjgghlaflqi4bklnubdxwh6vp5fklfwzf73ycraa' +
    's7isanvxdb6e7va6xzzhe5ay3t73jyoj7kiz5wwlk3bhksefsacaaaaafk5pvj';
  const knownDecoded = ownership.decodeData(knownRegtest, 'regtest');
  assert.strictEqual(knownDecoded.commitHeight, 1);

  const claimRaw = Buffer.from(claims[1].raw, 'hex');
  const oversizedLength = Buffer.from([0x11, 0x27]); // 10,001 little endian.
  const truncated = Buffer.from(claimRaw.subarray(0, -1));

  const validData = Buffer.from(data[2].raw, 'hex');
  const badChecksum = Buffer.from(validData);
  badChecksum[badChecksum.length - 1] ^= 1;
  const badVersion = Buffer.from(validData);
  badVersion[0] = 32;
  const trailingData = Buffer.concat([validData, Buffer.from([0])]);

  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: REVISION
    },
    knownRegtest: {
      txt: knownRegtest,
      version: knownDecoded.address.version,
      address: knownDecoded.address.hash,
      fee: knownDecoded.fee,
      commitHash: knownDecoded.commitHash,
      commitHeight: knownDecoded.commitHeight
    },
    proofs: PROOF_SOURCES.map(([id, filename]) => proofVector(id, filename)),
    gost94Digests: [
      gostDigestVector('empty', Buffer.alloc(0)),
      gostDigestVector('one-byte', Buffer.from('a')),
      gostDigestVector('abc', Buffer.from('abc')),
      gostDigestVector('31-byte-boundary', Buffer.alloc(31, 0x5a)),
      gostDigestVector('32-byte-boundary', Buffer.alloc(32, 0x5a)),
      gostDigestVector('33-byte-boundary', Buffer.alloc(33, 0x5a)),
      gostDigestVector(
        'multi-block-255',
        Buffer.from(Array.from({length: 255}, (_, index) => index))
      )
    ],
    claims,
    data,
    claimDecodeMutations: [
      claimDecodeMutation('trailing-byte', Buffer.concat([claimRaw, Buffer.from([0])])),
      claimDecodeMutation('oversized-length', oversizedLength),
      claimDecodeMutation('truncated-blob', truncated)
    ],
    dataDecodeMutations: [
      dataDecodeMutation('bad-checksum', badChecksum),
      dataDecodeMutation('version-out-of-range', badVersion),
      dataDecodeMutation('trailing-byte', trailingData)
    ]
  };
}

function stable(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function main() {
  const write = process.argv.includes('--write');
  const check = process.argv.includes('--check');
  assert(write || check, 'use --write and/or --check');
  const expected = stable(makeFixture());

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

main();
