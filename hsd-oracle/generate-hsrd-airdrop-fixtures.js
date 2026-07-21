'use strict';

// Generates deterministic HSD airdrop key/proof codec vectors. The committed
// faucet proof is copied from the pinned HSD upstream test corpus and exercises
// a complete address-key proof, including its production Merkle root.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const AirdropKey = require('hsd/lib/primitives/airdropkey');
const AirdropProof = require('hsd/lib/primitives/airdropproof');

const REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(ROOT, 'hsrd/fixtures/hsd/airdrops/codec-v1.json');
const FAUCET_PROOF_BASE64 =
  'MAEAAAsk88I7Sy9q89bcBYyQgm1M22vxwC7++XJxyVdqpVvJ8oH32lPurCMb4gg+GRREgJ26Bd23tf1+pDvj8JpGugxrfzWtzF3cRzdXfR64/rndCh1ABd/yjvgKYEOB/yxgN/TTzYcaHLlI/CR33j3OmHfS+e0ktRSb4Yv+fdmBrzJ4XjzbnZcrYBfyhc4QgqN8wM3fuvkNOuviuZsAJYkc3hdngxVZFQX0qQg87SuVDFbUT2GicLlmSwxE3b4Wk2EKthfNrdSa/8r2d0qbA7dyYtSd5Q+IrBLly4N8E2UTweIc8I5xBB7ssWEDGb3VQfroHulv+D0OIINjky32tDnbKYesCsOXdfD+5vDp8dg288NsZacFIpmy6El/ri58E31liXkU2qyvcyA+V+E4wqkPE4CShHqBaAzAbSxddiHnFvAfAFsKPkkdrkOQBJuxX0ZlXjHj2jJTspzwEE9Z0MYwuu2HAAAgBAAU3IMpICLzdoj4PQF5aBqkkHXqaK8U+0f6AQAAAAAAFNyDKSAi83aI+D0BeWgapJB16miv/gDh9QUA';

function repeated(size, byte) {
  return Buffer.alloc(size, byte);
}

function makeKeys() {
  const rsa = new AirdropKey();
  rsa.type = AirdropKey.keyTypes.RSA;
  rsa.n = Buffer.concat([Buffer.from([0x01]), repeated(255, 0x11)]);
  rsa.e = Buffer.from([0x01, 0x00, 0x01]);
  rsa.nonce = repeated(32, 0x12);

  const goo = new AirdropKey();
  goo.type = AirdropKey.keyTypes.GOO;
  goo.C1 = repeated(256, 0x21);

  const p256 = new AirdropKey();
  p256.type = AirdropKey.keyTypes.P256;
  p256.point = Buffer.concat([Buffer.from([0x02]), repeated(32, 0x31)]);
  p256.nonce = repeated(32, 0x32);

  const ed25519 = new AirdropKey();
  ed25519.type = AirdropKey.keyTypes.ED25519;
  ed25519.point = repeated(32, 0x41);
  ed25519.nonce = repeated(32, 0x42);

  const address = new AirdropKey();
  address.type = AirdropKey.keyTypes.ADDRESS;
  address.version = 0;
  address.address = repeated(20, 0x51);
  address.value = 8_493_988_628;
  address.sponsor = true;

  return [rsa, goo, p256, ed25519, address];
}

function keyVector(key) {
  const raw = key.encode();
  const decoded = AirdropKey.decode(raw);
  assert.deepStrictEqual(decoded.encode(), raw);
  return {
    type: AirdropKey.keyTypesByVal[key.type],
    raw: raw.toString('hex'),
    weak: decoded.isWeak(),
    isGoo: decoded.isGoo(),
    isAddress: decoded.isAddress(),
    json: decoded.getJSON()
  };
}

function syntheticProof(key, ordinal) {
  const proof = new AirdropProof();
  proof.index = 10 + ordinal;
  proof.proof = [repeated(32, 0x60 + ordinal), repeated(32, 0x70 + ordinal)];
  proof.key = key.encode();
  proof.version = 0;
  proof.address = repeated(20, 0x80 + ordinal);
  proof.fee = 100_000 + ordinal;
  proof.signature = repeated(8 + ordinal, 0x90 + ordinal);

  if (key.isAddress()) {
    proof.subindex = 0;
    proof.subproof = [];
    proof.version = key.version;
    proof.address = key.address;
    proof.fee = key.sponsor ? 500_000_000 : 100_000_000;
    proof.signature = Buffer.alloc(0);
  } else {
    proof.subindex = ordinal % 8;
    proof.subproof = [repeated(32, 0xa0 + ordinal)];
  }

  return proof;
}

function proofVector(id, proof) {
  const raw = proof.encode();
  const decoded = AirdropProof.decode(raw);
  assert.deepStrictEqual(decoded.encode(), raw);
  return {
    id,
    raw: raw.toString('hex'),
    hash: decoded.hash().toString('hex'),
    signatureData: decoded.signatureData().toString('hex'),
    signatureHash: decoded.signatureHash().toString('hex'),
    keyRaw: decoded.key.toString('hex'),
    keyType: decoded.getKey()
      ? AirdropKey.keyTypesByVal[decoded.getKey().type]
      : 'UNKNOWN',
    sane: decoded.isSane(),
    merkle: decoded.verifyMerkle(),
    signature: decoded.verifySignature(),
    verify: decoded.verify(),
    position: decoded.position(),
    value: decoded.getValue(),
    version: decoded.version,
    address: decoded.address.toString('hex'),
    fee: decoded.fee,
    sponsor: decoded.getKey() && decoded.getKey().isAddress()
      ? decoded.getKey().sponsor
      : false
  };
}

function decodeMutation(id, raw) {
  let accepted = true;
  try {
    AirdropProof.decode(raw);
  } catch (error) {
    accepted = false;
  }
  return {id, raw: raw.toString('hex'), accepted};
}

function makeFixture() {
  const keys = makeKeys();
  const faucetRaw = Buffer.from(FAUCET_PROOF_BASE64, 'base64');
  const faucet = AirdropProof.decode(faucetRaw);
  assert(faucet.verify(), 'pinned HSD faucet proof must verify');

  const invalidIndex = Buffer.from(faucetRaw);
  invalidIndex.writeUInt32LE(AirdropProof.AIRDROP_LEAVES, 0);
  const invalidDepth = Buffer.from(faucetRaw);
  invalidDepth[4] = 19;
  assert(faucetRaw.subarray(-6).equals(Buffer.from('fe00e1f50500', 'hex')));
  const unsafeFee = Buffer.concat([
    faucetRaw.subarray(0, -6),
    Buffer.from('ff000000000000200000', 'hex')
  ]);

  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: REVISION
    },
    constants: {
      airdropRoot: AirdropProof.AIRDROP_ROOT.toString('hex'),
      faucetRoot: AirdropProof.FAUCET_ROOT.toString('hex'),
      treeLeaves: AirdropProof.TREE_LEAVES,
      airdropLeaves: AirdropProof.AIRDROP_LEAVES,
      faucetLeaves: AirdropProof.FAUCET_LEAVES
    },
    keys: keys.map(keyVector),
    proofs: keys.map((key, index) => proofVector(`synthetic-${index}`, syntheticProof(key, index))),
    faucet: proofVector('upstream-valid-faucet', faucet),
    decodeMutations: [
      decodeMutation('trailing-byte', Buffer.concat([faucetRaw, Buffer.from([0])])),
      decodeMutation('index-out-of-range', invalidIndex),
      decodeMutation('proof-depth-out-of-range', invalidDepth),
      decodeMutation('fee-above-safe-integer', unsafeFee)
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
