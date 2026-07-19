#!/usr/bin/env node
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const hsd = resolveHsd();
const BLAKE2b = require(require.resolve('bcrypto/lib/blake2b', {paths: [hsd]}));
const outputPath = path.resolve(
  __dirname,
  '../specs/wire-vectors/core-v2.json'
);

function bytes(value) {
  return Buffer.alloc(value.length, value.byte);
}

function hash(byte) {
  return Buffer.alloc(32, byte);
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

function vector(values, encode = value => value) {
  return Buffer.concat([varint(values.length), ...values.map(encode)]);
}

function option(value, encode = item => item) {
  if (value == null)
    return Buffer.from([0]);
  return Buffer.concat([Buffer.from([1]), encode(value)]);
}

function signatureSet(set) {
  return Buffer.concat([
    u16(set.suite),
    vector(set.signatures, entry => Buffer.concat([
      entry.publicKey,
      variable(entry.signature)
    ]))
  ]);
}

function domainHash(domain, body) {
  return BLAKE2b.digest(Buffer.concat([
    variable(Buffer.from(domain, 'ascii')),
    body
  ]));
}

const signature = byte => Buffer.alloc(64, byte);
const u256 = byte => Buffer.alloc(32, byte);
const u512 = byte => Buffer.alloc(64, byte);
const signerSet = {
  suite: 1,
  signatures: [
    {publicKey: hash(1), signature: signature(11)},
    {publicKey: hash(2), signature: signature(22)}
  ]
};

const fixtures = [
  {
    name: 'operator-record-v2',
    domain: 'meshmine/operator/v2',
    unsigned: Buffer.concat([
      u16(2), u8(2), hash(1), u64(2), u64(3),
      vector([hash(4), hash(5)]), option(hash(6)), u16(1)
    ]),
    signature: variable(signature(7))
  },
  {
    name: 'payout-bucket-v2',
    domain: 'meshmine/payout-bucket/v2',
    unsigned: Buffer.concat([
      u16(2), u8(2), hash(1), u64(2), u8(0), variable(Buffer.alloc(20, 3)),
      u32(4), option(u32(5))
    ]),
    signature: variable(signature(6))
  },
  {
    name: 'payout-snapshot-v2',
    domain: 'meshmine/payout-snapshot/v2',
    unsigned: Buffer.concat([
      u16(2), u8(2), u64(1), hash(1), hash(2), hash(3), u32(4),
      u512(5), u512(6),
      vector([Buffer.concat([
        hash(1), hash(7), u8(0), variable(Buffer.alloc(20, 8)), u512(9)
      ])]),
      vector([Buffer.concat([
        hash(2), hash(10), u8(0), variable(Buffer.alloc(20, 11)), u512(12)
      ])]),
      hash(13), hash(14), hash(15)
    ]),
    signature: signatureSet(signerSet)
  },
  {
    name: 'payout-plan-v2',
    domain: 'meshmine/payout-plan/v2',
    unsigned: Buffer.concat([
      u16(2), u8(2), u64(1), hash(2), u32(3), u16(1),
      vector([hash(4)]), hash(5), hash(6), u16(7), u16(8),
      vector([hash(9)]), vector([hash(10)]), hash(11)
    ]),
    signature: signatureSet(signerSet)
  },
  {
    name: 'template-core-v2',
    domain: 'meshmine/template-core/v2',
    unsigned: Buffer.concat([
      u16(2), u8(2), hash(1), u32(100), hash(2), hash(3),
      hash(4), hash(5), u64(6), vector([hash(7), hash(8)]),
      vector([hash(9)]), vector([]), u32(10), u32(0x207fffff),
      u64(11), hash(12)
    ]),
    signature: Buffer.alloc(0)
  },
  {
    name: 'body-package-v2',
    domain: 'meshmine/body-package/v2',
    unsigned: (() => {
      const template = Buffer.concat([
        u16(2), u8(2), hash(1), u32(100), hash(2), hash(3),
        hash(4), hash(5), u64(6), vector([hash(7), hash(8)]),
        vector([hash(9)]), vector([]), u32(10), u32(0x207fffff),
        u64(11), hash(12)
      ]);
      return Buffer.concat([
        u16(2), u8(2), template,
        domainHash('meshmine/template-core/v2', template),
        variable(Buffer.from([1, 2, 3])),
        vector([Buffer.from([4, 5]), Buffer.from([6])], variable),
        hash(13), hash(14), hash(15), hash(16), u32(17), u32(18),
        u64(19), u64(20), u64(21), u64(22), u64(23), u64(24), hash(25)
      ]);
    })(),
    signature: variable(signature(26))
  },
  {
    name: 'body-erasure-v2',
    domain: 'meshmine/body-erasure/v2',
    unsigned: Buffer.concat([
      u16(2), u8(2), hash(1), u32(2), u16(3), u16(4), u32(5),
      hash(6), u32(7), u16(8)
    ]),
    signature: Buffer.alloc(0)
  },
  {
    name: 'body-certificate-v2',
    domain: 'meshmine/body-certificate/v2',
    unsigned: Buffer.concat([
      u16(2), u8(2), hash(1), hash(2), u32(3), hash(4), u64(5), hash(6)
    ]),
    signature: signatureSet(signerSet)
  },
  {
    name: 'parent-certificate-v2',
    domain: 'meshmine/parent-certificate/v2',
    unsigned: Buffer.concat([
      u16(2), u8(2), hash(1), u32(2), u256(3), u64(4), u64(5), hash(6)
    ]),
    signature: signatureSet(signerSet)
  },
  {
    name: 'mask-session-v2',
    domain: 'meshmine/mask-session/v2',
    unsigned: Buffer.concat([
      u16(2), u8(2), u16(1), u64(2), hash(3), hash(4),
      u256(5), u256(6), u256(6), u16(7), u16(8), hash(9),
      hash(10), hash(11), u16(12), u64(13), u64(14), u64(15),
      u64(16), hash(17)
    ]),
    signature: signatureSet(signerSet)
  },
  {
    name: 'assignment-v2',
    domain: 'meshmine/assignment/v2',
    unsigned: Buffer.concat([
      u16(2), u8(2), hash(1), hash(2), hash(3), hash(4), hash(5),
      hash(6), u64(7), u64(8), Buffer.alloc(24, 9), u32(10), u32(11),
      u32(12), u256(13), u256(14), u8(0)
    ]),
    signature: variable(signature(15))
  },
  {
    name: 'share-v2',
    domain: 'meshmine/share/v2',
    unsigned: Buffer.concat([
      u16(2), u8(2), hash(1), hash(2), hash(3), hash(4),
      hash(5), u32(6), u64(7), Buffer.alloc(24, 8), hash(9),
      u256(10), vector([hash(11), hash(12)]), option(hash(13))
    ]),
    signature: variable(signature(14)),
    workKeyBody: Buffer.concat([
      hash(1), hash(3), u64(7), Buffer.alloc(24, 8), u32(6), hash(9)
    ])
  },
  {
    name: 'receipt-batch-v2',
    domain: 'meshmine/receipt-batch/v2',
    unsigned: Buffer.concat([
      u16(2), u8(2), hash(1), u64(2), hash(3),
      vector([hash(10), hash(11)]), vector([hash(4), hash(5)]),
      vector([u512(6), u512(7)]), hash(8), u64(9), u512(10)
    ]),
    signature: signatureSet(signerSet)
  },
  {
    name: 'session-close-v2',
    domain: 'meshmine/session-close/v2',
    unsigned: Buffer.concat([
      u16(2), u8(2), hash(1), hash(2), hash(3), hash(4), u64(5),
      u512(6), u16(7), hash(8), vector([hash(9)])
    ]),
    signature: signatureSet(signerSet)
  }
];

const generated = {
  wire_profile: 'meshmine-core-v2-research',
  vectors: fixtures.map(fixture => {
    const vector = {
      name: fixture.name,
      unsigned_hex: fixture.unsigned.toString('hex'),
      canonical_hex: Buffer.concat([
        fixture.unsigned,
        fixture.signature
      ]).toString('hex'),
      id_hex: domainHash(fixture.domain, fixture.unsigned).toString('hex')
    };
    if (fixture.workKeyBody) {
      vector.work_key_hex = domainHash(
        'meshmine/share-work-key/v2',
        fixture.workKeyBody
      ).toString('hex');
    }
    return vector;
  })
};

if (process.argv.includes('--stdout')) {
  process.stdout.write(`${JSON.stringify(generated, null, 2)}\n`);
} else if (process.argv.includes('--write')) {
  fs.writeFileSync(outputPath, `${JSON.stringify(generated, null, 2)}\n`);
  console.log(`wrote ${generated.vectors.length} Core v2 vectors to ${outputPath}`);
} else {
  const checked = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
  assert.deepStrictEqual(generated, checked);
  console.log(`verified ${generated.vectors.length} Core v2 Node.js golden vectors`);
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
