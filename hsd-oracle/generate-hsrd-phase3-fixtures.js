#!/usr/bin/env node
'use strict';

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const hsdPackage = require('hsd/package.json');
const Address = require('hsd/lib/primitives/address');
const Covenant = require('hsd/lib/primitives/covenant');
const Input = require('hsd/lib/primitives/input');
const Outpoint = require('hsd/lib/primitives/outpoint');
const Output = require('hsd/lib/primitives/output');
const TX = require('hsd/lib/primitives/tx');
const CoinView = require('hsd/lib/coins/coinview');
const Network = require('hsd/lib/protocol/network');
const rules = require('hsd/lib/covenants/rules');

const ORACLE_REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const FIXTURE_ROOT = path.resolve(__dirname, '..', 'hsrd', 'fixtures', 'hsd', 'covenants');
const TARGET = path.join(FIXTURE_ROOT, 'linkage-v1.json');
const WRITE = process.argv.includes('--write');
const CHECK = process.argv.includes('--check') || !WRITE;
const network = Network.get('regtest');

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function u32(value) {
  const bytes = Buffer.allocUnsafe(4);
  bytes.writeUInt32LE(value >>> 0, 0);
  return bytes;
}

function address(byte, size = 20, version = 0) {
  return new Address({version, hash: Buffer.alloc(size, byte)});
}

function outpoint(byte, index = 0) {
  return new Outpoint(Buffer.alloc(32, byte), index);
}

function covenant(type, items = []) {
  return new Covenant(type, items.map(item => Buffer.from(item)));
}

function nameContext(nameText = 'alpha', start = 100) {
  const name = Buffer.from(nameText, 'ascii');
  return {name, nameHash: rules.hashName(name), start};
}

function none() {
  return covenant(rules.types.NONE);
}

function open(context) {
  return covenant(rules.types.OPEN, [context.nameHash, u32(0), context.name]);
}

function bid(context, value, nonce) {
  return covenant(rules.types.BID, [
    context.nameHash,
    u32(context.start),
    context.name,
    rules.blind(value, nonce)
  ]);
}

function reveal(context, nonce) {
  return covenant(rules.types.REVEAL, [context.nameHash, u32(context.start), nonce]);
}

function redeem(context) {
  return covenant(rules.types.REDEEM, [context.nameHash, u32(context.start)]);
}

function claim(context) {
  return covenant(rules.types.CLAIM, [
    context.nameHash,
    u32(context.start),
    context.name,
    Buffer.from([0]),
    Buffer.alloc(32, 0x81),
    u32(1)
  ]);
}

function register(context, resource = Buffer.alloc(0)) {
  return covenant(rules.types.REGISTER, [
    context.nameHash,
    u32(context.start),
    resource,
    Buffer.alloc(32, 0x82)
  ]);
}

function update(context, resource = Buffer.alloc(0)) {
  return covenant(rules.types.UPDATE, [context.nameHash, u32(context.start), resource]);
}

function renew(context) {
  return covenant(rules.types.RENEW, [
    context.nameHash,
    u32(context.start),
    Buffer.alloc(32, 0x83)
  ]);
}

function transfer(context, destination) {
  return covenant(rules.types.TRANSFER, [
    context.nameHash,
    u32(context.start),
    Buffer.from([destination.version]),
    destination.hash
  ]);
}

function finalize(context) {
  return covenant(rules.types.FINALIZE, [
    context.nameHash,
    u32(context.start),
    context.name,
    Buffer.from([0]),
    u32(1),
    u32(2),
    Buffer.alloc(32, 0x84)
  ]);
}

function revoke(context) {
  return covenant(rules.types.REVOKE, [context.nameHash, u32(context.start)]);
}

function makeCase({
  id,
  expected,
  inputs,
  outputs
}) {
  const txInputs = inputs.map(input => new Input({
    prevout: input.prevout,
    sequence: 0xffffffff
  }));
  const txOutputs = outputs.map(output => new Output({
    value: output.value,
    address: output.address,
    covenant: output.covenant
  }));
  const tx = new TX({version: 1, inputs: txInputs, outputs: txOutputs, locktime: 0});
  const view = new CoinView();

  for (const input of inputs) {
    view.addOutput(input.prevout, new Output({
      value: input.value,
      address: input.address,
      covenant: input.covenant
    }));
  }

  const oracleResult = tx.verifyCovenants(view, 200, network);
  const accepted = oracleResult >= 0;
  assert.strictEqual(accepted, expected, `${id}: unexpected hsd result ${oracleResult}`);

  return {
    id,
    accepted,
    oracleResult,
    transactionRaw: tx.encode().toString('hex'),
    inputCoins: inputs.map(input => ({
      outpointTxid: input.prevout.hash.toString('hex'),
      outpointIndex: input.prevout.index,
      value: input.value,
      height: 1,
      coinbase: false,
      addressVersion: input.address.version,
      addressHash: input.address.hash.toString('hex'),
      covenantType: input.covenant.type,
      covenantItems: input.covenant.items.map(item => item.toString('hex'))
    }))
  };
}

function buildCases() {
  const context = nameContext();
  const other = nameContext('bravo', 101);
  const owner = address(0x10);
  const otherOwner = address(0x11);
  const destination = address(0x12, 32);
  const nonce = Buffer.alloc(32, 0x21);
  const cases = [];

  const single = (id, expected, spent, created, options = {}) => {
    const prevout = outpoint(0x30 + cases.length, 0);
    const inputAddress = options.inputAddress || owner;
    const outputAddress = options.outputAddress || inputAddress;
    const inputValue = options.inputValue == null ? 1000 : options.inputValue;
    const outputValue = options.outputValue == null ? inputValue : options.outputValue;
    const outputs = created == null ? [] : [{
      value: outputValue,
      address: outputAddress,
      covenant: created
    }];
    cases.push(makeCase({
      id,
      expected,
      inputs: [{
        prevout,
        value: inputValue,
        address: inputAddress,
        covenant: spent
      }],
      outputs
    }));
  };

  single('none-to-none', true, none(), none());
  single('none-to-open', true, none(), open(context));
  single('redeem-to-bid', true, redeem(context), bid(context, 700, nonce), {
    outputValue: 700
  });
  single('none-to-update-rejected', false, none(), update(context));

  const first = outpoint(0x40, 0);
  const second = outpoint(0x41, 0);
  cases.push(makeCase({
    id: 'unlinked-none-input-with-shorter-output-vector',
    expected: true,
    inputs: [
      {prevout: first, value: 600, address: owner, covenant: none()},
      {prevout: second, value: 400, address: owner, covenant: none()}
    ],
    outputs: [{value: 900, address: owner, covenant: none()}]
  }));

  const alignedNone = outpoint(0x42, 0);
  const alignedRegister = outpoint(0x43, 0);
  cases.push(makeCase({
    id: 'multi-input-linked-output-index-alignment',
    expected: true,
    inputs: [
      {prevout: alignedNone, value: 600, address: owner, covenant: none()},
      {prevout: alignedRegister, value: 400, address: owner, covenant: register(context)}
    ],
    outputs: [
      {value: 600, address: owner, covenant: none()},
      {value: 400, address: owner, covenant: update(context)}
    ]
  }));
  cases.push(makeCase({
    id: 'multi-input-name-link-missing-at-own-index',
    expected: false,
    inputs: [
      {prevout: alignedNone, value: 600, address: owner, covenant: none()},
      {prevout: alignedRegister, value: 400, address: owner, covenant: register(context)}
    ],
    outputs: [{value: 600, address: owner, covenant: none()}]
  }));

  single('bid-to-reveal', true, bid(context, 700, nonce), reveal(context, nonce), {
    inputValue: 1000,
    outputValue: 700
  });
  single('bid-missing-linked-output', false, bid(context, 700, nonce), null);
  single('bid-to-wrong-covenant', false, bid(context, 700, nonce), redeem(context), {
    outputValue: 700
  });
  single('bid-name-mismatch', false, bid(context, 700, nonce), reveal(other, nonce), {
    outputValue: 700
  });
  const wrongHeight = {...context, start: context.start + 1};
  single('bid-height-mismatch', false, bid(context, 700, nonce), reveal(wrongHeight, nonce), {
    outputValue: 700
  });
  const wrongNonce = Buffer.alloc(32, 0x22);
  single('bid-blind-mismatch', false, bid(context, 700, nonce), reveal(context, wrongNonce), {
    outputValue: 700
  });
  single('bid-value-inflation', false, bid(context, 1200, nonce), reveal(context, nonce), {
    inputValue: 1000,
    outputValue: 1200
  });

  single('reveal-to-register', true, reveal(context, nonce), register(context), {
    outputValue: 500
  });
  single('reveal-to-redeem', true, reveal(context, nonce), redeem(context), {
    outputValue: 500
  });
  single('claim-to-register', true, claim(context), register(context));
  single('claim-to-redeem-rejected', false, claim(context), redeem(context));
  single('reveal-register-address-mismatch', false, reveal(context, nonce), register(context), {
    outputAddress: otherOwner
  });

  single('register-to-update', true, register(context), update(context));
  single('update-to-renew', true, update(context), renew(context));
  single('renew-to-transfer', true, renew(context), transfer(context, destination));
  single('finalize-to-revoke', true, finalize(context), revoke(context));
  single('register-value-mismatch', false, register(context), update(context), {
    inputValue: 1000,
    outputValue: 999
  });
  single('register-address-mismatch', false, register(context), update(context), {
    outputAddress: otherOwner
  });
  single('register-name-mismatch', false, register(context), update(other));
  single('register-to-none-rejected', false, register(context), none());

  single('transfer-to-finalize', true, transfer(context, destination), finalize(context), {
    inputAddress: owner,
    outputAddress: destination
  });
  single('transfer-to-update', true, transfer(context, destination), update(context));
  single('transfer-finalize-target-mismatch', false, transfer(context, destination), finalize(context), {
    outputAddress: otherOwner
  });
  single('revoke-is-unspendable', false, revoke(context), none());

  single('unknown-to-none', true, covenant(99), none());
  single('unknown-to-name-rejected', false, covenant(99), open(context));

  return cases;
}

function main() {
  const fixture = {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: ORACLE_REVISION,
      hsdVersion: hsdPackage.version
    },
    scope: 'non-coinbase covenant linkage only; name-state transitions are not covered',
    cases: buildCases()
  };
  const expected = canonicalJson(fixture);

  if (WRITE) {
    fs.mkdirSync(FIXTURE_ROOT, {recursive: true});
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

  console.log(`${path.relative(process.cwd(), TARGET)}: ${fixture.cases.length} hsd covenant-link cases verified`);
}

main();
