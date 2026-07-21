#!/usr/bin/env node
'use strict';

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const childProcess = require('child_process');
const fs = require('fs');
const path = require('path');
const secp256k1 = require('bcrypto/lib/secp256k1');

const {installMemoryOnlyDatabaseShim} = require('./memory-db-shim');
const hsdRoot = path.dirname(require.resolve('hsd/package.json'));
installMemoryOnlyDatabaseShim(hsdRoot);
const hsdPackage = require('hsd/package.json');
const Chain = require('hsd/lib/blockchain/chain');
const common = require('hsd/lib/script/common');
const consensus = require('hsd/lib/protocol/consensus');
const Address = require('hsd/lib/primitives/address');
const Covenant = require('hsd/lib/primitives/covenant');
const Input = require('hsd/lib/primitives/input');
const Outpoint = require('hsd/lib/primitives/outpoint');
const Output = require('hsd/lib/primitives/output');
const Script = require('hsd/lib/script/script');
const TX = require('hsd/lib/primitives/tx');
const Witness = require('hsd/lib/script/witness');

const ORACLE_REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const FIXTURE_ROOT = path.resolve(__dirname, '..', 'hsrd', 'fixtures', 'hsd', 'scripts');
const WRITE = process.argv.includes('--write');
const CHECK = process.argv.includes('--check') || !WRITE;

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function writeOrCheck(filename, value) {
  const target = path.join(FIXTURE_ROOT, filename);
  const expected = canonicalJson(value);

  if (WRITE) {
    fs.mkdirSync(path.dirname(target), {recursive: true});
    fs.writeFileSync(target, expected, {encoding: 'utf8', mode: 0o644});
  }

  if (CHECK) {
    const actual = fs.readFileSync(target, 'utf8');
    assert.strictEqual(
      actual,
      expected,
      `${path.relative(process.cwd(), target)} is not reproducible; run with --write`
    );
  }
}

function argumentValue(name) {
  const index = process.argv.indexOf(name);
  if (index === -1)
    return null;
  assert(index + 1 < process.argv.length, `${name} requires a value`);
  const value = process.argv[index + 1];
  assert(!value.startsWith('--'), `${name} requires a value`);
  return value;
}

function address(byte, size = 20) {
  return new Address({version: 0, hash: Buffer.alloc(size, byte)});
}

function noneCovenant() {
  return new Covenant();
}

function input(byte, index, sequence) {
  return new Input({
    prevout: new Outpoint(Buffer.alloc(32, byte), index),
    sequence: sequence >>> 0,
    witness: new Witness()
  });
}

function output(value, byte, size = 20) {
  return new Output({value, address: address(byte, size), covenant: noneCovenant()});
}

function createSignatureHashFixture() {
  const tx = new TX({
    version: 2,
    inputs: [
      input(0x11, 3, 0x12345678),
      input(0x22, 5, 0x87654321)
    ],
    outputs: [
      output(111111, 0xaa, 20),
      output(222222, 0xbb, 32),
      output(333333, 0xcc, 20)
    ],
    locktime: 0x34567890
  });
  const previousScript = Script.fromString('OP_2 OP_3 OP_ADD OP_5 OP_EQUAL');
  const previousValue = 987654321;
  const types = [];

  for (const modifier of [0, common.hashType.NOINPUT, common.hashType.ANYONECANPAY,
    common.hashType.NOINPUT | common.hashType.ANYONECANPAY]) {
    for (const base of [common.hashType.ALL, common.hashType.NONE,
      common.hashType.SINGLE, common.hashType.SINGLEREVERSE]) {
      types.push(modifier | base);
    }
  }

  const vectors = [];
  for (let inputIndex = 0; inputIndex < tx.inputs.length; inputIndex++) {
    for (const type of types) {
      vectors.push({
        inputIndex,
        type,
        hash: tx.signatureHash(inputIndex, previousScript, previousValue, type).toString('hex')
      });
    }
  }

  const signatureTypes = [];
  for (const type of [
    0, 1, 2, 3, 4, 5, 0x20, 0x21, 0x40, 0x41, 0x44, 0x45,
    0x80, 0x81, 0x84, 0x85, 0xc1, 0xc4, 0xc5, 0xff
  ]) {
    const signature = Buffer.alloc(65, 0);
    signature[64] = type;
    // isSignatureEncoding also enforces low-S. A zero compact signature is
    // low-S, which isolates the hash-type rule exercised by this vector.
    signatureTypes.push({type, valid: common.isSignatureEncoding(signature)});
  }

  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: ORACLE_REVISION,
      hsdVersion: hsdPackage.version
    },
    transactionRaw: tx.encode().toString('hex'),
    previousScriptRaw: previousScript.encode().toString('hex'),
    previousValue,
    vectors,
    signatureTypes
  };
}

function createScriptExecutionFixture() {
  const signingKey = Buffer.alloc(32, 0);
  signingKey[31] = 1;
  const signingPublicKey = secp256k1.publicKeyCreate(signingKey, true);
  const signingScript = `0x21 0x${signingPublicKey.toString('hex')} OP_CHECKSIG`;
  const signingVerifyScript =
    `0x21 0x${signingPublicKey.toString('hex')} OP_CHECKSIGVERIFY OP_1`;
  const invalidSigningScript =
    `0x21 0x${signingPublicKey.toString('hex')} OP_CHECKSIG OP_NOT`;
  const multisigScript =
    `OP_1 0x21 0x${signingPublicKey.toString('hex')} OP_1 OP_CHECKMULTISIG`;
  const cases = [
    {id: 'empty-script-true-witness', script: '', witness: ['01']},
    {id: 'negative-zero-is-false', script: 'OP_NOT', witness: ['80']},
    {id: 'nested-conditional', script: 'OP_IF OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF OP_ELSE OP_0 OP_ENDIF', witness: ['01', '01']},
    {id: 'unexecuted-reserved', script: 'OP_IF OP_RESERVED OP_ENDIF OP_1', witness: ['']},
    {id: 'disabled-opcode-fails-in-dead-branch', script: 'OP_IF OP_CAT OP_ENDIF OP_1', witness: ['']},
    {id: 'unknown-opcode-is-safe-in-dead-branch', script: 'OP_IF 0xba OP_ENDIF OP_1', witness: ['']},
    {id: 'unbalanced-conditional', script: 'OP_1 OP_IF'},
    {id: 'alt-stack-round-trip', script: 'OP_TOALTSTACK OP_FROMALTSTACK OP_1 OP_EQUAL', witness: ['01']},
    {id: 'two-duplicate', script: 'OP_2DUP OP_ADD OP_3 OP_EQUALVERIFY OP_ADD OP_3 OP_EQUAL', witness: ['01', '02']},
    {id: 'three-duplicate', script: 'OP_3DUP OP_ADD OP_ADD OP_6 OP_EQUALVERIFY OP_2DROP OP_1 OP_EQUAL', witness: ['01', '02', '03']},
    {id: 'two-over', script: 'OP_2OVER OP_ADD OP_3 OP_EQUALVERIFY OP_2DROP OP_ADD OP_3 OP_EQUAL', witness: ['01', '02', '03', '04']},
    {id: 'two-rotate', script: 'OP_2ROT OP_2DROP OP_2DROP OP_ADD OP_7 OP_EQUAL', witness: ['01', '02', '03', '04', '05', '06']},
    {id: 'two-swap', script: 'OP_2SWAP OP_ADD OP_3 OP_EQUALVERIFY OP_ADD OP_7 OP_EQUAL', witness: ['01', '02', '03', '04']},
    {id: 'tuck', script: 'OP_TUCK OP_ADD OP_3 OP_EQUALVERIFY OP_2 OP_EQUAL', witness: ['01', '02']},
    {id: 'pick-minimal-depth', script: 'OP_PICK OP_EQUAL', witness: ['01', '']},
    {id: 'roll-minimal-depth', script: 'OP_ROLL OP_DROP OP_1', witness: ['01', '']},
    {id: 'pick-nonminimal-depth-without-flag', script: 'OP_PICK OP_EQUAL', witness: ['01', '0000']},
    {id: 'roll-nonminimal-depth-without-flag', script: 'OP_ROLL OP_DROP OP_1', witness: ['01', '0000']},
    {id: 'pick-nonminimal-depth-with-minimaldata', script: 'OP_PICK OP_EQUAL', witness: ['01', '0000'], flags: ['MINIMALDATA']},
    {id: 'roll-negative-depth', script: 'OP_1NEGATE OP_ROLL', witness: ['01']},
    {id: 'arithmetic-five-byte-result', script: 'OP_1ADD 2147483648 OP_EQUAL', witness: ['ffffff7f']},
    {id: 'arithmetic-overflow-on-reuse', script: 'OP_1ADD OP_1ADD', witness: ['ffffff7f']},
    {id: 'within-lower-inclusive', script: 'OP_WITHIN', witness: ['01', '01', '02']},
    {id: 'within-upper-exclusive', script: 'OP_WITHIN OP_NOT', witness: ['02', '01', '02']},
    {id: 'ripemd160-empty', script: 'OP_RIPEMD160 0x14 0x9c1185a5c5e9fc54612808977ee8f548b2258d31 OP_EQUAL', witness: ['']},
    {id: 'sha1-abc', script: 'OP_SHA1 0x14 0xa9993e364706816aba3e25717850c26c9cd0d89d OP_EQUAL', witness: ['616263']},
    {id: 'sha256-abc', script: 'OP_SHA256 0x20 0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad OP_EQUAL', witness: ['616263']},
    {id: 'hash160-empty', script: 'OP_HASH160 0x14 0xb472a266d0bd89c13706a4132ccfb16f7c3b9fcb OP_EQUAL', witness: ['']},
    {id: 'hash256-empty', script: 'OP_HASH256 0x20 0x5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456 OP_EQUAL', witness: ['']},
    {id: 'blake160-empty', script: 'OP_BLAKE160 0x14 0x3345524abf6bbe1809449224b5972c41790b6cf2 OP_EQUAL', witness: ['']},
    {id: 'blake256-empty', script: 'OP_BLAKE256 0x20 0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8 OP_EQUAL', witness: ['']},
    {id: 'sha3-empty', script: 'OP_SHA3 0x20 0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a OP_EQUAL', witness: ['']},
    {id: 'keccak-empty', script: 'OP_KECCAK 0x20 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 OP_EQUAL', witness: ['']},
    {id: 'nonminimal-push-without-flag', raw: '4c0101', witness: []},
    {id: 'nonminimal-push-with-minimaldata', raw: '4c0101', witness: [], flags: ['MINIMALDATA']},
    {id: 'minimal-if-true', script: 'OP_IF OP_1 OP_ENDIF', witness: ['01'], flags: ['MINIMALIF']},
    {id: 'minimal-if-rejects-two', script: 'OP_IF OP_1 OP_ENDIF', witness: ['02'], flags: ['MINIMALIF']},
    {id: 'nop-policy', script: 'OP_NOP4 OP_1', flags: ['DISCOURAGE_UPGRADABLE_NOPS']},
    {id: 'nop-policy-dead-branch', script: 'OP_IF OP_NOP4 OP_ENDIF OP_1', witness: [''], flags: ['DISCOURAGE_UPGRADABLE_NOPS']},
    {id: 'check-locktime-satisfied', script: '100 OP_CHECKLOCKTIMEVERIFY OP_DROP OP_1', locktime: 100, sequence: 0xfffffffe},
    {id: 'check-locktime-final-sequence', script: '100 OP_CHECKLOCKTIMEVERIFY OP_DROP OP_1', locktime: 100},
    {id: 'check-locktime-type-mismatch', script: '500000000 OP_CHECKLOCKTIMEVERIFY OP_DROP OP_1', locktime: 100, sequence: 0xfffffffe},
    {id: 'check-sequence-satisfied', script: '5 OP_CHECKSEQUENCEVERIFY OP_DROP OP_1', version: 2, sequence: 5},
    {id: 'check-sequence-old-transaction', script: '5 OP_CHECKSEQUENCEVERIFY OP_DROP OP_1', version: 1, sequence: 5},
    {id: 'check-sequence-type-mismatch', script: '4194305 OP_CHECKSEQUENCEVERIFY OP_DROP OP_1', version: 2, sequence: 5},
    {id: 'type-none-covenant', script: 'OP_TYPE OP_0 OP_EQUAL'},
    {id: 'checksig-valid', script: signingScript, signingKey},
    {id: 'checksigverify-valid', script: signingVerifyScript, signingKey},
    {id: 'checksig-invalid-without-nullfail', script: invalidSigningScript, signingKey, tamperSignature: true},
    {id: 'checksig-invalid-with-nullfail', script: invalidSigningScript, signingKey, tamperSignature: true, flags: ['NULLFAIL']},
    {id: 'checkmultisig-valid', script: multisigScript, signingKey, multisig: true},
    {id: 'checkmultisig-zero-keys', script: 'OP_0 OP_0 OP_0 OP_CHECKMULTISIG OP_VERIFY OP_DEPTH OP_0 OP_EQUAL'},
    {id: 'op-return', script: 'OP_RETURN'},
    {id: 'reserved', script: 'OP_RESERVED'},
    {id: 'equal-verify', script: 'OP_EQUALVERIFY OP_1', witness: ['01', '02']},
    {id: 'verify-false', script: 'OP_VERIFY OP_1', witness: ['']}
  ];

  const flagValues = {
    MINIMALDATA: common.flags.VERIFY_MINIMALDATA,
    DISCOURAGE_UPGRADABLE_NOPS: common.flags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM:
      common.flags.VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    MINIMALIF: common.flags.VERIFY_MINIMALIF,
    NULLFAIL: common.flags.VERIFY_NULLFAIL
  };

  const vectors = cases.map((item, index) => {
    const script = item.raw != null
      ? Script.decode(Buffer.from(item.raw, 'hex'))
      : Script.fromString(item.script);
    const address = Address.fromScript(script);
    const witnessItems = (item.witness || []).map(value => Buffer.from(value, 'hex'));
    witnessItems.push(script.encode());
    const witness = new Witness(witnessItems);
    const tx = new TX({
      version: item.version == null ? 1 : item.version,
      inputs: [new Input({
        prevout: new Outpoint(Buffer.alloc(32, 0x40 + (index % 32)), index),
        sequence: item.sequence == null ? 0xffffffff : item.sequence,
        witness
      })],
      outputs: [output(item.value == null ? 1 : item.value, 0xee, 20)],
      locktime: item.locktime == null ? 0 : item.locktime
    });
    if (item.signingKey) {
      const signature = tx.signature(
        0,
        script,
        item.value == null ? 1 : item.value,
        item.signingKey,
        common.hashType.ALL
      );
      if (item.tamperSignature)
        signature[0] ^= 1;
      tx.inputs[0].witness = new Witness(item.multisig
        ? [Buffer.alloc(0), signature, script.encode()]
        : [signature, script.encode()]);
    }
    const flagNames = item.flags || [];
    const flags = flagNames.reduce((value, name) => value | flagValues[name], 0);
    let result = 'OK';
    try {
      Script.verify(
        tx.inputs[0].witness,
        address,
        tx,
        0,
        item.value == null ? 1 : item.value,
        flags
      );
    } catch (error) {
      assert.strictEqual(typeof error.code, 'string', `${item.id} returned an unclassified error`);
      result = error.code;
    }
    return {
      id: item.id,
      scriptRaw: script.encode().toString('hex'),
      witness: tx.inputs[0].witness.items
        .slice(0, -1)
        .map(value => value.toString('hex')),
      transactionRaw: tx.encode().toString('hex'),
      previousValue: item.value == null ? 1 : item.value,
      addressVersion: address.version,
      addressHash: address.hash.toString('hex'),
      flags: flagNames,
      result
    };
  });

  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: ORACLE_REVISION,
      hsdVersion: hsdPackage.version,
      source: 'lib/script/script.js#verify/execute'
    },
    vectors
  };
}

function createFullScriptExecutionFixture(hsdSource) {
  const source = fs.realpathSync(hsdSource);
  const revision = childProcess.execFileSync(
    'git',
    ['-C', source, 'rev-parse', 'HEAD'],
    {encoding: 'utf8'}
  ).trim();
  assert.strictEqual(
    revision,
    ORACLE_REVISION,
    `HSD source must be pinned to ${ORACLE_REVISION}`
  );
  const corpusPath = path.join(source, 'test', 'data', 'script-tests.json');
  const cases = JSON.parse(fs.readFileSync(corpusPath, 'utf8'));
  assert(Array.isArray(cases) && cases.length > 0, 'HSD script corpus is empty');

  const vectors = cases.map((item, index) => {
    const script = Script.fromString(item.script);
    const address = Address.fromScript(script);
    const witness = Witness.fromJSON(item.witness);
    witness.items.push(script.encode());
    const previous = new TX({
      version: 1,
      inputs: [{
        prevout: {
          hash: consensus.ZERO_HASH,
          index: 0xffffffff
        },
        witness: [Buffer.alloc(1), Buffer.alloc(1)],
        sequence: 0xffffffff
      }],
      outputs: [{address, value: item.value}],
      locktime: 0
    });
    const tx = new TX({
      version: 1,
      inputs: [{
        prevout: {
          hash: previous.hash(),
          index: 0
        },
        witness,
        sequence: item.sequence
      }],
      outputs: [{address: new Address(), value: item.value}],
      locktime: item.locktime
    });
    let flags = 0;
    for (const name of item.flags) {
      const flag = common.flags[`VERIFY_${name}`];
      assert.notStrictEqual(flag, undefined, `unknown HSD script flag ${name}`);
      flags |= flag;
    }
    let result = 'OK';
    try {
      Script.verify(witness, address, tx, 0, item.value, flags);
    } catch (error) {
      assert.strictEqual(
        typeof error.code,
        'string',
        `HSD script case ${index} returned an unclassified error`
      );
      result = error.code;
    }
    assert.strictEqual(
      result,
      item.result,
      `HSD script corpus case ${index} no longer matches its declared result`
    );
    return {
      id: `hsd-script-${index.toString().padStart(4, '0')}`,
      comments: item.comments || null,
      scriptRaw: script.encode().toString('hex'),
      witness: item.witness,
      transactionRaw: tx.encode().toString('hex'),
      previousValue: item.value,
      addressVersion: address.version,
      addressHash: address.hash.toString('hex'),
      flags: item.flags,
      result
    };
  });

  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: ORACLE_REVISION,
      hsdVersion: hsdPackage.version,
      source: 'test/data/script-tests.json via lib/script/script.js#verify/execute'
    },
    vectors
  };
}

async function createSequenceLockFixture() {
  const nextHeight = 250;
  const tip = {height: nextHeight - 1, marker: 'tip'};
  const ancestorTimes = new Map([
    [0, 1000000],
    [9, 1009000],
    [10, 1010000],
    [24, 1024000],
    [25, 1025000],
    [99, 1099000],
    [100, 1100000],
    [248, 1248000],
    [249, 1249000]
  ]);
  const chain = {
    height: tip.height,
    getLocks: Chain.prototype.getLocks,
    async getAncestor(_tip, height) {
      return {height};
    },
    async getMedianTime(entry) {
      if (entry === tip)
        return ancestorTimes.get(249);
      const time = ancestorTimes.get(entry.height);
      assert.notStrictEqual(time, undefined, `missing fixture MTP for ${entry.height}`);
      return time;
    }
  };

  const cases = [
    {
      id: 'disabled-sequence',
      sequences: [consensus.SEQUENCE_DISABLE_FLAG | 123],
      coinHeights: [10]
    },
    {
      id: 'height-relative-confirmed',
      sequences: [5],
      coinHeights: [100]
    },
    {
      id: 'height-relative-unconfirmed',
      sequences: [2],
      coinHeights: [-1]
    },
    {
      id: 'time-relative-confirmed',
      sequences: [consensus.SEQUENCE_TYPE_FLAG | 3],
      coinHeights: [25]
    },
    {
      id: 'mixed-maxima',
      sequences: [7, consensus.SEQUENCE_TYPE_FLAG | 4, 2],
      coinHeights: [10, 100, 24]
    }
  ];

  const vectors = [];
  for (const item of cases) {
    const inputs = item.sequences.map((sequence, index) => input(0x30 + index, index, sequence));
    const tx = new TX({
      version: 2,
      inputs,
      outputs: [output(1, 0xdd, 20)],
      locktime: 0
    });
    const heights = new Map(
      inputs.map((txInput, index) => [txInput.prevout.toKey().toString('hex'), item.coinHeights[index]])
    );
    const view = {
      getHeight(prevout) {
        const height = heights.get(prevout.toKey().toString('hex'));
        assert.notStrictEqual(height, undefined, 'missing coin height');
        return height;
      }
    };
    const [minimumHeight, minimumTime] = await Chain.prototype.getLocks.call(
      chain,
      tip,
      tx,
      view,
      0
    );
    const valid = await Chain.prototype.verifyLocks.call(chain, tip, tx, view, 0);
    vectors.push({
      id: item.id,
      transactionRaw: tx.encode().toString('hex'),
      coinHeights: item.coinHeights,
      nextHeight,
      tipMedianTime: ancestorTimes.get(249),
      ancestorMedianTimes: Object.fromEntries(
        [...ancestorTimes.entries()].map(([height, time]) => [String(height), time])
      ),
      minimumHeight,
      minimumTime,
      valid
    });
  }

  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: ORACLE_REVISION,
      source: 'lib/blockchain/chain.js#getLocks/verifyLocks'
    },
    vectors
  };
}

async function main() {
  const hsdSource = argumentValue('--hsd-source');
  const fullScriptOutput = argumentValue('--full-script-output');
  assert.strictEqual(
    hsdSource == null,
    fullScriptOutput == null,
    '--hsd-source and --full-script-output must be supplied together'
  );
  if (hsdSource != null) {
    const output = path.resolve(fullScriptOutput);
    fs.writeFileSync(
      output,
      canonicalJson(createFullScriptExecutionFixture(hsdSource)),
      {encoding: 'utf8', mode: 0o600}
    );
    process.stdout.write(`wrote full HSD script corpus to ${output}\n`);
    return;
  }
  writeOrCheck('sighash-v1.json', createSignatureHashFixture());
  writeOrCheck('sequence-locks-v1.json', await createSequenceLockFixture());
  writeOrCheck('execution-v1.json', createScriptExecutionFixture());
  process.stdout.write(
    `${WRITE ? 'wrote' : 'verified'} hsrd script fixtures at ${FIXTURE_ROOT}\n`
  );
}

main().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
