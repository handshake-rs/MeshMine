#!/usr/bin/env node
'use strict';

// Generates deterministic HSD NameState codec fixtures.

const assert = require('assert');
const fs = require('fs');
const path = require('path');

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const pkg = require('./node_modules/hsd/package.json');
const NameState = require('./node_modules/hsd/lib/covenants/namestate');
const Outpoint = require('./node_modules/hsd/lib/primitives/outpoint');

const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(ROOT, 'hsrd/fixtures/hsd/name-states/codec-v1.json');
const REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';

function vector(id, configure) {
  const state = new NameState();
  state.nameHash = Buffer.alloc(32, id.charCodeAt(0));
  configure(state);
  const raw = state.encode();
  const decoded = NameState.decode(raw);
  decoded.nameHash = state.nameHash;
  assert.strictEqual(decoded.encode().toString('hex'), raw.toString('hex'));
  return {
    id,
    nameHash: state.nameHash.toString('hex'),
    raw: raw.toString('hex'),
    json: {
      name: state.name.toString('binary'),
      height: state.height,
      renewal: state.renewal,
      ownerHash: state.owner.hash.toString('hex'),
      ownerIndex: state.owner.index,
      value: state.value,
      highest: state.highest,
      data: state.data.toString('hex'),
      transfer: state.transfer,
      revoked: state.revoked,
      claimed: state.claimed,
      renewals: state.renewals,
      registered: state.registered,
      expired: state.expired,
      weak: state.weak
    }
  };
}

const output = {
  schema: 1,
  oracle: {
    repository: 'handshake-org/hsd',
    revision: REVISION,
    hsdVersion: pkg.version
  },
  scope: 'exact NameState value codec; name hash is the external authenticated-tree key',
  vectors: [
    vector('minimal', state => {
      state.name = Buffer.from('alpha', 'ascii');
      state.height = 100;
      state.renewal = 100;
    }),
    vector('populated', state => {
      state.name = Buffer.from('handshake', 'ascii');
      state.height = 0x10203040;
      state.renewal = 0x50607080;
      state.owner = new Outpoint(Buffer.alloc(32, 0x42), 70000);
      state.value = 123456789;
      state.highest = 987654321;
      state.data = Buffer.from('00010203fefdfc', 'hex');
      state.transfer = 1234;
      state.revoked = 5678;
      state.claimed = 9012;
      state.renewals = 300;
      state.registered = true;
      state.expired = true;
      state.weak = true;
    })
  ]
};

const text = `${JSON.stringify(output, null, 2)}\n`;
const write = process.argv.includes('--write');
const check = process.argv.includes('--check');
assert(write || check, 'use --write and/or --check');

if (write) {
  fs.mkdirSync(path.dirname(OUT), {recursive: true});
  fs.writeFileSync(OUT, text);
  console.log(`wrote ${path.relative(ROOT, OUT)}`);
}

if (check) {
  const current = fs.readFileSync(OUT, 'utf8');
  assert.strictEqual(current, text, `${OUT} is not reproducible`);
  console.log(`verified ${path.relative(ROOT, OUT)}`);
}
