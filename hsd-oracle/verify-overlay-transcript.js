#!/usr/bin/env node
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const hsd = resolveHsd();
const BLAKE2b = require(require.resolve('bcrypto/lib/blake2b', {paths: [hsd]}));
const EVENT_DOMAIN = 'meshmine/testnet-event/v2';

function main() {
  const filename = process.argv[2];
  if (!filename)
    throw new Error('usage: verify-overlay-transcript.js TRANSCRIPT.json');
  const transcript = JSON.parse(fs.readFileSync(filename, 'utf8'));
  assert.strictEqual(transcript.protocol_version, 2);
  assert.strictEqual(transcript.network_id, 2);
  assert.strictEqual(transcript.implementation, 'meshmine-rust-local-overlay-harness/v2');
  assert.strictEqual(transcript.verifier_contract,
    'hsd-oracle/verify-overlay-transcript.js');
  assert(Number.isSafeInteger(transcript.session_count));
  assert(transcript.session_count >= 1000,
    'WP14 long-run evidence requires at least 1000 sessions');
  assert.strictEqual(transcript.opening_threshold, 3);
  assert.strictEqual(transcript.committee_members, 5);
  fixedHex(transcript.seed, 32);

  let previous = Buffer.alloc(32);
  const kinds = new Map();
  const accepted = new Map();
  const recovered = new Map();
  for (let index = 0; index < transcript.events.length; index++) {
    const event = transcript.events[index];
    assert.strictEqual(event.sequence, index);
    assert.strictEqual(event.previous_event_hash, previous.toString('hex'));
    const subject = fixedHex(event.subject, 32);
    const evidence = fixedHex(event.evidence_root, 32);
    assert(typeof event.kind === 'string' && event.kind.length > 0);
    assert(typeof event.outcome === 'string' && event.outcome.length > 0);
    if (event.session !== null) {
      assert(Number.isSafeInteger(event.session));
      assert(event.session >= 0 && event.session < transcript.session_count);
    }
    const expected = eventHash(event, previous, subject, evidence);
    assert.strictEqual(event.event_hash, expected.toString('hex'),
      `event hash mismatch at sequence ${index}`);
    previous = expected;
    if (!kinds.has(event.kind))
      kinds.set(event.kind, []);
    kinds.get(event.kind).push(index);
    if (event.kind === 'accepted_winner') {
      assert(event.session !== null);
      assert(!accepted.has(event.session), 'duplicate accepted-winner session');
      accepted.set(event.session, {index, subject: event.subject});
    }
    if (event.kind === 'winner_recovered') {
      assert(event.session !== null);
      assert(!recovered.has(event.session), 'duplicate recovery session');
      recovered.set(event.session, {index, subject: event.subject});
    }
  }
  assert.strictEqual(transcript.summary.final_event_hash, previous.toString('hex'));
  assert.strictEqual(accepted.size, transcript.session_count);
  assert.strictEqual(recovered.size, transcript.session_count);
  for (let session = 0; session < transcript.session_count; session++) {
    const first = accepted.get(session);
    const second = recovered.get(session);
    assert(first && second, `missing accepted/recovered pair for session ${session}`);
    assert.strictEqual(second.subject, first.subject);
    assert(second.index > first.index, 'recovery must follow receipt acceptance');
  }

  requireOrdered(kinds, 'network_partition_started', 'network_partition_reconciled');
  requireOrdered(kinds, 'body_unavailability_detected', 'body_reconstructed');
  requireOrdered(kinds, 'hns_plan_paid', 'hns_reorg_rollback');
  requireOrdered(kinds, 'hns_reorg_rollback', 'hns_plan_repaid');
  requireOrdered(kinds, 'committee_liveness_failure',
    'committee_replacement_activated');
  requireSingle(kinds, 'receipt_equivocation_detected');
  requireSingle(kinds, 'early_mask_reveal_rejected');
  const early = kinds.get('early_mask_reveal_rejected')[0];
  assert(early < recovered.get(0).index,
    'early reveal rejection must precede timed recovery');

  assert.strictEqual(transcript.summary.accepted_winners, transcript.session_count);
  assert.strictEqual(transcript.summary.recovered_winners, transcript.session_count);
  assert.strictEqual(transcript.summary.unrecoverable_winners_under_assumption, 0);
  assert.strictEqual(transcript.summary.injected_incidents, 6);
  assert.strictEqual(transcript.summary.research_backend_production_eligible, false);
  assert.strictEqual(transcript.summary.public_deployment_verified, false);

  console.log(JSON.stringify({
    status: 'independent-overlay-transcript-valid',
    implementation: transcript.implementation,
    sessions: transcript.session_count,
    accepted_winners: accepted.size,
    recovered_winners: recovered.size,
    final_event_hash: previous.toString('hex'),
    public_deployment_verified: false
  }, null, 2));
}

function eventHash(event, previous, subject, evidence) {
  const body = Buffer.concat([
    u16(2),
    u64(event.sequence),
    previous,
    variable(Buffer.from(event.kind, 'utf8')),
    event.session === null
      ? Buffer.from([0])
      : Buffer.concat([Buffer.from([1]), u64(event.session)]),
    subject,
    variable(Buffer.from(event.outcome, 'utf8')),
    evidence
  ]);
  return domainHash(EVENT_DOMAIN, body);
}

function requireSingle(kinds, kind) {
  assert(kinds.has(kind), `missing incident ${kind}`);
  assert.strictEqual(kinds.get(kind).length, 1, `incident ${kind} must be unique`);
}

function requireOrdered(kinds, first, second) {
  requireSingle(kinds, first);
  requireSingle(kinds, second);
  assert(kinds.get(first)[0] < kinds.get(second)[0], `${first} must precede ${second}`);
}

function fixedHex(value, size) {
  assert(typeof value === 'string');
  assert.strictEqual(value.length, size * 2);
  assert(/^[0-9a-f]+$/.test(value));
  return Buffer.from(value, 'hex');
}

function domainHash(domain, body) {
  return BLAKE2b.digest(Buffer.concat([
    variable(Buffer.from(domain, 'ascii')),
    body
  ]), 32);
}

function variable(value) {
  return Buffer.concat([varint(value.length), value]);
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

function u16(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16LE(value);
  return out;
}

function u64(value) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(BigInt(value));
  return out;
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

main();
