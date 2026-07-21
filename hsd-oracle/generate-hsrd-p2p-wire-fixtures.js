#!/usr/bin/env node
'use strict';

// Generates deterministic HSD P2P wire fixtures.

process.env.NODE_BACKEND = process.env.NODE_BACKEND || 'js';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const bio = require('bufio');
const Block = require('hsd/lib/primitives/block');
const Headers = require('hsd/lib/primitives/headers');
const InvItem = require('hsd/lib/primitives/invitem');
const NetAddress = require('hsd/lib/net/netaddress');
const Framer = require('hsd/lib/net/framer');
const packets = require('hsd/lib/net/packets');
const Network = require('hsd/lib/protocol/network');
const consensus = require('hsd/lib/protocol/consensus');

const ORACLE_REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const TARGET = path.resolve(
  __dirname,
  '..',
  'hsrd',
  'fixtures',
  'hsd',
  'p2p',
  'wire-v1.json'
);
const WRITE = process.argv.includes('--write');
const CHECK = process.argv.includes('--check') || !WRITE;

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function customAddress() {
  const address = new NetAddress();
  address.time = 0x01020304;
  address.services = 0x89abcdef;
  address.raw = Buffer.from('00000000000000000000ffff7f000001', 'hex');
  address.port = 14038;
  address.key = Buffer.from(`02${'11'.repeat(32)}`, 'hex');
  return address;
}

function customHeaders() {
  const header = new Headers();
  header.version = 7;
  header.prevBlock = Buffer.alloc(32, 0x01);
  header.merkleRoot = Buffer.alloc(32, 0x02);
  header.witnessRoot = Buffer.alloc(32, 0x03);
  header.treeRoot = Buffer.alloc(32, 0x04);
  header.reservedRoot = Buffer.alloc(32, 0x05);
  header.time = 0x010203040506;
  header.bits = 0x1d00ffff;
  header.nonce = 0x12345678;
  header.extraNonce = Buffer.alloc(consensus.NONCE_SIZE, 0x06);
  header.mask = Buffer.alloc(32, 0x07);
  return header;
}

function frameCase(id, networkName, packet) {
  const network = Network.get(networkName);
  const payload = packet.encode();
  const frame = new Framer(network).packet(packet.type, payload);
  return {
    id,
    network: networkName,
    magic: network.magic >>> 0,
    packetType: packet.type,
    payload: payload.toString('hex'),
    frame: frame.toString('hex')
  };
}

function decodeVersion(payload) {
  const packet = packets.VersionPacket.decode(payload);
  return {
    version: packet.version,
    services: packet.services,
    time: packet.time,
    remote: {
      time: packet.remote.time,
      services: packet.remote.services,
      raw: packet.remote.raw.toString('hex'),
      port: packet.remote.port,
      key: packet.remote.key.toString('hex')
    },
    nonce: packet.nonce.toString('hex'),
    agent: packet.agent,
    height: packet.height,
    noRelay: packet.noRelay
  };
}

function buildFixture() {
  const address = customAddress();
  const version = new packets.VersionPacket({
    version: 3,
    services: 1,
    time: 0x010203040506,
    remote: address,
    nonce: Buffer.from('0102030405060708', 'hex'),
    agent: '/hsrd-oracle:0.1.0/',
    height: 123456,
    noRelay: true
  });

  const versionPayload = version.encode();
  const noRelayTwo = Buffer.from(versionPayload);
  noRelayTwo[noRelayTwo.length - 1] = 2;

  const highAscii = Buffer.from(versionPayload);
  const agentLengthOffset = 20 + 88 + 8;
  const agentLength = highAscii[agentLengthOffset];
  assert(agentLength >= 2);
  highAscii[agentLengthOffset + 1] = 0x80;
  highAscii[agentLengthOffset + 2] = 0xff;

  const reservedServiceBits = Buffer.from(versionPayload);
  reservedServiceBits.writeUInt32LE(0xaabbccdd, 8);
  reservedServiceBits.writeUInt32LE(0x11223344, 20 + 12);

  const unsupportedAddress = Buffer.alloc(88, 0);
  unsupportedAddress.writeBigUInt64LE(123n, 0);
  unsupportedAddress.writeUInt32LE(7, 8);
  unsupportedAddress.writeUInt32LE(0xaabbccdd, 12);
  unsupportedAddress[16] = 9;
  unsupportedAddress.fill(0x55, 17, 53);
  unsupportedAddress.writeUInt16LE(14038, 53);
  unsupportedAddress.fill(0x22, 55, 88);
  const normalizedAddress = NetAddress.decode(unsupportedAddress).encode();

  const inventory = [
    new InvItem(InvItem.types.BLOCK, Buffer.alloc(32, 0x21)),
    new InvItem(0xfeedbeef, Buffer.alloc(32, 0x22))
  ];
  const locator = [Buffer.alloc(32, 0x31), Buffer.alloc(32, 0x32)];
  const stop = Buffer.alloc(32, 0x33);
  const header = customHeaders();
  const block = new Block();

  const packetCases = [
    frameCase('version-main', 'main', version),
    frameCase('ping-main', 'main', new packets.PingPacket(Buffer.from('0102030405060708', 'hex'))),
    frameCase('ping-testnet', 'testnet', new packets.PingPacket(Buffer.alloc(8, 0x42))),
    frameCase('ping-regtest', 'regtest', new packets.PingPacket(Buffer.alloc(8, 0x43))),
    frameCase('ping-simnet', 'simnet', new packets.PingPacket(Buffer.alloc(8, 0x44))),
    frameCase('addr-regtest', 'regtest', new packets.AddrPacket([address])),
    frameCase('inv-regtest', 'regtest', new packets.InvPacket(inventory)),
    frameCase('getheaders-regtest', 'regtest', new packets.GetHeadersPacket(locator, stop)),
    frameCase('headers-regtest', 'regtest', new packets.HeadersPacket([header])),
    frameCase('block-regtest', 'regtest', new packets.BlockPacket(block)),
    frameCase('reject-block-regtest', 'regtest', new packets.RejectPacket({
      message: packets.types.BLOCK,
      code: packets.RejectPacket.codes.INVALID,
      reason: 'bad-block',
      hash: Buffer.alloc(32, 0x51)
    })),
    frameCase('reject-version-regtest', 'regtest', new packets.RejectPacket({
      message: packets.types.VERSION,
      code: packets.RejectPacket.codes.OBSOLETE,
      reason: 'obsolete'
    })),
    frameCase('feefilter-positive-regtest', 'regtest', new packets.FeeFilterPacket(1234567)),
    frameCase('feefilter-negative-regtest', 'regtest', new packets.FeeFilterPacket(-1234567)),
    frameCase('sendcmpct-regtest', 'regtest', new packets.SendCmpctPacket(1, 2))
  ];

  const packetTypes = Object.entries(packets.types)
    .filter(([, value]) => Number.isInteger(value) && value >= 0 && value <= packets.types.AIRDROP)
    .sort((left, right) => left[1] - right[1])
    .map(([name, value]) => ({name, value}));

  return {
    schema: 1,
    oracle: {
      repository: 'handshake-org/hsd',
      revision: ORACLE_REVISION
    },
    constants: {
      protocolVersion: 3,
      minimumProtocolVersion: 1,
      headerSize: 9,
      netAddressSize: address.getSize(),
      maximumHeaders: 2000,
      networks: ['main', 'testnet', 'regtest', 'simnet'].map(name => ({
        name,
        magic: Network.get(name).magic >>> 0
      }))
    },
    packetTypes,
    frames: packetCases,
    versionDecoding: {
      canonical: decodeVersion(versionPayload),
      noRelayByteTwo: decodeVersion(noRelayTwo),
      highBitAscii: decodeVersion(highAscii),
      reservedHighServiceWords: decodeVersion(reservedServiceBits),
      payloads: {
        canonical: versionPayload.toString('hex'),
        noRelayByteTwo: noRelayTwo.toString('hex'),
        highBitAscii: highAscii.toString('hex'),
        reservedHighServiceWords: reservedServiceBits.toString('hex')
      }
    },
    netAddressNormalization: {
      unsupportedKindInput: unsupportedAddress.toString('hex'),
      decoded: {
        time: NetAddress.decode(unsupportedAddress).time,
        services: NetAddress.decode(unsupportedAddress).services,
        raw: NetAddress.decode(unsupportedAddress).raw.toString('hex'),
        port: NetAddress.decode(unsupportedAddress).port,
        key: NetAddress.decode(unsupportedAddress).key.toString('hex')
      },
      canonicalReencode: normalizedAddress.toString('hex')
    }
  };
}

const generated = canonicalJson(buildFixture());

if (WRITE) {
  fs.mkdirSync(path.dirname(TARGET), {recursive: true});
  fs.writeFileSync(TARGET, generated);
}

if (CHECK) {
  const existing = fs.readFileSync(TARGET, 'utf8');
  assert.strictEqual(existing, generated, `${TARGET} is not reproducible`);
}

process.stdout.write(`verified ${path.relative(process.cwd(), TARGET)}\n`);
