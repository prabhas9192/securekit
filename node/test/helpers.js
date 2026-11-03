'use strict';
// Fixed TEST-ONLY keys. Never use these for real data.

const { Keyring } = require('../src');

const bytes = (start) => Buffer.from(Array.from({ length: 32 }, (_, i) => start + i)).toString('base64url');
const KEY_K1 = bytes(0);
const KEY_K2 = bytes(32);
const KEY_K3 = bytes(64);

function ring(primary = 'k2', kids = ['k1', 'k2']) {
  const all = { k1: KEY_K1, k2: KEY_K2, k3: KEY_K3 };
  return new Keyring(Object.fromEntries(kids.map((kid) => [kid, all[kid]])), primary);
}

/** [[key, type, value], ...] (the vectors.json record format) -> object. */
function recordFromTriples(triples) {
  const record = {};
  for (const [key, kind, value] of triples) {
    switch (kind) {
      case 'null': record[key] = null; break;
      case 'str': record[key] = value; break;
      case 'int': record[key] = BigInt(value); break;
      case 'bool': record[key] = Boolean(value); break;
      case 'bytes': record[key] = Buffer.from(value, 'hex'); break;
      default: throw new Error(`unknown type ${kind}`);
    }
  }
  return record;
}

module.exports = { KEY_K1, KEY_K2, KEY_K3, ring, recordFromTriples };
