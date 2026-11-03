'use strict';

const crypto = require('node:crypto');
const { b64uDecode, b64uEncode, lengthPrefixed, utf8 } = require('./encoding');
const { constantTimeEquals } = require('./tokens');

const VERSION = 'sk1s';
const NULL = 0;
const STR = 1;
const INT = 2;
const BOOL = 3;
const BYTES = 4;

function encodeValue(value) {
  if (value === null) return [NULL, Buffer.alloc(0)];
  if (typeof value === 'boolean') return [BOOL, Buffer.from(value ? '1' : '0', 'ascii')];
  if (typeof value === 'bigint') return [INT, Buffer.from(value.toString(), 'ascii')];
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError('cannot seal a non-integer number: convert it to a string first (floats have no single canonical form)');
    }
    return [INT, Buffer.from(String(value), 'ascii')];
  }
  if (typeof value === 'string') return [STR, utf8(value)];
  if (value instanceof Uint8Array) return [BYTES, Buffer.from(value)];
  throw new TypeError('cannot seal this value: convert it to a string, integer, boolean, Buffer or null first');
}

function message(record, context, exclude) {
  if (typeof context !== 'string' || context === '') {
    throw new RangeError('context is required: bind the seal to its table and row id');
  }
  const skip = new Set(exclude);
  const entries = [];
  for (const [key, value] of Object.entries(record)) {
    if (key === '') throw new TypeError('record keys must be non-empty strings');
    if (!skip.has(key)) entries.push([utf8(key), value]);
  }
  entries.sort((a, b) => Buffer.compare(a[0], b[0]));

  const count = Buffer.alloc(4);
  count.writeUInt32BE(entries.length);
  const parts = [Buffer.from('securekit/v1/seal\0', 'ascii'), lengthPrefixed(utf8(context)), count];
  for (const [key, value] of entries) {
    const [kind, data] = encodeValue(value);
    parts.push(lengthPrefixed(key), Buffer.from([kind]), lengthPrefixed(data));
  }
  return Buffer.concat(parts);
}

/**
 * Tamper-evidence for plaintext columns: an HMAC over every field of the record plus its context.
 *
 * Every key is sealed unless named in `exclude`; nothing is skipped by name pattern, so columns like
 * password_hash are covered. Include a version counter in the record if you also need to detect
 * rollback to an older valid row.
 */
class RecordSealer {
  #ring;

  constructor(keyring) {
    this.#ring = keyring;
  }

  seal(record, context, { exclude = [] } = {}) {
    const kid = this.#ring.primaryKid;
    return `${VERSION}.${kid}.${this.#mac(kid, record, context, exclude)}`;
  }

  verify(record, context, seal, { exclude = [] } = {}) {
    const parts = typeof seal === 'string' ? seal.split('.') : [];
    if (parts.length !== 3 || parts[0] !== VERSION || !this.#ring.has(parts[1])) return false;
    try {
      b64uDecode(parts[2]);
    } catch {
      return false;
    }
    return constantTimeEquals(this.#mac(parts[1], record, context, exclude), parts[2]);
  }

  #mac(kid, record, context, exclude) {
    const key = this.#ring.derive(kid, 'seal');
    return b64uEncode(crypto.createHmac('sha256', key).update(message(record, context, exclude)).digest());
  }
}

module.exports = { RecordSealer };
