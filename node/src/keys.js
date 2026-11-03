'use strict';

const crypto = require('node:crypto');
const { b64uDecode, b64uEncode, utf8 } = require('./encoding');
const { SecureKitError, UnknownKeyError } = require('./errors');

const KEY_BYTES = 32;
const MAX_INFO_BYTES = 1024; // node:crypto hkdfSync limit; the Python package enforces the same
const KID = /^[A-Za-z0-9_-]{1,16}$/;

/** A new root key: 32 bytes from the OS CSPRNG, base64url encoded. */
function generateKey() {
  return b64uEncode(crypto.randomBytes(KEY_BYTES));
}

/**
 * Root keys by key id, with one primary used for new data.
 *
 * Root keys must be 32 random bytes (see generateKey). Passphrases are rejected on purpose: nothing
 * here stretches them. To use a KMS, fetch the data keys at startup and build a Keyring from them.
 */
class Keyring {
  #keys = new Map();
  #primary;

  constructor(keys, primary) {
    const entries = keys instanceof Map ? [...keys] : Object.entries(keys ?? {});
    if (entries.length === 0) throw new RangeError('a keyring needs at least one key');
    for (const [kid, encoded] of entries) {
      if (typeof kid !== 'string' || !KID.test(kid)) {
        throw new RangeError(`invalid key id '${kid}': use 1-16 characters from A-Z a-z 0-9 _ -`);
      }
      let raw;
      try {
        raw = b64uDecode(encoded);
      } catch {
        throw new RangeError(`key '${kid}' is not valid base64url; create keys with generateKey()`);
      }
      if (raw.length !== KEY_BYTES) {
        throw new RangeError(`key '${kid}' must be exactly ${KEY_BYTES} random bytes; create keys with generateKey()`);
      }
      this.#keys.set(kid, raw);
    }
    if (!this.#keys.has(primary)) throw new RangeError(`primary key id '${primary}' is not in the keyring`);
    this.#primary = primary;
  }

  /** Reads {"primary": "k2", "keys": {"k1": "<key>", "k2": "<key>"}}. */
  static fromJSON(text) {
    const data = JSON.parse(text);
    return new Keyring(data.keys, data.primary);
  }

  static fromEnv(name = 'SECUREKIT_KEYRING') {
    const text = process.env[name];
    if (!text) throw new SecureKitError(`environment variable ${name} is not set`);
    return Keyring.fromJSON(text);
  }

  get primaryKid() {
    return this.#primary;
  }

  kids() {
    return [...this.#keys.keys()];
  }

  has(kid) {
    return this.#keys.has(kid);
  }

  /** 32-byte sub-key for a purpose (and optional suffix such as a column context). */
  derive(kid, purpose, suffix = '') {
    const root = this.#keys.get(kid);
    if (root === undefined) throw new UnknownKeyError(`unknown key id '${kid}'`);
    const info = utf8(`securekit/v1/${purpose}${suffix ? `/${suffix}` : ''}`);
    if (info.length > MAX_INFO_BYTES) {
      throw new RangeError(`context is too long: sub-key info is limited to ${MAX_INFO_BYTES} bytes`);
    }
    return Buffer.from(crypto.hkdfSync('sha256', root, Buffer.alloc(0), info, 32));
  }

  toString() {
    return `Keyring(kids=[${this.kids().join(', ')}], primary=${this.#primary})`;
  }

  toJSON() {
    return { kids: this.kids(), primary: this.#primary };
  }

  [Symbol.for('nodejs.util.inspect.custom')]() {
    return this.toString();
  }
}

module.exports = { Keyring, generateKey, KEY_BYTES };
