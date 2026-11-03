'use strict';

const crypto = require('node:crypto');
const { b64uDecode, b64uEncode, utf8 } = require('./encoding');
const { InvalidToken, UnknownKeyError } = require('./errors');

const VERSION = 'sk1';
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

function aad(kid, context) {
  if (typeof context !== 'string' || context === '') {
    throw new RangeError('context is required: bind every field to its table, column and row (see context())');
  }
  return Buffer.concat([Buffer.from('securekit/v1/field\0', 'ascii'), Buffer.from(kid, 'ascii'), Buffer.from([0]), utf8(context)]);
}

function asBytes(plaintext) {
  if (typeof plaintext === 'string') return utf8(plaintext);
  if (plaintext instanceof Uint8Array) return Buffer.from(plaintext);
  throw new TypeError('plaintext must be a string or bytes');
}

/** AES-256-GCM field encryption with key ids, mandatory context binding and rotation. */
class FieldCipher {
  #ring;

  constructor(keyring) {
    this.#ring = keyring;
  }

  encrypt(plaintext, context) {
    const data = asBytes(plaintext);
    const kid = this.#ring.primaryKid;
    const additional = aad(kid, context);
    const nonce = crypto.randomBytes(NONCE_BYTES);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.#ring.derive(kid, 'field'), nonce, { authTagLength: TAG_BYTES });
    cipher.setAAD(additional);
    const body = Buffer.concat([cipher.update(data), cipher.final()]);
    return `${VERSION}.${kid}.${b64uEncode(Buffer.concat([nonce, body, cipher.getAuthTag()]))}`;
  }

  decrypt(token, context) {
    const { kid, raw } = this.#parse(token);
    const additional = aad(kid, context);
    const nonce = raw.subarray(0, NONCE_BYTES);
    const body = raw.subarray(NONCE_BYTES, raw.length - TAG_BYTES);
    const tag = raw.subarray(raw.length - TAG_BYTES);
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.#ring.derive(kid, 'field'), nonce, { authTagLength: TAG_BYTES });
      decipher.setAAD(additional);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(body), decipher.final()]);
    } catch {
      throw new InvalidToken('invalid token');
    }
  }

  decryptString(token, context) {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(this.decrypt(token, context));
    } catch (error) {
      if (error instanceof InvalidToken || !(error instanceof TypeError)) throw error;
      throw new InvalidToken('invalid token');
    }
  }

  /** True when the token was written under a key id other than the current primary. */
  needsRotation(token) {
    return this.#parse(token).kid !== this.#ring.primaryKid;
  }

  /** Re-encrypts under the primary key; returns the token unchanged if it already is. */
  rotate(token, context) {
    if (!this.needsRotation(token)) return token;
    return this.encrypt(this.decrypt(token, context), context);
  }

  #parse(token) {
    const parts = typeof token === 'string' ? token.split('.') : [];
    if (parts.length !== 3 || parts[0] !== VERSION) throw new InvalidToken('invalid token');
    const kid = parts[1];
    if (!this.#ring.has(kid)) throw new UnknownKeyError(`unknown key id '${kid}'`);
    let raw;
    try {
      raw = b64uDecode(parts[2]);
    } catch {
      throw new InvalidToken('invalid token');
    }
    if (raw.length < NONCE_BYTES + TAG_BYTES) throw new InvalidToken('invalid token');
    return { kid, raw };
  }
}

module.exports = { FieldCipher };
