'use strict';

const crypto = require('node:crypto');
const { normalizeText, utf8 } = require('./encoding');

const MODES = ['text', 'exact'];

/**
 * Keyed exact-match search tokens for encrypted columns.
 *
 * The column context is part of the key, so the same value in two columns gives unrelated indexes.
 * An index reveals which rows hold equal plaintexts; it reveals nothing else without the key.
 */
class BlindIndexer {
  #ring;
  #length;

  constructor(keyring, lengthBytes = 16) {
    if (!Number.isInteger(lengthBytes) || lengthBytes < 4 || lengthBytes > 32) {
      throw new RangeError('lengthBytes must be between 4 and 32');
    }
    this.#ring = keyring;
    this.#length = lengthBytes;
  }

  /** `<kid>.<hex>` under the primary key; store it next to the encrypted column. */
  index(value, context, { mode = 'text' } = {}) {
    return this.#indexFor(this.#ring.primaryKid, value, context, mode);
  }

  /** Indexes under every key in the ring, for `WHERE idx IN (...)` while rows are re-indexed. */
  candidates(value, context, { mode = 'text' } = {}) {
    return this.#ring.kids().map((kid) => this.#indexFor(kid, value, context, mode));
  }

  #indexFor(kid, value, context, mode) {
    if (typeof value !== 'string') throw new TypeError('value must be a string (handle NULLs before indexing)');
    if (typeof context !== 'string' || context === '') {
      throw new RangeError("context is required: use the table and column, e.g. context('users', 'email')");
    }
    if (!MODES.includes(mode)) throw new RangeError(`mode must be one of ${MODES.join(', ')}`);
    const data = utf8(mode === 'text' ? normalizeText(value) : value);
    const key = this.#ring.derive(kid, 'blind', context);
    const mac = crypto.createHmac('sha256', key).update(data).digest();
    return `${kid}.${mac.subarray(0, this.#length).toString('hex')}`;
  }
}

module.exports = { BlindIndexer };
