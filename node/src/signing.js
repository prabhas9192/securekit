'use strict';

const crypto = require('node:crypto');
const { constantTimeEquals } = require('./tokens');

const TIMESTAMP = /^[0-9]{1,12}$/;
const MAC_HEX = /^[0-9a-f]{64}$/;

function bodyBytes(body) {
  if (typeof body === 'string') return Buffer.from(body, 'utf8');
  if (body instanceof Uint8Array) return Buffer.from(body);
  throw new TypeError('body must be a string or bytes');
}

/** Webhook-style request signing: `t=<unix>,kid=<kid>,v1=<hmac>` with replay-window checking. */
class Signer {
  #ring;

  constructor(keyring) {
    this.#ring = keyring;
  }

  sign(body, { timestamp } = {}) {
    const t = timestamp === undefined ? Math.floor(Date.now() / 1000) : timestamp;
    if (!Number.isSafeInteger(t) || t < 0 || t >= 1e12) throw new RangeError('timestamp must be an integer number of seconds');
    const kid = this.#ring.primaryKid;
    return `t=${t},kid=${kid},v1=${this.#mac(kid, t, body)}`;
  }

  /** False for anything malformed, forged, stale or from the future; never throws on bad input. */
  verify(body, header, { toleranceSeconds = 300, now } = {}) {
    if (typeof header !== 'string') return false;
    const fields = new Map();
    for (const part of header.split(',')) {
      const at = part.indexOf('=');
      if (at < 0) return false;
      const name = part.slice(0, at);
      if (fields.has(name)) return false;
      fields.set(name, part.slice(at + 1));
    }
    if (fields.size !== 3 || !fields.has('t') || !fields.has('kid') || !fields.has('v1')) return false;
    const [t, kid, mac] = [fields.get('t'), fields.get('kid'), fields.get('v1')];
    if (!TIMESTAMP.test(t) || !MAC_HEX.test(mac) || !this.#ring.has(kid)) return false;
    const current = now === undefined ? Date.now() / 1000 : now;
    if (Math.abs(current - Number(t)) > toleranceSeconds) return false;
    return constantTimeEquals(this.#mac(kid, Number(t), body), mac);
  }

  #mac(kid, t, body) {
    const key = this.#ring.derive(kid, 'sign');
    return crypto.createHmac('sha256', key).update(Buffer.concat([Buffer.from(`${t}.`, 'ascii'), bodyBytes(body)])).digest('hex');
  }
}

module.exports = { Signer };
