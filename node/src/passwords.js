'use strict';

const crypto = require('node:crypto');
const { SecureKitError } = require('./errors');
const { constantTimeEquals } = require('./tokens');

const MAX_PASSWORD_BYTES = 4096;
// Verification refuses stored hashes that demand more than this, so a tampered row cannot make the
// server allocate gigabytes. Same limits in the Python package.
const MAX_MEMORY_KIB = 262144;
const MAX_PASSES = 10;
const MAX_PARALLELISM = 16;

// RFC 9106 section 4, memory-constrained option: m=64 MiB, t=3, p=4, 16-byte salt, 32-byte tag.
const CURRENT = { memory: 65536, passes: 3, parallelism: 4, saltBytes: 16, tagBytes: 32 };

const PHC = /^\$argon2id\$v=19\$m=(\d{1,10}),t=(\d{1,10}),p=(\d{1,10})\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;

function prepare(password) {
  if (typeof password !== 'string') throw new TypeError('password must be a string');
  if (!password.isWellFormed()) throw new RangeError('password contains a lone surrogate');
  const text = password.normalize('NFKC'); // NIST SP 800-63B
  const size = Buffer.byteLength(text, 'utf8');
  if (size < 1 || size > MAX_PASSWORD_BYTES) throw new RangeError(`password must be 1 to ${MAX_PASSWORD_BYTES} bytes`);
  return Buffer.from(text, 'utf8');
}

const encode = (buf) => buf.toString('base64').replace(/=+$/, '');

/** Strict unpadded standard base64 as used by PHC strings; null if it is not canonical. */
function decode(text) {
  const raw = Buffer.from(text, 'base64');
  return encode(raw) === text ? raw : null;
}

function parse(stored) {
  const match = typeof stored === 'string' ? PHC.exec(stored) : null;
  if (!match) return null;
  const [memory, passes, parallelism] = [Number(match[1]), Number(match[2]), Number(match[3])];
  const salt = decode(match[4]);
  const tag = decode(match[5]);
  if (!salt || !tag || salt.length < 8 || tag.length < 4) return null;
  return { memory, passes, parallelism, salt, tag };
}

/** Fail loudly on Node < 24.7: verifyPassword swallows errors, which would otherwise reject every password. */
function requireArgon2() {
  if (typeof crypto.argon2Sync !== 'function') {
    throw new SecureKitError('Argon2id needs Node.js 24.7 or later: crypto.argon2Sync is not available in this runtime');
  }
}

function argon2id(message, { memory, passes, parallelism, salt, tagLength }) {
  return crypto.argon2Sync('argon2id', { message, nonce: salt, parallelism, tagLength, memory, passes });
}

/** Argon2id PHC string, e.g. `$argon2id$v=19$m=65536,t=3,p=4$...`. */
function hashPassword(password) {
  requireArgon2();
  const salt = crypto.randomBytes(CURRENT.saltBytes);
  const tag = argon2id(prepare(password), { ...CURRENT, salt, tagLength: CURRENT.tagBytes });
  return `$argon2id$v=19$m=${CURRENT.memory},t=${CURRENT.passes},p=${CURRENT.parallelism}$${encode(salt)}$${encode(tag)}`;
}

/** True only for a matching argon2id hash. Wrong passwords and malformed, foreign or oversized hashes give false. */
function verifyPassword(password, stored) {
  requireArgon2();
  const parsed = parse(stored);
  if (!parsed) return false;
  if (parsed.memory > MAX_MEMORY_KIB || parsed.passes > MAX_PASSES || parsed.parallelism > MAX_PARALLELISM) return false;
  try {
    const actual = argon2id(prepare(password), { ...parsed, tagLength: parsed.tag.length });
    return constantTimeEquals(actual, parsed.tag);
  } catch {
    return false;
  }
}

/** True when the hash uses weaker or different parameters than the current ones (or is unreadable). */
function needsRehash(stored) {
  const parsed = parse(stored);
  return (
    !parsed ||
    parsed.memory !== CURRENT.memory ||
    parsed.passes !== CURRENT.passes ||
    parsed.parallelism !== CURRENT.parallelism ||
    parsed.salt.length !== CURRENT.saltBytes ||
    parsed.tag.length !== CURRENT.tagBytes
  );
}

module.exports = { hashPassword, verifyPassword, needsRehash, requireArgon2, MAX_MEMORY_KIB, MAX_PASSES, MAX_PARALLELISM };
