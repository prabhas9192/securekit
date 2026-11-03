'use strict';

const crypto = require('node:crypto');

/** URL-safe random token from the OS CSPRNG (password resets, session ids, API keys). */
function randomToken(nbytes = 32) {
  if (!Number.isInteger(nbytes) || nbytes < 16) {
    throw new RangeError('tokens shorter than 16 bytes (128 bits) are guessable at scale');
  }
  return crypto.randomBytes(nbytes).toString('base64url');
}

/** Timing-safe equality for secrets; strings are compared as UTF-8. */
function constantTimeEquals(a, b) {
  const left = typeof a === 'string' ? Buffer.from(a, 'utf8') : Buffer.from(a);
  const right = typeof b === 'string' ? Buffer.from(b, 'utf8') : Buffer.from(b);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

module.exports = { randomToken, constantTimeEquals };
