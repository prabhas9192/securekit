'use strict';
// Shared encodings. SPEC.md is normative; python/securekit/_encoding.py must produce identical bytes.

const B64U = /^[A-Za-z0-9_-]*$/;
const TRIM = new Set(
  [...'\t\n\v\f\r       　'].map((c) => c.charCodeAt(0))
);
for (let code = 0x2000; code <= 0x200a; code += 1) TRIM.add(code);

function b64uEncode(data) {
  return Buffer.from(data).toString('base64url');
}

/** Strict unpadded base64url: other alphabets and non-canonical encodings throw RangeError. */
function b64uDecode(text) {
  if (typeof text !== 'string' || !B64U.test(text) || text.length % 4 === 1) {
    throw new RangeError('invalid base64url');
  }
  const raw = Buffer.from(text, 'base64url');
  if (raw.toString('base64url') !== text) throw new RangeError('non-canonical base64url');
  return raw;
}

function lengthPrefixed(data) {
  const head = Buffer.alloc(4);
  head.writeUInt32BE(data.length);
  return Buffer.concat([head, data]);
}

/** UTF-8 encode, rejecting lone surrogates (Buffer.from would silently substitute U+FFFD). */
function utf8(text) {
  if (typeof text !== 'string') throw new TypeError('expected a string');
  if (!text.isWellFormed()) throw new RangeError('string contains a lone surrogate');
  return Buffer.from(text, 'utf8');
}

/** Unambiguous join of strings and integers: context('users', 'ssn', 42) === '5:users|3:ssn|2:42'. */
function context(...parts) {
  if (parts.length === 0) throw new RangeError('context needs at least one part');
  return parts
    .map((part) => {
      let text;
      if (typeof part === 'string') text = part;
      else if (typeof part === 'bigint') text = part.toString();
      else if (typeof part === 'number' && Number.isSafeInteger(part)) text = String(part);
      else throw new TypeError('context parts must be strings or integers');
      return `${utf8(text).length}:${text}`;
    })
    .join('|');
}

function trimSpecified(text) {
  let start = 0;
  let end = text.length;
  while (start < end && TRIM.has(text.charCodeAt(start))) start += 1;
  while (end > start && TRIM.has(text.charCodeAt(end - 1))) end -= 1;
  return text.slice(start, end);
}

function normalizeText(value) {
  utf8(value);
  return trimSpecified(value.normalize('NFKC')).replace(/[A-Z]/g, (c) =>
    String.fromCharCode(c.charCodeAt(0) + 32)
  );
}

module.exports = { b64uEncode, b64uDecode, lengthPrefixed, utf8, context, normalizeText };
