'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const sk = require('../src');
const { b64uEncode } = require('../src/encoding');
const { KEY_K1, KEY_K2, KEY_K3, ring } = require('./helpers');

const CTX = sk.context('users', 'ssn', 42);
const EMAIL = sk.context('users', 'email');

test('keyring: generated keys, rejected passphrases and key ids', () => {
  assert.notEqual(sk.generateKey(), sk.generateKey());
  for (const bad of ['MasterDatabaseSecretKey2026!', 'short', '', b64uEncode(Buffer.alloc(16)), b64uEncode(Buffer.alloc(33))]) {
    assert.throws(() => new sk.Keyring({ k1: bad }, 'k1'), RangeError, bad);
  }
  for (const kid of ['', 'has space', 'a.b', 'x'.repeat(17)]) {
    assert.throws(() => new sk.Keyring({ [kid]: KEY_K1 }, kid), RangeError, kid);
  }
  assert.throws(() => new sk.Keyring({}, 'k1'), RangeError);
  assert.throws(() => new sk.Keyring({ k1: KEY_K1 }, 'k2'), RangeError);
});

test('keyring: never reveals key material when printed or serialized', () => {
  const r = ring();
  for (const text of [String(r), JSON.stringify(r), require('node:util').inspect(r)]) {
    assert.ok(!text.includes(KEY_K1) && !text.includes(KEY_K2));
  }
});

test('keyring: JSON and environment loading', () => {
  const text = JSON.stringify({ primary: 'k1', keys: { k1: KEY_K1 } });
  assert.equal(sk.Keyring.fromJSON(text).primaryKid, 'k1');
  process.env.SECUREKIT_TEST_RING = text;
  assert.deepEqual(sk.Keyring.fromEnv('SECUREKIT_TEST_RING').kids(), ['k1']);
  delete process.env.SECUREKIT_TEST_RING;
  assert.throws(() => sk.Keyring.fromEnv('SECUREKIT_TEST_RING'), sk.SecureKitError);
});

test('keyring: sub-keys match an independent HKDF and are separated', () => {
  const hkdf = (ikm, info) => {
    const prk = crypto.createHmac('sha256', Buffer.alloc(32)).update(ikm).digest();
    return crypto.createHmac('sha256', prk).update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();
  };
  const r = ring();
  const root = Buffer.from(KEY_K1, 'base64url');
  assert.deepEqual(r.derive('k1', 'field'), hkdf(root, 'securekit/v1/field'));
  assert.deepEqual(r.derive('k1', 'blind', 'users/email'), hkdf(root, 'securekit/v1/blind/users/email'));
  const keys = new Set([
    r.derive('k1', 'field'), r.derive('k1', 'seal'), r.derive('k1', 'sign'),
    r.derive('k1', 'blind', 'a'), r.derive('k1', 'blind', 'b'), r.derive('k2', 'field'),
  ].map((k) => k.toString('hex')));
  assert.equal(keys.size, 6);
  r.derive('k1', 'blind', 'x'.repeat(900));
  assert.throws(() => r.derive('k1', 'blind', 'x'.repeat(1100)), RangeError);
  assert.throws(() => r.derive('nope', 'field'), sk.UnknownKeyError);
});

test('fields: round trip, randomized nonce, token shape', () => {
  const cipher = new sk.FieldCipher(ring());
  for (const plaintext of ['123-45-6789', 'ünïcödé ✓', '', Buffer.from([0, 255, 16])]) {
    const token = cipher.encrypt(plaintext, CTX);
    const expected = typeof plaintext === 'string' ? Buffer.from(plaintext) : plaintext;
    assert.deepEqual(cipher.decrypt(token, CTX), expected);
  }
  const [a, b] = [cipher.encrypt('x', CTX), cipher.encrypt('x', CTX)];
  assert.notEqual(a, b);
  const [version, kid, body] = a.split('.');
  assert.deepEqual([version, kid], ['sk1', 'k2']);
  assert.equal(Buffer.from(body, 'base64url').length, 12 + 1 + 16);
  assert.equal(cipher.decryptString(a, CTX), 'x');
});

test('fields: context is mandatory and bound', () => {
  const cipher = new sk.FieldCipher(ring());
  assert.throws(() => cipher.encrypt('x', ''), RangeError);
  const token = cipher.encrypt('secret', CTX);
  for (const other of [sk.context('users', 'ssn', 43), sk.context('users', 'email', 42), 'x']) {
    assert.throws(() => cipher.decrypt(token, other), sk.InvalidToken);
  }
  assert.throws(() => cipher.decrypt(token, ''), RangeError);
});

test('context(): unambiguous and typed', () => {
  assert.notEqual(sk.context('ab', 'c'), sk.context('a', 'bc'));
  assert.notEqual(sk.context('a|1:b'), sk.context('a', 'b'));
  assert.equal(sk.context('users', 'ssn', 42), '5:users|3:ssn|2:42');
  assert.equal(sk.context('é'), '2:é');
  assert.equal(sk.context('x', 10n ** 20n), '1:x|21:100000000000000000000');
  for (const bad of [true, 1.5, null, undefined, {}]) assert.throws(() => sk.context(bad), TypeError);
  assert.throws(() => sk.context(), RangeError);
  assert.throws(() => sk.context('\ud800'), RangeError);
});

test('fields: every single-character change is rejected', () => {
  const cipher = new sk.FieldCipher(ring());
  const token = cipher.encrypt('secret', CTX);
  const cut = token.lastIndexOf('.') + 1;
  for (let i = cut; i < token.length; i += 1) {
    const replacement = token[i] === 'A' ? 'B' : 'A';
    const tampered = token.slice(0, i) + replacement + token.slice(i + 1);
    assert.throws(() => cipher.decrypt(tampered, CTX), sk.InvalidToken, `position ${i}`);
  }
});

test('fields: malformed tokens only throw InvalidToken', () => {
  const cipher = new sk.FieldCipher(ring());
  const good = cipher.encrypt('x', CTX);
  for (const bad of ['', 'sk1', 'sk1.k2', 'sk1.k2.', 'sk1.k2.AAAA', `sk1.k2.${'A'.repeat(100)}`, 'sk2.k2.xx', 'a.b.c.d', `${good}.`, `${good}=`, good.replace('sk1', 'SK1'), null, undefined, 5, Buffer.from(good)]) {
    assert.throws(() => cipher.decrypt(bad, CTX), sk.InvalidToken, String(bad));
  }
});

test('fields: foreign keyring, unknown key id and relabelled key id', () => {
  const cipher = new sk.FieldCipher(ring());
  const foreign = new sk.FieldCipher(new sk.Keyring({ k2: KEY_K3 }, 'k2'));
  assert.throws(() => cipher.decrypt(foreign.encrypt('x', CTX), CTX), sk.InvalidToken);

  const other = new sk.FieldCipher(new sk.Keyring({ k9: KEY_K1 }, 'k9')).encrypt('x', CTX);
  assert.throws(() => cipher.decrypt(other, CTX), sk.UnknownKeyError);

  const same = new sk.FieldCipher(new sk.Keyring({ a: KEY_K1, b: KEY_K1 }, 'a'));
  const relabelled = same.encrypt('x', CTX).replace('sk1.a.', 'sk1.b.');
  assert.throws(() => same.decrypt(relabelled, CTX), sk.InvalidToken);
});

test('fields: rotation', () => {
  const old = new sk.FieldCipher(new sk.Keyring({ k1: KEY_K1 }, 'k1'));
  const token = old.encrypt('secret', CTX);
  const rotated = new sk.FieldCipher(new sk.Keyring({ k1: KEY_K1, k2: KEY_K2 }, 'k2'));
  assert.equal(rotated.decryptString(token, CTX), 'secret');
  assert.ok(rotated.needsRotation(token));
  const fresh = rotated.rotate(token, CTX);
  assert.ok(fresh.startsWith('sk1.k2.'));
  assert.ok(!rotated.needsRotation(fresh));
  assert.equal(rotated.rotate(fresh, CTX), fresh);
  const retired = new sk.FieldCipher(new sk.Keyring({ k2: KEY_K2 }, 'k2'));
  assert.equal(retired.decryptString(fresh, CTX), 'secret');
  assert.throws(() => retired.decrypt(token, CTX), sk.UnknownKeyError);
});

test('fields: non-UTF-8 plaintext is an InvalidToken from decryptString', () => {
  const cipher = new sk.FieldCipher(ring());
  assert.throws(() => cipher.decryptString(cipher.encrypt(Buffer.from([0xff, 0xfe]), CTX), CTX), sk.InvalidToken);
  assert.throws(() => cipher.encrypt(123, CTX), TypeError);
});

test('blind index: normalization, context separation, candidates', () => {
  const blind = new sk.BlindIndexer(ring());
  const base = blind.index('alice@example.com', EMAIL);
  for (const variant of ['Alice@Example.COM', '  alice@example.com\n', 'ＡＬＩＣＥ＠ｅｘａｍｐｌｅ．ｃｏｍ', ' alice@example.com　']) {
    assert.equal(blind.index(variant, EMAIL), base, JSON.stringify(variant));
  }
  assert.notEqual(blind.index('bob@example.com', EMAIL), base);
  assert.notEqual(base, blind.index('alice@example.com', sk.context('users', 'recovery_email')));
  assert.notEqual(blind.index('Alice', EMAIL, { mode: 'exact' }), blind.index('alice', EMAIL, { mode: 'exact' }));
  assert.equal(new sk.BlindIndexer(ring(), 8).index('x', EMAIL).split('.')[1].length, 16);
  assert.throws(() => new sk.BlindIndexer(ring(), 3), RangeError);

  const candidates = blind.candidates('alice@example.com', EMAIL);
  assert.deepEqual(candidates.map((c) => c.split('.')[0]), ['k1', 'k2']);
  assert.ok(candidates.includes(base));
  assert.throws(() => blind.index(null, EMAIL), TypeError);
  assert.throws(() => blind.index('x', ''), RangeError);
  assert.throws(() => blind.index('x', EMAIL, { mode: 'loose' }), RangeError);
});

test('normalizeText rules', () => {
  assert.equal(sk.normalizeText('é'), 'é');
  assert.equal(sk.normalizeText('É'), 'É');
  assert.equal(sk.normalizeText('K'), 'k');
  assert.equal(sk.normalizeText('ﬁ'), 'fi');
  assert.equal(sk.normalizeText('x '), 'x');
  assert.equal(sk.normalizeText('﻿a'), '﻿a');
  assert.throws(() => sk.normalizeText('a\ud800'), RangeError);
});

test('seal: covers every field, including *_hash columns', () => {
  const sealer = new sk.RecordSealer(ring());
  const record = { id: 42, email_index: 'k2.ab', password_hash: '$argon2id$original', active: true, note: null };
  const ctx = sk.context('users', 42);
  const seal = sealer.seal(record, ctx);
  assert.ok(seal.startsWith('sk1s.k2.'));
  assert.ok(sealer.verify({ note: null, active: true, password_hash: record.password_hash, email_index: 'k2.ab', id: 42 }, ctx, seal));
  for (const key of Object.keys(record)) {
    assert.ok(!sealer.verify({ ...record, [key]: 'tampered' }, ctx, seal), key);
  }
  const { note, ...withoutNote } = record;
  assert.ok(!sealer.verify(withoutNote, ctx, seal));
  assert.ok(!sealer.verify({ ...record, extra: 'x' }, ctx, seal));
  assert.ok(!sealer.verify(record, sk.context('users', 43), seal));
});

test('seal: types differ, exclusions are explicit, bad values rejected', () => {
  const sealer = new sk.RecordSealer(ring());
  const seals = new Set([ '1', 1, true, Buffer.from('1'), null, '' ].map((value) => sealer.seal({ v: value }, 'c')));
  assert.equal(seals.size, 6);

  const record = { id: 1, name: 'x' };
  const seal = sealer.seal(record, 'c');
  const stored = { ...record, row_seal: seal };
  assert.ok(sealer.verify(stored, 'c', seal, { exclude: ['row_seal'] }));
  assert.ok(!sealer.verify(stored, 'c', seal));

  for (const value of [1.5, [1], { a: 1 }, undefined, Symbol('x')]) assert.throws(() => sealer.seal({ v: value }, 'c'), TypeError);
  assert.throws(() => sealer.seal(record, ''), RangeError);
  assert.equal(sealer.seal({ v: 5 }, 'c'), sealer.seal({ v: 5n }, 'c'));
});

test('seal: malformed seals verify false; old keys still verify', () => {
  const sealer = new sk.RecordSealer(ring());
  const record = { id: 1 };
  const good = sealer.seal(record, 'c');
  for (const bad of ['', 'sk1s', 'sk1s.k2', 'sk1s.k2.', `sk1s.k9.${good.split('.')[2]}`, `${good}A`, good.slice(0, -1), null, 7]) {
    assert.ok(!sealer.verify(record, 'c', bad), String(bad));
  }
  const old = new sk.RecordSealer(ring('k1', ['k1'])).seal(record, 'c');
  assert.ok(sealer.verify(record, 'c', old));
});

test('signing: round trip, tamper, replay window, malformed headers', () => {
  const signer = new sk.Signer(ring());
  const now = 1_700_000_000;
  for (const body of ['{"event":"paid"}', 'héllo', Buffer.from([0, 255])]) {
    const header = signer.sign(body, { timestamp: now });
    assert.ok(header.startsWith(`t=${now},kid=k2,v1=`));
    assert.ok(signer.verify(body, header, { now: now + 10 }));
  }
  const header = signer.sign('body', { timestamp: now });
  assert.ok(!signer.verify('body!', header, { now }));
  assert.ok(!signer.verify('body', header.replace(`t=${now}`, `t=${now + 1}`), { now }));
  assert.ok(!signer.verify('body', header.slice(0, -1) + (header.endsWith('0') ? '1' : '0'), { now }));

  assert.ok(signer.verify('body', header, { now: now + 300 }));
  assert.ok(!signer.verify('body', header, { now: now + 301 }));
  assert.ok(signer.verify('body', header, { now: now - 300 }));
  assert.ok(!signer.verify('body', header, { now: now - 301 }));

  const mac = header.split('v1=')[1];
  for (const bad of ['', 't=1', `t=${now},kid=k2`, `t=${now},kid=k2,v1=${mac},v1=${mac}`, `t=${now},kid=k2,v1=${mac},x=1`, `t=abc,kid=k2,v1=${mac}`, `t=${now},kid=k9,v1=${mac}`, `t=${now},kid=k2,v1=${mac.toUpperCase()}`, `t=${now},kid=k2,v1=${mac.slice(0, -2)}`, `t=-1,kid=k2,v1=${mac}`, null, 5]) {
    assert.ok(!signer.verify('body', bad, { now }), String(bad));
  }
  for (const bad of [-1, 1.5, 1e12]) assert.throws(() => signer.sign('body', { timestamp: bad }), RangeError);
});

test('passwords: parameters, round trip, unicode equivalents, bad input', () => {
  const stored = sk.hashPassword('correct horse battery staple');
  assert.ok(stored.startsWith('$argon2id$v=19$m=65536,t=3,p=4$'));
  assert.ok(sk.verifyPassword('correct horse battery staple', stored));
  assert.ok(!sk.verifyPassword('Correct horse battery staple', stored));
  assert.notEqual(stored, sk.hashPassword('correct horse battery staple'));
  assert.ok(!sk.needsRehash(stored));

  const unicode = sk.hashPassword('pässwörd');
  assert.ok(sk.verifyPassword('pässwörd', unicode));
  assert.ok(sk.verifyPassword('ｐässwörd', unicode));

  for (const bad of ['', 'x', '$argon2id$garbage', null, 7]) assert.ok(!sk.verifyPassword('pw', bad), String(bad));
  assert.ok(!sk.verifyPassword('', stored));
  assert.ok(!sk.verifyPassword('x'.repeat(5000), stored));
  assert.throws(() => sk.hashPassword(''), RangeError);
  assert.throws(() => sk.hashPassword('x'.repeat(5000)), RangeError);
  assert.throws(() => sk.hashPassword(Buffer.from('pw')), TypeError);
  assert.ok(sk.needsRehash('not a hash'));
});

test('passwords: a runtime without crypto.argon2Sync throws instead of rejecting every password', () => {
  const stored = sk.hashPassword('pw');
  const original = crypto.argon2Sync;
  crypto.argon2Sync = undefined;
  try {
    assert.throws(() => sk.verifyPassword('pw', stored), sk.SecureKitError);
    assert.throws(() => sk.hashPassword('pw'), /Node\.js 24\.7/);
  } finally {
    crypto.argon2Sync = original;
  }
  assert.ok(sk.verifyPassword('pw', stored));
});

test('tokens', () => {
  assert.notEqual(sk.randomToken(), sk.randomToken());
  assert.ok(sk.randomToken(32).length >= 43);
  assert.throws(() => sk.randomToken(8), RangeError);
  assert.ok(sk.constantTimeEquals('abc', Buffer.from('abc')));
  assert.ok(!sk.constantTimeEquals('abc', 'abd'));
  assert.ok(!sk.constantTimeEquals('abc', 'abcd'));
});
