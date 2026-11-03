'use strict';
// Cross-language vectors: python/gen_vectors.py writes them, both test suites check them.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const sk = require('../src');
const { b64uDecode, b64uEncode } = require('../src/encoding');
const { recordFromTriples } = require('./helpers');

const v = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'vectors', 'vectors.json'), 'utf8'));
const ring = sk.Keyring.fromJSON(JSON.stringify(v.keyring));

test('sub-keys match the spec', () => {
  for (const c of v.subkeys) assert.equal(ring.derive(c.kid, c.purpose, c.suffix).toString('hex'), c.hex);
});

test('context encoding', () => {
  for (const c of v.context) assert.equal(sk.context(...c.parts), c.expected);
});

test('text normalization', () => {
  for (const c of v.normalize) assert.equal(sk.normalizeText(c.input), c.expected, JSON.stringify(c.input));
});

test('base64url strictness', () => {
  for (const c of v.b64u) {
    if (c.valid) {
      assert.equal(b64uEncode(Buffer.from(c.hex, 'hex')), c.encoded);
      assert.equal(b64uDecode(c.encoded).toString('hex'), c.hex);
    } else {
      assert.throws(() => b64uDecode(c.encoded), RangeError, JSON.stringify(c.encoded));
    }
  }
});

test('blind indexes', () => {
  for (const c of v.blind) {
    const indexer = new sk.BlindIndexer(ring, c.length);
    assert.deepEqual(indexer.candidates(c.value, c.context, { mode: c.mode }), c.candidates);
  }
});

test('record seals', () => {
  const sealer = new sk.RecordSealer(ring);
  for (const c of v.seal) {
    const record = recordFromTriples(c.record);
    assert.equal(sealer.seal(record, c.context, { exclude: c.exclude }), c.seal, c.name);
    assert.ok(sealer.verify(record, c.context, c.seal, { exclude: c.exclude }), c.name);
  }
});

test('request signatures', () => {
  const signer = new sk.Signer(ring);
  for (const c of v.sign) {
    const body = Buffer.from(c.body_hex, 'hex');
    assert.equal(signer.sign(body, { timestamp: c.timestamp }), c.header);
    assert.ok(signer.verify(body, c.header, { now: c.timestamp }));
  }
});

test('tokens written by Python decrypt here, and invalid ones are rejected', () => {
  const cipher = new sk.FieldCipher(ring);
  for (const c of v.fields) assert.equal(cipher.decrypt(c.token, c.context).toString('hex'), c.plaintext_hex);
  for (const c of v.fields_invalid) {
    assert.throws(() => cipher.decrypt(c.token, c.context), sk.InvalidToken, c.why);
  }
});

test('a vault file and a user vault state written by Python open here', (t) => {
  const os = require('node:os');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'securekit-vector-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'vault.json');
  fs.writeFileSync(file, JSON.stringify(v.vault.file));

  const vault = sk.Vault.open(file, ring, { clock: () => 1_700_000_100 });
  vault.verify({ deep: true });
  for (const item of v.vault.active) assert.equal(vault.get(item.name, { version: item.version }).toString('hex'), item.value_hex, item.name);
  for (const item of v.vault.destroyed) assert.throws(() => vault.get(item.name, { version: item.version }), sk.SecretNotFoundError);
  assert.deepEqual(v.vault.file.audit.map((e) => e.action), v.vault.audit_actions);
  vault.put('written/by-node', 'x');          // a vault from the other implementation can be extended here
  vault.verify({ deep: true });

  const user = v.uservault;
  for (const passphrase of [user.passphrase, ...user.also_valid_passphrases]) {
    const unlocked = sk.UserVault.unlock(user.user_id, user.state, passphrase);
    for (const item of user.items) assert.equal(unlocked.decryptItem(item.item_id, item.token).toString('hex'), item.plaintext_hex);
  }
  for (const passphrase of user.wrong_passphrases) assert.throws(() => sk.UserVault.unlock(user.user_id, user.state, passphrase), sk.WrongPassphraseError);
  const recovered = sk.UserVault.unlockWithRecovery(user.user_id, user.state, user.recovery_key);
  assert.equal(recovered.decryptItem(user.items[0].item_id, user.items[0].token).toString('hex'), user.items[0].plaintext_hex);
});

test('password hashes written by Python verify here', () => {
  for (const c of v.passwords) {
    assert.ok(sk.verifyPassword(c.password, c.hash));
    for (const other of c.also_valid) assert.ok(sk.verifyPassword(other, c.hash), other);
    for (const other of c.invalid) assert.ok(!sk.verifyPassword(other, c.hash), other);
    for (const bad of c.invalid_hashes) assert.ok(!sk.verifyPassword(c.password, bad), bad);
    assert.ok(!sk.needsRehash(c.hash));
  }
});
