'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const sk = require('../src');

const { UserVault, InvalidToken, SecureKitError, WrongPassphraseError } = sk;
const PASSPHRASE = 'correct horse battery staple';

test('user vault: round trip; the state is plain JSON', () => {
  const { vault, recoveryKey } = UserVault.create('user-42', PASSPHRASE);
  assert.equal(recoveryKey, null);
  const token = vault.encryptItem('note-1', 'my private note');
  const state = JSON.parse(JSON.stringify(vault.state));
  assert.deepEqual(Object.keys(state).sort(), ['format', 'kdf', 'recovery_wrapped_key', 'wrapped_key']);
  assert.equal(state.kdf.m, 65536);
  assert.equal(UserVault.unlock('user-42', state, PASSPHRASE).decryptString('note-1', token), 'my private note');
  assert.equal(UserVault.unlock('user-42', state, PASSPHRASE).decryptItemString('note-1', token), 'my private note');
});

test('user vault: wrong passphrase, wrong user, tampered state', () => {
  const { vault } = UserVault.create('user-42', PASSPHRASE);
  const state = vault.state;
  assert.throws(() => UserVault.unlock('user-42', state, 'not the passphrase'), WrongPassphraseError);
  assert.throws(() => UserVault.unlock('user-43', state, PASSPHRASE), WrongPassphraseError);
  for (const change of [
    (s) => { s.wrapped_key = `${s.wrapped_key.slice(0, -3)}AAA`; },
    (s) => { s.kdf.salt = 'AAAAAAAAAAAAAAAAAAAAAA'; },
  ]) {
    const broken = vault.state;
    change(broken);
    assert.throws(() => UserVault.unlock('user-42', broken, PASSPHRASE), WrongPassphraseError);
  }
});

test('user vault: a hostile state cannot demand unbounded work or crash the process', () => {
  const state = UserVault.create('u', PASSPHRASE).vault.state;
  const mutations = [
    (s) => { s.kdf.m = 4_194_304; },
    (s) => { s.kdf.t = 11; },
    (s) => { s.kdf.p = 17; },
    (s) => { s.kdf.alg = 'argon2i'; },
    (s) => { s.kdf.m = true; },
    (s) => { s.kdf.salt = 'AA'; },
    (s) => { s.format = 'x'; },
    (s) => { s.wrapped_key = 5; },
    (s) => { s.recovery_wrapped_key = 5; },
    (s) => { delete s.kdf.salt; },
  ];
  for (const mutate of mutations) {
    const broken = JSON.parse(JSON.stringify(state));
    mutate(broken);
    assert.throws(() => UserVault.unlock('u', broken, PASSPHRASE), SecureKitError);
  }
  for (const bad of [null, [], 'x', {}]) assert.throws(() => UserVault.unlock('u', bad, PASSPHRASE), SecureKitError);
});

test('user vault: items are bound to the user and the item', () => {
  const { vault } = UserVault.create('alice', PASSPHRASE);
  const token = vault.encryptItem('note-1', 'secret');
  assert.throws(() => vault.decryptItem('note-2', token), InvalidToken);
  const { vault: other } = UserVault.create('bob', PASSPHRASE);
  assert.throws(() => other.decryptItem('note-1', token), InvalidToken);
});

test('user vault: changing the passphrase keeps items and retires the old passphrase', () => {
  const { vault } = UserVault.create('u', PASSPHRASE);
  const token = vault.encryptItem('n', 'data');
  const before = vault.state;
  const after = vault.changePassphrase('a brand new passphrase');
  assert.notEqual(after.kdf.salt, before.kdf.salt);
  assert.equal(UserVault.unlock('u', after, 'a brand new passphrase').decryptString('n', token), 'data');
  assert.throws(() => UserVault.unlock('u', after, PASSPHRASE), WrongPassphraseError);
});

test('user vault: recovery key', () => {
  const { vault, recoveryKey } = UserVault.create('u', PASSPHRASE, { withRecovery: true });
  const token = vault.encryptItem('n', 'data');
  const recovered = UserVault.unlockWithRecovery('u', vault.state, recoveryKey);
  assert.equal(recovered.decryptString('n', token), 'data');
  assert.throws(() => UserVault.unlockWithRecovery('u', vault.state, 'A'.repeat(43)), WrongPassphraseError);
  assert.throws(() => UserVault.unlockWithRecovery('u', vault.state, 'not a key'), WrongPassphraseError);
  assert.throws(() => UserVault.unlockWithRecovery('u', UserVault.create('u', PASSPHRASE).vault.state, recoveryKey), SecureKitError);

  recovered.changePassphrase('recovered and renewed');
  const fresh = recovered.newRecoveryKey();
  assert.notEqual(fresh, recoveryKey);
  assert.throws(() => UserVault.unlockWithRecovery('u', recovered.state, recoveryKey), WrongPassphraseError);
  assert.equal(UserVault.unlockWithRecovery('u', recovered.state, fresh).decryptString('n', token), 'data');
});

test('user vault: passphrase rules and Unicode equivalence', () => {
  assert.throws(() => UserVault.create('u', 'short'), RangeError);
  assert.throws(() => UserVault.create('u', Buffer.from('not a string passphrase')), TypeError);
  const { vault } = UserVault.create('u', 'pässwörd long');
  UserVault.unlock('u', vault.state, 'pässwörd long');
  assert.throws(() => UserVault.unlock('u', vault.state, 'x'.repeat(5000)), RangeError);
});
