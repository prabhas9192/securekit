'use strict';
// Per-user vault (SPEC.md section 8): data the server must not be able to read.
//
//   const { vault, recoveryKey } = UserVault.create('user-42', passphrase, { withRecovery: true });
//   const state = vault.state;                          // store this JSON next to the user
//   const token = vault.encryptItem('note-1', 'my private note');
//
//   const again = UserVault.unlock('user-42', state, passphrase);
//   again.decryptString('note-1', token);
//
// A random data key encrypts the items; it is wrapped under a key derived from the passphrase with Argon2id.
// Changing the passphrase re-wraps one key and leaves every item untouched. Forget the passphrase without a
// recovery key and the data is gone: that is the point, and there is no reset.

const crypto = require('node:crypto');
const { b64uDecode, b64uEncode, context } = require('./encoding');
const { InvalidToken, SecureKitError, WrongPassphraseError } = require('./errors');
const { FieldCipher } = require('./fields');
const { Keyring, generateKey } = require('./keys');
const { MAX_MEMORY_KIB, MAX_PARALLELISM, MAX_PASSES, requireArgon2 } = require('./passwords');

const FORMAT = 'securekit-uservault/1';
const MIN_PASSPHRASE_CHARS = 8;
const MAX_PASSPHRASE_BYTES = 4096;
const PARAMS = { m: 65536, t: 3, p: 4 };
const LIMITS = { m: MAX_MEMORY_KIB, t: MAX_PASSES, p: MAX_PARALLELISM };

const single = (keyId, rootKey) => new FieldCipher(new Keyring({ [keyId]: rootKey }, keyId));
const isInt = (value) => Number.isSafeInteger(value);

function kek(passphrase, kdf) {
  requireArgon2();
  if (typeof passphrase !== 'string') throw new TypeError('passphrase must be a string');
  if (!passphrase.isWellFormed()) throw new RangeError('passphrase contains a lone surrogate');
  const message = Buffer.from(passphrase.normalize('NFKC'), 'utf8');
  if (message.length < 1 || message.length > MAX_PASSPHRASE_BYTES) throw new RangeError(`passphrase must be 1 to ${MAX_PASSPHRASE_BYTES} bytes`);
  const raw = crypto.argon2Sync('argon2id', {
    message,
    nonce: b64uDecode(kdf.salt),
    parallelism: kdf.p,
    tagLength: 32,
    memory: kdf.m,
    passes: kdf.t,
  });
  return b64uEncode(raw);
}

function checkNewPassphrase(passphrase) {
  if (typeof passphrase !== 'string') throw new TypeError('passphrase must be a string');
  if ([...passphrase.normalize('NFKC')].length < MIN_PASSPHRASE_CHARS) {
    throw new RangeError(`choose a passphrase of at least ${MIN_PASSPHRASE_CHARS} characters`);
  }
}

const freshKdf = () => ({ alg: 'argon2id', ...PARAMS, salt: b64uEncode(crypto.randomBytes(16)) });

function checkState(state) {
  const fail = () => {
    throw new SecureKitError('malformed or unsupported user vault state');
  };
  const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
  if (!plain(state) || state.format !== FORMAT || typeof state.wrapped_key !== 'string') fail();
  const { kdf } = state;
  if (!plain(kdf) || Object.keys(kdf).sort().join(',') !== 'alg,m,p,salt,t' || kdf.alg !== 'argon2id') fail();
  for (const key of ['m', 't', 'p']) if (!isInt(kdf[key]) || kdf[key] < 1 || kdf[key] > LIMITS[key]) fail();
  if (kdf.m < 8 * kdf.p || typeof kdf.salt !== 'string') fail();
  if (state.recovery_wrapped_key !== null && state.recovery_wrapped_key !== undefined && typeof state.recovery_wrapped_key !== 'string') fail();
  try {
    if (b64uDecode(kdf.salt).length < 8) fail();
  } catch (error) {
    if (error instanceof SecureKitError) throw error;
    fail();
  }
  return state;
}

class UserVault {
  #userId;
  #dataKey;
  #items;
  #state;

  constructor(userId, dataKey, state) {
    this.#userId = userId;
    this.#dataKey = dataKey;
    this.#items = single('d1', b64uEncode(dataKey));
    this.#state = state;
  }

  /** JSON-serializable state to store with the user. Contains only wrapped keys and KDF parameters. */
  get state() {
    return { ...this.#state, kdf: { ...this.#state.kdf } };
  }

  /** Returns { vault, recoveryKey }. Show the recovery key to the user once; it is not stored anywhere. */
  static create(userId, passphrase, { withRecovery = false } = {}) {
    checkNewPassphrase(passphrase);
    const dataKey = crypto.randomBytes(32);
    const kdf = freshKdf();
    const state = {
      format: FORMAT,
      kdf,
      recovery_wrapped_key: null,
      wrapped_key: single('u1', kek(passphrase, kdf)).encrypt(dataKey, context('uservault', userId, 'dek')),
    };
    const vault = new UserVault(userId, dataKey, state);
    return { vault, recoveryKey: withRecovery ? vault.newRecoveryKey() : null };
  }

  static unlock(userId, state, passphrase) {
    checkState(state);
    let dataKey;
    try {
      dataKey = single('u1', kek(passphrase, state.kdf)).decrypt(state.wrapped_key, context('uservault', userId, 'dek'));
    } catch (error) {
      if (error instanceof InvalidToken) throw new WrongPassphraseError('wrong passphrase, or this state belongs to another user');
      throw error;
    }
    return new UserVault(userId, UserVault.#validKey(dataKey), { ...state });
  }

  static unlockWithRecovery(userId, state, recoveryKey) {
    checkState(state);
    if (state.recovery_wrapped_key === null || state.recovery_wrapped_key === undefined) throw new SecureKitError('this vault has no recovery key');
    let dataKey;
    try {
      dataKey = single('r1', recoveryKey).decrypt(state.recovery_wrapped_key, context('uservault', userId, 'dek-recovery'));
    } catch (error) {
      if (error instanceof InvalidToken || error instanceof RangeError) throw new WrongPassphraseError('wrong recovery key, or this state belongs to another user');
      throw error;
    }
    return new UserVault(userId, UserVault.#validKey(dataKey), { ...state });
  }

  static #validKey(dataKey) {
    if (dataKey.length !== 32) throw new SecureKitError('malformed user vault state');
    return dataKey;
  }

  encryptItem(itemId, plaintext) {
    return this.#items.encrypt(plaintext, context('uservault', this.#userId, itemId));
  }

  decryptItem(itemId, token) {
    return this.#items.decrypt(token, context('uservault', this.#userId, itemId));
  }

  decryptString(itemId, token) {
    return this.#items.decryptString(token, context('uservault', this.#userId, itemId));
  }

  decryptItemString(itemId, token) {
    return this.decryptString(itemId, token);
  }

  /** Re-wrap the data key under a new passphrase. Items stay as they are. Returns (and keeps) the new state. */
  changePassphrase(newPassphrase) {
    checkNewPassphrase(newPassphrase);
    const kdf = freshKdf();
    this.#state = {
      ...this.#state,
      kdf,
      wrapped_key: single('u1', kek(newPassphrase, kdf)).encrypt(this.#dataKey, context('uservault', this.#userId, 'dek')),
    };
    return this.state;
  }

  /** Create (or replace) the recovery key. An earlier recovery key stops working once the new state is stored. */
  newRecoveryKey() {
    const recoveryKey = generateKey();
    this.#state = {
      ...this.#state,
      recovery_wrapped_key: single('r1', recoveryKey).encrypt(this.#dataKey, context('uservault', this.#userId, 'dek-recovery')),
    };
    return recoveryKey;
  }
}

module.exports = { UserVault };
