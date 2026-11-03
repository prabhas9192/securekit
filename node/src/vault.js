'use strict';
// Encrypted secrets vault for applications (SPEC.md section 7). Synchronous, like the file it manages.
//
//   const ring = Keyring.fromEnv();
//   Vault.create('secrets.vault.json', ring, { actor: 'deploy' });                  // once
//   const vault = Vault.open('secrets.vault.json', ring, { actor: 'payments-api' }); // at startup
//   vault.put('payments/stripe_key', 'sk_live_...');
//   const key = vault.getString('payments/stripe_key');
//
// A process that holds the keyring can read everything in the vault: use scoped() to limit what one component of
// your own code can reach, and a real secrets server if you need per-client authorization.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { b64uEncode, context } = require('./encoding');
const {
  InvalidToken,
  SecretNotFoundError,
  SecureKitError,
  TamperedVaultError,
  VaultExistsError,
  VaultLockedError,
} = require('./errors');
const { FieldCipher } = require('./fields');
const { RecordSealer } = require('./seal');

const FORMAT = 'securekit-vault/1';
const MAX_VALUE_BYTES = 1_048_576;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/;
const ACTOR = /^[^\x00-\x1f\x7f]{1,128}$/u;
const ACTIONS = new Set(['init', 'put', 'read', 'destroy', 'delete', 'rotate-keys']);

const nowSeconds = () => Math.floor(Date.now() / 1000);
// Secret names such as "constructor" or "toString" are valid, so never read them through the prototype chain.
const own = (object, key) => (Object.hasOwn(object, key) ? object[key] : undefined);
const isInt = (value) => Number.isSafeInteger(value);
const byBytes = (a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
const sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

function checkName(name) {
  if (typeof name !== 'string' || !NAME.test(name) || name.split('/').some((part) => ['', '.', '..'].includes(part))) {
    throw new RangeError(
      'secret names use 1-128 characters from A-Z a-z 0-9 . _ - and / between non-empty segments, starting with a letter or digit'
    );
  }
  return name;
}

function checkActor(actor) {
  if (typeof actor !== 'string' || !ACTOR.test(actor)) throw new RangeError('actor must be 1-128 characters without control characters');
  return actor;
}

/** Exclusive `<vault>.lock` file (create-exclusive). A lock older than staleAfter seconds is treated as abandoned. */
function withLock(lockPath, timeoutSeconds, work, staleAfter = 120) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  for (;;) {
    try {
      const fd = fs.openSync(lockPath, 'wx', 0o600);
      fs.writeSync(fd, String(process.pid));
      fs.closeSync(fd);
      break;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      try {
        if (Date.now() / 1000 - fs.statSync(lockPath).mtimeMs / 1000 > staleAfter) {
          fs.unlinkSync(lockPath);
          continue;
        }
      } catch (inner) {
        if (inner.code === 'ENOENT') continue;
        throw inner;
      }
      if (Date.now() >= deadline) throw new VaultLockedError(`could not lock the vault (${lockPath}); another process is writing to it`);
      sleep(50);
    }
  }
  try {
    return work();
  } finally {
    try {
      fs.unlinkSync(lockPath);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
}

class Vault {
  #path;
  #cipher;
  #sealer;
  #actor;
  #auditReads;
  #clock;
  #verifyAudit;
  #lockTimeout;
  #data = null;
  #fileState = null;

  constructor(vaultPath, keyring, { actor, auditReads, clock, verifyAudit, lockTimeout }) {
    this.#path = vaultPath;
    this.#cipher = new FieldCipher(keyring);
    this.#sealer = new RecordSealer(keyring);
    this.#actor = checkActor(actor);
    this.#auditReads = auditReads;
    this.#clock = clock;
    this.#verifyAudit = verifyAudit;
    this.#lockTimeout = lockTimeout;
  }

  static create(vaultPath, keyring, { actor = 'system', clock = nowSeconds, lockTimeout = 10 } = {}) {
    const vault = new Vault(vaultPath, keyring, { actor, auditReads: false, clock, verifyAudit: true, lockTimeout });
    return withLock(`${vaultPath}.lock`, lockTimeout, () => {
      if (fs.existsSync(vaultPath)) throw new VaultExistsError(`a vault already exists at ${vaultPath}`);
      const data = {
        format: FORMAT,
        id: b64uEncode(crypto.randomBytes(16)),
        created: clock(),
        generation: 0,
        secrets: {},
        audit: [],
        manifest: '',
      };
      vault.#appendAudit(data, 'init', null, null);
      data.manifest = vault.#manifest(data);
      vault.#write(data);
      vault.#data = data;
      vault.#fileState = vault.#statState();
      return vault;
    });
  }

  static open(vaultPath, keyring, { actor = 'system', auditReads = false, clock = nowSeconds, verifyAudit = true, lockTimeout = 10 } = {}) {
    const vault = new Vault(vaultPath, keyring, { actor, auditReads, clock, verifyAudit, lockTimeout });
    vault.#reload();
    return vault;
  }

  // ------------------------------------------------------------------ reading

  names() {
    const { secrets } = this.#current();
    return Object.keys(secrets)
      .filter((name) => secrets[name].versions.some((v) => v.state === 'active'))
      .sort(byBytes);
  }

  /** Metadata only (version, created, by, state); never the value. */
  versions(name) {
    const entry = own(this.#current().secrets, checkName(name));
    if (entry === undefined) throw new SecretNotFoundError(`no secret named '${name}'`);
    return entry.versions.map((v) => ({ version: v.v, created: v.created, by: v.by, state: v.state }));
  }

  get(name, { version } = {}) {
    const data = this.#current();
    const entry = own(data.secrets, checkName(name));
    const active = (entry ? entry.versions : []).filter((v) => v.state === 'active');
    const chosen = version === undefined ? active[active.length - 1] : active.find((v) => v.v === version);
    if (chosen === undefined) {
      throw new SecretNotFoundError(`no active secret '${name}'${version === undefined ? '' : ` version ${version}`}`);
    }
    let value;
    try {
      value = this.#cipher.decrypt(chosen.token, context('vault', data.id, name, chosen.v));
    } catch (error) {
      if (error instanceof InvalidToken) {
        throw new TamperedVaultError(`secret '${name}' v${chosen.v} does not decrypt: wrong keyring or modified vault`);
      }
      throw error;
    }
    if (this.#auditReads) this.#mutate((d, emit) => emit('read', name, chosen.v));
    return value;
  }

  getString(name, options) {
    return this.get(name, options).toString('utf8');
  }

  audit() {
    return this.#current().audit.map((entry) => ({ ...entry }));
  }

  /** Re-read the file and check every integrity property. deep: true also decrypts every active secret. */
  verify({ deep = false } = {}) {
    this.#reload();
    if (!deep) return;
    const data = this.#data;
    for (const [name, entry] of Object.entries(data.secrets)) {
      for (const v of entry.versions) {
        if (v.state !== 'active') continue;
        try {
          this.#cipher.decrypt(v.token, context('vault', data.id, name, v.v));
        } catch (error) {
          if (error instanceof InvalidToken) throw new TamperedVaultError(`secret '${name}' v${v.v} does not decrypt`);
          throw error;
        }
      }
    }
  }

  /** A view limited to names under `prefix` (for example "payments/"), to give one component only its own secrets. */
  scoped(prefix) {
    return new ScopedVault(this, prefix);
  }

  // ------------------------------------------------------------------ writing

  /** Store a new version and return its number. Only the newest `retain` active versions are kept. */
  put(name, value, { retain = 10 } = {}) {
    checkName(name);
    const bytes = typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(value);
    if (bytes.length < 1 || bytes.length > MAX_VALUE_BYTES) throw new RangeError(`a secret must be 1 to ${MAX_VALUE_BYTES} bytes`);
    if (!Number.isInteger(retain) || retain < 1) throw new RangeError('retain must be at least 1');

    return this.#mutate((data, emit) => {
      if (!Object.hasOwn(data.secrets, name)) data.secrets[name] = { versions: [] };
      const entry = data.secrets[name];
      const number = entry.versions.reduce((max, v) => Math.max(max, v.v), 0) + 1;
      const token = this.#cipher.encrypt(bytes, context('vault', data.id, name, number));
      entry.versions.push({ v: number, created: this.#clock(), by: this.#actor, state: 'active', token });
      emit('put', name, number);
      const active = entry.versions.filter((v) => v.state === 'active');
      for (const old of active.slice(0, Math.max(0, active.length - retain))) {
        old.state = 'destroyed';
        old.token = null;
        emit('destroy', name, old.v);
      }
      return number;
    });
  }

  /** Irreversibly remove one version's ciphertext. */
  destroy(name, version) {
    checkName(name);
    this.#mutate((data, emit) => {
      const entry = own(data.secrets, name);
      const target = (entry ? entry.versions : []).find((v) => v.v === version && v.state === 'active');
      if (target === undefined) throw new SecretNotFoundError(`no active secret '${name}' version ${version}`);
      target.state = 'destroyed';
      target.token = null;
      emit('destroy', name, version);
    });
  }

  /** Destroy every version of a secret. The name and the audit trail remain. */
  delete(name) {
    checkName(name);
    this.#mutate((data, emit) => {
      const entry = own(data.secrets, name);
      const active = (entry ? entry.versions : []).filter((v) => v.state === 'active');
      if (active.length === 0) throw new SecretNotFoundError(`no active secret '${name}'`);
      for (const v of active) {
        v.state = 'destroyed';
        v.token = null;
      }
      emit('delete', name, null);
    });
  }

  /** Re-encrypt every active secret under the keyring's primary key; returns how many were rewritten. */
  rotateKeys() {
    return this.#mutate((data, emit) => {
      let count = 0;
      for (const name of Object.keys(data.secrets).sort(byBytes)) {
        for (const v of data.secrets[name].versions) {
          if (v.state !== 'active') continue;
          const fresh = this.#cipher.rotate(v.token, context('vault', data.id, name, v.v));
          if (fresh !== v.token) {
            v.token = fresh;
            count += 1;
          }
        }
      }
      emit('rotate-keys', null, null);
      return count;
    });
  }

  // ------------------------------------------------------------------ internals

  #mutate(apply) {
    return withLock(`${this.#path}.lock`, this.#lockTimeout, () => {
      const data = this.#readVerified();
      const events = [];
      const result = apply(data, (action, name, version) => events.push([action, name, version]));
      for (const [action, name, version] of events) this.#appendAudit(data, action, name, version);
      data.generation += 1;
      data.manifest = this.#manifest(data);
      this.#write(data);
      this.#data = data;
      this.#fileState = this.#statState();
      return result;
    });
  }

  #current() {
    if (this.#fileState !== this.#statState()) this.#reload();
    return this.#data;
  }

  #reload() {
    this.#data = this.#readVerified();
    this.#fileState = this.#statState();
  }

  #statState() {
    try {
      const stat = fs.statSync(this.#path, { bigint: true });
      return `${stat.mtimeNs}:${stat.size}:${stat.ino}`;
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw error;
    }
  }

  #readVerified() {
    let text;
    try {
      text = fs.readFileSync(this.#path, 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') throw new SecureKitError(`no vault at ${this.#path}; create one with Vault.create`);
      throw error;
    }
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      throw new TamperedVaultError('the vault file is not valid JSON');
    }
    Vault.#checkStructure(data);
    if (!this.#sealer.verify(this.#manifestRecord(data), context('vault', data.id, 'manifest'), data.manifest)) {
      throw new TamperedVaultError('the vault manifest does not match its contents (edited, truncated or wrong keyring)');
    }
    if (this.#verifyAudit) this.#checkAudit(data);
    return data;
  }

  static #checkStructure(data) {
    const bad = (reason) => {
      throw new TamperedVaultError(`malformed vault: ${reason}`);
    };
    const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
    if (!plain(data) || data.format !== FORMAT) bad('unknown format');
    if (typeof data.id !== 'string' || !isInt(data.created) || !isInt(data.generation) || typeof data.manifest !== 'string') bad('a header field has the wrong type');
    if (!plain(data.secrets) || !Array.isArray(data.audit)) bad('secrets or audit have the wrong type');
    for (const [name, entry] of Object.entries(data.secrets)) {
      try {
        checkName(name);
      } catch {
        bad('invalid secret name');
      }
      if (!plain(entry) || !Array.isArray(entry.versions) || entry.versions.length === 0) bad(`'${name}' has no version list`);
      let last = 0;
      for (const v of entry.versions) {
        const keys = plain(v) ? Object.keys(v).sort().join(',') : '';
        if (keys !== 'by,created,state,token,v') bad(`'${name}' has a malformed version`);
        if (!isInt(v.v) || v.v <= last) bad(`'${name}' versions are not increasing`);
        last = v.v;
        if (!isInt(v.created) || typeof v.by !== 'string' || !ACTOR.test(v.by)) bad(`'${name}' has bad metadata`);
        const consistent = (v.state === 'active' && typeof v.token === 'string') || (v.state === 'destroyed' && v.token === null);
        if (!consistent) bad(`'${name}' has an inconsistent state`);
      }
    }
  }

  #checkAudit(data) {
    let previous = '';
    data.audit.forEach((entry, i) => {
      const index = i + 1;
      const ok =
        entry !== null &&
        typeof entry === 'object' &&
        Object.keys(entry).sort().join(',') === 'action,actor,name,prev,seal,seq,ts,version' &&
        entry.seq === index &&
        entry.prev === previous &&
        ACTIONS.has(entry.action);
      if (!ok) throw new TamperedVaultError(`audit entry ${index} is out of sequence or malformed`);
      const { seal, ...record } = entry;
      let valid = false;
      try {
        valid = this.#sealer.verify(record, context('vault', data.id, 'audit'), seal);
      } catch {
        valid = false;
      }
      if (!valid) {
        throw new TamperedVaultError(`audit entry ${index} fails its seal (edited, or sealed under a key that is not in this keyring)`);
      }
      previous = seal;
    });
  }

  #appendAudit(data, action, name, version) {
    const previous = data.audit.length ? data.audit[data.audit.length - 1].seal : '';
    const record = { seq: data.audit.length + 1, ts: this.#clock(), actor: this.#actor, action, name, version, prev: previous };
    data.audit.push({ ...record, seal: this.#sealer.seal(record, context('vault', data.id, 'audit')) });
  }

  static #index(data) {
    const lines = [];
    for (const name of Object.keys(data.secrets).sort(byBytes)) {
      for (const v of data.secrets[name].versions) {
        const digest = crypto.createHash('sha256').update(v.token ?? '', 'utf8').digest('hex');
        lines.push([name, String(v.v), v.state, String(v.created), v.by, digest].join('\t'));
      }
    }
    return lines.join('\n');
  }

  #manifestRecord(data) {
    return {
      format: FORMAT,
      id: data.id,
      created: data.created,
      generation: data.generation,
      audit_head: data.audit.length ? data.audit[data.audit.length - 1].seal : '',
      audit_count: data.audit.length,
      index: Vault.#index(data),
    };
  }

  #manifest(data) {
    return this.#sealer.seal(this.#manifestRecord(data), context('vault', data.id, 'manifest'));
  }

  #write(data) {
    const temporary = `${this.#path}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
    const fd = fs.openSync(temporary, 'wx', 0o600);
    try {
      fs.writeSync(fd, `${JSON.stringify(data, null, 2)}\n`);
      fs.fsyncSync(fd);
    } catch (error) {
      fs.closeSync(fd);
      fs.rmSync(temporary, { force: true });
      throw error;
    }
    fs.closeSync(fd);
    try {
      fs.renameSync(temporary, this.#path);
    } catch (error) {
      fs.rmSync(temporary, { force: true });
      throw error;
    }
    try {
      const directory = fs.openSync(path.dirname(path.resolve(this.#path)), 'r');
      try {
        fs.fsyncSync(directory);
      } finally {
        fs.closeSync(directory);
      }
    } catch {
      // making the rename durable is best effort on platforms that allow it
    }
  }
}

/** Read/write access to the names under one prefix of a Vault. */
class ScopedVault {
  #vault;
  #prefix;

  constructor(vault, prefix) {
    if (typeof prefix !== 'string' || !prefix.endsWith('/')) throw new RangeError("a scope prefix ends with '/', for example 'payments/'");
    checkName(`${prefix}x`);
    this.#vault = vault;
    this.#prefix = prefix;
  }

  #allow(name) {
    if (!checkName(name).startsWith(this.#prefix)) throw new SecretNotFoundError(`'${name}' is outside the scope '${this.#prefix}'`);
    return name;
  }

  names() {
    return this.#vault.names().filter((name) => name.startsWith(this.#prefix));
  }

  get(name, options) {
    return this.#vault.get(this.#allow(name), options);
  }

  getString(name, options) {
    return this.#vault.getString(this.#allow(name), options);
  }

  put(name, value, options) {
    return this.#vault.put(this.#allow(name), value, options);
  }
}

module.exports = { Vault, ScopedVault, checkName };
