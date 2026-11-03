'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const sk = require('../src');
const { KEY_K1, KEY_K2, ring } = require('./helpers');

const {
  Vault,
  Keyring,
  SecretNotFoundError,
  TamperedVaultError,
  VaultExistsError,
  VaultLockedError,
} = sk;

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'securekit-vault-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const state = { now: 1_700_000_000 };
  const clock = () => state.now;
  const file = path.join(dir, 'secrets.vault.json');
  const vault = Vault.create(file, ring(), { actor: 'deploy', clock });
  const reopen = (options = {}) => Vault.open(file, options.keyring ?? ring(), { clock, ...options });
  const edit = (change, target = file) => {
    const data = JSON.parse(fs.readFileSync(target, 'utf8'));
    change(data);
    fs.writeFileSync(target, JSON.stringify(data));
  };
  return { dir, file, state, clock, vault, reopen, edit };
}

test('vault: round trip, nothing readable on disk, private file mode', (t) => {
  const { vault, file, reopen } = fixture(t);
  assert.equal(vault.put('payments/stripe_key', 'sk_live_SECRET123'), 1);
  assert.equal(vault.getString('payments/stripe_key'), 'sk_live_SECRET123');
  assert.deepEqual(reopen().get('payments/stripe_key'), Buffer.from('sk_live_SECRET123'));
  assert.ok(!fs.readFileSync(file, 'utf8').includes('SECRET123'));
  if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.ok(!fs.existsSync(`${file}.lock`));
});

test('vault: binary values and listing', (t) => {
  const { vault } = fixture(t);
  vault.put('a/b', Buffer.from([0, 255, 1]));
  vault.put('c', 'x');
  assert.deepEqual(vault.get('a/b'), Buffer.from([0, 255, 1]));
  assert.deepEqual(vault.names(), ['a/b', 'c']);
});

test('vault: versions, retention, destroy; version numbers are never reused', (t) => {
  const { vault, file } = fixture(t);
  for (let n = 1; n <= 4; n += 1) assert.equal(vault.put('k', `value${n}`, { retain: 2 }), n);
  assert.deepEqual(vault.versions('k').map((v) => [v.version, v.state]), [[1, 'destroyed'], [2, 'destroyed'], [3, 'active'], [4, 'active']]);
  assert.equal(vault.getString('k'), 'value4');
  assert.equal(vault.getString('k', { version: 3 }), 'value3');
  assert.throws(() => vault.get('k', { version: 1 }), SecretNotFoundError);
  vault.destroy('k', 4);
  assert.equal(vault.getString('k'), 'value3');
  assert.ok(!fs.readFileSync(file, 'utf8').includes('value4'));
  assert.equal(vault.put('k', 'value5'), 5);
});

test('vault: delete and missing names', (t) => {
  const { vault } = fixture(t);
  vault.put('gone', 'x');
  vault.delete('gone');
  assert.deepEqual(vault.names(), []);
  for (const action of [() => vault.get('gone'), () => vault.get('never'), () => vault.delete('gone'), () => vault.destroy('never', 1), () => vault.versions('never')]) {
    assert.throws(action, SecretNotFoundError);
  }
});

test('vault: names that collide with Object.prototype members are ordinary names', (t) => {
  const { vault, reopen } = fixture(t);
  for (const name of ['constructor', 'toString', 'hasOwnProperty', 'valueOf']) {
    assert.throws(() => vault.get(name), SecretNotFoundError);
    assert.throws(() => vault.versions(name), SecretNotFoundError);
    assert.equal(vault.put(name, `value-of-${name}`), 1);
    assert.equal(reopen().getString(name), `value-of-${name}`);
  }
  assert.deepEqual(vault.names(), ['constructor', 'hasOwnProperty', 'toString', 'valueOf']);
  assert.throws(() => vault.put('__proto__', 'x'), RangeError);
});

test('vault: names, values and arguments are validated', (t) => {
  const { vault, file } = fixture(t);
  for (const bad of ['', '/x', 'x/', 'a//b', 'a/../b', 'a/./b', 'has space', 'x'.repeat(129), '-x', 'é', 5]) {
    assert.throws(() => vault.put(bad, 'v'), RangeError, String(bad));
  }
  for (const bad of ['', Buffer.alloc(0), 'x'.repeat(1_048_577)]) assert.throws(() => vault.put('ok', bad), RangeError);
  assert.throws(() => vault.put('ok', 'v', { retain: 0 }), RangeError);
  assert.throws(() => Vault.create(file, ring()), VaultExistsError);
});

test('vault: the audit trail records who did what; reads are not audited by default', (t) => {
  const { vault, reopen, state } = fixture(t);
  vault.put('k', 'v1');
  state.now += 5;
  const other = reopen({ actor: 'payments-api', auditReads: true });
  other.get('k');
  other.delete('k');
  const trail = reopen().audit().map((e) => [e.seq, e.actor, e.action, e.name, e.version]);
  assert.deepEqual(trail, [[1, 'deploy', 'init', null, null], [2, 'deploy', 'put', 'k', 1], [3, 'payments-api', 'read', 'k', 1], [4, 'payments-api', 'delete', 'k', null]]);

  const quiet = fixture(t);
  quiet.vault.put('k', 'v');
  const before = quiet.vault.audit().length;
  quiet.reopen().get('k');
  assert.equal(quiet.reopen().audit().length, before);
});

test('vault: any edit to the file is detected', (t) => {
  const { vault, file, reopen, edit } = fixture(t);
  vault.put('k', 'v1');
  vault.put('k', 'v2');
  const original = fs.readFileSync(file, 'utf8');
  const edits = {
    'bump generation': (d) => { d.generation += 1; },
    'change metadata': (d) => { d.secrets.k.versions[0].by = 'mallory'; },
    'drop a version': (d) => { d.secrets.k.versions.pop(); },
    'rename a secret': (d) => { d.secrets.other = d.secrets.k; delete d.secrets.k; },
    'edit audit entry': (d) => { d.audit[1].actor = 'mallory'; },
    'delete audit entry': (d) => { d.audit.splice(1, 1); },
    'truncate audit tail': (d) => { d.audit.pop(); },
    'swap tokens': (d) => { d.secrets.k.versions[0].token = d.secrets.k.versions[1].token; },
    'change vault id': (d) => { d.id = 'AAAAAAAAAAAAAAAAAAAAAA'; },
    'wrong format': (d) => { d.format = 'other/1'; },
    'bad state': (d) => { d.secrets.k.versions[0].state = 'weird'; },
  };
  for (const [label, change] of Object.entries(edits)) {
    fs.writeFileSync(file, original);
    edit(change);
    assert.throws(() => reopen(), TamperedVaultError, label);
  }
});

test('vault: garbage files are tamper errors, not crashes', (t) => {
  const { file, reopen } = fixture(t);
  for (const content of ['', 'not json', '[]', '{}', '{"format": "securekit-vault/1"}', 'null', '"text"']) {
    fs.writeFileSync(file, content);
    assert.throws(() => reopen(), TamperedVaultError, JSON.stringify(content));
  }
});

test('vault: a token copied between vaults does not decrypt; a wrong keyring is refused', (t) => {
  const first = fixture(t);
  const second = fixture(t);
  first.vault.put('k', 'from-first');
  second.vault.put('k', 'from-second');
  const stolen = JSON.parse(fs.readFileSync(first.file, 'utf8')).secrets.k.versions[0].token;
  second.edit((d) => { d.secrets.k.versions[0].token = stolen; }, second.file);
  assert.throws(() => Vault.open(second.file, ring(), { clock: second.clock }), TamperedVaultError);
  assert.throws(() => first.reopen({ keyring: new Keyring({ zz: KEY_K1 }, 'zz') }), TamperedVaultError);
});

test('vault: audit verification can be switched off; truncation is still caught but a middle edit is not', (t) => {
  const { vault, reopen, edit } = fixture(t);
  vault.put('k', 'v');
  edit((d) => { d.audit[0].actor = 'mallory'; });
  assert.throws(() => reopen(), TamperedVaultError);
  reopen({ verifyAudit: false });
  edit((d) => { d.audit.pop(); });
  assert.throws(() => reopen({ verifyAudit: false }), TamperedVaultError);
});

test('vault: key rotation moves everything to the primary key; retired keys cannot verify old audit entries', (t) => {
  const { dir, clock } = fixture(t);
  const file = path.join(dir, 'k1.json');
  const v1 = Vault.create(file, new Keyring({ k1: KEY_K1 }, 'k1'), { clock });
  v1.put('a', '1');
  v1.put('b', '2');
  const v2 = Vault.open(file, ring('k2', ['k1', 'k2']), { actor: 'ops', clock });
  assert.equal(v2.getString('a'), '1');
  assert.equal(v2.rotateKeys(), 2);
  assert.equal(v2.rotateKeys(), 0);
  const tokens = Object.values(JSON.parse(fs.readFileSync(file, 'utf8')).secrets).flatMap((e) => e.versions.map((v) => v.token));
  assert.ok(tokens.every((token) => token.startsWith('sk1.k2.')));
  v2.verify({ deep: true });

  const retired = new Keyring({ k2: KEY_K2 }, 'k2');
  assert.throws(() => Vault.open(file, retired, { clock }), TamperedVaultError);
  Vault.open(file, retired, { clock, verifyAudit: false });
});

test('vault: a held lock times out and a stale lock is cleared', (t) => {
  const { vault, file, clock } = fixture(t);
  fs.writeFileSync(`${file}.lock`, '999999');
  const quick = Vault.open(file, ring(), { clock, lockTimeout: 0.3 });
  assert.throws(() => quick.put('k', 'v'), VaultLockedError);
  const stale = new Date(Date.now() - 10_000_000);
  fs.utimesSync(`${file}.lock`, stale, stale);
  assert.equal(quick.put('k', 'v'), 1);
  assert.ok(vault);
});

test('vault: two handles see each other\'s writes', (t) => {
  const { reopen } = fixture(t);
  const [first, second] = [reopen(), reopen()];
  first.put('shared', '1');
  assert.equal(second.getString('shared'), '1');
  second.put('shared', '2');
  assert.equal(first.getString('shared'), '2');
});

test('vault: a scoped view only reaches its prefix', (t) => {
  const { vault } = fixture(t);
  vault.put('payments/key', 'p');
  vault.put('email/key', 'e');
  const scoped = vault.scoped('payments/');
  assert.deepEqual(scoped.names(), ['payments/key']);
  assert.equal(scoped.getString('payments/key'), 'p');
  scoped.put('payments/other', 'x');
  assert.throws(() => scoped.get('email/key'), SecretNotFoundError);
  assert.throws(() => scoped.put('email/new', 'x'), SecretNotFoundError);
  assert.throws(() => vault.scoped('payments'), RangeError);
});

test('cli: strict flag parsing, --flag=value, --help, and missing --version rejection', (t) => {
  const { execFileSync } = require('node:child_process');
  const { dir, file } = fixture(t);
  const bin = path.join(__dirname, '..', 'bin', 'securekit.js');
  const keyringJson = JSON.stringify({ primary: 'k2', keys: { k1: KEY_K1, k2: KEY_K2 } });
  const env = { ...process.env, SECUREKIT_KEYRING: keyringJson };
  const run = (args, input) => {
    try {
      const stdout = execFileSync(process.execPath, [bin, ...args], { env, input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      return { code: 0, stdout };
    } catch (err) {
      return { code: err.status, stdout: err.stdout || '', stderr: err.stderr || '' };
    }
  };

  assert.equal(run(['--help']).code, 0);
  assert.equal(run(['vault', `--file=${file}`, 'put', 'api/key'], 'secret-v1').code, 0);
  assert.equal(run(['vault', `--file=${file}`, 'put', 'api/key'], 'secret-v2').code, 0);
  const okV1 = run(['vault', `--file=${file}`, 'get', 'api/key', '--version=1']);
  assert.equal(okV1.code, 0);
  assert.equal(okV1.stdout, 'secret-v1');

  // Missing --version value must fail (exit 2), NEVER silently return latest secret!
  assert.equal(run(['vault', `--file=${file}`, 'get', 'api/key', '--version']).code, 2);
  // --version 0 must not fall back to latest; it must fail as not found (exit 1)
  assert.equal(run(['vault', `--file=${file}`, 'get', 'api/key', '--version', '0']).code, 1);
  // Unknown flag must fail (exit 2)
  assert.equal(run(['vault', `--file=${file}`, '--unknown', 'list']).code, 2);
});
