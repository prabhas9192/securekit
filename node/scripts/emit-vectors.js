'use strict';
// Writes ../vectors/from-node.json: tokens and password hashes produced by THIS package, so the Python
// suite (tests/test_vectors.py) can prove it reads what Node writes. Run: npm run emit-vectors

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { FieldCipher, Keyring, UserVault, Vault, context, hashPassword } = require('../src');

const vectorsDir = path.join(__dirname, '..', '..', 'vectors');
const base = JSON.parse(fs.readFileSync(path.join(vectorsDir, 'vectors.json'), 'utf8'));
const cipher = new FieldCipher(Keyring.fromJSON(JSON.stringify(base.keyring)));

const ctx = context('users', 'ssn', 7);
const fields = [Buffer.from('123-45-6789 ✓', 'utf8'), Buffer.from(Array.from({ length: 52 }, (_, i) => i * 5)), Buffer.alloc(0)].map(
  (plaintext) => ({ context: ctx, plaintext_hex: plaintext.toString('hex'), token: cipher.encrypt(plaintext, ctx) })
);

const password = 'pässwörd from node';

// A vault and a user vault written by this implementation, for the Python suite to open.
const ring = Keyring.fromJSON(JSON.stringify(base.keyring));
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'securekit-emit-'));
const vaultPath = path.join(directory, 'vault.json');
const secretBytes = Buffer.from(Array.from({ length: 16 }, (_, i) => i * 17));
const vault = Vault.create(vaultPath, ring, { actor: 'node-gen', clock: () => 1_700_000_000 });
vault.put('payments/stripe_key', 'sk_live_ünïcode-✓', { retain: 5 });
vault.put('db/password', 'hunter2');
vault.put('db/password', 'hunter3');
vault.destroy('db/password', 1);
vault.put('binary/blob', secretBytes);
const vaultFile = JSON.parse(fs.readFileSync(vaultPath, 'utf8'));
fs.rmSync(directory, { recursive: true, force: true });

const userPassphrase = 'pässwörd correct horse';
const { vault: userVault, recoveryKey } = UserVault.create('user-42', userPassphrase, { withRecovery: true });
const userItems = [['note-1', Buffer.from('my private note ✓', 'utf8')], ['note-2', Buffer.from([0, 1, 2])]];

const out = {
  fields,
  passwords: [{ password, hash: hashPassword(password) }],
  vault: {
    file: vaultFile,
    active: [
      { name: 'payments/stripe_key', version: 1, value_hex: Buffer.from('sk_live_ünïcode-✓', 'utf8').toString('hex') },
      { name: 'db/password', version: 2, value_hex: Buffer.from('hunter3').toString('hex') },
      { name: 'binary/blob', version: 1, value_hex: secretBytes.toString('hex') },
    ],
    destroyed: [{ name: 'db/password', version: 1 }],
    audit_actions: vaultFile.audit.map((entry) => entry.action),
  },
  uservault: {
    user_id: 'user-42',
    passphrase: userPassphrase,
    also_valid_passphrases: ['pässwörd correct horse'],
    wrong_passphrases: ['wrong passphrase'],
    recovery_key: recoveryKey,
    state: userVault.state,
    items: userItems.map(([itemId, data]) => ({ item_id: itemId, plaintext_hex: data.toString('hex'), token: userVault.encryptItem(itemId, data) })),
  },
};

fs.writeFileSync(path.join(vectorsDir, 'from-node.json'), `${JSON.stringify(out, null, 2)}\n`);
console.log('wrote vectors/from-node.json');
