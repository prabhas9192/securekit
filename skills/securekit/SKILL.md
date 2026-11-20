---
name: securekit
description: Add application-level encryption to a Python or Node.js project with the securekit library in this repository. Use it to encrypt database fields (including SQLAlchemy models), search encrypted columns, make rows tamper-evident, verify signed webhooks, hash passwords with Argon2id, keep application secrets in an encrypted versioned vault, give each user a server-blind vault, and scan a codebase for unprotected secrets and data. Trigger on tasks about storing PII, passwords, API keys, tokens or secrets, "encrypt this", "make this app secure", key rotation, or removing secrets from a repo.
---

# securekit: integration skill for AI agents and production teams

You are adding encryption to someone's application. securekit is a **thin layer over vetted primitives** (AES-256-GCM, HMAC-SHA256,
HKDF, Argon2id from `cryptography` / `argon2-cffi` / `node:crypto`). It contains no cryptography of its own. Python and Node.js
produce and read identical tokens, seals, vault files and password hashes (`SPEC.md`).

**Building or reviewing a whole application?** This skill is only the *data-protection* part. Start with `../secure-app/SKILL.md`, which covers the threat model, authentication,
authorization, injection and web attacks, operations and delivery, and calls back here for encryption, secrets and password hashing.

**Say plainly to the user:** securekit is not independently audited and is not a compliance certification. It protects data
*inside the application*. TLS, disk encryption, KMS/HSM custody and backups are still needed: `docs/ENCRYPTION-MAP.md` lists every place and
who covers it.

Paths in this note (`python/`, `node/`, `docs/`, `SPEC.md`) are relative to the `securekit/` folder of this repository. Recipes use names from the
user's own app (`user`, `request`, `db`, `session`) as placeholders; everything from `securekit` is real API and was run as written.

## 1. Pick the right tool

| The task says... | Use | Python | Node.js |
|---|---|---|---|
| store a sensitive value in a database column | field encryption | `FieldCipher(ring).encrypt(v, context("users","ssn",row_id))` | `new FieldCipher(ring).encrypt(v, context('users','ssn',rowId))` |
| the same, with SQLAlchemy | model integration | `securekit.orm.SecureModels` + `EncryptedText` | n/a (use `FieldCipher`) |
| look rows up by an encrypted value (email) | blind index | `BlindIndexer(ring).index(v, context("users","email"))`, `.candidates(...)` for queries | same names, camelCase |
| detect edits to important rows | record seal | `RecordSealer(ring).seal(record, ctx)` / `.verify(...)` | same |
| verify or sign webhooks | request signing | `Signer(ring).verify(body, header)` | same |
| store user passwords | Argon2id | `hash_password`, `verify_password`, `needs_rehash` | `hashPassword`, `verifyPassword`, `needsRehash` |
| remove API keys / DB passwords from code and `.env` | **app secrets vault** | `securekit.vault.Vault` or `python -m securekit vault ...` | `Vault` or `node bin/securekit.js vault ...` |
| data the server must not be able to read | **per-user vault** | `securekit.uservault.UserVault` | `UserVault` |
| session ids, reset tokens | random tokens | `random_token()` | `randomToken()` |
| find what is unprotected in a codebase | scanner | `python -m securekit scan PATH` | (same tool, language independent) |
| a network secrets service with logins and policies | **not securekit** | use OpenBao / HashiCorp Vault / cloud secret manager; feed their data keys to `Keyring` | same |

## 2. Fast path (about an hour for one service)

1. **Install** (this repo is the source): `pip install -e securekit/python` (add `sqlalchemy` for the ORM layer, 2.0.x),
   `npm install ./securekit/node` (Node 24.7+ for Argon2id). Or copy the folder into the project so it is versioned with it.
2. **Make the keyring** once per environment: `python -m securekit genkeyring k1` prints JSON. Put it in the platform secret store
   and expose it to the app as `SECUREKIT_KEYRING`. Never commit it, never put it in an image or the database it protects.
3. **Scan first** to see the starting point: `python -m securekit scan . --fail-on never`. Fix `critical` and `high` items.
4. **Move secrets into the vault**: create it with `securekit vault init`, `printf %s "$VALUE" | securekit vault put NAME`
   for each, then read them at startup (recipe 3.3). Delete the old copies and **rotate anything that was ever in git**.
5. **Encrypt the sensitive columns** (recipes 3.1, 3.2). Decide the `context` for each column before writing data (it cannot change later).
6. **Replace password hashing** with Argon2id (recipe 3.5) and re-hash on login using `needs_rehash`.
7. **Add the checks to CI**: the test suites you wrote plus `python -m securekit scan . --fail-on high`.
8. **Write down** who owns the keyring, the rotation schedule and the restore procedure (`docs/RUNBOOK.md`).

## 3. Recipes

### 3.1 Encrypt a field (Python)

```python
from securekit import Keyring, FieldCipher, context, InvalidToken
ring = Keyring.from_env()                      # SECUREKIT_KEYRING
cipher = FieldCipher(ring)

token = cipher.encrypt("123-45-6789", context("users", "ssn", user.id))   # store this string
ssn = cipher.decrypt_str(token, context("users", "ssn", user.id))          # raises InvalidToken if moved to another row/column
```

```js
const { Keyring, FieldCipher, context } = require('securekit');
const cipher = new FieldCipher(Keyring.fromEnv());
const token = cipher.encrypt('123-45-6789', context('users', 'ssn', user.id));
const ssn = cipher.decryptString(token, context('users', 'ssn', user.id));
```

Use client-generated ids (UUIDs) so the id exists before you encrypt. Add a column for the token (TEXT) and another for a blind index if you search it.

### 3.2 SQLAlchemy 2.0 (Python), automatic

```python
class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(EncryptedText)
    email_idx: Mapped[Optional[str]] = mapped_column(String(100), index=True)   # blind index, maintained for you
    role: Mapped[str] = mapped_column(String(20))
    row_seal: Mapped[Optional[str]] = mapped_column(String(200))

secure = SecureModels(Keyring.from_env())
secure.register(User, encrypted=["email"], blind={"email_idx": "email"},
                seal=SealSpec("row_seal", ["id", "role"]), assign_id=lambda: str(uuid.uuid4()))

user = session.scalars(select(User).where(secure.blind_filter(User, "email", "a@x.com"))).one()
```

Rules the layer enforces: ids exist before the flush (autoincrement ints raise), sealed columns are set explicitly (no column
defaults), plaintext cannot reach an encrypted column through Core or bulk operations, and `select(User.email)` (a column, not an
entity) returns ciphertext. Loading a row whose ciphertext was moved raises `InvalidToken`; a changed sealed column raises `TamperedRowError`.

### 3.3 Application secrets vault

```bash
export SECUREKIT_KEYRING="$(cat keyring.json)"      # from the platform secret store in production
export SECUREKIT_VAULT=/var/lib/app/secrets.vault.json
python -m securekit vault init
printf %s "$STRIPE_KEY" | python -m securekit vault put payments/stripe_key       # value on stdin, never an argument
python -m securekit vault list
```

```python
from securekit import Keyring
from securekit.vault import Vault
vault = Vault.open(os.environ["SECUREKIT_VAULT"], Keyring.from_env(), actor="payments-api")
stripe_key = vault.scoped("payments/").get_str("payments/stripe_key")     # a component sees only its own prefix
```

```js
const { Keyring, Vault } = require('securekit');
const vault = Vault.open(process.env.SECUREKIT_VAULT, Keyring.fromEnv(), { actor: 'payments-api' });
const stripeKey = vault.scoped('payments/').getString('payments/stripe_key');
```

Versions are kept (newest 10 by default), `destroy` removes a version for good, `audit` shows who did what, `verify --deep` proves
the file and every secret are intact. Rotate keys with `securekit vault rotate-keys` after adding a new primary key to the keyring.

### 3.4 Webhooks

```python
from securekit import Keyring, Signer
signer = Signer(Keyring.from_env())
if not signer.verify(request.body, request.headers["X-Signature"]):      # replay window 300 s by default
    abort(401)
# to sign an outgoing request: header = signer.sign(body)   and send it as X-Signature
```

### 3.5 Passwords

```python
stored = hash_password(password)                    # Argon2id, store the string
if verify_password(password, stored):
    if needs_rehash(stored): stored = hash_password(password)           # upgrade silently on login
```

On Node.js older than 24.7 these throw a clear error instead of failing quietly. Never log or return the hash to clients.

### 3.6 Per-user vault (server cannot read)

```python
vault, recovery_key = UserVault.create(user_id, passphrase, with_recovery=True)   # show recovery_key once
db.save(user_id, vault.state)                       # JSON with wrapped keys only
token = vault.encrypt_item("note-1", "text")        # store the token
# later, on the client with the passphrase:
vault = UserVault.unlock(user_id, db.load(user_id), passphrase)
```

The passphrase must never be sent to the server. A forgotten passphrase without a recovery key means the data is gone. That is the design.

### 3.7 Key rotation

Add a new key id to the keyring and make it `primary`, keep the old one. Then for fields call `cipher.rotate(token, ctx)` (or
`secure.mark_for_rotation(obj)` for SQLAlchemy rows, paged, see README), and `vault rotate-keys` for the vault. Remove the old key
only when `needs_rotation` is false everywhere and old audit entries are archived (a retired key can no longer verify them).

## 4. Rules for the agent

1. **Never write your own cryptography** and never "improve" a securekit construction. Use the API; if it cannot do something, say so.
2. **Never print, log, commit or paste secrets**, keys, vault values or passwords, including in your own summaries or test output.
   Pass secret values on stdin or through environment variables, never as command-line arguments.
3. **Never swallow `InvalidToken`, `TamperedRowError` or `TamperedVaultError`** and carry on with a default. They mean the data was moved, edited or
   encrypted under another key. Surface them, log the identifier (not the value), and stop the request.
4. **Never lower a safety setting to make a test pass** (verify off, audit verification off, a shorter key, a weaker hash).
5. **Do not invent keys.** Use `generate_key()` / `genkeyring`. A passphrase is rejected as a root key on purpose.
6. **Set the `context` deliberately** (table, column, row id) and never change it for existing data without re-encrypting.
7. **Do not index low-entropy columns** with a blind index (booleans, status codes); equality leaks.
8. **Say what remains.** After you finish, list what is still unprotected (TLS, disk, backups, KMS, other languages) using `docs/ENCRYPTION-MAP.md`.
9. **Do not claim compliance.** Say "this supports your PCI/HIPAA/GDPR work" at most, never "this makes you compliant".
10. If a user wants a vault *server* with logins and policies, recommend an established product and wire securekit to it; do not build one.

## 5. Verify before you say "done"

```bash
cd securekit/python && python -m unittest discover -s tests -t .        # needs sqlalchemy for the ORM tests (they skip without it)
cd securekit/node   && node --test                                       # Node 24.7+
python -m securekit scan <project> --fail-on high                        # the project you changed
python -m securekit vault verify --deep                                  # if you used a vault
```

Also write at least one test in the user's project that proves the **negative**: a ciphertext moved to another row is rejected, plaintext is
not in the database, a tampered sealed column is refused.

## 6. What errors mean

| Error | Meaning | Do |
|---|---|---|
| `InvalidToken` | wrong key, wrong context, edited or truncated ciphertext | check the context and keyring; never ignore |
| `UnknownKeyError` | token written under a key id that is not in the keyring | restore the retired key or finish the rotation |
| `TamperedRowError` | a sealed column was changed outside the app | treat as an incident; compare with backup |
| `TamperedVaultError` | vault edited, truncated, mixed up, or the wrong keyring | stop; restore from backup; check who had write access |
| `VaultLockedError` | another process holds the lock | retry; a lock older than 2 minutes is treated as abandoned |
| `WrongPassphraseError` | wrong passphrase / recovery key / another user's state | ask again; there is no reset |
| `SecretNotFoundError` | no such active secret or version | check the name and version |
| scan exit code 1 | findings at or above `--fail-on` | fix, or mark reviewed lines `securekit-ignore: rule-id` |

## 7. Files

- `README.md` overview and API tour · `SPEC.md` wire formats (normative) · `docs/ENCRYPTION-MAP.md` every place to encrypt ·
  `docs/RUNBOOK.md` operating it · `vectors/vectors.json` cross-language test vectors · `python/examples/orm_quickstart.py` runnable demo.
