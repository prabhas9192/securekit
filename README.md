# securekit

A small, opinionated layer for the things applications usually get wrong: encrypting database fields, searching
encrypted columns, detecting tampered rows, verifying webhooks and storing passwords. It has **no cryptographic
primitives of its own**. Everything is composed from AES-256-GCM, HMAC-SHA256, HKDF-SHA256 and Argon2id as
provided by:

| Language | Implementation | Dependencies |
| --- | --- | --- |
| Python 3.10+ | `cryptography` (OpenSSL), `argon2-cffi` | both on PyPI |
| Node.js 24.7+ | built-in `node:crypto`, including `crypto.argon2` | none |

Both packages follow [SPEC.md](SPEC.md) and are checked against the same [test vectors](vectors/vectors.json).

> **Status: not audited.** This is a thin wrapper, not a certified product. Have an independent review before it
> protects data you cannot afford to lose. See [Limits](#limits-and-status).

## What it does

| Need | API | Notes |
| --- | --- | --- |
| Encrypt a column | `FieldCipher.encrypt / decrypt / rotate` | AES-256-GCM, key ids, **mandatory** context bound as AAD |
| Search an encrypted column | `BlindIndexer.index / candidates` | per-column keys, Unicode normalization, rotation-aware |
| Detect tampered rows | `RecordSealer.seal / verify` | HMAC over **every** field plus the row context |
| Verify webhooks / signed requests | `Signer.sign / verify` | timestamped, replay window, constant-time |
| Store passwords | `hash_password / verify_password / needs_rehash` | Argon2id, RFC 9106 parameters, NFKC |
| Tokens | `random_token`, `constant_time_equals` | OS CSPRNG |
| SQLAlchemy models | `securekit.orm.SecureModels`, `EncryptedText` | encrypts, indexes and seals automatically; see [SQLAlchemy](#sqlalchemy-20) |
| Application secrets | `Vault`, `securekit vault ...` | encrypted, versioned, audited file vault; see [Vaults and scanning](#vaults-and-scanning) |
| Data the server must not read | `UserVault` | passphrase-derived key, optional recovery key |
| Finding unprotected spots | `securekit scan` | heuristic, language-independent |

Keys are 32 random bytes in a `Keyring` with key ids. Passphrases are rejected, because nothing here stretches them.

## Python

```bash
cd python
pip install -e .                              # cryptography, argon2-cffi
python -m securekit genkeyring k1 > keyring.json
export SECUREKIT_KEYRING="$(cat keyring.json)"
```

```python
from securekit import Keyring, FieldCipher, BlindIndexer, RecordSealer, context, hash_password, verify_password

ring = Keyring.from_env()
cipher, blind, sealer = FieldCipher(ring), BlindIndexer(ring), RecordSealer(ring)

row_id = 42
ssn = cipher.encrypt("123-45-6789", context("users", "ssn", row_id))     # 'sk1.k1.<...>'
cipher.decrypt_str(ssn, context("users", "ssn", row_id))                  # raises InvalidToken in any other row or column

email_idx = blind.index("Alice@Example.com", context("users", "email"))   # store next to the encrypted email
# SELECT ... WHERE email_idx IN :candidates
candidates = blind.candidates("alice@example.com", context("users", "email"))

seal = sealer.seal({"id": row_id, "role": "admin", "password_hash": stored_hash}, context("users", row_id))
sealer.verify(record, context("users", row_id), seal)

stored = hash_password("correct horse battery staple")
verify_password("correct horse battery staple", stored)                   # True
```

## SQLAlchemy 2.0

```bash
pip install -e "python[sqlalchemy]"
python python/examples/orm_quickstart.py      # runnable end-to-end demo
```

```python
class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(EncryptedText)                          # ciphertext at rest
    email_idx: Mapped[Optional[str]] = mapped_column(String(100), index=True)  # blind index, maintained for you
    ssn: Mapped[Optional[str]] = mapped_column(EncryptedText)
    role: Mapped[str] = mapped_column(String(20))
    balance: Mapped[int] = mapped_column(Integer)
    row_seal: Mapped[Optional[str]] = mapped_column(String(200))               # tamper seal

secure = SecureModels(Keyring.from_env())
secure.register(
    User,
    encrypted=["email", "ssn"],
    blind={"email_idx": "email"},
    seal=SealSpec("row_seal", ["id", "role", "balance"]),
    assign_id=lambda: str(uuid.uuid4()),
)

session.add(User(email="Alice@Example.com", ssn="123-45-6789", role="user", balance=10))
session.commit()
user = session.scalars(select(User).where(secure.blind_filter(User, "email", "alice@example.com"))).one()
user.email, user.ssn                                   # plaintext, decrypted on load
```

A column type cannot see its row, so `SecureModels` hooks the flush and load events instead. Before an INSERT or UPDATE
the plaintext attributes are replaced by tokens bound to `context(table, column, *primary_key)`; after the flush the
plaintext is put back on the instance; when a row loads the tokens are decrypted. Plaintext never reaches the
database layer, the bind parameters or the SQL log.

What you get, and what it refuses to do:

- A ciphertext copied to another row or column raises `InvalidToken` when the row loads.
- A sealed column changed behind the application's back raises `TamperedRowError` on load, and on the next
  update of an expired object (the stored row is verified first, so a tampered value is never re-sealed as if it were legitimate).
- Core inserts, bulk updates and filters that touch an encrypted column raise instead of storing or comparing plaintext.
  Search with `secure.blind_filter(...)`.
- Ids must exist before the flush, because they are bound into every ciphertext. Use `assign_id` (or set them in the
  constructor). Autoincrement integer keys raise a clear error.
- Sealed columns must be set explicitly: a column `default` is applied after the seal is computed, so it is rejected.
  Loading a sealed row without all sealed columns (`load_only`, deferred) raises; set `SealSpec(verify_on_load=False)`
  and call `secure.verify_seal(obj)` if you need that.
- Values that are not plain text, integers, booleans, bytes or null (datetimes, decimals, floats) cannot be sealed as
  they are; give `SealSpec(transforms={"created_at": lambda d: d.isoformat()})` or leave them out.
- Use ORM entities. `select(User.ssn)` returns ciphertext, not plaintext. If a flush fails, discard the instances in it.

Key rotation, paged so rows are not modified while a cursor is open (the same loop, with a page size of 2, is covered by a test):

```python
last = ""
while True:
    page = session.scalars(select(User).where(User.id > last).order_by(User.id).limit(500)).all()
    if not page:
        break
    last = page[-1].id
    for user in page:
        if secure.needs_rotation(user):
            secure.mark_for_rotation(user)     # the flush re-encrypts, re-indexes and re-seals
    session.commit()
```

Searching keeps working during a rotation: `blind_filter` matches indexes under every key still in the keyring.

## Vaults and scanning

Start with the three documents written for people (and AI agents) who need to integrate quickly:

- [`docs/ENCRYPTION-MAP.md`](docs/ENCRYPTION-MAP.md): **every place an application needs encryption**, what to do about each, and what securekit does and does not cover.
- [`skills/securekit/SKILL.md`](skills/securekit/SKILL.md): the integration skill note for AI agents (decision table, recipes, rules, verification, error meanings).
- [`docs/RUNBOOK.md`](docs/RUNBOOK.md): key ceremony, deployment, monitoring, rotation, backup and restore, incident response, and how to use securekit with a secrets server or KMS.

**Building a whole application securely:** [`skills/secure-app/`](skills/secure-app/SKILL.md) is a router skill with eight focused references (design and threat model,
authentication, authorization, injection and web attacks, platform and operations, dependencies and delivery, domain packs for billing/POS, payments, personal data, mobile,
SaaS and internal tools, and a release gate), templates, an authorization-matrix tester, and a **benchmark** that attacks any implementation of a small billing API and scores it
(`skills/secure-app/benchmark/`). The benchmark tooling is verified (the reference app scores 100%, a deliberately vulnerable one 7%); **no AI agent has been measured on it yet**.

**App secrets vault.** One JSON file holding versioned, encrypted secrets with a tamper-evident audit log. Same file, same CLI, either language:

```bash
export SECUREKIT_KEYRING="$(cat keyring.json)" SECUREKIT_VAULT=/var/lib/app/secrets.vault.json
python -m securekit vault init                               # or: node node/bin/securekit.js vault init
printf %s "$STRIPE_KEY" | python -m securekit vault put payments/stripe_key     # the value goes on stdin, never on the command line
python -m securekit vault get payments/stripe_key
python -m securekit vault list | versions NAME | destroy NAME VERSION | delete NAME | rotate-keys | audit | verify --deep
```

```python
vault = Vault.open("secrets.vault.json", Keyring.from_env(), actor="payments-api")
vault.scoped("payments/").get_str("payments/stripe_key")      # a component sees only its own prefix
```

Each version is encrypted and bound to the vault, name and version; a manifest detects edited, swapped, removed or added entries; the audit log is hash-chained;
the file is written atomically with mode 0600 under an exclusive lock. Names such as `constructor` work. Limits are in [`SPEC.md`](SPEC.md) section 7 and the runbook.

**Per-user vault.** For data the server must not be able to read: a random data key encrypts the user's items and is wrapped under an Argon2id key derived from the user's
passphrase (and optionally a recovery key). Changing the passphrase re-wraps one key. A forgotten passphrase without a recovery key loses the data on purpose.

```python
vault, recovery_key = UserVault.create("user-42", passphrase, with_recovery=True)
token = vault.encrypt_item("note-1", "private note")
UserVault.unlock("user-42", vault.state, passphrase).decrypt_item_str("note-1", token)
```

**Scanner.** `python -m securekit scan PATH [--json] [--fail-on high] [--include-tests]` looks for hard-coded secrets and private keys, committed `.env` files,
secrets in Dockerfiles and Kubernetes manifests, weak hashes and ciphers, unauthenticated modes, predictable randomness for tokens, disabled TLS verification,
unsafe JWT and cookie settings, tokens in browser storage, sensitive columns stored as plain text, sensitive values passed to log calls, and the web-attack patterns
(SQL and command injection, `eval`, unsafe deserialization, XSS sinks, debug mode, wildcard CORS, path traversal, SSRF, open redirects, disabled CSRF, hard-coded framework secret keys,
secrets in URLs, non-constant-time secret comparison, world-writable files, default credentials). It prints secret values only masked.
It matches text patterns, so it has false positives and false negatives: a clean scan is not proof. Suppress a reviewed line with `securekit-ignore: rule-id`
or list paths in `.securekitignore`.

## Node.js

```bash
cd node
node bin/securekit.js genkeyring k1 > keyring.json
export SECUREKIT_KEYRING="$(cat keyring.json)"
```

```js
const { Keyring, FieldCipher, BlindIndexer, RecordSealer, context, hashPassword, verifyPassword } = require('securekit');

const ring = Keyring.fromEnv();
const cipher = new FieldCipher(ring);

const token = cipher.encrypt('123-45-6789', context('users', 'ssn', 42));
cipher.decryptString(token, context('users', 'ssn', 42));
```

Tokens, indexes, seals, signatures and password hashes written by one language are read by the other.

## Key management and rotation

1. Generate a key (`genkey`) and add it to the keyring under a new id, for example `k2`, **keeping the old key**.
2. Set `primary` to `k2`. New writes use `k2`; everything under `k1` still reads.
3. Re-encrypt in the background: `if cipher.needs_rotation(token): token = cipher.rotate(token, ctx)`.
   For blind indexes query with `candidates(...)` (all keys) and re-index rows as you touch them.
4. When `needs_rotation` is false everywhere, remove `k1`.

Random 96-bit nonces are safe for **at most 2^32 encryptions per key** (NIST SP 800-38D). Rotate well before that.

**Where the keyring lives.** Do not store root keys next to the data they protect. Load them from your platform's
secret store or KMS at startup (envelope encryption: the KMS decrypts the data keys, `Keyring` holds them in memory).
No cloud adapters are included, because they cannot be tested here.

**Row-level binding.** Context should include the row's primary key (`context("users", "ssn", row_id)`), which stops
an attacker copying a ciphertext between rows. That is awkward with database-generated ids that only exist after
the insert. Prefer client-generated ids (UUIDs), or insert, then encrypt and update.

## Relationship to the older `protocol/` library in this repo

securekit replaces it for new code. What changed and why:

- **Dropped: the stateless "deterministic key" generator.** It is not an established pattern, cannot rotate a
  compromised password and had four divergent implementations. Use a password manager.
- **Dropped: PBKDF2 / scrypt hashing and thin SHA-256 / HMAC wrappers.** Argon2id only for new hashes; call
  `hashlib` / `node:crypto` directly for plain digests.
- **Changed: field encryption** now has key ids and rotation; the context is mandatory instead of optional.
- **Changed: blind indexes** use a per-column key; normalization is specified byte for byte.
- **Changed: the row seal** covers every field. Nothing is skipped by name, and it is not JSON-based, so Python
  and Node produce identical bytes.
- **Changed: master keys** must be 32 random bytes, not passphrases.

- **Changed: the ORM column types** (`protocol/orm_helpers.py`) only bound a column name. `securekit.orm` binds the
  table, column and primary key, and also maintains blind indexes and seals.

There is no automatic migration of old ciphertexts or seals; the wire formats differ.

## Limits and status

- **Not independently reviewed or certified.** No FIPS 140 validation; "compliant with X" is not a claim made here.
- **Node.js version matters.** The Node tests were run on Node v24+ (55 tests pass, 120 base Python tests + 25 SQLAlchemy ORM tests pass,
  and each language reads what the other writes, including vault files and user-vault states; the two command-line tools
  were also run against one shared vault file). Argon2id needs `crypto.argon2Sync`, added in Node 24.7. On an older
  runtime `hashPassword` / `verifyPassword` throw a clear error rather than failing quietly. The rest only uses APIs
  that predate Node 24, but it has not been run on an older version. Check `node --version` first if a Node test fails.
- **Cross-language check:** `npm run emit-vectors` writes `vectors/from-node.json`; the Python suite then verifies
  it can read Node's tokens and password hashes (that test is skipped until the file exists).
- **The vaults and the scanner** are covered by tests in both languages (vault: tamper cases, rotation, locking, scoping, cross-language files; user vault: wrong
  passphrase, hostile state, recovery; scanner: every rule, masking, ignores, exit codes). They have had no independent review. The file vault does not detect rollback
  to an older complete copy, and the scanner is a pattern matcher. Locking was tested between handles in one process and by simulating a stale lock, not with many
  competing processes, and not on Windows.
- **The SQLAlchemy integration** was tested on SQLAlchemy 2.0.55 with SQLite (25 tests; last run before the vault and scanner work, which only added classes to
  `errors.py`, so re-run them in your environment). It has not been run on 2.1,
  on PostgreSQL or MySQL, with async sessions, with inheritance mappings or with composite primary keys. The code
  is written for those, but "written for" is not "tested". The Python tests that need SQLAlchemy skip themselves
  when it is not installed.
- **Blind indexes leak equality and frequency** of plaintexts by design. Do not index low-entropy columns
  (booleans, status codes) or anything where equality alone is sensitive.
- **Seals do not detect rollback or deletion.** Put a version counter in the sealed record.
- **Unicode:** normalization uses NFKC, whose tables depend on the runtime's Unicode version. Characters assigned
  after a runtime's Unicode release can normalize differently across languages. ASCII values never differ.
- **No pepper, rate limiting, breach checking or password policy.** Those belong in the application.
- **Key material in memory** is not zeroed (neither language gives reliable control over that).

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 prabhas9192. The software is provided as is, without warranty, and has not been independently audited.

## Tests

```bash
cd python && python -m unittest discover -s tests -t .      # 120 tests, +25 when SQLAlchemy is installed
cd node   && npm test                                        # node --test, 55 tests, needs Node 24.7+ for Argon2id
python -m securekit scan .. --fail-on high                   # from securekit/python: the repo scans clean (fixtures are listed in .securekitignore)
```

The Python suite includes mutation-style checks that were run by hand: removing context binding, skipping `*_hash`
columns in seals, dropping the replay window, dropping per-column blind keys, accepting any key length and accepting
non-canonical base64 each makes the suite fail. The same was done for the ORM layer: dropping the row id or column
name from the ciphertext context, letting plaintext through the column type, skipping the stored-row check before a
re-seal, not restoring plaintext after a flush, and ignoring the primary key in the seal are each caught.

`python/gen_vectors.py` regenerates `vectors/vectors.json`. Run it only when the spec changes, because the encrypted
tokens and password hashes in it contain fresh random values.
