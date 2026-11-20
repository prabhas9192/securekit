<div align="center">

# SecureKit

**Opinionated Application-Level Cryptography, Vaults, Scanner & Secure-SDLC AI Skills**

Encrypt database fields, search encrypted columns, detect tampered rows, verify webhooks, hash passwords, manage versioned secrets vaults, and scan codebases across **Python & Node.js**.

<p>
  <a href="https://github.com/prabhas9192/securekit/actions/workflows/ci.yml"><img src="https://github.com/prabhas9192/securekit/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/Node.js-24.7%2B-339933?style=flat-square&logo=nodedotjs&logoColor=white" alt="Node.js 24.7+" />
  <img src="https://img.shields.io/badge/Node%20Deps-Zero-111827?style=flat-square" alt="Zero Node Dependencies" />
  <img src="https://img.shields.io/badge/License-MIT-374151?style=flat-square" alt="MIT License" />
</p>

</div>

---

SecureKit has **no cryptographic primitives of its own**. Everything is composed from `AES-256-GCM`, `HMAC-SHA256`, `HKDF-SHA256`, and `Argon2id` as provided by:

| Language | Implementation | Dependencies |
| :--- | :--- | :--- |
| **Python 3.10+** | `cryptography` (OpenSSL), `argon2-cffi` | Both on PyPI |
| **Node.js 24.7+** | Built-in `node:crypto` (including `crypto.argon2`) | None |

Both packages follow [SPEC.md](SPEC.md) and are verified against the same cross-language [test vectors](vectors/vectors.json).

> **Status: not independently audited.** This is a thin, opinionated wrapper, not a certified cryptographic module. Have an independent security review before protecting data you cannot afford to lose. See [Limits and status](#limits-and-status).

---

## What It Does

| Need | API | Notes |
| :--- | :--- | :--- |
| Encrypt a column | `FieldCipher.encrypt / decrypt / rotate` | AES-256-GCM, key IDs, **mandatory** context bound as AAD |
| Search an encrypted column | `BlindIndexer.index / candidates` | Per-column keys, NFKC normalization, rotation-aware |
| Detect tampered rows | `RecordSealer.seal / verify` | HMAC over **every** field plus row context |
| Verify webhooks / signed requests | `Signer.sign / verify` | Timestamped, replay window, constant-time compare |
| Store passwords | `hash_password / verify_password / needs_rehash` | Argon2id, RFC 9106 parameters, NFKC |
| Tokens | `random_token`, `constant_time_equals` | OS CSPRNG |
| SQLAlchemy models | `securekit.orm.SecureModels`, `EncryptedText` | Encrypts, indexes, and seals automatically; see [SQLAlchemy 2.0](#sqlalchemy-20) |
| Application secrets | `Vault`, `securekit vault ...` | Encrypted, versioned, hash-chained audited file vault; see [Vaults, Scanner & AI Skills](#vaults-scanner--ai-skills) |
| Server-blind user data | `UserVault` | Passphrase-derived key, optional recovery key |
| Static security scanner | `securekit scan` | Heuristic, language-independent secret & web-attack scan |

Keys are 32 random bytes in a `Keyring` with key IDs. Passphrases are rejected, because nothing in `Keyring` stretches them.

---

## Python Quickstart

From the repository root:

```bash
pip install -e ./python
securekit genkeyring k1 > keyring.json            # or: python -m securekit genkeyring k1
export SECUREKIT_KEYRING="$(cat keyring.json)"
```

```python
from securekit import (
    Keyring, FieldCipher, BlindIndexer, RecordSealer,
    context, hash_password, verify_password,
)

ring = Keyring.from_env()
cipher, blind, sealer = FieldCipher(ring), BlindIndexer(ring), RecordSealer(ring)

row_id = 42
ssn = cipher.encrypt("123-45-6789", context("users", "ssn", row_id))     # 'sk1.k1.<...>'
cipher.decrypt_str(ssn, context("users", "ssn", row_id))                 # raises InvalidToken in any other row or column

email_idx = blind.index("Alice@Example.com", context("users", "email"))  # store next to encrypted email
# SELECT ... WHERE email_idx IN :candidates
candidates = blind.candidates("alice@example.com", context("users", "email"))

seal = sealer.seal({"id": row_id, "role": "admin", "password_hash": stored_hash}, context("users", row_id))
sealer.verify(record, context("users", row_id), seal)

stored = hash_password("correct horse battery staple")
verify_password("correct horse battery staple", stored)                  # True
```

---

## SQLAlchemy 2.0

From the repository root:

```bash
pip install -e "./python[sqlalchemy]"
python python/examples/orm_quickstart.py         # runnable end-to-end demo
```

```python
class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(EncryptedText)                          # ciphertext at rest
    email_idx: Mapped[Optional[str]] = mapped_column(String(100), index=True)  # blind index, maintained automatically
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

A column type cannot see its row, so `SecureModels` hooks the flush and load events instead. Before an `INSERT` or `UPDATE`, plaintext attributes are replaced by tokens bound to `context(table, column, *primary_key)`; after the flush, plaintext is restored on the instance; on load, tokens are decrypted. Plaintext never reaches the database layer, bind parameters, or SQL logs.

What you get, and what it refuses to do:

- A ciphertext copied to another row or column raises `InvalidToken` when loaded.
- A sealed column modified outside the application raises `TamperedRowError` on load and before re-sealing an expired instance.
- Core inserts, bulk updates, and filters touching an encrypted column raise instead of storing or comparing plaintext. Search using `secure.blind_filter(...)`.
- Primary key IDs must exist before flush because they are bound into every ciphertext. Use `assign_id` or set them in the constructor; autoincrement integer keys raise a clear error.
- Sealed columns must be set explicitly (a column `default` runs after seal computation and is rejected). Loading a sealed row without all sealed columns (`load_only`, deferred) raises unless `SealSpec(verify_on_load=False)` is set and `secure.verify_seal(obj)` is called manually.
- Non-primitive values (`datetime`, `Decimal`, `float`) require explicit `SealSpec(transforms=...)` or omission.
- Query ORM entities (`select(User)`), not raw columns (`select(User.ssn)` returns ciphertext). Discard instances if a flush fails.

Key rotation, paged so rows are not modified while a cursor is open:

```python
last = ""
while True:
    page = session.scalars(select(User).where(User.id > last).order_by(User.id).limit(500)).all()
    if not page:
        break
    last = page[-1].id
    for user in page:
        if secure.needs_rotation(user):
            secure.mark_for_rotation(user)       # flush re-encrypts, re-indexes, and re-seals
    session.commit()
```

Searching continues working seamlessly during rotation: `blind_filter` matches indexes under every key still present in the keyring.

---

## Vaults, Scanner & AI Skills

Start with the three guides written for engineers and AI coding agents:

- [`docs/ENCRYPTION-MAP.md`](docs/ENCRYPTION-MAP.md): every place an application needs encryption, recommended controls, and exact scope boundaries.
- [`skills/securekit/SKILL.md`](skills/securekit/SKILL.md): integration skill for AI agents (decision table, recipes, rules, verification, error taxonomy).
- [`docs/RUNBOOK.md`](docs/RUNBOOK.md): key ceremony, deployment, monitoring, rotation, backup/restore, incident response, and KMS integration.

**Full-app security skill:** [`skills/secure-app/`](skills/secure-app/SKILL.md) is a router skill with 8 focused references (threat modeling, authentication, authorization, injection/web attacks, platform ops, dependencies/delivery, domain packs for billing/POS/payments/health/mobile/SaaS, and a 32-gate release checklist), templates, an authorization-matrix tester, and an executable adversarial **benchmark** (`skills/secure-app/benchmark/` — reference app scores 100%, deliberately vulnerable app scores 7%).

### Application Secrets Vault

One JSON file holding versioned, encrypted secrets with a hash-chained tamper-evident audit log — interoperable across Python and Node.js:

```bash
export SECUREKIT_KEYRING="$(cat keyring.json)"
export SECUREKIT_VAULT=/var/lib/app/secrets.vault.json

securekit vault init                                       # or: node node/bin/securekit.js vault init
printf %s "$STRIPE_KEY" | securekit vault put payments/stripe_key
securekit vault get payments/stripe_key
securekit vault verify --deep
```

```python
vault = Vault.open("secrets.vault.json", Keyring.from_env(), actor="payments-api")
vault.scoped("payments/").get_str("payments/stripe_key")   # component sees only its own prefix
```

Each version is encrypted and bound to vault, name, and version; a manifest detects edited, swapped, removed, or inserted entries; the audit log is hash-chained; writes are atomic (`0600`) under an exclusive lock. See [`SPEC.md`](SPEC.md) section 7 and [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

### Server-Blind Per-User Vault

For data the server must not read: a random data key encrypts user items and is wrapped under an Argon2id key derived from the user's passphrase (plus an optional recovery key). Changing the passphrase re-wraps one key.

```python
vault, recovery_key = UserVault.create("user-42", passphrase, with_recovery=True)
token = vault.encrypt_item("note-1", "private note")
UserVault.unlock("user-42", vault.state, passphrase).decrypt_item_str("note-1", token)
```

### Static Security Scanner

```bash
securekit scan . --fail-on high                  # supports --json and --include-tests
```

Detects hard-coded secrets and private keys, committed `.env` files, secrets in Dockerfiles/Kubernetes manifests, weak hashes/ciphers, unauthenticated modes, predictable randomness, disabled TLS verification, unsafe JWT/cookie flags, tokens in browser storage, plaintext sensitive columns, secret logging, and common web-attack sinks (SQLi, command injection, `eval`, unsafe deserialization, XSS, debug mode, wildcard CORS, path traversal, SSRF, open redirects, disabled CSRF, default credentials). Secrets are always printed masked. Suppress reviewed false positives with `securekit-ignore: rule-id` or `.securekitignore`.

---

## Node.js Quickstart

Requires **Node.js 24.7+** (for built-in `crypto.argon2Sync`) with **zero npm dependencies**. From the repository root:

```bash
node node/bin/securekit.js genkeyring k1 > keyring.json
export SECUREKIT_KEYRING="$(cat keyring.json)"
```

Import directly from `./node/src` (or install locally into your project with `npm install ./node`):

```js
const {
  Keyring, FieldCipher, BlindIndexer, RecordSealer,
  context, hashPassword, verifyPassword,
} = require('./node/src');                       // or require('securekit') after `npm install ./node`

const ring = Keyring.fromEnv();
const cipher = new FieldCipher(ring);

const token = cipher.encrypt('123-45-6789', context('users', 'ssn', 42));
cipher.decryptString(token, context('users', 'ssn', 42));
```

Tokens, blind indexes, seals, signatures, password hashes, vault files, and user-vault states written by one language are verified readable by the other.

---

## Key Management & Rotation

1. Generate a new key (`genkey`) and add it to the keyring under a new ID (e.g., `k2`) while **keeping the old key**.
2. Set `primary` to `k2`. New writes use `k2`; reads under `k1` continue working.
3. Re-encrypt in the background: `if cipher.needs_rotation(token): token = cipher.rotate(token, ctx)`. For blind indexes, query with `candidates(...)` (all active keys) and re-index rows as touched.
4. Once `needs_rotation` is false everywhere, remove `k1`.

Random 96-bit nonces are safe for **at most 2³² encryptions per key** (NIST SP 800-38D). Rotate well before that threshold.

- **Keyring storage:** Never store root keys next to the data they protect. Load them from your platform's secret manager or KMS at startup (envelope encryption).
- **Row-level binding:** Include the row's primary key (`context("users", "ssn", row_id)`) to prevent cross-row ciphertext swapping. Prefer client-generated UUIDs over post-insert autoincrement IDs.

---

## Repository Layout

```text
securekit/
├── python/                  # Python 3.10+ library, SQLAlchemy 2.0 ORM, scanner, CLI & 145+ tests
├── node/                    # Zero-dependency Node.js 24.7+ library, CLI & 55 tests
├── vectors/                 # Shared cross-language wire-format test vectors
├── docs/                    # ENCRYPTION-MAP.md & operational RUNBOOK.md
├── skills/
│   ├── securekit/           # Library integration AI skill
│   └── secure-app/          # Full secure-SDLC router skill, 8 references, templates & benchmark
├── .github/workflows/ci.yml # Automated Python, Node 24, cross-language vector & self-scan CI
├── SPEC.md                  # Normative wire-format and cryptographic specification
├── plugin.json              # Plugin manifest
└── LICENSE                  # MIT License
```

---

## Limits and Status

- **Not independently reviewed or certified.** No FIPS 140 validation or compliance certification is claimed.
- **Node.js 24.7+ required for Argon2id.** `hashPassword` / `verifyPassword` rely on `crypto.argon2Sync` (added in Node 24.7) and throw a clear `SecureKitError` on older runtimes.
- **Cross-language verification:** `npm run emit-vectors` (in `node/`) writes `vectors/from-node.json`, which `python/tests/test_vectors.py` reads to prove full Node → Python compatibility (automated in CI).
- **Vaults & scanner boundaries:** The file vault does not detect rollback to an older complete file copy; file locking has not been stress-tested across many competing processes or on Windows; the static scanner is pattern-based (a clean scan is not proof of absence of flaws).
- **SQLAlchemy scope:** Verified on SQLAlchemy 2.0 with SQLite (25 ORM tests). Not yet tested against SQLAlchemy 2.1, PostgreSQL/MySQL drivers, async sessions, inheritance mappings, or composite primary keys.
- **Blind indexes leak equality and frequency** by design. Never index low-entropy fields (booleans, status codes) or values where frequency alone is sensitive.
- **Seals do not detect rollback or deletion.** Include a monotonic version counter inside the sealed record.
- **Unicode:** Normalization uses NFKC, which follows each runtime's Unicode table version (ASCII values never differ).
- **No pepper, rate limiting, breach checking, or password policy.** Enforce those at the application layer.
- **Key material in memory** is not zeroed (neither Python nor Node provides reliable guarantees).

---

## Tests

```bash
# Python suite (120 base + 25 SQLAlchemy ORM tests)
cd python && python -m unittest discover -s tests -t .

# Node.js suite (55 tests — requires Node 24.7+)
cd node && npm test

# Cross-language Node -> Python vector check
cd node && npm run emit-vectors
cd ../python && python -m unittest tests.test_vectors

# Self-scan repository (clean; intentional test fixtures listed in .securekitignore)
python -m securekit scan . --fail-on high
```

`python/gen_vectors.py` regenerates `vectors/vectors.json` — run only when `SPEC.md` changes.

---

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 `prabhas9192`. Provided as-is, without warranty, and not independently audited.
