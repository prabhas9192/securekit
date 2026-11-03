# Where an application needs encryption: the complete map

Every place an application stores, moves, derives or proves something that an attacker would want, with what to do
about it and how much of it securekit covers. Use it as a checklist: go down the list, mark each row *done*, *n/a* or
*accepted risk*, and write down who owns it.

**Legend**

- ✅ securekit does it. Use the named API.
- 🟡 securekit helps with part of it. The note says which part and what is still yours.
- ⬜ Not securekit's job. Use the tool named here. Skipping these rows leaves holes that securekit cannot close.

securekit is application-level encryption: it protects data *as the application handles it*. It does not replace TLS, disk
encryption or a key management service, and it cannot protect data from code that is already running inside your app with
the keys loaded. Nothing here is a compliance claim.

---

## A. Data at rest

| # | Place | If left plain | What to do | securekit |
|---|---|---|---|---|
| A1 | Sensitive database columns (SSN, tax id, card number, health data, tokens you must read back) | A SQL injection, a stolen backup or a curious DBA reads everything | Encrypt per field with a context that names table, column and row | ✅ `FieldCipher`, or `SecureModels` + `EncryptedText` for SQLAlchemy |
| A2 | Searching those columns (login by email, lookup by SSN) | Either you cannot search, or you keep a plaintext copy to search | Store a keyed blind index next to the ciphertext and query the index | ✅ `BlindIndexer`, `SecureModels.blind_filter`. It reveals which rows are equal; do not index low-entropy columns |
| A3 | The whole database, disk or volume | A stolen disk or snapshot is readable | Full-disk or transparent database encryption from your cloud or OS | ⬜ LUKS, cloud volume encryption, TDE. Complements A1, does not replace it: it does nothing against SQL injection or a DBA |
| A4 | Tamper evidence for important rows (roles, balances, entitlements) | Someone with write access edits a value and nothing notices | Seal the row so any edit, swap or copy to another row fails verification | ✅ `RecordSealer`, `SealSpec`. Does not detect a rollback to an older valid row; add a version counter |
| A5 | User uploads and other blobs | Anyone with bucket or disk access reads documents | Encrypt before storage; keep the key out of the bucket | 🟡 `FieldCipher` for blobs up to a few MB (it holds the whole value in memory). No streaming mode: for large files use `age`, Tink streaming AEAD, or provider-side encryption |
| A6 | Object storage (S3, GCS, Azure Blob) | Public or over-shared buckets leak | Private by default, SSE-KMS, least-privilege policies, access logging | ⬜ Provider features. Client-side encryption of sensitive objects is 🟡 via `FieldCipher` |
| A7 | Backups, snapshots, database dumps | The backup is usually less protected than production | Encrypt every backup; keep the keys **separately** from them; test restores | ⬜ Backup tool encryption (`age`, `restic`, cloud). Your keyring and vault file must be in the backup plan too, see the runbook |
| A8 | Caches (Redis, Memcached) and session stores | Secrets and PII sit in memory and on disk, often unauthenticated | Do not cache secrets. If you must, encrypt the value; require auth and TLS | 🟡 `FieldCipher` for cached values |
| A9 | Message queues and event streams | Payloads are readable by every consumer and by broker admins | Encrypt sensitive fields in the payload, not the whole message; TLS on the broker | 🟡 `FieldCipher` for fields |
| A10 | Search indexes (Elasticsearch, OpenSearch) | Plaintext copies of everything, with weaker access control | Index blind indexes or non-sensitive fields only | 🟡 `BlindIndexer` for exact-match search |
| A11 | Logs, traces, metrics, error trackers | Passwords, tokens and PII end up in the most widely read system you have | Never log values; scrub before sending; short retention | 🟡 `securekit scan` flags `sensitive-logging`. Scrubbing is yours |
| A12 | Analytics, data warehouse, exports, CSV reports | Production secrets copied to places with weaker controls | Pseudonymise identifiers; encrypt exports; limit who can export | 🟡 `BlindIndexer` (exact mode) gives a stable pseudonym that cannot be reversed without the key |
| A13 | Temp files, swap, core dumps, crash reports | Secrets spill from memory to disk | Disk encryption, disable core dumps for secret-handling processes, avoid writing secrets to temp files | ⬜ OS settings |
| A14 | Email and attachments | Mail is routinely stored and forwarded in clear | Do not email secrets; use TLS (MTA-STS) for transport; end-to-end only if users need it | ⬜ |
| A15 | Config files and environment variables | Secrets in repos, images and `ps` output | Keep one small secret (the keyring) outside the repo and put the rest in the vault | ✅ `Vault` for application secrets |
| A16 | Client-side storage (browser, mobile, desktop) | Anything in `localStorage` is readable by any script on the page | Short-lived tokens in HttpOnly Secure cookies; mobile Keychain / Keystore | ⬜ Platform features. `securekit scan` flags `browser-token-storage` 🟡 |

## B. Data in transit

| # | Place | If left plain | What to do | securekit |
|---|---|---|---|---|
| B1 | Browser to server | Interception, injection, session theft | TLS 1.2+, HSTS, modern ciphers, valid certificates | ⬜ Your load balancer or web server. `securekit scan` flags `cleartext-http` and `tls-verification-off` 🟡 |
| B2 | Service to service | The internal network is not trusted | TLS everywhere; mutual TLS or a service mesh for sensitive paths | ⬜ |
| B3 | App to database | Credentials and data cross the network in clear | `sslmode=verify-full` (or the equivalent) with a pinned CA | ⬜ |
| B4 | App to cache, queue, search | Same as B3 | TLS plus authentication on every connection | ⬜ |
| B5 | Inbound webhooks and callbacks | Anyone can forge a call to your endpoint | Verify a signature over body and timestamp; reject old requests | ✅ `Signer.verify` |
| B6 | Outbound calls that others must trust | The receiver cannot tell the request is yours | Sign the body with a shared key | ✅ `Signer.sign` |
| B7 | Data the server must never read | A server breach exposes every user's data | Encrypt on the client under a key only the user holds; the server stores ciphertext | ✅ `UserVault` (passphrase-derived key, optional recovery key) |
| B8 | Admin access, SSH, CI runners | Stolen credentials and unaudited access | Keys not passwords, short-lived credentials, MFA, audit | ⬜ |

## C. Secrets and keys

| # | Place | If left plain | What to do | securekit |
|---|---|---|---|---|
| C1 | Application secrets (API keys, database passwords, third-party tokens) | A leaked repo or image is a breach | Keep them in a vault with versions, rotation and an audit trail | ✅ `Vault`, `securekit vault ...` CLI |
| C2 | The keyring (root keys) itself | Whoever has it can read everything securekit protects | Load from your platform's secret store or KMS at startup; never in the repo, the image or the same database | 🟡 `Keyring.from_env`. Where the value comes from is yours |
| C3 | CI/CD variables and pipelines | Pipeline logs and forks leak them | Scoped, masked variables; short-lived OIDC credentials; no secrets in build logs | ⬜ CI features. `securekit scan` in the pipeline catches committed secrets 🟡 |
| C4 | Container images and Dockerfiles | Secrets baked into layers are recoverable forever | No `ENV`/`ARG` secrets; mount or inject at runtime; BuildKit secret mounts | 🟡 scan rule `dockerfile-secret` |
| C5 | Kubernetes secrets | Base64 is not encryption; etcd and manifests expose them | Encrypt at rest in etcd; commit only sealed/SOPS/external-secret forms | ⬜ Scan rule `k8s-secret-manifest` points at the committed ones 🟡 |
| C6 | Infrastructure as code and Terraform state | State files contain every secret in clear | Encrypted remote state backend with tight access; no secrets in `.tfvars` in git | ⬜ Scan covers `.tfvars` 🟡 |
| C7 | Developer machines and git history | A secret committed once is exposed for good | Pre-commit scanning; rotate anything that ever touched git | 🟡 `securekit scan` as a hook or CI step |
| C8 | Key lifecycle: generate, rotate, retire, destroy | Old keys live forever; a leak is permanent | Rotate on a schedule and after any suspicion; keep retired keys only as long as data needs them | ✅ `generate_key`, keyring with key ids, `rotate`/`rotate_keys`, `mark_for_rotation`. The schedule and the sign-off are yours |
| C9 | Hardware custody (HSM, cloud KMS) | Keys exist as bytes in application memory | Keep the root key in a KMS/HSM and wrap data keys with it | ⬜ securekit has no KMS adapters; fetch data keys at startup and build a `Keyring` (see the runbook) |

## D. Identity and sessions

| # | Place | If left plain | What to do | securekit |
|---|---|---|---|---|
| D1 | User passwords | A database leak exposes every account, and reused passwords everywhere else | Argon2id with per-password salt; never encrypt passwords, hash them | ✅ `hash_password`, `verify_password`, `needs_rehash` |
| D2 | Session identifiers and cookies | Session theft | Random, long, Secure + HttpOnly + SameSite; store a hash server-side if you can | 🟡 `random_token`; hash with `BlindIndexer` (exact mode) so a database leak does not leak live sessions |
| D3 | JWTs and signing keys | Forged tokens | Pin the algorithm, verify signature and expiry, keep the signing key in the vault | 🟡 Vault for the key; scan rule `jwt-unsafe` |
| D4 | API keys you issue to customers | A database leak exposes every customer's key | Show once, store only a keyed hash, compare in constant time | 🟡 `random_token` + `BlindIndexer` (exact) + `constant_time_equals` |
| D5 | OAuth refresh tokens and third-party tokens you store for users | A leak lets attackers act as your users elsewhere | Encrypt per user; revoke on logout and on suspicion | ✅ `FieldCipher` with context naming the user |
| D6 | MFA/TOTP seeds and recovery codes | Seeds are as good as the second factor itself | Seeds are encrypted (you must read them back); recovery codes are hashed | ✅ `FieldCipher` for seeds, `hash_password` for codes |
| D7 | Password-reset and email-verification tokens | Account takeover | Random, single use, short expiry, stored hashed | 🟡 `random_token` + exact `BlindIndexer` |
| D8 | CSRF tokens and signed URLs | Cross-site abuse, link forgery | Framework CSRF protection; expiring signed links | 🟡 `Signer` for signed links |

## E. Integrity and authenticity

| # | Place | If left plain | What to do | securekit |
|---|---|---|---|---|
| E1 | Webhooks (see B5) | Forged events | Signature + timestamp | ✅ `Signer` |
| E2 | Audit trails | An intruder edits the evidence | Hash-chain entries with a key; ship copies off the host | ✅ for the vault's own audit log. 🟡 for your application logs: chain entries with `RecordSealer` |
| E3 | Configuration that changes behaviour (feature flags, limits, entitlements) | Silent tampering | Seal it or sign it and verify on load | 🟡 `RecordSealer` |
| E4 | Software supply chain (dependencies, build artifacts, updates) | Malicious code runs with your keys | Lock files, hash pinning, signed artifacts, minimal build permissions | ⬜ |

## F. Operations

| # | Place | What to do | securekit |
|---|---|---|---|
| F1 | Rotation schedule and runbook | Written, rehearsed, owned | ✅ APIs; the runbook has the steps |
| F2 | Break-glass and key escrow | Two people, offline copy, tested | ⬜ Process |
| F3 | Alerting | Page on `TamperedRowError`, `TamperedVaultError`, spikes of `InvalidToken`, failed vault locks | 🟡 Errors are distinct types; the alert is yours |
| F4 | Offboarding | Rotate every secret a leaver could read | ✅ `Vault.put` new versions, `destroy` old ones. The list of who could read what is yours |
| F5 | Continuous checking | Run the test suites and `securekit scan` on every change | ✅ |
| F6 | Deleting data for good | Destroy the key, not just the row ("crypto-shredding") | 🟡 Destroy a user's data key by deleting their `UserVault` state; backups of the state defeat this, so manage them |
| F7 | Backups of keys and vaults | Without them encrypted data is unrecoverable | ⬜ Store separately from the data, restore-test quarterly |

## G. Regulation (orientation only, not advice)

- **PCI DSS:** stored card numbers must be rendered unreadable and the keys managed; sensitive authentication data such as the card
  verification code must not be stored after authorization. Field encryption addresses the first, nothing addresses the second except not storing it.
- **HIPAA:** encryption of protected health information is the practical route to the breach-notification safe harbor.
- **GDPR:** names encryption and pseudonymisation as example security measures; crypto-shredding helps with erasure requests.
- securekit is not certified or validated (no FIPS 140 module). If you need a validated cryptographic module, use one and
  keep securekit's role to the application layer around it.

## H. What securekit deliberately does not do

- A network secrets server with logins and policies (use OpenBao, HashiCorp Vault or a cloud secret manager and feed securekit's `Keyring` from it).
- TLS, certificates, disk or database encryption, backup tooling, HSM/KMS integration.
- Streaming encryption of large files.
- Protecting data from code already running in your process with the keys loaded.
- Password policy, rate limiting, breach checking, device or session management.
- Anything for languages other than Python and Node.js (the formats in `SPEC.md` are open; a port is a matter of implementing them and passing `vectors/`).
