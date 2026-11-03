# Production runbook

For the team that deploys and operates an application using securekit. Read `ENCRYPTION-MAP.md` first for the full list of what to protect.

## 1. Roles

| Role | Owns |
|---|---|
| Service owner | which data is encrypted, the `context` for each column, the tests |
| Key custodian (two people) | creating, storing, rotating and recovering keyrings |
| Platform / SRE | secret store, backups, TLS, disk encryption, alerting |
| Security | review, incident response, the rotation schedule |

## 2. Day 0: the key ceremony

1. Generate the keyring on a trusted machine: `python -m securekit genkeyring k1 > keyring.json`.
2. Put it in the production secret store (or KMS-wrapped storage). Use a separate keyring for each environment; never reuse production keys in staging or on laptops.
3. Make **two offline backups** of the keyring in different places, held by different people. Test that you can restore from them. **Losing the keyring means losing every
   value it encrypts, permanently.**
4. Record: key ids in use, creation date, who can read the keyring, where the backups are. Do not record the keys.
5. Expose it to the application as the `SECUREKIT_KEYRING` environment variable (injected by the platform, not baked into the image).

## 3. Deploying

| Item | Requirement |
|---|---|
| Keyring | injected at start from the secret store; not in the repo, image, config map or the same database as the data |
| Vault file | on a private volume owned by the service user (mode 0600 is set for you), included in backups, **not** next to the keyring backup |
| TLS | everywhere, including to the database and cache (see `ENCRYPTION-MAP.md` section B) |
| Logs | no values; the only securekit identifiers worth logging are secret names, key ids and token prefixes |
| Process | service runs as a non-root user; core dumps disabled for processes that hold the keyring |
| CI | tests for both languages plus `python -m securekit scan . --fail-on high` on every change |

A `Keyring` lives in application memory. Anyone who can execute code in the process or read its memory can use it. Limit what each component can reach with
`vault.scoped("prefix/")`, and run risky components (document converters, plugin hosts) in separate processes without the keyring.

## 4. Fast integration plan (one service)

| Step | Output | Check |
|---|---|---|
| 1. Inventory | the completed `ENCRYPTION-MAP.md` rows for this service | owner named per row |
| 2. Scan | `securekit scan . --fail-on never` saved as the baseline | counts by severity |
| 3. Secrets to vault | every secret moved, old copies deleted, anything ever in git rotated | `scan` shows no secret findings |
| 4. Fields | sensitive columns encrypted (new writes first, then backfill) | a test proves a moved ciphertext is rejected |
| 5. Passwords | Argon2id with rehash-on-login | old hashes upgrade as users sign in |
| 6. Pipeline | tests + scan in CI | the build fails on a planted secret |
| 7. Operations | alerts and the rotation date in the calendar | a restore drill is done |

**Backfilling existing plaintext:** add the new token column, write both, backfill in small batches (read plaintext, encrypt with the row's context, store the token,
verify by decrypting), switch reads to the token, stop writing plaintext, then drop the plaintext column and purge backups that contain it according to your retention rules.

## 5. Monitoring

Alert on:

- `TamperedRowError`, `TamperedVaultError` (page someone: a sealed value was changed outside the app);
- a rise in `InvalidToken` or `UnknownKeyError` (a bad deploy of the keyring, or someone moving ciphertext);
- `VaultLockedError` in volume (a stuck writer);
- failed `securekit vault verify --deep` in a scheduled job (run it daily);
- `vault audit` entries by unexpected actors, or `rotate-keys` / `destroy` outside change windows (ship the audit log to your log system as well; the file's own chain cannot detect a rollback).

## 6. Rotation

**Routine (suggested: every 12 months, and before a key has encrypted 2^32 values):**

1. Create a key: `python -m securekit genkey`. Add it to the keyring as a new id (`k2`) **and keep `k1`**; set `primary` to `k2`. Deploy.
2. Re-encrypt in the background: fields with `rotate`, SQLAlchemy rows with `needs_rotation` / `mark_for_rotation` (paged loop in the README), the vault with `vault rotate-keys`.
3. Blind indexes follow the same path; queries use `candidates` / `blind_filter`, which match every key still in the ring.
4. When `needs_rotation` is false everywhere, archive the audit log, take a final backup, and only then remove `k1` from the live keyring. Keep it in the offline archive
   for verifying old audit entries.

**After a suspected key leak:** rotate immediately (same steps, fast), treat all data encrypted under the old key as exposed for the period the key could be read, rotate every
secret in the vault (new versions, then `destroy` the old ones), and rotate the keyring custody credentials.

**Application secrets that leave with a person:** `vault put` a new version of every secret they could read, `destroy` the old version, check `audit` for their reads (enable `--audit-reads` for sensitive vaults).

## 7. Backup and restore

| What | How | Restore test |
|---|---|---|
| Keyring | two offline copies, separate custodians | quarterly: decrypt a sample with the restored copy |
| Vault file | with the application backups; it is already encrypted | `vault verify --deep` on the restored file |
| Database | encrypted backups; ciphertext columns stay ciphertext | restore to staging with the *staging* keyring and confirm decryption fails there, then with the right one that it works |
| Per-user vault states | with the database | a user can unlock after restore |

Never store a backup of the data and the only copy of its keyring together.

## 8. Incident response

| Event | First actions |
|---|---|
| Database dump leaked | Ciphertext columns stay protected as long as the keyring did not leak. Rotate session tokens and any credentials stored as plaintext, force password resets for hashes made with weak parameters, review blind-index exposure (equality leaks). |
| Keyring leaked | Section 6 "suspected key leak". Assume previously captured ciphertext is readable. |
| Vault file leaked | Without the keyring it stays encrypted. Check the audit log, rotate the keyring if there is any doubt, and rotate the secrets inside. |
| `TamperedVaultError` / `TamperedRowError` | Stop writes to the affected data, preserve the file and the database state for forensics, restore from backup, find who had write access. |
| Detected rollback (an old file restored) | Compare `generation` and the audit head with the copy you shipped to your log system. |
| User cannot unlock their vault | There is no reset. Use their recovery key if they have one; otherwise the data is lost by design. |

## 9. Compatibility and upgrades

- Wire formats are versioned: field tokens `sk1.`, seals `sk1s.`, vault files `securekit-vault/1`, user vault states `securekit-uservault/1`. A future incompatible format will use a new prefix; old data will keep reading.
- The Python and Node packages must be upgraded together while formats change; the shared vectors in `vectors/` are the compatibility test.
- Pin the package versions and run both test suites in your pipeline before upgrading.

## 10. Using securekit with a secrets server or KMS

If you run OpenBao, HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager or Azure Key Vault, keep using it as the **custodian** and let securekit do the application-level
encryption with a keyring fetched at startup (envelope-style). This is the recommended setup for anything beyond a small deployment.

```python
# Untested sketch: fetch the keyring JSON from your secret manager at startup, then build the Keyring.
import json
keyring_json = secret_manager.get("prod/securekit-keyring")          # your client library
ring = Keyring.from_json(keyring_json)
```

The fetch is done once per process (and on a schedule if you rotate), with an identity that is allowed to read exactly that secret. The secret manager adds what securekit does not:
network authentication, per-client policies, central audit, HSM-backed custody and automatic rotation of the keyring itself.

**Why securekit does not ship its own vault server:** a secrets server is an authentication and authorization system on a network. Writing one is a different, larger security problem
than encrypting data in a library, mature products exist, and a half-hardened home-made one is worse than none. The file vault here is for secrets a single application (or a few
cooperating processes on one host) reads.

## 11. Limits to remember

- Not independently audited; not a compliance certification.
- The file vault is built for hundreds, not millions, of secrets; every write rewrites the file under an exclusive lock.
- Rollback to an older complete copy of a vault file is not detected without state kept elsewhere.
- Retiring a key makes audit entries sealed under it unverifiable unless you keep it in an archive keyring.
- A process holding the keyring can read everything the keyring protects.
- Tested: Python 3.14 with SQLAlchemy 2.0.55 and SQLite; Node 24.12. Not tested: other versions, PostgreSQL/MySQL, async sessions, Windows file semantics.
