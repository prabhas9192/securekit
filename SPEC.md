# securekit wire formats (normative)

Python (`python/securekit`) and Node.js (`node/src`) implement exactly this. Every rule below is
exercised by `vectors/vectors.json`, which both test suites load. If the code and this file
disagree, that is a bug in the code.

securekit contains no cryptographic primitives of its own. Everything is composed from
AES-256-GCM, HMAC-SHA256, HKDF-SHA256 and Argon2id, as provided by OpenSSL via
`cryptography` / `argon2-cffi` (Python) and `node:crypto` (Node.js).

## 1. Encodings

- **base64url**: RFC 4648 section 5, no padding. Decoders are strict: only `[A-Za-z0-9_-]`,
  length mod 4 is never 1, and re-encoding the decoded bytes must reproduce the input.
- **lp(x)**: 4-byte big-endian length of `x`, then `x`.
- **context(parts...)**: each part (string, or integer that is not a boolean) is written as
  `<utf8 byte length>:<text>`; parts are joined with `|`. Example: `context("users","ssn",42)`
  is `5:users|3:ssn|2:42`. Length prefixes make the encoding unambiguous.
- All text is UTF-8. Strings containing lone surrogates are rejected.

## 2. Keys

- A **root key** is exactly 32 random bytes, written as base64url (43 characters). Passphrases are
  rejected because they fail to decode as 32 bytes.
- A **key id** (`kid`) matches `[A-Za-z0-9_-]{1,16}`.
- A **keyring** maps kids to root keys and names one `primary` kid. New data uses the primary key;
  old data stays readable with older kids still in the ring.
- **Sub-keys**: `HKDF-SHA256(ikm = root, salt = none, info = "securekit/v1/" + purpose [+ "/" + suffix], L = 32)`.
  Purposes: `field`, `blind` (suffix = context), `seal`, `sign`. `info` is limited to 1024 bytes
  (the Node.js `hkdfSync` limit), so blind-index contexts must be shorter than about 1000 bytes.

## 3. Field encryption

Token: `sk1.<kid>.<base64url(nonce || ciphertext || tag)>`

- Cipher: AES-256-GCM, key = sub-key `field` of `kid`, nonce = 12 random bytes, tag = 16 bytes.
- AAD: `"securekit/v1/field" 0x00 kid 0x00 context` (context is mandatory and non-empty).
- Every decryption failure (malformed, wrong key, wrong context, tampering) is reported as the same
  error. An unknown `kid` is reported as a subclass of it.
- Limit: random 96-bit nonces are safe for at most 2^32 encryptions per key (NIST SP 800-38D).
  Rotate to a new `kid` well before that.

## 4. Blind index

`<kid>.<hex(HMAC-SHA256(sub-key blind/context of kid, normalized)[0:length])>`; `length` defaults to 16 bytes.

- Modes: `text` normalizes as NFKC, then trims `\t \n \v \f \r`, space, U+00A0, U+1680, U+2000-U+200A,
  U+2028, U+2029, U+202F, U+205F, U+3000 from both ends, then lowercases ASCII `A-Z` only.
  `exact` uses the string unchanged.
- The context becomes part of the key, so equal values in different columns get unrelated indexes.
- `candidates` returns the index under every kid in the ring, for use in `WHERE index IN (...)`
  while rows are being re-indexed after a rotation.
- A blind index reveals equality of plaintexts (and therefore frequency). That is inherent.

## 5. Record seal

Token: `sk1s.<kid>.<base64url(HMAC-SHA256(sub-key seal of kid, message))>`

message = `"securekit/v1/seal" 0x00 || lp(context) || u32(n) || entries`, where entries are sorted by
the key's UTF-8 bytes and each is `lp(key) || type || lp(value)`:

| type | value                  | encoding of value                   |
| ---- | ---------------------- | ----------------------------------- |
| 0x00 | null                   | empty                               |
| 0x01 | string                 | UTF-8                               |
| 0x02 | integer                | decimal ASCII, `-` prefix if negative |
| 0x03 | boolean                | `1` or `0`                          |
| 0x04 | bytes                  | raw                                 |

Floats and every other type are rejected. Every key in the record is sealed unless the caller
excludes it by name. Nothing is skipped by name pattern.

A seal detects modification of the sealed fields. It does not detect a row being deleted, or an
older valid row being restored (rollback). Put a version counter in the record if you need that.

## 6. Request signing

Header: `t=<unix seconds>,kid=<kid>,v1=<hex>`
with `v1 = HMAC-SHA256(sub-key sign of kid, "<t>." || body)`.
Verification parses strictly (exactly those three fields, `t` is 1-12 digits, `v1` is 64 lowercase
hex), compares in constant time, and rejects timestamps further than the tolerance (default 300 s)
from the current time in either direction.

## 7. App secrets vault (`securekit-vault/1`)

A single JSON file (mode 0600, replaced atomically, guarded by `<file>.lock`) holding versioned secrets.

```
{ "format": "securekit-vault/1", "id": <16 random bytes, base64url>, "created": <unix s>, "generation": <int>,
  "secrets": { "<name>": { "versions": [ { "v": <int>, "created": <unix s>, "by": <actor>,
                                           "state": "active" | "destroyed", "token": <field token> | null } ] } },
  "audit":   [ { "seq", "ts", "actor", "action", "name", "version", "prev", "seal" } ],
  "manifest": <seal token> }
```

- **Names:** `[A-Za-z0-9][A-Za-z0-9._/-]{0,127}`, no empty, `.` or `..` path segments. **Actors:** 1-128 characters, no control characters.
- **Values** (at most 1 MiB) are field tokens (section 3) with context `context("vault", id, name, v)`, so a token cannot be moved
  to another secret, version or vault. Version numbers are never reused. Destroying a version removes its token.
- **Audit entry:** a seal (section 5) over `{seq, ts, actor, action, name|null, version|null, prev}` with context
  `context("vault", id, "audit")`, where `prev` is the previous entry's seal (`""` for the first). `seq` starts at 1.
  Actions: `init put read destroy delete rotate-keys`.
- **Manifest:** a seal over `{format, id, created, generation, audit_head, audit_count, index}` with context
  `context("vault", id, "manifest")`. `audit_head` is the last audit seal (`""` if none). `index` is one line per
  version, `name TAB v TAB state TAB created TAB by TAB sha256hex(token or "")`, names sorted by UTF-8 bytes, versions
  ascending, lines joined with `\n`. It detects removed, swapped, edited or added entries and truncated audit logs.
- **Not detected:** restoring an older complete copy of the file (rollback). Anchor `generation` and the audit head outside the file
  if that matters. Retiring a key makes audit entries sealed under it unverifiable; keep retired keys in an archive keyring
  used only for verification.
- **Reads** are audited only when the vault is opened with `audit_reads`, because every audited read rewrites the file.

## 8. Per-user vault (`securekit-uservault/1`)

For data the server must not be able to read. A random 32-byte data key (DEK) encrypts the user's items; the DEK is
wrapped under a key derived from the user's passphrase.

- **KEK:** Argon2id (raw output, 32 bytes) of the NFKC-normalized passphrase with a random 16-byte salt and the section 9
  parameters (m = 65536, t = 3, p = 4), stored in the state as `kdf`.
- **Wrapped key:** a field token of the DEK under a one-key keyring `{"u1": KEK}`, context `context("uservault", user_id, "dek")`.
- **Recovery (optional):** a random root key shown to the user once; the DEK is also wrapped under it as `{"r1": recovery_key}`
  with context `context("uservault", user_id, "dek-recovery")`. Without it a forgotten passphrase means the data is gone.
- **Items:** field tokens under a one-key keyring `{"d1": DEK}`, context `context("uservault", user_id, item_id)`.
- **Changing the passphrase** derives a new KEK from a new salt and re-wraps the same DEK; items are untouched.
- **State:** `{"format": "securekit-uservault/1", "kdf": {"alg": "argon2id", "m", "t", "p", "salt"}, "wrapped_key", "recovery_wrapped_key"}`.
  A wrong passphrase fails the unwrap and is reported as a wrong passphrase.

## 9. Passwords

- Argon2id, PHC string format, parameters from RFC 9106 section 4 (memory-constrained option):
  m = 65536 KiB, t = 3, p = 4, 16-byte salt, 32-byte tag.
- The password is NFKC-normalized (NIST SP 800-63B) before hashing and verification; it must
  be 1 to 4096 UTF-8 bytes.
- Verification accepts only `$argon2id$v=19$...` hashes and returns `false` for anything malformed, and
  for hashes asking for more than m = 262144 KiB, t = 10 or p = 16 (so a tampered row cannot make the
  server allocate gigabytes).
- `needsRehash` reports hashes whose parameters differ from the current ones.
