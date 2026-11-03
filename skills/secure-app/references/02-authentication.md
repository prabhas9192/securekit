# 02 Authentication and sessions

Working example of everything below: `../benchmark/apps/reference_app.py` (scores 100% on `../benchmark/score.py`). Read it before writing your own.
Cryptographic pieces come from securekit (`../../securekit/SKILL.md`); do not hand-roll them.

## Passwords

- **Store only an Argon2id hash**: `hash_password(pw)` / `verify_password(pw, stored)` / `needs_rehash(stored)` (re-hash on successful login). Never encrypt passwords, never use SHA/MD5/bcrypt-without-salt-handling by hand.
- **Policy (NIST SP 800-63B style):** at least 10 characters (never below 8), allow up to 64 or more, allow spaces and Unicode, **no composition rules** ("one symbol, one digit"), no forced periodic change, no hints,
  never truncate silently. Reject passwords found in a common/breached list (a local top-10k list is a fine start; a k-anonymity range lookup against a breach service is better).
- Normalize with NFKC before hashing (securekit does it) so the same typed password works on every device.
- Cap the length (for example 128) to avoid hashing very large inputs.

```python
# runnable
import re

COMMON = {"password123", "1234567890", "qwertyuiop", "letmein1234", "iloveyou123", "admin12345"}

def check_password_policy(password, username=""):
    """Returns a list of problems (empty means acceptable)."""
    problems = []
    if not isinstance(password, str) or not 10 <= len(password) <= 128:
        problems.append("must be 10 to 128 characters")
    elif password.lower() in COMMON or (username and username.lower() in password.lower()):
        problems.append("too easy to guess")
    elif len(set(password)) < 5:
        problems.append("too repetitive")
    return problems

assert check_password_policy("short") == ["must be 10 to 128 characters"]
assert check_password_policy("password123") == ["too easy to guess"]
assert check_password_policy("1234567890") == ["too easy to guess"]
assert check_password_policy("aaaaaaaaaaaa") == ["too repetitive"]
assert check_password_policy("correct horse battery staple") == []
assert check_password_policy("alice-is-great-1", username="alice") == ["too easy to guess"]
```

## Login

1. Validate input types and lengths first.
2. **Rate limit before verifying**: per username (for example 5 failures per minute) and per source address. Return `429`. Prefer slowing down (backoff) over permanent lockout, which lets an attacker lock real users out.
3. Look up the user. If not found, **verify against a dummy hash** so response time does not reveal whether the account exists.
4. On any failure return the **same status and message** (`401 invalid credentials`) for unknown user, wrong password, disabled account.
5. On success create a new session (below), reset the failure counter, log the event (user id, time, source; never the password), optionally notify the user of a new device.
6. Log failures with the username attempted and the source, so brute force is visible.

## Sessions and tokens

- **Opaque random tokens**: `random_token(32)` (256 bits). Not a hash of the username, not sequential, not a timestamp, not a JWT unless you have a reason.
- **Store only a keyed hash of the token** so a database leak does not hand out live sessions: `BlindIndexer(ring).index(token, context("sessions","token"), mode="exact")`; look up with `.candidates(...)`.
- Store `user_id`, `created`, `last_seen`, `expires`. **Idle timeout** (for example 30 minutes for admins, longer for POS/mobile) and **absolute timeout** (for example 8-12 hours).
- **Rotate** the session id at login and when privilege changes. **Invalidate** on logout, password change, MFA change and when an admin disables the account. "Log out everywhere" must really delete all sessions.
- Cookies (browser apps): `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Lax` (`Strict` for admin areas), `Path=/`, no `Domain`. Never put tokens in URLs, local storage, or logs.
- API/mobile: `Authorization: Bearer`. Bearer tokens in headers are not sent automatically by browsers, so CSRF does not apply to them; cookies need CSRF protection (`04`).
- Compare secrets in constant time (`constant_time_equals`), never `==`.

## Multi-factor authentication

- Prefer **WebAuthn / passkeys**; TOTP (RFC 6238: 30-second steps, 6 digits, accept the previous/next step only) as the common fallback. SMS is the weakest option; offer it only if you must.
- **Encrypt the TOTP seed** (you must read it back): `FieldCipher.encrypt(seed, context("users","totp",user_id))`. Never log it.
- Generate **recovery codes** (10 random codes from `random_token`), show once, store hashed (`hash_password`), one use each.
- Rate-limit MFA attempts like passwords. Require **step-up** (re-enter password or MFA) before changing email, password, MFA, payout details, or creating API keys.

## Password reset and email verification

- Token = `random_token(32)`; store only its keyed hash, the user id, an **expiry (15-30 minutes)** and a **used** flag. Single use.
- The "forgot password" response is identical whether or not the account exists. Rate-limit by account and by source.
- Send the link over email only, HTTPS, token in the path or fragment, the page must not load third-party resources (Referer leak).
- After reset: invalidate all sessions, require re-login (do not auto-login), notify the account's email.
- Changing the email address requires confirmation from the **old** address (or step-up) as well as the new one.

## Account enumeration, other doors

- Registration saying "username taken" is hard to avoid; use email-based registration ("check your inbox") for high-value apps, and rate-limit registration.
- Support/admin password reset must not create a password the admin knows; send a reset link to the user.
- Disable or protect secondary entrances: legacy login routes, "remember me" cookies (store a hashed selector/validator pair), default or test accounts.

## OAuth / OpenID Connect / SSO

- Authorization Code flow with **PKCE**; no implicit flow. `state` (CSRF) and `nonce` (replay) verified.
- **Exact-match redirect URIs**; never a pattern, never taken from the request.
- Validate the ID token: signature (keys from the provider's JWKS), `iss`, `aud`, `exp`, `nonce`. Map users by the provider's stable `sub`, not by email alone (emails can change or be unverified).
- Request minimal scopes. Store refresh tokens encrypted (`FieldCipher`, context with user id); revoke on logout.

## API keys (for customers or services)

`key = prefix + random_token(32)`; show once; store only a keyed hash (exact blind index) and the non-secret `prefix` for lookup; scopes per key; last-used timestamp; expiry; rotation; per-key rate limits.

## JWTs, only if you need them

Pin the algorithm (never accept `none`, never let the header choose); verify `exp`, `nbf`, `iss`, `aud`; keep access tokens short (5-15 minutes) with rotating refresh tokens; keep signing keys in the vault with a
`kid` so you can rotate; never put secrets in the payload (it is only encoded, not encrypted); have a revocation story (denylist or short life plus refresh revocation).

## Local and desktop apps (POS on a shop PC, used from phones)

- Authentication is still required: anyone on the same wifi can reach `0.0.0.0`. Bind to `127.0.0.1` unless other devices must connect; if they must, use TLS (even a locally trusted certificate) and per-user logins.
- **Staff PINs** are low-entropy: hash with Argon2id, enforce lockout/backoff per account **and** per device, require a full password for owner/admin actions, never show PINs in logs or on screen.
- Provide a way to **revoke a lost device's session** and to set a session idle timeout shorter than the shop day for sensitive roles.
- First-run setup creates the owner account with a chosen or generated password; ship no default credentials.

## Negative tests to write (each must fail if the control is removed)

- Unknown user and wrong password give identical status and body.
- Six wrong passwords in a minute produce `429`.
- A token from one login does not work after logout; a reset token cannot be used twice or after expiry.
- A password with the username in it, a short one and a common one are rejected.
- Two logins give different tokens; the database does not contain the token or the password in clear.
- Cookie flags are present (`Secure`, `HttpOnly`, `SameSite`).
- Changing the password invalidates other sessions.
