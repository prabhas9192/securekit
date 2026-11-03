---
name: secure-app
description: Build or review an application with security designed in, from threat model to release. Covers authentication and sessions, authorization (access control, IDOR, multi-tenant), injection and web attacks (SQL, XSS, CSRF, SSRF, uploads), data protection with the securekit library (encryption, secrets vault, password hashing), platform and operations, dependencies and delivery, and domain packs for billing/POS, payments, personal and health data, mobile and multi-tenant SaaS. Use before writing code for any request to build an app, API or service, add login, an admin page or file upload, store customer or financial data, or "make this secure", and for security reviews. Loads small reference files on demand.
---

# secure-app: build it secure, prove it, say what is left

This is a **router and workflow**. The detail lives in `references/` (load only what the task needs), the tools in `templates/` and `benchmark/`, and the encryption
specifics in the sibling skill `../securekit/SKILL.md`. Paths below are relative to this folder.

**Honest scope.** Following this makes security decisions systematic and checkable. It is not a guarantee, not an audit and not a compliance certification. A clean
checklist and a good benchmark score are evidence, not proof. Always finish by telling the user what is *not* covered.

## When to use it

Use it at the **start** of any task that creates or changes: a login or account system, an API, an admin area, anything that stores customer, payment or personal data,
file uploads, webhooks, or a new deployment. Also for "review this app's security". Skip it for pure UI styling or throwaway scripts with no data.

## Workflow (do the phases in order; each has an output)

| # | Phase | Output | Load |
|---|---|---|---|
| 0 | **Frame**: app type, who uses it, roles, what data, where it runs, any regulation. If the user did not say, choose the safer option and write the assumption down. | 5-line assumptions list | `references/01-design.md` |
| 1 | **Threat model**: assets, entry points, trust boundaries, top abuse cases per feature | `docs/threat-model.md` from `templates/threat-model.md` | 01 |
| 2 | **Requirements**: the security requirements this app must meet | `docs/security-requirements.md` from `templates/security-requirements.md` | 01 + a domain pack in 07 |
| 3 | **Design decisions**: how users authenticate, how access is decided, which data is encrypted and where keys live | short design note | 02, 03, `../securekit/SKILL.md` |
| 4 | **Build** under the always-on rules below | the code | 04, 05 as needed |
| 5 | **Prove**: write the negative tests (wrong user, injection string, tampered data, missing token) and run the scanner | tests that fail if a control is removed | 03, 04, `templates/authz_matrix.py` |
| 6 | **Release hygiene**: dependency audit, CI checks, config, headers, backups | checklist results | 05, 06 |
| 7 | **Gate and report**: run the gate, print what passed, what was not done, what is outside the code | the report in `references/08-gate.md` | 08 |

## Which reference for which task

| The task involves... | Load |
|---|---|
| a new app, a new feature, "what could go wrong", requirements | 01 |
| signup, login, sessions, passwords, MFA, reset, OAuth/SSO, API keys, JWT | 02 |
| roles, permissions, "who can see/edit this", admin pages, tenants, sharing | 03 |
| any user input, database queries, HTML output, forms, uploads, URLs fetched by the server, redirects, shell or file access | 04 |
| deployment, TLS, headers, rate limits, errors, logging, config, containers, backups, monitoring | 05 |
| dependencies, CI/CD, releases, SBOM, vulnerability reports | 06 |
| billing/POS/inventory, payments, personal or health data, mobile/desktop clients, multi-tenant SaaS, internal tools | 07 (the matching pack) |
| the final check | 08 |
| encrypting fields, a secrets vault, password hashing, signing, key rotation | `../securekit/SKILL.md` |

## Always-on build rules (apply to every line you write)

1. **Deny by default.** Every route and function requires authentication and an explicit permission check unless it is listed as public. New code starts closed.
2. **Authorize on the server, on the object.** Check that *this user* may act on *this record* on every request. Never trust ids, roles, prices or flags sent by the client. Take the user and tenant from the session, not the request.
3. **Parameterize every query.** No SQL built with string formatting, concatenation or f-strings. Dynamic table or column names come from an allow-list.
4. **Escape on output, validate on input.** Use auto-escaping templates and `textContent`. Validate type, length, range and format at the boundary against a schema; reject, do not repair.
5. **Never run user text.** No `eval`, no shell with user strings, no deserializing untrusted pickle/YAML. Run programs with argument lists.
6. **Secrets live in the vault or the platform secret store.** Never in code, config in git, images, logs, URLs or error messages. Rotate anything that leaked once.
7. **No home-made cryptography.** Passwords: Argon2id (`securekit.hash_password`). Sensitive fields: `FieldCipher`. Random tokens: `random_token`. Compare secrets in constant time.
8. **Fail closed with generic errors.** Same message for "no such user" and "wrong password". Never return stack traces, SQL errors or internal paths. Log details server-side without secrets.
9. **Limit abuse.** Rate-limit login, reset, signup, and expensive endpoints. Cap request size, page size, upload size, and query cost.
10. **Safe session and cookie settings.** `Secure`, `HttpOnly`, `SameSite`, expiry, rotation after login, real logout. CSRF protection on cookie-authenticated state changes.
11. **Security headers and TLS.** HTTPS only; `X-Content-Type-Options`, a Content-Security-Policy on HTML, frame protection, `no-store` on private responses. Restrictive CORS (named origins).
12. **Least privilege everywhere.** Database user can do only what the app needs; services run as non-root; tokens have scopes; support/admin access is separate and audited.
13. **Log security events, not secrets.** Logins, failures, permission denials, admin actions, key rotations. Never passwords, tokens, full card or ID numbers.
14. **Pin and audit dependencies.** Lock files, minimal packages, an audit step in CI, no abandoned libraries.
15. **Debug off, defaults changed.** No debug mode, sample accounts, default passwords or open admin consoles in anything deployed.
16. **Prove it with a negative test** for each control you rely on (see phase 5). A control with no test is a hope.

## Things that fail the gate (stop and fix, do not ship)

Hard-coded secrets or keys; string-built SQL; an endpoint with no authentication or ownership check; `role`/`is_admin`/`price` accepted from the request body;
passwords stored with a fast hash or reversibly; session tokens that are guessable, long-lived with no logout, or stored in plain text; stack traces returned to clients;
`verify=False` / disabled TLS checks; wildcard CORS with credentials; file uploads stored under the web root with the user's file name; user input in a shell command, `eval` or a file path;
unauthenticated debug or admin routes; sensitive data in logs or URLs.

## Tools in this skill

| Tool | Use |
|---|---|
| `python -m securekit scan PATH --fail-on high` | static scan for secrets, weak crypto, injection patterns, debug flags, CORS, CSRF, JWT and cookie settings |
| `templates/authz_matrix.py` | table-driven "who may do what" test against a running API; add a row per user × route × object |
| `benchmark/score.py --app app.py` | attacks a running implementation of the billing scenario and scores it; use to test the skill itself (below) |
| `templates/*.md` | threat model, requirements, SECURITY.md starting points |

## Testing this skill itself

The skill is only as good as the apps it produces. To measure it, give an agent `benchmark/scenarios/billing-api.md` **without** the score script or reference app, once with this skill
and once without, and score each result with `benchmark/score.py`. Compare the score, the failed check ids and the static scan. Details and scoring rubric: `benchmark/README.md`.
Re-run after every change to the skill; record results in `benchmark/RESULTS.md`.

## What to tell the user at the end

Use the report format in `references/08-gate.md`: what was built, which controls exist and where, which tests prove them, the scan result, the **assumptions you made**, and a plain list of what is
outside the code (TLS termination, disk encryption, backups, key custody, monitoring, penetration testing, legal review). Never say "secure" or "compliant" without that list.
