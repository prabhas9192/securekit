# 08 The gate: what "done" means, and how to report it

Run this before telling the user the work is finished. Every row needs **evidence** (a file and line, a test name, a command and its output). "I believe so" is not evidence.
Mark each row **PASS**, **FAIL**, **N/A ** (with the reason) or **ACCEPTED** (a named person accepts the risk, with a date).

## Blocking rows (any FAIL here means do not ship)

| ID | Control | Evidence to show |
|---|---|---|
| G4 | Passwords stored with Argon2id; policy enforced | code line + test that the database holds `$argon2id and not the password |
| G5 | Login: generic errors, rate limit | test: identical responses; 429 after N failures |
| G6 | Sessions: random, hashed at rest, expiring, real logout | test: two logins differ; token not in database; token dead after logout |
| G9 | Deny by default; one central authorization path | where the policy lives; list of public routes |
| G10 | Object-level authorization on every route that takes an id | `authz_matrix.py` run, all rows pass |
| G11 | Roles, owner, tenant and prices never taken from the client | test: request with `role=admin` / foreign `owner_id` is ignored or rejected |
| G13 | Every query parameterized; dynamic identifiers allow-listed | `securekit scan` shows no `sql-injection`; injection test |
| G20 | Sensitive fields encrypted with row context | test: database bytes lack the plaintext; moved ciphertext rejected |
| G21 | No secrets in code, config in git, images, logs | `securekit scan` clean at `--fail-on high`; where secrets come from |

## Required rows (FAIL must be fixed or ACCEPTED with an owner)

| ID | Control |
|---|---|
| G1 | Threat model exists with ranked abuse cases (`docs/threat-model.md`) |
| G2 | Data classified; sensitive data inventory |
| G3 | Assumptions written down |
| G7 | MFA / step-up for sensitive actions (when the app has accounts with money or admin power) |
| G8 | Reset / verification flows: single-use, expiring, no enumeration |
| G12 | Authorization matrix covers anonymous, other user, owner, admin for every route and object type |
| G14 | Output escaped / auto-escaping on; no unsafe sinks (`xss-sink`) |
| G15 | CSRF protection for cookie-authenticated state changes |
| G16 | Input validated by schema; size, page and upload limits |
| G17 | No shell with user text, `eval`, or unsafe deserialization |
| G18 | Uploads, file paths, outbound URLs and redirects constrained |
| G19 | Security headers; CORS lists exact origins |
| G22 | No sensitive data in logs, URLs, error messages |
| G23 | Backups encrypted and tested; key custody and recovery written down |
| G24 | HTTPS everywhere, including internal hops |
| G25 | Debug off; no default or sample credentials |
| G26 | Least-privilege database user and service identity |
| G27 | Rate limits on login, reset, signup and expensive endpoints |
| G28 | Security events logged; alerts defined |
| G29 | Dependencies pinned and audited |
| G30 | CI runs tests, scan and audit |
| G31 | `SECURITY.md` and a named owner for reports |
| G32 | A negative test exists for every control claimed above |

## Commands to run and include in the report

```bash
python -m securekit scan <project> --fail-on high          # static scan
<your test command>                                          # including the negative and authorization tests
pip-audit   /   npm audit                                    # dependency audit (whichever applies)
python <skill>/benchmark/score.py --app app.py               # only when the scenario is the billing benchmark
```

## Report format (print this at the end)

```
SECURITY REPORT: <app name>, <date>
Built: <what exists, in two or three lines>

Assumptions: <the five framing answers, as assumed>

Controls and evidence
  Authentication      PASS  <where + test>
  Authorization       PASS  <where + matrix result: n/n>
  Injection / web     PASS  <where + tests>
  Data protection     PASS  <fields encrypted, vault use, key source>
  Platform            <PASS / FAIL / N/A rows>
  Delivery            <rows>

Scan: <counts by severity, and what the remaining findings are>
Tests: <number run, number passed, negative tests listed>

Accepted risks (owner, date): <list, or "none">
Not done / not verified: <honest list>

Outside the code (the user must handle): TLS certificates and termination, disk and backup encryption, key custody and rotation schedule,
monitoring and on-call, penetration testing / independent review, legal and regulatory review, user training.

This report is evidence from automated checks and review, not a guarantee or a certification.
```

## Hard rules for the report

1. Do not write "secure", "fully secure", "compliant" or "hack-proof". Write what was checked.
2. Every FAIL and every "not verified" appears in the report, near the top.
3. If you could not run something (no network, tool missing), say so and mark the row **not verified**, not PASS.
4. If the user asked you to skip a control, record it under Accepted risks with their name or role.
5. Do not lower a check to make a gate pass; fix the code or record the risk.
