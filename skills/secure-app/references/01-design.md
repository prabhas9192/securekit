# 01 Design: frame, threat model, requirements

Do this before code. It takes minutes and decides most of what follows. Output goes in `docs/threat-model.md` and `docs/security-requirements.md`
(templates in `../templates/`).

## 1. Frame the application (answer all five; if unknown, assume the stricter option and write it down)

1. **What is it?** Web app, JSON API, mobile backend, desktop/local app, internal tool, batch job. Public internet, company network, or one machine?
2. **Who uses it?** Anonymous visitors, customers, staff, admins, other systems. How many roles? Do users belong to organizations (tenants)?
3. **What data does it hold?** Classify it (table below).
4. **Where does it run and who operates it?** Laptop, shop PC, cloud VM, containers; who has shell and database access.
5. **What rules apply?** Payments (PCI DSS), health (HIPAA), personal data (GDPR/DPDP and similar), tax records, sector rules. Not legal advice: flag them for the user.

## 2. Classify the data

| Class | Examples | Minimum handling |
|---|---|---|
| Public | marketing pages, product catalog | integrity only |
| Internal | internal reports, non-sensitive config | authentication, access control |
| Personal | name, phone, email, address, purchase history | access control, minimize, retention limit, no logs, encrypt at rest where the threat model says so |
| Sensitive personal / financial | national ids, bank or card numbers, health data, salary, location trails | encrypt the field (`securekit.FieldCipher`), access audited, never in logs/URLs/analytics, strict retention |
| Secrets | passwords, API keys, tokens, signing keys, keyrings | never stored reversibly unless required; vault; rotation |

**Rule:** if you do not need to store it, do not. Do not collect fields "just in case". Never store card verification codes.

## 3. Threat model in 20 minutes

1. **Draw the system** as boxes and arrows: browser/app → server → database/cache/queue → third parties. Mark every arrow that crosses a **trust boundary** (internet, between services, to a vendor).
2. **List assets**: what an attacker wants (accounts, money records, personal data, the ability to act as an admin, availability).
3. **List entry points**: every route, form field, header, file upload, webhook, background job input, admin tool, and every place the server fetches a URL or reads a file.
4. **For each entry point and asset, ask STRIDE-lite:**

| Letter | Question | Typical control |
|---|---|---|
| **S**poofing | Can someone pretend to be another user or system? | authentication, signed webhooks, mTLS |
| **T**ampering | Can data or requests be altered? | authorization, integrity seals, TLS, input validation |
| **R**epudiation | Can someone deny an action? | audit log of security events |
| **I**nformation disclosure | Can data leak (IDOR, errors, logs, caches, backups)? | object-level authz, encryption, generic errors, log hygiene |
| **D**enial of service | Can one request or user exhaust resources? | rate limits, size/page caps, timeouts |
| **E**levation of privilege | Can a user gain rights they lack? | server-side role checks, no client-supplied roles, least privilege |

5. **Write abuse cases** in the form "As an attacker, I ...": e.g. "change the id in the URL to read another customer's invoice", "replay a stolen session token",
   "send `' OR 1=1 --` as the search text", "upload a script as a profile picture", "guess reset codes", "edit the price in the checkout request".
6. **Rank** by likelihood × impact (high/medium/low). Everything high must have a control and a test before release.
7. **Record accepted risks** with an owner and a date. "Not handled" must be written, not silent.

## 4. Requirements by application type (starting set; extend with the domain pack in `07`)

| Requirement | Web app | JSON API | Mobile backend | Local/desktop POS | Internal tool |
|---|---|---|---|---|---|
| Authentication on every non-public route | yes | yes | yes | yes (even on localhost) | yes (SSO preferred) |
| Object-level authorization | yes | yes | yes | yes per role | yes |
| CSRF protection | yes (cookie auth) | if cookie auth | n/a for bearer tokens | yes if browser UI | yes |
| Rate limiting | yes | yes | yes | login only | login only |
| Input schema validation | yes | yes | yes | yes | yes |
| TLS | yes | yes | yes (+ pinning decision) | when reachable by other devices | yes |
| Sensitive fields encrypted | per classification | per classification | per classification | per classification | per classification |
| Audit log of security events | yes | yes | yes | yes (cash/price changes) | yes |
| Dependency audit in CI | yes | yes | yes | yes | yes |

An app "only used on the shop's wifi" or "only internal" still needs authentication and access control: the network is not a security boundary you control.

## 5. Secure defaults to adopt in every project

- New routes closed until explicitly opened. New roles have no permissions until granted.
- Configuration safe by default (debug off, secure cookies on, wildcard CORS off); unsafe options require an explicit, named setting.
- No default accounts. The first admin is created at install time with a generated password or a prompt.
- Everything that can be an allow-list is one: file types, redirect targets, outbound hosts, sortable columns, fields a client may set.
- Errors are generic outward and specific in the server log (without secrets).
- One central place per concern: one authorization function, one input validator layer, one HTML escaping path, one secrets loader. Scattered checks get forgotten.

## 6. Ask before building when it changes the design

Only ask if the answer changes the design and the user can answer. Otherwise assume and record. Good questions: "Will other people's devices (phones) reach this over a network?",
"Are there staff roles with different permissions?", "Does it handle card payments or national ids?", "Is more than one business/tenant using the same install?"
