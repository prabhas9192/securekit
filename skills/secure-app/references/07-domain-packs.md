# 07 Domain packs

Load the section that matches the product. Each adds to the general rules; it does not replace them. Legal and regulatory points are orientation only: tell the user to confirm with a qualified adviser.

---

## A. Billing, POS and inventory (shop software, local or small-server)

**What attackers (and dishonest staff) want:** lower prices, free goods, hidden sales (tax evasion), stolen cash, edited history, customer data, a way to act as the owner.
Most losses here come from **insiders and trusting the client**, not from outsiders.

**Rules**
1. **The server computes money.** Totals, discounts, taxes and rounding are calculated server-side from catalog prices and rules. Ignore any price, total, tax or discount sent by the client except as a *request* that is validated against what the user's role may grant.
2. **Use exact arithmetic**: integer minor units (paise/cents) or `Decimal`; never binary floats. Define rounding once. Reject negative or zero quantities unless the endpoint is explicitly a return.
3. **Invoices are immutable.** No edit, no delete. Corrections are new documents (credit note, reversal, replacement) that reference the original. Invoice numbers are sequential per series, unique by database constraint, assigned by the server in a transaction.
4. **Append-only audit trail** for sales, voids, refunds, discounts, price changes, stock adjustments, cash movements, logins, role changes, exports and backups. Tamper evidence: seal each ledger row with securekit `RecordSealer` (context with table and row id) or chain entries; ship copies off the machine.
5. **Role separation**: cashier (sell), manager (void/refund/discount above limit/price override/reports), owner (users, settings, tax, backup/restore). Each person has their own login: **no shared cashier account**. Sensitive actions need a manager's approval with a reason, recorded.
6. **Cash and shifts**: open/close shift with counted cash; variances are reported; voids after payment and no-sale drawer opens are logged and alerted; limits on discounts and refunds per role per day.
7. **Stock** is a ledger of movements (purchase, sale, adjustment, transfer) so shrinkage is visible; adjustments need a reason and an approver. Statutory inventory ledgers follow the same append-only rule.
8. **Time**: the server sets timestamps. Back-dating is restricted to roles, requires a reason and is flagged in reports.
9. **Customer data minimum**: name/phone only if needed. Encrypt phone/ID/address fields (`FieldCipher`), keep a blind index for lookup by phone, never print full ids on receipts, honor deletion requests within tax-retention limits.
10. **Devices and network**: phones/tablets are enrolled and can be revoked; sessions on shared devices expire quickly; no `0.0.0.0` listener without TLS and logins; separate guest wifi from the till network when you can.
11. **Backups**: automatic, encrypted, off the till machine, restore tested, retention matching the legal period for business records (varies by country; check), keyring kept separately.
12. **Reports/exports** that contain customer or financial data require the right role, are logged, and (if emailed) go to verified addresses only.
13. **Offline / sync**: conflict rules are explicit; synced records are signed or sealed so a rogue device cannot rewrite history; clock-skew handled.

**Negative tests**: send a lower price/total than the catalog → server ignores or rejects; negative quantity → rejected; void the same invoice twice → second refused; cashier calls manager endpoints → 403;
edit/delete an invoice via API or database → refused / detected by the seal; two parallel sales never reuse an invoice number; discount over the role's limit needs approval; export without role → 403.

**Compliance note:** tax invoicing, GST/VAT, e-invoicing, record retention and audit-trail requirements are jurisdiction-specific. Build the controls above; do not claim the product is compliant.

---

## B. Payments

- **Never store** card numbers (PAN), security codes (CVV/CVC), PIN or full magnetic-stripe data. Use the payment provider's hosted fields / checkout / SDK so card data never touches your servers: that keeps PCI scope minimal.
- Store only the provider's **token / payment-method id**, brand and last four digits. Encrypt tokens (`FieldCipher`) and bind them to the customer.
- **Server-side amounts**: the client sends a cart or order id, never the final amount. Create the payment intent on the server.
- **Webhooks**: verify the provider's signature and timestamp, make handlers **idempotent** (store event ids), ignore events for objects you didn't create, never trust the redirect return URL as proof of payment.
- **Refunds and payouts**: manager step-up approval, limits, audit, reconcile daily against the provider's reports.
- Secrets (API keys, webhook secrets) in the vault, per environment; restricted keys with minimum permissions; rotate on staff changes.
- No card or token data in logs, URLs, analytics or error messages. Use the provider's sandbox in tests and keep live keys out of CI.
- Handle partial failures: payment succeeded but order failed, double submit, retries. Idempotency keys on every create.

---

## C. Personal, sensitive and health data

- **Minimize and justify**: collect only fields with a stated purpose; keep a data inventory (what, why, where, who can read, how long).
- **Lawful basis and consent** where required; record consent with version and time; make withdrawal as easy as giving it.
- **Access control by need**: role + relationship (a clinician sees their own patients). **Log every read** of sensitive records and review the logs; provide a break-glass path that is loudly audited.
- **Encrypt sensitive fields** (`FieldCipher`, context with the subject id); encrypt backups; pseudonymise or aggregate for analytics and testing. Never copy production personal data into development.
- **Retention and deletion**: define periods; delete or anonymise when expired. For per-user private data consider `UserVault` and **crypto-shredding** (destroy the key to erase every copy, including backups).
- **Data subject requests** (access, correction, export, erasure): build the export and delete paths early; they touch every table, cache, index, log and backup.
- **Breach readiness**: know what you hold, who must be told and how fast (regulation-specific); keep contact details and a draft notice ready.
- Children's data, biometrics, location trails and health data are high-risk categories: involve a privacy adviser.

---

## D. Mobile and desktop clients

- **Anything shipped in the app can be extracted**: no API secrets, signing keys, admin credentials or private endpoints "hidden" in the binary.
- Store tokens in the platform keystore (iOS Keychain, Android Keystore, Windows DPAPI/Credential Locker, macOS Keychain), not plain preferences or files. Gate sensitive actions with biometrics or the device passcode.
- Local databases with sensitive data: encrypt (for example SQLCipher) with a key from the keystore. Exclude sensitive files from cloud backups; clear on logout.
- **Auth:** OAuth/OIDC Authorization Code with PKCE in the system browser; short-lived access tokens, refresh tokens in secure storage; revoke on logout.
- **TLS:** system trust by default. Certificate pinning is a trade-off (it stops some interception but can lock out users if certificates change): if you pin, pin the public key with a backup pin and a way to update.
- Deep links, intents and custom URL schemes are untrusted input: validate and require authentication before acting. WebViews: disable JavaScript bridges you don't need, restrict navigation to your origins.
- Disable debug logging, screenshots in sensitive screens where appropriate, clipboard exposure for secrets. Root/jailbreak detection is a speed bump, not a control: design as if the device is hostile.
- Updates: only over HTTPS with signature verification; minimum supported version enforced by the server.

---

## E. Multi-tenant SaaS

- Everything in `03-authorization.md` section "Multi-tenant", plus: per-tenant rate limits and quotas, per-tenant audit logs visible to tenant admins, tenant-scoped API keys and webhook secrets.
- Isolate by default in storage (tenant id in every key/path), cache, search index, queues, logs, backups and exports. Offer per-tenant encryption keys where customers require it (separate securekit keyring or `context` per tenant, envelope keys from a KMS).
- Support staff access: just-in-time, approved by the tenant or a second person, time-boxed, audited, visible to the tenant.
- Tenant offboarding: export, then verified deletion including backups (crypto-shredding helps).
- SSO/SAML/OIDC per tenant with correct audience/issuer checks and domain verification.

---

## F. Internal tools and admin panels

- Treat as production-grade: they hold the most powerful credentials and the most data. SSO with MFA, **not exposed to the internet** (VPN, identity-aware proxy), no shared accounts.
- Read-only by default; write and delete actions need a role, confirmation and, for dangerous ones, a second approver. Log every action with the actor.
- No generic "run any SQL / shell" consoles for broad roles. If you need one, restrict by role, time and network, and record the statements.
- Short sessions, re-authentication for destructive actions, and an easy way to see "who did what" afterwards.

---

## G. Partner APIs and webhooks (outbound and inbound)

- Per-partner credentials with scopes, rotation and revocation. Signatures with timestamps (securekit `Signer`), a replay window, idempotency keys, schema validation, versioning, per-partner rate limits.
- Optional IP allow-listing is an extra layer, not authentication.
- Publish a changelog and deprecation policy so security fixes can ship without breaking everyone.
