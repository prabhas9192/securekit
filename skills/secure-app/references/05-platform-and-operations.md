# 05 Platform and operations

What surrounds the code decides whether the controls hold in production. Encryption specifics are in `../../securekit/docs/RUNBOOK.md` and `../../securekit/docs/ENCRYPTION-MAP.md`.

## Transport and exposure

- **HTTPS only**, TLS 1.2 or newer, modern ciphers, valid certificates, automatic renewal. Redirect HTTP to HTTPS and send HSTS once you are sure. Terminate TLS at a reverse proxy or load balancer you control.
- **Encrypt the internal hops** too: app to database, cache, queue, search (`sslmode=verify-full` or equivalent). "Internal network" is not a trust boundary.
- Reach only what must be reachable: databases, caches and admin consoles are **not** on the public internet; security groups and firewalls default to deny; bind development servers to `127.0.0.1`.
- Local/LAN applications (a shop PC serving phones): still use TLS and per-user logins; a locally trusted certificate is fine. Document how devices are enrolled and revoked.

## Rate limiting and abuse control

| Surface | Control |
|---|---|
| login, MFA, reset, signup | per account and per source address; backoff; alert on spikes |
| expensive endpoints (search, export, report, PDF) | per-user quotas and timeouts; async jobs with queue limits |
| list endpoints | maximum page size; cursor pagination; no unbounded `LIMIT` |
| uploads | size, count and type limits; per-user storage quotas |
| webhooks received | signature + timestamp (securekit `Signer`), body size cap, idempotency keys |

Rate limits behind a proxy must use the real client address from a trusted header configured for **your** proxy only; otherwise an attacker sets the header and evades limits.

## Errors, logging, monitoring

- **Outward:** generic message + status + a request id. **Inward (server log):** the detail, without secrets. Never return stack traces, SQL, file paths, framework banners or version strings.
- **Log security events:** login success/failure, lockouts, password/MFA/email changes, permission denials, admin actions, key or secret rotations, data exports, vault reads of sensitive secrets, unusual volume.
  Each with timestamp, actor, source, object, outcome. Send logs off the host so an intruder cannot erase them.
- **Never log:** passwords, tokens, API keys, session ids, full card or national id numbers, request bodies of sensitive endpoints, decrypted values. Mask on the way in. (scan: sensitive-logging)
- **Alerts** for repeated denials, spikes of 401/403/429, changes to admin users or roles, new API keys, failed integrity checks (securekit `TamperedRowError` / `TamperedVaultError`), error-rate jumps.
- Keep logs for a defined period; check privacy rules before keeping personal data in them.

## Configuration, environments, secrets

- Separate **development, staging, production** with different credentials and keys. Production data does not go to development.
- Config from environment or the vault; **no secrets in the repository** (`securekit scan` in CI). A `.env.example` with placeholders is fine, a real `.env` is not.
- Debug mode, verbose errors, sample data, demo accounts and admin consoles are **off** in anything deployed. Make the unsafe setting the one that needs a name.
- Rotate on a schedule and after any exposure, any leaver, any suspicion (runbook in the securekit docs).

## Containers, hosts, cloud

- Run as a **non-root** user, read-only root filesystem where possible, drop Linux capabilities, no privileged containers, no host mounts of secrets directories.
- Minimal base images, pinned by digest, rebuilt regularly; scan images. **No secrets in image layers or `ENV`/`ARG`** (scan: dockerfile-secret).
- Kubernetes: Secrets encrypted at rest in etcd and committed only as sealed/SOPS/external forms (scan: k8s-secret-manifest), network policies default-deny, resource limits, separate namespaces, service accounts with least privilege.
- Infrastructure as code: reviewed like application code; state files are encrypted and access-controlled; no secrets in variable files in git.
- Cloud: no public buckets by default, IAM least privilege, no long-lived access keys on laptops or in CI (use short-lived federation), audit logging on.

## Database

- The application connects as a **dedicated user with only needed rights**; migrations run as a different user. No shared admin password in app config.
- Backups encrypted, tested by restoring, access-controlled, retention defined, keys stored separately from the data.
- Consider row-level security for multi-tenant data, and database auditing for admin access.
- Sensitive columns: field-level encryption (securekit) in addition to disk encryption.

## Availability and recovery

- Defined RPO/RTO even if informal ("we can lose one day, we are back in four hours").
- Backups of data **and** of keys/vault/keyring (separately). A restore drill each quarter.
- Dependency on one machine? Say so in the risk list and write what happens when it dies.
- Graceful degradation: timeouts on every outbound call, bounded queues, circuit breakers for third parties.

## Release checklist

Debug off; secrets from vault/env; migrations reviewed; dependency audit clean or accepted; scan clean at `--fail-on high`; headers present; rate limits enabled; logging and alerts working;
backup job verified; rollback plan; `SECURITY.md` and an owner for incoming reports; admin accounts reviewed; default credentials changed or absent.
