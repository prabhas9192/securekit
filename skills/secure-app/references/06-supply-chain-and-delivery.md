# 06 Dependencies, CI/CD and delivery

Most code in a running application is code you did not write. Treat the path from a package registry or a commit to production as part of the attack surface.

## Dependencies

- **Fewer is safer.** Before adding a package ask: can the standard library or an existing dependency do it? Is it maintained (recent releases, several maintainers), widely used, and from the real author?
- **Check the name**: typosquats (`reqeusts`), look-alikes, brand-new packages with few downloads, install scripts that fetch things. Install by exact name from the official registry.
- **Lock and pin.** Commit the lock file (`package-lock.json`, `poetry.lock`, `requirements.txt` with hashes via `pip-compile --generate-hashes`). Install in CI with the lock enforced (`npm ci`, `pip install --require-hashes`).
- **Audit continuously**: `pip-audit`, `npm audit`, `osv-scanner`, GitHub Dependabot / Renovate. Triage by whether the vulnerable code path is reachable, but do not ignore without a written reason and a date.
- **Update regularly** in small steps; a quarterly "everything is two years old" jump is how breakage and exposure accumulate.
- Remove unused dependencies. Vendor or fork small critical libraries only with a plan to track upstream security fixes.
- Optional dependencies and extras are still dependencies. Development tools run on developer machines: treat them the same.
- **Python/Node specifics:** avoid `curl | sh` installers; disable npm install scripts for packages that do not need them (`--ignore-scripts`) and review those that do; use `python -I` for untrusted inputs; keep virtual environments per project.

## Source control

- Protected main branch: pull requests, at least one review, passing checks, no force-push. Signed commits or at minimum verified identities for maintainers.
- **Secret scanning on every push** (`python -m securekit scan . --fail-on high` as a CI step and a pre-commit hook). If a secret was ever committed: **rotate it first**, then remove it; history removal is cosmetic.
- CODEOWNERS for security-sensitive paths (auth, payments, crypto, CI config).
- Keep `.gitignore` covering `.env`, key files, vault files, local databases, backups, IDE settings with tokens.

## CI/CD pipeline

- The pipeline is a privileged system: **least-privilege tokens**, short-lived credentials via OIDC federation instead of stored long-lived cloud keys, secrets scoped to the jobs and branches that need them, masked in logs.
- Don't run untrusted code (forks' pull requests) with access to secrets. Pin third-party actions/steps to a commit SHA.
- Required stages: build, unit tests, **security tests** (negative tests, authorization matrix), scan for secrets and risky patterns, dependency audit, container image scan, then deploy.
- Separate build from deploy. Deploy from a clean, reproducible build, not from a developer laptop.
- Keep an audit trail of who deployed what and when.

## Artifacts and releases

- Build once, promote the same artifact through environments. Record the commit, the build, and the dependency list (**SBOM**: `cyclonedx` / `syft`).
- Sign release artifacts and container images (sigstore/cosign or your registry's mechanism) and verify signatures at deploy time where you can.
- Never publish secrets or internal config in packages, containers or mobile apps; unpack your own artifact once and look.
- Mobile/desktop updates: HTTPS plus signature verification of the update package.

## Reporting vulnerabilities

- Publish `SECURITY.md` (template: `../templates/SECURITY.md`): how to report, what to expect, supported versions.
- Decide who triages, how fast you respond, and how you notify users. Practice once.

## Quick policy a small team can adopt

1. Lock files committed; CI installs from them.
2. `pip-audit` / `npm audit` and `securekit scan --fail-on high` run on every pull request.
3. Main branch protected; reviews required for auth, payment and crypto code.
4. No long-lived cloud keys in CI; secrets masked and scoped.
5. Quarterly: update dependencies, rotate secrets, test restore, review admin accounts.
