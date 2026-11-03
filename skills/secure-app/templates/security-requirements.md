# Security requirements: <application name>

Each requirement is testable. "Test" names the automated check that fails if the requirement is broken.

| ID | Requirement | Applies to | Test |
|---|---|---|---|
| SR-01 | Every non-public route requires authentication | all routes | anonymous request returns 401 for each route |
| SR-02 | Access to a record requires ownership or an explicit role permission | routes with ids | `authz_matrix` rows: other user gets 403/404 |
| SR-03 | Roles, owner, tenant and prices are set by the server | write endpoints | request with `role`/`owner_id`/`price` is ignored or rejected |
| SR-04 | Passwords are stored as Argon2id; minimum length 10; common passwords rejected | accounts | database inspection test; policy test |
| SR-05 | Login failures are rate limited and return identical errors | login | 6 failures give 429; unknown vs wrong password identical |
| SR-06 | Session tokens are random, stored hashed, expire, and die on logout | sessions | token absent from database; reuse after logout fails |
| SR-07 | All SQL uses bound parameters | data layer | scanner has no `sql-injection`; injection payload test |
| SR-08 | User text is escaped on output; CSP is sent on HTML | HTML responses | script payload comes back escaped; header present |
| SR-09 | Request bodies, pages and uploads have size limits | all inputs | oversized request refused |
| SR-10 | Sensitive fields are encrypted with row context (securekit) | <list fields> | database bytes lack plaintext; moved ciphertext rejected |
| SR-11 | Secrets come from the vault or environment, never from code or git | all | scanner clean at `--fail-on high` |
| SR-12 | Errors are generic outward; details only in server logs without secrets | all | no stack trace in any error response |
| SR-13 | Security events are logged; secrets and personal identifiers are not | all | log inspection test |
| SR-14 | Dependencies are locked and audited in CI | build | CI step present and green |
| SR-15 | <domain-specific, from references/07> | | |

Add rows for every feature in the threat model. Remove none without writing why.
