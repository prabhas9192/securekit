# 03 Authorization: who may do what

Broken access control is the most common serious flaw in real applications, and encryption does not help with it. Treat this file as the most important one for any app with more than one user.

## The model

- **Authentication** says who you are. **Authorization** says what you may do. Do both on every request, on the server.
- Three checks, all required:
  1. **Function level**: may this role call this endpoint at all? (`/admin/users` needs admin.)
  2. **Object level**: may this user act on *this record*? (Invoice 17 belongs to someone else.) This is where IDOR bugs live.
  3. **Field level**: may this user see or set *this field*? (Cost price, other users' emails, `role`, `is_admin`, `price`.)
- Start simple: **roles for functions, ownership (or tenant) for objects**. Add attribute rules only when the business needs them.

## Rules

1. **Deny by default.** A route with no policy is closed. Make "public" an explicit list.
2. **One policy function**, called from every handler: `authorize(user, action, resource)` that raises or returns a denial. No inline `if user.role == ...` scattered around.
3. **Scope the query, not just the check.** Load objects with the owner/tenant in the `WHERE` clause (`WHERE id = ? AND owner_id = ?`). It cannot be forgotten at the use site and it avoids loading data you may not touch.
4. **Take identity from the session.** The user id, role and tenant never come from the request body, query string, headers or a hidden form field.
5. **Allow-list writable fields** (mass assignment). Build the record from named fields; never `User(**request.json)`. `role`, `owner_id`, `tenant_id`, `price`, `status`, `created_by` are server-set.
6. **Same answer for "missing" and "not yours"**: return `404` for both (or `403` for both). Different answers reveal that an id exists.
7. **Every access path counts**: list, search, export/CSV, report, file download, websocket/SSE subscription, webhook payloads, background jobs, caches (include user/tenant in the cache key), GraphQL fields, bulk endpoints, "recent items", autocomplete.
8. **Unpredictable ids help but are not a defense.** Use UUIDs or random ids for public references *and* check ownership.
9. **Re-check after state changes**: when a role is removed or a user disabled, sessions and caches must stop granting access immediately.
10. **Sensitive actions need more**: step-up authentication, a second approver, or limits (refunds, price overrides, bulk deletes, payout changes, role changes, data export).

## A policy function you can copy

```python
# runnable
class Denied(Exception):
    pass

ROLE_ACTIONS = {
    "user": {"invoice:create", "invoice:read", "invoice:list"},
    "admin": {"invoice:create", "invoice:read", "invoice:list", "user:list", "invoice:read_any"},
}

def authorize(user, action, resource=None):
    """Deny by default. `user` is built from the session, never from the request."""
    if user is None:
        raise Denied("authentication required")
    if action not in ROLE_ACTIONS.get(user["role"], set()):
        raise Denied("forbidden")
    if resource is not None and user["role"] != "admin" and resource["owner_id"] != user["id"]:
        raise Denied("not found")          # same answer as a missing object
    return True

alice = {"id": 1, "role": "user"}
bob = {"id": 2, "role": "user"}
admin = {"id": 9, "role": "admin"}
invoice = {"id": 17, "owner_id": 1}

assert authorize(alice, "invoice:read", invoice)
assert authorize(admin, "invoice:read", invoice)
for who, action, resource in [(None, "invoice:read", invoice), (bob, "invoice:read", invoice), (bob, "user:list", None), (alice, "role:grant", None)]:
    try:
        authorize(who, action, resource)
        raise AssertionError(f"{who} {action} should have been denied")
    except Denied:
        pass
```

```python
# runnable
import sqlite3

db = sqlite3.connect(":memory:")
db.executescript("CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner_id INTEGER, customer TEXT);"
                 "INSERT INTO invoices VALUES (17, 1, 'Acme'), (18, 2, 'Other');")

def get_invoice(user, invoice_id):
    """Scoped query: someone else's row simply does not exist for this caller."""
    row = db.execute("SELECT id, customer FROM invoices WHERE id = ? AND (owner_id = ? OR ?)",
                     (invoice_id, user["id"], 1 if user["role"] == "admin" else 0)).fetchone()
    if row is None:
        raise LookupError("not found")
    return row

assert get_invoice({"id": 1, "role": "user"}, 17) == (17, "Acme")
assert get_invoice({"id": 9, "role": "admin"}, 17) == (17, "Acme")
try:
    get_invoice({"id": 1, "role": "user"}, 18)
    raise AssertionError("IDOR")
except LookupError:
    pass
db.close()
```

Node equivalents: the same two ideas, a central `authorize(user, action, resource)` and a scoped query (`WHERE id = $1 AND owner_id = $2`). In Express put authorization in middleware per route group and still scope the query.

## Mass assignment

```python
# runnable
WRITABLE = {"customer", "amount", "note"}

def build_invoice(payload, user):
    unknown = set(payload) - WRITABLE
    if unknown:
        raise ValueError(f"unexpected fields: {sorted(unknown)}")      # or silently drop; never pass them through
    return {**{k: payload[k] for k in WRITABLE if k in payload}, "owner_id": user["id"]}      # owner is server-set

assert build_invoice({"customer": "A", "amount": 5}, {"id": 3}) == {"customer": "A", "amount": 5, "owner_id": 3}
try:
    build_invoice({"customer": "A", "owner_id": 99, "role": "admin"}, {"id": 3})
    raise AssertionError("mass assignment")
except ValueError:
    pass
```

## Multi-tenant applications

- Put `tenant_id` on **every** table and every unique key. Derive it from the session. A scoped-query helper that always adds `tenant_id` is better than remembering it.
- Defense in depth: database row-level security (PostgreSQL RLS) with the tenant set per connection/transaction, and a separate database role for the app.
- Include the tenant in cache keys, file paths, queue names, search indexes, and in securekit `context(...)` for encrypted fields.
- Tests always use **two tenants** and try every read and write across the boundary.

## Admin, support and impersonation

- Separate admin identities from normal accounts; no shared "admin" login. Require MFA for admin roles.
- Impersonation ("log in as the customer") is time-limited, visibly marked, blocked for the most sensitive actions, and fully audited with who/why/when.
- Admin APIs, are not a different, weaker door: same authentication, same logging, ideally a separate network path.

## Test it as a matrix (the way these bugs are found)

Use `../templates/authz_matrix.py` with a config of users, setup steps and cases. **Add one row per combination**: anonymous, other user, owner, admin × every route × every object type. Expected answers are part of the specification.

```bash
python authz_matrix.py --base http://127.0.0.1:8080 --config my_matrix.json
```

If the application has 20 routes and the matrix has 9 rows, the matrix is not finished. A missing row is a missing test.

## Failure patterns to look for in review

Handler that loads by id without owner/tenant; `if user.is_admin` taken from the request; an admin route protected only by hiding the link; list endpoints that filter but the export does not;
`PUT`/`PATCH` allowing `owner_id`; cached responses shared across users; permission checked at login only; GraphQL resolvers with no per-object check; direct database ids in file paths;
trusting a `X-User-Id` header set by a client; public bucket URLs for private documents; sequential invoice numbers used as the only access control.
