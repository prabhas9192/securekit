# 04 Injection and web attacks

Every one of these has the same root: **data crossing into a place where it is interpreted as code or structure** (SQL, HTML, shell, file paths, URLs, templates, deserializers).
The fix is also the same: keep data and instructions separate with the platform's safe mechanism, and validate at the boundary. The scanner (`python -m securekit scan`) flags the patterns marked (scan).

## Input validation (everywhere, first)

- Validate at the boundary against a **schema**: type, length, range, format, allowed values. **Reject** bad input with `400`; do not "clean" it.
- Cap sizes: request body (for example 1 MiB), page size, array length, string length, nesting depth, upload size, number of fields.
- Parse JSON in a try/except and require the expected top-level type (an object, not a list or a string).
- Validation is not a substitute for the escaping below; do both.

```python
# runnable
import json

MAX_BODY = 1_048_576

def parse_json_object(raw: bytes):
    if len(raw) > MAX_BODY:
        raise ValueError("request too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ValueError("invalid JSON")
    if not isinstance(data, dict):
        raise ValueError("a JSON object is required")
    return data

assert parse_json_object(b'{"a": 1}') == {"a": 1}
for bad in (b"{bad", b"[1]", b'"text"', b"\xff\xfe", b"x" * 2_000_000):
    try:
        parse_json_object(bad)
        raise AssertionError(bad[:10])
    except ValueError:
        pass
```

## SQL injection (scan: sql-injection)

- **Always bound parameters.** Never build SQL with `%`, `+`, `.format`, f-strings or template literals. ORMs are safe until you write raw SQL: check `.raw()`, `text()`, `$queryRawUnsafe`, `extra()`.
- Dynamic **identifiers** (table, column, ORDER BY direction) cannot be parameters: map the user's choice through an allow-list dictionary.
- `LIKE` patterns: bind the pattern as a parameter **and escape** `%`, `_` and the escape character in the user's text.
- Give the application database user only the rights it needs (no `DROP`, no superuser, separate migration user). That limits the damage of a bug you missed.

```python
# runnable
import sqlite3

db = sqlite3.connect(":memory:")
db.executescript("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, owner INTEGER);"
                 "INSERT INTO items VALUES (1, 'Rice 5kg', 1), (2, 'Secret of user 2', 2);")

def search(owner, text):
    pattern = "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    return db.execute("SELECT name FROM items WHERE owner = ? AND name LIKE ? ESCAPE '\\'", (owner, pattern)).fetchall()

SORTABLE = {"name": "name", "id": "id"}          # allow-list for identifiers

def listing(owner, sort):
    column = SORTABLE.get(sort, "id")             # unknown input falls back to a safe default
    return db.execute(f"SELECT name FROM items WHERE owner = ? ORDER BY {column}", (owner,)).fetchall()   # securekit-ignore: sql-injection (column from allow-list)

assert search(1, "rice") == [("Rice 5kg",)]
assert search(1, "' OR 1=1 --") == []             # the payload is just text
assert search(1, "%") == []                       # a wildcard from the user matches nothing special
assert listing(1, "name; DROP TABLE items") == [("Rice 5kg",)]
db.close()
```

Node (`pg`): `client.query('SELECT * FROM items WHERE owner = $1 AND name ILIKE $2', [owner, pattern])`. MySQL (`mysql2`): `execute('... WHERE owner = ?', [owner])`. Never `${}` into the SQL string.

## Cross-site scripting, XSS (scan: xss-sink)

- Use a template engine with **auto-escaping on** and keep it on. Mark nothing "safe" that contains user data (`|safe`, `mark_safe`, `Markup`, `dangerouslySetInnerHTML`, `v-html`, triple braces).
- In JavaScript use `textContent`, `setAttribute` for known-safe attributes, and framework bindings. Avoid `innerHTML`, `document.write`, `insertAdjacentHTML`, `eval`, `setTimeout("string")`.
- Context matters: HTML body, attribute, URL (`javascript:` URLs), JavaScript string, CSS each need their own encoding. Let the framework do it; never concatenate user text into any of them.
- Rich text (comments, descriptions): sanitize on output with a maintained sanitizer (DOMPurify, bleach/nh3) with an allow-list of tags, or support Markdown only.
- Defense in depth: a **Content-Security-Policy** (`default-src 'self'` or stricter, no `unsafe-inline`), `X-Content-Type-Options: nosniff`, and `HttpOnly` cookies.
- JSON responses must have `Content-Type: application/json` and `nosniff`.

```python
# runnable
import html

def results_page(text):
    return "<!doctype html><meta charset=utf-8><p>Results for " + html.escape(text) + "</p>"

page = results_page('<script>alert(1)</script>')
assert "<script>" not in page and "&lt;script&gt;" in page
assert "<img" not in results_page('"><img src=x onerror=alert(1)>')
```

## Cross-site request forgery, CSRF (scan: csrf-disabled)

- Applies when the browser sends credentials automatically (cookies, HTTP auth). Does **not** apply to bearer tokens sent in a header by your own JavaScript.
- Defenses together: `SameSite=Lax` (or `Strict`) cookies, a per-session **CSRF token** on state-changing requests (`POST/PUT/PATCH/DELETE`), checking the `Origin`/`Sec-Fetch-Site` header, and never changing state on `GET`.
- Re-authenticate for the most sensitive actions. Don't disable the framework's CSRF protection to "make a form work".

## Command injection and unsafe evaluation (scan: command-injection, unsafe-eval)

- Do not build shell strings. Use argument lists with no shell: `subprocess.run(["convert", path, out], check=True)`; Node `execFile("convert", [path, out])`.
- If the user chooses an option or a file, map it through an allow-list; never pass it as an option (leading `-`) without `--`.
- No `eval`, `exec`, `new Function`, `setTimeout(string)`, template engines rendering user-provided templates (server-side template injection).

```python
# runnable
import subprocess, sys

def convert_name(name):
    allowed = {"upper": str.upper, "lower": str.lower}
    return allowed[name]            # an unknown choice raises KeyError instead of being executed

out = subprocess.run([sys.executable, "-c", "import sys; print(sys.argv[1])", "; echo pwned"], capture_output=True, text=True, check=True).stdout
assert out.strip() == "; echo pwned"        # with an argument list the text stays text
assert convert_name("upper")("a") == "A"
```

## Path traversal and file uploads (scan: path-traversal)

- Never join a user-supplied name onto a directory. Use **generated ids** for stored files and keep the user's original name only as metadata.
- If you must accept a path component: resolve it and verify it stays inside the base directory.
- Uploads: limit size and count; check the **type by content** (magic bytes) against an allow-list, not by file name or the client's `Content-Type`; store **outside the web root**; serve with `Content-Disposition: attachment`
  and `nosniff`; scan for malware if files are shared with others; strip metadata from images when privacy matters; never execute or `include` uploaded files; store on a separate domain when serving user HTML/SVG.

```python
# runnable
import os, secrets, tempfile

def safe_join(base, user_path):
    base = os.path.realpath(base)
    target = os.path.realpath(os.path.join(base, user_path))
    if os.path.commonpath([base, target]) != base:
        raise ValueError("path escapes the base directory")
    return target

def new_stored_name(original):
    extension = os.path.splitext(original)[1].lower()
    if extension not in {".png", ".jpg", ".pdf"}:
        raise ValueError("file type not allowed")
    return secrets.token_hex(16) + extension          # the user's name is never used on disk

with tempfile.TemporaryDirectory() as base:
    assert safe_join(base, "reports/2026.pdf").startswith(os.path.realpath(base))
    for evil in ("../secret", "/etc/passwd", "a/../../b"):
        try:
            safe_join(base, evil)
            raise AssertionError(evil)
        except ValueError:
            pass
assert new_stored_name("My Invoice.PDF").endswith(".pdf") and len(new_stored_name("x.png")) == 36
```

## Server-side request forgery, SSRF (scan: ssrf)

When the server fetches a URL the user chose (webhooks, link previews, "import from URL", PDF/image fetchers): allow-list schemes (`https`) and hosts where possible; **resolve the name and refuse private, loopback,
link-local and metadata addresses** (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16` including `169.254.169.254`, `::1`, `fc00::/7`); connect to the address you checked (defeat DNS rebinding);
do not follow redirects blindly; set timeouts and size limits; don't return raw responses to the user.

```python
# runnable
import ipaddress

def is_public_address(text):
    address = ipaddress.ip_address(text)
    return not (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast or address.is_unspecified)

assert is_public_address("93.184.216.34")
for blocked in ("127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.9.9", "169.254.169.254", "::1", "0.0.0.0", "fd00::1"):
    assert not is_public_address(blocked), blocked
```

## Redirects, deserialization, XML (scan: open-redirect, unsafe-deserialization)

- **Open redirect:** redirect only to relative paths you build or to an allow-list; never to a raw `next=` URL. Check `url.startswith("/") and not url.startswith("//")` at minimum.
- **Deserialization:** `pickle`, `marshal`, `yaml.load`, Java `ObjectInputStream`, PHP `unserialize`, `node-serialize` execute attacker code. Use JSON and validate it.
- **XML:** disable external entities and DTDs (`defusedxml` in Python); prefer JSON.
- **Regular expressions:** avoid nested quantifiers on user input (ReDoS); put length limits before matching.

## HTTP hardening checklist (every response)

| Header / setting | Value |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` (HTML) | at least `default-src 'self'; frame-ancestors 'none'`; tighten per page |
| `Cache-Control` (private data) | `no-store` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` once HTTPS-only |
| `Referrer-Policy` | `no-referrer` or `strict-origin-when-cross-origin` |
| `X-Frame-Options` / `frame-ancestors` | `DENY` unless you embed on purpose |
| CORS | list exact origins; never `*` together with credentials (scan: cors-wildcard) |
| Cookies | `Secure; HttpOnly; SameSite` |
| Methods | refuse unsupported methods with `405`; no `TRACE` |

## Negative tests to write

SQL payloads (`' OR 1=1 --`, `') OR 1=1 --`, a `UNION SELECT`) return no foreign rows and no `500`; `<script>` text comes back escaped; malformed JSON is `400`; an oversized body is refused; `../` and absolute paths are rejected;
a URL pointing at `127.0.0.1` or the metadata address is refused; a state-changing request without the CSRF token fails; an uploaded `.html`/`.php` with an image extension is not served as code.
The benchmark scorer shows how to automate several of these (`../benchmark/score.py`).
