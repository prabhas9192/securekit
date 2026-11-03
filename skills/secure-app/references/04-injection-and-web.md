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
    target = os.path.realpath(os.path.join(_­ç‹\Ù\—Ü]
JBˆYˆÜËœ]˜ÛÛ[[Ûœ]
Ø˜\ÙK\™Ù]JHOH˜\ÙN‚ˆ˜Z\ÙH˜[YQ\œ›ÜŠœ]\ØØ\\ÈH˜\ÙH\™XİÜHŠBˆ™]\›ˆ\™Ù]‚™Yˆ™]×ÜİÜ™YÛ˜[YJÜšYÚ[˜[
N‚ˆ^[œÚ[ÛˆHÜËœ]œÜ]^
ÜšYÚ[˜[
VÌWK›İÙ\Š
BˆYˆ^[œÚ[Ûˆ›İ[ˆÈ‹œ™È‹‹šœÈ‹‹œˆŸN‚ˆ˜Z\ÙH˜[YQ\œ›ÜŠ™š[H\H›İ[İÙYŠBˆ™]\›ˆÙXÜ™]ËÚÙ[—Ú^
MŠH
È^[œÚ[ÛˆÈH\Ù\‰ÜÈ˜[YH\È™]™\ˆ\ÙYÛˆ\ÚÂ‚Ú][\š[K•[\Ü˜\Q\™XİÜJ
H\È˜\ÙN‚ˆ\ÜÙ\ØY™WÚ›Ú[Š˜\ÙKœ™\ÜËÌŒ‹œˆŠKœİ\İÚ]
ÜËœ]œ™X[]
˜\ÙJJBˆ›Üˆ]š[[ˆ
‹‹‹ÜÙXÜ™]‹‹Ù]ËÜ\ÜİÙ‹˜KË‹‹Ë‹‹ØˆŠN‚ˆN‚ˆØY™WÚ›Ú[Š˜\ÙK]š[
Bˆ˜Z\ÙH\ÜÙ\[Û‘\œ›ÜŠ]š[
Bˆ^Ù\˜[YQ\œ›Ü‚ˆ\ÜÂ˜\ÜÙ\™]×ÜİÜ™YÛ˜[YJ“^H[›ÚXÙK”ˆŠK™[™İÚ]
‹œˆŠH[™[Š™]×ÜİÜ™YÛ˜[YJœ™ÈŠJHOHÍ‚˜‚ˆÈÈÙ\™\‹\ÚYH™\]Y\İ›Ü™Ù\KÔÔ‘ˆ
ØØ[ˆÜÜ™ŠB‚•Ú[ˆHÙ\™\ˆ™]Ú\ÈHT“H\Ù\ˆÚÜÙH
ÙXšÛÚÜË[šÈ™]šY]ÜËš[\Üœ›ÛHT“‹‹Ú[XYÙH™]Ú\œÊNˆ[İË[\İØÚ[Y\È
Ø
H[™ÜİÈÚ\™HÜÜÚX›NÈ
Šœ™\ÛÛ™HH˜[YH[™™Y\ÙHš]˜]KÛÜ˜XÚË›[šË[ØØ[[™Y]Y]HY™\ÜÙ\ÊŠˆ
LÎMÌ‹ŒM‹ÌL˜NL‹ŒMÌM˜LËÎMKŒMÌM˜[˜ÛY[™ÈMKŒMŒMKŒMŒX˜Ì‹ÍØ
NÈÛÛ›™XİÈHY™\ÜÈ[İHÚXÚÙY
Y™X]”È™Xš[™[™ÊNÂ™È›İ›ÛİÈ™Y\™XİÈ›[™NÈÙ][Y[İ]È[™Ú^™H[Z]ÎÈÛ‰İ™]\›ˆ˜]È™\ÜÛœÙ\ÈÈH\Ù\‹‚‚˜]Û‚ˆÈ[›˜X›Bš[\Ü\Y™\ÜÂ‚™Yˆ\×ÜX›X×ØY™\ÜÊ^
N‚ˆY™\ÜÈH\Y™\ÜËš\ØY™\ÜÊ^
Bˆ™]\›ˆ›İ
Y™\ÜËš\×Üš]˜]HÜˆY™\ÜËš\×ÛÛÜ˜XÚÈÜˆY™\ÜËš\×Û[š×ÛØØ[ÜˆY™\ÜËš\×Ü™\Ù\™YÜˆY™\ÜËš\×Û][XØ\İÜˆY™\ÜËš\×İ[œÜXÚYšYY
B‚˜\ÜÙ\\×ÜX›X×ØY™\ÜÊLËŒNŒŒM‹ŒÍŠB™›Üˆ›ØÚÙY[ˆ
ŒLËŒŒŒH‹ŒLŒKŒ‹ŒÈ‹ŒNL‹ŒMŒH‹ŒMÌ‹ŒM‹KH‹ŒMKŒMŒMKŒM‹ŒH‹ŒŒŒŒ‹™™ŒHŠN‚ˆ\ÜÙ\›İ\×ÜX›X×ØY™\ÜÊ›ØÚÙY
K›ØÚÙY˜‚ˆÈÈ™Y\™XİË\Ù\šX[^˜][Û‹S
ØØ[ˆÜ[‹\™Y\™Xİ[œØY™KY\Ù\šX[^˜][ÛŠB‚‹H
Š“Ü[ˆ™Y\™XİŠŠˆ™Y\™XİÛ›HÈ™[]]™H]È[İHZ[ÜˆÈ[ˆ[İË[\İÈ™]™\ˆÈH˜]È™^XT“ˆÚXÚÈ\›œİ\İÚ]
‹ÈŠH[™›İ\›œİ\İÚ]
‹ËÈŠX]Z[š[][K‚‹H
Š‘\Ù\šX[^˜][ÛŠŠˆXÚÛXX\œÚ[X[[›ØY˜]˜HØš™Xİ[œ]İ™X[X[œÙ\šX[^™X›ÙK\Ù\šX[^™X^Xİ]H]XÚÙ\ˆÛÙKˆ\ÙH”ÓÓˆ[™˜[Y]H]‚‹H
Š–SŠŠˆ\ØX›H^\›˜[[]Y\È[™È
Y\ÙY[[ˆ]ÛŠNÈ™Y™\ˆ”ÓÓ‹‚‹H
Š”™Yİ[\ˆ^™\ÜÚ[ÛœÎŠŠˆ]›ÚY™\İY]X[YšY\œÈÛˆ\Ù\ˆ[œ]
™QÔÊNÈ][™İ[Z]È™Y›Ü™HX]Ú[™Ë‚‚ˆÈÈ\™[š[™ÈÚXÚÛ\İ
]™\H™\ÜÛœÙJB‚ŸXY\ˆÈÙ][™È˜[YHŸKK_KK_ŸPÛÛ[U\KSÜ[ÛœØ›ÜÛšY™˜ŸÛÛ[TÙXİ\š]KTÛXŞX
S
H]X\İY˜][\Ü˜È	ÜÙ[‰ÎÈœ˜[YKX[˜Ù\İÜœÈ	Û›Û™IØÈYÚ[ˆ\ˆYÙHŸØXÚKPÛÛ›Û
š]˜]H]JH›Ë\İÜ™XŸİšXİU˜[œÜÜTÙXİ\š]XX^XYÙOLÌMLÍŒÈ[˜ÛYTİX‘ÛXZ[œØÛ˜ÙHË[Û›HŸ™Y™\œ™\‹TÛXŞX›Ë\™Y™\œ™\˜ÜˆİšXİ[ÜšYÚ[‹]Ú[‹XÜ›ÜÜË[ÜšYÚ[˜ŸQœ˜[YKSÜ[ÛœØÈœ˜[YKX[˜Ù\İÜœØS–X[›\ÜÈ[İH[X™YÛˆ\œÜÙHŸÓÔ”È\İ^XİÜšYÚ[œÎÈ™]™\ˆ
˜ÙÙ]\ˆÚ]Ü™Y[X[È
ØØ[ˆÛÜœË]Ú[Ø\™
HŸÛÛÚÚY\ÈÙXİ\™NÈÛ›NÈØ[YTÚ]XŸY]ÙÈ™Y\ÙH[œİ\ÜYY]ÙÈÚ]XÈ›ÈPÑX‚ˆÈÈ™YØ]]™H\İÈÈÜš]B‚”ÔS^[ØYÈ
	ÈÔˆOLHKX	ÊHÔˆOLHKXHS’SÓˆÑSPÕ
H™]\›ˆ›È›Ü™ZYÛˆ›İÜÈ[™›ÈLÈØÜš\˜^ÛÛY\È˜XÚÈ\ØØ\YÈX[›Ü›YY”ÓÓˆ\ÈÈ[ˆİ™\œÚ^™Y›ÙH\È™Y\ÙYÈ‹‹Ø[™XœÛÛ]H]È\™H™Z™XİYÂ˜HT“Ú[[™È]LËŒŒŒXÜˆHY]Y]HY™\ÜÈ\È™Y\ÙYÈHİ]KXÚ[™Ú[™È™\]Y\İÚ]İ]HÔÔ‘ˆÚÙ[ˆ˜Z[ÎÈ[ˆ\ØYYš[ØœÚ][ˆ[XYÙH^[œÚ[Ûˆ\È›İÙ\™Y\ÈÛÙK‚•H™[˜ÚX\šÈØÛÜ™\ˆÚİÜÈİÈÈ]]ÛX]HÙ]™\˜[Ùˆ\ÙH‹‹Ø™[˜ÚX\šËÜØÛÜ™KœX
K‚