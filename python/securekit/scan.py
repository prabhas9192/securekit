"""
Heuristic scanner: finds places in a codebase where secrets or sensitive data are not protected.

    python -m securekit scan path/to/project [--json] [--fail-on high]

It reads files as text and matches patterns. That makes it fast and language-independent, and also makes it wrong
sometimes: a clean report is not proof that nothing needs encryption, and a finding is a prompt to look, not a verdict.
Secret values are never printed in full. Suppress a reviewed line with a comment containing `securekit-ignore`
(all rules) or `securekit-ignore: rule-id`, or list paths in a `.securekitignore` file (glob patterns, one per line).
"""

import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Optional, Pattern, Tuple

SEVERITIES = ["low", "medium", "high", "critical"]
MAX_FILE_BYTES = 1_048_576
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".idea", ".next"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock", "composer.lock", "Pipfile.lock"}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "fixtures", "testdata", "e2e", "examples", "example"}
CODE = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt", ".go", ".rb", ".php", ".cs", ".rs", ".swift", ".scala", ".sql", ".c", ".cc", ".cpp", ".h", ".m", ".vue", ".svelte", ".html"}
CONFIG = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".tf", ".tfvars", ".sh", ".bash", ".zsh", ".ps1", ".env", ".gradle"}
DOCS = {".md", ".rst", ".txt", ".adoc"}
PLACEHOLDER = re.compile(
    r"(?i)changeme|change[_-]me|replace[_-]|example|placeholder|your[_-]|xxx|\*{3,}|dummy|sample|todo|fixme|"
    r"\bnone\b|\bnull\b|undefined|process\.env|os\.environ|getenv|environ\[|^\$\{|^\$\(|^%\(|^<.+>$|^\{\{|^__"
)


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    pattern: Pattern
    message: str
    fix: str
    kinds: Tuple[str, ...] = ("code", "config")
    skip_tests: bool = False
    secret: bool = False                 # redact the match; also drop placeholder values
    also: Optional[Pattern] = None       # the same line must match this too
    also_code: Optional[Pattern] = None  # ...and so must the code outside string literals (interpolated expressions count)
    unless: Optional[Pattern] = None     # ...and must not match this (for example "already encrypted")
    filenames: Optional[Pattern] = None  # only for files whose name matches


def _r(pattern: str, flags: int = 0) -> Pattern:
    return re.compile(pattern, flags)


_SENSITIVE_COLUMN = (
    r"(?:ssn|social_security\w*|tax_id|national_id|passport\w*|credit_card\w*|card_number|cvv|cvc|iban|"
    r"bank_account\w*|api_key|secret\w*|private_key|mfa_secret|totp_secret|recovery_code\w*)"
)

RULES: List[Rule] = [
    Rule("private-key", "critical", _r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
         "A private key is stored in the codebase.", "Remove it from the repository history, rotate the key, and load it from a secrets store (securekit Vault, KMS or your platform's secret manager).",
         kinds=("code", "config", "doc", "other"), secret=True),
    Rule("aws-access-key", "high", _r(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
         "An AWS access key id is hard-coded.", "Revoke the key and use an instance/role identity or a secrets store.", kinds=("code", "config", "doc", "other"), secret=True),
    Rule("token-literal", "high", _r(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
         "A live-looking API token or JWT is hard-coded.", "Revoke it and keep it in the vault (Vault.put) or your secret manager.", kinds=("code", "config", "doc", "other"), secret=True),
    Rule("hardcoded-secret", "medium",
         _r(r"""(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret)\b["']?\s*[:=]\s*["']([^"'\s$<{][^"'\n]{7,})["']"""),
         "A credential appears to be assigned a literal value.", "Read it at runtime from the vault or environment instead (Vault.get_str / Keyring.from_env).", skip_tests=True, secret=True),
    Rule("env-file-secret", "high",
         _r(r"""(?i)^\s*(?:export\s+)?[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY)[A-Z0-9_]*\s*=\s*["']?([^\s"'#][^\s"'#]{3,})"""),
         "A committed .env file holds a secret.", "Keep .env out of version control, rotate what was exposed, and load secrets from the vault.",
         kinds=("config", "other"), secret=True, filenames=_r(r"^\.env(?!.*\.(?:example|sample|template|dist)$)")),
    Rule("hardcoded-key-material", "high",
         _r(r"""(?i)\b(?:key|secret|iv|nonce|salt)\w*\s*[:=]\s*b?["']((?:[0-9a-fA-F]{32,}|[A-Za-z0-9+/]{43}=))["']"""),
         "Key material (long hex/base64) is hard-coded.", "Generate keys with generate_key() and load them with Keyring.from_env().", skip_tests=True, secret=True),
    Rule("dockerfile-secret", "high", _r(r"""(?i)^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)\w*(?:\s*=\s*|\s+)["']?([^\s"'$][^\s"']{3,})"""),
         "A Dockerfile bakes a secret into the image layers.", "Pass secrets at runtime (mounted file or environment) or with BuildKit secret mounts; never ENV/ARG.",
         kinds=("config", "other"), secret=True, filenames=_r(r"(?i)^(?:dockerfile|.*\.dockerfile)")),
    Rule("weak-hash", "medium",
         _r(r"""\b(?:hashlib\.(?:md5|sha1)\s*\(|createHash\(\s*["'](?:md5|sha1)["']\s*\)|MessageDigest\.getInstance\(\s*["'](?:MD5|SHA-?1)["']\s*\)|\bmd5\s*\()"""),
         "MD5/SHA-1 is broken for security purposes.", "Use SHA-256 (hashlib.sha256) for integrity, HMAC for authenticity, hash_password (Argon2id) for passwords."),
    Rule("fast-password-hash", "high", _r(r"(?i)(?<![-\w])(?:sha(?:1|224|256|384|512)|md5)\s*\([^)\n]*pass(?:word|wd)?\b|createHash\([^)\n]*\)\.update\([^)\n]*pass(?:word|wd)?\b"),
         "A password appears to be hashed with a fast, unsalted hash.", "Use hash_password / verify_password (Argon2id)."),
    Rule("broken-cipher", "high", _r(r"""\b(?:MODE_ECB|AES/ECB|DES(?:ede|3)?|RC4|ARC4|Blowfish)\b|["']aes-(?:128|192|256)-ecb["']"""),
         "ECB mode or a broken cipher (DES, RC4, Blowfish) is in use.", "Use authenticated encryption: FieldCipher (AES-256-GCM)."),
    Rule("unauthenticated-cipher", "medium", _r(r"""\bMODE_(?:CBC|CTR|CFB|OFB)\b|["']aes-(?:128|192|256)-(?:cbc|ctr|cfb|ofb)["']|AES/(?:CBC|CTR)/"""),
         "Encryption without authentication (CBC/CTR/CFB/OFB) lets an attacker modify ciphertext undetected.", "Use FieldCipher (AES-256-GCM), which authenticates the ciphertext."),
    Rule("weak-random", "medium", _r(r"\b(?:random\.(?:random|randint|choice|choices|getrandbits|randrange)\(|Math\.random\(\)|\brand\(\))"),
         "A predictable random generator is used where secrets are made.", "Use random_token() / secrets / crypto.randomBytes.",
         also=_r(r"(?i)token|secret|password|passwd|\bkey\b|nonce|\bsalt\b|\botp\b|session|csrf|reset|api[_-]?key")),
    Rule("tls-verification-off", "high",
         _r(r"""(?i)\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED["']?\s*[:=]\s*["']?0|_create_unverified_context|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER"""),
         "TLS certificate verification is switched off.", "Remove it; fix the trust store instead. Without verification the connection is open to interception."),
    Rule("cleartext-http", "low",
         _r(r"(?i)\bhttp://(?!localhost|127\.|0\.0\.0\.0|\[::1\]|host\.docker\.internal|example\.|www\.w3\.org|schemas\.|json-schema\.org|purl\.org|xmlns|ns\.|[\w.-]*\.local\b)[a-z0-9.-]+\.[a-z]{2,}"),
         "A cleartext http:// URL to an external host.", "Use https:// (and mTLS between internal services where you can)."),
    Rule("plaintext-sensitive-column", "medium",
         _r(r"(?i)\b" + _SENSITIVE_COLUMN + r"\b\s*(?::[^=\n]+)?=\s*(?:\w+\.)*(?:Column|mapped_column|CharField|TextField|StringField|String)\("),
         "A sensitive-looking column is stored as plain text.", "Declare it EncryptedText and register it with SecureModels (or encrypt with FieldCipher and a row context).", skip_tests=True,
         unless=_r(r"(?i)encrypt|ciphertext")),
    Rule("plaintext-sensitive-column", "medium", _r(r"(?i)^\s*" + _SENSITIVE_COLUMN + r"\s+(?:var)?char|^\s*" + _SENSITIVE_COLUMN + r"\s+text\b"),
         "A sensitive-looking SQL column is stored as plain text.", "Store ciphertext (FieldCipher token) and a blind index if you must search it.", kinds=("code",), skip_tests=True,
         unless=_r(r"(?i)encrypt|ciphertext")),
    Rule("sensitive-logging", "medium",
         _r(r"(?i)\b(?:log(?:ger)?\.(?:debug|info|warn(?:ing)?|error|exception|critical)|print|console\.(?:log|info|debug|warn|error)|println|Log\.[dviwe])\s*\("),
         "A log or print statement passes something that looks like a secret or sensitive value; check that the value itself is not written.",
         "Log identifiers, never the value; mask it first.", skip_tests=True,
         also_code=_r(r"(?i)\w*(?:password|passwd|secret|api_?key|authorization|\bssn|_ssn|credit_?card|card_?number|\bcvv|private_?key|access_?token|refresh_?token|auth_?token|bearer)\w*")),
    Rule("jwt-unsafe", "high", _r(r"""(?i)algorithms?\s*[:=]\s*\[[^\]]*["']none["']|verify_signature["']?\s*[:=]\s*False|ignoreExpiration\s*:\s*true|jwt\.decode\([^)\n]*verify\s*=\s*False"""),
         "JWT validation is weakened (none algorithm, no signature or expiry check).", "Pin the algorithm, verify the signature and expiry, and keep the signing key in the vault."),
    Rule("insecure-cookie", "medium", _r(r"(?i)\bsecure\s*[:=]\s*false\b|\bhttponly\s*[:=]\s*false\b|(?:SESSION|CSRF)_COOKIE_SECURE\s*=\s*False"),
         "A cookie is sent without the Secure/HttpOnly flag.", "Set Secure and HttpOnly (and SameSite) on session and auth cookies."),
    Rule("browser-token-storage", "medium", _r(r"""(?i)(?:localStorage|sessionStorage)\.setItem\(\s*["']\w*(?:token|jwt|password|secret|api_?key)\w*["']"""),
         "A token or secret is kept in browser storage, readable by any script on the page.", "Prefer an HttpOnly Secure cookie; never store long-lived secrets in the browser.", kinds=("code",)),
    Rule("k8s-secret-manifest", "medium", _r(r"^\s*kind:\s*Secret\s*$"),
         "A Kubernetes Secret manifest is committed. Its values are base64, not encryption.", "Use sealed-secrets, SOPS or an external secrets operator so the committed form is encrypted.", kinds=("config",)),

    # --- injection and web attacks (see skills/secure-app/references/04-injection-and-web.md) ---
    Rule("sql-injection", "high",
         _r(r"""\.(?:execute|executemany|executescript|raw|query|\$queryRawUnsafe|\$executeRawUnsafe)\(\s*(?:[fF]["'][^"'\n]*\{|`[^`\n]*\$\{|["'][^"'\n]*["']\s*(?:%\s*[\w(]|\+\s*[\w(])|["'][^"'\n]*["']\s*\.format\()"""),
         "An SQL statement is built by string formatting or concatenation.", "Pass values as bound parameters (`execute(\"... WHERE id = ?\", (x,))`); allow-list any dynamic table or column name.", kinds=("code",)),
    Rule("command-injection", "high",
         _r(r"""\bshell\s*=\s*True\b|\bos\.(?:system|popen)\(|\bexec(?:Sync)?\(\s*(?:`[^`\n]*\$\{|["'][^"'\n]*["']\s*\+)"""),
         "A shell command is built from strings or run through a shell.", "Run programs with an argument list and no shell (`subprocess.run([...])`, `execFile`), and allow-list any user-chosen value.", kinds=("code",)),
    Rule("unsafe-eval", "high", _r(r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|(?<![\w.])exec\s*\(\s*[^)\s]"),
         "Dynamic code evaluation (eval, exec, new Function).", "Parse data with JSON or a real parser; never evaluate strings that can contain user input.", kinds=("code",)),
    Rule("unsafe-deserialization", "high",
         _r(r"\bc?[pP]ickle\.loads?\(|\bmarshal\.loads?\(|\byaml\.load\((?![^)\n]*Safe)|\bjsonpickle\.decode\(|node-serialize|\bunserialize\(|ObjectInputStream\("),
         "Deserializing untrusted data with a format that can run code.", "Use JSON (or yaml.safe_load) and validate the shape.", kinds=("code",)),
    Rule("xss-sink", "medium",
         _r(r"""\.innerHTML\s*\+?=|\.outerHTML\s*=|insertAdjacentHTML\(|dangerouslySetInnerHTML|document\.write(?:ln)?\(|\|\s*safe\b|\bmark_safe\(|\bMarkup\(|\bv-html\b|<%-|\|\s*raw\b"""),
         "Output that bypasses HTML escaping (innerHTML, |safe, dangerouslySetInnerHTML ...).", "Use textContent / auto-escaping templates; sanitize rich text with a maintained sanitizer and set a Content-Security-Policy.",
         kinds=("code",), unless=_r(r"""innerHTML\s*=\s*(?:["']\s*["']|``)""")),
    Rule("debug-enabled", "medium", _r(r"\bdebug\s*=\s*True\b|\bDEBUG\s*=\s*True\b|FLASK_DEBUG\s*=\s*[\"']?1|\bapp\.debug\s*=\s*true"),
         "Debug mode is switched on; it shows stack traces and often allows code execution.", "Read it from the environment and default to off.", skip_tests=True),
    Rule("cors-wildcard", "medium",
         _r(r"""(?i)access-control-allow-origin["']?\s*[:,=]\s*["']?\*|allow_origins\s*=\s*\[\s*["']\*|\borigins?\s*[:=]\s*["']\*["']|\bcors\(\s*\)|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True"""),
         "Any website may call this API from a browser (wildcard CORS).", "List the exact origins you trust; never combine a wildcard with credentials."),
    Rule("path-traversal", "medium",
         _r(r"\b(?:open|send_file|send_from_directory|readFile(?:Sync)?|createReadStream|sendFile)\(.*\b(?:request|req)\.(?:args|form|json|params|query|body|GET|POST|files)\b"),
         "A request value is used to build a file path.", "Resolve the path and check it stays inside the allowed directory; better, use generated ids instead of names.", kinds=("code",)),
    Rule("ssrf", "medium",
         _r(r"\b(?:requests\.(?:get|post|put|request)|urlopen|fetch|axios(?:\.(?:get|post))?|http\.get|got)\(.*\b(?:request|req)\.(?:args|form|json|params|query|body|GET|POST)\b"),
         "The server fetches a URL taken from the request (server-side request forgery).", "Allow-list hosts, resolve and block private/link-local addresses, disable redirects, and set short timeouts.", kinds=("code",)),
    Rule("open-redirect", "medium", _r(r"\bredirect\(.*\b(?:request|req)\.(?:args|form|params|query|GET|POST)\b"),
         "A redirect target comes from the request.", "Redirect only to relative paths or an allow-list of hosts.", kinds=("code",)),
    Rule("csrf-disabled", "medium", _r(r"@csrf_exempt|\bWTF_CSRF_ENABLED\s*=\s*False|\bCSRF_ENABLED\s*=\s*False|\bcsrf\s*:\s*false|csrf_protect\s*=\s*False"),
         "CSRF protection is switched off.", "Keep CSRF protection on for cookie-authenticated, state-changing routes (SameSite cookies plus tokens).", skip_tests=True),
    Rule("framework-secret-key", "high",
         _r(r"""(?i)\b(?:SECRET_KEY|JWT_SECRET|JWT_KEY|SESSION_SECRET|COOKIE_SECRET|APP_SECRET|SIGNING_KEY|ENCRYPTION_KEY)\b["']?\]?\s*[:=]\s*b?["']([^"'\s$<{][^"'\n]{3,})["']"""),
         "A framework signing/session key is a literal in the code.", "Load it from the vault or environment; anyone with the repository could otherwise forge sessions.", skip_tests=True, secret=True),
    Rule("secret-in-url", "medium", _r(r"""["'][^"'\n]*[?&](?:password|passwd|pwd|token|api_?key|secret|access_token)="""),
         "A secret travels in a URL query string, which ends up in logs, history and Referer headers.", "Send it in a header or request body; if it is a single-use link token, keep it short-lived and one-time.", skip_tests=True),
    Rule("non-constant-time-compare", "medium",
         _r(r"\b\w*(?:token|signature|hmac|digest|api_?key|secret)\w*\s*(?:==|!=|===|!==)\s*[\w.\[\]]"),
         "A secret-like value is compared with ==, which leaks timing information.", "Use constant_time_equals / hmac.compare_digest / crypto.timingSafeEqual.", kinds=("code",), skip_tests=True,
         unless=_r(r"""(?:==|!=|===|!==)\s*(?:None|null|undefined|True|False|true|false|["'\d])|\blen\(|\.length""")),
    Rule("world-writable", "medium", _r(r"\bchmod\(.*\b0o?777\b|\bchmod\s+(?:-R\s+)?777\b"),
         "A file or directory is made world-writable.", "Use the narrowest mode that works (0600 for secrets, 0750 for directories).", kinds=("code", "config")),
    Rule("default-credentials", "high", _r(r"""(?i)["']admin["']\s*,\s*["'](?:admin|password|123456|1234|admin123|root|changeme)["'](?!\s*:)|\badmin:(?:admin|password|123456)\b"""),
         "Default administrator credentials appear in the code.", "Create the first admin with a generated one-time password or an install-time prompt.", skip_tests=True),
]


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    snippet: str
    message: str
    fix: str

    def as_dict(self) -> Dict[str, object]:
        return {"rule": self.rule, "severity": self.severity, "path": self.path, "line": self.line,
                "snippet": self.snippet, "message": self.message, "fix": self.fix}


_LITERAL = re.compile(r"""[fFrRbB]{0,2}("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)""")
_INTERPOLATION = re.compile(r"\{([^{}]*)\}")


def _code_outside_strings(line: str) -> str:
    """The line with string literals removed, keeping the expressions inside f-string / template-literal braces."""
    def keep(match: "re.Match") -> str:
        expressions = " ".join(_INTERPOLATION.findall(match.group(1)))
        return " " + _LITERAL.sub(" ", expressions) + " "

    return _LITERAL.sub(keep, line)


def _kind(path: str) -> str:
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    if ext in CODE:
        return "code"
    if ext in CONFIG or name.startswith(".env") or name.lower().startswith("dockerfile"):
        return "config"
    if ext in DOCS:
        return "doc"
    return "other"


def _is_test_path(relative: str) -> bool:
    return any(part.lower() in TEST_DIRS or part.lower().startswith("test_") or part.lower().endswith((".test.js", ".test.ts", "_test.py", "_test.go", ".spec.ts", ".spec.js")) for part in relative.split(os.sep))


def _ignored_rules(line: str) -> Optional[set]:
    """None if the line has no ignore marker; an empty set means 'ignore everything'."""
    marker = re.search(r"securekit-ignore(?::\s*([\w,\s-]+))?", line)
    if not marker:
        return None
    return {r.strip() for r in marker.group(1).split(",")} if marker.group(1) else set()


def _mask(line: str, match: "re.Match", secret: bool) -> str:
    text = line.strip()
    if secret:
        value = match.group(1) if match.groups() else match.group(0)
        shown = value[:3] + "***" if len(value) > 6 else "***"
        text = text.replace(value, shown)
    return text if len(text) <= 160 else text[:157] + "..."


def scan_text(relative: str, text: str, *, include_tests: bool = False) -> List[Finding]:
    kind, name = _kind(relative), os.path.basename(relative)
    in_tests = _is_test_path(relative)
    findings: List[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if len(line) > 2000:
            continue
        ignored = _ignored_rules(line)
        comment = line.lstrip().startswith(("#", "//", "*", "/*", "--", "<!--"))
        for rule in RULES:
            if comment and not rule.secret:       # a commented-out secret is still a leak; commented-out code is not a finding
                continue
            if kind not in rule.kinds or (rule.filenames and not rule.filenames.search(name)) or (rule.skip_tests and in_tests and not include_tests):
                continue
            match = rule.pattern.search(line)
            if not match or (rule.also and not rule.also.search(line)) or (rule.unless and rule.unless.search(line)):
                continue
            if rule.also_code and not rule.also_code.search(_code_outside_strings(line)):
                continue
            if ignored is not None and (not ignored or rule.id in ignored):
                continue
            if rule.secret and match.groups() and PLACEHOLDER.search(match.group(1)):
                continue
            findings.append(Finding(rule.id, rule.severity, relative, number, _mask(line, match, rule.secret), rule.message, rule.fix))
    return findings


def _load_ignores(root: str) -> List[str]:
    path = os.path.join(root, ".securekitignore")
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")]


def _files(root: str, patterns: List[str]) -> Iterator[Tuple[str, str]]:
    if os.path.isfile(root):
        yield root, os.path.basename(root)
        return
    for current, directories, names in os.walk(root):
        directories[:] = sorted(d for d in directories if d not in SKIP_DIRS)
        for name in sorted(names):
            full = os.path.join(current, name)
            relative = os.path.relpath(full, root)
            if name in SKIP_FILES or name.endswith((".min.js", ".map", ".lock")) or any(fnmatch.fnmatch(relative, p) or relative.startswith(p.rstrip("/") + os.sep) for p in patterns):
                continue
            yield full, relative


def scan_path(root: str, *, include_tests: bool = False) -> Tuple[List[Finding], int]:
    findings: List[Finding] = []
    scanned = 0
    base = root if os.path.isdir(root) else os.path.dirname(root) or "."
    for full, relative in _files(root, _load_ignores(base)):
        try:
            if os.path.getsize(full) > MAX_FILE_BYTES:
                continue
            with open(full, "rb") as handle:
                raw = handle.read()
        except OSError:
            continue
        if b"\x00" in raw[:8192]:
            continue
        scanned += 1
        findings.extend(scan_text(relative, raw.decode("utf-8", errors="replace"), include_tests=include_tests))
    findings.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.path, f.line, f.rule))
    return findings, scanned


def run_cli(args) -> int:
    if not os.path.exists(args.path):
        print(f"securekit: no such path: {args.path}", file=sys.stderr)
        return 2
    findings, scanned = scan_path(args.path, include_tests=args.include_tests)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in reversed(SEVERITIES)}
    if args.json:
        print(json.dumps({"scanned": scanned, "summary": counts, "findings": [f.as_dict() for f in findings]}, indent=2))
    else:
        for f in findings:
            print(f"[{f.severity.upper()}] {f.rule}  {f.path}:{f.line}\n    {f.snippet}\n    {f.message}\n    fix: {f.fix}\n")
        summary = ", ".join(f"{n} {s}" for s, n in counts.items() if n) or "no findings"
        print(f"scanned {scanned} file(s): {summary}")
        if not findings:
            print("A clean scan is not proof of safety: this tool matches patterns and cannot see data flows.")
    if args.fail_on == "never":
        return 0
    threshold = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(f.severity) >= threshold for f in findings) else 0
