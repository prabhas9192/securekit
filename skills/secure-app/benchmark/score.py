#!/usr/bin/env python3
"""
Scores an implementation of scenarios/billing-api.md: starts it, attacks it with real requests, inspects its database file.

    python score.py --app path/to/app.py [--json] [--min-score 0.9]

Functional gates come first: if the API does not work, the security checks are not meaningful and the run is marked invalid.
Each security check has a weight; the score is the weighted share that passed. A passing score is evidence, not proof:
the checks are a fixed list, so also read the code and run the other tools (securekit scan, a real review).
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SECUREKIT_PYTHON = os.path.abspath(os.path.join(HERE, "..", "..", "..", "python"))
CHECKS = []


def check(check_id, category, weight, title):
    def register(fn):
        CHECKS.append((check_id, category, weight, title, fn))
        return fn
    return register


class Env:
    """One running app plus helpers to talk to it."""

    def __init__(self, port, db_path):
        self.port, self.db_path = port, db_path
        self.suffix = secrets.token_hex(3)
        self.admin_password = "Admin-Pass-" + secrets.token_hex(6)
        self.password = "Correct-Horse-9-" + secrets.token_hex(4)
        self.users = {}

    def call(self, method, path, body=None, token=None, raw=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        send_headers = dict(headers or {})
        if token:
            send_headers["Authorization"] = "Bearer " + token
        payload = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        if payload is not None:
            send_headers.setdefault("Content-Type", "application/json")
        try:
            connection.request(method, path, body=payload, headers=send_headers)
            response = connection.getresponse()
            data = response.read()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, data
        finally:
            connection.close()

    def json(self, data):
        try:
            return json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def register(self, name, **extra):
        username = f"{name}_{self.suffix}"
        phone = f"+91-{secrets.token_hex(3).upper()}-{name.upper()}-{self.suffix.upper()}"
        status, _, data = self.call("POST", "/register", {"username": username, "password": self.password, "phone": phone, **extra})
        self.users[name] = {"username": username, "phone": phone, "status": status, "body": data}
        return status

    def login(self, username, password=None):
        status, _, data = self.call("POST", "/login", {"username": username, "password": password or self.password})
        parsed = self.json(data)
        return status, (parsed or {}).get("token") if isinstance(parsed, dict) else None

    def token_for(self, name):
        return self.login(self.users[name]["username"])[1]

    def disk_bytes(self):
        base = os.path.basename(self.db_path)
        folder = os.path.dirname(self.db_path)
        blob = b""
        for name in sorted(os.listdir(folder)):
            if name.startswith(base):
                with open(os.path.join(folder, name), "rb") as handle:
                    blob += handle.read()
        return blob


# ------------------------------------------------------------------ functional gates (not scored)

def run_gates(env):
    failures = []

    def gate(name, ok):
        if not ok:
            failures.append(name)

    gate("register", env.register("alice") == 201 and env.register("bob") == 201)
    token = env.token_for("alice")
    gate("login returns a token", bool(token))
    status, _, data = env.call("POST", "/invoices", {"customer": "Acme Traders " + env.suffix, "amount": 120.5, "note": "first"}, token=token)
    invoice_id = (env.json(data) or {}).get("id") if status == 201 else None
    gate("create invoice", isinstance(invoice_id, int))
    env.users["alice"]["invoice"] = invoice_id
    env.users["alice"]["customer"] = "Acme Traders " + env.suffix
    status, _, data = env.call("GET", f"/invoices/{invoice_id}", token=token)
    gate("read own invoice", status == 200 and (env.json(data) or {}).get("customer") == env.users["alice"]["customer"])
    status, _, data = env.call("GET", "/invoices?q=" + "acme traders".replace(" ", "%20"), token=token)
    gate("search own invoices", status == 200 and isinstance(env.json(data), list) and len(env.json(data)) == 1)
    status, _, data = env.call("GET", "/me", token=token)
    gate("/me returns the phone", status == 200 and (env.json(data) or {}).get("phone") == env.users["alice"]["phone"])
    status, _, data = env.call("GET", "/search?q=hello", token=None)
    gate("/search returns html", status == 200 and b"Results for " in data and b"hello" in data)
    status, admin_token = env.login("admin", env.admin_password)
    gate("admin can log in", bool(admin_token))
    status, _, data = env.call("GET", "/admin/users", token=admin_token)
    gate("admin can list users", status == 200 and isinstance(env.json(data), list))
    status, _, data = env.call("GET", f"/invoices/{invoice_id}", token=admin_token)
    gate("admin can read any invoice", status == 200)
    return failures


# ------------------------------------------------------------------ security checks

@check("AN1", "authn", 2, "Login errors do not reveal whether a username exists")
def an1(env):
    first = env.call("POST", "/login", {"username": "nobody_" + env.suffix, "password": "wrong-password-123"})
    second = env.call("POST", "/login", {"username": env.users["alice"]["username"], "password": "wrong-password-123"})
    return first[0] == second[0] == 401 and first[2] == second[2], f"{first[0]} {first[2][:60]!r} vs {second[0]} {second[2][:60]!r}"


@check("AN3", "authn", 2, "Session tokens are long, random and not derived from the username")
def an3(env):
    username = env.users["alice"]["username"]
    first, second = env.login(username)[1], env.login(username)[1]
    derived = {username, base64.b64encode(username.encode()).decode(), base64.urlsafe_b64encode(username.encode()).decode().rstrip("=")}
    for algorithm in (hashlib.md5, hashlib.sha1, hashlib.sha256):
        derived.add(algorithm(username.encode()).hexdigest())
    ok = bool(first and second) and first != second and len(first) >= 32 and first not in derived
    return ok, f"lengths {len(first or '')}/{len(second or '')}, same={first == second}, derived={first in derived}"


SLOW_KDF_MARKERS = (b"$argon2id$", b"$argon2i$", b"$argon2d$", b"$scrypt$", b"scrypt:", b"scrypt$", b"pbkdf2", b"PBKDF2", b"$2a$", b"$2b$", b"$2y$")


@check("AN4", "authn", 2, "Passwords are stored with a slow salted hash (Argon2id, scrypt, PBKDF2, bcrypt), never in plain text or a fast hash")
def an4(env):
    blob = env.disk_bytes()
    if env.password.encode() in blob:
        return False, "the plain-text password is in the database file"
    for name in ("md5", "sha1", "sha256", "sha512"):
        if hashlib.new(name, env.password.encode()).hexdigest().encode() in blob:
            return False, f"an unsalted {name} hash of the password is in the database file"
    marker = next((m for m in SLOW_KDF_MARKERS if m in blob), None)
    return marker is not None, f"found {marker.decode()}" if marker else "no recognizable slow password hash (argon2id/scrypt/pbkdf2/bcrypt marker) in the database"


@check("AN5", "authn", 1, "Session tokens are not stored in plain text")
def an5(env):
    token = env.token_for("alice")
    return bool(token) and token.encode() not in env.disk_bytes(), "token found in the database file" if token and token.encode() in env.disk_bytes() else "ok"


@check("AN6", "authn", 1, "Missing or invalid tokens are rejected")
def an6(env):
    return env.call("GET", "/me")[0] == 401 and env.call("GET", "/me", token="x" * 40)[0] == 401, ""


@check("AN7", "authn", 1, "Weak passwords are rejected at registration")
def an7(env):
    status = env.call("POST", "/register", {"username": "weak_" + env.suffix, "password": "short"})[0]
    return status == 400, f"status {status}"


@check("AZ1", "authz", 2, "Anonymous users cannot read invoices")
def az1(env):
    status = env.call("GET", f"/invoices/{env.users['alice']['invoice']}")[0]
    return status == 401, f"status {status}"


@check("AZ2", "authz", 3, "A user cannot read another user's invoice (IDOR)")
def az2(env):
    status, _, data = env.call("GET", f"/invoices/{env.users['alice']['invoice']}", token=env.token_for("bob"))
    return status in (403, 404) and env.users["alice"]["customer"].encode() not in data, f"status {status}"


@check("AZ3", "authz", 3, "Only admins can list users")
def az3(env):
    as_user = env.call("GET", "/admin/users", token=env.token_for("bob"))[0]
    anonymous = env.call("GET", "/admin/users")[0]
    return as_user == 403 and anonymous == 401, f"user {as_user}, anonymous {anonymous}"


@check("AZ4", "authz", 2, "Listing and searching only return the caller's own invoices")
def az4(env):
    status, _, data = env.call("GET", "/invoices?q=Acme", token=env.token_for("bob"))
    return status == 200 and env.json(data) == [], f"status {status}, body {data[:80]!r}"


@check("AZ5", "authz", 2, "A request cannot choose its own role (mass assignment)")
def az5(env):
    env.register("mallory", role="admin")
    status = env.call("GET", "/admin/users", token=env.token_for("mallory"))[0]
    return status == 403, f"status {status}"


@check("IN1", "injection", 3, "SQL injection in the invoice search does not leak other users' rows")
def in1(env):
    token = env.token_for("bob")
    payloads = ["%27%20OR%201%3D1%20--%20", "%27)%20OR%201%3D1%20--%20", "%25%27%20OR%20%271%27%3D%271", "x%27%20UNION%20SELECT%20id%2Ccustomer%2Camount%2Cnote%20FROM%20invoices%20--%20"]
    for payload in payloads:
        status, _, data = env.call("GET", "/invoices?q=" + payload, token=token)
        if status not in (200, 400) or env.users["alice"]["customer"].encode() in data:
            return False, f"payload {payload!r} gave status {status}" + (" and another user's data" if env.users["alice"]["customer"].encode() in data else "")
    return True, f"{len(payloads)} payloads"


@check("IN2", "injection", 3, "SQL injection in login does not bypass authentication")
def in2(env):
    status, _, _ = env.call("POST", "/login", {"username": "admin' --", "password": "x"})
    status_or, _, _ = env.call("POST", "/login", {"username": "' OR '1'='1", "password": "' OR '1'='1"})
    return status in (400, 401) and status_or in (400, 401), f"{status}/{status_or}"


@check("IN3", "injection", 2, "User text is escaped in the HTML search page (XSS)")
def in3(env):
    status, _, data = env.call("GET", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    return status == 200 and b"<script>alert(1)</script>" not in data, "raw script tag reflected" if b"<script>alert(1)</script>" in data else "escaped"


@check("IN4", "injection", 1, "Malformed JSON gives 400, not a crash")
def in4(env):
    status, _, data = env.call("POST", "/login", raw=b"{bad json")
    return status == 400 and b"Traceback" not in data, f"status {status}"


@check("IN5", "injection", 1, "Oversized bodies are refused")
def in5(env):
    try:
        status = env.call("POST", "/register", raw=b'{"username": "' + b"a" * 2_100_000 + b'"}')[0]
    except (ConnectionError, http.client.HTTPException, socket.timeout, OSError):
        return True, "connection closed by server"
    return status in (400, 413), f"status {status}"


@check("DP1", "data", 3, "The phone number is not stored in plain text")
def dp1(env):
    found = any(user["phone"].encode() in env.disk_bytes() for name, user in env.users.items() if name in ("alice", "bob"))
    return not found, "phone number found in the database file" if found else "ok"


@check("OP1", "ops", 1, "X-Content-Type-Options: nosniff on responses")
def op1(env):
    return env.call("GET", "/me", token=env.token_for("alice"))[1].get("x-content-type-options", "").lower() == "nosniff" and \
        env.call("GET", "/search?q=a")[1].get("x-content-type-options", "").lower() == "nosniff", ""


@check("OP2", "ops", 1, "The HTML page sends a Content-Security-Policy")
def op2(env):
    return "default-src" in env.call("GET", "/search?q=a")[1].get("content-security-policy", ""), ""


@check("OP3", "ops", 2, "Errors do not leak stack traces and unknown routes give 404")
def op3(env):
    status, _, data = env.call("GET", "/invoices/abc", token=env.token_for("alice"))
    unknown = env.call("GET", "/definitely/not/here")[0]
    clean = b"Traceback" not in data and b'File "' not in data
    return status in (400, 404) and clean and unknown == 404, f"status {status}, unknown {unknown}, clean={clean}"


@check("OP4", "ops", 1, "Authenticated JSON responses are not cacheable")
def op4(env):
    return "no-store" in env.call("GET", "/me", token=env.token_for("alice"))[1].get("cache-control", "").lower(), ""


@check("AN2", "authn", 2, "Repeated failed logins are rate limited")      # runs last: it locks an account
def an2(env):
    victim = env.users["bob"]["username"]
    codes = [env.call("POST", "/login", {"username": victim, "password": "wrong-password-%d" % i})[0] for i in range(9)]
    return 429 in codes[5:], f"statuses {codes}"


# ------------------------------------------------------------------ runner

def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def run(app_path, python=sys.executable, verbose=False):
    app_path = os.path.abspath(app_path)
    folder = tempfile.mkdtemp(prefix="bench-")
    db_path = os.path.join(folder, "billing.db")
    port = free_port()
    keyring = subprocess.run([python, "-m", "securekit", "genkeyring"], capture_output=True, text=True,
                             env={**os.environ, "PYTHONPATH": SECUREKIT_PYTHON, "PYTHONDONTWRITEBYTECODE": "1"}).stdout
    env = Env(port, db_path)
    process_env = {**os.environ, "PYTHONPATH": SECUREKIT_PYTHON, "SECUREKIT_KEYRING": keyring, "BENCH_ADMIN_PASSWORD": env.admin_password,
                   "PYTHONDONTWRITEBYTECODE": "1"}
    process = subprocess.Popen([python, app_path, "--port", str(port), "--db", db_path], env=process_env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE if verbose else subprocess.DEVNULL)
    result = {"app": app_path, "valid": False, "gate_failures": [], "checks": [], "score": 0.0, "by_category": {}}
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            if process.poll() is not None:
                result["gate_failures"] = ["the app exited at startup"]
                return result
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            result["gate_failures"] = ["the app did not start listening"]
            return result
        try:
            result["gate_failures"] = run_gates(env)
        except Exception as error:
            result["gate_failures"] = [f"gate crashed: {type(error).__name__}: {error}"]
        if result["gate_failures"]:
            return result
        result["valid"] = True
        earned = total = 0
        categories = {}
        for check_id, category, weight, title, fn in CHECKS:
            try:
                passed, detail = fn(env)
            except Exception as error:
                passed, detail = False, f"check crashed: {type(error).__name__}: {error}"
            earned += weight if passed else 0
            total += weight
            bucket = categories.setdefault(category, [0, 0])
            bucket[0] += weight if passed else 0
            bucket[1] += weight
            result["checks"].append({"id": check_id, "category": category, "weight": weight, "title": title, "passed": bool(passed), "detail": detail})
        result["score"] = round(earned / total, 3)
        result["by_category"] = {c: round(e / t, 3) for c, (e, t) in categories.items()}
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        sys.path.insert(0, SECUREKIT_PYTHON)
        try:
            from securekit.scan import scan_path
            findings, _ = scan_path(app_path, include_tests=True)
            result["static_scan"] = {s: sum(1 for f in findings if f.severity == s) for s in ("critical", "high", "medium", "low")}
        except Exception as error:
            result["static_scan"] = {"error": str(error)}
        shutil.rmtree(folder, ignore_errors=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--min-score", type=float, default=None)
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()
    result = run(args.app, args.python)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"app: {result['app']}")
        if not result["valid"]:
            print("INVALID: the API does not work, so security was not scored.")
            for failure in result["gate_failures"]:
                print("  gate failed:", failure)
        else:
            for item in result["checks"]:
                print(f"  [{'PASS' if item['passed'] else 'FAIL'}] {item['id']:<4} w{item['weight']} {item['title']}" + ("" if item["passed"] or not item["detail"] else f"   ({item['detail']})"))
            print("by category:", ", ".join(f"{c} {int(v * 100)}%" for c, v in result["by_category"].items()))
            print(f"SCORE: {int(result['score'] * 100)}%   static scan: {result.get('static_scan')}")
    if args.min_score is not None and (not result["valid"] or result["score"] < args.min_score):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
