"""
Reference implementation of scenarios/billing-api.md: what a secure answer looks like.
Standard library plus securekit. Binds to 127.0.0.1 only.

    PYTHONPATH=securekit/python SECUREKIT_KEYRING="$(python -m securekit genkeyring)" \
        python reference_app.py --port 8080 --db billing.db
"""

import argparse
import html
import json
import os
import re
import sqlite3
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from securekit import BlindIndexer, FieldCipher, Keyring, context, hash_password, random_token, verify_password

MAX_BODY = 1_048_576
USERNAME = re.compile(r"[a-z0-9_]{3,32}\Z")
LOGIN_WINDOW_SECONDS, LOGIN_MAX_FAILURES = 60, 5
SESSION_SECONDS = 8 * 3600


class HttpError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


class App:
    def __init__(self, db_path, keyring):
        self.db_path = db_path
        self.cipher, self.blind = FieldCipher(keyring), BlindIndexer(keyring)
        self.failures = defaultdict(deque)
        self.lock = threading.Lock()
        self.dummy_hash = hash_password("a-password-nobody-has")   # equalizes timing for unknown usernames
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
                                                  role TEXT NOT NULL, phone_enc TEXT);
                CREATE TABLE IF NOT EXISTS sessions (token_idx TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS invoices (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id TEXT NOT NULL,
                                                     customer TEXT NOT NULL, amount REAL NOT NULL, note TEXT);
            """)
        admin_password = os.environ.get("BENCH_ADMIN_PASSWORD")
        if admin_password:
            self.create_user("admin", admin_password, None, "admin", ignore_duplicate=True)

    def connect(self):
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    # ---------------------------------------------------------------- users and sessions

    def create_user(self, username, password, phone, role="user", ignore_duplicate=False):
        user_id = str(uuid.uuid4())                  # exists before encrypting: it is bound into the ciphertext
        phone_enc = self.cipher.encrypt(phone, context("users", "phone", user_id)) if phone else None
        try:
            with self.connect() as db:
                db.execute("INSERT INTO users (id, username, password_hash, role, phone_enc) VALUES (?, ?, ?, ?, ?)",
                           (user_id, username, hash_password(password), role, phone_enc))
        except sqlite3.IntegrityError:
            if ignore_duplicate:
                return None
            raise HttpError(409, "username taken")
        return user_id

    def login(self, username, password):
        now = time.monotonic()
        with self.lock:
            recent = self.failures[username]
            while recent and now - recent[0] > LOGIN_WINDOW_SECONDS:
                recent.popleft()
            if len(recent) >= LOGIN_MAX_FAILURES:
                raise HttpError(429, "too many attempts, try again later")
            if len(self.failures) > 10_000:
                self.failures = defaultdict(deque, {k: v for k, v in self.failures.items() if v})
        with self.connect() as db:
            row = db.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        valid = verify_password(password, row["password_hash"] if row else self.dummy_hash) and row is not None
        if not valid:
            with self.lock:
                self.failures[username].append(now)
            raise HttpError(401, "invalid credentials")        # identical for unknown user and wrong password
        token = random_token(32)
        with self.connect() as db:
            db.execute("INSERT INTO sessions (token_idx, user_id, expires) VALUES (?, ?, ?)",
                       (self.blind.index(token, context("sessions", "token"), mode="exact"), row["id"], time.time() + SESSION_SECONDS))
        return token

    def authenticate(self, headers):
        header = headers.get("Authorization", "")
        if not header.startswith("Bearer ") or not 20 <= len(header) <= 200:
            raise HttpError(401, "authentication required")
        candidates = self.blind.candidates(header[7:], context("sessions", "token"), mode="exact")
        with self.connect() as db:
            row = db.execute(
                f"SELECT users.id, users.username, users.role, users.phone_enc FROM sessions JOIN users ON users.id = sessions.user_id "
                f"WHERE sessions.token_idx IN ({','.join('?' * len(candidates))}) AND sessions.expires > ?",
                (*candidates, time.time())).fetchone()
        if row is None:
            raise HttpError(401, "authentication required")
        return dict(row)

    # ---------------------------------------------------------------- routes

    def handle(self, method, url, headers, body):
        path, query = url.path, parse_qs(url.query)
        if method == "POST" and path == "/register":
            data = require_object(body)
            username, password, phone = data.get("username"), data.get("password"), data.get("phone")
            if not isinstance(username, str) or not USERNAME.match(username):
                raise HttpError(400, "username must be 3-32 characters of a-z, 0-9 or _")
            if not isinstance(password, str) or not 10 <= len(password) <= 128:
                raise HttpError(400, "password must be 10-128 characters")
            if phone is not None and (not isinstance(phone, str) or len(phone) > 32):
                raise HttpError(400, "phone must be a string of at most 32 characters")
            return 201, {"id": self.create_user(username, password, phone)}          # role is never taken from the request
        if method == "POST" and path == "/login":
            data = require_object(body)
            if not isinstance(data.get("username"), str) or not isinstance(data.get("password"), str):
                raise HttpError(400, "username and password are required")
            return 200, {"token": self.login(data["username"], data["password"])}
        if method == "GET" and path == "/search":                                      # public, returns HTML
            term = (query.get("q") or [""])[0][:200]
            return 200, ("<!doctype html><meta charset=utf-8><title>Search</title><p>Results for " + html.escape(term) + "</p>", "text/html")

        if (method, path) not in {("GET", "/me"), ("POST", "/invoices"), ("GET", "/invoices"), ("GET", "/admin/users")} \
                and not (method == "GET" and re.fullmatch(r"/invoices/(\d{1,18})", path)):
            raise HttpError(404, "not found")                                          # unknown routes are 404 for everyone
        user = self.authenticate(headers)
        if method == "GET" and path == "/me":
            phone = self.cipher.decrypt_str(user["phone_enc"], context("users", "phone", user["id"])) if user["phone_enc"] else None
            return 200, {"username": user["username"], "role": user["role"], "phone": phone}
        if method == "POST" and path == "/invoices":
            data = require_object(body)
            customer, amount, note = data.get("customer"), data.get("amount"), data.get("note")
            if not isinstance(customer, str) or not 1 <= len(customer) <= 100:
                raise HttpError(400, "customer must be 1-100 characters")
            if isinstance(amount, bool) or not isinstance(amount, (int, float)) or not 0 < amount < 1e9:
                raise HttpError(400, "amount must be a positive number")
            if note is not None and (not isinstance(note, str) or len(note) > 500):
                raise HttpError(400, "note must be a string of at most 500 characters")
            with self.connect() as db:
                cursor = db.execute("INSERT INTO invoices (owner_id, customer, amount, note) VALUES (?, ?, ?, ?)", (user["id"], customer, amount, note))
            return 201, {"id": cursor.lastrowid}
        if method == "GET" and path == "/invoices":
            term = (query.get("q") or [""])[0][:100]
            pattern = "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            with self.connect() as db:
                rows = db.execute("SELECT id, customer, amount, note FROM invoices WHERE owner_id = ? AND customer LIKE ? ESCAPE '\\' ORDER BY id",
                                  (user["id"], pattern)).fetchall()
            return 200, [dict(r) for r in rows]
        match = re.fullmatch(r"/invoices/(\d{1,18})", path)
        if method == "GET" and match:
            with self.connect() as db:
                row = db.execute("SELECT id, customer, amount, note FROM invoices WHERE id = ? AND (owner_id = ? OR ?)",
                                 (int(match.group(1)), user["id"], 1 if user["role"] == "admin" else 0)).fetchone()
            if row is None:
                raise HttpError(404, "not found")                                   # same answer for "missing" and "not yours"
            return 200, dict(row)
        if method == "GET" and path == "/admin/users":
            if user["role"] != "admin":
                raise HttpError(403, "forbidden")
            with self.connect() as db:
                return 200, [dict(r) for r in db.execute("SELECT username, role FROM users ORDER BY username")]
        raise HttpError(404, "not found")


def require_object(body):
    if not isinstance(body, dict):
        raise HttpError(400, "a JSON object is required")
    return body


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "billing"
        sys_version = ""

        def log_message(self, *args):
            pass

        def send(self, status, payload, content_type="application/json"):
            data = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            if content_type == "text/html":
                self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            else:
                self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def respond(self, method):
            try:
                body = None
                if method == "POST":
                    length = int(self.headers.get("Content-Length") or 0)
                    if length > MAX_BODY:
                        self.close_connection = True
                        return self.send(413, {"error": "request too large"})
                    raw = self.rfile.read(length)
                    try:
                        body = json.loads(raw.decode("utf-8")) if raw else None
                    except (ValueError, UnicodeDecodeError):
                        raise HttpError(400, "invalid JSON")
                status, result = app.handle(method, urlparse(self.path), self.headers, body)
                if isinstance(result, tuple):
                    self.send(status, result[0], result[1])
                else:
                    self.send(status, result)
            except HttpError as error:
                self.send(error.status, {"error": error.message})
            except Exception:                                   # never show internals to the client
                print("internal error", file=sys.stderr)
                self.send(500, {"error": "internal error"})

        def do_GET(self):
            self.respond("GET")

        def do_POST(self):
            self.respond("POST")

        def do_PUT(self):
            self.send(405, {"error": "method not allowed"})

        do_DELETE = do_PATCH = do_PUT

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db", default="billing.db")
    args = parser.parse_args()
    app = App(args.db, Keyring.from_env())
    ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(app)).serve_forever()


if __name__ == "__main__":
    main()
