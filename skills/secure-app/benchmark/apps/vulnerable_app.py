"""
!!! INTENTIONALLY VULNERABLE !!! Benchmark fixture only. Never deploy, never copy patterns from it.

Implements scenarios/billing-api.md with the classic mistakes planted so the scorer has something to catch.
Binds to 127.0.0.1 only. Standard library only.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


def md5(text):
    return hashlib.md5(text.encode()).hexdigest()


class App:
    def __init__(self, db_path):
        self.db_path = db_path
        db = self.connect()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, role TEXT, phone TEXT);
            CREATE TABLE IF NOT EXISTS sessions (token TEXT, user_id INTEGER);
            CREATE TABLE IF NOT EXISTS invoices (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER, customer TEXT, amount REAL, note TEXT);
        """)
        admin_password = os.environ.get("BENCH_ADMIN_PASSWORD")
        if admin_password and not db.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
            db.execute("INSERT INTO users (username, password_hash, role, phone) VALUES ('admin', ?, 'admin', NULL)", (md5(admin_password),))
        db.commit()

    def connect(self):
        return sqlite3.connect(self.db_path)

    def user_from(self, headers):
        token = headers.get("Authorization", "").replace("Bearer ", "")
        row = self.connect().execute("SELECT users.id, users.username, users.role, users.phone FROM sessions JOIN users ON users.id = sessions.user_id "
                                     "WHERE token = '%s'" % token).fetchone()
        return row

    def handle(self, method, url, headers, body):
        path, query = url.path, parse_qs(url.query)
        db = self.connect()
        if method == "POST" and path == "/register":
            data = json.loads(body)
            try:
                db.execute("INSERT INTO users (username, password_hash, role, phone) VALUES (?, ?, ?, ?)",
                           (data["username"], md5(data["password"]), data.get("role", "user"), data.get("phone")))     # takes the role from the request
                db.commit()
            except sqlite3.IntegrityError:
                return 409, {"error": "username taken"}
            return 201, {"id": db.execute("SELECT id FROM users WHERE username=?", (data["username"],)).fetchone()[0]}
        if method == "POST" and path == "/login":
            data = json.loads(body)
            if not db.execute("SELECT 1 FROM users WHERE username='%s'" % data["username"]).fetchone():
                return 401, {"error": "unknown user"}
            row = db.execute("SELECT id FROM users WHERE username='%s' AND password_hash='%s'" % (data["username"], md5(data["password"]))).fetchone()
            if not row:
                return 401, {"error": "wrong password"}
            token = md5(data["username"])
            db.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, row[0]))
            db.commit()
            return 200, {"token": token}
        if method == "GET" and path == "/search":
            return 200, ("<html><body><p>Results for " + (query.get("q") or [""])[0] + "</p></body></html>", "text/html")
        match_id = path.startswith("/invoices/") and path[len("/invoices/"):]
        if match_id:                                                         # no authentication, no ownership check
            row = db.execute("SELECT id, customer, amount, note FROM invoices WHERE id=%d" % int(match_id)).fetchone()
            return (200, dict(zip(("id", "customer", "amount", "note"), row))) if row else (404, {"error": "not found"})

        user = self.user_from(headers)
        if not user:
            return 401, {"error": "authentication required"}
        if method == "GET" and path == "/me":
            return 200, {"username": user[1], "role": user[2], "phone": user[3]}
        if method == "POST" and path == "/invoices":
            data = json.loads(body)
            cursor = db.execute("INSERT INTO invoices (owner_id, customer, amount, note) VALUES (?, ?, ?, ?)",
                                (user[0], data["customer"], data["amount"], data.get("note")))
            db.commit()
            return 201, {"id": cursor.lastrowid}
        if method == "GET" and path == "/invoices":
            term = (query.get("q") or [""])[0]
            rows = db.execute("SELECT id, customer, amount, note FROM invoices WHERE owner_id=%d AND customer LIKE '%%%s%%'" % (user[0], term)).fetchall()
            return 200, [dict(zip(("id", "customer", "amount", "note"), r)) for r in rows]
        if method == "GET" and path == "/admin/users":                       # any logged-in user may list everyone
            return 200, [{"username": r[0], "role": r[1]} for r in db.execute("SELECT username, role FROM users")]
        return 404, {"error": "not found"}


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, method):
            try:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                status, result = app.handle(method, urlparse(self.path), self.headers, body)
            except Exception:
                status, result = 500, {"error": traceback.format_exc()}      # leaks internals
            payload, ctype = (result if isinstance(result, tuple) else (json.dumps(result), "application/json"))
            data = payload.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self.respond("GET")

        def do_POST(self):
            self.respond("POST")

    return Handler


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db", default="billing.db")
    args = parser.parse_args()
    HTTPServer(("127.0.0.1", args.port), make_handler(App(args.db))).serve_forever()
