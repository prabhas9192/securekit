#!/usr/bin/env python3
"""
Authorization matrix tester: runs a table of "who may do what" against a running HTTP API and reports every case where the answer is wrong.

    python authz_matrix.py --base http://127.0.0.1:8080 --config authz_matrix.billing.json

The config lists users (with credentials), optional setup steps that create objects and remember their ids, and the cases to check:

    {"login": {"path": "/login", "user_field": "username", "pass_field": "password", "token_field": "token"},
     "users": {"alice": {"username": "alice1", "password": "..."}},
     "steps": [{"as": "alice", "method": "POST", "path": "/invoices", "json": {...}, "expect": [201], "save": {"alice_invoice": "id"}}],
     "cases": [{"name": "bob cannot read alice's invoice", "as": "bob", "method": "GET", "path": "/invoices/{alice_invoice}", "expect": [403, 404]}]}

`as` may be null for an anonymous request. `{name}` in a path is replaced with a saved value. Exit code 1 if any case fails.
Add one case per (user, route, object) combination the application has; a missing row is a missing test.
Standard library only.
"""

import argparse
import http.client
import json
import sys
from urllib.parse import urlparse


def call(base, method, path, token=None, body=None):
    parts = urlparse(base)
    connection = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=15)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        connection.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def run(base, config):
    login = config["login"]
    tokens, saved, results = {}, {}, []
    for name, credentials in config["users"].items():
        status, data = call(base, "POST", login["path"], body={login["user_field"]: credentials["username"], login["pass_field"]: credentials["password"]})
        try:
            tokens[name] = json.loads(data)[login["token_field"]] if status == 200 else None
        except (ValueError, KeyError, TypeError):
            tokens[name] = None
        if not tokens[name]:
            results.append({"name": f"log in as {name}", "passed": False, "detail": f"login returned {status}"})

    def resolve(text):
        for key, value in saved.items():
            text = text.replace("{" + key + "}", str(value))
        return text

    for step in config.get("steps", []):
        status, data = call(base, step["method"], resolve(step["path"]), tokens.get(step["as"]) if step.get("as") else None, step.get("json"))
        ok = status in step.get("expect", [200, 201])
        if ok and step.get("save"):
            parsed = json.loads(result = data)
            for key, field in step["save"].items():
                saved[key] = parsed[field]
        results.append({"name": "setup: " + step.get("name", step["path"]), "passed": ok, "detail": f"status {status}"})

    for case in config["cases"]:
        user = case.get("as")
        status, data = call(base, case["method"], resolve(case["path"]), tokens.get(user) if user else None, case.get("json"))
        passed = status in case["expect"]
        detail = f"status {status}, expected one of {case['expect']}"
        for marker in case.get("must_not_contain", []):
            if resolve(marker).encode() in data:
                passed, detail = False, f"response leaked {resolve(marker)!r}"
        results.append({"name": case["name"], "passed": passed, "detail": detail})
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    with open(args.config, encoding="utf-8") as handle:
        results = run(args.base, json.load(handle))
    for item in results:
        print(f"[{'PASS' if item['passed'] else 'FAIL'}] {item['name']}" + ("" if item["passed"] else f"   ({item['detail']})"))
    failed = [r for r in results if not r["passed"]]
    print(f"{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
