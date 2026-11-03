import importlib.util
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
SKILL = os.path.join(ROOT, "skills", "secure-app")
PYTHON_DIR = os.path.join(ROOT, "python")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AuthzMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = load("authz_matrix", os.path.join(SKILL, "templates", "authz_matrix.py"))
        cls.bench = load("bench_score", os.path.join(SKILL, "benchmark", "score.py"))

    def serve(self, app, folder):
        port = self.bench.free_port()
        admin_password = "Admin-Pass-" + secrets.token_hex(6)
        keyring = subprocess.run([sys.executable, "-m", "securekit", "genkeyring"], capture_output=True, text=True, cwd=PYTHON_DIR,
                                 env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}).stdout
        process = subprocess.Popen([sys.executable, os.path.join(SKILL, "benchmark", "apps", app), "--port", str(port), "--db", os.path.join(folder, "db")],
                                   env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "python"), "SECUREKIT_KEYRING": keyring,
                                        "BENCH_ADMIN_PASSWORD": admin_password, "PYTHONDONTWRITEBYTECODE": "1"},
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                import socket
                socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
                break
            except OSError:
                time.sleep(0.1)
        return f"http://127.0.0.1:{port}", admin_password, process

    @staticmethod
    def _stop(process):
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def results_for(self, app):
        with tempfile.TemporaryDirectory() as folder:
            base, admin_password, process = self.serve(app, folder)
            try:
                password = "Correct-Horse-9-" + secrets.token_hex(3)
                suffix = secrets.token_hex(3)
                for name in ("alice", "bob"):
                    self.matrix.call(base, "POST", "/register", body={"username": f"{name}_{suffix}", "password": password, "phone": "000"})
                with open(os.path.join(SKILL, "templates", "authz_matrix.billing.json"), encoding="utf-8") as handle:
                    config = json.load(handle)
                config["users"]["alice"] = {"username": f"alice_{suffix}", "password": password}
                config["users"]["bob"] = {"username": f"bob_{suffix}", "password": password}
                config["users"]["admin"]["password"] = admin_password
                return {r["name"]: r["passed"] for r in self.matrix.run(base, config)}
            finally:
                self._stop(process)

    def test_the_reference_app_passes_every_case(self):
        results = self.results_for("reference_app.py")
        self.assertTrue(all(results.values()), [name for name, ok in results.items() if not ok])
        self.assertGreaterEqual(len(results), 9)

    def test_the_vulnerable_app_fails_exactly_the_access_control_cases(self):
        failed = {name for name, ok in self.results_for("vulnerable_app.py").items() if not ok}
        self.assertEqual(failed, {
            "anonymous cannot read an invoice",
            "another user cannot read it (IDOR)",
            "ordinary user cannot list users",
        })


if __name__ == "__main__":
    unittest.main()
