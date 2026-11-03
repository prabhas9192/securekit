import importlib.util
import os
import sys
import tempfile
import unittest

BENCH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "skills", "secure-app", "benchmark")


def load_scorer():
    spec = importlib.util.spec_from_file_location("bench_score", os.path.join(BENCH, "score.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.score = load_scorer()

    def run_app(self, name):
        return self.score.run(os.path.join(BENCH, "apps", name))

    def test_the_reference_app_passes_everything(self):
        result = self.run_app("reference_app.py")
        self.assertTrue(result["valid"], result["gate_failures"])
        failed = [(c["id"], c["detail"]) for c in result["checks"] if not c["passed"]]
        self.assertEqual(failed, [])
        self.assertEqual(result["score"], 1.0)
        self.assertEqual(result["static_scan"], {"critical": 0, "high": 0, "medium": 0, "low": 0})

    def test_the_vulnerable_app_works_but_scores_low_and_is_flagged_statically(self):
        result = self.run_app("vulnerable_app.py")
        self.assertTrue(result["valid"], "the vulnerable app must still be a working API, or the benchmark proves nothing")
        self.assertLess(result["score"], 0.25)
        self.assertEqual(set(result["by_category"]), {"authn", "authz", "injection", "data", "ops"})
        for category in ("injection", "data", "ops"):
            self.assertEqual(result["by_category"][category], 0.0, category)
        self.assertGreaterEqual(result["static_scan"]["high"], 4)

    def test_each_planted_flaw_is_caught_by_its_own_check(self):
        failed = {c["id"] for c in self.run_app("vulnerable_app.py")["checks"] if not c["passed"]}
        planted = {"AN1", "AN3", "AN4", "AN5", "AN7", "AZ1", "AZ2", "AZ3", "AZ5", "IN1", "IN2", "IN3", "IN4", "DP1", "OP1", "OP2", "OP3", "OP4", "AN2"}
        self.assertEqual(planted - failed, set())

    def test_a_broken_api_is_invalid_not_secure(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "app.py")
            with open(path, "w") as handle:
                handle.write("import sys\nsys.exit(0)\n")                # starts and exits: no API
            result = self.score.run(path)
        self.assertFalse(result["valid"])
        self.assertEqual(result["score"], 0.0)
        self.assertTrue(result["gate_failures"])

    def test_an_app_that_answers_everything_with_403_is_invalid(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "app.py")
            with open(path, "w") as handle:
                handle.write(
                    "import argparse\nfrom http.server import BaseHTTPRequestHandler, HTTPServer\n"
                    "class H(BaseHTTPRequestHandler):\n"
                    "    def log_message(self, *a): pass\n"
                    "    def do_GET(self):\n        self.send_response(403); self.send_header('Content-Length','0'); self.end_headers()\n"
                    "    do_POST = do_GET\n"
                    "p = argparse.ArgumentParser(); p.add_argument('--port', type=int); p.add_argument('--db'); a = p.parse_args()\n"
                    "HTTPServer(('127.0.0.1', a.port), H).serve_forever()\n")
            result = self.score.run(path)
        self.assertFalse(result["valid"], "locking everything down must not count as secure")


if __name__ == "__main__":
    unittest.main()
