import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests.helpers import KEY_K1

PYTHON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.vault = os.path.join(self.dir.name, "v.json")
        self.env = {**os.environ, "SECUREKIT_KEYRING": json.dumps({"primary": "k1", "keys": {"k1": KEY_K1}}),
                    "SECUREKIT_VAULT": self.vault, "USER": "tester", "PYTHONDONTWRITEBYTECODE": "1"}

    def run_cli(self, *args, stdin=None, env=None):
        return subprocess.run([sys.executable, "-m", "securekit", *args], input=stdin, capture_output=True,
                              cwd=PYTHON_DIR, env=env or self.env, timeout=60)

    def test_full_workflow(self):
        self.assertEqual(self.run_cli("vault", "init").returncode, 0)
        put = self.run_cli("vault", "put", "db/password", stdin=b"hunter2-very-secret\n")
        self.assertEqual(put.returncode, 0, put.stderr)
        self.assertIn(b"version 1", put.stdout)
        self.assertNotIn(b"hunter2", put.stdout + put.stderr)

        got = self.run_cli("vault", "get", "db/password")
        self.assertEqual(got.stdout, b"hunter2-very-secret")         # trailing newline of the input was stripped
        self.assertEqual(self.run_cli("vault", "list").stdout.split(), [b"db/password"])
        self.assertIn(b"v1\tactive", self.run_cli("vault", "versions", "db/password").stdout)

        audit = self.run_cli("vault", "audit", "--json")
        self.assertEqual([e["action"] for e in json.loads(audit.stdout)], ["init", "put"])
        self.assertNotIn(b"hunter2", audit.stdout)
        self.assertEqual(json.loads(audit.stdout)[1]["actor"], "tester")

        self.assertIn(b"ok", self.run_cli("vault", "verify", "--deep").stdout)
        self.assertEqual(self.run_cli("vault", "rotate-keys").returncode, 0)
        self.assertEqual(self.run_cli("vault", "delete", "db/password").returncode, 0)
        self.assertEqual(self.run_cli("vault", "list").stdout, b"\n")

    def test_errors_have_exit_codes_and_do_not_leak(self):
        self.run_cli("vault", "init")
        missing = self.run_cli("vault", "get", "nope")
        self.assertEqual(missing.returncode, 1)
        self.assertIn(b"no active secret", missing.stderr)
        self.assertEqual(self.run_cli("vault", "put", "bad name", stdin=b"x").returncode, 2)
        self.assertEqual(self.run_cli("vault", "init").returncode, 1)                       # already exists

        no_file = {k: v for k, v in self.env.items() if k != "SECUREKIT_VAULT"}
        self.assertEqual(self.run_cli("vault", "list", env=no_file).returncode, 2)
        no_keys = {k: v for k, v in self.env.items() if k != "SECUREKIT_KEYRING"}
        self.assertEqual(self.run_cli("vault", "list", env=no_keys).returncode, 1)

        with open(self.vault, "a", encoding="utf-8") as handle:
            handle.write("tampered")
        self.assertEqual(self.run_cli("vault", "verify").returncode, 1)

    def test_key_generation(self):
        self.assertEqual(len(self.run_cli("genkey").stdout.strip()), 43)
        ring = json.loads(self.run_cli("genkeyring", "prod1").stdout)
        self.assertEqual(ring["primary"], "prod1")


if __name__ == "__main__":
    unittest.main()
