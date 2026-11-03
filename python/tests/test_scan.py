import json
import os
import subprocess
import sys
import tempfile
import unittest

from securekit.scan import SEVERITIES, scan_path, scan_text

PYTHON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

# Sample secrets are assembled at run time so this file does not itself look like a leak.
AWS = "AKIA" + "QYLPMN5HHHFPZAM2"   # made up; the documented AWS sample key contains the word EXAMPLE and is deliberately ignored
GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
PASSWORD = "Tr0ub4dor" + "&3-realish"
PRIVATE_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----"


def rules(findings):
    return {f.rule for f in findings}


class ScanTextTests(unittest.TestCase):
    def test_secrets_are_found_and_never_printed_in_full(self):
        text = "\n".join([f'aws = "{AWS}"', f"token = '{GITHUB}'", f'STRIPE = "{STRIPE}"', f'password = "{PASSWORD}"', PRIVATE_KEY])
        found = scan_text("src/config.py", text)
        self.assertEqual(rules(found), {"aws-access-key", "token-literal", "hardcoded-secret", "private-key"})
        shown = "\n".join(f.snippet for f in found)
        for secret in (AWS, GITHUB, STRIPE, PASSWORD):
            self.assertNotIn(secret, shown)

    def test_placeholders_and_environment_reads_are_not_flagged(self):
        text = "\n".join([
            'password = "changeme"', 'api_key = "your-api-key-here"', 'secret = os.environ["SECRET"]', 'token = "${TOKEN}"',
            'password = "<password>"', 'password = "REPLACE_with_real_value"', 'password = process.env.DB_PASSWORD', 'secret = "xxxxxxxxxxxx"', 'password = ""',
        ])
        self.assertEqual(scan_text("src/config.py", text), [])

    def test_crypto_and_tls_misuse(self):
        cases = {
            "weak-hash": "digest = hashlib.md5(data).hexdigest()",
            "fast-password-hash": "stored = hashlib.sha256(password.encode()).hexdigest()",
            "broken-cipher": "cipher = AES.new(key, AES.MODE_ECB)",
            "unauthenticated-cipher": "cipher = AES.new(key, AES.MODE_CBC, iv)",
            "weak-random": "reset_token = str(random.randint(0, 999999))",
            "tls-verification-off": "requests.get(url, verify=False)",
            "jwt-unsafe": 'jwt.decode(token, options={"verify_signature": False})',
            "insecure-cookie": "response.set_cookie('sid', sid, secure=False)",
            "cleartext-http": 'API = "http://api.partner-service.com/v1"',
            "sensitive-logging": 'logger.info("login with password %s", password)',
        }
        for rule, line in cases.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, rules(scan_text("src/app.py", line)), line)

    def test_safe_lookalikes_are_quiet(self):
        text = "\n".join([
            "digest = hashlib.sha256(data).hexdigest()", "n = random.randint(1, 6)  # dice", "requests.get(url, verify=True)",
            'URL = "http://localhost:8000/health"', 'NS = "http://www.w3.org/2000/svg"', "cipher = AESGCM(key)",
        ])
        self.assertEqual(scan_text("src/app.py", text), [])

    def test_unencrypted_storage_places(self):
        sql = scan_text("db/schema.sql", "CREATE TABLE users (\n  ssn VARCHAR(11),\n  credit_card TEXT\n);")
        self.assertEqual([f.rule for f in sql], ["plaintext-sensitive-column"] * 2)
        orm = scan_text("app/models.py", "    ssn = Column(String(11))\n    token_hint = Column(String)\n    iban: Mapped[str] = mapped_column(String(34))")
        self.assertEqual({f.line for f in orm}, {1, 3})
        safe = scan_text("app/models.py", "    ssn = Column(EncryptedText)\n    iban: Mapped[str] = mapped_column(EncryptedText)")
        self.assertEqual(safe, [])
        self.assertIn("browser-token-storage", rules(scan_text("web/app.js", "localStorage.setItem('access_token', t)")))
        self.assertIn("k8s-secret-manifest", rules(scan_text("deploy/secret.yaml", "apiVersion: v1\nkind: Secret\ndata:\n  a: Yg==")))

    def test_env_files_and_dockerfiles(self):
        self.assertIn("env-file-secret", rules(scan_text(".env", f"DB_PASSWORD={PASSWORD}\nDEBUG=1")))
        self.assertEqual(scan_text(".env.example", f"DB_PASSWORD={PASSWORD}"), [])
        self.assertEqual(scan_text(".env", "DB_PASSWORD=\nAPI_TOKEN=changeme"), [])
        self.assertIn("dockerfile-secret", rules(scan_text("Dockerfile", f"ENV API_TOKEN={PASSWORD}")))
        self.assertEqual(scan_text("Dockerfile", "ENV NODE_ENV=production"), [])

    def test_inline_ignores(self):
        line = f'password = "{PASSWORD}"'
        self.assertEqual(scan_text("src/a.py", f"{line}  # securekit-ignore"), [])
        self.assertEqual(scan_text("src/a.py", f"{line}  # securekit-ignore: hardcoded-secret"), [])
        self.assertTrue(scan_text("src/a.py", f"{line}  # securekit-ignore: weak-hash"))

    def test_test_directories_are_skipped_for_noisy_rules_unless_asked(self):
        line = f'password = "{PASSWORD}"'
        self.assertEqual(scan_text("tests/test_login.py", line), [])
        self.assertTrue(scan_text("tests/test_login.py", line, include_tests=True))
        self.assertIn("private-key", rules(scan_text("tests/keys.py", PRIVATE_KEY)))   # real keys matter everywhere

    def test_logging_rule_looks_at_code_not_prose(self):
        flagged = [
            'logger.info("login with password %s", password)',
            'print(f"decrypted: {decrypted_ssn}")',
            "console.log(`token is ${accessToken}`)",
            "console.log('auth', req.headers.authorization)",
        ]
        for line in flagged:
            with self.subTest(line=line):
                self.assertIn("sensitive-logging", rules(scan_text("src/app.py", line)), line)
        quiet = [
            'print("ok: every secret decrypts")',
            'logger.info("rotating the api key for the vendor")',
            "console.log(`ok: ${flags.deep ? ' and every secret decrypt' : ''} verified`)",
            'print("copying Alice\'s encrypted SSN into Bob\'s row")',
        ]
        for line in quiet:
            with self.subTest(line=line):
                self.assertNotIn("sensitive-logging", rules(scan_text("src/app.py", line)), line)
        self.assertNotIn("fast-password-hash", rules(scan_text("src/kdf.py", "    U_2 = HMAC-SHA256(Password, U_1)")))

    def test_comments_are_quiet_for_crypto_rules_but_not_for_secrets(self):
        self.assertEqual(scan_text("src/a.py", "# old: hashlib.md5(data)\n// verify=False\n * DES is broken"), [])
        self.assertIn("aws-access-key", rules(scan_text("src/a.py", f"# aws = {AWS}")))

    def test_docs_only_get_the_secret_rules(self):
        self.assertEqual(scan_text("README.md", "We used hashlib.md5(x) and verify=False in an example"), [])
        self.assertIn("aws-access-key", rules(scan_text("README.md", f"export KEY={AWS}")))


class ScanPathTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = self.dir.name

    def write(self, relative, content, binary=False):
        path = os.path.join(self.root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb" if binary else "w") as handle:
            handle.write(content)

    def test_walk_skips_vendored_binary_huge_and_ignored_files(self):
        self.write("src/app.py", f'aws = "{AWS}"\n')
        self.write("node_modules/dep/index.js", f'aws = "{AWS}"\n')
        self.write(".git/config", f'aws = "{AWS}"\n')
        self.write("assets/logo.bin", b"\x00\x01" + AWS.encode(), binary=True)
        self.write("big.py", "x = 1\n" * 300_000 + f'aws = "{AWS}"\n')
        self.write("generated/out.py", f'aws = "{AWS}"\n')
        self.write(".securekitignore", "# generated code\ngenerated/\n")
        findings, scanned = scan_path(self.root)
        self.assertEqual([(f.path, f.rule) for f in findings], [(os.path.join("src", "app.py"), "aws-access-key")])
        self.assertGreaterEqual(scanned, 2)

    def test_findings_are_sorted_by_severity(self):
        self.write("a.py", f'x = hashlib.md5(d)\naws = "{AWS}"\n')
        findings, _ = scan_path(self.root)
        self.assertEqual([f.severity for f in findings], ["high", "medium"])

    def test_cli_report_json_and_exit_codes(self):
        self.write("src/app.py", f'aws = "{AWS}"\nx = hashlib.md5(d)\n')
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}

        def run(*args):
            return subprocess.run([sys.executable, "-m", "securekit", "scan", self.root, *args], capture_output=True, text=True, cwd=PYTHON_DIR, env=env, timeout=60)

        report = run()
        self.assertEqual(report.returncode, 1)                       # default --fail-on high
        self.assertIn("aws-access-key", report.stdout)
        self.assertNotIn(AWS, report.stdout + report.stderr)
        as_json = json.loads(run("--json", "--fail-on", "never").stdout)
        self.assertEqual(as_json["summary"]["high"], 1)
        self.assertEqual(as_json["summary"]["medium"], 1)
        self.assertNotIn(AWS, json.dumps(as_json))
        self.assertEqual(run("--fail-on", "never").returncode, 0)
        self.assertEqual(run("--fail-on", "critical").returncode, 0)
        self.assertEqual(run("--fail-on", "medium").returncode, 1)
        self.assertEqual(subprocess.run([sys.executable, "-m", "securekit", "scan", os.path.join(self.root, "missing")],
                                        capture_output=True, cwd=PYTHON_DIR, env=env, timeout=60).returncode, 2)

        clean_dir = tempfile.TemporaryDirectory()
        self.addCleanup(clean_dir.cleanup)
        with open(os.path.join(clean_dir.name, "ok.py"), "w") as handle:
            handle.write("print('hello')\n")
        clean = subprocess.run([sys.executable, "-m", "securekit", "scan", clean_dir.name], capture_output=True, text=True, cwd=PYTHON_DIR, env=env, timeout=60)
        self.assertEqual(clean.returncode, 0)
        self.assertIn("not proof", clean.stdout)

    def test_severity_names_are_ordered(self):
        self.assertEqual(SEVERITIES, ["low", "medium", "high", "critical"])


if __name__ == "__main__":
    unittest.main()
