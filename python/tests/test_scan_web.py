import unittest

from securekit.scan import scan_text

# rule id -> (lines that must be flagged, lines that look similar and must not be)
CASES = {
    "sql-injection": (
        ['cur.execute(f"SELECT * FROM invoices WHERE id = {invoice_id}")',
         'cur.execute("SELECT * FROM t WHERE name = \'%s\'" % name)',
         'cur.execute("SELECT * FROM t WHERE a = " + a)',
         'cur.execute("SELECT * FROM t WHERE a = {}".format(a))',
         "db.query(`SELECT * FROM users WHERE id = ${id}`)",
         'db.query("SELECT * FROM users WHERE id = " + id)'],
        ['cur.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,))',
         'cur.execute("SELECT * FROM t WHERE a = %s", (a,))',
         'db.query("SELECT * FROM users WHERE id = $1", [id])',
         'print("SELECT " + name)'],
    ),
    "command-injection": (
        ["subprocess.run(cmd, shell=True)", "os.system('ls ' + path)", "exec(`ls ${dir}`)", "execSync('git log ' + ref)"],
        ["subprocess.run(['ls', path])", "execFile('ls', [dir])", "regex.exec(text)"],
    ),
    "unsafe-eval": (
        ["result = eval(expression)", "const f = new Function('a', body)", "exec(code)"],
        ["value = ast.literal_eval(text)", "const m = pattern.exec(text)", "evaluate(x)"],
    ),
    "unsafe-deserialization": (
        ["obj = pickle.loads(blob)", "cfg = yaml.load(text)", "marshal.loads(b)"],
        ["cfg = yaml.safe_load(text)", "cfg = yaml.load(text, Loader=yaml.SafeLoader)", "data = json.loads(text)"],
    ),
    "xss-sink": (
        ["el.innerHTML = userComment", "el.innerHTML += row", "<div dangerouslySetInnerHTML={{__html: x}} />", "{{ comment | safe }}", "return mark_safe(text)"],
        ["el.textContent = userComment", "el.innerHTML = ''", "el.innerHTML = \"\""],
    ),
    "debug-enabled": (["app.run(debug=True)", "DEBUG = True"], ["app.run(debug=settings.debug)", "DEBUG = os.environ.get('DEBUG') == '1'"]),
    "cors-wildcard": (['res.setHeader("Access-Control-Allow-Origin", "*")', "app.use(cors())", "allow_origins=['*']"], ['res.setHeader("Access-Control-Allow-Origin", origin)']),
    "path-traversal": (["return send_file(request.args['name'])", "fs.readFileSync(req.query.file)"], ["return send_file(path_for(invoice_id))"]),
    "ssrf": (["r = requests.get(request.args['url'])", "const r = await fetch(req.body.url)"], ["r = requests.get(PARTNER_URL)"]),
    "open-redirect": (["return redirect(request.args['next'])", "res.redirect(req.query.next)"], ["return redirect(url_for('home'))"]),
    "csrf-disabled": (["@csrf_exempt", "WTF_CSRF_ENABLED = False"], ["WTF_CSRF_ENABLED = True"]),
    "framework-secret-key": (
        ['SECRET_KEY = "dev-key-please-change"', "app.config['SECRET_KEY'] = 'my-session-secret'", 'JWT_SECRET: "abcdef123456"'],
        ['SECRET_KEY = os.environ["SECRET_KEY"]', 'SECRET_KEY = "changeme"', 'SECRET_KEY = ""'],
    ),
    "secret-in-url": (['url = "https://api.example.org/export?token=" + t', 'link = f"/reset?password={p}"'], ['url = "https://api.example.org/export"']),
    "non-constant-time-compare": (
        ["if token == expected_token:", "if request_signature != computed:", "ok = api_key === stored"],
        ["if token is None:", "if token == None:", "if token_type == 'bearer':", "if len(token) == 32:", "if secret == null"],
    ),
    "world-writable": (["os.chmod(path, 0o777)", "chmod -R 777 /var/app"], ["os.chmod(path, 0o600)"]),
    "default-credentials": (['create_user("admin", "admin")', 'DEFAULT_LOGIN = "admin:admin"'], ['create_user("admin", generated_password)', '{"username": "admin", "password": secret_value}', 'creds = {"user": "admin", "password": "REPLACE_me_please"}']),
}


class WebRuleTests(unittest.TestCase):
    def found(self, line, path="src/app.py"):
        return {f.rule for f in scan_text(path, line)}

    def test_every_rule_flags_its_examples_and_ignores_lookalikes(self):
        for rule, (bad, good) in CASES.items():
            for line in bad:
                with self.subTest(rule=rule, flagged=line):
                    path = "web/page.html" if rule == "xss-sink" and "{{" in line else "src/app.js" if any(t in line for t in ("const ", "res.", "app.use", "fs.", "el.", "db.query", "execSync", "exec(`", "new Function", "===", "execFile")) else "src/app.py"
                    self.assertIn(rule, self.found(line, path), line)
            for line in good:
                with self.subTest(rule=rule, quiet=line):
                    path = "src/app.js" if any(t in line for t in ("const ", "res.", "fs.", "el.", "db.query", "execFile", "null")) else "src/app.py"
                    self.assertNotIn(rule, self.found(line, path), line)

    def test_secret_key_value_is_masked(self):
        finding = next(f for f in scan_text("src/app.py", 'SECRET_KEY = "dev-key-please-change"') if f.rule == "framework-secret-key")
        self.assertNotIn("dev-key-please-change", finding.snippet)

    def test_debug_and_secret_key_rules_skip_test_files(self):
        self.assertEqual({f.rule for f in scan_text("tests/test_app.py", "DEBUG = True\nSECRET_KEY = 'test-secret-key'")}, set())

    def test_comments_do_not_trigger_code_rules(self):
        self.assertEqual(scan_text("src/app.py", "# cur.execute(f'SELECT {x}')  was removed"), [])


if __name__ == "__main__":
    unittest.main()
