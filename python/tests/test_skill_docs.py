import glob
import os
import re
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SKILLS = os.path.join(ROOT, "skills")
SECURE_APP = os.path.join(SKILLS, "secure-app")
OUTPUT_FILES = {"docs/threat-model.md", "docs/security-requirements.md"}      # files the skill tells an agent to create in the user's project


def markdown_files():
    return sorted(glob.glob(os.path.join(SKILLS, "**", "*.md"), recursive=True))


def runnable_blocks():
    for path in markdown_files():
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for index, block in enumerate(re.findall(r"```python\n(# runnable\n.*?)```", text, re.S), start=1):
            yield os.path.relpath(path, ROOT), index, block


class SkillDocsTests(unittest.TestCase):
    def test_runnable_examples_run(self):
        count = 0
        for path, index, block in runnable_blocks():
            with self.subTest(file=path, block=index):
                exec(compile(block, f"{path}#{index}", "exec"), {"__name__": "__skill_example__"})   # securekit-ignore: unsafe-eval (runs our own documentation examples)
            count += 1
        self.assertGreaterEqual(count, 10, "the reference docs should keep their runnable examples")

    def test_frontmatter_of_every_skill(self):
        for skill in glob.glob(os.path.join(SKILLS, "*", "SKILL.md")):
            folder = os.path.basename(os.path.dirname(skill))
            with open(skill, encoding="utf-8") as handle:
                text = handle.read()
            front = re.match(r"---\n(.*?)\n---\n", text, re.S)
            self.assertIsNotNone(front, skill)
            name = re.search(r"^name:\s*(.+)$", front.group(1), re.M).group(1).strip()
            description = re.search(r"^description:\s*(.+)$", front.group(1), re.M).group(1).strip()
            self.assertEqual(name, folder)
            self.assertLessEqual(len(description), 1024, f"{folder} description is {len(description)} characters")
            self.assertGreater(len(description), 150, "the description is what makes the skill trigger; keep it specific")

    def test_file_references_resolve(self):
        pattern = re.compile(r"`((?:\.\./|\./)*(?:[\w.-]+/)+[\w.-]+\.(?:md|py|json))`|\]\(((?:\.\./|\./)*[\w./-]+\.(?:md|py|json))\)")
        unresolved = []
        for path in markdown_files():
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            here = os.path.dirname(path)
            for match in pattern.finditer(text):
                reference = match.group(1) or match.group(2)
                if "<" in reference or reference in OUTPUT_FILES:
                    continue
                candidates = [os.path.join(here, reference), os.path.join(SECURE_APP, reference), os.path.join(ROOT, reference), os.path.join(SKILLS, reference)]
                if not any(os.path.exists(c) for c in candidates):
                    unresolved.append((os.path.relpath(path, ROOT), reference))
        self.assertEqual(unresolved, [])

    def test_router_lists_every_reference_and_template(self):
        with open(os.path.join(SECURE_APP, "SKILL.md"), encoding="utf-8") as handle:
            router = handle.read()
        references = sorted(glob.glob(os.path.join(SECURE_APP, "references", "*.md")))
        self.assertEqual(len(references), 8)
        for reference in references:
            number = os.path.basename(reference).split("-")[0]
            self.assertTrue(re.search(rf"\b{number}\b", router), f"the router never mentions reference {number}")
        for template in ("threat-model.md", "security-requirements.md", "SECURITY.md", "authz_matrix.py"):
            self.assertTrue(os.path.exists(os.path.join(SECURE_APP, "templates", template)), template)
            self.assertIn(os.path.splitext(template)[0], router)

    def test_gate_rows_are_unique_and_complete(self):
        with open(os.path.join(SECURE_APP, "references", "08-gate.md"), encoding="utf-8") as handle:
            ids = re.findall(r"^\| (G\d+) \|", handle.read(), re.M)
        self.assertEqual(len(ids), len(set(ids)), "duplicate gate ids")
        self.assertEqual(sorted(ids, key=lambda i: int(i[1:])), [f"G{n}" for n in range(1, 33)])


if __name__ == "__main__":
    unittest.main()
