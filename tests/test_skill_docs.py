"""Structure checks for SKILL.md and its references: frontmatter, script and flag names, links, size."""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = ROOT / "auditing-infra-compliance"
SCRIPTS_DIR = SKILL_DIR / "scripts"
SKILL_MD = SKILL_DIR / "SKILL.md"
REFERENCES = ("vault-reading.md", "remediation-guidelines.md", "report-format.md", "drata-vanta.md")
CLI_SCRIPTS = ("vault_index", "collect", "assemble_findings", "render_report", "verify_remediation")
KEY_SHAPED = re.compile(r"\b(?:AK|AS)IA[0-9A-Z]{16}\b")

SCRIPT_MENTION = re.compile(r"scripts/([A-Za-z0-9_]+)\.py")
FLAG = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]*)")
FENCE = re.compile(r"```[a-z]*\n(.*?)```", re.S)


def read(path):
    return Path(path).read_text(encoding="utf-8")


def frontmatter(text):
    match = re.match(r"---\n(.*?)\n---\n", text, re.S)
    if not match:
        return None
    fields = {}
    for line in match.group(1).splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


def invocations(text):
    """(script name, command text) for every fenced-code command that runs scripts/<name>.py."""
    found = []
    for block in FENCE.findall(text):
        joined = re.sub(r"\\\n\s*", " ", block)
        for line in joined.splitlines():
            for match in SCRIPT_MENTION.finditer(line):
                found.append((match.group(1), line[match.end():]))
    return found


class SkillDocsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read(SKILL_MD)

    def test_frontmatter_is_valid(self):
        fields = frontmatter(self.text)
        self.assertIsNotNone(fields, "SKILL.md must start with a --- frontmatter block")
        self.assertEqual(set(fields), {"name", "description"})
        self.assertEqual(fields["name"], "auditing-infra-compliance")
        self.assertEqual(fields["name"], SKILL_DIR.name)
        self.assertRegex(fields["name"], r"^[a-z0-9-]+$")

    def test_description_is_a_trigger_under_the_limit(self):
        description = frontmatter(self.text)["description"]
        self.assertTrue(description.startswith("Use when"), description[:30])
        self.assertLessEqual(len(description), 1024)
        for trigger in ("SOC 2", "ISO 27001", "Drata", "Vanta", "feature"):
            self.assertIn(trigger, description)

    def test_skill_md_is_lean(self):
        self.assertLessEqual(len(self.text.splitlines()), 500)

    def test_every_mentioned_script_exists(self):
        names = set(SCRIPT_MENTION.findall(self.text))
        self.assertTrue(names)
        for name in names:
            self.assertTrue((SCRIPTS_DIR / f"{name}.py").is_file(), f"scripts/{name}.py does not exist")

    def test_every_cli_of_the_pipeline_is_used(self):
        used = {name for name, _ in invocations(self.text)}
        for name in CLI_SCRIPTS:
            self.assertIn(name, used, f"SKILL.md never runs scripts/{name}.py in a code block")

    def test_every_flag_in_a_command_exists_in_that_script(self):
        for name, command in invocations(self.text):
            source = read(SCRIPTS_DIR / f"{name}.py")
            for flag in FLAG.findall(command):
                self.assertIn(f'"{flag}"', source, f"{flag} is not an argparse flag of scripts/{name}.py")

    def test_subcommands_of_vault_index_exist(self):
        source = read(SCRIPTS_DIR / "vault_index.py")
        for sub in ("index", "feature"):
            self.assertRegex(self.text, rf"vault_index\.py\" {sub}\b")
            self.assertIn(f'"{sub}"', source)

    def test_verification_stage_is_in_the_flow(self):
        for needle in ("--check-cli", "--claims", "--verification", "verification-claims.json",
                       "vault-claims.json", "scope.json", "get-caller-identity", "PENDING_CLAUDE"):
            self.assertIn(needle, self.text)

    def test_hard_rules_are_stated(self):
        for needle in (".env", "solo los nombres", "si me das acceso", "aproximados", "a mano",
                       "pedir una fuente", "esperar confirmación", "check_id: null", "compliance-reports"):
            self.assertIn(needle.lower(), self.text.lower(), needle)

    def test_every_reference_linked_from_skill_md_exists(self):
        linked = set(re.findall(r"references/([A-Za-z0-9_./<>-]+)", self.text))
        for name in REFERENCES:
            self.assertIn(name, linked, f"SKILL.md does not link references/{name}")
        for ref in linked:
            ref = ref.rstrip(".")
            if "<" in ref:
                self.assertTrue((SKILL_DIR / "references" / ref.split("/")[0]).is_dir(), ref)
            else:
                self.assertTrue((SKILL_DIR / "references" / ref).exists(), f"references/{ref} does not exist")

    def test_references_exist_and_mention_only_real_scripts_and_files(self):
        for name in REFERENCES:
            path = SKILL_DIR / "references" / name
            self.assertTrue(path.is_file(), name)
            text = read(path)
            for script in SCRIPT_MENTION.findall(text):
                self.assertTrue((SCRIPTS_DIR / f"{script}.py").is_file(), f"{name}: scripts/{script}.py")
            for ref in re.findall(r"references/([A-Za-z0-9_./-]+\.(?:md|json))", text):
                self.assertTrue((SKILL_DIR / "references" / ref).is_file(), f"{name}: references/{ref}")

    def test_no_access_key_shaped_literals(self):
        for path in [SKILL_MD, *(SKILL_DIR / "references" / n for n in REFERENCES), ROOT / "tests" / "skill-scenarios.md"]:
            self.assertIsNone(KEY_SHAPED.search(read(path)), f"key-shaped literal in {path.name}")

    def test_scenarios_file_has_the_four_scenarios_with_empty_green_sections(self):
        text = read(ROOT / "tests" / "skill-scenarios.md")
        for letter in "abcd":
            self.assertIn(f"## Escenario ({letter})", text)
        self.assertEqual(text.count("### Línea base (sin skill)"), 4)
        self.assertEqual(text.count("### Resultado con el skill (GREEN)"), 4)


if __name__ == "__main__":
    unittest.main()
