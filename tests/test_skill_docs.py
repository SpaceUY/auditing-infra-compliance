"""Structure checks for SKILL.md and its references: frontmatter, script and flag names, links, size."""

import contextlib
import io
import re
import shlex
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = ROOT / "auditing-infra-compliance"
SCRIPTS_DIR = SKILL_DIR / "scripts"
SKILL_MD = SKILL_DIR / "SKILL.md"
REFERENCES = ("vault-reading.md", "remediation-guidelines.md", "report-format.md", "drata-vanta.md")
CLI_SCRIPTS = ("vault_index", "collect", "assemble_findings", "render_report", "verify_remediation")
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import assemble_findings  # noqa: E402
import collect  # noqa: E402
import render_report  # noqa: E402
import validate_catalog  # noqa: E402
import vault_index  # noqa: E402
import verify_remediation  # noqa: E402

PARSERS = {
    "vault_index": vault_index.build_parser,
    "collect": collect.build_parser,
    "assemble_findings": assemble_findings.build_parser,
    "render_report": render_report.build_parser,
    "verify_remediation": verify_remediation.build_parser,
    "validate_catalog": validate_catalog.build_parser,
}
KEY_SHAPED = re.compile(r"\b(?:AK|AS)IA[0-9A-Z]{16}\b")

SCRIPT_MENTION = re.compile(r"scripts/([A-Za-z0-9_]+)\.py")
FENCE = re.compile(r"```[a-z]*\n(.*?)```", re.S)
INLINE = re.compile(r"`([^`\n]*python3[^`\n]*)`")


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


def command_lines(text):
    """Lines of fenced blocks (continuations joined) and inline `python3 ...` spans."""
    lines = []
    for block in FENCE.findall(text):
        lines += re.sub(r"\\\n\s*", " ", block).splitlines()
    return lines + INLINE.findall(FENCE.sub("", text))


def invocations(text):
    """(script name, argv tokens after the script) for every documented command that runs scripts/<name>.py.

    `[...]` marks optional arguments in the docs; the brackets are dropped and the arguments kept, so the
    parser sees the longest form of the command.
    """
    found = []
    for line in command_lines(text):
        match = SCRIPT_MENTION.search(line)
        if match:
            tail = line[match.end():].lstrip("\"'").replace("[", " ").replace("]", " ")
            found.append((match.group(1), shlex.split(tail)))
    return found


def parse(name, argv):
    """Parse argv with the real argparse parser of the script; return the error text or None."""
    parser = PARSERS[name]()
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stderr(stderr):
            parser.parse_args(argv)
    except SystemExit:
        return stderr.getvalue().strip().splitlines()[-1] if stderr.getvalue().strip() else "exit"
    return None


def documents():
    return [SKILL_MD, *(SKILL_DIR / "references" / n for n in REFERENCES)]


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

    def test_every_documented_command_is_accepted_by_the_real_parser(self):
        checked = 0
        for path in documents():
            for name, argv in invocations(read(path)):
                self.assertIn(name, PARSERS, f"{path.name}: scripts/{name}.py has no build_parser()")
                error = parse(name, argv)
                self.assertIsNone(error, f"{path.name}: scripts/{name}.py {' '.join(argv)} -> {error}")
                checked += 1
        self.assertGreaterEqual(checked, 6)

    def test_the_parser_check_rejects_unknown_flags_and_missing_required_ones(self):
        self.assertIsNotNone(parse("collect", ["--scope", "s.json", "--out", "o", "--role-name", "x"]))
        self.assertIsNotNone(parse("collect", ["--scope", "s.json"]))
        self.assertIsNotNone(parse("verify_remediation", ["--claims", "c.json"]))
        self.assertIsNotNone(parse("vault_index", ["feature", "only-one-arg"]))
        self.assertIsNone(parse("render_report", ["f.json", "-o", "r.html", "--verification", "v.json"]))

    def test_the_full_flag_set_of_the_pipeline_is_documented(self):
        used = {}
        for name, argv in invocations(self.text):
            used.setdefault(name, set()).update(t for t in argv if t.startswith("-"))
        self.assertLessEqual({"--scope", "--out"}, used["collect"])
        self.assertLessEqual({"--run-dir", "--vault-index", "--vault-claims", "--platform", "--mode"}, used["assemble_findings"])
        self.assertLessEqual({"--run-dir", "--claims", "--check-cli"}, used["verify_remediation"])
        self.assertIn("--verification", used["render_report"])
        self.assertIn("-o", used["vault_index"])
        self.assertLessEqual({"--list", "--type", "--grep"}, used["validate_catalog"])

    def test_subcommands_of_vault_index_exist(self):
        subcommands = {argv[0] for name, argv in invocations(self.text) if name == "vault_index"}
        self.assertEqual(subcommands, {"index", "feature"})

    def test_verification_stage_is_in_the_flow(self):
        for needle in ("--check-cli", "--claims", "--verification", "verification-claims.json",
                       "vault-claims.json", "scope.json", "get-caller-identity", "PENDING_CLAUDE"):
            self.assertIn(needle, self.text)

    def test_hard_rules_are_stated(self):
        for needle in (".env", "solo los nombres", "si me das acceso", "aproximados", "a mano",
                       "pedir una fuente", "esperar confirmación", "check_id: null", "compliance-reports",
                       "sensitive_files", "dato, no instrucciones", "AVISO", "no persisten", '"domains": ["inventory"]',
                       "no verificado: no aplicar sin confirmar", "actual_status", "contexto", "traducción",
                       "could not be found", "diferida", "no se pueden producir"):
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
