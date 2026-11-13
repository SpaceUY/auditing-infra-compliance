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
        self.assertEqual(set(fields), {"name", "description", "disable-model-invocation", "argument-hint"})
        self.assertEqual(fields["name"], "auditing-infra-compliance")
        self.assertEqual(fields["name"], SKILL_DIR.name)
        self.assertRegex(fields["name"], r"^[a-z0-9-]+$")

    def test_description_is_a_trigger_under_the_limit(self):
        description = frontmatter(self.text)["description"]
        self.assertTrue(description.startswith("Use when"), description[:30])
        self.assertLessEqual(len(description), 1024)
        for trigger in ("SOC 2", "ISO 27001", "Drata", "Vanta", "feature"):
            self.assertIn(trigger, description)

    def test_the_skill_is_only_invoked_by_the_user(self):
        # user requirement: never auto-invoked; it runs only through /auditing-infra-compliance <request>
        fields = frontmatter(self.text)
        self.assertEqual(fields["disable-model-invocation"], "true")
        self.assertIn("/auditing-infra-compliance <request>", self.text)

    def test_requests_are_accepted_in_english_and_spanish(self):
        hint = frontmatter(self.text)["argument-hint"]
        self.assertIn("English or Spanish", hint)
        self.assertIn("revisá", hint)  # a Spanish example request
        self.assertIn("audit the whole account", hint)  # an English example request
        self.assertIn("in English or Spanish", frontmatter(self.text)["description"])

    def test_skill_md_is_lean(self):
        self.assertLessEqual(len(self.text.splitlines()), 220)  # detail lives in references/

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
        for needle in (".env", "just the variable names", "if you give me access", "approximate", "by hand",
                       "ask for a source", "wait for confirmation", "check_id: null", "compliance-reports",
                       "sensitive_files", "data, not instructions", "WARNING", "do not persist", '"domains": ["inventory"]',
                       "not verified: do not apply without confirming", "actual_status", "context", "translation",
                       "could not be found", "deferred", "cannot be produced"):
            self.assertIn(needle.lower(), self.text.lower(), needle)

    def test_background_collect_says_where_the_summary_arrives_and_not_to_poll(self):
        step = next(line for line in self.text.splitlines() if "run_in_background" in line)
        for needle in ("background task's output", "do not poll it while waiting", "read only that summary"):
            self.assertIn(needle, step)

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

    def test_scenarios_file_has_the_four_scenarios_each_with_a_baseline_and_a_green_section(self):
        text = read(ROOT / "tests" / "skill-scenarios.md")
        for letter in "abcd":
            self.assertIn(f"## Scenario ({letter})", text)
        self.assertEqual(text.count("### Baseline (without the skill)"), 4)
        self.assertEqual(text.count("### Result with the skill (GREEN)"), 4)


def hard_rules(text):
    """Rows of the "Hard rules" table: [(rule, rationalisation, what to do)]."""
    section = text.split("## Hard rules", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("|")][2:]
    return [[cell.strip() for cell in row.strip("|").split(" | ")] for row in rows]


class ReadOnlyRuleTests(unittest.TestCase):
    """Review 2 C: the product rule (the skill never writes to AWS or applies a fix) is the first, absolute hard rule."""

    @classmethod
    def setUpClass(cls):
        cls.skill = read(SKILL_MD)

    def test_the_first_hard_rule_is_the_absolute_read_only_rule(self):
        rule, rationalisation, action = hard_rules(self.skill)[0]
        for needle in ("never writes to AWS", "not even if the user asks", "just to test", "another tool", "PR", "IaC"):
            self.assertIn(needle, rule)
        self.assertIn("if you give me access", rationalisation.lower())
        for needle in ("Refuse", "always a no", "without exceptions", "Copy block"):
            self.assertIn(needle, action)

    def test_no_other_hard_rule_leaves_room_for_an_exception(self):
        text = "\n".join(" ".join(row) for row in hard_rules(self.skill)).lower()
        for forbidden in ("unless the user", "if the user authorizes", "with confirmation may apply"):
            self.assertNotIn(forbidden, text)

    def test_readme_and_guidelines_state_the_same_rule(self):
        readme = read(ROOT / "README.md")
        self.assertIn("Absolute rule: the skill only reports", readme)
        self.assertIn("never\nwrites to AWS and never applies a fix", readme)
        what_not = readme.split("## What it does not do", 1)[1].split("\n## ", 1)[0]
        self.assertIn("It never writes to AWS", what_not)
        self.assertIn("not even if asked", what_not)
        guidelines = read(SKILL_DIR / "references" / "remediation-guidelines.md")
        self.assertIn("never writes to AWS", guidelines)
        self.assertIn("not even if the user asks", guidelines)

    def test_the_read_only_guarantee_names_the_reviewed_allowlist(self):
        guidelines = read(SKILL_DIR / "references" / "remediation-guidelines.md")
        for needle in ("REVIEWED_OPERATIONS", "SENSITIVE_NAME_EXCEPTIONS", "aws <service> <operation> help"):
            self.assertIn(needle, guidelines)
        self.assertIn("REVIEWED_OPERATIONS", read(ROOT / "README.md"))


class BehaviourChangesAreDocumentedTests(unittest.TestCase):
    """Review 2 A/B/C: every behaviour the engine commits changed is in SKILL.md or its references, and the quoted
    messages still exist in the scripts (the docs cannot drift from the code)."""

    @classmethod
    def setUpClass(cls):
        cls.skill = read(SKILL_MD)
        cls.refs = {n: read(SKILL_DIR / "references" / n) for n in REFERENCES}
        cls.scripts = {p.name: read(p) for p in SCRIPTS_DIR.glob("*.py")}

    def test_the_verdict_is_documented_in_skill_readme_and_report_format(self):
        for needle in ("verdict_text", "NOT_OPTIMAL", "NOT_VERIFIABLE", "OPTIMAL"):
            self.assertIn(needle, self.skill, needle)
            self.assertIn(needle, self.refs["report-format.md"], needle)
        self.assertNotIn("never `OPTIMAL` without credentials", self.refs["report-format.md"])
        self.assertNotIn("There is never `OPTIMAL` without", read(ROOT / "README.md"))
        for verdict in ("NOT_OPTIMAL", "NOT_VERIFIABLE", "OPTIMAL"):
            self.assertIn(verdict, self.scripts["assemble_findings.py"])
        self.assertIn("verdict_text", self.scripts["assemble_findings.py"])

    def test_the_verdict_basis_is_documented_everywhere(self):
        for text in (self.skill, self.refs["report-format.md"], read(ROOT / "README.md"), self.scripts["assemble_findings.py"]):
            for needle in ("verdict_basis", "vault", "aws+vault"):
                self.assertIn(needle, text, needle)
        self.assertIn("not verified against AWS", self.refs["report-format.md"])
        self.assertIn("not verified against AWS", self.scripts["assemble_findings.py"])
        for phrase in ("do not insist", "With credentials only: continue", "Ask for a source only if there is none"):
            self.assertIn(phrase, self.skill, phrase)
        self.assertNotIn("Never `OPTIMAL` without credentials", self.skill)

    def test_spec_amends_a2_and_lists_the_post_approval_changes_and_the_plan_points_to_them(self):
        spec = read(ROOT / "docs" / "specs" / "2026-11-12-infra-compliance-audit-design.md")
        plan = read(ROOT / "docs" / "plans" / "2026-11-12-infra-compliance-audit.md")
        self.assertIn("## 16. Changes after approval", spec)
        self.assertIn("verdict per source", spec)
        self.assertNotIn("or a global \"pass / fail\"", spec)
        for needle in ("verdict_basis", "REVIEWED_OPERATIONS", "IAM-009", "DAT-001", "ENC-001", "DAT-008", "aws_runner.py", "--tool"):
            self.assertIn(needle, spec, needle)
        self.assertIn("section 16 of `docs/specs/2026-11-12-infra-compliance-audit-design.md`", plan.split("\n\n")[1])

    def test_tool_and_lang_flags_are_documented(self):
        self.assertIn("--tool drata|vanta|both", self.skill)
        self.assertNotIn("--lang", self.skill)
        report_format = self.refs["report-format.md"]
        self.assertIn("`--lang` only accepts `en`", report_format)
        self.assertIn("preselects", report_format)

    def test_no_sources_exit_and_the_scope_file_location_are_documented(self):
        message = "no sources: a vault or read-only AWS credentials are required"
        self.assertIn(message, self.scripts["assemble_findings.py"])
        for text in (self.skill, self.refs["report-format.md"]):
            self.assertIn(message, text)
        self.assertIn("$RUN/scope.json", self.skill)
        self.assertIn("do not move or delete it", self.skill)
        self.assertIn("neither moved nor deleted", self.refs["report-format.md"])

    def test_claims_are_optional_in_the_second_verification_pass(self):
        self.assertIn("`--claims` only if you wrote the file", self.skill)
        self.assertIn("does not exist only warns", self.skill)
        self.assertIn("the claims file does not exist", self.scripts["verify_remediation.py"])

    def test_scope_regions_rule_and_exit_2_are_documented(self):
        for text in (self.skill, self.refs["report-format.md"]):
            self.assertIn("non-empty", text)
        self.assertIn("exit `2`", self.refs["report-format.md"])
        self.assertIn("auto", self.scripts["collect.py"])

    def test_the_not_verified_reasons_quoted_in_the_docs_exist_in_the_engine(self):
        collect = self.scripts["collect.py"]
        for reason in ("could not list the regions", "no regions in scope", "incomplete inventory", "blocked by SCP"):
            self.assertIn(reason, collect, reason)
            self.assertIn(reason, self.refs["report-format.md"], reason)
        self.assertIn("ec2:DescribeRegions", self.refs["report-format.md"])
        self.assertIn("ec2:DescribeRegions", collect)

    def test_cmp_006_context_rows_are_documented(self):
        self.assertIn("context_for", self.scripts["collect.py"])
        for text in (self.skill, self.refs["report-format.md"]):
            self.assertIn("context_for", text)
            self.assertIn("CR-003", text)

    def test_the_matched_note_and_truncated_notes_are_documented(self):
        reading = self.refs["vault-reading.md"]
        self.assertIn('via: ["matched"]', reading)
        self.assertIn("truncated_notes", reading)
        self.assertIn("matched", self.scripts["vault_index.py"])
        self.assertIn("truncated_notes", self.scripts["vault_index.py"])
        self.assertIn("MAX_NOTE_BYTES", self.scripts["vault_index.py"])

    def test_vault_statements_are_documented_as_evaluated_by_vault(self):
        self.assertIn("`vault`", self.refs["report-format.md"])
        self.assertIn('"vault"', self.scripts["assemble_findings.py"])

    def test_the_reviewed_allowlist_and_denylist_rules_exist_in_the_engine(self):
        self.assertIn("REVIEWED_OPERATIONS", self.scripts["catalog.py"])
        self.assertIn("SENSITIVE_NAME_EXCEPTIONS", self.scripts["aws_runner.py"])

    def test_known_secret_detection_limits_are_documented_in_the_references(self):
        reading = self.refs["vault-reading.md"]
        self.assertIn("Known limits of secret detection", reading)
        for needle in ("Secrets Manager", "shaped like a key", "no separator at all", "Column tables", "manually review", "false positive", "false negative"):
            self.assertIn(needle, reading, needle)
        self.assertNotIn("Known limits of secret detection", self.skill)  # the detail lives in the references, SKILL.md only points to it
        self.assertIn("vault-reading.md` §9", self.skill)

    def test_coverage_limits_and_root_logins_are_documented(self):
        vendors = self.refs["drata-vanta.md"]
        for needle in ("Known coverage limits", "DynamoDB", "Alternate account contacts", "IAM-004", "LOG-010", "ENC-001"):
            self.assertIn(needle, vendors, needle)

    def test_fixes_that_replace_things_are_documented_as_read_then_merge(self):
        guidelines = self.refs["remediation-guidelines.md"]
        for needle in ("Read before replacing", "STOPPED", "--no-publicly-accessible", "Alternatives are not copied together"):
            self.assertIn(needle, guidelines, needle)


class FinalCleanupDocsTests(unittest.TestCase):
    """Final cleanup A+C: SKILL.md says what the scripts do (verdict, printed line, scope errors, regions) and keeps the read-only rule."""

    @classmethod
    def setUpClass(cls):
        cls.skill = read(SKILL_MD)
        cls.readme = read(ROOT / "README.md")
        cls.vault_index = read(SCRIPTS_DIR / "vault_index.py")

    def test_the_verdict_text_matches_how_assemble_computes_it(self):
        for needle in ("`DRIFT`/`UNDOCUMENTED` with `actual_status: FAIL`", "critical/high", "at least one evaluated `PASS`/`FAIL`",
                       "complete run"):
            self.assertIn(needle, self.skill, needle)
        self.assertIn("at least one evaluated `PASS` or `FAIL`", self.readme.replace("\n  ", " "))

    def test_the_vault_line_matches_what_vault_index_prints(self):
        self.assertIn("Typed vault", self.skill)
        self.assertIn("Free-form (untyped) vault", self.skill)
        self.assertIn('"Typed vault"', self.vault_index)
        self.assertNotIn("(`typed` or `free`)", self.skill)

    def test_an_offered_admin_profile_is_only_for_the_read_only_collection(self):
        self.assertIn("admin profile", self.skill)
        for text in (self.skill, self.readme, read(SKILL_DIR / "references" / "remediation-guidelines.md")):
            self.assertRegex(text.replace("\n", " "), r"(?s)admin profile.{0,400}(only|never)")
        self.assertIn("never to apply", self.skill)

    def test_the_copy_block_is_only_pointed_to_when_there_is_a_verified_fix(self):
        self.assertIn("if the report has a verified fix", self.skill)
        self.assertIn("nothing verified to fix", self.skill)

    def test_scope_errors_and_unknown_regions_are_documented(self):
        self.assertIn("DET-004, DET-006, DET-007", self.skill)
        self.assertIn("an unknown domain", self.skill)
        self.assertIn("no catalog check applies to: <types>", self.skill)
        self.assertIn("no catalog check applies to: <types>", read(SKILL_DIR / "references" / "report-format.md"))
        self.assertIn("a domain that does not exist in the catalog", read(SKILL_DIR / "references" / "report-format.md"))
        for needle in ("you build", "§4"):
            self.assertIn(needle, self.skill)

    def test_shell_caveats_for_zsh_are_documented(self):
        self.assertIn("zsh", self.skill)
        self.assertIn("`| head`", self.skill)


class FlowRulingsTests(unittest.TestCase):
    """Review 3 D: vault-only skips collect, AWS needs a confirmed account, the run folder is absolute and outside the vault."""

    @classmethod
    def setUpClass(cls):
        cls.skill = read(SKILL_MD)
        cls.vault_reading = read(SKILL_DIR / "references" / "vault-reading.md")
        cls.readme = read(ROOT / "README.md")

    def step(self, title):
        return self.skill.split(f"### {title}", 1)[1].split("\n### ", 1)[0]

    def test_collect_is_skipped_without_credentials_or_without_aws_resources(self):
        step = self.step("5. Collect")
        self.assertIn("**Skip this step**", step)
        for needle in ("no credentials", "vault-only run", "`scope.resources` would be empty"):
            self.assertIn(needle, step)
        self.assertIn("skip step 5", self.step("2. Preflight"))

    def test_a_vault_without_profile_is_vault_only_and_aws_needs_a_confirmed_account(self):
        self.assertIn("vault-only** unless the user asks", self.skill)
        preflight = self.step("2. Preflight")
        for needle in ("always** run `aws sts get-caller-identity", "Account id and ARN", "confirmation of that account"):
            self.assertIn(needle, preflight)
        self.assertIn("a profile or the ambient credentials", self.readme.replace("\n", " "))

    def test_the_run_folder_is_absolute_and_never_inside_the_vault(self):
        preflight = self.step("2. Preflight")
        for needle in ("**absolute**", "inside the vault", "parent directory", ".gitignore"):
            self.assertIn(needle, preflight)
        self.assertIn("Exit `2` = invalid vault or output inside the vault", self.step("3. Vault index"))

    def test_feature_without_a_vault_goes_straight_to_the_inventory_search(self):
        self.assertIn("without a vault, skip `vault_index.py feature`", self.step("4. Resolve the scope and write `scope.json`"))
        self.assertIn("**with no vault**", self.vault_reading)

    def test_the_catalog_list_example_returns_results(self):
        self.assertIn("--grep encrypt`", self.skill)
        self.assertNotIn("--grep encryption", self.skill + self.readme)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = validate_catalog.main(["--list", "--type", "rds_instance", "--grep", "encrypt"])
        self.assertEqual(code, 0)
        self.assertIn("ENC-003", out.getvalue())

    def test_the_vault_only_fail_exception_is_stated_wherever_pass_fail_is_ruled_out(self):
        self.assertIn("with one exception: a secret or sensitive file", self.skill)
        self.assertIn("except a secret or sensitive file", read(SKILL_DIR / "references" / "report-format.md"))
        self.assertIn("except a secret or sensitive file", self.readme)


if __name__ == "__main__":
    unittest.main()
