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
        self.assertLessEqual(len(self.text.splitlines()), 195)  # detail lives in references/

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

    def test_background_collect_says_where_the_summary_arrives_and_not_to_poll(self):
        step = next(line for line in self.text.splitlines() if "run_in_background" in line)
        for needle in ("salida de la tarea de fondo", "no consultarla mientras espera", "leer solo ese resumen"):
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
            self.assertIn(f"## Escenario ({letter})", text)
        self.assertEqual(text.count("### Línea base (sin skill)"), 4)
        self.assertEqual(text.count("### Resultado con el skill (GREEN)"), 4)


def hard_rules(text):
    """Rows of the "Reglas duras" table: [(rule, rationalisation, what to do)]."""
    section = text.split("## Reglas duras", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("|")][2:]
    return [[cell.strip() for cell in row.strip("|").split(" | ")] for row in rows]


class ReadOnlyRuleTests(unittest.TestCase):
    """Review 2 C: the product rule (the skill never writes to AWS or applies a fix) is the first, absolute hard rule."""

    @classmethod
    def setUpClass(cls):
        cls.skill = read(SKILL_MD)

    def test_the_first_hard_rule_is_the_absolute_read_only_rule(self):
        rule, rationalisation, action = hard_rules(self.skill)[0]
        for needle in ("jamás escribe en AWS", "ni si el usuario lo pide", "solo para probar", "otra herramienta", "PR", "IaC"):
            self.assertIn(needle, rule)
        self.assertIn("si me das acceso", rationalisation.lower())
        for needle in ("Negarte", "siempre un no", "sin excepciones", "bloque Copy"):
            self.assertIn(needle, action)

    def test_no_other_hard_rule_leaves_room_for_an_exception(self):
        text = "\n".join(" ".join(row) for row in hard_rules(self.skill)).lower()
        for forbidden in ("salvo que el usuario", "si el usuario lo autoriza", "con confirmación puede aplicar"):
            self.assertNotIn(forbidden, text)

    def test_readme_and_guidelines_state_the_same_rule(self):
        readme = read(ROOT / "README.md")
        self.assertIn("Regla absoluta: el skill solo informa", readme)
        self.assertIn("nunca\nescribe en AWS ni aplica un arreglo", readme)
        what_not = readme.split("## Qué no hace", 1)[1].split("\n## ", 1)[0]
        self.assertIn("No escribe en AWS, jamás", what_not)
        self.assertIn("ni siquiera si se lo piden", what_not)
        guidelines = read(SKILL_DIR / "references" / "remediation-guidelines.md")
        self.assertIn("nunca escribe en AWS", guidelines)
        self.assertIn("ni si el usuario lo pide", guidelines)

    def test_the_read_only_guarantee_names_the_reviewed_allowlist(self):
        guidelines = read(SKILL_DIR / "references" / "remediation-guidelines.md")
        for needle in ("REVIEWED_OPERATIONS", "SENSITIVE_NAME_EXCEPTIONS", "aws <servicio> <operación> help"):
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
        for needle in ("verdict_text", "NO_OPTIMO", "NO_VERIFICABLE", "OPTIMO"):
            self.assertIn(needle, self.skill, needle)
            self.assertIn(needle, self.refs["report-format.md"], needle)
        self.assertIn("nunca `OPTIMO` sin credenciales", self.refs["report-format.md"])
        self.assertIn("Nunca hay `OPTIMO` sin\n  credenciales", read(ROOT / "README.md"))
        for verdict in ("NO_OPTIMO", "NO_VERIFICABLE", "OPTIMO"):
            self.assertIn(verdict, self.scripts["assemble_findings.py"])
        self.assertIn("verdict_text", self.scripts["assemble_findings.py"])

    def test_no_sources_exit_and_the_scope_file_location_are_documented(self):
        message = "sin fuentes: hace falta un vault o credenciales AWS de solo lectura"
        self.assertIn(message, self.scripts["assemble_findings.py"])
        for text in (self.skill, self.refs["report-format.md"]):
            self.assertIn(message, text)
        self.assertIn("$RUN/scope.json", self.skill)
        self.assertIn("no moverlo ni borrarlo", self.skill)
        self.assertIn("no se mueve ni se borra", self.refs["report-format.md"])

    def test_claims_are_optional_in_the_second_verification_pass(self):
        self.assertIn("`--claims` solo si escribiste el archivo", self.skill)
        self.assertIn("no existe solo avisa", self.skill)
        self.assertIn("el archivo de claims no existe", self.scripts["verify_remediation.py"])

    def test_scope_regions_rule_and_exit_2_are_documented(self):
        for text in (self.skill, self.refs["report-format.md"]):
            self.assertIn("no vacía", text)
        self.assertIn("exit `2`", self.refs["report-format.md"])
        self.assertIn("auto", self.scripts["collect.py"])

    def test_the_no_verificado_reasons_quoted_in_the_docs_exist_in_the_engine(self):
        collect = self.scripts["collect.py"]
        for reason in ("no se pudieron listar las regiones", "sin regiones en el alcance", "inventario incompleto", "bloqueado por SCP"):
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
        self.assertIn("Límites conocidos de la detección de secretos", reading)
        for needle in ("Secrets Manager", "forma de clave", "sin ningún separador", "Tablas por columnas", "revisar a mano", "falso positivo", "falso negativo"):
            self.assertIn(needle, reading, needle)
        self.assertNotIn("Límites conocidos de la detección", self.skill)  # the detail lives in the references, SKILL.md only points to it
        self.assertIn("vault-reading.md` §9", self.skill)

    def test_coverage_limits_and_root_logins_are_documented(self):
        vendors = self.refs["drata-vanta.md"]
        for needle in ("Límites de cobertura conocidos", "DynamoDB", "Contactos alternativos", "IAM-004", "LOG-010", "ENC-001"):
            self.assertIn(needle, vendors, needle)

    def test_fixes_that_replace_things_are_documented_as_read_then_merge(self):
        guidelines = self.refs["remediation-guidelines.md"]
        for needle in ("Leer antes de reemplazar", "DETENIDO", "--no-publicly-accessible", "Alternativas no se copian juntas"):
            self.assertIn(needle, guidelines, needle)


class FinalCleanupDocsTests(unittest.TestCase):
    """Final cleanup A+C: SKILL.md says what the scripts do (verdict, printed line, scope errors, regions) and keeps the read-only rule."""

    @classmethod
    def setUpClass(cls):
        cls.skill = read(SKILL_MD)
        cls.readme = read(ROOT / "README.md")
        cls.vault_index = read(SCRIPTS_DIR / "vault_index.py")

    def test_the_verdict_text_matches_how_assemble_computes_it(self):
        for needle in ("`DRIFT`/`UNDOCUMENTED` con `actual_status: FAIL`", "crítica/alta", "al menos un `PASS`/`FAIL` evaluado",
                       "corrida completa"):
            self.assertIn(needle, self.skill, needle)
        self.assertIn("al menos un `PASS` o `FAIL`", self.readme.replace("\n  ", " "))

    def test_the_vault_line_matches_what_vault_index_prints(self):
        self.assertIn("Vault tipado", self.skill)
        self.assertIn("Vault libre (no tipado)", self.skill)
        self.assertIn('"tipado"', self.vault_index)
        self.assertNotIn("(`typed` o `free`)", self.skill)

    def test_an_offered_admin_profile_is_only_for_the_read_only_collection(self):
        self.assertIn("perfil admin", self.skill)
        for text in (self.skill, self.readme, read(SKILL_DIR / "references" / "remediation-guidelines.md")):
            self.assertRegex(text.replace("\n", " "), r"(?s)perfil admin.{0,400}(solo|nunca)")
        self.assertIn("nunca para aplicar", self.skill)

    def test_the_copy_block_is_only_pointed_to_when_there_is_a_verified_fix(self):
        self.assertIn("si el reporte tiene un arreglo verificado", self.skill)
        self.assertIn("no hay nada verificado para arreglar", self.skill)

    def test_scope_errors_and_unknown_regions_are_documented(self):
        self.assertIn("DET-004, DET-006, DET-007", self.skill)
        self.assertIn("un dominio desconocido", self.skill)
        self.assertIn("ningún chequeo del catálogo aplica a: <tipos>", self.skill)
        self.assertNotIn("sin ningún chequeo que aplique", self.skill)
        self.assertIn("ningún chequeo del catálogo aplica a: <tipos>", read(SKILL_DIR / "references" / "report-format.md"))
        self.assertIn("dominio que no existe en el catálogo", read(SKILL_DIR / "references" / "report-format.md"))
        for needle in ("armás vos", "§4"):
            self.assertIn(needle, self.skill)

    def test_shell_caveats_for_zsh_are_documented(self):
        self.assertIn("zsh", self.skill)
        self.assertIn("`| head`", self.skill)


if __name__ == "__main__":
    unittest.main()
