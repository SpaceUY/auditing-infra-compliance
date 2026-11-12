import contextlib
import io
import json
import re
import shutil
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

import helpers
from helpers import FIXTURES_DIR, SKILL_DIR

import render_report

TEMPLATE = (SKILL_DIR / "assets" / "report-template.html").read_text(encoding="utf-8")
SAMPLE = helpers.load_fixture("findings-sample.json")
HOSTILE_NAME = "<script>alert(1)</script>"


class ScriptCounter(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.scripts.append(dict(attrs))


def i18n_block(template):
    match = re.search(r"/\*i18n:start\*/(.*?)/\*i18n:end\*/", template, re.S)
    assert match, "la plantilla debe delimitar sus strings con /*i18n:start*/ ... /*i18n:end*/"
    return match.group(1)


class TemplateTests(unittest.TestCase):
    def test_no_external_resources(self):
        rendered = render_report.render(SAMPLE, TEMPLATE)
        for pattern in (r"<script[^>]+src=", r"<link[^>]+href=", r'<img[^>]+src="http', r"@import", r"url\(\s*['\"]?http"):
            self.assertIsNone(re.search(pattern, rendered, re.I), pattern)

    def test_single_marker(self):
        self.assertEqual(TEMPLATE.count(render_report.MARKER), 1)
        self.assertIn(f'<script id="data" type="application/json">{render_report.MARKER}</script>', TEMPLATE)

    def test_no_innerhtml_with_data(self):
        self.assertEqual(re.findall(r"innerHTML\s*=\s*[^'\"\s]", TEMPLATE), [])

    def test_has_copy_fallback(self):
        self.assertIn("navigator.clipboard", TEMPLATE)
        self.assertIn("execCommand('copy')", TEMPLATE)
        self.assertIn("textarea", TEMPLATE)

    def test_footer_disclaimer_present(self):
        self.assertIn("Pre-auditoría técnica automatizada. No es una opinión de auditoría ni cubre controles "
                      "organizacionales (políticas, RRHH, equipos, proveedores, ISMS).", TEMPLATE)

    def test_no_percentage_in_summary_strings(self):
        # Targets the template's UI strings only: remediation text in the data may legitimately contain "%" (date +%s).
        self.assertNotIn("%", i18n_block(TEMPLATE))

    def test_numbers_steps_and_marks_placeholders_without_html(self):
        self.assertIn("'ol'", TEMPLATE)
        self.assertIn("el('mark'", TEMPLATE)
        self.assertIn("COMPLETAR", TEMPLATE)

    def test_theme_print_and_mobile_support(self):
        self.assertIn(":root", TEMPLATE)
        self.assertIn("prefers-color-scheme: dark", TEMPLATE)
        self.assertIn("@media print", TEMPLATE)
        self.assertIn('name="viewport"', TEMPLATE)

    def test_filters_persist_inside_try_catch(self):
        self.assertRegex(TEMPLATE, r"try\s*\{[^}]*localStorage")


class RenderTests(unittest.TestCase):
    def test_data_injected_and_escaped(self):
        rendered = render_report.render(SAMPLE, TEMPLATE)
        self.assertNotIn("</script><script>alert", rendered)
        self.assertNotIn("<script>alert(1)", rendered)
        self.assertIn("<script", rendered)
        self.assertNotIn(render_report.MARKER, rendered)

    def test_embedded_json_round_trips(self):
        rendered = render_report.render(SAMPLE, TEMPLATE)
        match = re.search(r'<script id="data" type="application/json">(.*?)</script>', rendered, re.S)
        self.assertEqual(json.loads(match.group(1)), SAMPLE)

    def test_ampersand_and_angle_brackets_escaped(self):
        rendered = render_report.render({"findings": [{"title": "a & <b>"}]}, TEMPLATE)
        match = re.search(r'<script id="data" type="application/json">(.*?)</script>', rendered, re.S)
        self.assertNotRegex(match.group(1), r"[<>&]")
        self.assertEqual(json.loads(match.group(1))["findings"][0]["title"], "a & <b>")

    def test_hostile_names_escaped(self):
        hostile = [f for f in SAMPLE["findings"] if f["resource"]["name"] == HOSTILE_NAME]
        self.assertTrue(hostile, "el fixture debe incluir un recurso con nombre hostil")
        rendered = render_report.render(SAMPLE, TEMPLATE)
        parser = ScriptCounter()
        parser.feed(rendered)
        self.assertEqual(len(parser.scripts), 2)
        self.assertEqual([s.get("type") for s in parser.scripts], ["application/json", None])
        self.assertEqual(parser.scripts[0].get("id"), "data")

    def test_fixture_covers_every_status_severity_and_kind(self):
        findings = SAMPLE["findings"]
        self.assertEqual({f["status"] for f in findings},
                         {"FAIL", "PASS", "DRIFT", "DOCUMENTED_ONLY", "DOCUMENTED_GAP", "UNDOCUMENTED", "NO_VERIFICADO", "N/A"})
        self.assertEqual({f["severity"] for f in findings}, {"critical", "high", "medium", "low"})
        kinds = {f["remediation"]["kind"] for f in findings if f["remediation"]}
        self.assertEqual(kinds, {"cli", "cli_with_decision", "planned_change", "console_only"})
        tags = [t for f in findings if isinstance(f["evidence"], dict) for t in (f["evidence"].get("tags") or {})]
        self.assertIn('x"onmouseover=', tags)
        self.assertTrue(any("`" in c for f in findings if f["remediation"] for c in f["remediation"]["commands"]))
        self.assertTrue(any(f["vacuous"] and f["status"] == "N/A" for f in findings))
        self.assertTrue(any(f["missing"] for f in findings if f["status"] == "NO_VERIFICADO"))
        self.assertTrue(any(not m["sourced"] for f in findings for m in f["mappings"]["tsc"] + f["mappings"]["iso27001_2022"]))

    def test_render_is_pure_and_ignores_verification(self):
        before = json.dumps(SAMPLE, sort_keys=True)
        first = render_report.render(SAMPLE, TEMPLATE)
        self.assertEqual(first, render_report.render(SAMPLE, TEMPLATE, verification={"results": []}))
        self.assertEqual(json.dumps(SAMPLE, sort_keys=True), before)

    def test_rejects_template_without_marker_and_bad_findings(self):
        with self.assertRaises(ValueError):
            render_report.render(SAMPLE, "<html></html>")
        with self.assertRaises(ValueError):
            render_report.render({"meta": {}}, TEMPLATE)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def run_cli(self, *args):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = render_report.main([str(a) for a in args])
        return code, err.getvalue()

    def test_writes_report(self):
        out = self.tmp / "nested" / "report.html"
        code, _ = self.run_cli(FIXTURES_DIR / "findings-sample.json", "-o", out)
        self.assertEqual(code, 0)
        self.assertIn('<script id="data"', out.read_text(encoding="utf-8"))

    def test_default_output_next_to_input(self):
        src = self.tmp / "findings.json"
        shutil.copy(FIXTURES_DIR / "findings-sample.json", src)
        self.assertEqual(self.run_cli(src)[0], 0)
        self.assertTrue((self.tmp / "report.html").is_file())

    def test_clean_errors(self):
        bad = self.tmp / "bad.json"
        bad.write_text("{no json", encoding="utf-8")
        code, err = self.run_cli(bad, "-o", self.tmp / "r.html")
        self.assertEqual(code, 2)
        self.assertTrue(err.startswith("error:"))
        self.assertNotIn("Traceback", err)
        code, err = self.run_cli(self.tmp / "missing.json")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
