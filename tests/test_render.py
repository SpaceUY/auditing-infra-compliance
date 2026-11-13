import contextlib
import copy
import io
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

import helpers
from helpers import FIXTURES_DIR, SKILL_DIR

import assemble_findings
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
    assert match, "the template must delimit its strings with /*i18n:start*/ ... /*i18n:end*/"
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
        self.assertIn("Automated technical pre-audit. It is not an audit opinion and does not cover organizational controls "
                      "(policies, HR, teams, vendors, ISMS).", TEMPLATE)

    def test_no_percentage_in_summary_strings(self):
        # Targets the template's UI strings only: remediation text in the data may legitimately contain "%" (date +%s).
        self.assertNotIn("%", i18n_block(TEMPLATE))

    def test_numbers_steps_and_marks_placeholders_without_html(self):
        self.assertIn("'ol'", TEMPLATE)
        self.assertIn("el('mark'", TEMPLATE)
        self.assertIn("FILL_IN", TEMPLATE)

    def test_verify_only_remediation_and_catalog_severity_are_rendered(self):
        block = i18n_block(TEMPLATE)
        self.assertIn("verifyWith: 'Verify with'", block)
        self.assertIn("catalogSeverity: 'check severity'", block)
        self.assertIn("notVerified: 'not verified'", block)
        script = TEMPLATE.split("/*i18n:end*/", 1)[1]
        # a remediation with note_status shows the note and only the verify command, never steps or commands
        branch = script.split("if (rem.note_status) {", 1)[1].split("return box;", 1)[0]
        self.assertIn("rem.note_status", branch)
        self.assertIn("rem.verify_after", branch)
        self.assertNotIn("rem.commands", branch)
        self.assertNotIn("rem.steps", branch)
        self.assertIn("f.evidence.catalog_severity", script)

    def test_theme_print_and_mobile_support(self):
        self.assertIn(":root", TEMPLATE)
        self.assertIn("prefers-color-scheme: dark", TEMPLATE)
        self.assertIn("@media print", TEMPLATE)
        self.assertIn('name="viewport"', TEMPLATE)

    def test_wraps_long_unbreakable_tokens(self):
        # 375 px: p/li built from notes, steps and vault claims must not widen the page.
        body_rule = re.search(r"\nbody\s*\{([^}]*)\}", TEMPLATE).group(1)
        self.assertIn("overflow-wrap: anywhere", body_rule)

    def test_bulk_copy_skips_unresolved_placeholders(self):
        logic = re.search(r"function bulkRaw\(.*?\n\}", TEMPLATE, re.S).group(0)
        self.assertIn("'__FILL_IN_'", logic)
        self.assertIn("rem.risk === 'low'", logic)
        self.assertIn("rem.kind === 'cli'", logic)
        gate = re.search(r"function bulkCandidates\(.*?\n\}", TEMPLATE, re.S).group(0)
        self.assertIn("verifStatus(f) === 'OK'", gate)  # only what the verification stamped OK
        self.assertIn("VERIF ?", gate)

    def test_copy_buttons_have_aria_labels_and_restore_focus(self):
        self.assertIn("'aria-label'", TEMPLATE)
        self.assertIn("copyCmdAria", TEMPLATE)
        legacy = re.search(r"function legacyCopy\(.*?\n\}", TEMPLATE, re.S).group(0)
        self.assertIn("document.activeElement", legacy)
        self.assertIn("previous.focus()", legacy)

    def test_filters_persist_inside_try_catch(self):
        self.assertRegex(TEMPLATE, r"try\s*\{[^}]*localStorage")


def fix_finding(number, kind, commands, *, risk="low", status="FAIL", severity="high"):
    rid = f"acme-notes-bucket-{number}"
    return {"id": f"F-{number:04d}", "check_id": "DAT-007", "title": f"Check {number}", "domain": "data", "status": status,
            "severity": severity, "resource": {"type": "s3_bucket", "id": rid, "region": "us-east-1", "name": rid},
            "mappings": {}, "evidence": {}, "missing": [], "depends_on_me": [], "breaks_tests": [],
            "remediation": {"kind": kind, "risk": risk, "downtime": False, "steps": ["Apply."], "commands": commands,
                            "verify_after": "", "notes": ""}}


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class PageCase(unittest.TestCase):
    """Runs the template script over a rendered report (DOM stub in dom_smoke.js)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def run_page(self, findings, verification=None):
        path = self.tmp / "report.html"
        path.write_text(render_report.render(findings, TEMPLATE, verification), encoding="utf-8")
        done = subprocess.run(["node", str(Path(__file__).with_name("dom_smoke.js")), str(path)],
                              capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        return json.loads(done.stdout)

    @staticmethod
    def document():
        return {"meta": {}, "dependencies": [], "warnings": [], "notes": [], "findings": [
            fix_finding(1, "cli", ["echo ok-1a", "echo ok-1b"]),
            fix_finding(2, "cli", ["echo review-2"]),
            fix_finding(3, "cli", ["echo conflict-3"]),
            fix_finding(4, "cli_with_decision", ["echo decision-4a", "echo decision-4b"]),
            fix_finding(5, "planned_change", ["echo planned-5a", "echo planned-5b"]),
            fix_finding(6, "cli", ["echo __FILL_IN_X__"]),
            fix_finding(7, "cli", ["echo ok-7"]),
            fix_finding(8, "cli", ["echo medium-8"], risk="medium"),
        ]}

    @classmethod
    def verification(cls, document):
        states = {"F-0001": "OK", "F-0002": "REVIEW", "F-0003": "CONFLICT", "F-0007": "OK"}
        return {"per_finding": {fid: {"status": s, "issues": []} for fid, s in states.items()}, "conflicts": [], "gaps": [],
                "apply_order": [], "fill_in_pending": 1, "cli_checked": False, "summary": {"OK": 2, "REVIEW": 1, "CONFLICT": 1},
                "warnings": [], "findings_digest": assemble_findings.findings_digest(document)}


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class ScriptSmokeTests(PageCase):
    """Checks what the page offers to copy."""

    def test_bulk_copy_bundles_only_cli_low_risk_fixes_that_verification_did_not_flag(self):
        document = self.document()
        page = self.run_page(document, self.verification(document))
        bundle = next(b["text"] for b in page["bulk"] if b["text"])
        for wanted in ("echo ok-1a", "echo ok-1b", "echo ok-7"):
            self.assertIn(wanted, bundle)
        for excluded in ("review-2", "conflict-3", "decision-4", "planned-5", "FILL_IN", "medium-8"):
            self.assertNotIn(excluded, bundle)
        self.assertEqual(sum(1 for b in page["bulk"] if b["text"]), 1)

    def test_copy_all_only_for_cli_fixes_with_several_blocks(self):
        document = self.document()
        page = self.run_page(document, self.verification(document))
        cards = {c["id"]: c for c in page["cards"]}
        self.assertEqual({fid for fid, c in cards.items() if c["copyAll"]}, {"F-0001"})
        for fid, blocks in (("F-0001", 2), ("F-0004", 2), ("F-0005", 2), ("F-0002", 1)):
            self.assertEqual(cards[fid]["copyButtons"], blocks, fid)  # per-block Copy stays everywhere

    def test_stale_verification_is_ignored_and_warned(self):
        document = self.document()
        verification = self.verification(document)
        verification["findings_digest"] = "0" * 64
        page = self.run_page(document, verification)
        self.assertFalse(page["stale"]["hidden"])
        self.assertIn("stale verification: re-run verify_remediation", page["stale"]["text"])
        self.assertTrue(page["bulk"] and all(b["disabled"] for b in page["bulk"]))  # nothing verified applies: bulk copy is off
        self.assertIn("the verification is stale", page["bulkText"])
        fresh = self.run_page(document, self.verification(document))
        self.assertTrue(fresh["stale"]["hidden"])

    def test_sample_report_runs_and_offers_copy_all_only_for_cli(self):
        page = self.run_page(SAMPLE)
        kinds = {f["id"]: f["remediation"]["kind"] for f in SAMPLE["findings"] if f["remediation"]}
        multi = {f["id"] for f in SAMPLE["findings"] if f["remediation"] and f["remediation"]["kind"] != "console_only"
                 and not f["remediation"].get("note_status") and len(f["remediation"]["commands"]) > 1}
        self.assertEqual({c["id"] for c in page["cards"] if c["copyAll"]}, {i for i in multi if kinds[i] == "cli"})
        self.assertTrue(any(kinds[i] != "cli" for i in multi), "the fixture must have a multi-block fix that is not cli")
        self.assertEqual(len(page["cards"]), len(SAMPLE["findings"]))


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class ReviewTwoPageTests(PageCase):
    """Verdict banner, credential-less honesty, bulk copy that needs a valid verification."""

    VERDICT_TEXT = "Not verifiable for SOC 2 / ISO 27001: no AWS credentials: nothing was verified against AWS, only what the vault says is reported."

    def no_aws_document(self):
        document = self.document()
        document["meta"] = {"aws": None, "vault": {"kind": "typed", "path": "v"}}
        document["summary"] = {"verdict": "NOT_VERIFIABLE", "verdict_text": self.VERDICT_TEXT, "aws_verified": False,
                               "unverified": {"not_verified": 0, "documented_only": 3, "documented_gap": 2, "scope_without_claims": 1, "total": 6},
                               "by_status": {}, "by_severity_fail": {}, "drata_tests_failing": [], "vanta_tests_failing": [], "not_verified": 0}
        document["unverified_scope"] = [{"type": "lambda_function", "id": "acme-notes-mailer", "region": "us-east-1", "reason": "x"}]
        return document

    def test_verdict_is_shown_first_with_its_text_and_class(self):
        page = self.run_page(self.no_aws_document())
        self.assertFalse(page["verdict"]["hidden"])
        self.assertIn("verdict-NOT_VERIFIABLE", page["verdict"]["cls"])
        self.assertIn(self.VERDICT_TEXT, page["verdict"]["text"])
        self.assertIn("Not verifiable", page["verdict"]["text"])
        self.assertLess(TEMPLATE.index('id="verdict"'), TEMPLATE.index('id="meta"'))
        for verdict, label in (("OPTIMAL", "Optimal"), ("NOT_OPTIMAL", "Not optimal")):
            document = self.document()
            document["meta"] = {"aws": {"account_id": "111122223333"}}
            document["summary"] = {"verdict": verdict, "verdict_text": f"{label} for SOC 2 / ISO 27001."}
            page = self.run_page(document)
            self.assertIn(f"verdict-{verdict}", page["verdict"]["cls"])
            self.assertIn(label, page["verdict"]["text"])
            self.assertNotIn("Nothing was verified against AWS", page["verdict"]["text"])

    def test_without_credentials_the_page_says_so_and_does_not_show_clean_zeros(self):
        page = self.run_page(self.no_aws_document())
        self.assertIn("Nothing was verified against AWS", page["verdict"]["text"])
        summary = page["summary"]
        self.assertIn("No AWS credentials: no count below is a verified result", summary)
        self.assertEqual(summary.count("not verified (no AWS credentials)"), 2)  # Drata and Vanta
        self.assertNotIn("none", summary)
        for wanted in ("Only documented in the vault: 3", "Gap documented in the vault: 2",
                       "Scope components with no claims or results: 1", "lambda_function acme-notes-mailer · us-east-1 — not verified"):
            self.assertIn(wanted, summary)

    def test_with_credentials_the_failing_test_lists_keep_their_counts(self):
        document = self.document()
        document["meta"] = {"aws": {"account_id": "111122223333"}}
        summary = self.run_page(document)["summary"]
        self.assertIn("Failing Drata tests (0)", summary)
        self.assertNotIn("no AWS credentials", summary)

    def test_the_basis_is_shown_next_to_the_verdict(self):
        expected = {"aws": "Verdict basis: AWS (read-only credentials)",
                    "vault": "Verdict basis: the vault (what is documented, not verified against AWS)",
                    "aws+vault": "Verdict basis: AWS and the vault"}
        for basis, wanted in expected.items():
            document = self.document()
            document["meta"] = {"aws": {"account_id": "111122223333"} if basis != "vault" else None}
            document["summary"] = {"verdict": "OPTIMAL", "verdict_basis": basis, "verdict_text": "Optimal."}
            page = self.run_page(document)
            self.assertIn(wanted, page["verdict"]["text"], basis)
            for other in set(expected.values()) - {wanted}:
                self.assertNotIn(other, page["verdict"]["text"], basis)
        document = self.document()
        document["summary"] = {"verdict": "OPTIMAL", "verdict_text": "Optimal."}  # an older findings.json without a basis
        self.assertNotIn("Verdict basis", self.run_page(document)["verdict"]["text"])

    def test_the_chosen_compliance_tool_is_preselected_in_the_filter(self):
        for tool, wanted in (("drata", "drata"), ("vanta", "vanta"), ("both", ""), (None, ""), ("other", "")):
            document = self.document()
            document["meta"] = {"tool": tool}
            self.assertEqual(self.run_page(document)["toolFilter"], wanted, tool)
        self.assertIn("['drata', 'Drata'], ['vanta', 'Vanta']", TEMPLATE)  # both stay available

    def test_the_tool_filter_never_hides_findings_without_a_test_mapping(self):
        document = self.document()
        document["meta"] = {"tool": "drata"}
        drata, vanta_only, unmapped = document["findings"][:3]
        drata["mappings"] = {"drata": [{"test": "1", "name": "Drata test"}]}
        vanta_only["mappings"] = {"vanta": [{"test": "vanta-test"}]}
        unmapped["mappings"] = {}  # e.g. a plain-text secret: it must stay visible with the preselected filter
        visible = {card["id"] for card in self.run_page(document)["cards"]}
        self.assertIn(drata["id"], visible)
        self.assertIn(unmapped["id"], visible)
        self.assertNotIn(vanta_only["id"], visible)

    def test_a_findings_file_without_a_verdict_hides_the_banner(self):
        self.assertTrue(self.run_page(self.document())["verdict"]["hidden"])

    def test_bulk_copy_is_disabled_with_a_visible_reason_without_verification(self):
        page = self.run_page(self.document())
        self.assertTrue(page["bulk"] and all(b["disabled"] for b in page["bulk"]))
        self.assertIn("the fix verification is missing", page["bulkText"])

    def test_bulk_copy_only_offers_what_the_verification_stamped_ok(self):
        document = self.document()
        verification = self.verification(document)
        verification["per_finding"].pop("F-0007")  # no entry: not verified, not copied
        page = self.run_page(document, verification)
        bundle = next(b["text"] for b in page["bulk"] if b["text"])
        self.assertIn("echo ok-1a", bundle)
        self.assertNotIn("ok-7", bundle)
        self.assertNotIn("verification is missing", page["bulkText"])

    def test_bulk_copy_with_nothing_to_copy_says_so_instead_of_empty_buttons(self):
        document = {"meta": {}, "dependencies": [], "warnings": [], "notes": [], "findings": [fix_finding(1, "planned_change", ["echo x"])]}
        page = self.run_page(document, {"per_finding": {}, "findings_digest": assemble_findings.findings_digest(document), "summary": {}})
        self.assertEqual(page["bulk"], [])
        self.assertIn("There are no low-risk fixes to copy", page["bulkText"])

    def test_verification_section_does_not_claim_a_cli_check_that_never_ran(self):
        document = self.document()
        verification = self.verification(document)
        verification.update(cli_checked=False, cli_requested=True, cli_operations_checked=0)
        self.assertIn("there were no aws commands to check", self.run_page(document, verification)["verification"])
        verification.update(cli_checked=True, cli_operations_checked=3)
        self.assertIn("checked against the local AWS CLI help", self.run_page(document, verification)["verification"])
        verification.update(cli_checked=False, cli_requested=False, cli_operations_checked=0)
        self.assertIn("not checked", self.run_page(document, verification)["verification"])

    def test_pass_status_note_is_not_an_alert(self):
        document = self.document()
        passed = fix_finding(9, "cli", [], status="PASS")
        passed["remediation"].update(steps=[], note_status="verified in AWS: compliant, no fix needed", verify_after="echo ok")
        document["findings"].append(passed)
        self.assertNotIn("verified in AWS: compliant, no fix needed", self.run_page(document)["planned"])

    def test_template_has_a_noscript_fallback_and_new_labels(self):
        self.assertIn("<noscript>", TEMPLATE)
        block = i18n_block(TEMPLATE)
        for key in ("high_risk: 'High risk'", "missing_evidence: 'Missing evidence'", "fromVault:"):
            self.assertIn(key, block)
        self.assertNotIn("%", block)


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

    def test_line_separators_escaped(self):
        rendered = render_report.render({"findings": [{"title": "a\u2028b\u2029c"}]}, TEMPLATE)
        match = re.search(r'<script id="data" type="application/json">(.*?)</script>', rendered, re.S)
        self.assertNotIn("\u2028", match.group(1))
        self.assertNotIn("\u2029", match.group(1))
        self.assertEqual(json.loads(match.group(1))["findings"][0]["title"], "a\u2028b\u2029c")

    def test_fixture_verdict_matches_what_the_assembler_computes(self):
        recomputed = assemble_findings._summary(SAMPLE["findings"], True, [], [], True)
        for key in ("verdict", "verdict_basis", "verdict_text", "unverified"):
            self.assertEqual(SAMPLE["summary"][key], recomputed[key], key)

    def test_fixture_has_long_tokens_and_placeholder_cli_fix(self):
        findings = SAMPLE["findings"]
        long_token = [f for f in findings if f["vault_claim"] and max(map(len, f["vault_claim"].split())) >= 300]
        self.assertTrue(long_token)
        longest = lambda t: max(map(len, t.split()))
        self.assertGreaterEqual(longest(long_token[0]["remediation"]["notes"]), 300)
        self.assertGreaterEqual(max(longest(s) for s in long_token[0]["remediation"]["steps"]), 300)
        placeholder = [f for f in findings if f["status"] == "FAIL" and f["remediation"] and f["remediation"]["kind"] == "cli"
                       and f["remediation"]["risk"] == "low" and any("__FILL_IN_" in c for c in f["remediation"]["commands"])]
        self.assertTrue(placeholder)

    def test_hostile_names_escaped(self):
        hostile = [f for f in SAMPLE["findings"] if f["resource"]["name"] == HOSTILE_NAME]
        self.assertTrue(hostile, "the fixture must include a resource with a hostile name")
        rendered = render_report.render(SAMPLE, TEMPLATE)
        parser = ScriptCounter()
        parser.feed(rendered)
        self.assertEqual(len(parser.scripts), 2)
        self.assertEqual([s.get("type") for s in parser.scripts], ["application/json", None])
        self.assertEqual(parser.scripts[0].get("id"), "data")

    def test_fixture_covers_every_status_severity_and_kind(self):
        findings = SAMPLE["findings"]
        self.assertEqual({f["status"] for f in findings},
                         {"FAIL", "PASS", "DRIFT", "DOCUMENTED_ONLY", "DOCUMENTED_GAP", "UNDOCUMENTED", "NOT_VERIFIED", "N/A"})
        self.assertEqual({f["severity"] for f in findings}, {"critical", "high", "medium", "low"})
        kinds = {f["remediation"]["kind"] for f in findings if f["remediation"]}
        self.assertEqual(kinds, {"cli", "cli_with_decision", "planned_change", "console_only"})
        tags = [t for f in findings if isinstance(f["evidence"], dict) for t in (f["evidence"].get("tags") or {})]
        self.assertIn('x"onmouseover=', tags)
        self.assertTrue(any("`" in c for f in findings if f["remediation"] for c in f["remediation"]["commands"]))
        self.assertTrue(any(f["vacuous"] and f["status"] == "N/A" for f in findings))
        self.assertTrue(any(f["missing"] for f in findings if f["status"] == "NOT_VERIFIED"))
        self.assertTrue(any(not m["sourced"] for f in findings for m in f["mappings"]["tsc"] + f["mappings"]["iso27001_2022"]))

    def test_vault_path_is_reduced_to_the_folder_name(self):
        findings = copy.deepcopy(SAMPLE)
        findings["meta"]["vault"]["path"] = "/home/someone/vaults/acme-notes"
        rendered = render_report.render(findings, TEMPLATE)
        self.assertNotIn("someone", rendered)
        match = re.search(r'<script id="data" type="application/json">(.*?)</script>', rendered, re.S)
        self.assertEqual(json.loads(match.group(1))["meta"]["vault"], {"path": "acme-notes", "kind": "typed"})
        self.assertEqual(findings["meta"]["vault"]["path"], "/home/someone/vaults/acme-notes")

    def test_planned_change_banner_does_not_claim_the_commands_only_read(self):
        block = i18n_block(TEMPLATE)
        planned = re.search(r"planned: '([^']*)'", block).group(1)
        self.assertNotIn("only read", planned)
        for phrase in ("change the infrastructure", "order", "window", "automatically"):
            self.assertIn(phrase, planned)

    def test_copy_all_is_only_offered_for_cli_fixes(self):
        self.assertIn("cmds.length > 1 && rem.kind === 'cli'", TEMPLATE)

    def test_render_is_pure_and_does_not_mutate_inputs(self):
        before = json.dumps(SAMPLE, sort_keys=True)
        verification = {"per_finding": {}}
        first = render_report.render(SAMPLE, TEMPLATE)
        self.assertEqual(first, render_report.render(SAMPLE, TEMPLATE))
        render_report.render(SAMPLE, TEMPLATE, verification)
        self.assertEqual(json.dumps(SAMPLE, sort_keys=True), before)
        self.assertEqual(verification, {"per_finding": {}})

    def test_rejects_template_without_marker_and_bad_findings(self):
        with self.assertRaises(ValueError):
            render_report.render(SAMPLE, "<html></html>")
        with self.assertRaises(ValueError):
            render_report.render({"meta": {}}, TEMPLATE)


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class FinalCleanupBPageTests(PageCase):
    """Empty report wording (D2 minor 5) and organizational controls that findings touch (D2 minor 7)."""

    def test_an_empty_report_says_so_instead_of_blaming_the_filters(self):
        document = {"meta": {}, "dependencies": [], "warnings": [], "notes": [], "findings": []}
        text = self.run_page(document)["cardsText"]
        self.assertIn("No findings in this run", text)
        self.assertNotIn("filters", text)

    def test_organizational_controls_touched_by_findings_are_not_listed_as_out_of_scope(self):
        document = self.document()
        document["coverage"] = {"iso": [
            {"id": "A.5.14", "name": "Information transfer", "status": "NOT_VERIFIED", "category": "organizational"},
            {"id": "A.5.1", "name": "Policies", "status": "NOT_TOUCHED", "category": "organizational"},
            {"id": "A.8.1", "name": "Devices", "status": "PASS", "category": "technical"}], "tsc": []}
        text = self.run_page(document)["coverage"]
        self.assertIn("Organizational controls mentioned by findings", text)
        self.assertIn("Organizational: outside the scope of this report (1)", text)
        self.assertLess(text.index("A.5.14"), text.index("Organizational: outside the scope"))
        self.assertGreater(text.index("Policies"), text.index("Organizational: outside the scope"))


class FinalCleanupBRenderTests(unittest.TestCase):
    def test_a_verification_without_digest_is_stale(self):
        findings = {"meta": {}, "findings": []}
        self.assertTrue(render_report.verification_is_stale(findings, {"per_finding": {}}))
        self.assertFalse(render_report.verification_is_stale(findings, {"findings_digest": assemble_findings.findings_digest(findings)}))
        self.assertFalse(render_report.verification_is_stale(findings, None))
        html = render_report.render(findings, TEMPLATE, {"per_finding": {"F-0001": {"status": "OK"}}})
        self.assertIn('"verification_stale": true', html)
        self.assertNotIn('"per_finding"', html)

    def test_cli_names_the_missing_findings_file(self):
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = render_report.main([str(Path(tmp) / "findings.json")])
        self.assertEqual(code, 2)
        self.assertIn("findings.json", err.getvalue())
        self.assertIn("assemble_findings.py", err.getvalue())
        self.assertNotIn("Errno", err.getvalue())


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
