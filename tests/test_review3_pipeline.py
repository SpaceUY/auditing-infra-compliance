"""Review 3, pipeline findings: scope resolution (I-1), whole-finding digest (I-2), failing DRIFT/UNDOCUMENTED in counters (M-2),
actual_status only on DRIFT/UNDOCUMENTED (M-3), claim text validation (M-4), per-report filter storage (M-7), masking of scope text
and run/output folders inside the vault (safety review)."""

import contextlib
import copy
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import helpers
from helpers import SKILL_DIR

import assemble_findings
import render_report
import test_assemble
import test_render
import verify_remediation

SG_WEB = "sg-0f1e2d3c4b5a69788"
RESOURCE = {"type": "rds_instance", "id": "acme-notes-db", "region": "us-east-1"}
HASH_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/acme-web/50dc6c495c0c9188"


class PipelineCase(test_assemble.AssembleCase):
    def only(self, *keep):
        def prune(data):
            data["results"] = [r for r in data["results"] if (r["check_id"], r["resource_id"]) in keep]
            data["warnings"] = []
        self.edit_results(prune)

    def write_scope(self, *resources):
        (self.run_dir / "scope.json").write_text(json.dumps({
            "platform": "Acme Notes", "mode": "resource", "target": "x", "regions": ["us-east-1"],
            "resources": [{"type": t, "id": i, "region": "us-east-1"} for t, i in resources]}), encoding="utf-8")

    def drift(self, **extra):
        return {"kind": "DRIFT", "check_id": "ENC-003", "resource": RESOURCE, "actual_status": "FAIL", "severity": "high", **extra}

    def run_cli(self, *args):
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            code = assemble_findings.main(list(args))
        return code, err.getvalue()


class ScopeResolutionTests(PipelineCase):
    def set_arn(self, arn):
        path = self.run_dir / "inventory.json"
        inventory = json.loads(path.read_text(encoding="utf-8"))
        for item in inventory:
            if item["id"] == SG_WEB:
                item["arn"] = arn
        path.write_text(json.dumps(inventory), encoding="utf-8")

    def test_a_component_given_by_an_arn_the_inventory_resolves_is_not_unverified(self):
        self.set_arn(HASH_ARN)
        self.only(("NET-001", SG_WEB), ("DET-001", "account"))
        self.write_scope(("security_group", HASH_ARN))
        out = self.assemble([])
        self.assertEqual(out["unverified_scope"], [])
        self.assertEqual(out["summary"]["verdict"], "OPTIMAL")

    def test_a_scope_arn_the_inventory_does_not_know_is_still_listed(self):
        self.set_arn(HASH_ARN)
        self.only(("NET-001", SG_WEB), ("DET-001", "account"))
        self.write_scope(("security_group", HASH_ARN.replace("acme-web", "other")))
        self.assertEqual([u["id"] for u in self.assemble([])["unverified_scope"]], [HASH_ARN.replace("acme-web", "other")])

    def test_the_inventory_match_needs_the_same_type(self):
        self.set_arn(HASH_ARN)
        self.only(("NET-001", SG_WEB), ("DET-001", "account"))
        self.write_scope(("s3_bucket", HASH_ARN))
        self.assertEqual(len(self.assemble([])["unverified_scope"]), 1)


class DigestTests(PipelineCase):
    def test_digest_changes_with_every_field_the_verification_reads(self):
        out = self.assemble()
        digest = assemble_findings.findings_digest(out)
        net = next(i for i, f in enumerate(out["findings"]) if f["check_id"] == "NET-001" and f["status"] == "FAIL")
        mutations = [
            lambda f: f.update(severity="low"),
            lambda f: f.update(depends_on_me=[{"tool": "drata", "test": 1, "name": "x"}]),
            lambda f: f["evidence"].update(ssm_unreachable=True, attachments=[{"instance_id": "i-0a1b2c3d4e5f60718"}]),
            lambda f: f["resource"].update(region="eu-west-1"),
            lambda f: f["resource"].update(type="other"),
            lambda f: f.update(actual_status="FAIL"),
        ]
        for mutate in mutations:
            other = copy.deepcopy(out)
            mutate(other["findings"][net])
            self.assertNotEqual(assemble_findings.findings_digest(other), digest)

    def test_a_verification_computed_before_an_evidence_change_is_stale(self):
        out = self.assemble()
        verification = {"findings_digest": assemble_findings.findings_digest(out)}
        self.assertFalse(render_report.verification_is_stale(out, verification))
        out["findings"][0]["evidence"] = {**out["findings"][0]["evidence"], "ssm_unreachable": False}
        self.assertTrue(render_report.verification_is_stale(out, verification))

    def test_the_digest_survives_a_json_round_trip(self):
        out = self.assemble()
        self.assertEqual(assemble_findings.findings_digest(json.loads(json.dumps(out))), assemble_findings.findings_digest(out))

    def test_verification_written_by_verify_matches_the_digest_of_the_same_findings(self):
        out = self.assemble()
        result = verify_remediation.verify(out, [], [])
        self.assertEqual(result["findings_digest"], assemble_findings.findings_digest(out))


class FailingDriftTests(PipelineCase):
    def setUp(self):
        super().setUp()
        self.only(("DET-001", "account"))

    def test_a_drift_that_fails_counts_in_the_failure_summary_and_coverage(self):
        out = self.assemble([self.drift()])
        finding = next(f for f in out["findings"] if f["status"] == "DRIFT")
        self.assertEqual(out["summary"]["verdict"], "NOT_OPTIMAL")
        self.assertEqual(out["summary"]["by_severity_fail"]["high"], 1)
        wanted = {t["test"] for t in finding["mappings"]["drata"]}
        self.assertTrue(wanted)
        self.assertEqual(set(out["summary"]["drata_tests_failing"]), wanted)
        self.assertEqual(set(out["summary"]["vanta_tests_failing"]), {m["test"] for m in finding["mappings"]["vanta"]})
        iso = {e["id"]: e["status"] for e in out["coverage"]["iso"]}
        tsc = {e["id"]: e["status"] for e in out["coverage"]["tsc"]}
        self.assertTrue(finding["mappings"]["iso27001_2022"] and finding["mappings"]["tsc"])
        self.assertTrue(all(iso[m["id"]] == "FAIL" for m in finding["mappings"]["iso27001_2022"]))
        self.assertTrue(all(tsc[m["id"]] == "FAIL" for m in finding["mappings"]["tsc"]))
        self.assertEqual(out["summary"]["by_status"]["DRIFT"], 1)  # the status itself stays DRIFT

    def test_an_undocumented_that_fails_counts_too(self):
        claim = {"kind": "UNDOCUMENTED", "check_id": "ENC-003", "resource": RESOURCE, "actual_status": "FAIL", "severity": "medium"}
        self.assertEqual(self.assemble([claim])["summary"]["by_severity_fail"]["medium"], 1)

    def test_a_drift_that_does_not_fail_counts_nowhere(self):
        out = self.assemble([self.drift(actual_status="PASS")])
        self.assertEqual(sum(out["summary"]["by_severity_fail"].values()), 0)
        self.assertEqual(out["summary"]["drata_tests_failing"], [])
        self.assertNotIn("FAIL", {e["status"] for e in out["coverage"]["iso"]})


class ActualStatusKindTests(PipelineCase):
    def setUp(self):
        super().setUp()
        self.only(("DET-001", "account"))

    def test_documented_only_ignores_actual_status_and_warns(self):
        claim = {"kind": "DOCUMENTED_ONLY", "check_id": "ENC-003", "resource": RESOURCE, "actual_status": "FAIL"}
        out = self.assemble([claim])
        finding = self.one(out, "ENC-003")
        self.assertIsNone(finding["actual_status"])
        self.assertNotEqual(out["summary"]["verdict"], "NOT_OPTIMAL")
        self.assertEqual(sum(out["summary"]["by_severity_fail"].values()), 0)
        self.assertTrue(any("actual_status FAIL ignored" in w and "DOCUMENTED_ONLY" in w for w in out["warnings"]), out["warnings"])

    def test_documented_gap_low_ignores_actual_status(self):
        claim = {"kind": "DOCUMENTED_GAP", "check_id": "ENC-003", "resource": RESOURCE, "actual_status": "FAIL", "severity": "low"}
        out = self.assemble([claim])
        self.assertNotEqual(out["summary"]["verdict"], "NOT_OPTIMAL")
        self.assertIsNone(self.one(out, "ENC-003")["actual_status"])

    def test_breaks_tests_promoted_drift_keeps_actual_status(self):
        claim = {"kind": "DOCUMENTED_ONLY", "check_id": "ENC-003", "resource": RESOURCE, "actual_status": "FAIL",
                 "breaks_tests": [{"tool": "drata", "test": 30}]}
        out = self.assemble([claim])
        self.assertEqual(out["summary"]["verdict"], "NOT_OPTIMAL")
        self.assertEqual(self.one(out, "ENC-003")["actual_status"], "FAIL")

    def test_a_vault_only_documented_only_claim_with_actual_fail_is_not_optimal_no_more(self):
        self.edit_results(lambda data: data.update(aws=None, results=[], warnings=[]))
        claim = {"kind": "DOCUMENTED_ONLY", "check_id": "ENC-003", "resource": RESOURCE, "actual_status": "FAIL"}
        self.assertNotEqual(self.assemble([claim])["summary"]["verdict"], "NOT_OPTIMAL")


class ClaimTextValidationTests(PipelineCase):
    def test_non_text_claim_fields_are_an_error_not_a_traceback(self):
        for field, value in (("vault_claim", ["a", "b"]), ("vault_claim", 5), ("vault_note", 3), ("actual", {"x": 1})):
            claims = self.tmp / "claims.json"
            claims.write_text(json.dumps([{"kind": "UNDOCUMENTED", "check_id": None, field: value}]), encoding="utf-8")
            code, err = self.run_cli("--run-dir", str(self.run_dir), "--vault-claims", str(claims), "--platform", "p", "--mode", "full")
            self.assertEqual(code, 2, (field, value))
            self.assertTrue(err.startswith("error:"), err)
            self.assertIn(field if field != "actual" else "actual", err)
            self.assertNotIn("Traceback", err)

    def test_null_or_text_values_are_fine(self):
        claims = self.tmp / "claims.json"
        claims.write_text(json.dumps([{"kind": "UNDOCUMENTED", "check_id": None, "vault_claim": None, "vault_note": "n.md",
                                       "actual": "text"}]), encoding="utf-8")
        code, _ = self.run_cli("--run-dir", str(self.run_dir), "--vault-claims", str(claims), "--platform", "p", "--mode", "full")
        self.assertEqual(code, 0)


class MaskingTests(PipelineCase):
    SECRET = "hunter2" + "Zq9xyz"

    def test_scope_text_is_masked_in_summary_reasons_and_unverified_scope(self):
        self.only(("DET-001", "account"))
        self.write_scope(("rds_instance", f"db password: {self.SECRET}"))
        out = self.assemble([])
        self.assertTrue(out["unverified_scope"])
        self.assertNotIn(self.SECRET, json.dumps(out))

    def test_emails_in_identifiers_are_kept_as_before(self):
        self.only(("DET-001", "account"))
        self.write_scope(("iam_user", "jane@acme-notes.example"))
        self.assertIn("jane@acme-notes.example", json.dumps(self.assemble([])["unverified_scope"]))


class InsideVaultTests(PipelineCase):
    def setUp(self):
        super().setUp()
        self.vault = self.tmp / "vault"
        self.vault.mkdir()
        (self.vault / "Note.md").write_text("# Note\nText.\n", encoding="utf-8")
        self.index_path = self.tmp / "vault-index.json"

    def index(self, root=None):
        index = {"kind": "free", "root": str(root or self.vault), "notes": [], "broken_links": [], "secrets_detected": [],
                 "sensitive_files": []}
        self.index_path.write_text(json.dumps(index), encoding="utf-8")
        return self.index_path

    def test_assemble_refuses_a_run_dir_inside_the_vault(self):
        inside = self.vault / "reports" / "run"
        shutil.copytree(self.run_dir, inside)
        code, err = self.run_cli("--run-dir", str(inside), "--vault-index", str(self.index()), "--platform", "p", "--mode", "full")
        self.assertEqual(code, 2)
        self.assertTrue(err.startswith("error:") and "inside the vault" in err, err)
        self.assertFalse((inside / "findings.json").exists())

    def test_assemble_accepts_a_run_dir_next_to_the_vault(self):
        code, err = self.run_cli("--run-dir", str(self.run_dir), "--vault-index", str(self.index()), "--platform", "p", "--mode", "full")
        self.assertEqual(code, 0, err)

    def test_render_refuses_an_output_inside_the_vault_recorded_next_to_the_findings(self):
        self.assertEqual(self.run_cli("--run-dir", str(self.run_dir), "--platform", "p", "--mode", "full")[0], 0)
        (self.run_dir / "vault-index.json").write_text(self.index(self.tmp).read_text(encoding="utf-8"), encoding="utf-8")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = render_report.main([str(self.run_dir / "findings.json"), "-o", str(self.vault / "report.html")])
        self.assertEqual(code, 2)
        self.assertTrue(err.getvalue().startswith("error:") and "inside the vault" in err.getvalue(), err.getvalue())
        self.assertFalse((self.vault / "report.html").exists())

    def test_render_writes_outside_the_vault(self):
        self.run_cli("--run-dir", str(self.run_dir), "--platform", "p", "--mode", "full")
        (self.run_dir / "vault-index.json").write_text(self.index().read_text(encoding="utf-8"), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(render_report.main([str(self.run_dir / "findings.json")]), 0)
        self.assertTrue((self.run_dir / "report.html").is_file())


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class TemplateTests(test_render.PageCase):
    def run_with_storage(self, document, storage):
        path = self.tmp / "report.html"
        path.write_text(render_report.render(document, test_render.TEMPLATE), encoding="utf-8")
        done = subprocess.run(["node", str(Path(helpers.ROOT / "tests" / "dom_smoke.js")), str(path)], capture_output=True, text=True,
                              timeout=60, check=False, env={"PATH": "/usr/bin:/bin:/usr/local/bin", "DOM_LOCAL_STORAGE": json.dumps(storage)})
        self.assertEqual(done.returncode, 0, done.stderr)
        return json.loads(done.stdout)

    @staticmethod
    def report(meta):
        document = test_render.PageCase.document()
        document["meta"] = {"aws": {}, **meta}
        return document

    def test_failing_drift_counts_in_the_page_counters(self):
        document = self.report({})
        drift = test_render.fix_finding(9, "cli", ["echo x"])
        drift.update(status="DRIFT", actual_status="FAIL", severity="critical",
                     mappings={"drata": [{"test": 777, "name": "Drift test"}], "vanta": []})
        document["findings"] = [drift]
        page = self.run_page(document)
        self.assertIn("Critical: 1", page["summary"])
        self.assertIn("777", page["summary"])
        drift["actual_status"] = None
        page = self.run_page(document)
        self.assertIn("Critical: 0", page["summary"])
        self.assertNotIn("777", page["summary"])

    def test_filters_are_stored_per_report(self):
        first = self.report({"generated_at": "2026-11-01T10:00:00+00:00", "platform": "Acme"})
        second = self.report({"generated_at": "2026-11-02T10:00:00+00:00", "platform": "Acme"})
        stored = self.run_with_storage(first, {})
        self.assertEqual(stored["storage"], {})  # nothing saved just by opening
        key = "iac-report-filters-v2:" + "|".join(["2026-11-01T10:00:00+00:00", "Acme", "undefined", "undefined", "undefined"])
        other = self.run_with_storage(first, {key: json.dumps({"status": "FAIL"})})
        self.assertEqual(other["statusFilter"], "FAIL")  # its own filter is restored
        again = self.run_with_storage(second, {key: json.dumps({"status": "FAIL"})})
        self.assertEqual(again["statusFilter"], "")  # another report's filter does not apply

    def test_the_tool_option_wins_over_a_stored_filter(self):
        document = self.report({"generated_at": "2026-11-01T10:00:00+00:00", "tool": "vanta"})
        key = "iac-report-filters-v2:" + "|".join(["2026-11-01T10:00:00+00:00", "undefined", "undefined", "undefined", "undefined"])
        for tool in ("drata", ""):
            saved = json.dumps({"tool": tool, "status": ""})
            page = self.run_with_storage(document, {key: saved, "iac-report-filters-v1": saved})
            self.assertEqual(page["toolFilter"], "vanta", tool)


if __name__ == "__main__":
    unittest.main()
