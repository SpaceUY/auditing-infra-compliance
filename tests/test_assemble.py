import contextlib
import copy
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import helpers
from helpers import FIXTURES_DIR, SKILL_DIR

import assemble_findings
import catalog
import vault_index

SAMPLE = FIXTURES_DIR / "run-sample"
KEY = "AKIA" + "TESTKEYABCDEMNOP"
SECRET_VALUE = "wJalr" + "XUtnFEMI/K7MDENG/bPxRfiCY" + "TESTVALUE"
SG = "sg-0a1b2c3d4e5f60718"
SG2 = "sg-0f1e2d3c4b5a69788"
META = {"platform": "Acme Notes", "mode": "full", "target": None, "lang": "es"}
STATUS_ORDER = ("FAIL", "DRIFT", "UNDOCUMENTED", "DOCUMENTED_GAP", "NO_VERIFICADO", "DOCUMENTED_ONLY", "PASS", "N/A")


class AssembleCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.run_dir = self.tmp / "run"
        shutil.copytree(SAMPLE, self.run_dir)
        self.claims = helpers.load_fixture("vault-claims.json")

    def edit_results(self, fn):
        path = self.run_dir / "checks-result.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        fn(data)
        path.write_text(json.dumps(data), encoding="utf-8")

    def assemble(self, claims=None, index=None):
        return assemble_findings.assemble(self.run_dir, index, self.claims if claims is None else claims,
                                          dict(META), SKILL_DIR)

    def find(self, out, check_id, resource_id=None, status=None):
        return [f for f in out["findings"] if f["check_id"] == check_id
                and (resource_id is None or f["resource"]["id"] == resource_id)
                and (status is None or f["status"] == status)]

    def one(self, out, check_id, resource_id=None, status=None):
        found = self.find(out, check_id, resource_id, status)
        self.assertEqual(len(found), 1, found)
        return found[0]


class OrderingTests(AssembleCase):
    def test_sort_order_and_ids(self):
        findings = self.assemble()["findings"]
        keys = [(catalog.SEVERITIES.index(f["severity"]), STATUS_ORDER.index(f["status"])) for f in findings]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual([f["id"] for f in findings], [f"F-{n:04d}" for n in range(1, len(findings) + 1)])
        self.assertEqual((findings[0]["check_id"], findings[0]["status"]), ("IAM-001", "FAIL"))
        same = [f["check_id"] for f in findings if (f["severity"], f["status"]) == ("high", "FAIL")]
        self.assertEqual(same, sorted(same))

    def test_meta_and_summary(self):
        out = self.assemble()
        self.assertEqual(out["meta"]["aws"]["account_id"], "111122223333")
        self.assertEqual(out["meta"]["catalog_checks"], len(catalog.load_checks(SKILL_DIR / "references" / "checks")))
        self.assertIsNone(out["meta"]["vault"])
        summary = out["summary"]
        self.assertEqual(summary["by_status"]["FAIL"], 5)
        self.assertEqual(summary["by_severity_fail"], {"critical": 1, "high": 3, "medium": 0, "low": 1})
        self.assertEqual(summary["drata_tests_failing"], [102, 104, 214])
        self.assertIn("MFA is enabled on the root account", summary["vanta_tests_failing"])
        self.assertEqual(summary["not_verified"], 1)
        self.assertIn("inventario incompleto: rds_instance ACCESS_DENIED en us-east-1", out["warnings"])


class SeverityTests(AssembleCase):
    def test_severity_override(self):
        finding = self.one(self.assemble(), "DAT-007", "acme-notes-uploads", "FAIL")
        self.assertEqual(finding["severity"], "low")  # catalog says critical; detail.severity_override wins
        self.assertEqual(self.one(self.assemble(), "DAT-007", "acme-notes-assets")["severity"], "critical")

    def test_breaks_tests_claim_is_high_drift(self):
        finding = self.one(self.assemble(), "NET-001", SG2, "DRIFT")
        self.assertEqual(finding["severity"], "high")  # claim asked for low
        self.assertEqual(finding["breaks_tests"], [{"tool": "drata", "test": 102}])
        self.assertEqual(finding["evaluated_by"], "claude")

    def test_breaks_tests_never_lowers_a_critical_claim(self):
        claims = [{"kind": "DOCUMENTED_GAP", "check_id": None, "severity": "critical",
                   "resource": {"type": "s3_bucket", "id": "acme-notes-assets", "region": "us-east-1"},
                   "breaks_tests": [{"tool": "vanta", "test": "x"}]}]
        finding = next(f for f in self.assemble(claims)["findings"] if f["evaluated_by"] == "claude")
        self.assertEqual((finding["status"], finding["severity"]), ("DRIFT", "critical"))

    def test_undocumented_defaults_low_and_claim_without_check(self):
        out = self.assemble()
        undocumented = next(f for f in out["findings"] if f["status"] == "UNDOCUMENTED")
        self.assertEqual((undocumented["severity"], undocumented["check_id"]), ("low", None))
        self.assertEqual(undocumented["resource"]["id"], "acme-notes-dlq")
        self.assertIsNone(undocumented["remediation"])
        self.assertEqual(self.one(out, "LOG-001")["severity"], "high")  # check severity when claim has none
        self.assertEqual(self.one(out, "DAT-007", status="DRIFT")["severity"], "critical")


class RemediationTests(AssembleCase):
    def test_remediation_placeholders_filled_and_completar_kept(self):
        out = self.assemble()
        sg = self.one(out, "NET-001", SG, "FAIL")["remediation"]
        command = sg["commands"][0]
        self.assertIn('REGION="us-east-1"', command)
        self.assertIn('ACCOUNT_ID="111122223333"', command)
        self.assertIn(f'SG_ID="{SG}"', command)
        self.assertIn("""--ip-permissions '[{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]'""",
                      command)
        self.assertIn(SG, sg["steps"][0])
        self.assertIn(f'--group-ids "{SG}" --region "us-east-1"', sg["verify_after"])
        uploads = self.one(out, "INV-001", "acme-notes-uploads")["remediation"]
        self.assertIn('RESOURCE_ARN="arn:aws:s3:::acme-notes-uploads"', uploads["commands"][0])
        self.assertIn("arn:aws:s3:::acme-notes-uploads", uploads["verify_after"])
        assets = self.one(out, "INV-001", "acme-notes-assets")["remediation"]
        self.assertIn('RESOURCE_ARN="__COMPLETAR_RESOURCE_ARN__"', assets["commands"][0])
        self.assertIn("__COMPLETAR_OWNER_EMAIL__", assets["commands"][0])
        for finding in out["findings"]:
            rem = finding["remediation"] or {}
            text = json.dumps([rem.get("steps"), rem.get("commands"), rem.get("verify_after")])
            for placeholder in ("{resource_id}", "{region}", "{account_id}", "{resource_arn}", "{detail_json:"):
                self.assertNotIn(placeholder, text, finding["id"])

    def test_missing_detail_key_leaves_marker(self):
        def drop(data):
            for r in data["results"]:
                if r["check_id"] == "NET-001" and r["status"] == "FAIL":
                    r["detail"] = {}
        self.edit_results(drop)
        command = self.one(self.assemble(), "NET-001", SG, "FAIL")["remediation"]["commands"][0]
        self.assertIn("--ip-permissions __COMPLETAR_IP_PERMISSIONS__", command)

    def test_detail_json_is_shell_quoted(self):
        def quoted(data):
            for r in data["results"]:
                if r["check_id"] == "NET-001" and r["status"] == "FAIL":
                    r["detail"] = {"ip_permissions": [{"Description": "it's open"}]}
        self.edit_results(quoted)
        command = self.one(self.assemble(), "NET-001", SG, "FAIL")["remediation"]["commands"][0]
        self.assertIn("""'[{"Description":"it'"'"'s open"}]'""", command)

    def test_fill_uses_name_and_never_formats(self):
        values = {"resource_id": "r-1", "region": "us-east-1", "account_id": "1", "resource_name": "Acme {x}",
                  "resource_arn": "a"}
        text = assemble_findings._fill('echo {resource_name} \'{"k": 1}\' {unknown} {detail_json:k}', values, {"k": [1]})
        self.assertEqual(text, 'echo Acme {x} \'{"k": 1}\' {unknown} \'[1]\'')

    def test_identifiers_are_not_email_masked_in_commands(self):
        def email_named(data):
            data["results"].append({"check_id": "DAT-007", "status": "FAIL", "resource_id": "jane@acme-notes.example",
                                    "region": "us-east-1", "detail": {}, "missing": [], "vacuous": False})
        self.edit_results(email_named)
        finding = self.one(self.assemble(), "DAT-007", "jane@acme-notes.example")
        self.assertIn('--bucket "jane@acme-notes.example"', finding["remediation"]["verify_after"])


class DependencyTests(AssembleCase):
    def test_dependencies_from_passes(self):
        out = self.assemble()
        deps = {d["resource_id"]: d for d in out["dependencies"]}
        self.assertNotIn("account", deps)
        self.assertNotIn(SG, deps)  # only FAIL rows for that group
        self.assertEqual(deps[SG2]["resource_type"], "security_group")
        tests = [(t["tool"], t["test"]) for t in deps[SG2]["tests"]]
        self.assertEqual(tests.count(("drata", 102)), 1)
        self.assertIn(("drata", 119), tests)
        self.assertIn(("vanta", "No security group allows unrestricted IPv6 ingress (::/0) to remote administration ports"),
                      tests)
        self.assertEqual(len(tests), len(set(tests)))
        self.assertIn({"tool": "drata", "test": 102, "name": "Public SSH Denied"}, deps[SG2]["tests"])
        self.assertEqual(deps["acme-notes-assets"]["tests"][0]["test"], 104)

    def test_depends_on_me_on_every_finding_of_the_resource(self):
        out = self.assemble()
        expected = {d["resource_id"]: d["tests"] for d in out["dependencies"]}
        sg2 = [f for f in out["findings"] if f["resource"]["id"] == SG2]
        self.assertGreaterEqual(len(sg2), 3)  # two PASS rows and the breaks_tests DRIFT
        for finding in sg2:
            self.assertEqual(finding["depends_on_me"], expected[SG2])
        self.assertEqual(self.one(out, "NET-001", SG, "FAIL")["depends_on_me"], [])
        self.assertEqual(self.one(out, "IAM-001")["depends_on_me"], [])

    def test_passes_are_deduplicated(self):
        def twice(data):
            data["results"] += [r for r in data["results"] if r["check_id"] == "NET-001" and r["resource_id"] == SG2]
        self.edit_results(twice)
        deps = {d["resource_id"]: d for d in self.assemble()["dependencies"]}
        tests = [(t["tool"], t["test"]) for t in deps[SG2]["tests"]]
        self.assertEqual(len(tests), len(set(tests)))


class CoverageTests(AssembleCase):
    def coverage(self, out, framework="iso"):
        return {c["id"]: c for c in out["coverage"][framework]}

    def test_coverage_worst_status_and_categories(self):
        iso = self.coverage(self.assemble())
        self.assertEqual(iso["A.8.2"]["status"], "FAIL")  # IAM-001 FAIL
        self.assertEqual(iso["A.8.16"]["status"], "FAIL")  # FAIL from IAM-001, PASS from DET-001 and NET-004
        self.assertEqual(iso["A.8.21"]["status"], "FAIL")  # NET-001 FAIL on one group, PASS on another
        self.assertEqual(iso["A.8.22"]["status"], "PASS")  # only NET-004 PASS
        self.assertEqual(iso["A.8.13"]["status"], "NO_VERIFICADO")  # DAT-001 not verified
        self.assertEqual(iso["A.8.15"]["status"], "NOT_TOUCHED")  # only an N/A row and a claim
        self.assertEqual(iso["A.7.1"]["status"], "NOT_TOUCHED")
        self.assertEqual(iso["A.7.1"]["category"], "inherited")
        self.assertEqual(iso["A.8.2"]["category"], "technical")
        self.assertEqual(iso["A.5.1"]["category"], "organizational")
        self.assertEqual(len([c for c in iso.values() if c["id"].startswith("A.")]), 93)
        self.assertTrue(all(c["name"] for c in iso.values()))

    def test_tsc_coverage(self):
        tsc = self.coverage(self.assemble(), "tsc")
        self.assertEqual(tsc["CC6.1"]["status"], "FAIL")
        self.assertEqual(tsc["A1.2"]["status"], "NO_VERIFICADO")
        self.assertEqual(tsc["CC1.1"]["status"], "NOT_TOUCHED")
        self.assertEqual(tsc["CC1.1"]["category"], "organizational")
        self.assertEqual(len(tsc), 61)

    def test_resolved_eval_pass_counts_unresolved_does_not_hide(self):
        resolved = self.coverage(self.assemble())
        self.assertEqual(resolved["A.8.3"]["status"], "PASS")
        unresolved = self.coverage(self.assemble(claims=[]))
        self.assertEqual(unresolved["A.8.3"]["status"], "NO_VERIFICADO")


class MaskingTests(AssembleCase):
    def test_findings_are_masked(self):
        def leaky(data):
            for r in data["results"]:
                if r["check_id"] == "IAM-001":
                    r["detail"] = {"note": f"clave {KEY}", "contacto": "jane@acme-notes.example",
                                   "dueño": "owner@acme-notes.example"}
            data["warnings"].append(f"se vio {KEY} y jane@acme-notes.example")
        self.edit_results(leaky)
        claims = copy.deepcopy(self.claims)
        claims[0]["vault_claim"] = "usar aws_secret" + f"_access_key={SECRET_VALUE} y {KEY}"
        claims[0]["actual"] = f"ver jane@acme-notes.example {KEY}"
        text = json.dumps(self.assemble(claims), ensure_ascii=False)
        self.assertNotIn(KEY, text)
        self.assertNotIn(SECRET_VALUE, text)
        self.assertNotIn("jane@acme-notes.example", text)
        self.assertIn("AKIA…MNOP", text)
        self.assertIn("j***@acme-notes.example", text)
        self.assertIn("owner@acme-notes.example", text)  # VantaOwner values from the inventory are kept

    def test_secret_in_vault_creates_critical_finding_without_value(self):
        vault = self.tmp / "vault"
        vault.mkdir()
        helpers.make_secret_note(vault)
        index = vault_index.build_index(vault)
        out = self.assemble(claims=[], index=index)
        secret = next(f for f in out["findings"] if f["title"] == "Credenciales en texto plano en el vault")
        self.assertEqual((secret["check_id"], secret["severity"], secret["status"]), (None, "critical", "FAIL"))
        self.assertEqual(set(secret["evidence"]), {"path", "pattern"})
        self.assertEqual(secret["evidence"]["path"], "secret-note.md")
        self.assertEqual(out["findings"][0]["id"], "F-0001")
        self.assertEqual((out["findings"][0]["severity"], out["findings"][0]["status"]), ("critical", "FAIL"))
        text = json.dumps(out)
        self.assertNotIn(KEY, text)
        self.assertNotIn("TESTKEYABCDEMNOP", text)
        self.assertEqual(out["meta"]["vault"], {"path": index["root"], "kind": "free"})
        self.assertTrue(any("secret-note.md" in w for w in out["warnings"]))

    def test_broken_links_become_warnings(self):
        index = {"kind": "typed", "root": "/v", "notes": [], "secrets_detected": [],
                 "broken_links": [{"from": "systems/A.md", "target": "Nope"}]}
        self.assertIn("link roto en systems/A.md: [[Nope]]", self.assemble(claims=[], index=index)["warnings"])


class EvalTests(AssembleCase):
    def test_eval_claim_resolves_pending(self):
        out = self.assemble()
        found = self.find(out, "IAM-013")
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0]["status"], found[0]["evaluated_by"]), ("PASS", "claude"))
        self.assertEqual(found[0]["evidence"], {"reason": "Las políticas administrativas están acotadas a un rol de emergencia"})
        self.assertFalse(any("IAM-013" in w for w in out["warnings"]))

    def test_eval_claim_can_fail_with_override_and_resource(self):
        claims = [{"kind": "EVAL", "check_id": "IAM-013", "resource": {"type": "iam_role", "id": "acme-admin"},
                   "status": "FAIL", "detail": {"severity_override": "critical", "policy": "*:*"}}]
        finding = self.one(self.assemble(claims), "IAM-013")
        self.assertEqual((finding["status"], finding["severity"], finding["resource"]["id"]),
                         ("FAIL", "critical", "acme-admin"))

    def test_pending_claude_unresolved_becomes_not_verified(self):
        out = self.assemble(claims=[])
        finding = self.one(out, "IAM-013")
        self.assertEqual((finding["status"], finding["evaluated_by"]), ("NO_VERIFICADO", "script"))
        self.assertTrue(any("IAM-013" in w for w in out["warnings"]))
        self.assertNotIn("PENDING_CLAUDE", {f["status"] for f in out["findings"]})

    def test_invalid_eval_status_is_not_verified(self):
        claims = [{"kind": "EVAL", "check_id": "IAM-013", "status": "MAYBE", "detail": {}}]
        out = self.assemble(claims)
        self.assertEqual(self.one(out, "IAM-013")["status"], "NO_VERIFICADO")
        self.assertTrue(any("MAYBE" in w for w in out["warnings"]))

    def test_orphan_eval_claim_warns(self):
        claims = [{"kind": "EVAL", "check_id": "IAM-014", "status": "PASS"}]
        self.assertTrue(any("IAM-014" in w for w in self.assemble(claims)["warnings"]))


class NoAwsTests(AssembleCase):
    def test_no_aws_only_documented_findings(self):
        self.edit_results(lambda data: data.update(aws=None, results=[], warnings=["sin credenciales AWS válidas"]))
        out = self.assemble()
        self.assertIsNone(out["meta"]["aws"])
        self.assertTrue({f["status"] for f in out["findings"]} <= {"DRIFT", "UNDOCUMENTED", "DOCUMENTED_ONLY",
                                                                  "DOCUMENTED_GAP"})
        self.assertIn("sin credenciales AWS válidas", out["warnings"])
        self.assertTrue(any("IAM-013" in w for w in out["warnings"]))  # EVAL claim with nothing to resolve
        self.assertEqual(out["dependencies"], [])
        remediation = self.one(out, "NET-001", SG2)["remediation"]
        self.assertIn('ACCOUNT_ID="__COMPLETAR_ACCOUNT_ID__"', remediation["commands"][0])

    def test_missing_checks_result_file(self):
        (self.run_dir / "checks-result.json").unlink()
        (self.run_dir / "inventory.json").unlink()
        out = self.assemble()
        self.assertIsNone(out["meta"]["aws"])
        self.assertTrue(out["findings"])


class NoPercentageTests(AssembleCase):
    def test_no_percentage_anywhere(self):
        text = json.dumps(self.assemble())
        self.assertNotIn("%", text)

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    self.assertNotRegex(key.lower(), r"score|compliance|percent")
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)
        walk(json.loads(text))


class CliTests(AssembleCase):
    def test_cli_writes_findings_json(self):
        vault = self.tmp / "vault"
        vault.mkdir()
        helpers.make_secret_note(vault)
        index_path = self.tmp / "vault-index.json"
        index_path.write_text(json.dumps(vault_index.build_index(vault)), encoding="utf-8")
        claims_path = self.tmp / "vault-claims.json"
        claims_path.write_text(json.dumps(self.claims), encoding="utf-8")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = assemble_findings.main(["--run-dir", str(self.run_dir), "--vault-index", str(index_path),
                                           "--vault-claims", str(claims_path), "--platform", "Acme Notes",
                                           "--mode", "full"])
        self.assertEqual(code, 0)
        out = json.loads((self.run_dir / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(out["meta"]["platform"], "Acme Notes")
        self.assertEqual(out["meta"]["lang"], "es")
        self.assertIsNotNone(out["meta"]["vault"])
        self.assertRegex(out["meta"]["generated_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d$")
        self.assertLess(len(stdout.getvalue().splitlines()), 5)

    def test_cli_rejects_missing_run_dir(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code = assemble_findings.main(["--run-dir", str(self.tmp / "nope"), "--platform", "x", "--mode", "full"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
