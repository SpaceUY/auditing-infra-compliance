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
        text = assemble_findings._fill('echo {resource_name} \'{"k": 1}\' {unknown} {detail_json:k}', values, {"k": [1]}, set())
        self.assertEqual(text, 'echo Acme {x} \'{"k": 1}\' {unknown} \'[1]\'')

    def test_identifiers_are_not_email_masked_in_commands(self):
        def email_named(data):
            data["results"].append({"check_id": "DAT-007", "status": "FAIL", "resource_id": "jane@acme-notes.example",
                                    "region": "us-east-1", "detail": {}, "missing": [], "vacuous": False})
        self.edit_results(email_named)
        finding = self.one(self.assemble(), "DAT-007", "jane@acme-notes.example")
        self.assertIn('--bucket "jane@acme-notes.example"', finding["remediation"]["verify_after"])


HOSTILE_IDS = ['x$(touch /tmp/PWNED)`id`"; echo hi #', 'a"b', "a'b", "a b", "a`id`b", "a\nb", "a\n", "$HOME", "a;b",
               "a|b", "a\\b", "a" * 513]
SAFE_IDS = ["arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
            "https://sqs.us-east-1.amazonaws.com/111122223333/q", "ses@acme-notes.example", "/aws/lambda/x",
            "acme-notes-assets"]


class InjectionTests(AssembleCase):
    def add_row(self, resource_id, region="us-east-1", check="DAT-007", status="FAIL"):
        def add(data):
            data["results"].append({"check_id": check, "status": status, "resource_id": resource_id, "region": region,
                                    "detail": {}, "missing": [], "vacuous": False})
        self.edit_results(add)

    def test_hostile_identifiers_become_markers_with_warning(self):
        for hostile in HOSTILE_IDS:
            with self.subTest(hostile=hostile[:30]):
                self.setUp()
                self.add_row(hostile)
                out = self.assemble(claims=[])
                finding = self.one(out, "DAT-007", hostile, "FAIL")
                rem = finding["remediation"]
                text = json.dumps([rem["steps"], rem["commands"], rem["verify_after"], rem["notes"]])
                self.assertIn("__COMPLETAR_RESOURCE_ID__", rem["commands"][1])
                self.assertIn("__COMPLETAR_RESOURCE_ID__", rem["verify_after"])
                self.assertNotIn(json.dumps(hostile)[1:-1], text)
                self.assertIn(f"{finding['id']}: identificador con caracteres no seguros, completar a mano",
                              out["warnings"])

    def test_probe_is_not_live_command_substitution(self):
        probe = 'x$(touch /tmp/PWNED)`id`"; echo hi #'
        self.add_row(probe)
        rem = self.one(self.assemble(claims=[]), "DAT-007", probe)["remediation"]
        for command in (*rem["commands"], rem["verify_after"]):
            self.assertNotIn("$(", command)
            self.assertNotIn("PWNED", command)

    def test_safe_identifiers_pass_unchanged(self):
        for safe in SAFE_IDS:
            with self.subTest(safe=safe):
                self.setUp()
                self.add_row(safe)
                out = self.assemble(claims=[])
                rem = self.one(out, "DAT-007", safe, "FAIL")["remediation"]
                self.assertIn(f'--bucket "{safe}"', rem["verify_after"])
                self.assertNotIn("__COMPLETAR_RESOURCE_ID__", json.dumps(rem))
                self.assertFalse([w for w in out["warnings"] if "no seguros" in w])

    def test_unsafe_value_not_used_by_the_check_raises_no_warning(self):
        self.edit_results(lambda data: data.update(results=[r for r in data["results"] if r["check_id"] == "IAM-001"]))
        (self.run_dir / "inventory.json").write_text(json.dumps([
            {"type": "s3_bucket", "id": "b", "arn": "", "name": "<b>x y</b>", "region": "us-east-1", "tags": {}}]),
            encoding="utf-8")
        self.assertFalse([w for w in self.assemble(claims=[])["warnings"] if "no seguros" in w])

    def test_unsafe_region_and_account_id(self):
        self.add_row("acme-notes-assets", region='us-east-1"; id #')
        out = self.assemble(claims=[])
        finding = self.one(out, "DAT-007", "acme-notes-assets", "FAIL")
        self.assertIn('REGION="__COMPLETAR_REGION__"', finding["remediation"]["commands"][0])
        self.assertIn(f"{finding['id']}: identificador con caracteres no seguros, completar a mano", out["warnings"])

        self.setUp()
        self.edit_results(lambda data: data["aws"].update(account_id="1111; rm -rf ~"))
        out = self.assemble(claims=[])
        command = self.one(out, "DAT-007", "acme-notes-uploads", "FAIL")["remediation"]["commands"][0]
        self.assertIn('ACCOUNT_ID="__COMPLETAR_ACCOUNT_ID__"', command)
        self.assertTrue([w for w in out["warnings"] if "no seguros" in w])

    def test_safe_values_rules(self):
        env = assemble_findings.Env({}, {}, [], "111122223333", frozenset(), {})
        resource = {"type": "s3_bucket", "id": "my bucket", "region": "eu-west-1", "name": "ok-name"}
        values, bad = assemble_findings._safe_values(env, None, resource, "arn:aws:s3:::my$bucket")
        self.assertEqual(bad, {"resource_id", "resource_arn"})
        self.assertEqual((values["region"], values["resource_name"], values["account_id"]),
                         ("eu-west-1", "ok-name", "111122223333"))
        self.assertEqual(values["resource_arn"], "__COMPLETAR_RESOURCE_ARN__")
        resource["name"] = "two words"
        self.assertEqual(assemble_findings._safe_values(env, None, resource, None)[0]["resource_name"],
                         "__COMPLETAR_RESOURCE_NAME__")

    def test_notes_are_filled_with_the_same_rules(self):
        out = self.assemble(claims=[])
        notes = self.one(out, "INV-001", "acme-notes-uploads")["remediation"]["notes"]
        self.assertIn("arn:aws:s3:::acme-notes-uploads es el ARN del recurso acme-notes-uploads", notes)
        self.assertNotIn("{resource_arn}", notes)
        net = self.one(out, "NET-001", SG, "FAIL")["remediation"]["notes"]
        self.assertIn('"IpProtocol":"tcp"', net)
        self.assertNotIn("{detail_json", net)
        self.add_row("x$(id)", check="INV-001")
        hostile = self.one(self.assemble(claims=[]), "INV-001", "x$(id)")["remediation"]["notes"]
        self.assertNotIn("$(id)", hostile)
        self.assertIn("__COMPLETAR_RESOURCE_ID__", hostile)


class Round1Tests(AssembleCase):
    def test_eval_claim_honours_explicit_severity(self):
        claims = [{"kind": "EVAL", "check_id": "IAM-013", "status": "FAIL", "severity": "critical", "detail": {}}]
        self.assertEqual(self.one(self.assemble(claims), "IAM-013")["severity"], "critical")
        claims[0]["detail"] = {"severity_override": "low"}
        self.assertEqual(self.one(self.assemble(claims), "IAM-013")["severity"], "low")  # override still wins
        claims[0].update(detail={}, severity=None)
        self.assertEqual(self.one(self.assemble(claims), "IAM-013")["severity"], "medium")  # catalog

    def test_identity_arn_is_masked(self):
        self.edit_results(lambda data: data["aws"].update(
            identity_arn="arn:aws:sts::111122223333:assumed-role/audit/jane@acme-notes.example"))
        arn = self.assemble()["meta"]["aws"]["identity_arn"]
        self.assertNotIn("jane@", arn)
        self.assertIn("j***@acme-notes.example", arn)

    def test_claim_for_regional_resource_without_region_gets_marker(self):
        def claim(check, rtype, rid):
            return {"kind": "DOCUMENTED_GAP", "check_id": check, "resource": {"type": rtype, "id": rid, "region": None}}
        out = self.assemble([claim("NET-001", "security_group", "sg-0123456789abcdef0")])
        finding = self.one(out, "NET-001", "sg-0123456789abcdef0")
        self.assertIn('REGION="__COMPLETAR_REGION__"', finding["remediation"]["commands"][0])
        self.assertFalse([w for w in out["warnings"] if "no seguros" in w])  # a missing value is not unsafe
        # global types, account rows and account-level claims keep us-east-1
        bucket = self.one(self.assemble([claim("DAT-007", "s3_bucket", "acme-notes-claimed")]), "DAT-007",
                          "acme-notes-claimed")
        self.assertIn('REGION="us-east-1"', bucket["remediation"]["commands"][0])
        account = self.one(self.assemble(), "LOG-001")
        self.assertIn('REGION="us-east-1"', account["remediation"]["commands"][0])


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
        self.assertEqual(iso["A.8.15"]["status"], "NO_VERIFICADO")  # an N/A row and a DOCUMENTED_GAP claim: the vault says so, nothing checked it
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
        self.assertEqual(out["meta"]["vault"], {"path": "vault", "kind": "free"})  # folder name only, never the absolute path
        self.assertNotIn(str(self.tmp), text)
        self.assertTrue(any("secret-note.md" in w for w in out["warnings"]))

    def test_sensitive_file_by_name_creates_critical_fail_finding(self):
        index = {"kind": "free", "root": "/v", "notes": [], "secrets_detected": [], "broken_links": [],
                 "sensitive_files": [{"path": ".env", "reason": "archivo .env"}]}
        out = self.assemble(claims=[], index=index)
        found = [f for f in out["findings"] if f["resource"]["id"] == ".env"]
        self.assertEqual(len(found), 1)
        finding = found[0]
        self.assertEqual((finding["check_id"], finding["status"], finding["severity"]), (None, "FAIL", "critical"))
        self.assertEqual(finding["evidence"], {"path": ".env", "detection": "nombre de archivo"})
        self.assertEqual((finding["remediation"]["kind"], finding["remediation"]["commands"]), ("console_only", []))
        self.assertEqual(out["findings"][0]["id"], "F-0001")
        self.assertGreaterEqual(out["summary"]["by_severity_fail"]["critical"], 1)
        self.assertTrue(any(".env" in w for w in out["warnings"]))

    def test_sensitive_names_that_may_be_templates_or_public_certs_carry_a_review_hint(self):
        hint = "revisar: puede ser una plantilla o un certificado público"
        paths = [".env.example", "ops/server.pem", "docs/AWS-Credentials.md", ".env", "id.key", "notes/credentials.txt"]
        index = {"kind": "free", "root": "/v", "notes": [], "secrets_detected": [], "broken_links": [],
                 "sensitive_files": [{"path": p, "reason": "x"} for p in paths]}
        out = self.assemble(claims=[], index=index)
        by_path = {f["resource"]["id"]: f["remediation"] for f in out["findings"] if f["resource"]["type"] == "vault_note"}
        for path in (".env.example", "ops/server.pem", "docs/AWS-Credentials.md"):
            self.assertEqual(sum(hint in step for step in by_path[path]["steps"]), 1, path)
        for path in (".env", "id.key", "notes/credentials.txt"):
            self.assertFalse(any(hint in step for step in by_path[path]["steps"]), path)
        self.assertEqual(len(by_path[".env"]["steps"]), 3)

    def test_breaks_tests_and_meta_are_masked(self):
        claims = [{"kind": "DRIFT", "check_id": None, "severity": None, "resource": None,
                   "breaks_tests": [{"tool": "drata", "name": "aws_secret" + f"_access_key={SECRET_VALUE} {KEY} jane@acme-notes.example"}]}]
        meta = {**META, "platform": f"Acme {KEY}", "target": "jane@acme-notes.example"}
        out = assemble_findings.assemble(self.run_dir, None, claims, meta, SKILL_DIR)
        text = json.dumps(out)
        for leaked in (KEY, SECRET_VALUE, "jane@acme-notes.example"):
            self.assertNotIn(leaked, text)
        self.assertEqual((out["meta"]["platform"], out["meta"]["target"]), ("Acme AKIA…MNOP", "j***@acme-notes.example"))
        self.assertEqual(self.assemble([])["meta"]["target"], None)

    def test_broken_links_become_warnings(self):
        index = {"kind": "typed", "root": "/v", "notes": [], "secrets_detected": [],
                 "broken_links": [{"from": "systems/A.md", "target": "Nope"}]}
        self.assertIn("link roto en systems/A.md: [[Nope]]", self.assemble(claims=[], index=index)["warnings"])


class PartialRunTests(AssembleCase):
    def test_partial_run_becomes_a_warning_with_the_pending_checks(self):
        self.edit_results(lambda data: data.update(partial=True, pending_checks=["LOG-002", "IAM-001"]))
        warnings = self.assemble()["warnings"]
        partial = [w for w in warnings if "parcial" in w.lower()]
        self.assertEqual(len(partial), 1, warnings)
        self.assertIn("IAM-001, LOG-002", partial[0])  # sorted
        self.assertRegex(partial[0], r"(?i)volver a correr|re-?ejecutar|correr de nuevo")

    def test_partial_run_without_pending_list_still_warns(self):
        self.edit_results(lambda data: data.update(partial=True))
        self.assertTrue(any("parcial" in w.lower() for w in self.assemble()["warnings"]))

    def test_complete_run_has_no_partial_warning(self):
        warnings = self.assemble()["warnings"]
        self.assertFalse([w for w in warnings if "parcial" in w.lower() or "SCP" in w])

    def test_blocked_regions_become_a_warning(self):
        self.edit_results(lambda data: data["aws"].update(blocked_regions=["sa-east-1", "af-south-1"]))
        warnings = self.assemble()["warnings"]
        blocked = [w for w in warnings if "bloqueado por SCP" in w]
        self.assertEqual(len(blocked), 1, warnings)
        self.assertIn("af-south-1, sa-east-1", blocked[0])
        self.assertIn("no se verificaron", blocked[0])

    def test_empty_blocked_regions_is_silent(self):
        self.edit_results(lambda data: data["aws"].update(blocked_regions=[]))
        self.assertFalse([w for w in self.assemble()["warnings"] if "SCP" in w])

    def test_malformed_partial_fields_do_not_break_assembly(self):
        self.edit_results(lambda data: (data.update(partial=True, pending_checks="LOG-002"), data["aws"].update(blocked_regions=None)))
        self.assertTrue(any("parcial" in w.lower() for w in self.assemble()["warnings"]))


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
        remediation = self.one(out, "LOG-001")["remediation"]
        self.assertIn('ACCOUNT_ID="__COMPLETAR_ACCOUNT_ID__"', remediation["commands"][0])

    def test_missing_checks_result_file(self):
        (self.run_dir / "checks-result.json").unlink()
        (self.run_dir / "inventory.json").unlink()
        out = self.assemble()
        self.assertIsNone(out["meta"]["aws"])
        self.assertTrue(out["findings"])


class RemediationByStatusTests(AssembleCase):
    """R61 / R62: only FAIL, DOCUMENTED_GAP and a DRIFT or UNDOCUMENTED whose actual fails keep the fix; the rest only verify."""

    NO_FIX = {"steps": [], "commands": [], "notes": ""}

    def claim(self, kind, check, **extra):
        return {"kind": kind, "check_id": check, "resource": {"type": "rds_instance", "id": "acme-notes-db",
                                                              "region": "us-east-1"}, **extra}

    def assert_verify_only(self, finding):
        rem = finding["remediation"]
        self.assertEqual({k: rem[k] for k in self.NO_FIX}, self.NO_FIX)
        self.assertEqual(rem["note_status"], assemble_findings.NOTE_STATUS_BY_STATUS.get(finding["status"], "no verificado: no aplicar sin confirmar"))
        self.assertTrue(rem["verify_after"].strip())

    def test_documented_only_destructive_fix_is_not_carried(self):
        out = self.assemble([self.claim("DOCUMENTED_ONLY", "ENC-003", vault_claim="La base está cifrada con CMK")])
        finding = self.one(out, "ENC-003", "acme-notes-db")
        self.assertEqual(finding["status"], "DOCUMENTED_ONLY")
        self.assert_verify_only(finding)
        self.assertNotIn("create-db-snapshot", json.dumps(finding["remediation"]))
        self.assertIn("us-east-1", finding["remediation"]["verify_after"])  # placeholders of verify_after are filled

    def test_documented_gap_keeps_the_full_fix(self):
        out = self.assemble([self.claim("DOCUMENTED_GAP", "ENC-003")])
        rem = self.one(out, "ENC-003", "acme-notes-db")["remediation"]
        self.assertTrue(rem["commands"] and rem["steps"])
        self.assertNotIn("note_status", rem)

    def test_undocumented_keeps_the_fix_only_when_its_actual_fails(self):
        keep = self.one(self.assemble([self.claim("UNDOCUMENTED", "ENC-003", actual_status="FAIL")]), "ENC-003", "acme-notes-db")
        self.assertEqual(keep["status"], "UNDOCUMENTED")
        self.assertTrue(keep["remediation"]["commands"] and keep["remediation"]["steps"])
        self.assertNotIn("note_status", keep["remediation"])
        for extra in ({}, {"actual_status": "PASS"}):
            found = self.one(self.assemble([self.claim("UNDOCUMENTED", "ENC-003", **extra)]), "ENC-003", "acme-notes-db")
            self.assertEqual(found["status"], "UNDOCUMENTED")
            self.assert_verify_only(found)

    def test_drift_keeps_the_fix_only_when_its_actual_fails(self):
        keep = self.one(self.assemble([self.claim("DRIFT", "ENC-003", actual_status="FAIL")]), "ENC-003", "acme-notes-db")
        self.assertTrue(keep["remediation"]["commands"])
        for extra in ({}, {"actual_status": "PASS"}, {"breaks_tests": [{"tool": "drata", "test": 30}]}):
            found = self.one(self.assemble([self.claim("DRIFT", "ENC-003", **extra)]), "ENC-003", "acme-notes-db")
            self.assertEqual(found["status"], "DRIFT")
            self.assert_verify_only(found)

    def test_pass_na_and_not_verified_rows_carry_only_verify_after(self):
        out = self.assemble()
        for check_id, resource, status in (("DET-001", "account", "PASS"), ("LOG-002", "account", "N/A"),
                                           ("DAT-001", "account", "NO_VERIFICADO")):
            finding = self.one(out, check_id, resource, status)
            self.assert_verify_only(finding)
        fail = self.one(out, "NET-001", SG, "FAIL")
        self.assertTrue(fail["remediation"]["commands"])

    def test_eval_claims_follow_their_status(self):
        out = self.assemble()  # fixture EVAL IAM-013 is PASS
        self.assert_verify_only(self.one(out, "IAM-013"))
        claims = [{"kind": "EVAL", "check_id": "IAM-013", "status": "FAIL", "detail": {"reason": "iam:* sin acotar"}}]
        self.assertTrue(self.one(self.assemble(claims), "IAM-013")["remediation"]["commands"])

    def test_documented_only_is_low_with_the_catalog_severity_kept_in_evidence(self):
        claim = self.claim("DOCUMENTED_ONLY", "ENC-003", severity="critical")
        finding = self.one(self.assemble([claim]), "ENC-003", "acme-notes-db")
        check = next(c for c in catalog.load_checks(SKILL_DIR / "references" / "checks") if c["id"] == "ENC-003")
        self.assertEqual(finding["severity"], "low")
        self.assertEqual(finding["evidence"]["catalog_severity"], check["severity"])
        self.assertEqual(finding["evidence"]["note"], "no verificada")
        nocheck = {"kind": "DOCUMENTED_ONLY", "check_id": None, "resource": None}
        found = [f for f in self.assemble([nocheck])["findings"] if f["status"] == "DOCUMENTED_ONLY" and f["check_id"] is None]
        self.assertEqual((found[0]["severity"], found[0]["evidence"]["catalog_severity"]), ("low", None))

    def test_stripped_remediation_does_not_raise_unsafe_value_warnings(self):
        claim = self.claim("DOCUMENTED_ONLY", "NET-008")  # its verify_after has no {resource_id}: only the stripped commands carry the id
        claim["resource"]["id"] = "bad id; rm"
        out = self.assemble([claim])
        self.assertFalse([w for w in out["warnings"] if "no seguros" in w or "inseguro" in w])


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


class ReviewTwoVerdictTests(AssembleCase):
    """Review 2 (D Important 3 and the verdict decision): one verdict per run, never OPTIMO without credentials."""

    def no_aws(self):
        self.edit_results(lambda data: data.update(aws=None, results=[], warnings=["sin credenciales AWS válidas"]))

    def only(self, *keep, status_for=None):
        """Complete run with credentials where only these (check, resource) rows exist."""
        def prune(data):
            data["results"] = [r for r in data["results"] if (r["check_id"], r["resource_id"]) in keep]
            data["warnings"] = []
        self.edit_results(prune)

    def verdict(self, claims=None, index=None):
        summary = self.assemble(claims, index)["summary"]
        return summary["verdict"], summary

    def test_fail_makes_it_not_optimal(self):
        verdict, summary = self.verdict()
        self.assertEqual(verdict, "NO_OPTIMO")
        self.assertTrue(summary["verdict_text"].startswith("No óptimo"))
        self.assertNotIn("\n", summary["verdict_text"])

    def test_clean_complete_run_with_credentials_is_optimal(self):
        self.only(("DET-001", "account"), ("DAT-007", "acme-notes-assets"))
        verdict, summary = self.verdict([])
        self.assertEqual(verdict, "OPTIMO")
        self.assertTrue(summary["verdict_text"].startswith("Óptimo"))
        self.assertEqual(summary["unverified"]["total"], 0)

    def test_no_credentials_is_never_optimal_and_says_nothing_was_verified(self):
        self.no_aws()
        only_vault = [{"kind": "DOCUMENTED_ONLY", "check_id": "ENC-003", "resource": {"type": "rds_instance", "id": "acme-notes-db", "region": "us-east-1"}}]
        verdict, summary = self.verdict(only_vault)  # a vault statement is the only source
        self.assertEqual(verdict, "NO_VERIFICABLE")
        self.assertIn("nada se verificó contra AWS", summary["verdict_text"])
        self.assertFalse(summary["aws_verified"])

    def test_no_credentials_with_a_vault_secret_is_still_not_optimal(self):
        self.no_aws()
        vault = self.tmp / "vault"
        vault.mkdir()
        helpers.make_secret_note(vault)
        verdict, summary = self.verdict([], vault_index.build_index(vault))
        self.assertEqual(verdict, "NO_OPTIMO")
        self.assertIn("nada se verificó contra AWS", summary["verdict_text"])

    def test_partial_run_blocked_regions_and_incomplete_inventory_are_not_verifiable(self):
        self.only(("DET-001", "account"))
        for patch in ({"partial": True, "pending_checks": ["NET-001"]},
                      {"aws": {"account_id": "111122223333", "identity_arn": "x", "regions": ["us-east-1"], "blocked_regions": ["eu-west-1"]}},
                      {"warnings": ["inventario incompleto: rds_instance ACCESS_DENIED en us-east-1"]}):
            self.only(("DET-001", "account"))
            self.edit_results(lambda data, patch=patch: data.update(patch))
            self.assertEqual(self.verdict([])[0], "NO_VERIFICABLE", patch)

    def test_not_verified_and_documented_only_items_block_optimal(self):
        self.only(("DET-001", "account"), ("DAT-001", "account"))
        verdict, summary = self.verdict([])
        self.assertEqual((verdict, summary["unverified"]["no_verificado"]), ("NO_VERIFICABLE", 1))
        self.only(("DET-001", "account"))
        claim = {"kind": "DOCUMENTED_ONLY", "check_id": "ENC-003", "resource": {"type": "rds_instance", "id": "acme-notes-db", "region": "us-east-1"}}
        verdict, summary = self.verdict([claim])
        self.assertEqual((verdict, summary["unverified"]["documented_only"]), ("NO_VERIFICABLE", 1))

    def test_documented_gap_and_failing_drift_make_it_not_optimal(self):
        self.only(("DET-001", "account"))
        resource = {"type": "rds_instance", "id": "acme-notes-db", "region": "us-east-1"}
        gap = {"kind": "DOCUMENTED_GAP", "check_id": "ENC-003", "resource": resource}  # catalog severity high/critical
        self.assertEqual(self.verdict([gap])[0], "NO_OPTIMO")
        low = {"kind": "DOCUMENTED_GAP", "check_id": "ENC-003", "resource": resource, "severity": "low"}
        self.assertEqual(self.verdict([low])[0], "NO_VERIFICABLE")
        drift = {"kind": "DRIFT", "check_id": "ENC-003", "resource": resource, "actual_status": "FAIL", "severity": "low"}
        self.assertEqual(self.verdict([drift])[0], "NO_OPTIMO")
        calm = {"kind": "DRIFT", "check_id": "ENC-003", "resource": resource, "actual_status": "PASS"}
        self.assertEqual(self.verdict([calm])[0], "OPTIMO")

    def test_scoped_components_without_claims_are_listed_as_unverified(self):
        self.only(("DET-001", "account"))
        (self.run_dir / "scope.json").write_text(json.dumps({
            "platform": "Acme Notes", "mode": "feature", "target": "email", "regions": ["us-east-1"], "resources": [
                {"type": "lambda_function", "id": "acme-notes-mailer", "region": "us-east-1"},
                {"type": "sqs_queue", "id": "arn:aws:sqs:us-east-1:111122223333:acme-notes-mail-queue", "region": "us-east-1"},
                {"type": "s3_bucket", "id": "acme-notes-uploads", "region": "us-east-1"}]}), encoding="utf-8")
        claim = {"kind": "DOCUMENTED_ONLY", "check_id": None, "resource": {"type": "sqs_queue", "id": "acme-notes-mail-queue", "region": "us-east-1"}}
        out = self.assemble([claim])
        listed = {u["id"] for u in out["unverified_scope"]}
        self.assertEqual(listed, {"acme-notes-mailer", "acme-notes-uploads"})
        self.assertEqual(out["summary"]["unverified"]["scope_without_claims"], 2)
        self.assertEqual(out["summary"]["verdict"], "NO_VERIFICABLE")

    def test_without_scope_file_nothing_is_listed(self):
        self.assertEqual(self.assemble()["unverified_scope"], [])

    def test_summary_keeps_its_old_keys_and_has_no_percentage(self):
        summary = self.assemble()["summary"]
        for key in ("by_status", "by_severity_fail", "drata_tests_failing", "vanta_tests_failing", "not_verified"):
            self.assertIn(key, summary)
        self.assertNotIn("%", json.dumps(summary))


class ReviewTwoSourcesTests(AssembleCase):
    def run_cli(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = assemble_findings.main(["--run-dir", str(self.run_dir), "--platform", "x", "--mode", "resource", *extra])
        return code, out.getvalue(), err.getvalue()

    def test_no_vault_and_no_credentials_stops_without_writing_findings(self):
        self.edit_results(lambda data: data.update(aws=None, results=[]))
        code, out, err = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("sin fuentes: hace falta un vault o credenciales AWS de solo lectura", err)
        self.assertEqual(out, "")
        self.assertFalse((self.run_dir / "findings.json").exists())

    def test_missing_checks_result_without_vault_stops_too(self):
        (self.run_dir / "checks-result.json").unlink()
        code, _, err = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("sin fuentes", err)

    def test_a_vault_alone_or_credentials_alone_are_enough(self):
        self.assertEqual(self.run_cli()[0], 0)  # credentials, no vault
        self.edit_results(lambda data: data.update(aws=None, results=[]))
        vault = self.tmp / "v"
        vault.mkdir()
        (vault / "a.md").write_text("# A\n", encoding="utf-8")
        index = self.tmp / "i.json"
        index.write_text(json.dumps(vault_index.build_index(vault)), encoding="utf-8")
        self.assertEqual(self.run_cli("--vault-index", str(index))[0], 0)


class ReviewTwoSmallFixesTests(AssembleCase):
    def test_lookup_keys_on_resource_type_as_well_as_id(self):
        inventory = json.loads((self.run_dir / "inventory.json").read_text(encoding="utf-8"))
        inventory.insert(0, {"type": "iam_role", "id": "acme-notes-uploads", "arn": "arn:aws:iam::111122223333:role/acme-notes-uploads",
                             "name": "acme-notes-uploads", "region": "us-east-1", "tags": {}})
        (self.run_dir / "inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
        finding = self.one(self.assemble(), "INV-001", "acme-notes-uploads")
        self.assertEqual(finding["resource"]["type"], "s3_bucket")
        self.assertIn('RESOURCE_ARN="arn:aws:s3:::acme-notes-uploads"', finding["remediation"]["commands"][0])
        self.assertNotIn(":role/", json.dumps(finding["remediation"]))

    def test_lookup_with_only_a_wrong_type_match_leaves_the_arn_to_complete(self):
        inventory = [{"type": "iam_role", "id": "acme-notes-uploads", "arn": "arn:aws:iam::111122223333:role/acme-notes-uploads",
                      "name": "acme-notes-uploads", "region": "us-east-1", "tags": {}}]
        (self.run_dir / "inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
        finding = self.one(self.assemble(), "INV-001", "acme-notes-uploads")
        self.assertIn('RESOURCE_ARN="__COMPLETAR_RESOURCE_ARN__"', finding["remediation"]["commands"][0])

    def test_unicode_digits_are_not_safe_in_region_or_account(self):
        claim = {"kind": "DOCUMENTED_GAP", "check_id": "ENC-003",
                 "resource": {"type": "rds_instance", "id": "acme-notes-db", "region": "us-east-\u0663"}}
        finding = self.one(self.assemble([claim]), "ENC-003", "acme-notes-db")
        self.assertNotIn("\u0663", json.dumps(finding["remediation"], ensure_ascii=False))
        self.assertIn('REGION="__COMPLETAR_REGION__"', finding["remediation"]["commands"][0])

    def test_pass_and_na_get_their_own_status_note(self):
        out = self.assemble()
        passed = self.one(out, "DET-001", "account", "PASS")["remediation"]["note_status"]
        na = self.one(out, "LOG-002", "account", "N/A")["remediation"]["note_status"]
        unverified = self.one(out, "DAT-001", "account", "NO_VERIFICADO")["remediation"]["note_status"]
        self.assertEqual(unverified, "no verificado: no aplicar sin confirmar")
        self.assertNotIn("no verificado", passed)
        self.assertNotIn("no verificado", na)
        self.assertNotEqual(passed, na)

    def test_vault_statements_are_not_marked_as_claude_evaluations(self):
        resource = {"type": "rds_instance", "id": "acme-notes-db", "region": "us-east-1"}
        claims = [{"kind": kind, "check_id": "ENC-003", "resource": resource} for kind in ("DOCUMENTED_ONLY", "DOCUMENTED_GAP")]
        out = self.assemble(claims)
        for finding in self.find(out, "ENC-003"):
            self.assertEqual(finding["evaluated_by"], "vault", finding["status"])
        drift = self.assemble([{"kind": "DRIFT", "check_id": "ENC-003", "resource": resource}])
        self.assertEqual(self.one(drift, "ENC-003")["evaluated_by"], "claude")

    def test_free_vault_adds_an_untyped_warning(self):
        vault = self.tmp / "free"
        vault.mkdir()
        (vault / "a.md").write_text("# A\n", encoding="utf-8")
        index = vault_index.build_index(vault)
        self.assertEqual(index["kind"], "free")
        self.assertTrue(any("vault no tipado" in w for w in self.assemble([], index)["warnings"]))
        index["kind"] = "typed"
        self.assertFalse(any("vault no tipado" in w for w in self.assemble([], index)["warnings"]))

    def test_truncated_notes_warn(self):
        index = {"kind": "typed", "root": "/v", "notes": [], "broken_links": [], "secrets_detected": [], "sensitive_files": [],
                 "truncated_notes": ["big.md"]}
        self.assertTrue(any("big.md" in w and "truncada" in w for w in self.assemble([], index)["warnings"]))

    def test_documented_findings_touch_their_controls_as_not_verified(self):
        claim = {"kind": "DOCUMENTED_ONLY", "check_id": "ENC-003", "resource": {"type": "rds_instance", "id": "acme-notes-db", "region": "us-east-1"}}
        out = self.assemble([claim])
        finding = self.one(out, "ENC-003")
        ids = {m["id"] for m in finding["mappings"]["iso27001_2022"]}
        self.assertTrue(ids)
        coverage = {c["id"]: c["status"] for c in out["coverage"]["iso"]}
        for control in ids:
            self.assertIn(coverage[control], ("NO_VERIFICADO", "FAIL"), control)

    def test_malformed_rows_and_claim_fields_do_not_crash(self):
        def corrupt(data):
            data["results"] += [{"check_id": "NET-001", "status": "FAIL"}, "texto", {"status": "FAIL", "resource_id": "x"}]
        self.edit_results(corrupt)
        out = self.assemble()
        self.assertTrue(any("fila inválida" in w for w in out["warnings"]))
        path = self.tmp / "claims.json"
        path.write_text(json.dumps([{"kind": "DRIFT", "resource": {"id": 5}}]), encoding="utf-8")
        with self.assertRaises(ValueError):
            assemble_findings._load_claims(path)

    def test_findings_digest_covers_status_and_commands(self):
        out = self.assemble()
        before = assemble_findings.findings_digest(out)
        changed = json.loads(json.dumps(out))
        changed["findings"][0]["status"] = "PASS"
        self.assertNotEqual(assemble_findings.findings_digest(changed), before)
        again = json.loads(json.dumps(out))
        again["findings"][0]["remediation"]["commands"] = ["echo cambiado"]
        self.assertNotEqual(assemble_findings.findings_digest(again), before)
        self.assertEqual(assemble_findings.findings_digest(json.loads(json.dumps(out))), before)

    def test_sensitive_note_with_credentials_in_a_policy_title_carries_the_review_hint(self):
        index = {"kind": "typed", "root": "/v", "notes": [], "broken_links": [], "secrets_detected": [],
                 "sensitive_files": [{"path": "policies/Credentials rotation policy.md", "reason": "x"},
                                     {"path": "Rotation of credentials.md", "reason": "x"}]}
        findings = [f for f in self.assemble([], index)["findings"] if f["evidence"].get("detection") == "nombre de archivo"]
        self.assertEqual(len(findings), 2)
        for finding in findings:
            self.assertIn(assemble_findings.TEMPLATE_HINT, finding["remediation"]["steps"])


class FinalCleanupBTests(AssembleCase):
    """Final cleanup B: UNDOCUMENTED that fails is a failure (N2), OPTIMO needs an evaluated PASS/FAIL (N4), malformed scope.json (N6),
    reason wording, vault silent about the target, no risk on verify-only fixes, clear errors for missing inputs (D2 minors 4, 6, 8, 11)."""

    RESOURCE = {"type": "rds_instance", "id": "acme-notes-db", "region": "us-east-1"}

    def only(self, *keep):
        def prune(data):
            data["results"] = [r for r in data["results"] if (r["check_id"], r["resource_id"]) in keep]
            data["warnings"] = []
        self.edit_results(prune)

    def verdict(self, claims=None, index=None):
        summary = self.assemble(claims, index)["summary"]
        return summary["verdict"], summary

    def test_undocumented_with_a_failing_actual_state_is_not_optimal(self):
        self.only(("DET-001", "account"))
        claim = {"kind": "UNDOCUMENTED", "check_id": "ENC-003", "resource": self.RESOURCE, "actual_status": "FAIL"}
        verdict, summary = self.verdict([claim])
        self.assertEqual(verdict, "NO_OPTIMO")
        self.assertTrue(summary["verdict_text"].startswith("No óptimo"))

    def test_any_claim_status_with_a_failing_actual_state_is_not_optimal(self):
        self.only(("DET-001", "account"))
        for kind in ("DRIFT", "UNDOCUMENTED", "DOCUMENTED_ONLY", "DOCUMENTED_GAP"):
            claim = {"kind": kind, "check_id": "ENC-003", "resource": self.RESOURCE, "actual_status": "FAIL", "severity": "low"}
            self.assertEqual(self.verdict([claim])[0], "NO_OPTIMO", kind)

    def test_drift_or_undocumented_without_a_failing_actual_state_is_called_out_in_the_text(self):
        self.only(("DET-001", "account"))
        claims = [{"kind": "UNDOCUMENTED", "check_id": "ENC-003", "resource": self.RESOURCE},
                  {"kind": "DRIFT", "check_id": "ENC-003", "resource": self.RESOURCE, "actual_status": "PASS"}]
        verdict, summary = self.verdict(claims)
        self.assertEqual(verdict, "OPTIMO")
        self.assertIn("2 diferencia(s)", summary["verdict_text"])
        self.assertNotIn("\n", summary["verdict_text"])

    def test_optimal_needs_at_least_one_evaluated_pass_or_fail(self):
        self.edit_results(lambda data: data.update(results=[], warnings=[]))
        verdict, summary = self.verdict([])
        self.assertEqual(verdict, "NO_VERIFICABLE")
        self.assertIn("ningún chequeo", summary["verdict_text"])
        shutil.rmtree(self.run_dir)
        shutil.copytree(SAMPLE, self.run_dir)
        self.only(("LOG-002", "account"))  # N/A row
        self.assertEqual(self.verdict([])[0], "NO_VERIFICABLE")
        shutil.rmtree(self.run_dir)
        shutil.copytree(SAMPLE, self.run_dir)
        self.only(("DET-001", "account"))
        self.assertEqual(self.verdict([])[0], "OPTIMO")

    def test_documented_gap_reason_does_not_say_it_was_verified_to_fail(self):
        self.only(("DET-001", "account"))
        gap = {"kind": "DOCUMENTED_GAP", "check_id": "ENC-003", "resource": self.RESOURCE, "severity": "high"}
        summary = self.verdict([gap])[1]
        self.assertEqual(summary["verdict"], "NO_OPTIMO")
        self.assertEqual(len(summary["verdict_reasons"]), 1)
        self.assertIn("documentada", summary["verdict_reasons"][0])
        self.assertNotIn("incumplen", summary["verdict_reasons"][0])
        self.assertIn("1 hallazgo(s) abierto(s)", summary["verdict_text"])

    def test_verified_failures_and_documented_gaps_get_separate_reasons(self):
        gap = {"kind": "DOCUMENTED_GAP", "check_id": "ENC-003", "resource": self.RESOURCE, "severity": "high"}
        reasons = self.verdict([gap])[1]["verdict_reasons"]
        self.assertEqual(len(reasons), 2)
        self.assertIn("falla", reasons[0])
        self.assertIn("documentada", reasons[1])

    def test_malformed_scope_json_is_a_clear_error(self):
        for content in ("[]", '"x"', "3", "null", '{"resources": "x"}', '{"resources": {"id": "x"}}', "{oops"):
            (self.run_dir / "scope.json").write_text(content, encoding="utf-8")
            with self.subTest(content=content):
                if content == "null":
                    self.assertEqual(self.assemble()["unverified_scope"], [])
                    continue
                with self.assertRaisesRegex(ValueError, "scope.json"):
                    self.assemble()

    def test_malformed_scope_json_through_the_cli_has_no_traceback(self):
        (self.run_dir / "scope.json").write_text("[1, 2]", encoding="utf-8")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = assemble_findings.main(["--run-dir", str(self.run_dir), "--platform", "x", "--mode", "full"])
        self.assertEqual(code, 2)
        self.assertTrue(err.getvalue().startswith("error: "))
        self.assertNotIn("Traceback", err.getvalue())
        self.assertFalse((self.run_dir / "findings.json").exists())

    def resource_meta(self, target):
        return {"platform": "Acme Notes", "mode": "resource", "target": target, "lang": "es"}

    def test_resource_mode_says_when_the_vault_does_not_mention_the_target(self):
        vault = self.tmp / "vault"
        vault.mkdir()
        (vault / "Other.md").write_text("# Other\n\nnada\n", encoding="utf-8")
        index = vault_index.build_index(vault)
        out = assemble_findings.assemble(self.run_dir, index, [], self.resource_meta("i-0a1b2c3d4e5f60718"), SKILL_DIR)
        self.assertTrue([n for n in out["notes"] if "i-0a1b2c3d4e5f60718" in n and "vault" in n], out["notes"])
        (vault / "Server.md").write_text("# Server\n\nInstancia i-0a1b2c3d4e5f60718 de producción\n", encoding="utf-8")
        out = assemble_findings.assemble(self.run_dir, vault_index.build_index(vault), [], self.resource_meta("i-0a1b2c3d4e5f60718"), SKILL_DIR)
        self.assertFalse([n for n in out["notes"] if "no menciona" in n])
        out = assemble_findings.assemble(self.run_dir, vault_index.build_index(vault), [], dict(META), SKILL_DIR)
        self.assertFalse([n for n in out["notes"] if "no menciona" in n])

    def test_verify_only_findings_carry_no_kind_risk_or_downtime(self):
        claim = {"kind": "DOCUMENTED_ONLY", "check_id": "ENC-003", "resource": self.RESOURCE}
        out = self.assemble([claim])
        for finding in out["findings"]:
            rem = finding["remediation"]
            if rem and rem.get("note_status"):
                self.assertEqual((rem["kind"], rem["risk"], rem["downtime"]), (None, None, None), finding["id"])
        fail = self.one(out, "NET-001", SG, "FAIL")["remediation"]
        self.assertIn(fail["risk"], ("low", "medium", "high"))
        self.assertIsNotNone(fail["kind"])

    def test_missing_claims_and_index_files_are_named_in_the_error(self):
        for flag in ("--vault-claims", "--vault-index"):
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                code = assemble_findings.main(["--run-dir", str(self.run_dir), "--platform", "x", "--mode", "full",
                                               flag, str(self.tmp / "nope.json")])
            self.assertEqual(code, 2, flag)
            self.assertIn("no existe", err.getvalue(), flag)
            self.assertIn("nope.json", err.getvalue(), flag)
            self.assertNotIn("se esperaba", err.getvalue(), flag)


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

    def run_cli(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = assemble_findings.main(["--run-dir", str(self.run_dir), "--platform", "x", "--mode", "full", *extra])
        return code, out.getvalue(), err.getvalue()

    def write(self, name, content):
        path = self.tmp / name
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return str(path)

    def assert_clean_error(self, result):
        code, out, err = result
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(len(err.strip().splitlines()), 1, err)
        self.assertTrue(err.startswith("error: "))
        self.assertNotIn("Traceback", err)
        self.assertFalse((self.run_dir / "findings.json").exists())

    def test_cli_malformed_claims(self):
        for name, content in (("bad.json", "{not json"), ("dict.json", {"kind": "DRIFT"}),
                              ("strings.json", ["DRIFT"]), ("kind.json", [{"kind": 3}]),
                              ("check.json", [{"kind": "DRIFT", "check_id": 5}]),
                              ("res.json", [{"kind": "DRIFT", "resource": "x"}]),
                              ("bt.json", [{"kind": "DRIFT", "breaks_tests": ["a"]}])):
            with self.subTest(name=name):
                self.assert_clean_error(self.run_cli("--vault-claims", self.write(name, content)))

    def test_cli_malformed_vault_index(self):
        for name, content in (("bad.json", "["), ("list.json", []), ("nokind.json", {"notes": []}),
                              ("links.json", {"kind": "free", "broken_links": [{"from": "a"}]}),
                              ("secrets.json", {"kind": "free", "secrets_detected": ["x"]})):
            with self.subTest(name=name):
                self.assert_clean_error(self.run_cli("--vault-index", self.write(name, content)))

    def test_cli_malformed_run_files(self):
        (self.run_dir / "checks-result.json").write_text("{oops", encoding="utf-8")
        self.assert_clean_error(self.run_cli())

    def test_cli_rejects_missing_run_dir(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code = assemble_findings.main(["--run-dir", str(self.tmp / "nope"), "--platform", "x", "--mode", "full"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
