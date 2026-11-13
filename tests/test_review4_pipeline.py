"""Review 4, pipeline: unverified_scope is type-aware (I-1), the verdict basis follows the vault index (M-1), a failing UNDOCUMENTED
keeps the check's severity (M-3), SAFE_VALUE rejects a leading # or - (N-6), no Spanish messages (M-7) and the catalog fixes
(placeholders, NET-005, DAT-001, TLS-004)."""

import contextlib
import io
import json
import re
import unittest

from helpers import SKILL_DIR

import assemble_findings
import catalog
import test_assemble
import test_review3_pipeline
import vault_index
import verify_remediation

CHECKS_DIR = SKILL_DIR / "references" / "checks"
QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/111122223333/orders"
TOPIC_ARN = "arn:aws:sns:us-east-1:111122223333:orders"
RESOURCE = test_review3_pipeline.RESOURCE


def catalog_check(check_id):
    return {c["id"]: c for c in catalog.load_checks(CHECKS_DIR)}[check_id]


class TypeAwareScopeTests(test_review3_pipeline.PipelineCase):
    def write_inventory(self, *items):
        (self.run_dir / "inventory.json").write_text(json.dumps([
            {"type": t, "id": i, "arn": a, "name": n, "region": "us-east-1", "tags": {}} for t, i, a, n in items]), encoding="utf-8")

    def claim(self, rtype, rid):
        return {"kind": "DOCUMENTED_ONLY", "check_id": None, "resource": {"type": rtype, "id": rid, "region": "us-east-1"}}

    def test_a_same_named_resource_of_another_type_does_not_cover_a_scoped_component(self):
        self.only(("DET-001", "account"))
        self.write_scope(("sqs_queue", "orders"), ("sns_topic", "orders"))
        out = self.assemble([self.claim("sqs_queue", "orders")])
        self.assertEqual([(u["type"], u["id"]) for u in out["unverified_scope"]], [("sns_topic", "orders")])
        self.assertEqual(out["summary"]["verdict"], "NOT_VERIFIABLE")

    def test_the_inventory_resolution_does_not_cross_types_either(self):
        self.only(("DET-001", "account"))
        self.write_inventory(("sqs_queue", QUEUE_URL, "", "orders"), ("sns_topic", TOPIC_ARN, TOPIC_ARN, "orders"))
        self.write_scope(("sqs_queue", QUEUE_URL), ("sns_topic", TOPIC_ARN))
        out = self.assemble([self.claim("sqs_queue", QUEUE_URL)])
        self.assertEqual([(u["type"], u["id"]) for u in out["unverified_scope"]], [("sns_topic", TOPIC_ARN)])

    def test_the_same_type_by_name_or_arn_is_still_covered(self):
        self.only(("DET-001", "account"))
        self.write_inventory(("sns_topic", TOPIC_ARN, TOPIC_ARN, "orders"))
        self.write_scope(("sns_topic", TOPIC_ARN))
        self.assertEqual(self.assemble([self.claim("sns_topic", "orders")])["unverified_scope"], [])
        self.assertEqual(self.assemble([self.claim("sns_topic", TOPIC_ARN)])["unverified_scope"], [])

    def test_a_finding_without_a_type_covers_only_its_exact_id(self):
        self.only(("DET-001", "account"))
        self.write_scope(("sqs_queue", "orders"), ("sns_topic", "orders-two"))
        out = self.assemble([{"kind": "DOCUMENTED_ONLY", "check_id": None, "resource": {"id": "orders", "region": "us-east-1"}}])
        self.assertEqual([u["id"] for u in out["unverified_scope"]], ["orders-two"])


class VerdictBasisWithoutVaultTests(test_review3_pipeline.PipelineCase):
    def observation(self):
        return {"kind": "UNDOCUMENTED", "check_id": None, "resource": None, "title": "Claude observation"}

    def test_a_claim_without_a_vault_index_does_not_make_the_basis_include_the_vault(self):
        self.only(("DET-001", "account"))
        summary = self.assemble([self.observation()])["summary"]
        self.assertEqual(summary["verdict_basis"], "aws")
        self.assertNotIn("vault", summary["verdict_text"].lower())

    def test_with_an_index_the_basis_still_includes_the_vault(self):
        self.only(("DET-001", "account"))
        vault = self.tmp / "vault"
        vault.mkdir()
        (vault / "Note.md").write_text("# Note\nText.\n", encoding="utf-8")
        summary = self.assemble([self.observation()], vault_index.build_index(vault))["summary"]
        self.assertEqual(summary["verdict_basis"], "aws+vault")


class UndocumentedSeverityTests(test_review3_pipeline.PipelineCase):
    def severity(self, **extra):
        self.only(("DET-001", "account"))
        claim = {"kind": "UNDOCUMENTED", "check_id": "ENC-003", "resource": RESOURCE, **extra}
        return self.one(self.assemble([claim]), "ENC-003")["severity"]

    def test_a_failing_undocumented_keeps_the_catalog_severity(self):
        self.assertNotEqual(catalog_check("ENC-003")["severity"], "low")
        self.assertEqual(self.severity(actual_status="FAIL"), catalog_check("ENC-003")["severity"])

    def test_an_explicit_severity_still_wins(self):
        self.assertEqual(self.severity(actual_status="FAIL", severity="medium"), "medium")

    def test_an_unverified_undocumented_stays_low(self):
        self.assertEqual(self.severity(), "low")
        self.assertEqual(self.severity(actual_status="PASS"), "low")


class SafeValueTests(test_assemble.AssembleCase):
    def add_row(self, value):
        self.edit_results(lambda data: data["results"].append({
            "check_id": "DAT-007", "status": "FAIL", "resource_id": value, "region": "us-east-1",
            "detail": {}, "missing": [], "vacuous": False}))

    def test_a_leading_hash_or_dash_falls_back_to_the_placeholder(self):
        for value in ("#x", "-x", "--profile", "#"):
            with self.subTest(value=value):
                self.setUp()
                self.add_row(value)
                out = self.assemble(claims=[])
                rem = self.one(out, "DAT-007", value, "FAIL")["remediation"]
                self.assertIn("__FILL_IN_RESOURCE_ID__", rem["verify_after"])
                self.assertNotIn(f'"{value}"', rem["verify_after"])
                self.assertTrue([w for w in out["warnings"] if "unsafe characters" in w])

    def test_the_pattern_accepts_inner_symbols_and_rejects_leading_ones(self):
        for value in ("a-b#c", "/aws/lambda/x", "_x", "9-lives"):
            with self.subTest(value=value):
                self.assertTrue(assemble_findings.SAFE_VALUE.fullmatch(value))
        for value in ("#x", "-x", "", "a" * 513):
            with self.subTest(value=value[:8]):
                self.assertIsNone(assemble_findings.SAFE_VALUE.fullmatch(value))


class EnglishMessagesTests(test_assemble.AssembleCase):
    def test_a_findings_json_that_is_not_an_object_reports_an_english_error(self):
        (self.run_dir / "findings.json").write_text("[]", encoding="utf-8")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = verify_remediation.main(["--run-dir", str(self.run_dir)])
        self.assertEqual(code, 2)
        self.assertIn("findings.json: unexpected shape", err.getvalue())

    def test_the_scripts_hold_no_spanish_text(self):
        spanish = re.compile(r"[áéíóúñ¿¡]|forma inesperada|no registrado|evaluador|\bdebe\b", re.I)
        for name in ("assemble_findings.py", "verify_remediation.py"):
            text = (SKILL_DIR / "scripts" / name).read_text(encoding="utf-8")
            self.assertIsNone(spanish.search(text), name)


class CatalogFixTests(unittest.TestCase):
    TOKEN = re.compile(r"__FILL_IN_[A-Za-z0-9_-]*")

    def test_every_fill_in_token_is_uppercase_so_the_tooling_recognises_it(self):
        seen = 0
        for path in sorted(CHECKS_DIR.glob("*.json")):
            for token in self.TOKEN.findall(path.read_text(encoding="utf-8")):
                if token == "__FILL_IN_":  # the bare prefix (a glob or a test of it) is used as a guard that detect an unfilled value (DAT-010, INV-004)
                    continue
                seen += 1
                self.assertRegex(token, r"^__FILL_IN_[A-Z0-9_]+__$", f"{path.name}: {token}")
        self.assertGreater(seen, 100)

    def test_cmp_004_names_the_allowed_scheme_values(self):
        rem = catalog_check("CMP-004")["remediation"]
        self.assertIn("__FILL_IN_ALB_SCHEME__", rem["commands"][0])
        self.assertIn("internet-facing or internal", rem["commands"][0])
        self.assertIn("internet-facing or internal", rem["notes"])

    def test_net_005_default_nacl_rules_and_free_numbers_per_ip_version(self):
        rem = catalog_check("NET-005")["remediation"]
        self.assertIn("rule 100 of the default NACL for IPv4", rem["commands"][1])
        self.assertIn("rule 101 of the default NACL for IPv6", rem["commands"][2])
        self.assertIn("12 different numbers", " ".join(rem["steps"]))

    def test_dat_001_retention_is_a_placeholder(self):
        rem = catalog_check("DAT-001")["remediation"]
        for command in rem["commands"]:
            self.assertIn('RETENTION_DAYS="__FILL_IN_RETENTION_DAYS__"', command)
            self.assertIn('--backup-retention-period "$RETENTION_DAYS"', command)
            self.assertNotIn("--backup-retention-period 7", command)

    def test_tls_004_verifies_instances_and_clusters_without_a_placeholder(self):
        verify = catalog_check("TLS-004")["remediation"]["verify_after"]
        self.assertIn("describe-db-parameters", verify)
        self.assertIn("describe-db-cluster-parameters --db-cluster-parameter-group-name", verify)
        self.assertNotIn("__FILL_IN_", verify)
        self.assertTrue(verify.startswith("aws "))


if __name__ == "__main__":
    unittest.main()
