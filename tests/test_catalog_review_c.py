"""Final review C: catalog content fixes (Vanta names, Drata names, remediation blocks)."""
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import SKILL_DIR

import catalog
import verify_remediation
from test_verify import RULES, doc

REFS = SKILL_DIR / "references"
CHECKS = {c["id"]: c for c in catalog.load_checks(REFS / "checks")}
HAS_BASH = shutil.which("bash") is not None
TOUCHED = ("LOG-006", "NET-005", "NET-006", "NET-001", "NET-002", "NET-004", "ENC-002", "ENC-003", "EML-001", "DAT-003", "EML-005")


def commands(check_id):
    return CHECKS[check_id]["remediation"]["commands"]


def instantiate(text):
    text = re.sub(r"\{detail_json:[^}]+\}", "'[]'", text)
    for key, value in (("resource_id", "res-1"), ("region", "us-east-1"), ("account_id", "111122223333"),
                       ("resource_name", "n"), ("resource_arn", "arn:aws:s3:::x")):
        text = text.replace("{" + key + "}", value)
    return text


class VantaNameTests(unittest.TestCase):
    # Test names that the public Vanta articles do not give: the mapping is dropped ("sin test equivalente").
    NO_PUBLIC_NAME = [f"MON-00{n}" for n in range(1, 10)] + ["INT-003", "INT-004", "INV-003", "TLS-005"]

    def test_checks_without_a_public_vanta_test_name_have_no_vanta_mapping(self):
        for check_id in self.NO_PUBLIC_NAME:
            self.assertEqual(CHECKS[check_id]["mappings"]["vanta"], [], check_id)

    def test_every_vanta_name_is_in_the_research_report(self):
        research = (SKILL_DIR.parent / "docs" / "research" / "vanta-drata-tests.md").read_text(encoding="utf-8")
        for check_id, check in CHECKS.items():
            for mapping in check["mappings"]["vanta"]:
                self.assertIn(mapping["test"], research, f"{check_id}: {mapping['test']}")

    def test_vanta_names_are_not_spanish_descriptions(self):
        for check_id, check in CHECKS.items():
            for mapping in check["mappings"]["vanta"]:
                self.assertNotRegex(mapping["test"], r"[áéíóúñ¿¡]|rol vanta-auditor|\(scoping\)", check_id)


class DrataNameTests(unittest.TestCase):
    def test_catalog_names_equal_the_dcf_file(self):
        names = {t["test_id"]: t["test_name"] for t in json.loads((REFS / "mappings" / "drata-dcf.json").read_text(encoding="utf-8"))["tests"]}
        for check_id, check in CHECKS.items():
            for mapping in check["mappings"]["drata"]:
                if mapping["test"] in names:
                    self.assertEqual(mapping["name"], names[mapping["test"]], check_id)


class RemediationBlockTests(unittest.TestCase):
    def test_log_006_never_pastes_a_fixed_policy_and_keeps_existing_statements(self):
        rem = CHECKS["LOG-006"]["remediation"]
        text = "\n".join(rem["commands"])
        self.assertIn("get-bucket-policy", rem["commands"][1])
        self.assertNotIn("POLICY='", text)
        self.assertEqual(sum("put-bucket-policy" in c for c in rem["commands"]), 1)
        apply_block = rem["commands"][3]
        self.assertIn('file://policy-$BUCKET-new.json', apply_block)
        merge = rem["commands"][2]
        self.assertIn('TRAIL_PREFIX="__COMPLETAR_PREFIJO_TRAIL__"', merge)
        self.assertIn('p["Statement"]=s', merge)  # the statement list is extended, never replaced
        self.assertNotIn("put-bucket-policy", merge)

    def test_log_006_merge_script_respects_prefix_and_keeps_other_statements(self):
        if not HAS_BASH:
            self.skipTest("bash is not available")
        merge = instantiate(CHECKS["LOG-006"]["remediation"]["commands"][2])
        existing = {"Version": "2012-10-17", "Statement": [
            {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::res-1/*",
             "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
            {"Sid": "AWSCloudTrailAclCheck", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::res-1"}]}
        arn = "arn:aws:cloudtrail:us-east-1:111122223333:trail/acme-notes"
        for prefix, expected in (("", "arn:aws:s3:::res-1/AWSLogs/111122223333/*"), ("logs/ct", "arn:aws:s3:::res-1/logs/ct/AWSLogs/111122223333/*")):
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "policy-res-1.json").write_text(json.dumps(existing), encoding="utf-8")
                script = merge.replace('"__COMPLETAR_TRAIL_ARN__"', f'"{arn}"').replace('"__COMPLETAR_PREFIJO_TRAIL__"', f'"{prefix}"')
                done = subprocess.run(["bash", "-c", script], cwd=tmp, capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, done.stderr)
                merged = json.loads((Path(tmp) / "policy-res-1-new.json").read_text(encoding="utf-8"))
            sids = [s["Sid"] for s in merged["Statement"]]
            self.assertEqual(sids, ["DenyInsecureTransport", "AWSCloudTrailAclCheck", "AWSCloudTrailWrite"])
            acl = merged["Statement"][1]
            self.assertEqual(acl["Condition"]["StringEquals"]["aws:SourceArn"], arn)  # existing CloudTrail statement gains the condition
            self.assertEqual(merged["Statement"][2]["Resource"], expected)

    def test_log_006_without_a_bucket_policy_merge_starts_from_an_empty_policy(self):
        if not HAS_BASH:
            self.skipTest("bash is not available")
        commands_ = CHECKS["LOG-006"]["remediation"]["commands"]
        fetch, merge = instantiate(commands_[1]), instantiate(commands_[2])
        merge = merge.replace('"__COMPLETAR_TRAIL_ARN__"', '"arn:aws:cloudtrail:us-east-1:111122223333:trail/acme-notes"')
        merge = merge.replace('"__COMPLETAR_PREFIJO_TRAIL__"', '""')
        # stub: never the real aws CLI. get-bucket-policy fails like NoSuchBucketPolicy
        stub = 'aws() { echo "An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation" >&2; return 254; }\n'
        with tempfile.TemporaryDirectory() as tmp:
            done = subprocess.run(["bash", "-c", stub + fetch + "\n" + merge], cwd=tmp, capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            merged = json.loads((Path(tmp) / "policy-res-1-new.json").read_text(encoding="utf-8"))
        self.assertEqual([s["Sid"] for s in merged["Statement"]], ["AWSCloudTrailAclCheck", "AWSCloudTrailWrite"])

    def test_log_006_other_read_errors_stop_and_produce_no_merged_policy(self):
        if not HAS_BASH:
            self.skipTest("bash is not available")
        commands_ = CHECKS["LOG-006"]["remediation"]["commands"]
        fetch, merge = instantiate(commands_[1]), instantiate(commands_[2])
        merge = merge.replace('"__COMPLETAR_TRAIL_ARN__"', '"arn:aws:cloudtrail:us-east-1:111122223333:trail/acme-notes"')
        merge = merge.replace('"__COMPLETAR_PREFIJO_TRAIL__"', '""')
        # stub: never the real aws CLI. get-bucket-policy is denied, so an existing policy may be hidden
        stub = 'aws() { echo "An error occurred (AccessDenied) when calling the GetBucketPolicy operation" >&2; return 254; }\n'
        with tempfile.TemporaryDirectory() as tmp:
            done = subprocess.run(["bash", "-c", stub + fetch + "\n" + merge], cwd=tmp, capture_output=True, text=True)
            self.assertIn("DETENIDO", done.stdout)
            self.assertFalse((Path(tmp) / "policy-res-1-new.json").exists())

    def test_log_006_notes_warn_that_the_merge_is_scoped_to_one_trail(self):
        notes = CHECKS["LOG-006"]["remediation"]["notes"]
        self.assertIn("ESTE trail", notes)
        self.assertIn("varios trails", notes)

    def test_log_006_merge_refuses_unfilled_placeholders(self):
        if not HAS_BASH:
            self.skipTest("bash is not available")
        merge = instantiate(CHECKS["LOG-006"]["remediation"]["commands"][2])
        with tempfile.TemporaryDirectory() as tmp:
            done = subprocess.run(["bash", "-c", merge], cwd=tmp, capture_output=True, text=True)
            self.assertNotEqual(done.returncode, 0)
            self.assertFalse((Path(tmp) / "policy-res-1-new.json").exists())

    def test_net_001_002_004_are_cli_with_decision(self):
        for check_id in ("NET-001", "NET-002", "NET-004"):
            self.assertEqual(CHECKS[check_id]["remediation"]["kind"], "cli_with_decision", check_id)

    def test_enc_003_cluster_block_sets_subnet_group_and_security_group(self):
        block = commands("ENC-003")[1]
        self.assertIn('SUBNET_GROUP="__COMPLETAR_DB_SUBNET_GROUP__"', block)
        self.assertIn('SG_ID="__COMPLETAR_SECURITY_GROUP_ID__"', block)
        self.assertRegex(block, r'restore-db-cluster-from-snapshot [^\n]*--db-subnet-group-name "\$SUBNET_GROUP" --vpc-security-group-ids "\$SG_ID"')

    def test_enc_002_reads_the_source_volume_instead_of_hardcoding_gp3(self):
        rem = CHECKS["ENC-002"]["remediation"]
        block = rem["commands"][0]
        self.assertNotIn("--volume-type gp3", block)
        self.assertIn('describe-volumes --volume-ids "$VOLUME_ID"', block)
        for query in ("Volumes[0].VolumeType", "Volumes[0].Iops", "Volumes[0].Throughput"):
            self.assertIn(query, block)
        self.assertRegex(block, r'create-volume [^\n]*--volume-type "\$VOL_TYPE" \$IOPS_ARG \$THR_ARG')
        self.assertIn("instance store", rem["notes"])

    def test_eml_001_first_block_says_when_to_use_it(self):
        self.assertIn("solo si la identidad usa BYODKIM o no tiene Easy DKIM", commands("EML-001")[0])

    def test_dat_003_is_medium_risk_so_it_leaves_the_low_risk_bulk_copy(self):
        self.assertEqual(CHECKS["DAT-003"]["remediation"]["risk"], "medium")

    def test_eml_005_notes_mention_inheritance_from_the_organizational_domain(self):
        notes = CHECKS["EML-005"]["remediation"]["notes"]
        self.assertIn("RFC 7489", notes)
        self.assertRegex(notes, r"(?i)dominio padre")


@unittest.skipUnless(HAS_BASH, "bash is not available")
class VerifierSweepTests(unittest.TestCase):
    """The verifier (bash -n, hygiene, placeholders) evaluates the touched catalog fixes."""

    def test_touched_fixes_have_no_syntax_hygiene_or_destructive_issues(self):
        findings = []
        for number, check_id in enumerate(TOUCHED):
            check = CHECKS[check_id]
            rem = check["remediation"]
            if not rem.get("commands"):
                continue
            findings.append({
                "id": f"F-{number:04d}", "check_id": check_id, "title": check["title"], "domain": "x", "status": "FAIL",
                "severity": check["severity"], "resource": {"type": "x", "id": "res-1", "region": "us-east-1", "name": "n"},
                "remediation": {"kind": rem["kind"], "risk": rem["risk"], "downtime": rem["downtime"],
                                "steps": [instantiate(s) for s in rem["steps"]], "notes": instantiate(rem["notes"]),
                                "verify_after": instantiate(rem["verify_after"]), "commands": [instantiate(c) for c in rem["commands"]]},
                "evidence": {}, "depends_on_me": [], "missing": []})
        result = verify_remediation.verify(doc(*findings), [], RULES, runner=subprocess.run)
        for finding in findings:
            kinds = {i["kind"] for i in result["per_finding"][finding["id"]]["issues"]}
            self.assertFalse(kinds & {"syntax", "higiene", "placeholder_sin_resolver", "destructivo_sin_aviso"}, (finding["check_id"], kinds))


if __name__ == "__main__":
    unittest.main()
