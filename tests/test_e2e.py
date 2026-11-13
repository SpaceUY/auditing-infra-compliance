"""End-to-end pipeline tests with a fake AWS: collect -> assemble -> render -> verify -> render.

Nothing here touches the network, the real aws CLI or the repo: every output goes to a temp directory.
"""

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from helpers import FIXTURES_DIR, SKILL_DIR, FakeRunner, load_fixture, make_secret_note

import assemble_findings
import aws_runner
import catalog
import collect
import render_report
import vault_index
import verify_remediation

REGION = "us-east-1"
SG = "sg-0a1b2c3d4e5f60718"
INSTANCE = "i-0a1b2c3d4e5f60718"
ACCESS_DENIED = ("An error occurred (AccessDeniedException) when calling the {op} operation: "
                 "User: arn:aws:iam::111122223333:user/auditor is not authorized to perform: {perm}")
NO_PUBLIC_ACCESS_BLOCK = ("An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the "
                          "GetPublicAccessBlock operation: The public access block configuration was not found")
UNVERIFIED_MARKER = '"verification": {'  # key of the embedded verification (the template only has id="verification")
CR003_MARKER = '"rule_id": "CR-003"'  # per-finding verification issue, only inside the embedded verification
META = {"platform": "Acme Notes", "mode": "full", "target": None, "lang": "es"}
CLAIMS = [
    {"kind": "DRIFT", "check_id": "ENC-006", "resource": {"type": "kms_key", "id": "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d",
                                                            "region": REGION},
     "vault_note": "constraints/PII handling.md", "vault_claim": "La clave de la base rota automáticamente",
     "actual": "La rotación automática está desactivada", "status": None, "detail": None, "severity": None,
     "breaks_tests": []},
    {"kind": "UNDOCUMENTED", "check_id": None, "resource": {"type": "sqs_queue", "id": "acme-notes-dlq", "region": REGION},
     "vault_note": None, "vault_claim": None, "actual": "Cola sin documentar en el vault", "status": None,
     "detail": None, "severity": None, "breaks_tests": []},
]


def ok(data):
    return {"stdout": json.dumps(data), "returncode": 0}


def err(stderr):
    return {"stdout": "", "stderr": stderr, "returncode": 255}


def e2e(name):
    return load_fixture(f"aws/e2e/{name}.json")


class AcmeAws(FakeRunner):
    """A fake AWS account with partial read permissions.

    Responses are keyed by (service, operation, region) for plain calls and by (service, operation, region, query)
    for jmespath checks, which pass --query (FakeRunner ignores it, but the same operation is read raw by other
    checks). A call nobody scripted is answered with AccessDenied, as an auditor profile without that permission.
    """

    DENIED = ("__denied__", None, None)

    def __init__(self, responses):
        super().__init__({**responses, self.DENIED: err(ACCESS_DENIED.format(op="Unscripted", perm="*"))})

    def _key(self, argv):
        key = FakeRunner._key(argv)
        if argv[0] == "aws" and "--query" in argv:
            key += (argv[argv.index("--query") + 1],)
        return key if key in self.responses else self.DENIED


def offenders_query(check_id):
    """(service, operation, region, query) of a jmespath check, read from the catalog."""
    check = next(c for c in catalog.load_checks(SKILL_DIR / "references" / "checks") if c["id"] == check_id)
    call = check["verify"]["calls"][0]
    return call["service"], call["operation"], REGION, check["verify"]["offenders"]


def acme_responses():
    inventory = json.loads((SKILL_DIR / "references" / "inventory.json").read_text(encoding="utf-8"))
    responses = {(spec["service"], spec["operation"], REGION): ok({}) for spec in inventory.values()}
    responses.update({
        ("sts", "get-caller-identity", REGION): ok(load_fixture("aws/core/sts-get-caller-identity.json")),
        ("ec2", "describe-regions", REGION): ok({"Regions": [{"RegionName": REGION, "OptInStatus": "opt-in-not-required"}]}),
        ("ec2", "describe-instances", REGION): ok(e2e("ec2-describe-instances")),
        ("ec2", "describe-security-groups", REGION): ok(e2e("ec2-describe-security-groups")),
        ("ec2", "describe-network-interfaces", REGION): ok(e2e("ec2-describe-network-interfaces")),
        ("ssm", "describe-instance-information", REGION): ok(load_fixture("aws/compute/ssm-describe-instance-information-none.json")),
        ("s3api", "list-buckets", REGION): ok(e2e("s3api-list-buckets")),
        ("s3api", "get-public-access-block", REGION): err(NO_PUBLIC_ACCESS_BLOCK),
        ("rds", "describe-db-instances", REGION): ok(e2e("rds-describe-db-instances")),
        ("cloudwatch", "describe-alarms", REGION): ok(load_fixture("aws/monitoring/cloudwatch-describe-alarms-covered.json")),
        ("sns", "list-subscriptions-by-topic", REGION): ok(load_fixture("aws/monitoring/sns-list-subscriptions-by-topic-pending.json")),
        ("inspector2", "batch-get-account-status", REGION): err(
            ACCESS_DENIED.format(op="BatchGetAccountStatus", perm="inspector2:BatchGetAccountStatus")),
        offenders_query("IAM-001"): ok(load_fixture("aws/core/iam-get-account-summary-offenders.json")),
    })
    return responses


def bash_only():
    return FakeRunner({("bash", None, None): {"returncode": 0}})


class PipelineCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.template = (SKILL_DIR / "assets" / "report-template.html").read_text(encoding="utf-8")

    def find(self, check_id, status=None, resource_id=None):
        return [f for f in self.findings["findings"] if f["check_id"] == check_id
                and (status is None or f["status"] == status)
                and (resource_id is None or f["resource"]["id"] == resource_id)]

    def one(self, check_id, status=None, resource_id=None):
        found = self.find(check_id, status, resource_id)
        self.assertEqual(len(found), 1, found)
        return found[0]


class FullPipelineTests(PipelineCase):
    def run_collect(self):
        scope = self.tmp / "scope.json"
        scope.write_text(json.dumps(load_fixture("scope-full.json")), encoding="utf-8")
        self.run_dir = self.tmp / "compliance-reports" / "acme-notes-full-2026-11-13-1200"
        self.aws = AcmeAws(acme_responses())
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = collect.main(["--scope", str(scope), "--out", str(self.run_dir), "--quiet"], runner=self.aws,
                                sleep=lambda s: None, which=lambda name: None)
        self.assertEqual(code, 0, stdout.getvalue())
        self.assertLessEqual(len(stdout.getvalue().splitlines()), 40)

    def test_full_pipeline_typed_vault(self):
        self.run_collect()
        index = vault_index.build_index(FIXTURES_DIR / "typed-vault")
        self.assertEqual(index["kind"], "typed")
        self.findings = assemble_findings.assemble(self.run_dir, index, CLAIMS, dict(META), SKILL_DIR)
        (self.run_dir / "findings.json").write_text(json.dumps(self.findings, ensure_ascii=False), encoding="utf-8")

        iam = self.one("IAM-001")
        self.assertEqual((iam["status"], iam["severity"]), ("FAIL", "critical"))
        self.assertEqual(self.one("NET-001", "FAIL", SG)["status"], "FAIL")
        dat = self.one("DAT-007", "FAIL")
        self.assertEqual(dat["severity"], "critical")
        self.assertEqual(dat["resource"]["id"], "acme-notes-uploads")
        mon = [f for f in self.find("MON-001", "FAIL") if f["evidence"].get("missing_part") == "confirmed_subscription"]
        self.assertEqual([f["resource"]["id"] for f in mon], ["acme-notes-db"])
        det = self.one("DET-006")
        self.assertEqual(det["status"], "NO_VERIFICADO")
        self.assertIn("inspector2:BatchGetAccountStatus", det["missing"])
        self.assertEqual(self.one("ENC-006", "DRIFT")["resource"]["id"], "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d")
        self.assertEqual(self.one(None, "UNDOCUMENTED")["resource"]["id"], "acme-notes-dlq")

        html = render_report.render(self.findings, self.template)
        (self.run_dir / "report.html").write_text(html, encoding="utf-8")
        self.assertIn("F-0001", html)

        inventory = json.loads((self.run_dir / "inventory.json").read_text(encoding="utf-8"))
        rules = json.loads((SKILL_DIR / "references" / "conflict-rules.json").read_text(encoding="utf-8"))
        verifier = bash_only()
        verification = verify_remediation.verify(self.findings, inventory, rules, runner=verifier,
                                                 which=lambda name: None, check_cli=True)
        (self.run_dir / "verification.json").write_text(json.dumps(verification, ensure_ascii=False), encoding="utf-8")
        self.assertTrue((self.run_dir / "verification.json").is_file())
        self.assertFalse(verification["cli_checked"])  # no aws CLI here: tolerated, reported
        self.assertEqual([c[0] for c in verifier.calls], ["bash"] * len(verifier.calls))
        net = verification["per_finding"][self.one("NET-001", "FAIL", SG)["id"]]
        self.assertNotEqual(net["status"], "OK")  # CR-003: the instance behind the SG has no SSM
        self.assertIn("CR-003", [i["rule_id"] for i in net["issues"]])

        verified_html = render_report.render(self.findings, self.template, verification)
        for marker in (UNVERIFIED_MARKER, CR003_MARKER):  # present only when verification is embedded in the data block
            self.assertNotIn(marker, html)
            self.assertIn(marker, verified_html)
        self.assertIn("Verificación", verified_html)
        self.assertIn("F-0001", verified_html)

    def test_only_allowlisted_operations_are_called(self):
        self.run_collect()
        calls = [argv for argv in self.aws.calls if argv[0] == "aws"]
        self.assertGreater(len(calls), 20)
        self.assertEqual([argv for argv in self.aws.calls if argv[0] != "aws"], [])
        for argv in calls:
            args = argv[3:argv.index("--output")]  # the call's own args; --output/--region/--query are added by the runner
            aws_runner.assert_read_only(argv[1], argv[2], args)  # the runner's own predicate (allowlist + denylist)
        self.assertTrue(all(kwargs.get("shell") is not True for kwargs in self.aws.kwargs))


class WithoutAwsTests(PipelineCase):
    def test_pipeline_without_aws(self):
        vault = self.tmp / "vault"
        shutil.copytree(FIXTURES_DIR / "free-vault", vault)
        make_secret_note(vault)
        run_dir = self.tmp / "run"
        run_dir.mkdir()
        index = vault_index.build_index(vault)
        claims = load_fixture("vault-claims.json")
        self.findings = assemble_findings.assemble(run_dir, index, claims, dict(META), SKILL_DIR)

        statuses = {f["status"] for f in self.findings["findings"]}
        self.assertTrue({"DOCUMENTED_ONLY", "DOCUMENTED_GAP"} <= statuses, statuses)
        self.assertNotIn("PASS", statuses)
        secrets = [f for f in self.findings["findings"] if f["status"] == "FAIL" and f["severity"] == "critical"]
        self.assertEqual(len(secrets), 1, secrets)
        self.assertEqual(secrets[0]["title"], assemble_findings.SECRET_TITLE)
        self.assertTrue(any(w.startswith("link roto en") for w in self.findings["warnings"]), self.findings["warnings"])
        self.assertIn("Sin credenciales AWS", " ".join(self.findings["notes"]))

        html = render_report.render(self.findings, self.template)
        self.assertIn("F-0001", html)
        self.assertNotIn("AKIA" + "TESTKEYABCDEMNOP", html)
        self.assertNotIn("AKIA" + "TESTKEYABCDEMNOP", json.dumps(self.findings))


if __name__ == "__main__":
    unittest.main()
