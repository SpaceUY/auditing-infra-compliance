import contextlib
import copy
import io
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import helpers
from helpers import FakeRunner, SKILL_DIR

import catalog
import render_report
import validate_catalog
import verify_remediation

RULES = json.loads((SKILL_DIR / "references" / "conflict-rules.json").read_text(encoding="utf-8"))
TEMPLATE = (SKILL_DIR / "assets" / "report-template.html").read_text(encoding="utf-8")
FINDINGS = helpers.load_fixture("findings-verify.json")
INVENTORY = helpers.load_fixture("inventory-verify.json")
CLAIMS = helpers.load_fixture("verification-claims.json")
HEADER = 'REGION="us-east-1"\nACCOUNT_ID="111122223333"\n'


def bash_ok():
    return FakeRunner({("bash", None, None): {"returncode": 0}})


def finding(number, check, cmds, *, kind="cli", notes="", severity="medium", status="FAIL", domain="network",
            deps=None, verify_after="aws sts get-caller-identity", rtype="security_group", rid=None, evidence=None):
    rid = rid or f"sg-{number:017x}"
    return {"id": f"F-{number:04d}", "check_id": check, "title": f"Chequeo {check}", "domain": domain, "status": status,
            "severity": severity, "resource": {"type": rtype, "id": rid, "region": "us-east-1", "name": rid},
            "remediation": {"kind": kind, "risk": "low", "downtime": False, "steps": ["Aplicar."], "commands": cmds,
                            "verify_after": verify_after, "notes": notes},
            "evidence": evidence or {}, "depends_on_me": deps or [], "missing": []}


def sg_evidence(*attachments):
    return {"attachments": [{"eni_id": f"eni-{n}", "instance_id": i, "description": d, "requester_id": None}
                            for n, (i, d) in enumerate(attachments)]}


ALB_ENI = (None, "ELB app/acme-notes-alb/50dc6c495c0c9188")
INSTANCE = "i-0123456789abcdef0"


def doc(*findings):
    return {"meta": {}, "findings": list(findings), "dependencies": [], "warnings": [], "notes": []}


def run(*findings, **kwargs):
    kwargs.setdefault("runner", bash_ok())
    return verify_remediation.verify(doc(*findings), kwargs.pop("inventory", []), kwargs.pop("rules", RULES), **kwargs)


def kinds(result, fid):
    return [i["kind"] for i in result["per_finding"][fid]["issues"]]


def status(result, fid):
    return result["per_finding"][fid]["status"]


SAFE = "aws s3api get-bucket-versioning --bucket acme-notes-uploads"


class AutomaticChecksTests(unittest.TestCase):
    def test_syntax_error_is_conflict(self):
        broken = 'aws s3api put-x --bucket "a'
        result = verify_remediation.verify(doc(finding(1, "DAT-007", [broken])), [], RULES)
        self.assertEqual(status(result, "F-0001"), "CONFLICTO")
        self.assertIn("syntax", kinds(result, "F-0001"))

    def test_clean_fix_is_ok(self):
        result = run(finding(1, "DAT-007", [HEADER + SAFE]))
        self.assertEqual(status(result, "F-0001"), "OK")
        self.assertEqual(result["per_finding"]["F-0001"]["issues"], [])
        self.assertEqual(result["summary"], {"OK": 1, "REVISAR": 0, "CONFLICTO": 0})

    def test_bash_n_never_executes(self):
        runner = bash_ok()
        command = HEADER + "aws s3api delete-bucket --bucket acme-notes-uploads"
        run(finding(1, "DAT-007", [command]), runner=runner)
        self.assertEqual(runner.calls, [["bash", "-n"]])
        self.assertEqual(runner.kwargs[0]["input"], command)
        self.assertIsNot(runner.kwargs[0].get("shell"), True)
        self.assertNotIn(command, [part for call in runner.calls for part in call])

    def test_unresolved_placeholder_is_conflict(self):
        result = run(finding(1, "DAT-007", ['aws ec2 describe-security-groups --group-ids "{resource_id}" --region {region}']))
        self.assertEqual(status(result, "F-0001"), "CONFLICTO")
        self.assertIn("placeholder_sin_resolver", kinds(result, "F-0001"))

    def test_literal_json_braces_are_not_placeholders(self):
        command = """aws s3api put-bucket-tagging --bucket b --tagging '{"TagSet":[{"Key":"Environment","Value":"prod"}]}'"""
        result = run(finding(1, "DAT-007", [command]))
        self.assertNotIn("placeholder_sin_resolver", kinds(result, "F-0001"))

    def test_detail_json_placeholder_is_unresolved(self):
        result = run(finding(1, "DAT-007", ["aws ec2 revoke-security-group-ingress --ip-permissions {detail_json:ip_permissions}"],
                             kind="cli_with_decision", notes="Revisar."))
        self.assertIn("placeholder_sin_resolver", kinds(result, "F-0001"))

    def test_completar_counted_and_review(self):
        command = HEADER + 'KEY="__COMPLETAR_KMS_KEY_ARN__"\nOWNER="__COMPLETAR_OWNER_EMAIL__"\necho "$KEY" "$OWNER" "$KEY"'
        result = run(finding(1, "DAT-007", [command]), )
        self.assertEqual(status(result, "F-0001"), "REVISAR")
        self.assertIn("requiere_completar", kinds(result, "F-0001"))
        self.assertEqual(result["completar_pendientes"], 2)
        second = run(finding(1, "DAT-007", [command]), finding(2, "DAT-007", [HEADER + 'X="__COMPLETAR_KMS_KEY_ARN__"']))
        self.assertEqual(second["completar_pendientes"], 3)

    def test_heredoc_or_set_e_is_conflict(self):
        for command in ("cat <<EOF\nhola\nEOF", "set -e\n" + SAFE, "set -eu\n" + SAFE, "set -o errexit\n" + SAFE):
            result = run(finding(1, "DAT-007", [command]))
            self.assertEqual(status(result, "F-0001"), "CONFLICTO", command)
            self.assertIn("higiene", kinds(result, "F-0001"), command)

    def test_destructive_without_warning_is_review(self):
        for op in ("delete-bucket --bucket b", "revoke-security-group-ingress --group-id g", "terminate-instances --instance-ids i",
                   "put-bucket-policy --bucket b --policy file://p.json", "put-key-policy --key-id k --policy-name default",
                   "update-account-password-policy --minimum-password-length 14"):
            result = run(finding(1, "DAT-007", [f"aws svc {op}"], kind="cli"))
            self.assertEqual(status(result, "F-0001"), "REVISAR", op)
            self.assertIn("destructivo_sin_aviso", kinds(result, "F-0001"), op)
        result = run(finding(1, "DAT-007", ["aws ec2 stop-instances --instance-ids i --force"], kind="cli"))
        self.assertIn("destructivo_sin_aviso", kinds(result, "F-0001"))

    def test_destructive_with_warning_is_fine(self):
        command = "aws ec2 revoke-security-group-ingress --group-id g"
        for kind, notes in (("planned_change", ""), ("cli_with_decision", "Revisar antes.")):
            result = run(finding(1, "DAT-007", [command], kind=kind, notes=notes))
            self.assertNotIn("destructivo_sin_aviso", kinds(result, "F-0001"), kind)
        result = run(finding(1, "DAT-007", [command], kind="cli_with_decision", notes=""))
        self.assertIn("destructivo_sin_aviso", kinds(result, "F-0001"))

    def test_destructive_flags_and_s3_removals(self):
        for command in ("aws s3 rm s3://acme-notes-uploads/old --recursive", "aws s3 rb s3://acme-notes-uploads",
                        "aws s3 sync . s3://acme-notes-uploads --delete", "aws secretsmanager rotate-secret --force-delete-without-recovery",
                        "aws ec2 describe-instances && aws ec2 terminate-instances --instance-ids i-1",
                        'X=$(aws ec2 describe-instances) ; aws ec2 delete-volume --volume-id v',
                        'for i in a b; do aws ec2 stop-instances --instance-ids $i; done'):
            result = run(finding(1, "DAT-007", [command]))
            self.assertIn("destructivo_sin_aviso", kinds(result, "F-0001"), command)

    def test_benign_force_flags_and_quoted_words_are_not_destructive(self):
        for command in ("aws ecs update-service --cluster c --service s --force-new-deployment",
                        'echo "aws s3 rm s3://x; aws ec2 delete-volume"', "echo 'aws ec2 terminate-instances'",
                        'aws ec2 describe-instances --query "Reservations[?State==`--delete`]"',
                        'VOL=$(aws ec2 describe-volumes --query "Volumes[0].VolumeId") && echo "$VOL"'):
            result = run(finding(1, "DAT-007", [command]))
            self.assertNotIn("destructivo_sin_aviso", kinds(result, "F-0001"), command)

    def test_aws_inside_command_substitution_in_double_quotes_is_a_command(self):
        command = 'aws ec2 describe-instances --instance-ids "$(aws ec2 delete-volume --volume-id v)"'
        self.assertIn("destructivo_sin_aviso", kinds(run(finding(1, "DAT-007", [command])), "F-0001"))

    def test_here_string_is_not_a_heredoc(self):
        result = run(finding(1, "DAT-007", ["cat <<< \"$X\"\n" + SAFE]))
        self.assertNotIn("higiene", kinds(result, "F-0001"))
        self.assertIn("higiene", kinds(run(finding(1, "DAT-007", ["cat <<-EOF\nx\nEOF"])), "F-0001"))

    def test_destructive_words_in_comments_and_queries_ignored(self):
        command = "# delete-bucket y revoke-x son solo texto\naws ec2 describe-security-groups --query 'SecurityGroups[?x==`delete-me`]'"
        result = run(finding(1, "DAT-007", [command]))
        self.assertNotIn("destructivo_sin_aviso", kinds(result, "F-0001"))

    def test_dependency_impact_names_tests(self):
        deps = [{"tool": "drata", "test": 104, "name": "Cloud Storage Public Access Disabled"},
                {"tool": "vanta", "test": "Buckets use Block Public Access settings", "name": "Buckets use Block Public Access settings"}]
        result = run(finding(1, "DAT-007", [HEADER + SAFE], deps=deps))
        self.assertEqual(status(result, "F-0001"), "REVISAR")
        issue = next(i for i in result["per_finding"]["F-0001"]["issues"] if i["kind"] == "impacto_dependencias")
        self.assertIn("Drata 104", issue["message"])
        self.assertIn("Cloud Storage Public Access Disabled", issue["message"])
        self.assertIn("Buckets use Block Public Access settings", issue["message"])


class ConflictRuleTests(unittest.TestCase):
    def alb_sg(self, *attachments):
        return finding(1, "NET-003", ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes="Decidir.",
                       evidence=sg_evidence(*attachments))

    def test_cr001_port80_vs_redirect(self):
        result = run(self.alb_sg(ALB_ENI, (INSTANCE, "")))
        self.assertEqual(status(result, "F-0001"), "CONFLICTO")
        self.assertIn("conflicto_regla", kinds(result, "F-0001"))
        conflict = next(c for c in result["conflicts"] if c["rule_id"] == "CR-001")
        self.assertEqual((conflict["status"], conflict["findings"]), ("CONFLICTO", ["F-0001"]))
        self.assertIn("redirección", conflict["message"])

    def test_cr001_needs_an_alb_attachment_not_just_an_alb_in_the_region(self):
        ec2_only = self.alb_sg((INSTANCE, ""))
        redirect_ok = finding(2, "TLS-002", [], status="PASS", rtype="elbv2", rid="acme-notes-alb")
        self.assertEqual(run(ec2_only, redirect_ok)["conflicts"], [])
        self.assertEqual(run(self.alb_sg())["conflicts"], [])  # no attachment data: no conflict
        no_evidence = finding(1, "NET-003", ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes="n")
        self.assertEqual(run(no_evidence)["conflicts"], [])
        nlb = self.alb_sg((None, "ELB net/acme-notes-nlb/8f2ae1a53a0e1b2b"))
        self.assertEqual(run(nlb)["conflicts"], [])

    def ssh_and_instance(self, *, unreachable=True, attached=INSTANCE, instance_id=INSTANCE):
        ssh = finding(1, "NET-001", ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes="Ojo.",
                      severity="critical", evidence=sg_evidence((attached, "")) if attached else {})
        ssm = finding(2, "CMP-006", [SAFE], kind="planned_change", severity="low", domain="compute", rtype="ec2_instance",
                      rid=instance_id, evidence={"problems": ["x"], "ssm_unreachable": unreachable})
        return ssh, ssm

    def test_cr003_ssh_without_ssm_orders_ssm_first(self):
        result = run(*self.ssh_and_instance())
        self.assertEqual(status(result, "F-0001"), "CONFLICTO")
        conflict = next(c for c in result["conflicts"] if c["rule_id"] == "CR-003")
        self.assertEqual(conflict["findings"], ["F-0001", "F-0002"])
        self.assertLess(result["apply_order"].index("F-0002"), result["apply_order"].index("F-0001"))
        self.assertEqual(status(result, "F-0002"), "OK")

    def test_cr003_also_covers_rdp(self):
        ssh, ssm = self.ssh_and_instance()
        ssh["check_id"] = "NET-002"
        self.assertEqual(status(run(ssh, ssm), "F-0001"), "CONFLICTO")

    def test_cr003_ignores_ssm_registered_instance_with_only_a_patch_problem(self):
        result = run(*self.ssh_and_instance(unreachable=False))
        self.assertEqual(result["conflicts"], [])
        self.assertEqual(status(result, "F-0001"), "OK")

    def test_cr003_ignores_unrelated_instances_and_missing_attachment_data(self):
        self.assertEqual(run(*self.ssh_and_instance(instance_id="i-0fedcba9876543210"))["conflicts"], [])
        self.assertEqual(run(*self.ssh_and_instance(attached=None))["conflicts"], [])
        ssh, _ = self.ssh_and_instance()
        self.assertEqual(run(ssh)["conflicts"], [])

    def test_cr002_orders_key_before_trail(self):
        trail = finding(1, "LOG-003", [SAFE], kind="planned_change", severity="high", domain="logging", rtype="cloudtrail_trail")
        key = finding(2, "INT-004", [SAFE], kind="cli_with_decision", notes="n", severity="low", domain="integration", rtype="kms_key")
        result = run(trail, key)
        self.assertEqual(status(result, "F-0001"), "REVISAR")
        self.assertLess(result["apply_order"].index("F-0002"), result["apply_order"].index("F-0001"))

    def test_any_fail_rules_review_each_check(self):
        for check in ("CMP-001", "CMP-002", "IAM-008", "IAM-009", "IAM-010", "TLS-001", "ENC-002", "ENC-003", "ENC-004",
                      "INV-003", "INT-004", "DAT-002"):
            result = run(finding(1, check, [SAFE], kind="planned_change"))
            self.assertEqual(status(result, "F-0001"), "REVISAR", check)
            self.assertIn("conflicto_regla", kinds(result, "F-0001"), check)

    def test_cr009_any_put_key_policy(self):
        policy = finding(1, "ENC-007", ["aws kms put-key-policy --key-id k --policy-name default --policy file://p.json"],
                         kind="cli_with_decision", notes="Conservar el statement root.")
        result = run(policy)
        issue = next(i for i in result["per_finding"]["F-0001"]["issues"] if i["kind"] == "conflicto_regla")
        self.assertEqual(issue["rule_id"], "CR-009")

    def test_all_fail_and_same_resource_scope(self):
        rules = [{"id": "CR-X", "when": {"all_fail": ["AAA-001", "BBB-001"]}, "scope": "same_resource", "status": "CONFLICTO",
                  "message": "juntos rompen", "order": []}]
        a = finding(1, "AAA-001", [SAFE], rid="r-1")
        b_same = finding(2, "BBB-001", [SAFE], rid="r-1")
        b_other = finding(3, "BBB-001", [SAFE], rid="r-2")
        result = run(a, b_other, rules=rules)
        self.assertEqual(result["conflicts"], [])
        result = run(a, b_same, b_other, rules=rules)
        self.assertEqual(result["conflicts"][0]["findings"], ["F-0001", "F-0002"])
        self.assertEqual(status(result, "F-0003"), "OK")

    def test_apply_order_by_group_and_severity(self):
        specs = [(1, "TAG-001", "integration", "low", "cli"), (2, "NET-009", "network", "critical", "cli"),
                 (3, "IAM-020", "iam", "low", "cli"), (4, "LOG-009", "logging", "medium", "cli"),
                 (5, "DET-009", "detection", "high", "cli"), (6, "ENC-006", "encryption", "medium", "cli"),
                 (7, "ENC-009", "encryption", "high", "planned_change"), (8, "ENC-010", "encryption", "low", "cli"),
                 (9, "DAT-009", "data", "high", "cli"), (10, "MON-009", "monitoring", "high", "cli"),
                 (11, "NET-010", "network", "medium", "cli")]
        findings = [finding(n, c, [SAFE], kind=k, domain=d, severity=s, notes="n") for n, c, d, s, k in specs]
        findings[5]["resource"]["type"] = "kms_key"
        order = run(*findings)["apply_order"]
        # iam, logging+detection (by severity), kms, encryption (planned_change last), network (by severity), data, monitoring, integration
        self.assertEqual(order, ["F-0003", "F-0005", "F-0004", "F-0006", "F-0008", "F-0007", "F-0002", "F-0011", "F-0009", "F-0010", "F-0001"])

    def test_order_cycle_ignored_with_gap(self):
        rules = [{"id": "CR-A", "when": {"any_fail": ["AAA-001"]}, "scope": "same_account", "status": "REVISAR", "message": "a",
                  "order": [["AAA-001", "BBB-001"]]},
                 {"id": "CR-B", "when": {"any_fail": ["BBB-001"]}, "scope": "same_account", "status": "REVISAR", "message": "b",
                  "order": [["BBB-001", "AAA-001"]]}]
        a = finding(1, "AAA-001", [SAFE], severity="low")
        b = finding(2, "BBB-001", [SAFE], severity="critical")
        result = run(a, b, rules=rules)
        self.assertEqual(result["apply_order"], ["F-0002", "F-0001"])
        self.assertTrue(any("ciclo" in g["message"] for g in result["gaps"]))


class GapTests(unittest.TestCase):
    def test_gaps_listed(self):
        result = verify_remediation.verify(FINDINGS, INVENTORY, RULES, runner=bash_ok())
        by_kind = {}
        for gap in result["gaps"]:
            by_kind.setdefault(gap["kind"], []).append(gap)
        self.assertEqual({"sin_arreglo", "no_verificado", "recurso_sin_chequeo", "sin_verify_after"}, set(by_kind))
        self.assertEqual([g["ref"] for g in by_kind["sin_arreglo"]], ["F-0009"])
        self.assertEqual([g["ref"] for g in by_kind["sin_verify_after"]], ["F-0010"])
        self.assertIn("rds:DescribeDBInstances", by_kind["no_verificado"][0]["message"])
        self.assertEqual(by_kind["no_verificado"][0]["ref"], "F-0008")
        orphan = by_kind["recurso_sin_chequeo"]
        self.assertEqual([g["ref"] for g in orphan], ["vpc"])
        self.assertIn("vpc-0aaa1111bbbb2222c", orphan[0]["message"])
        self.assertNotIn("acme-notes-uploads", orphan[0]["message"])

    def test_console_only_without_commands_is_not_a_gap(self):
        result = verify_remediation.verify(FINDINGS, INVENTORY, RULES, runner=bash_ok())
        self.assertNotIn("F-0007", [g["ref"] for g in result["gaps"]])

    def test_fixture_end_to_end(self):
        result = verify_remediation.verify(FINDINGS, INVENTORY, RULES, runner=bash_ok())
        self.assertEqual(status(result, "F-0003"), "CONFLICTO")  # CR-001: el SG lo usa una ENI de ALB
        self.assertEqual(status(result, "F-0001"), "CONFLICTO")  # CR-003: su instancia no está en SSM (F-0002)
        self.assertEqual(status(result, "F-0005"), "REVISAR")
        self.assertEqual(status(result, "F-0006"), "OK")
        self.assertEqual(result["completar_pendientes"], 2)
        self.assertEqual(sum(result["summary"].values()), len(result["per_finding"]))
        self.assertEqual(set(result["apply_order"]), set(result["per_finding"]))
        self.assertNotIn("F-0004", result["per_finding"])
        self.assertNotIn("F-0008", result["per_finding"])
        self.assertFalse(result["cli_checked"])


class ClaimTests(unittest.TestCase):
    def test_claude_claim_cannot_downgrade_conflict(self):
        ssh, ssm = ConflictRuleTests().ssh_and_instance()
        claims = [{"finding_id": "F-0001", "status": "OK", "message": "Sin dependencias.", "vault_note": None}]
        result = run(ssh, ssm, claims=claims)
        self.assertEqual(status(result, "F-0001"), "CONFLICTO")
        self.assertEqual(status(run(ssh, ssm), "F-0001"), "CONFLICTO")

    def test_claim_can_raise_status_and_is_attributed(self):
        result = run(finding(1, "DAT-007", [HEADER + SAFE]), claims=[
            {"finding_id": "F-0001", "status": "CONFLICTO", "message": "La Lambda de envío usa la key.", "vault_note": "systems/Mailer Lambda.md"}])
        self.assertEqual(status(result, "F-0001"), "CONFLICTO")
        issue = result["per_finding"]["F-0001"]["issues"][0]
        self.assertEqual((issue["kind"], issue["source"], issue["rule_id"]), ("claude", "claude", None))
        self.assertIn("La Lambda de envío usa la key.", issue["message"])
        self.assertIn("systems/Mailer Lambda.md", issue["message"])

    def test_ok_claim_and_unknown_finding_are_ignored(self):
        result = run(finding(1, "DAT-007", [HEADER + SAFE]), claims=[
            {"finding_id": "F-0001", "status": "OK", "message": "ok", "vault_note": None},
            {"finding_id": "F-9999", "status": "CONFLICTO", "message": "x", "vault_note": None}])
        self.assertEqual(status(result, "F-0001"), "OK")
        self.assertEqual(result["summary"]["CONFLICTO"], 0)

    def test_malformed_claims_are_skipped_with_a_warning(self):
        good = {"finding_id": "F-0001", "status": "REVISAR", "message": "ok", "vault_note": None}
        bad = ["texto", 7, None, {"finding_id": ["F-0001"], "status": "REVISAR"}, {"finding_id": "F-0001", "status": ["x"]},
               {"finding_id": "F-0001", "status": "REVISAR", "message": {"a": 1}}, {"finding_id": "F-0001", "status": "REVISAR", "vault_note": 3},
               {"status": "REVISAR"}]
        result = run(finding(1, "DAT-007", [HEADER + SAFE]), claims=bad + [good])
        self.assertEqual(status(result, "F-0001"), "REVISAR")
        self.assertEqual(len(result["warnings"]), len(bad))
        self.assertIn("claim 1 ignorado", result["warnings"][0])
        self.assertEqual(run(finding(1, "DAT-007", [HEADER + SAFE]))["warnings"], [])
        self.assertEqual(len(run(finding(1, "DAT-007", [HEADER + SAFE]), claims={"a": 1})["warnings"]), 1)

    def test_cli_with_malformed_claims_file_still_writes_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "findings.json").write_text(json.dumps(FINDINGS), encoding="utf-8")
            (tmp / "inventory.json").write_text("[]", encoding="utf-8")
            (tmp / "claims.json").write_text(json.dumps([{"finding_id": ["x"], "status": 1}, "x"]), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(verify_remediation.main(["--run-dir", str(tmp), "--claims", str(tmp / "claims.json")]), 0)
            self.assertEqual(len(json.loads((tmp / "verification.json").read_text(encoding="utf-8"))["warnings"]), 2)

    def test_claim_text_is_masked(self):
        key = "AKIA" + "TESTKEYABCDEMNOP"
        result = run(finding(1, "DAT-007", [HEADER + SAFE]), claims=[
            {"finding_id": "F-0001", "status": "REVISAR", "message": f"La key {key} la usa el pipeline.", "vault_note": None}])
        self.assertNotIn(key, json.dumps(result))

    def test_fixture_claims_merge(self):
        result = verify_remediation.verify(FINDINGS, INVENTORY, RULES, claims=CLAIMS, runner=bash_ok())
        self.assertEqual(status(result, "F-0006"), "REVISAR")
        self.assertEqual(status(result, "F-0003"), "CONFLICTO")


class CliCheckTests(unittest.TestCase):
    HELP_OK = "NAME\n       revoke-security-group-ingress\nOPTIONS\n       --group-id (string)\n       --ip-permissions (list)\n"

    def runner(self, help_text, returncode=0):
        return FakeRunner({("bash", None, None): {"returncode": 0},
                           ("ec2", "revoke-security-group-ingress", None): {"stdout": help_text, "returncode": returncode}})

    def test_check_cli_flags(self):
        command = 'aws ec2 revoke-security-group-ingress --group-id g --foo bar --region us-east-1'
        runner = self.runner(self.HELP_OK)
        result = run(finding(1, "NET-009", [command], kind="cli_with_decision", notes="n"), runner=runner, check_cli=True,
                     which=lambda name: "/usr/bin/aws")
        self.assertEqual(status(result, "F-0001"), "CONFLICTO")
        issue = next(i for i in result["per_finding"]["F-0001"]["issues"] if i["kind"] == "cli_invalida")
        self.assertIn("--foo", issue["message"])
        self.assertNotIn("--region", issue["message"])
        self.assertTrue(result["cli_checked"])
        help_call = [c for c in runner.calls if c[0] == "aws"]
        self.assertEqual(help_call, [["aws", "ec2", "revoke-security-group-ingress", "help"]])
        env = runner.kwargs[runner.calls.index(help_call[0])]["env"]
        self.assertEqual((env["PAGER"], env["AWS_PAGER"]), ("cat", ""))

    def test_valid_flags_pass_and_help_is_cached(self):
        command = 'aws ec2 revoke-security-group-ingress --group-id g --ip-permissions \'[]\'\naws ec2 revoke-security-group-ingress --group-id h --ip-permissions \'[]\''
        runner = self.runner(self.HELP_OK)
        result = run(finding(1, "NET-009", [command], kind="cli_with_decision", notes="n"), runner=runner, check_cli=True,
                     which=lambda name: "/usr/bin/aws")
        self.assertNotIn("cli_invalida", kinds(result, "F-0001"))
        self.assertEqual(len([c for c in runner.calls if c[0] == "aws"]), 1)

    def test_help_with_overstrike_is_readable(self):
        bold = "".join(f"{ch}\b{ch}" for ch in "--group-id") + " (string)\n"
        result = run(finding(1, "NET-009", ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes="n"),
                     runner=self.runner(bold), check_cli=True, which=lambda name: "/usr/bin/aws")
        self.assertNotIn("cli_invalida", kinds(result, "F-0001"))

    def test_unknown_operation_is_conflict(self):
        for code, stderr in ((252, "aws: error: argument operation: Invalid choice, valid choices are:"), (2, "usage: aws [options]")):
            runner = FakeRunner({("bash", None, None): {"returncode": 0},
                                 ("ec2", "revoke-security-group-ingress", None): {"returncode": code, "stderr": stderr}})
            result = run(finding(1, "NET-009", ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes="n"),
                         runner=runner, check_cli=True, which=lambda name: "/usr/bin/aws")
            self.assertEqual(status(result, "F-0001"), "CONFLICTO", code)
            self.assertIn("cli_invalida", kinds(result, "F-0001"), code)
            self.assertTrue(result["cli_checked"])

    def assert_help_unavailable(self, runner):
        result = run(finding(1, "NET-009", ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes="n"),
                     runner=runner, check_cli=True, which=lambda name: "/usr/bin/aws")
        self.assertNotIn("cli_invalida", kinds(result, "F-0001"))
        self.assertEqual(status(result, "F-0001"), "OK")
        self.assertFalse(result["cli_checked"])
        gap = next(g for g in result["gaps"] if g["ref"] == "aws-cli")
        self.assertIn("ayuda de la CLI no disponible", gap["message"])

    def test_help_failures_other_than_missing_operation_are_not_conflicts(self):
        # aws-cli without groff/mandoc exits 255; also a stray nonzero code with unrelated stderr
        for code, stderr in ((255, "\nCould not find executable named 'groff'\n"), (1, "boom"), (252, "no groff"), (2, "unrelated")):
            self.assert_help_unavailable(self.runner("", returncode=code) if not stderr else FakeRunner({
                ("bash", None, None): {"returncode": 0},
                ("ec2", "revoke-security-group-ingress", None): {"returncode": code, "stderr": stderr}}))

    def test_empty_help_timeout_and_missing_binary_are_not_conflicts(self):
        self.assert_help_unavailable(self.runner("", returncode=0))

        def timing_out(argv, **kwargs):
            if argv[0] == "aws":
                raise subprocess.TimeoutExpired(argv, 30)
            return subprocess.CompletedProcess(argv, 0, "", "")

        def missing(argv, **kwargs):
            if argv[0] == "aws":
                raise FileNotFoundError("aws")
            return subprocess.CompletedProcess(argv, 0, "", "")

        self.assert_help_unavailable(timing_out)
        self.assert_help_unavailable(missing)

    def test_help_runs_with_a_scrubbed_environment(self):
        runner = self.runner(self.HELP_OK)
        secrets = {"AWS_SECRET_ACCESS_KEY": "x", "AWS_PROFILE": "prod", "AWS_SESSION_TOKEN": "y", "PATH": "/usr/bin", "HOME": "/home/u", "OTHER": "z"}
        with mock.patch.dict(os.environ, secrets):
            run(finding(1, "NET-009", ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes="n"),
                runner=runner, check_cli=True, which=lambda name: "/usr/bin/aws")
        env = runner.kwargs[runner.calls.index(["aws", "ec2", "revoke-security-group-ingress", "help"])]["env"]
        self.assertEqual(sorted(k for k in env if k.startswith("AWS_")), ["AWS_PAGER"])
        self.assertEqual((env["PATH"], env["HOME"], env["PAGER"]), ("/usr/bin", "/home/u", "cat"))
        self.assertNotIn("OTHER", env)

    def test_only_first_command_of_a_pipeline_is_checked(self):
        command = "aws ec2 revoke-security-group-ingress --group-id g && aws ec2 other-op --zzz 1"
        result = run(finding(1, "NET-009", [command], kind="cli_with_decision", notes="n"), runner=self.runner(self.HELP_OK),
                     check_cli=True, which=lambda name: "/usr/bin/aws")
        self.assertNotIn("cli_invalida", kinds(result, "F-0001"))

    def test_no_cli_available_gap(self):
        runner = bash_ok()
        result = run(finding(1, "NET-009", [SAFE]), runner=runner, check_cli=True, which=lambda name: None)
        self.assertFalse(result["cli_checked"])
        self.assertTrue(any("CLI" in g["message"] for g in result["gaps"]))
        self.assertEqual(runner.calls, [["bash", "-n"]])

    def test_cli_not_requested_runs_no_aws(self):
        runner = bash_ok()
        result = run(finding(1, "NET-009", [SAFE]), runner=runner, which=lambda name: "/usr/bin/aws")
        self.assertFalse(result["cli_checked"])
        self.assertEqual(runner.calls, [["bash", "-n"]])


class CatalogTests(unittest.TestCase):
    def validate(self, rules):
        refs = SKILL_DIR / "references"
        checks = catalog.load_checks(refs / "checks")
        tsc, iso = catalog.load_frameworks(refs / "frameworks")
        drata = catalog.load_drata_map(refs / "mappings" / "drata-dcf.json")
        return catalog.validate(checks, tsc, iso, drata, rules)

    def test_conflict_rules_reference_existing_checks(self):
        self.assertEqual(self.validate(RULES), [])
        self.assertEqual([r["id"] for r in RULES], [f"CR-{n:03d}" for n in range(1, 11)])
        bad = copy.deepcopy(RULES)
        bad[2]["when"]["attached_instance_fail"]["check"] = "ZZZ-999"
        bad[1]["order"] = [["LOG-003", "QQQ-111"]]
        bad[3]["when"]["any_fail"] = ["WWW-000"]
        errors = self.validate(bad)
        self.assertTrue(any("ZZZ-999" in e for e in errors))
        self.assertTrue(any("WWW-000" in e for e in errors))
        self.assertTrue(any("QQQ-111" in e for e in errors))

    def test_conflict_rules_shape_is_validated(self):
        bad = copy.deepcopy(RULES)
        bad[0]["status"] = "ROJO"
        bad[1]["scope"] = "global"
        bad[2]["id"] = bad[3]["id"]
        bad[4]["when"] = {"nada": []}
        bad[0]["when"] = {"fail": "NET-003"}
        bad[5]["when"] = {"any_fail": ["TLS-001"], "attachment_description_prefix": "ELB app/"}
        bad[6]["when"] = {"fail": "NET-003", "attached_instance_fail": {"check": "CMP-006"}}
        errors = "\n".join(self.validate(bad))
        for expected in ("ROJO", "global", "duplicado", "when", "exactamente una de attachment_description_prefix",
                         "solo se usa con 'when.fail'", "attached_instance_fail requiere"):
            self.assertIn(expected, errors)

    def test_validate_catalog_cli_checks_rules(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(validate_catalog.main(), 0)


class RenderTests(unittest.TestCase):
    def verification(self):
        return verify_remediation.verify(FINDINGS, INVENTORY, RULES, claims=CLAIMS, runner=bash_ok())

    @staticmethod
    def embedded(html):
        return json.loads(re.search(r'<script id="data" type="application/json">(.*?)</script>', html, re.S).group(1))

    def test_render_with_verification_shows_badges_and_section(self):
        verification = self.verification()
        html = render_report.render(FINDINGS, TEMPLATE, verification)
        data = self.embedded(html)
        self.assertEqual(data["verification"], verification)
        self.assertEqual(data["findings"], FINDINGS["findings"])
        for token in ("id=\"verification\"", "renderVerification", "verifStatus", "ver-CONFLICTO", "ver-REVISAR", "ver-OK",
                      "Verificación", "verifWarnings", "apply_order", "completar_pendientes", "gaps", "conflicts"):
            self.assertIn(token, TEMPLATE, token)
        self.assertEqual(TEMPLATE.index('id="summary"') < TEMPLATE.index('id="verification"') < TEMPLATE.index('id="filters-section"'), True)

    def test_verification_section_uses_text_nodes_only(self):
        self.assertEqual(re.findall(r"innerHTML\s*=\s*[^'\"\s]", TEMPLATE), [])
        block = re.search(r"function renderVerification\(.*?\n\}", TEMPLATE, re.S).group(0)
        self.assertNotIn("innerHTML", block)
        self.assertNotRegex(TEMPLATE, r"<script[^>]+src=")

    def test_hostile_verification_text_is_escaped(self):
        verification = self.verification()
        verification["conflicts"].append({"rule_id": "CR-X", "findings": ["F-0001"], "status": "REVISAR",
                                          "message": "</script><script>alert(1)</script> x"})
        html = render_report.render(FINDINGS, TEMPLATE, verification)
        self.assertNotIn("</script><script>alert", html)
        self.assertNotIn(" ", html)
        self.assertEqual(self.embedded(html)["verification"]["conflicts"][-1]["message"], "</script><script>alert(1)</script> x")

    def test_low_risk_copy_excludes_conflicts(self):
        logic = re.search(r"function bulkCandidates\(.*?\n\}", TEMPLATE, re.S).group(0)
        self.assertIn("'CONFLICTO'", logic)
        self.assertIn("verifStatus(f)", logic)
        self.assertIn("'__COMPLETAR_'", logic)
        self.assertEqual(TEMPLATE.count("bulkCandidates("), 3)

    def test_render_without_verification_unchanged(self):
        plain = render_report.render(FINDINGS, TEMPLATE)
        self.assertEqual(plain, render_report.render(FINDINGS, TEMPLATE, None))
        self.assertNotIn("verification", self.embedded(plain))
        self.assertEqual(self.embedded(plain), FINDINGS)

    def test_stale_verification_key_in_findings_is_ignored_unless_passed(self):
        stale = {**FINDINGS, "verification": {"summary": {"OK": 99}}}
        self.assertEqual(render_report.render(stale, TEMPLATE), render_report.render(FINDINGS, TEMPLATE))
        self.assertNotIn("verification", self.embedded(render_report.render(stale, TEMPLATE)))
        fresh = self.verification()
        self.assertEqual(self.embedded(render_report.render(stale, TEMPLATE, fresh))["verification"], fresh)
        self.assertEqual(stale["verification"], {"summary": {"OK": 99}})

    def test_render_rejects_malformed_verification(self):
        with self.assertRaises(ValueError):
            render_report.render(FINDINGS, TEMPLATE, ["no", "es", "un", "dict"])

    def test_render_cli_accepts_verification_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "findings.json").write_text(json.dumps(FINDINGS), encoding="utf-8")
            (tmp / "verification.json").write_text(json.dumps(self.verification()), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                code = render_report.main([str(tmp / "findings.json"), "--verification", str(tmp / "verification.json")])
            self.assertEqual(code, 0)
            self.assertIn("verification", self.embedded((tmp / "report.html").read_text(encoding="utf-8")))
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(render_report.main([str(tmp / "findings.json"), "--verification", str(tmp / "nope.json")]), 2)
            self.assertIn("error", err.getvalue())


class CliTests(unittest.TestCase):
    def test_cli_tolerates_a_missing_inventory_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "findings.json").write_text(json.dumps(FINDINGS), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(verify_remediation.main(["--run-dir", str(tmp)]), 0)
            self.assertTrue((tmp / "verification.json").is_file())

    def test_cli_writes_verification_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "findings.json").write_text(json.dumps(FINDINGS), encoding="utf-8")
            (tmp / "inventory.json").write_text(json.dumps(INVENTORY), encoding="utf-8")
            claims = tmp / "claims.json"
            claims.write_text(json.dumps(CLAIMS), encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = verify_remediation.main(["--run-dir", str(tmp), "--claims", str(claims)])
            self.assertEqual(code, 0)
            written = json.loads((tmp / "verification.json").read_text(encoding="utf-8"))
            self.assertEqual(set(written), {"per_finding", "conflicts", "gaps", "apply_order", "completar_pendientes", "cli_checked", "summary",
                                        "warnings"})
            self.assertLessEqual(len(out.getvalue().splitlines()), 10)

    def test_cli_missing_inputs_is_clean_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(verify_remediation.main(["--run-dir", tmp]), 2)
            self.assertIn("error", err.getvalue())
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(verify_remediation.main(["--run-dir", tmp + "/no-existe"]), 2)


if __name__ == "__main__":
    unittest.main()
