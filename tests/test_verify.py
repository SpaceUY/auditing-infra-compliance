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

import assemble_findings
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
WARN = "Atención: puede cortar el acceso de quien hoy entra."  # a real warning (see verify_remediation.WARNING_WORDS)


class StatusCoverageTests(unittest.TestCase):
    """R61: every finding that carries commands is evaluated, not only FAIL; verify-only findings are not."""

    def test_documented_gap_with_commands_gets_a_status_count_pending_and_order(self):
        pending = 'REGION="us-east-1"\nKEY="__COMPLETAR_KMS_KEY_ID__"\naws s3api get-bucket-versioning --bucket b'
        gap = finding(1, "DAT-007", [pending], status="DOCUMENTED_GAP", domain="data")
        fail = finding(2, "NET-001", [HEADER + SAFE])
        result = run(gap, fail)
        self.assertEqual(set(result["per_finding"]), {"F-0001", "F-0002"})
        self.assertEqual(status(result, "F-0001"), "REVISAR")
        self.assertIn("requiere_completar", kinds(result, "F-0001"))
        self.assertEqual(result["completar_pendientes"], 1)
        self.assertEqual(set(result["apply_order"]), {"F-0001", "F-0002"})
        self.assertEqual(sum(result["summary"].values()), 2)

    def test_conflict_rules_cover_documented_gap_findings(self):
        gap = finding(1, "CMP-001", [HEADER + SAFE], status="DOCUMENTED_GAP", domain="compute", rtype="ec2_instance")
        self.assertIn("conflicto_regla", kinds(run(gap), "F-0001"))

    def test_verify_only_findings_are_not_evaluated(self):
        only = finding(1, "ENC-003", [], status="DOCUMENTED_ONLY", domain="encryption", rtype="rds_instance")
        only["remediation"].update(steps=[], note_status="no verificado: no aplicar sin confirmar")
        passed = finding(2, "DAT-007", [], status="PASS", domain="data")
        passed["remediation"].update(steps=[], note_status="verificado")
        result = run(only, passed, finding(3, "NET-001", [HEADER + SAFE]))
        self.assertEqual(set(result["per_finding"]), {"F-0003"})
        self.assertEqual(result["apply_order"], ["F-0003"])
        self.assertEqual(sum(result["summary"].values()), 1)

    def test_summary_matches_the_findings_the_html_shows_a_badge_for(self):
        gap = finding(1, "DAT-007", [HEADER + SAFE], status="DOCUMENTED_GAP")
        result = run(gap, finding(2, "NET-001", [HEADER + SAFE]))
        html = render_report.render(doc(gap, finding(2, "NET-001", [HEADER + SAFE])), TEMPLATE, result)
        self.assertIn('"F-0001"', html)
        self.assertEqual(sum(result["summary"].values()), len(result["per_finding"]))


class DowntimeFloorTests(unittest.TestCase):
    def test_a_fix_that_declares_downtime_is_never_ok(self):
        quiet = finding(1, "NET-001", [HEADER + SAFE])
        down = finding(2, "DAT-001", [HEADER + SAFE], domain="data")
        down["remediation"]["downtime"] = True
        console = finding(3, "IAM-001", [], kind="console_only", domain="iam")
        console["remediation"]["downtime"] = True
        result = run(quiet, down, console)
        self.assertEqual(status(result, "F-0001"), "OK")
        for fid in ("F-0002", "F-0003"):
            self.assertEqual(status(result, fid), "REVISAR", fid)
            self.assertIn("downtime", kinds(result, fid))
        message = next(i["message"] for i in result["per_finding"]["F-0002"]["issues"] if i["kind"] == "downtime")
        self.assertEqual(message, "el arreglo declara downtime")

    def test_downtime_does_not_lower_a_conflict(self):
        down = finding(1, "NET-001", ["echo $(("], domain="network")
        down["remediation"]["downtime"] = True
        self.assertEqual(status(run(down, runner=FakeRunner({("bash", None, None): {"returncode": 2, "stderr": "syntax"}})), "F-0001"),
                         "CONFLICTO")


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
        for kind, notes in (("planned_change", ""), ("cli_with_decision", "Atención: revoca el acceso de entrada.")):
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
        return finding(1, "NET-003", ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes=WARN,
                       evidence=sg_evidence(*attachments))

    def test_cr001_port80_vs_redirect(self):
        result = run(self.alb_sg(ALB_ENI, (INSTANCE, "")))
        self.assertEqual(status(result, "F-0001"), "CONFLICTO")
        self.assertIn("conflicto_regla", kinds(result, "F-0001"))
        conflict = next(c for c in result["conflicts"] if c["rule_id"] == "CR-001")
        self.assertEqual((conflict["status"], conflict["findings"]), ("CONFLICTO", ["F-0001"]))
        self.assertIn("redirección", conflict["message"])

    def test_cr001_needs_a_load_balancer_attachment_not_just_one_in_the_region(self):
        ec2_only = self.alb_sg((INSTANCE, ""))
        redirect_ok = finding(2, "TLS-002", [], status="PASS", rtype="elbv2", rid="acme-notes-alb")
        self.assertEqual(run(ec2_only, redirect_ok)["conflicts"], [])
        self.assertEqual(run(self.alb_sg())["conflicts"], [])  # no attachment data: no conflict
        no_evidence = finding(1, "NET-003", ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes=WARN)
        self.assertEqual(run(no_evidence)["conflicts"], [])
        nlb = self.alb_sg((None, "ELB net/acme-notes-nlb/8f2ae1a53a0e1b2b"))  # an NLB or classic ELB breaks too (review 2)
        self.assertEqual([c["rule_id"] for c in run(nlb)["conflicts"]], ["CR-001"])
        self.assertEqual(run(self.alb_sg((None, "AWS Lambda VPC ENI-x")))["conflicts"], [])

    def ssh_and_instance(self, *, unreachable=True, attached=INSTANCE, instance_id=INSTANCE):
        ssh = finding(1, "NET-001", ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes=WARN,
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
        key = finding(2, "INT-004", [SAFE], kind="cli_with_decision", notes=WARN, severity="low", domain="integration", rtype="kms_key")
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
        findings = [finding(n, c, [SAFE], kind=k, domain=d, severity=s, notes=WARN) for n, c, d, s, k in specs]
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


class ReviewTwoStepsAndPlaceholdersTests(unittest.TestCase):
    """D Important 2: steps-only fixes are verified and the placeholders of steps, verify_after and notes are counted."""

    @staticmethod
    def dns_gap(**fix):
        gap = finding(1, "EML-005", [], kind="console_only", status="DOCUMENTED_GAP", domain="email", rtype="ses_identity", rid="acme-notes.example")
        gap["remediation"].update(steps=["Publicar el TXT _dmarc con __COMPLETAR_EMAIL_DMARC__."], risk="medium", **fix)
        return gap

    def test_a_steps_only_fix_gets_a_status_a_pending_count_and_an_apply_order_slot(self):
        result = run(self.dns_gap())
        self.assertEqual(status(result, "F-0001"), "REVISAR")
        self.assertIn("requiere_completar", kinds(result, "F-0001"))
        self.assertEqual(result["completar_pendientes"], 1)
        self.assertEqual(result["apply_order"], ["F-0001"])
        self.assertEqual(result["summary"]["REVISAR"], 1)

    def test_a_steps_only_fix_without_placeholders_is_ok(self):
        gap = self.dns_gap()
        gap["remediation"]["steps"] = ["Publicar el TXT _dmarc."]
        self.assertEqual(status(run(gap), "F-0001"), "OK")

    def test_placeholders_in_verify_after_and_notes_are_counted_and_need_completing(self):
        fail = finding(1, "DAT-002", [HEADER + SAFE], verify_after='aws rds describe-db-instances --region "__COMPLETAR_REGION__"',
                       notes="Usar __COMPLETAR_RETENCION__ dias.")
        result = run(fail)
        self.assertEqual(result["completar_pendientes"], 2)
        self.assertEqual(status(result, "F-0001"), "REVISAR")
        self.assertIn("__COMPLETAR_REGION__", result["per_finding"]["F-0001"]["issues"][0]["message"])

    def test_an_unresolved_brace_placeholder_in_a_step_is_a_conflict(self):
        gap = self.dns_gap()
        gap["remediation"]["steps"] = ["Usar {resource_id}."]
        self.assertEqual(status(run(gap), "F-0001"), "CONFLICTO")


class ReviewTwoEvidenceTests(unittest.TestCase):
    """B I4: no green OK when the evidence a rule needs is missing."""

    def ssh(self, *attachments, check="NET-001"):
        return finding(1, check, ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes=WARN,
                       severity="critical", evidence=sg_evidence(*attachments))

    def ssm(self, number=2, *, state="FAIL", unreachable=False):
        return finding(number, "CMP-006", [SAFE], kind="planned_change", domain="compute", rtype="ec2_instance", rid=INSTANCE,
                       status=state, evidence={"ssm_unreachable": unreachable})

    def test_attached_instance_without_a_cmp006_result_is_review_and_a_gap(self):
        for others in ((), (finding(2, "TLS-002", [], status="PASS", rtype="elbv2", rid="x"),)):
            result = run(self.ssh((INSTANCE, ""), ), *others)
            self.assertEqual(status(result, "F-0001"), "REVISAR")
            self.assertEqual([k for k in kinds(result, "F-0001") if k != "downtime"], ["evidencia_faltante"])
            self.assertEqual(result["conflicts"], [])
            gap = next(g for g in result["gaps"] if g["ref"] == "F-0001")
            self.assertIn("CMP-006", gap["message"])
            self.assertIn(INSTANCE, gap["message"])

    def test_unverified_or_not_applicable_cmp006_counts_as_missing(self):
        for state in ("NO_VERIFICADO", "N/A"):
            result = run(self.ssh((INSTANCE, "")), self.ssm(state=state))
            self.assertIn("evidencia_faltante", kinds(result, "F-0001"), state)

    def test_a_cmp006_result_for_the_instance_clears_the_missing_evidence(self):
        for attached in (self.ssm(unreachable=False), self.ssm(state="PASS")):
            result = run(self.ssh((INSTANCE, "")), attached)
            self.assertNotIn("evidencia_faltante", kinds(result, "F-0001"))
            self.assertEqual(status(result, "F-0001"), "OK")

    def test_no_instances_attached_needs_no_evidence(self):
        self.assertEqual(status(run(self.ssh((None, "ELB app/x/1"), check="NET-002")), "F-0001"), "OK")
        self.assertEqual(status(run(self.ssh()), "F-0001"), "OK")

    def test_rdp_is_covered_like_ssh(self):
        self.assertIn("evidencia_faltante", kinds(run(self.ssh((INSTANCE, ""), check="NET-002")), "F-0001"))

    def test_cr001_covers_every_load_balancer_type(self):
        for description in ("ELB app/acme-notes-alb/50dc6c495c0c9188", "ELB net/acme-notes-nlb/8f2ae1a53a0e1b2b",
                            "ELB acme-notes-classic", "ELB gwy/acme-notes-gwlb/1"):
            for check in ("NET-003", "NET-004"):
                result = run(self.ssh((None, description), check=check))
                self.assertEqual(status(result, "F-0001"), "CONFLICTO", (description, check))
                self.assertEqual([c["rule_id"] for c in result["conflicts"]], ["CR-001"])
        self.assertEqual(run(self.ssh((None, "AWS Lambda VPC ENI-x"), check="NET-003"))["conflicts"], [])

    def test_the_cr001_message_names_every_balancer_type(self):
        rule = next(r for r in RULES if r["id"] == "CR-001")
        for word in ("ALB", "NLB", "clásico"):
            self.assertIn(word, rule["message"])


class ReviewTwoRiskAndWarningTests(unittest.TestCase):
    def test_risk_high_always_floors_at_review(self):
        for kind in ("cli", "cli_with_decision", "planned_change", "console_only"):
            fix = finding(1, "NET-005", [] if kind == "console_only" else [HEADER + SAFE], kind=kind, notes=WARN)
            fix["remediation"]["risk"] = "high"
            result = run(fix)
            self.assertEqual(status(result, "F-0001"), "REVISAR", kind)
            self.assertIn("riesgo_alto", kinds(result, "F-0001"), kind)
        medium = finding(1, "NET-005", [HEADER + SAFE])
        medium["remediation"]["risk"] = "medium"
        self.assertEqual(status(run(medium), "F-0001"), "OK")

    def test_risk_floor_never_lowers_a_conflict(self):
        fix = finding(1, "NET-003", ["echo $(("], kind="cli")
        fix["remediation"]["risk"] = "high"
        bad = FakeRunner({("bash", None, None): {"returncode": 2, "stderr": "syntax"}})
        self.assertEqual(status(run(fix, runner=bad), "F-0001"), "CONFLICTO")

    def test_notes_must_contain_a_warning_to_silence_the_destructive_check(self):
        command = "aws ec2 revoke-security-group-ingress --group-id g"
        for notes in ("Decidir.", "Ver el vault.", "Ojo.", "n", "Ejecutar en CloudShell"):
            result = run(finding(1, "DAT-007", [command], kind="cli_with_decision", notes=notes))
            self.assertIn("destructivo_sin_aviso", kinds(result, "F-0001"), notes)
        for notes in ("ADVERTENCIA: corta el tráfico.", "Riesgo: deja sin acceso a la subnet.", "Reemplaza toda la política.",
                      "Warning: this cannot be undone, data loss.", "Es irreversible.", "Borra la regla actual."):
            result = run(finding(1, "DAT-007", [command], kind="cli_with_decision", notes=notes))
            self.assertNotIn("destructivo_sin_aviso", kinds(result, "F-0001"), notes)

    def test_every_catalog_warning_note_is_recognised(self):
        unrecognised = {c["id"] for c in catalog.load_checks(SKILL_DIR / "references" / "checks")
                        if c["remediation"]["kind"] == "cli_with_decision" and verify_remediation._destructive_operations(c["remediation"]["commands"])
                        and not verify_remediation._has_warning(c["remediation"])}
        self.assertEqual(unrecognised, set())

    def test_replacing_operations_are_flagged(self):
        flagged = ("s3api put-bucket-policy", "s3api put-bucket-acl", "s3api put-bucket-lifecycle-configuration", "s3api put-bucket-logging",
                   "s3api put-bucket-notification-configuration", "s3api put-bucket-tagging", "s3api put-bucket-encryption",
                   "iam put-user-policy", "iam put-role-policy", "iam put-group-policy", "iam update-assume-role-policy",
                   "iam update-account-password-policy", "kms put-key-policy", "logs put-retention-policy", "ec2 replace-network-acl-entry",
                   "ec2 replace-route", "ec2 replace-iam-instance-profile-association", "ec2 modify-instance-attribute",
                   "ec2 modify-network-interface-attribute", "elbv2 modify-listener", "elbv2 modify-rule", "cloudtrail put-event-selectors",
                   "s3api put-public-access-block", "s3control put-public-access-block", "s3control put-account-public-access-block",
                   "resourcegroupstaggingapi untag-resources")
        for operation in flagged:
            result = run(finding(1, "DAT-007", [f"aws {operation} --x y"], kind="cli"))
            self.assertIn("destructivo_sin_aviso", kinds(result, "F-0001"), operation)
        for operation in ("s3api get-bucket-policy", "s3api put-object", "ec2 modify-volume", "rds modify-db-instance",
                          "iam put-user-permissions-boundary", "cloudwatch put-metric-data", "ec2 describe-network-acls",
                          "ec2 create-tags", "ssm put-parameter", "resourcegroupstaggingapi tag-resources",
                          "s3api get-public-access-block"):
            result = run(finding(1, "DAT-007", [f"aws {operation} --x y"], kind="cli"))
            self.assertNotIn("destructivo_sin_aviso", kinds(result, "F-0001"), operation)


class FinalCleanupBTests(unittest.TestCase):
    """Final cleanup B: placeholders in the verify_after of verify-only findings are counted (D2 minor 1), a missing findings.json is
    named (D2 minor 11), public access blocks and untag-resources are replacing operations."""

    def test_pending_values_in_verify_after_of_verify_only_findings_are_counted(self):
        only = finding(1, "ENC-003", [], status="DOCUMENTED_ONLY", domain="encryption", rtype="rds_instance",
                       verify_after="aws rds describe-db-instances --region __COMPLETAR_REGION__")
        only["remediation"].update(steps=[], note_status="no verificado: no aplicar sin confirmar")
        passed = finding(2, "DAT-007", [], status="PASS", domain="data", verify_after="aws s3api get-public-access-block --region us-east-1")
        passed["remediation"].update(steps=[], note_status="verificado")
        result = run(only, passed)
        self.assertEqual(result["completar_pendientes"], 1)
        self.assertEqual(result["per_finding"], {})  # still nothing to verify: no status for them
        fail = finding(3, "NET-001", [HEADER + 'X="__COMPLETAR_FOO__"\n' + SAFE])
        self.assertEqual(run(only, passed, fail)["completar_pendientes"], 2)

    def test_untag_resources_and_public_access_blocks_need_a_warning(self):
        for operation in ("resourcegroupstaggingapi untag-resources --resource-arn-list a --tag-keys k",
                          "s3api put-public-access-block --bucket b --public-access-block-configuration BlockPublicAcls=true"):
            result = run(finding(1, "DAT-007", [f"aws {operation}"], kind="cli"))
            self.assertEqual(status(result, "F-0001"), "REVISAR", operation)
            self.assertIn("destructivo_sin_aviso", kinds(result, "F-0001"), operation)
            warned = run(finding(1, "DAT-007", [f"aws {operation}"], kind="cli_with_decision", notes="ADVERTENCIA: reemplaza la configuración."))
            self.assertNotIn("destructivo_sin_aviso", kinds(warned, "F-0001"), operation)

    def test_cli_names_the_missing_findings_file(self):
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = verify_remediation.main(["--run-dir", tmp])
        self.assertEqual(code, 2)
        self.assertIn("findings.json", err.getvalue())
        self.assertIn("assemble_findings.py", err.getvalue())
        self.assertNotIn("Errno", err.getvalue())


class ReviewTwoVerificationOutputTests(unittest.TestCase):
    def test_claim_for_an_unknown_finding_warns(self):
        result = run(finding(1, "DAT-007", [HEADER + SAFE]), claims=[
            {"finding_id": "F-9999", "status": "CONFLICTO", "message": "x", "vault_note": None},
            {"finding_id": "F-0001", "status": "OK", "message": "ok", "vault_note": None}])
        self.assertEqual(len(result["warnings"]), 1)
        self.assertIn("claim 1 ignorado", result["warnings"][0])
        self.assertIn("F-9999", result["warnings"][0])

    def test_without_credentials_the_verification_says_nothing_was_checked_against_aws(self):
        findings = doc(finding(1, "DAT-007", [HEADER + SAFE]))
        findings["meta"] = {"aws": None}
        result = verify_remediation.verify(findings, [], RULES, runner=bash_ok())
        gap = next(g for g in result["gaps"] if g["ref"] == "aws")
        self.assertIn("sin credenciales AWS", gap["message"])
        findings["meta"] = {"aws": {"account_id": "111122223333"}}
        self.assertFalse([g for g in verify_remediation.verify(findings, [], RULES, runner=bash_ok())["gaps"] if g["ref"] == "aws"])
        self.assertFalse([g for g in run(finding(1, "DAT-007", [HEADER + SAFE]))["gaps"] if g["ref"] == "aws"])

    def test_cli_checked_needs_at_least_one_operation_compared(self):
        runner = FakeRunner({("bash", None, None): {"returncode": 0}})
        none = run(finding(1, "IAM-001", [], kind="console_only"), runner=runner, check_cli=True, which=lambda name: "/usr/bin/aws")
        self.assertFalse(none["cli_checked"])
        self.assertEqual((none["cli_requested"], none["cli_operations_checked"]), (True, 0))
        self.assertFalse(run(finding(1, "IAM-001", [], kind="console_only"))["cli_requested"])

    def test_missing_claims_file_is_a_warning_not_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "findings.json").write_text(json.dumps(FINDINGS), encoding="utf-8")
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                code = verify_remediation.main(["--run-dir", str(tmp), "--claims", str(tmp / "nada.json")])
            self.assertEqual(code, 0)
            warnings = json.loads((tmp / "verification.json").read_text(encoding="utf-8"))["warnings"]
            self.assertEqual(len(warnings), 1)
            self.assertIn("no existe", warnings[0])
            (tmp / "roto.json").write_text("{no json", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(verify_remediation.main(["--run-dir", str(tmp), "--claims", str(tmp / "roto.json")]), 2)


class CliCheckTests(unittest.TestCase):
    HELP_OK = "NAME\n       revoke-security-group-ingress\nOPTIONS\n       --group-id (string)\n       --ip-permissions (list)\n"

    def runner(self, help_text, returncode=0):
        return FakeRunner({("bash", None, None): {"returncode": 0},
                           ("ec2", "revoke-security-group-ingress", None): {"stdout": help_text, "returncode": returncode}})

    def test_check_cli_flags(self):
        command = 'aws ec2 revoke-security-group-ingress --group-id g --foo bar --region us-east-1'
        runner = self.runner(self.HELP_OK)
        result = run(finding(1, "NET-009", [command], kind="cli_with_decision", notes=WARN), runner=runner, check_cli=True,
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
        result = run(finding(1, "NET-009", [command], kind="cli_with_decision", notes=WARN), runner=runner, check_cli=True,
                     which=lambda name: "/usr/bin/aws")
        self.assertNotIn("cli_invalida", kinds(result, "F-0001"))
        self.assertEqual(len([c for c in runner.calls if c[0] == "aws"]), 1)

    def test_help_with_overstrike_is_readable(self):
        bold = "".join(f"{ch}\b{ch}" for ch in "--group-id") + " (string)\n"
        result = run(finding(1, "NET-009", ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes=WARN),
                     runner=self.runner(bold), check_cli=True, which=lambda name: "/usr/bin/aws")
        self.assertNotIn("cli_invalida", kinds(result, "F-0001"))

    def test_unknown_operation_is_conflict(self):
        for code, stderr in ((252, "aws: error: argument operation: Invalid choice, valid choices are:"), (2, "usage: aws [options]")):
            runner = FakeRunner({("bash", None, None): {"returncode": 0},
                                 ("ec2", "revoke-security-group-ingress", None): {"returncode": code, "stderr": stderr}})
            result = run(finding(1, "NET-009", ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes=WARN),
                         runner=runner, check_cli=True, which=lambda name: "/usr/bin/aws")
            self.assertEqual(status(result, "F-0001"), "CONFLICTO", code)
            self.assertIn("cli_invalida", kinds(result, "F-0001"), code)
            self.assertTrue(result["cli_checked"])

    def assert_help_unavailable(self, runner):
        result = run(finding(1, "NET-009", ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes=WARN),
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
            run(finding(1, "NET-009", ["aws ec2 revoke-security-group-ingress --group-id g"], kind="cli_with_decision", notes=WARN),
                runner=runner, check_cli=True, which=lambda name: "/usr/bin/aws")
        env = runner.kwargs[runner.calls.index(["aws", "ec2", "revoke-security-group-ingress", "help"])]["env"]
        self.assertEqual(sorted(k for k in env if k.startswith("AWS_")), ["AWS_PAGER"])
        self.assertEqual((env["PATH"], env["HOME"], env["PAGER"]), ("/usr/bin", "/home/u", "cat"))
        self.assertNotIn("OTHER", env)

    def test_only_first_command_of_a_pipeline_is_checked(self):
        command = "aws ec2 revoke-security-group-ingress --group-id g && aws ec2 other-op --zzz 1"
        result = run(finding(1, "NET-009", [command], kind="cli_with_decision", notes=WARN), runner=self.runner(self.HELP_OK),
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
            self.assertEqual(validate_catalog.main([]), 0)


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

    def test_low_risk_copy_excludes_conflicts_and_reviews(self):
        raw = re.search(r"function bulkRaw\(.*?\n\}", TEMPLATE, re.S).group(0)
        gate = re.search(r"function bulkCandidates\(.*?\n\}", TEMPLATE, re.S).group(0)
        self.assertIn("'__COMPLETAR_'", raw)
        self.assertIn("verifStatus(f) === 'OK'", gate)  # CONFLICTO, REVISAR and findings without an entry are all out
        self.assertIn("VERIF ?", gate)

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


class StaleVerificationTests(unittest.TestCase):
    """The verification is bound to findings.json by a digest of ids, check_ids and resource ids."""

    def setUp(self):
        self.verification = verify_remediation.verify(FINDINGS, INVENTORY, RULES, claims=CLAIMS, runner=bash_ok())

    def shifted(self):
        other = copy.deepcopy(FINDINGS)
        other["findings"][0]["resource"]["id"] = "sg-0f00000000000000f"
        return other

    def test_digest_depends_on_ids_resources_statuses_and_fixes_but_not_titles(self):
        digest = assemble_findings.findings_digest(FINDINGS)
        self.assertEqual(self.verification["findings_digest"], digest)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        changed = copy.deepcopy(FINDINGS)
        changed["findings"][0]["title"] = "otro título"
        changed["findings"][0]["evidence"] = {"otra": "evidencia"}
        self.assertEqual(assemble_findings.findings_digest(changed), digest)
        for mutate in (lambda f: f["findings"][0].update(id="F-9999"), lambda f: f["findings"][0].update(check_id="ZZZ-001"),
                       lambda f: f["findings"][0]["resource"].update(id="otro"), lambda f: f["findings"].pop(),
                       lambda f: f["findings"][0].update(status="PASS"),
                       lambda f: f["findings"][0]["remediation"].update(commands=["echo otro"]),
                       lambda f: f["findings"][0]["remediation"].update(notes="otras notas")):
            other = copy.deepcopy(FINDINGS)
            mutate(other)
            self.assertNotEqual(assemble_findings.findings_digest(other), digest)

    def test_render_ignores_a_stale_verification_and_flags_it(self):
        html = render_report.render(self.shifted(), TEMPLATE, self.verification)
        data = RenderTests.embedded(html)
        self.assertNotIn("verification", data)
        self.assertTrue(data["verification_stale"])
        self.assertTrue(render_report.verification_is_stale(self.shifted(), self.verification))

    def test_render_with_a_matching_verification_is_unchanged(self):
        html = render_report.render(FINDINGS, TEMPLATE, self.verification)
        data = RenderTests.embedded(html)
        self.assertEqual(data["verification"], self.verification)
        self.assertNotIn("verification_stale", data)
        self.assertFalse(render_report.verification_is_stale(FINDINGS, self.verification))

    def test_template_shows_a_visible_warning_when_stale(self):
        self.assertIn("verificación desactualizada: volver a correr verify_remediation", TEMPLATE)
        self.assertIn("DATA.verification_stale", TEMPLATE)
        self.assertIn('id="stale-warning"', TEMPLATE)

    def test_cli_warns_on_stale_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "findings.json").write_text(json.dumps(self.shifted()), encoding="utf-8")
            (tmp / "verification.json").write_text(json.dumps(self.verification), encoding="utf-8")
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                code = render_report.main([str(tmp / "findings.json"), "--verification", str(tmp / "verification.json")])
            self.assertEqual(code, 0)
            self.assertIn("verificación desactualizada: volver a correr verify_remediation", err.getvalue())
            self.assertNotIn("verification", RenderTests.embedded((tmp / "report.html").read_text(encoding="utf-8")))

    def test_cli_is_quiet_when_the_verification_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "findings.json").write_text(json.dumps(FINDINGS), encoding="utf-8")
            (tmp / "verification.json").write_text(json.dumps(self.verification), encoding="utf-8")
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                render_report.main([str(tmp / "findings.json"), "--verification", str(tmp / "verification.json")])
            self.assertEqual(err.getvalue(), "")

    def test_a_verification_without_digest_is_stale(self):
        # verify_remediation always writes the digest: one without it is old or hand-made and cannot be tied to these findings
        legacy = {k: v for k, v in self.verification.items() if k != "findings_digest"}
        self.assertTrue(render_report.verification_is_stale(FINDINGS, legacy))


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
            self.assertEqual(set(written), {"per_finding", "conflicts", "gaps", "apply_order", "completar_pendientes", "cli_checked", "cli_requested",
                                        "cli_operations_checked", "summary", "warnings", "findings_digest"})
            self.assertEqual(written["findings_digest"], assemble_findings.findings_digest(FINDINGS))
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
