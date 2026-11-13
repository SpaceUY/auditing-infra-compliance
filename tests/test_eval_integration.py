import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import helpers
from helpers import SKILL_DIR, load_fixture

import catalog
import collect
import evaluators
from test_eval_encryption import flags, for_each, merge
from test_eval_iam import RuleRunner, err, ok

INTEGRATION_JSON = SKILL_DIR / "references" / "checks" / "integration.json"
REFS = SKILL_DIR / "references"
REGION = "us-east-1"
KEY = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
DRATA, VANTA, APP = "DrataAutopilotRole", "vanta-auditor", "acme-notes-app"
NO_SUCH_ROLE = err("An error occurred (NoSuchEntity) when calling the ListAttachedRolePolicies operation: The role with name x cannot be found.")


def fx(name):
    return load_fixture(f"aws/integration/{name}.json")


def evaluate(name, responses, params=None):
    return evaluators.EVALUATORS[name](responses, params or {})


def catalog_check(check_id):
    data = json.loads(INTEGRATION_JSON.read_text(encoding="utf-8"))
    return next(c for c in data["checks"] if c["id"] == check_id)


def params_of(check_id):
    return catalog_check(check_id)["verify"]["params"]


def real(offenders):
    return [o for o in offenders if not o.get("not_applicable")]


def not_applicable(offenders):
    return sorted((o["resource_id"] for o in offenders if o.get("not_applicable")), key=str.lower)


def one(call, data):
    return {call: [(REGION, data)]}


def roles(name="inventory-with-drata-and-vanta"):
    return {"__inventory__": fx(name)}


class DrataRoleTests(unittest.TestCase):
    PARAMS = {"role_name": DRATA}

    def run_with(self, attached, inventory="inventory-with-drata-and-vanta"):
        return evaluate("drata_role", {**roles(inventory), **one("attached", attached)}, self.PARAMS)

    def test_drata_role_pass(self):
        found = self.run_with(fx("iam-list-attached-role-policies-security-audit"))
        self.assertEqual(real(found), [])
        self.assertEqual(not_applicable(found), [APP, VANTA])  # only the Drata role is evaluated

    def test_drata_role_fail_reports_offenders(self):
        (offender,) = real(self.run_with(fx("iam-list-attached-role-policies-none")))
        self.assertEqual((offender["resource_id"], offender["region"]), (DRATA, REGION))
        self.assertEqual(offender["detail"]["missing_policy"], "SecurityAudit")
        self.assertEqual(offender["detail"]["attached_policies"], [])

    def test_a_customer_managed_policy_named_security_audit_is_not_the_aws_one(self):
        (offender,) = real(self.run_with(fx("iam-list-attached-role-policies-lookalike")))
        self.assertEqual(offender["detail"]["attached_policies"], ["SecurityAudit"])

    def test_without_the_drata_role_every_role_is_not_applicable(self):
        found = self.run_with(fx("iam-list-attached-role-policies-none"), inventory="inventory-without-roles")
        self.assertEqual((real(found), not_applicable(found)), ([], [APP]))

    def test_a_role_that_vanished_meanwhile_is_not_applicable(self):
        found = self.run_with({"__error__": "NoSuchEntity"})
        self.assertEqual((real(found), not_applicable(found)), ([], [APP, DRATA, VANTA]))


class DrataBackupPermsTests(unittest.TestCase):
    PARAMS = {"role_name": DRATA, "actions": ["backup:ListRecoveryPointsByResource", "backup:ListBackupJobs"]}

    def run_with(self, details, inventory="inventory-with-drata-and-vanta"):
        data = fx(f"iam-get-account-authorization-details-backup-{details}") if isinstance(details, str) else details
        return evaluate("drata_backup_perms", {**roles(inventory), **one("details", data)}, self.PARAMS)

    def test_drata_backup_perms_pass_with_an_inline_policy(self):
        found = self.run_with("inline")
        self.assertEqual((real(found), not_applicable(found)), ([], [APP, VANTA]))

    def test_drata_backup_perms_pass_with_wildcards_and_with_a_customer_managed_policy(self):
        for details in ("wildcard", "managed"):
            self.assertEqual(real(self.run_with(details)), [], details)

    def test_drata_backup_perms_fail_reports_offenders(self):
        (offender,) = real(self.run_with("none"))
        self.assertEqual((offender["resource_id"], offender["region"]), (DRATA, REGION))
        self.assertEqual(offender["detail"]["missing_actions"], ["backup:ListRecoveryPointsByResource", "backup:ListBackupJobs"])

    def test_one_missing_action_is_reported_alone(self):
        (offender,) = real(self.run_with("partial"))
        self.assertEqual(offender["detail"]["missing_actions"], ["backup:ListRecoveryPointsByResource"])

    def test_a_deny_or_a_resource_restriction_does_not_count_as_granted(self):
        (denied,) = real(self.run_with("denied"))
        self.assertEqual(denied["detail"]["missing_actions"], ["backup:ListBackupJobs"])
        (scoped,) = real(self.run_with("scoped"))
        self.assertEqual(scoped["detail"]["missing_actions"], ["backup:ListRecoveryPointsByResource", "backup:ListBackupJobs"])

    def test_aws_managed_policies_are_not_read_and_are_named_in_the_detail(self):
        data = fx("iam-get-account-authorization-details-backup-none")
        data["RoleDetailList"][0]["AttachedManagedPolicies"].append({"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})
        (offender,) = real(self.run_with(data))
        self.assertEqual(offender["detail"]["aws_managed_not_evaluated"], ["ReadOnlyAccess"])

    def test_without_the_drata_role_the_check_is_not_applicable(self):
        found = self.run_with("none", inventory="inventory-without-roles")
        self.assertEqual((real(found), not_applicable(found)), ([], [APP]))

    def test_a_role_missing_from_the_details_is_not_applicable(self):
        data = fx("iam-get-account-authorization-details-backup-none")
        data["RoleDetailList"] = [r for r in data["RoleDetailList"] if r["RoleName"] != DRATA]
        self.assertEqual(real(self.run_with(data)), [])


class VantaRoleTests(unittest.TestCase):
    PARAMS = {"role_name": VANTA, "additional_policy": "VantaAdditionalPermissions"}

    def run_with(self, attached, inline="none", inventory="inventory-with-drata-and-vanta"):
        inline_data = fx(f"iam-list-role-policies-{inline}") if isinstance(inline, str) else inline
        return evaluate("vanta_role", {**roles(inventory), **one("attached", attached), **one("inline", inline_data)}, self.PARAMS)

    def test_vanta_role_pass(self):
        found = self.run_with(fx("iam-list-attached-role-policies-security-audit-and-vanta"))
        self.assertEqual((real(found), not_applicable(found)), ([], [APP, DRATA]))

    def test_vanta_role_fail_reports_offenders(self):
        (offender,) = real(self.run_with(fx("iam-list-attached-role-policies-none")))
        self.assertEqual((offender["resource_id"], offender["region"]), (VANTA, REGION))
        self.assertEqual(offender["detail"]["missing_policies"], ["SecurityAudit", "VantaAdditionalPermissions"])
        self.assertEqual(offender["detail"]["additional_permissions"], "absent")

    def test_an_inline_additional_permissions_policy_is_not_detected_by_vanta(self):
        (offender,) = real(self.run_with(fx("iam-list-attached-role-policies-security-audit"), inline="inline-vanta"))
        self.assertEqual(offender["detail"]["missing_policies"], ["VantaAdditionalPermissions"])
        self.assertEqual(offender["detail"]["additional_permissions"], "inline")

    def test_security_audit_must_be_the_aws_managed_policy(self):
        data = fx("iam-list-attached-role-policies-security-audit-and-vanta")
        data["AttachedPolicies"][0] = {"PolicyName": "SecurityAudit", "PolicyArn": "arn:aws:iam::111122223333:policy/SecurityAudit"}
        (offender,) = real(self.run_with(data))
        self.assertEqual(offender["detail"]["missing_policies"], ["SecurityAudit"])

    def test_the_additional_permissions_policy_must_be_customer_managed(self):
        data = fx("iam-list-attached-role-policies-security-audit-and-vanta")
        data["AttachedPolicies"][1]["PolicyArn"] = "arn:aws:iam::aws:policy/VantaAdditionalPermissions"
        (offender,) = real(self.run_with(data))
        self.assertEqual(offender["detail"]["missing_policies"], ["VantaAdditionalPermissions"])

    def test_a_policy_path_is_accepted(self):
        data = fx("iam-list-attached-role-policies-security-audit-and-vanta")
        data["AttachedPolicies"][1]["PolicyArn"] = "arn:aws:iam::111122223333:policy/vanta/VantaAdditionalPermissions"
        self.assertEqual(real(self.run_with(data)), [])

    def test_without_the_vanta_role_every_role_is_not_applicable(self):
        found = self.run_with(fx("iam-list-attached-role-policies-none"), inventory="inventory-without-roles")
        self.assertEqual((real(found), not_applicable(found)), ([], [APP]))


class KmsAuditorAccessTests(unittest.TestCase):
    ARN = f"arn:aws:kms:{REGION}:111122223333:key/{KEY}"

    def params(self):
        return params_of("INT-004")

    def run_with(self, policy, describe="customer", inventory="inventory-with-drata-and-vanta", params=None):
        described = fx(f"kms-describe-key-{describe}") if isinstance(describe, str) else describe
        answered = fx(f"kms-get-key-policy-{policy}") if isinstance(policy, str) else policy
        items = [{"type": "kms_key", "id": KEY, "arn": self.ARN, "name": KEY, "region": REGION, "tags": {}}]
        responses = merge(for_each("describe", [(KEY, described)]), for_each("policy", [(KEY, answered)]))
        responses["__inventory__"] = items + fx(inventory)
        return evaluate("kms_auditor_access", responses, params or self.params())

    def test_kms_auditor_access_pass_with_root_delegation(self):
        self.assertEqual(self.run_with("root-delegation"), [])

    def test_kms_auditor_access_pass_with_targeted_statements(self):
        self.assertEqual(self.run_with("targeted"), [])

    def test_kms_auditor_access_fail_reports_offenders(self):
        (offender,) = self.run_with("closed")
        self.assertEqual((offender["resource_id"], offender["region"]), (KEY, REGION))
        missing = offender["detail"]["missing_actions"]
        self.assertEqual(missing[DRATA], ["kms:DescribeKey", "kms:GetKeyRotationStatus"])
        self.assertEqual(missing[VANTA], ["kms:DescribeKey", "kms:GetPublicKey", "kms:ListAliases", "kms:ListGrants", "kms:ListKeyPolicies",
                                          "kms:ListResourceTags", "kms:ListRetirableGrants"])
        self.assertEqual(offender["detail"]["arn"], self.ARN)

    def test_partial_statements_report_only_what_is_missing(self):
        (offender,) = self.run_with("partial")
        # Vanta's statement uses kms:Describe* and kms:List* wildcards, which cover all of its actions
        self.assertEqual(offender["detail"]["missing_actions"], {DRATA: ["kms:GetKeyRotationStatus"]})

    def test_a_conditional_root_delegation_is_not_modelled_and_does_not_count(self):
        self.assertEqual(len(self.run_with("conditional-root")), 1)

    def test_a_deny_for_the_auditor_wins(self):
        (offender,) = self.run_with("denied")
        self.assertEqual(offender["detail"]["missing_actions"], {VANTA: ["kms:ListGrants"]})

    def deny_not_principal(self, *listed):
        statements = [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"}, "Action": "kms:*", "Resource": "*"},
                      {"Effect": "Deny", "NotPrincipal": {"AWS": list(listed)}, "Action": "kms:*", "Resource": "*"}]
        return {"PolicyName": "default", "Policy": json.dumps({"Version": "2012-10-17", "Statement": statements})}

    def test_a_deny_with_not_principal_denies_every_auditor_that_is_not_listed(self):
        admin = "arn:aws:iam::111122223333:role/acme-notes-admin"
        (offender,) = self.run_with(self.deny_not_principal(admin))
        self.assertEqual(list(offender["detail"]["missing_actions"]), [DRATA, VANTA])

    def test_a_deny_with_not_principal_spares_the_listed_role_and_its_account_root(self):
        drata, vanta = (f"arn:aws:iam::111122223333:role/{n}" for n in (DRATA, VANTA))
        self.assertEqual(self.run_with(self.deny_not_principal(drata, vanta)), [])
        (offender,) = self.run_with(self.deny_not_principal(vanta))
        self.assertEqual(list(offender["detail"]["missing_actions"]), [DRATA])
        self.assertEqual(self.run_with(self.deny_not_principal("arn:aws:iam::111122223333:root")), [])

    def test_only_the_roles_that_exist_are_required(self):
        inventory = [i for i in fx("inventory-with-drata-and-vanta") if i["id"] != VANTA]
        responses = merge(for_each("describe", [(KEY, fx("kms-describe-key-customer"))]), for_each("policy", [(KEY, fx("kms-get-key-policy-closed"))]))
        responses["__inventory__"] = inventory + [{"type": "kms_key", "id": KEY, "arn": self.ARN, "name": KEY, "region": REGION, "tags": {}}]
        (offender,) = evaluate("kms_auditor_access", responses, self.params())
        self.assertEqual(list(offender["detail"]["missing_actions"]), [DRATA])

    def test_without_auditor_roles_every_key_is_not_applicable(self):
        self.assertEqual(flags(self.run_with("closed", inventory="inventory-without-roles")), [(KEY, "not_applicable")])

    def test_keys_managed_by_aws_or_pending_deletion_are_not_applicable(self):
        for describe in ("aws-managed", "pending-deletion"):
            self.assertEqual(flags(self.run_with("closed", describe=describe)), [(KEY, "not_applicable")], describe)

    def test_a_key_that_blocks_the_audit_identity_is_unverified_for_that_key_only(self):
        self.assertEqual(flags(self.run_with("closed", describe={"__error__": "ACCESS_DENIED"})), [(KEY, "unverified")])
        (found,) = self.run_with({"__error__": "ACCESS_DENIED"})
        self.assertEqual((found["unverified"], found["detail"]["error_code"], found["detail"]["call"]), (True, "ACCESS_DENIED", "get-key-policy"))
        self.assertEqual(flags(self.run_with({"__error__": "NotFoundException"})), [(KEY, "not_applicable")])
        self.assertEqual(flags(self.run_with("closed", describe={"__error__": "NotFoundException"})), [(KEY, "not_applicable")])
        self.assertEqual(flags(self.run_with({"__error__": "THROTTLED"})), [(KEY, "unverified")])


class IntegrationCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks = json.loads(INTEGRATION_JSON.read_text(encoding="utf-8"))["checks"]

    def test_integration_catalog_valid(self):
        data = json.loads(INTEGRATION_JSON.read_text(encoding="utf-8"))
        for check in data["checks"]:
            check.setdefault("domain", data["domain"])
        tsc_ids, iso_ids = catalog.load_frameworks(REFS / "frameworks")
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        self.assertEqual(catalog.validate(data["checks"], tsc_ids, iso_ids, drata), [])
        self.assertEqual([c["id"] for c in data["checks"]], [f"INT-{n:03d}" for n in range(1, 5)])
        self.assertEqual(data["domain"], "integration")

    def test_every_python_evaluator_is_registered(self):
        for check in self.checks:
            kind, _, name = check["verify"]["evaluator"].partition(":")
            self.assertEqual(kind, "python", check["id"])
            self.assertIn(name, evaluators.EVALUATORS, check["id"])

    def test_evaluators_severities_and_remediation_follow_the_brief(self):
        expected = {"INT-001": ("python:drata_role", "high", "cli"), "INT-002": ("python:drata_backup_perms", "medium", "cli_with_decision"),
                    "INT-003": ("python:vanta_role", "high", "cli_with_decision"), "INT-004": ("python:kms_auditor_access", "medium", "cli_with_decision")}
        self.assertEqual({c["id"]: (c["verify"]["evaluator"], c["severity"], c["remediation"]["kind"]) for c in self.checks}, expected)

    def test_scopes_and_resource_types(self):
        expected = {"INT-001": ["iam_role"], "INT-002": ["iam_role"], "INT-003": ["iam_role"], "INT-004": ["kms_key"]}
        self.assertEqual({c["id"]: c["resource_types"] for c in self.checks}, expected)
        self.assertEqual({c["scope"] for c in self.checks}, {"resource"})
        self.assertFalse([c["id"] for c in self.checks if c["all_regions"]])

    def test_int_004_depends_on_the_key_and_role_inventories(self):
        self.assertEqual(params_of("INT-004")["inventory_types"], ["kms_key", "iam_role"])

    def test_role_calls_name_the_role_and_tolerate_its_absence(self):
        expected = {"INT-001": [("attached", "list-attached-role-policies", DRATA)], "INT-003": [("attached", "list-attached-role-policies", VANTA),
                                                                                              ("inline", "list-role-policies", VANTA)]}
        for check_id, calls in expected.items():
            found = [(c["name"], c["operation"], c["args"][c["args"].index("--role-name") + 1]) for c in catalog_check(check_id)["verify"]["calls"]]
            self.assertEqual(found, calls, check_id)
            for call in catalog_check(check_id)["verify"]["calls"]:
                self.assertEqual((call["region"], call["ok_errors"]), ("global", ["NoSuchEntity"]), check_id)
        (call,) = catalog_check("INT-002")["verify"]["calls"]
        self.assertEqual((call["operation"], call["args"]), ("get-account-authorization-details", ["--filter", "Role", "LocalManagedPolicy"]))
        self.assertEqual(params_of("INT-002")["actions"], ["backup:ListRecoveryPointsByResource", "backup:ListBackupJobs"])
        for check_id, role in (("INT-001", DRATA), ("INT-002", DRATA), ("INT-003", VANTA)):
            self.assertEqual(params_of(check_id)["role_name"], role, check_id)

    def test_int_004_reads_each_key_and_declares_item_errors(self):
        calls = {c["name"]: c for c in catalog_check("INT-004")["verify"]["calls"]}
        self.assertEqual((calls["describe"]["operation"], calls["policy"]["operation"]), ("describe-key", "get-key-policy"))
        self.assertEqual(calls["policy"]["args"], ["--policy-name", "default"])
        for call in calls.values():
            self.assertEqual(call["for_each"], {"from": "__inventory__", "path": "id", "arg": "--key-id"})
            self.assertEqual((call["ok_errors"], call["item_errors"]), (["NotFoundException"], "evaluator"))
        auditors = params_of("INT-004")["auditors"]
        self.assertEqual(auditors[DRATA], ["kms:DescribeKey", "kms:GetKeyRotationStatus"])
        self.assertEqual(auditors[VANTA], ["kms:DescribeKey", "kms:GetPublicKey", "kms:ListAliases", "kms:ListGrants", "kms:ListKeyPolicies",
                                           "kms:ListResourceTags", "kms:ListRetirableGrants"])

    def test_absent_roles_are_not_applicable_and_the_texts_say_so(self):
        for check in self.checks:
            self.assertRegex(check["verify"]["pass_when_text"], r"N/A", check["id"])

    def test_inline_vanta_policy_is_called_out(self):
        text = catalog_check("INT-003")["verify"]["pass_when_text"]
        self.assertRegex(text, r"(?i)inline")
        self.assertRegex(text, r"(?i)administrada por el cliente|customer-managed")

    def test_drata_mappings_resolve_from_the_dcf_file(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        expected = {"INT-001": [123], "INT-002": [132, 133], "INT-004": [223]}
        for check_id, tests in expected.items():
            resolved = catalog.resolve_mappings(catalog_check(check_id), drata)
            self.assertEqual([m["test"] for m in resolved["drata"]], tests, check_id)
            self.assertTrue(resolved["tsc"] and all(t["sourced"] == catalog.DCF_SOURCE for t in resolved["tsc"]), check_id)

    def test_int_003_has_no_drata_test_so_its_mappings_are_inferred(self):
        check = catalog_check("INT-003")
        self.assertEqual(check["mappings"]["drata"], [])
        resolved = catalog.resolve_mappings(check, catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json"))
        self.assertTrue(resolved["tsc"] and resolved["iso27001_2022"])
        self.assertTrue(all(m["sourced"] is False for m in resolved["tsc"] + resolved["iso27001_2022"]))

    def test_steps_are_not_numbered_by_hand(self):
        for check in self.checks:
            for step in check["remediation"]["steps"]:
                self.assertNotRegex(step, r"^\d+\.\s", check["id"])

    def test_remediation_commands_follow_cloudshell_rules(self):
        for check in self.checks:
            rem = check["remediation"]
            self.assertTrue(rem["commands"], check["id"])
            for command in rem["commands"]:
                self.assertTrue(command.startswith('REGION="{region}"\nACCOUNT_ID="{account_id}"\n'), check["id"])
                self.assertNotIn("set -e", command, check["id"])
                self.assertNotIn("<<", command, check["id"])
            self.assertTrue(rem["verify_after"].startswith("aws "), check["id"])

    @unittest.skipUnless(shutil.which("bash"), "bash not installed")
    def test_remediation_commands_and_verification_parse_as_bash(self):
        for check in self.checks:
            rem = check["remediation"]
            for text in [*rem["commands"], rem["verify_after"]]:
                script = text.replace("{region}", "us-east-1").replace("{account_id}", "111122223333").replace("{resource_id}", KEY)
                done = subprocess.run(["bash", "-n"], input=script, capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, f"{check['id']}: {done.stderr}\n{script}")

    def test_commands_attach_the_documented_policies(self):
        self.assertIn("arn:aws:iam::aws:policy/SecurityAudit", "\n".join(catalog_check("INT-001")["remediation"]["commands"]))
        text = "\n".join(catalog_check("INT-002")["remediation"]["commands"])
        self.assertIn("put-role-policy", text)
        self.assertIn("backup:ListRecoveryPointsByResource", text)
        self.assertIn("backup:ListBackupJobs", text)
        text = "\n".join(catalog_check("INT-003")["remediation"]["commands"])
        self.assertIn("create-policy", text)
        self.assertIn("policy/VantaAdditionalPermissions", text)

    def test_deleting_the_inline_policy_never_runs_before_the_attach_succeeded(self):
        commands = catalog_check("INT-003")["remediation"]["commands"]
        for command in commands:
            if "delete-role-policy" in command:
                self.assertIn("attach-role-policy", command)
                self.assertLess(command.index("attach-role-policy"), command.index("delete-role-policy"))
                self.assertIn("&&", command[command.index("attach-role-policy"):command.index("delete-role-policy")])


class IntegrationCollectTests(unittest.TestCase):
    """The integration catalog through collect.main with a fake AWS: wiring of calls, ok_errors and item_errors."""

    TYPES = ("iam_role", "kms_key")

    def run_collect(self, role_names, rules):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "checks").mkdir()
        shutil.copy(INTEGRATION_JSON, tmp / "checks" / "integration.json")
        specs = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))
        (tmp / "inventory.json").write_text(json.dumps({t: specs[t] for t in self.TYPES}), encoding="utf-8")
        scope = {"platform": "Acme Notes", "mode": "full", "target": None, "regions": [REGION], "profile": None, "resources": [], "domains": None}
        (tmp / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
        listing = {"Roles": [{"RoleName": n, "Arn": f"arn:aws:iam::111122223333:role/{n}"} for n in role_names]}
        core = lambda name: ok(load_fixture(f"aws/core/{name}.json"))
        runner = RuleRunner([
            ("sts", "get-caller-identity", None, "", core("sts-get-caller-identity")),
            ("ec2", "describe-regions", None, "", core("ec2-describe-regions")),
            ("iam", "list-attached-user-policies", None, "", ok({"AttachedPolicies": []})),
            ("iam", "list-roles", None, "", ok(listing)),
            ("kms", "list-keys", REGION, "", ok({"Keys": [{"KeyId": KEY, "KeyArn": f"arn:aws:kms:{REGION}:111122223333:key/{KEY}"}]})),
            *rules,
        ])
        with contextlib.redirect_stdout(io.StringIO()):
            code = collect.main(["--scope", str(tmp / "scope.json"), "--out", str(tmp / "out"), "--checks-dir", str(tmp / "checks"),
                                 "--inventory", str(tmp / "inventory.json"), "--quiet"], runner=runner, sleep=lambda s: None, which=lambda name: None)
        result = json.loads((tmp / "out" / "checks-result.json").read_text(encoding="utf-8"))
        return code, result, runner

    def rows(self, result, check_id):
        return [(r["status"], r["resource_id"], r["vacuous"]) for r in result["results"] if r["check_id"] == check_id]

    def with_roles(self):
        return [
            ("iam", "list-attached-role-policies", None, DRATA, ok(fx("iam-list-attached-role-policies-security-audit"))),
            ("iam", "list-attached-role-policies", None, VANTA, ok(fx("iam-list-attached-role-policies-security-audit-and-vanta"))),
            ("iam", "list-role-policies", None, VANTA, ok(fx("iam-list-role-policies-none"))),
            ("iam", "get-account-authorization-details", None, "", ok(fx("iam-get-account-authorization-details-backup-inline"))),
            ("kms", "describe-key", None, KEY, ok(fx("kms-describe-key-customer"))),
            ("kms", "get-key-policy", None, KEY, ok(fx("kms-get-key-policy-root-delegation"))),
        ]

    def test_a_compliant_account_passes_for_the_auditor_roles_and_the_key(self):
        code, result, _ = self.run_collect([APP, DRATA, VANTA], self.with_roles())
        self.assertEqual(code, 0)
        self.assertEqual(self.rows(result, "INT-001"), [("PASS", DRATA, False)])
        self.assertEqual(self.rows(result, "INT-002"), [("PASS", DRATA, False)])
        self.assertEqual(self.rows(result, "INT-003"), [("PASS", VANTA, False)])
        self.assertEqual(self.rows(result, "INT-004"), [("PASS", KEY, False)])

    def test_an_account_without_the_integration_roles_is_vacuous_not_pass(self):
        rules = [("iam", "list-attached-role-policies", None, DRATA, NO_SUCH_ROLE), ("iam", "list-attached-role-policies", None, VANTA, NO_SUCH_ROLE),
                 ("iam", "list-role-policies", None, VANTA, NO_SUCH_ROLE),
                 ("iam", "get-account-authorization-details", None, "", ok(fx("iam-get-account-authorization-details-backup-none"))),
                 ("kms", "describe-key", None, KEY, ok(fx("kms-describe-key-customer"))),
                 ("kms", "get-key-policy", None, KEY, ok(fx("kms-get-key-policy-closed")))]
        code, result, _ = self.run_collect([APP], rules)
        self.assertEqual(code, 0)
        for check_id in ("INT-001", "INT-002", "INT-003", "INT-004"):
            self.assertEqual(self.rows(result, check_id), [("N/A", "account", True)], check_id)

    def test_offending_roles_and_keys_fail(self):
        rules = [
            ("iam", "list-attached-role-policies", None, DRATA, ok(fx("iam-list-attached-role-policies-none"))),
            ("iam", "list-attached-role-policies", None, VANTA, ok(fx("iam-list-attached-role-policies-security-audit"))),
            ("iam", "list-role-policies", None, VANTA, ok(fx("iam-list-role-policies-inline-vanta"))),
            ("iam", "get-account-authorization-details", None, "", ok(fx("iam-get-account-authorization-details-backup-none"))),
            ("kms", "describe-key", None, KEY, ok(fx("kms-describe-key-customer"))),
            ("kms", "get-key-policy", None, KEY, ok(fx("kms-get-key-policy-closed"))),
        ]
        _, result, _ = self.run_collect([APP, DRATA, VANTA], rules)
        for check_id, resource in (("INT-001", DRATA), ("INT-002", DRATA), ("INT-003", VANTA), ("INT-004", KEY)):
            self.assertEqual(self.rows(result, check_id), [("FAIL", resource, False)], check_id)

    def test_a_key_policy_that_blocks_the_audit_identity_names_the_missing_permission(self):
        denied = err("An error occurred (AccessDeniedException) when calling the GetKeyPolicy operation: User is not authorized to perform: kms:GetKeyPolicy")
        rules = [r for r in self.with_roles() if r[1] != "get-key-policy"] + [("kms", "get-key-policy", None, KEY, denied)]
        _, result, _ = self.run_collect([APP, DRATA, VANTA], rules)
        (row,) = [r for r in result["results"] if r["check_id"] == "INT-004"]
        self.assertEqual((row["status"], row["resource_id"], row["detail"]["error_code"]), ("NOT_VERIFIED", KEY, "ACCESS_DENIED"))
        self.assertEqual(row["missing"], catalog_check("INT-004")["verify"]["needs"])


if __name__ == "__main__":
    unittest.main()
