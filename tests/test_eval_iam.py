import base64
import contextlib
import csv
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import helpers
from helpers import SKILL_DIR, load_fixture

import catalog
import collect
import evaluators

IAM_JSON = SKILL_DIR / "references" / "checks" / "iam.json"
REFS = SKILL_DIR / "references"
REGION = "us-east-1"
NOW = "2026-11-12T12:00:00+00:00"

CREDENTIAL_COLUMNS = (
    "user", "arn", "user_creation_time", "password_enabled", "password_last_used", "password_last_changed",
    "password_next_rotation", "mfa_active",
    "access_key_1_active", "access_key_1_last_rotated", "access_key_1_last_used_date",
    "access_key_1_last_used_region", "access_key_1_last_used_service",
    "access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date",
    "access_key_2_last_used_region", "access_key_2_last_used_service",
    "cert_1_active", "cert_1_last_rotated", "cert_2_active", "cert_2_last_rotated",
)


def cred_row(user, **fields):
    """One credential-report row; everything is 'off' / 'N/A' unless given."""
    row = {c: "N/A" for c in CREDENTIAL_COLUMNS}
    row.update(user=user, arn=f"arn:aws:iam::111122223333:user/{user}", user_creation_time="2026-01-05T10:00:00+00:00",
              password_enabled="false", mfa_active="false", access_key_1_active="false", access_key_2_active="false",
              cert_1_active="false", cert_2_active="false")
    row.update(fields)
    return row


ROOT_ROW = cred_row("<root_account>", arn="arn:aws:iam::111122223333:root", password_enabled="not_supported",
                    password_last_used="2026-10-30T10:00:00+00:00", mfa_active="true")


def credential_report(*rows):
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=CREDENTIAL_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows([ROOT_ROW, *rows])
    content = base64.b64encode(out.getvalue().encode("utf-8")).decode("ascii")
    return {"Content": content, "ReportFormat": "text/csv", "GeneratedTime": NOW}


def report_responses(*rows):
    return {"generate": [(REGION, {"State": "COMPLETE"})], "report": [(REGION, credential_report(*rows))]}


def one(call, data):
    return {call: [(REGION, data)]}


def evaluate(name, responses, params=None):
    return evaluators.EVALUATORS[name](responses, params or {})


def ids(offenders):
    return [o["resource_id"] for o in offenders]


class RootEvaluatorTests(unittest.TestCase):
    def responses(self, summary, devices):
        return {**one("summary", load_fixture(f"aws/iam/{summary}.json")),
                **one("virtual_mfa", load_fixture(f"aws/iam/{devices}.json"))}

    def test_root_hardware_mfa_pass(self):
        responses = self.responses("iam-get-account-summary-mfa-on", "iam-list-virtual-mfa-devices-hardware")
        self.assertEqual(evaluate("root_hardware_mfa", responses), [])

    def test_root_hardware_mfa_fail_reports_offenders(self):
        responses = self.responses("iam-get-account-summary-mfa-on", "iam-list-virtual-mfa-devices-virtual-root")
        (offender,) = evaluate("root_hardware_mfa", responses)
        self.assertEqual((offender["resource_id"], offender["region"]), ("root", REGION))
        self.assertEqual(offender["detail"]["reason"], "MFA virtual")

    def test_root_hardware_mfa_fail_without_any_mfa(self):
        responses = self.responses("iam-get-account-summary-mfa-off", "iam-list-virtual-mfa-devices-hardware")
        (offender,) = evaluate("root_hardware_mfa", responses)
        self.assertEqual((offender["resource_id"], offender["detail"]["reason"]), ("root", "sin MFA"))

    def test_root_usage_pass(self):
        responses = one("events", load_fixture("aws/iam/cloudtrail-lookup-events-root-clean.json"))
        self.assertEqual(evaluate("root_usage", responses, {"days": 7, "max": 1, "now": NOW}), [])

    def test_root_usage_fail_reports_offenders(self):
        responses = one("events", load_fixture("aws/iam/cloudtrail-lookup-events-root-logins.json"))
        (offender,) = evaluate("root_usage", responses, {"days": 7, "max": 1, "now": NOW})
        self.assertEqual((offender["resource_id"], offender["region"]), ("root", REGION))
        self.assertEqual(offender["detail"], {"console_logins": 2, "days": 7})


class CredentialReportEvaluatorTests(unittest.TestCase):
    ALICE = dict(password_enabled="true", password_last_used="2026-11-11T08:00:00+00:00", mfa_active="true",
                 access_key_1_active="true", access_key_1_last_rotated="2026-11-02T10:00:00+00:00",
                 access_key_1_last_used_date="2026-11-11T08:00:00+00:00")
    BOB_NO_MFA = dict(password_enabled="true", password_last_used="2026-11-01T08:00:00+00:00", mfa_active="false")
    CAROL_STALE = dict(password_enabled="true", password_last_used="2026-08-01T08:00:00+00:00", mfa_active="true",
                       access_key_1_active="true", access_key_1_last_rotated="2026-06-01T10:00:00+00:00",
                       access_key_1_last_used_date="2026-09-01T08:00:00+00:00")
    DAVE_NEW = dict(password_enabled="true", password_last_used="no_information",
                    password_last_changed="2026-11-11T08:00:00+00:00", mfa_active="true")
    CI_TWO_KEYS = dict(access_key_1_active="true", access_key_1_last_rotated="2026-11-01T10:00:00+00:00",
                       access_key_1_last_used_date="2026-11-11T08:00:00+00:00",
                       access_key_2_active="true", access_key_2_last_rotated="2026-11-05T10:00:00+00:00")
    SVC_ONE_KEY = dict(access_key_1_active="true", access_key_1_last_rotated="2026-11-01T10:00:00+00:00",
                       access_key_1_last_used_date="2026-11-11T08:00:00+00:00")

    def clean(self):
        return report_responses(cred_row("alice.dev", **self.ALICE), cred_row("svc-reports", **self.SVC_ONE_KEY))

    def offending(self):
        return report_responses(
            cred_row("alice.dev", **self.ALICE), cred_row("bob.qa", **self.BOB_NO_MFA),
            cred_row("carol.old", **self.CAROL_STALE), cred_row("dave.new", **self.DAVE_NEW),
            cred_row("ci-deployer", **self.CI_TWO_KEYS))

    def test_cred_report_console_mfa_pass(self):
        self.assertEqual(evaluate("cred_report_console_mfa", self.clean()), [])

    def test_cred_report_console_mfa_fail_reports_offenders(self):
        offenders = evaluate("cred_report_console_mfa", self.offending())
        self.assertEqual(ids(offenders), ["bob.qa"])
        self.assertEqual(offenders[0]["region"], REGION)

    def test_cred_report_key_age_pass(self):
        self.assertEqual(evaluate("cred_report_key_age", self.clean(), {"fail_at_days": 90, "now": NOW}), [])

    def test_cred_report_key_age_fail_reports_offenders(self):
        offenders = evaluate("cred_report_key_age", self.offending(), {"fail_at_days": 90, "now": NOW})
        self.assertEqual(ids(offenders), ["carol.old"])
        self.assertEqual(offenders[0]["detail"]["keys"], [{"key": "access_key_1", "age_days": 164}])

    def test_cred_report_key_age_ignores_inactive_keys(self):
        row = cred_row("old.inactive", access_key_1_active="false", access_key_1_last_rotated="2025-01-01T10:00:00+00:00")
        self.assertEqual(evaluate("cred_report_key_age", report_responses(row), {"fail_at_days": 90, "now": NOW}), [])

    def test_cred_report_unused_pass(self):
        self.assertEqual(evaluate("cred_report_unused", self.clean(), {"max_days": 45, "now": NOW}), [])

    def test_cred_report_unused_fail_reports_offenders(self):
        offenders = evaluate("cred_report_unused", self.offending(), {"max_days": 45, "now": NOW})
        self.assertEqual(ids(offenders), ["carol.old"])
        self.assertEqual(offenders[0]["detail"]["credentials"],
                         [{"credential": "password", "unused_days": 103}, {"credential": "access_key_1", "unused_days": 72}])

    def test_cred_report_unused_counts_never_used_from_creation(self):
        row = cred_row("never.used", access_key_1_active="true", access_key_1_last_rotated="2026-06-01T10:00:00+00:00")
        offenders = evaluate("cred_report_unused", report_responses(row), {"max_days": 45, "now": NOW})
        self.assertEqual(ids(offenders), ["never.used"])

    def test_cred_report_multi_keys_pass(self):
        self.assertEqual(evaluate("cred_report_multi_keys", self.clean()), [])

    def test_cred_report_multi_keys_fail_reports_offenders(self):
        offenders = evaluate("cred_report_multi_keys", self.offending())
        self.assertEqual(ids(offenders), ["ci-deployer"])
        self.assertEqual(offenders[0]["detail"], {"active_keys": 2})

    def test_iam_human_users_pass(self):
        responses = report_responses(cred_row("svc-reports", **self.SVC_ONE_KEY))
        self.assertEqual(evaluate("iam_human_users", responses), [])

    def test_iam_human_users_fail_reports_offenders(self):
        self.assertEqual(ids(evaluate("iam_human_users", self.offending())), ["alice.dev", "bob.qa", "carol.old", "dave.new"])

    def test_root_row_is_never_reported(self):
        responses = report_responses()
        for name, params in (("cred_report_console_mfa", {}), ("cred_report_key_age", {"fail_at_days": 1, "now": NOW}),
                             ("cred_report_unused", {"max_days": 1, "now": NOW}), ("cred_report_multi_keys", {}),
                             ("iam_human_users", {})):
            self.assertEqual(evaluate(name, responses, params), [], name)


class PolicyEvaluatorTests(unittest.TestCase):
    def test_password_min_length_pass(self):
        responses = one("policy", load_fixture("aws/iam/iam-get-account-password-policy-strong.json"))
        self.assertEqual(evaluate("password_min_length", responses, {"min_length": 14}), [])

    def test_password_min_length_fail_reports_offenders(self):
        responses = one("policy", load_fixture("aws/iam/iam-get-account-password-policy-weak.json"))
        (offender,) = evaluate("password_min_length", responses, {"min_length": 14})
        self.assertEqual((offender["resource_id"], offender["region"]), ("account", REGION))
        self.assertEqual(offender["detail"], {"minimum_password_length": 8, "required": 14})

    def test_password_min_length_fail_without_policy(self):
        (offender,) = evaluate("password_min_length", one("policy", {"__error__": "NoSuchEntity"}), {"min_length": 14})
        self.assertEqual((offender["resource_id"], offender["detail"]["reason"]), ("account", "sin política de contraseñas"))

    def test_password_reuse_prevention_pass(self):
        responses = one("policy", load_fixture("aws/iam/iam-get-account-password-policy-strong.json"))
        self.assertEqual(evaluate("password_reuse_prevention", responses, {"min_reuse": 24}), [])

    def test_password_reuse_prevention_fail_reports_offenders(self):
        responses = one("policy", load_fixture("aws/iam/iam-get-account-password-policy-weak.json"))
        (offender,) = evaluate("password_reuse_prevention", responses, {"min_reuse": 24})
        self.assertEqual((offender["resource_id"], offender["detail"]), ("account", {"password_reuse_prevention": 5, "required": 24}))

    def test_password_reuse_prevention_fail_without_policy_or_setting(self):
        (offender,) = evaluate("password_reuse_prevention", one("policy", {"__error__": "NoSuchEntity"}), {"min_reuse": 24})
        self.assertEqual(offender["detail"]["reason"], "sin política de contraseñas")
        responses = one("policy", {"PasswordPolicy": {"MinimumPasswordLength": 14}})
        (offender,) = evaluate("password_reuse_prevention", responses, {"min_reuse": 24})
        self.assertEqual(offender["detail"], {"password_reuse_prevention": 0, "required": 24})

    def test_user_direct_policies_pass(self):
        responses = one("details", load_fixture("aws/iam/iam-get-account-authorization-details-users-ok.json"))
        self.assertEqual(evaluate("user_direct_policies", responses), [])

    def test_user_direct_policies_fail_reports_offenders(self):
        responses = one("details", load_fixture("aws/iam/iam-get-account-authorization-details-users-offenders.json"))
        offenders = evaluate("user_direct_policies", responses)
        self.assertEqual(ids(offenders), ["bob.qa", "ci-deployer"])
        self.assertEqual(offenders[0]["detail"], {"attached_policies": ["ReadOnlyAccess"], "inline_policies": []})
        self.assertEqual(offenders[1]["detail"], {"attached_policies": [], "inline_policies": ["deploy-notes-app"]})

    def test_admin_policies_pass(self):
        responses = one("details", load_fixture("aws/iam/iam-get-account-authorization-details-policies-ok.json"))
        self.assertEqual(evaluate("admin_policies", responses), [])

    def test_admin_policies_fail_reports_offenders(self):
        responses = one("details", load_fixture("aws/iam/iam-get-account-authorization-details-policies-offenders.json"))
        (offender,) = evaluate("admin_policies", responses)
        self.assertEqual(offender["resource_id"], "arn:aws:iam::111122223333:policy/temp-full-admin")
        self.assertEqual(offender["detail"], {"policy_name": "temp-full-admin", "attachment_count": 1})

    def test_admin_policies_reads_url_encoded_documents_and_action_lists(self):
        document = '%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%5B%22*%22%5D%2C%22Resource%22%3A%5B%22*%22%5D%7D%5D%7D'
        policy = {"PolicyName": "encoded-admin", "Arn": "arn:aws:iam::111122223333:policy/encoded-admin",
                  "AttachmentCount": 1, "PolicyVersionList": [{"Document": document, "VersionId": "v1", "IsDefaultVersion": True}]}
        self.assertEqual(ids(evaluate("admin_policies", one("details", {"Policies": [policy]}))),
                         ["arn:aws:iam::111122223333:policy/encoded-admin"])

    def test_alternate_contact_present_pass(self):
        responses = one("contact", load_fixture("aws/iam/account-get-alternate-contact-security.json"))
        self.assertEqual(evaluate("alternate_contact_present", responses), [])

    def test_alternate_contact_present_fail_reports_offenders(self):
        (offender,) = evaluate("alternate_contact_present", one("contact", {"__error__": "ResourceNotFoundException"}))
        self.assertEqual((offender["resource_id"], offender["region"]), ("account", REGION))
        self.assertEqual(offender["detail"]["reason"], "sin contacto alternativo SECURITY")



class BoundaryTests(unittest.TestCase):
    """Exact thresholds: now is NOW (2026-11-12T12:00Z); each case shifts a timestamp by hours."""

    @staticmethod
    def ago(days=0, hours=0):
        return (datetime.fromisoformat(NOW) - timedelta(days=days, hours=hours)).isoformat()

    def key_age(self, days, hours):
        row = cred_row("u", access_key_1_active="true", access_key_1_last_rotated=self.ago(days, hours))
        return ids(evaluate("cred_report_key_age", report_responses(row), {"fail_at_days": 90, "now": NOW}))

    def unused(self, days, hours):
        row = cred_row("u", access_key_1_active="true", access_key_1_last_rotated=self.ago(400),
                       access_key_1_last_used_date=self.ago(days, hours))
        return ids(evaluate("cred_report_unused", report_responses(row), {"max_days": 45, "now": NOW}))

    def test_key_age_boundary(self):
        self.assertEqual(self.key_age(89, 23), [])
        self.assertEqual(self.key_age(90, 0), ["u"])
        self.assertEqual(self.key_age(91, 0), ["u"])

    def test_unused_boundary(self):
        self.assertEqual(self.unused(45, 0), [])
        self.assertEqual(self.unused(45, 1), ["u"])
        self.assertEqual(self.unused(46, 0), ["u"])

    def test_password_length_boundary(self):
        for length, expected in ((13, 1), (14, 0)):
            responses = one("policy", {"PasswordPolicy": {"MinimumPasswordLength": length, "PasswordReusePrevention": 24}})
            self.assertEqual(len(evaluate("password_min_length", responses, {"min_length": 14})), expected, length)

    def test_password_reuse_boundary(self):
        for reuse, expected in ((23, 1), (24, 0)):
            responses = one("policy", {"PasswordPolicy": {"MinimumPasswordLength": 14, "PasswordReusePrevention": reuse}})
            self.assertEqual(len(evaluate("password_reuse_prevention", responses, {"min_reuse": 24})), expected, reuse)

    def test_root_logins_boundary(self):
        def logins(*times):
            events = [{"EventName": "ConsoleLogin", "EventTime": t, "Username": "root"} for t in times]
            return evaluate("root_usage", one("events", {"Events": events}), {"days": 7, "max": 1, "now": NOW})

        self.assertEqual(logins(self.ago(1)), [])
        self.assertEqual(len(logins(self.ago(1), self.ago(2))), 1)

    def test_root_login_just_outside_window_is_ignored(self):
        events = [{"EventName": "ConsoleLogin", "EventTime": self.ago(1), "Username": "root"},
                  {"EventName": "ConsoleLogin", "EventTime": self.ago(7, 1), "Username": "root"}]
        self.assertEqual(evaluate("root_usage", one("events", {"Events": events}), {"days": 7, "max": 1, "now": NOW}), [])
        events[1]["EventTime"] = self.ago(6, 23)
        self.assertEqual(len(evaluate("root_usage", one("events", {"Events": events}), {"days": 7, "max": 1, "now": NOW})), 1)


class IamCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks = json.loads(IAM_JSON.read_text(encoding="utf-8"))["checks"]

    def test_iam_catalog_valid(self):
        data = json.loads(IAM_JSON.read_text(encoding="utf-8"))
        for check in data["checks"]:
            check.setdefault("domain", data["domain"])
        tsc_ids, iso_ids = catalog.load_frameworks(REFS / "frameworks")
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        self.assertEqual(catalog.validate(data["checks"], tsc_ids, iso_ids, drata), [])
        self.assertEqual([c["id"] for c in data["checks"]], [f"IAM-{n:03d}" for n in range(1, 18)])

    def test_every_python_evaluator_is_registered(self):
        for check in self.checks:
            kind, _, name = check["verify"]["evaluator"].partition(":")
            if kind == "python":
                self.assertIn(name, evaluators.EVALUATORS, check["id"])

    def test_steps_are_not_numbered_by_hand(self):
        for check in self.checks:
            for step in check["remediation"]["steps"]:
                self.assertNotRegex(step, r"^\d+\.\s", check["id"])

    def test_iam_011_detach_only_runs_after_attach_and_add(self):
        (command, _) = next(c for c in self.checks if c["id"] == "IAM-011")["remediation"]["commands"]
        lines = [l for l in command.splitlines() if l.startswith("aws ")]
        self.assertTrue(lines[0].startswith("aws iam create-group") and "&&" not in lines[0])
        self.assertIn("attach-group-policy", lines[1])
        self.assertRegex(lines[1], r"attach-group-policy .*&& aws iam add-user-to-group .*&& aws iam detach-user-policy")

    def test_destructive_lines_are_chained_or_alone(self):
        destructive = ("detach-", "delete-")
        for check in self.checks:
            for command in check["remediation"]["commands"]:
                aws_lines = [l for l in command.splitlines() if l.startswith("aws ")]
                if any(d in l for l in aws_lines for d in destructive):
                    self.assertEqual(len(aws_lines), 1 if "&&" not in command else len(aws_lines), check["id"])

    def test_remediation_commands_follow_cloudshell_rules(self):
        for check in self.checks:
            rem = check["remediation"]
            if rem["kind"] == "console_only":
                self.assertEqual(rem["commands"], [], check["id"])
                self.assertTrue(rem["steps"], check["id"])
            for command in rem["commands"]:
                self.assertTrue(command.startswith('REGION="{region}"\nACCOUNT_ID="{account_id}"\n'), check["id"])
                self.assertNotIn("set -e", command, check["id"])
            if rem["kind"] != "console_only":
                self.assertTrue(rem["verify_after"].startswith("aws "), check["id"])


class RuleRunner:
    """FakeRunner variant for calls whose response depends on the arguments, not only on service/operation.

    rules: [(service, operation, region | None, argv-substring, response)], first match wins.
    """

    def __init__(self, rules):
        self.rules, self.calls = rules, []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        region = argv[argv.index("--region") + 1] if "--region" in argv else None
        text = " ".join(argv)
        for service, operation, rule_region, token, response in self.rules:
            if (argv[1], argv[2]) == (service, operation) and rule_region in (None, region) and token in text:
                return subprocess.CompletedProcess(argv, response.get("returncode", 0), stdout=response.get("stdout", ""),
                                                   stderr=response.get("stderr", ""))
        raise AssertionError(f"unexpected call: {argv}")


def ok(data):
    return {"stdout": json.dumps(data)}


def err(stderr):
    return {"returncode": 255, "stderr": stderr}


class IamCollectTests(unittest.TestCase):
    """The whole IAM catalog through collect.main with a fake AWS: wiring of calls, args and ok_errors."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        (cls.tmp / "checks").mkdir()
        shutil.copy(IAM_JSON, cls.tmp / "checks" / "iam.json")
        inventory = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))
        (cls.tmp / "inventory.json").write_text(json.dumps({"iam_user": inventory["iam_user"]}), encoding="utf-8")
        scope = {"platform": "Acme Notes", "mode": "full", "target": None, "regions": ["us-east-1"], "profile": None,
                 "resources": [], "domains": None}
        (cls.tmp / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
        cls.runner = RuleRunner(cls.rules())
        out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            cls.code = collect.main(
                ["--scope", str(cls.tmp / "scope.json"), "--out", str(out), "--checks-dir", str(cls.tmp / "checks"),
                 "--inventory", str(cls.tmp / "inventory.json"), "--quiet"],
                runner=cls.runner, sleep=lambda s: None, which=lambda name: None)
        cls.result = json.loads((out / "checks-result.json").read_text(encoding="utf-8"))

    @staticmethod
    def rules():
        now = datetime.now(timezone.utc)
        stamp = lambda days: (now - timedelta(days=days)).isoformat(timespec="seconds")
        report = credential_report(
            cred_row("alice.dev", password_enabled="true", password_last_used=stamp(1), mfa_active="true",
                     access_key_1_active="true", access_key_1_last_rotated=stamp(10), access_key_1_last_used_date=stamp(1)),
            cred_row("bob.qa", password_enabled="true", password_last_used=stamp(2), mfa_active="false"),
            cred_row("ci-deployer", access_key_1_active="true", access_key_1_last_rotated=stamp(20),
                     access_key_1_last_used_date=stamp(1)))
        iam = lambda fixture: ok(load_fixture(f"aws/iam/{fixture}.json"))
        core = lambda fixture: ok(load_fixture(f"aws/core/{fixture}.json"))
        users = {"Users": [{"UserName": n, "Arn": f"arn:aws:iam::111122223333:user/{n}", "Path": "/"}
                           for n in ("alice.dev", "bob.qa", "ci-deployer")]}
        return [
            ("sts", "get-caller-identity", None, "", core("sts-get-caller-identity")),
            ("ec2", "describe-regions", None, "", core("ec2-describe-regions")),
            ("iam", "list-users", None, "", ok(users)),
            ("iam", "list-attached-user-policies", None, "", ok({"AttachedPolicies": []})),
            # IAM-001 (offender) and IAM-003 (clean) use the same call with different --query expressions
            ("iam", "get-account-summary", None, "AccountAccessKeysPresent", ok([])),
            ("iam", "get-account-summary", None, "--query", iam("iam-get-account-summary-query-offenders")),
            ("iam", "get-account-summary", None, "", iam("iam-get-account-summary-mfa-off")),
            ("iam", "list-virtual-mfa-devices", None, "", iam("iam-list-virtual-mfa-devices-hardware")),
            ("cloudtrail", "lookup-events", None, "", ok({"Events": []})),
            ("iam", "generate-credential-report", None, "", ok({"State": "COMPLETE"})),
            ("iam", "get-credential-report", None, "", ok(report)),
            ("iam", "get-account-password-policy", None, "",
             err("An error occurred (NoSuchEntity) when calling the GetAccountPasswordPolicy operation: The Password Policy cannot be found.")),
            ("iam", "get-account-authorization-details", None, "User", iam("iam-get-account-authorization-details-users-offenders")),
            ("iam", "get-account-authorization-details", None, "LocalManagedPolicy",
             iam("iam-get-account-authorization-details-policies-offenders")),
            ("iam", "list-entities-for-policy", None, "", ok([])),
            ("accessanalyzer", "list-analyzers", "us-east-1", "", ok([])),
            ("accessanalyzer", "list-analyzers", "eu-west-1", "", ok([{"detail": {"analyzers": 0}}])),
            ("account", "get-alternate-contact", None, "",
             err("An error occurred (ResourceNotFoundException) when calling the GetAlternateContact operation: no contact")),
        ]

    def rows(self, check_id):
        return [(r["status"], r["resource_id"], r["region"]) for r in self.result["results"] if r["check_id"] == check_id]

    def test_run_succeeds_and_nothing_is_unverified(self):
        self.assertEqual(self.code, 0)
        unverified = [(r["check_id"], r["detail"]) for r in self.result["results"] if r["status"] == "NO_VERIFICADO"]
        self.assertEqual(unverified, [])

    def test_account_checks_outcomes(self):
        self.assertEqual(self.rows("IAM-001"), [("FAIL", "root", REGION)])
        self.assertEqual(self.rows("IAM-002"), [("FAIL", "root", REGION)])
        self.assertEqual(self.rows("IAM-003"), [("PASS", "account", None)])
        self.assertEqual(self.rows("IAM-004"), [("PASS", "account", None)])
        self.assertEqual(self.rows("IAM-006"), [("FAIL", "account", REGION)])
        self.assertEqual(self.rows("IAM-007"), [("FAIL", "account", REGION)])
        self.assertEqual(self.rows("IAM-012"), [("FAIL", "arn:aws:iam::111122223333:policy/temp-full-admin", REGION)])
        self.assertEqual([s for s, *_ in self.rows("IAM-013")], ["PENDING_CLAUDE"])
        self.assertEqual(self.rows("IAM-014"), [("PASS", "account", None)])
        self.assertEqual(self.rows("IAM-015"), [("FAIL", "account", "eu-west-1")])
        self.assertEqual(self.rows("IAM-016"), [("FAIL", "account", REGION)])

    def test_resource_checks_outcomes_per_user(self):
        self.assertEqual(self.rows("IAM-005"), [("PASS", "alice.dev", REGION), ("FAIL", "bob.qa", REGION),
                                                ("PASS", "ci-deployer", REGION)])
        for check_id in ("IAM-008", "IAM-009", "IAM-010"):
            self.assertEqual([s for s, *_ in self.rows(check_id)], ["PASS"] * 3, check_id)
        self.assertEqual(self.rows("IAM-011"), [("PASS", "alice.dev", REGION), ("FAIL", "bob.qa", REGION),
                                                ("FAIL", "ci-deployer", REGION)])
        self.assertEqual([(s, r) for s, r, _ in self.rows("IAM-017")],
                         [("FAIL", "alice.dev"), ("FAIL", "bob.qa"), ("PASS", "ci-deployer")])

    def test_only_read_only_calls_were_made(self):
        for argv in self.runner.calls:
            operation = argv[2]
            self.assertTrue(operation.startswith(("get-", "list-", "describe-")) or operation in ("lookup-events", "generate-credential-report"), argv)


if __name__ == "__main__":
    unittest.main()
