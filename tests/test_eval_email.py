import contextlib
import io
import json
import re
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
from test_eval_iam import RuleRunner, ok

try:
    import jmespath
except ImportError:  # the skill itself is stdlib-only; the JMESPath expressions are only verified when it is installed
    jmespath = None

EMAIL_JSON = SKILL_DIR / "references" / "checks" / "email.json"
REFS = SKILL_DIR / "references"
REGION = "us-east-1"
OTHER = "eu-west-1"
DOMAIN, SUBDOMAIN, ADDRESS = "acme-notes.example", "mail.acme-notes.example", "noreply@acme-notes.example"
TRANSACTIONAL, QUIET, OPTIONAL = "acme-notes-transactional", "acme-notes-quiet", "acme-notes-optional"


def fx(name):
    return load_fixture(f"aws/email/{name}.json")


def evaluate(name, responses, params=None):
    return evaluators.EVALUATORS[name](responses, params or {})


def catalog_check(check_id):
    data = json.loads(EMAIL_JSON.read_text(encoding="utf-8"))
    return next(c for c in data["checks"] if c["id"] == check_id)


def ids(offenders):
    return [o["resource_id"] for o in offenders]


def identity_item(name, region=REGION):
    return {"type": "ses_identity", "id": name, "arn": "", "name": name, "region": region, "tags": {}}


class DefaultConfigSetTests(unittest.TestCase):
    def tls(self, identities, sets):
        return evaluate("ses_default_config_tls", merge(for_each("identity", identities), for_each("cset", sets)), {})

    def test_ses_default_config_tls_pass(self):
        found = self.tls([(DOMAIN, fx("sesv2-get-email-identity-verified-dkim"))], [(TRANSACTIONAL, fx("sesv2-get-configuration-set-require"))])
        self.assertEqual(found, [])

    def test_ses_default_config_tls_fail_reports_offenders(self):
        found = self.tls([(DOMAIN, fx("sesv2-get-email-identity-config-set-optional")), (SUBDOMAIN, fx("sesv2-get-email-identity-no-config-set")),
                          (ADDRESS, fx("sesv2-get-email-identity-config-set-quiet"))],
                         [(OPTIONAL, fx("sesv2-get-configuration-set-optional")), (QUIET, fx("sesv2-get-configuration-set-no-tls"))])
        self.assertEqual([(o["resource_id"], o["region"]) for o in found], [(DOMAIN, REGION), (SUBDOMAIN, REGION), (ADDRESS, REGION)])
        self.assertEqual(found[0]["detail"], {"config_set": OPTIONAL, "tls_policy": "OPTIONAL", "reason": "el configuration set por defecto no exige TLS (TlsPolicy distinto de REQUIRE)"})
        self.assertRegex(found[1]["detail"]["reason"], "sin configuration set por defecto")
        self.assertEqual(found[2]["detail"]["tls_policy"], "OPTIONAL")  # no TlsPolicy means the AWS default, OPTIONAL

    def test_tls_policy_is_compared_ignoring_case(self):
        data = fx("sesv2-get-configuration-set-require")
        data["DeliveryOptions"]["TlsPolicy"] = "require"
        self.assertEqual(self.tls([(DOMAIN, fx("sesv2-get-email-identity-verified-dkim"))], [(TRANSACTIONAL, data)]), [])

    def test_a_default_config_set_that_no_longer_exists_fails(self):
        (found,) = self.tls([(DOMAIN, fx("sesv2-get-email-identity-verified-dkim"))], [(TRANSACTIONAL, {"__error__": "NotFoundException"})])
        self.assertEqual((found["resource_id"], found["detail"]["config_set"]), (DOMAIN, TRANSACTIONAL))
        self.assertRegex(found["detail"]["reason"], "no existe")

    def test_blocked_reads_are_unverified_and_a_vanished_identity_is_not_applicable(self):
        denied = {"__error__": "ACCESS_DENIED"}
        found = self.tls([(DOMAIN, denied), (SUBDOMAIN, {"__error__": "NotFoundException"})], [])
        self.assertEqual(flags(found), [(DOMAIN, "unverified"), (SUBDOMAIN, "not_applicable")])
        self.assertEqual((found[0]["detail"]["error_code"], found[0]["detail"]["call"]), ("ACCESS_DENIED", "get-email-identity"))
        (found,) = self.tls([(DOMAIN, fx("sesv2-get-email-identity-verified-dkim"))], [(TRANSACTIONAL, denied)])
        self.assertEqual((found["unverified"], found["detail"]["error_code"], found["detail"]["call"]), (True, "ACCESS_DENIED", "get-configuration-set"))

    def test_two_identities_may_share_the_default_config_set(self):
        shared = fx("sesv2-get-email-identity-verified-dkim")
        found = self.tls([(DOMAIN, shared), (SUBDOMAIN, shared)], [(TRANSACTIONAL, fx("sesv2-get-configuration-set-optional"))])
        self.assertEqual(ids(found), [DOMAIN, SUBDOMAIN])

    def events(self, identities, sets):
        return evaluate("ses_default_config_events", merge(for_each("identity", identities), for_each("events", sets)), {})

    def test_ses_default_config_events_pass(self):
        found = self.events([(DOMAIN, fx("sesv2-get-email-identity-verified-dkim"))], [(TRANSACTIONAL, fx("sesv2-get-configuration-set-event-destinations-active"))])
        self.assertEqual(found, [])

    def test_ses_default_config_events_fail_reports_offenders(self):
        found = self.events([(DOMAIN, fx("sesv2-get-email-identity-config-set-optional")), (SUBDOMAIN, fx("sesv2-get-email-identity-no-config-set")),
                             (ADDRESS, fx("sesv2-get-email-identity-config-set-quiet"))],
                            [(OPTIONAL, fx("sesv2-get-configuration-set-event-destinations-none")),
                             (QUIET, fx("sesv2-get-configuration-set-event-destinations-disabled"))])
        self.assertEqual([(o["resource_id"], o["region"]) for o in found], [(DOMAIN, REGION), (SUBDOMAIN, REGION), (ADDRESS, REGION)])
        self.assertEqual(found[0]["detail"], {"config_set": OPTIONAL, "event_destinations": 0, "reason": "el configuration set por defecto no tiene un event destination habilitado"})
        self.assertRegex(found[1]["detail"]["reason"], "sin configuration set por defecto")
        self.assertEqual(found[2]["detail"]["event_destinations"], 1)  # present but disabled

    def test_blocked_event_destinations_are_unverified(self):
        (found,) = self.events([(DOMAIN, fx("sesv2-get-email-identity-verified-dkim"))], [(TRANSACTIONAL, {"__error__": "ACCESS_DENIED"})])
        self.assertEqual((found["unverified"], found["detail"]["error_code"], found["detail"]["call"]),
                         (True, "ACCESS_DENIED", "get-configuration-set-event-destinations"))


class AccountSendingTests(unittest.TestCase):
    def responses(self, *accounts):
        inventory = [identity_item(DOMAIN), identity_item(ADDRESS), identity_item("acme-notes.eu.example", OTHER)]
        return {"__inventory__": inventory, "account": [(region, fx(name)) for region, name in accounts]}

    def test_ses_account_sending_pass(self):
        self.assertEqual(evaluate("ses_account_sending", self.responses((REGION, "sesv2-get-account-production"), (OTHER, "sesv2-get-account-production"))), [])

    def test_ses_account_sending_fail_reports_offenders(self):
        found = evaluate("ses_account_sending", self.responses((REGION, "sesv2-get-account-sandbox"), (OTHER, "sesv2-get-account-no-suppression")))
        self.assertEqual([(o["resource_id"], o["region"]) for o in found], [(DOMAIN, REGION), (ADDRESS, REGION), ("acme-notes.eu.example", OTHER)])
        self.assertEqual(found[0]["detail"]["reasons"], ["la cuenta SES está en sandbox (sin acceso a producción)"])
        self.assertEqual(found[2]["detail"]["reasons"], ["la lista de supresión de la cuenta no suprime rebotes ni quejas"])

    def test_both_problems_are_reported_together(self):
        data = fx("sesv2-get-account-sandbox")
        data["SuppressionAttributes"]["SuppressedReasons"] = []
        found = evaluate("ses_account_sending", {"__inventory__": [identity_item(DOMAIN)], "account": [(REGION, data)]})
        self.assertEqual(len(found[0]["detail"]["reasons"]), 2)

    def test_a_region_without_identities_is_not_evaluated(self):
        found = evaluate("ses_account_sending", {"__inventory__": [identity_item(DOMAIN)], "account": [(REGION, fx("sesv2-get-account-production")),
                                                                                                      (OTHER, fx("sesv2-get-account-sandbox"))]})
        self.assertEqual(found, [])

    def test_suppressed_reasons_are_compared_ignoring_case(self):
        data = fx("sesv2-get-account-production")
        data["SuppressionAttributes"]["SuppressedReasons"] = ["bounce"]
        self.assertEqual(evaluate("ses_account_sending", {"__inventory__": [identity_item(DOMAIN)], "account": [(REGION, data)]}), [])


class EmailCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks = json.loads(EMAIL_JSON.read_text(encoding="utf-8"))["checks"]

    def search(self, check_id, document):
        return jmespath.search(catalog_check(check_id)["verify"]["offenders"], document)

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_eml_001_passes_a_verified_identity_with_successful_dkim(self):
        for name in ("sesv2-get-email-identity-verified-dkim", "sesv2-get-email-identity-email-address"):
            self.assertEqual(self.search("EML-001", fx(name)), [], name)

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_eml_001_reports_unverified_identities_and_dkim_that_is_not_working(self):
        for name, dkim in (("sesv2-get-email-identity-dkim-pending", "PENDING"), ("sesv2-get-email-identity-dkim-failed", "FAILED"),
                           ("sesv2-get-email-identity-dkim-off", "SUCCESS")):
            (found,) = self.search("EML-001", fx(name))
            self.assertEqual(found["detail"]["dkim_status"], dkim, name)
            self.assertNotIn("resource_id", found)  # the for_each value (the identity) is used

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_eml_001_detail_and_missing_fields(self):
        (found,) = self.search("EML-001", fx("sesv2-get-email-identity-dkim-pending"))
        self.assertEqual(found["detail"], {"identity_type": "DOMAIN", "verified_for_sending": False, "dkim_status": "PENDING", "dkim_signing_enabled": True,
                                           "dkim_origin": "AWS_SES"})
        self.assertEqual(len(self.search("EML-001", {"IdentityType": "DOMAIN"})), 1)
        self.assertEqual(len(self.search("EML-001", {"IdentityType": "EMAIL_ADDRESS"})), 1)  # not verified

    def test_email_catalog_valid(self):
        data = json.loads(EMAIL_JSON.read_text(encoding="utf-8"))
        for check in data["checks"]:
            check.setdefault("domain", data["domain"])
        tsc_ids, iso_ids = catalog.load_frameworks(REFS / "frameworks")
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        self.assertEqual(catalog.validate(data["checks"], tsc_ids, iso_ids, drata), [])
        self.assertEqual([c["id"] for c in data["checks"]], [f"EML-{n:03d}" for n in range(1, 7)])
        self.assertEqual(data["domain"], "email")

    def test_every_python_evaluator_is_registered(self):
        for check in self.checks:
            kind, _, name = check["verify"]["evaluator"].partition(":")
            if kind == "python":
                self.assertIn(name, evaluators.EVALUATORS, check["id"])

    def test_evaluators_severities_and_remediation_follow_the_brief(self):
        expected = {"EML-001": ("jmespath", "medium", "cli_with_decision"), "EML-002": ("python:ses_default_config_tls", "medium", "cli"),
                    "EML-003": ("python:ses_default_config_events", "medium", "cli_with_decision"), "EML-004": ("dns", "medium", "cli_with_decision"),
                    "EML-005": ("dns", "high", "cli_with_decision"), "EML-006": ("python:ses_account_sending", "low", "console_only")}
        self.assertEqual({c["id"]: (c["verify"]["evaluator"], c["severity"], c["remediation"]["kind"]) for c in self.checks}, expected)

    def test_every_check_is_per_ses_identity(self):
        for check in self.checks:
            self.assertEqual((check["scope"], check["resource_types"], check["all_regions"]), ("resource", ["ses_identity"], False), check["id"])

    def test_dns_checks_declare_the_record_and_the_pattern(self):
        for check_id, name, pattern in (("EML-004", "{domain}", "v=spf1"), ("EML-005", "_dmarc.{domain}", "(?i)(^|;)\\s*p=(quarantine|reject)\\b")):
            check = catalog_check(check_id)
            self.assertEqual(check["verify"]["params"], {"rrtype": "TXT", "name_template": name, "must_match": pattern, "domains_from": "ses_identity"})
            self.assertEqual((check["verify"]["calls"], check["verify"]["needs"]), ([], []))

    def test_dmarc_pattern_accepts_quarantine_and_reject_only(self):
        pattern = re.compile(catalog_check("EML-005")["verify"]["params"]["must_match"])
        for text, expected in (('"v=DMARC1; p=reject; rua=mailto:dmarc@acme-notes.example"', True), ('"v=DMARC1; p=quarantine"', True),
                               ('"v=DMARC1;p=quarantine"', True), ('"v=DMARC1; P=REJECT"', True), ('p=reject', True),
                               ('"v=DMARC1; p=none; sp=reject"', False), ('"v=DMARC1; sp=quarantine; p=none"', False),
                               ('"v=DMARC1; p=none"', False), ('"v=DMARC1; p=rejected"', False), ('"v=DMARC1"', False)):
            self.assertEqual(bool(pattern.search(text)), expected, text)

    def test_ses_reads_use_sesv2_and_declare_item_errors(self):
        for check_id, last in (("EML-002", ("cset", "get-configuration-set")), ("EML-003", ("events", "get-configuration-set-event-destinations"))):
            calls = {c["name"]: c for c in catalog_check(check_id)["verify"]["calls"]}
            self.assertEqual(calls["identity"]["operation"], "get-email-identity", check_id)
            self.assertEqual(calls["identity"]["for_each"], {"from": "__inventory__", "path": "id", "arg": "--email-identity"}, check_id)
            self.assertEqual(calls[last[0]]["operation"], last[1], check_id)
            self.assertEqual(calls[last[0]]["for_each"], {"from": "identity", "path": "ConfigurationSetName", "arg": "--configuration-set-name"}, check_id)
            for call in calls.values():
                self.assertEqual((call["service"], call["ok_errors"], call["item_errors"]), ("sesv2", ["NotFoundException"], "evaluator"), check_id)
        (call,) = catalog_check("EML-001")["verify"]["calls"]
        self.assertEqual((call["service"], call["operation"], call["for_each"]),
                         ("sesv2", "get-email-identity", {"from": "__inventory__", "path": "id", "arg": "--email-identity"}))
        (call,) = catalog_check("EML-006")["verify"]["calls"]
        self.assertEqual((call["service"], call["operation"], call["region"]), ("sesv2", "get-account", "each"))

    def test_steps_are_not_numbered_by_hand(self):
        for check in self.checks:
            for step in check["remediation"]["steps"]:
                self.assertNotRegex(step, r"^\d+\.\s", check["id"])

    def test_remediation_commands_follow_cloudshell_rules(self):
        for check in self.checks:
            rem = check["remediation"]
            if rem["kind"] == "console_only":
                self.assertEqual(rem["commands"], [], check["id"])
            for command in rem["commands"]:
                self.assertTrue(command.startswith('REGION="{region}"\nACCOUNT_ID="{account_id}"\n'), check["id"])
                self.assertNotIn("set -e", command, check["id"])
                self.assertNotIn("<<", command, check["id"])
            self.assertTrue(rem["verify_after"].startswith(("aws ", "dig ")), check["id"])

    def test_dns_records_are_plain_steps_in_the_console_or_the_registrar(self):
        for check_id in ("EML-004", "EML-005"):
            rem = catalog_check(check_id)["remediation"]
            self.assertEqual(rem["commands"], [], check_id)
            self.assertRegex(" ".join(rem["steps"]), r"(?i)registrador|Route 53|DNS", check_id)
            self.assertTrue(rem["verify_after"].startswith("dig "), check_id)
        self.assertIn("v=DMARC1", " ".join(catalog_check("EML-005")["remediation"]["steps"]))
        self.assertIn("v=spf1", " ".join(catalog_check("EML-004")["remediation"]["steps"]))

    @unittest.skipUnless(shutil.which("bash"), "bash not installed")
    def test_remediation_commands_and_verification_parse_as_bash(self):
        for check in self.checks:
            rem = check["remediation"]
            for text in [*rem["commands"], rem["verify_after"]]:
                script = text.replace("{region}", "us-east-1").replace("{account_id}", "111122223333").replace("{resource_id}", DOMAIN)
                done = subprocess.run(["bash", "-n"], input=script, capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, f"{check['id']}: {done.stderr}\n{script}")

    def test_eml_002_commands_create_the_set_and_make_it_the_identity_default(self):
        text = "\n".join(catalog_check("EML-002")["remediation"]["commands"])
        self.assertIn("create-configuration-set", text)
        self.assertIn("TlsPolicy=REQUIRE", text)
        self.assertIn("put-configuration-set-delivery-options", text)
        self.assertIn("put-email-identity-configuration-set-attributes", text)

    def test_eml_003_commands_create_an_sns_event_destination(self):
        text = "\n".join(catalog_check("EML-003")["remediation"]["commands"])
        self.assertIn("create-configuration-set-event-destination", text)
        self.assertIn("__COMPLETAR_SNS_TOPIC_ARN__", text)
        self.assertIn("BOUNCE", text)
        self.assertIn("COMPLAINT", text)

    def test_mappings_are_inferred_and_without_drata_or_vanta_tests(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        for check in self.checks:
            self.assertEqual((check["mappings"]["drata"], check["mappings"]["vanta"]), ([], []), check["id"])
            resolved = catalog.resolve_mappings(check, drata)
            self.assertEqual([t["id"] for t in resolved["tsc"]], ["CC6.7"], check["id"])
            self.assertEqual([t["id"] for t in resolved["iso27001_2022"]], ["A.8.24", "A.5.14"], check["id"])
            self.assertTrue(all(t["sourced"] is False for t in resolved["tsc"] + resolved["iso27001_2022"]), check["id"])

    def test_the_texts_say_no_drata_or_vanta_test_covers_ses(self):
        for check in self.checks:
            self.assertRegex(check["verify"]["pass_when_text"], r"(?i)ni Drata ni Vanta|ni Vanta ni Drata|Drata y Vanta no", check["id"])


class DigRunner:
    """RuleRunner for the aws calls plus canned `dig +short TXT <name>` answers. Like every fake AWS it ignores --query, so the
    jmespath call of EML-001 (the only get-email-identity with --query) is answered with the already-queried offender list."""

    def __init__(self, rules, txt, queried):
        self.aws, self.txt, self.queried, self.calls = RuleRunner(rules), txt, queried, []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[0] == "dig":
            return subprocess.CompletedProcess(argv, 0, stdout=self.txt.get(argv[-1], ""), stderr="")
        if argv[2] == "get-email-identity" and "--query" in argv:
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(self.queried[argv[argv.index("--email-identity") + 1]]), stderr="")
        return self.aws(argv, **kwargs)


class EmailCollectTests(unittest.TestCase):
    """The whole email catalog through collect.main with a fake AWS and a fake dig."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        (cls.tmp / "checks").mkdir()
        shutil.copy(EMAIL_JSON, cls.tmp / "checks" / "email.json")
        specs = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))
        (cls.tmp / "inventory.json").write_text(json.dumps({"ses_identity": specs["ses_identity"]}), encoding="utf-8")
        scope = {"platform": "Acme Notes", "mode": "full", "target": None, "regions": [REGION], "profile": None, "resources": [], "domains": None}
        (cls.tmp / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
        txt = {DOMAIN: '"v=spf1 include:amazonses.com ~all"\n"google-site-verification=abc"\n', SUBDOMAIN: "",
               f"_dmarc.{DOMAIN}": '"v=DMARC1; p=reject; rua=mailto:dmarc@acme-notes.example"\n', f"_dmarc.{SUBDOMAIN}": '"v=DMARC1; p=none"\n'}
        pending = [{"detail": {"identity_type": "DOMAIN", "verified_for_sending": False, "dkim_status": "PENDING", "dkim_signing_enabled": True}}]
        cls.runner = DigRunner(cls.rules(), txt, {DOMAIN: [], SUBDOMAIN: pending, ADDRESS: []})
        out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            cls.code = collect.main(
                ["--scope", str(cls.tmp / "scope.json"), "--out", str(out), "--checks-dir", str(cls.tmp / "checks"),
                 "--inventory", str(cls.tmp / "inventory.json")],
                runner=cls.runner, sleep=lambda s: None, which=lambda name: "/usr/bin/dig" if name == "dig" else None)
        cls.result = json.loads((out / "checks-result.json").read_text(encoding="utf-8"))

    @classmethod
    def rules(cls):
        core = lambda name: ok(load_fixture(f"aws/core/{name}.json"))
        data = lambda name: ok(fx(name))
        return [
            ("sts", "get-caller-identity", None, "", core("sts-get-caller-identity")),
            ("ec2", "describe-regions", None, "", core("ec2-describe-regions")),
            ("iam", "list-attached-user-policies", None, "", ok({"AttachedPolicies": []})),
            ("sesv2", "list-email-identities", None, "", data("sesv2-list-email-identities-raw")),
            # most specific identity first: "acme-notes.example" is a substring of the other two
            ("sesv2", "get-email-identity", None, SUBDOMAIN, data("sesv2-get-email-identity-dkim-pending")),
            ("sesv2", "get-email-identity", None, ADDRESS, data("sesv2-get-email-identity-email-address")),
            ("sesv2", "get-email-identity", None, DOMAIN, data("sesv2-get-email-identity-verified-dkim")),
            ("sesv2", "get-configuration-set-event-destinations", None, TRANSACTIONAL, data("sesv2-get-configuration-set-event-destinations-active")),
            ("sesv2", "get-configuration-set", None, TRANSACTIONAL, data("sesv2-get-configuration-set-require")),
            ("sesv2", "get-account", REGION, "", data("sesv2-get-account-production")),
        ]

    def rows(self, check_id):
        return [(r["status"], r["resource_id"]) for r in self.result["results"] if r["check_id"] == check_id]

    def test_run_succeeds_and_nothing_is_unverified(self):
        self.assertEqual(self.code, 0)
        self.assertEqual([r for r in self.result["results"] if r["status"] == "NO_VERIFICADO"], [])

    def test_identity_and_dkim_outcomes(self):
        self.assertEqual(self.rows("EML-001"), [("PASS", DOMAIN), ("FAIL", SUBDOMAIN), ("PASS", ADDRESS)])

    def test_default_configuration_set_outcomes(self):
        for check_id in ("EML-002", "EML-003"):
            self.assertEqual(self.rows(check_id), [("PASS", DOMAIN), ("FAIL", SUBDOMAIN), ("FAIL", ADDRESS)], check_id)

    def test_dns_outcomes_cover_domains_and_skip_email_addresses(self):
        self.assertEqual(self.rows("EML-004"), [("PASS", DOMAIN), ("FAIL", SUBDOMAIN)])
        self.assertEqual(self.rows("EML-005"), [("PASS", DOMAIN), ("FAIL", SUBDOMAIN)])
        queried = sorted(c[-1] for c in self.runner.calls if c[0] == "dig")
        self.assertEqual(queried, sorted([DOMAIN, SUBDOMAIN, f"_dmarc.{DOMAIN}", f"_dmarc.{SUBDOMAIN}"]))

    def test_dmarc_failure_is_high_and_keeps_the_found_record(self):
        (row,) = [r for r in self.result["results"] if r["check_id"] == "EML-005" and r["status"] == "FAIL"]
        self.assertEqual(row["detail"]["record"], f"_dmarc.{SUBDOMAIN}")
        self.assertEqual(catalog_check("EML-005")["severity"], "high")

    def test_account_outcome_is_per_identity(self):
        self.assertEqual(self.rows("EML-006"), [("PASS", DOMAIN), ("PASS", SUBDOMAIN), ("PASS", ADDRESS)])

    def test_each_identity_is_read_once_per_check(self):
        reads = [c[c.index("--email-identity") + 1] for c in self.runner.calls if c[2] == "get-email-identity"]
        self.assertEqual(sorted(reads), sorted([ADDRESS, DOMAIN, SUBDOMAIN] * 3))
        sets = [c[c.index("--configuration-set-name") + 1] for c in self.runner.calls if c[2] == "get-configuration-set"]
        self.assertEqual(sets, [TRANSACTIONAL])  # only one identity has a default configuration set


if __name__ == "__main__":
    unittest.main()
