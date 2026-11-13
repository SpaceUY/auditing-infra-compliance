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
from test_eval_iam import RuleRunner, ok

INVENTORY_JSON = SKILL_DIR / "references" / "checks" / "inventory.json"
REFS = SKILL_DIR / "references"
REGION = "us-east-1"
OTHER = "eu-west-1"
BUCKET_DATA, BUCKET_LOGS, BUCKET_BARE = "acme-notes-data", "acme-notes-logs", "acme-notes-untagged"
TABLE, DB, INSTANCE = "acme-notes-sessions", "acme-notes-db", "i-0a1b2c3d4e5f60718"
QUEUE = "https://sqs.us-east-1.amazonaws.com/111122223333/acme-notes-jobs"
AWS_KEY, CUSTOMER_KEY = "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e", "3c4d5e6f-7a8b-4c9d-8e1f-2a3b4c5d6e7f"
DATA_TYPES = ("s3_bucket", "rds_instance", "rds_cluster", "dynamodb_table", "sqs_queue")


def fx(name):
    return load_fixture(f"aws/inventory/{name}.json")


def evaluate_all(name, responses, params=None):
    return evaluators.EVALUATORS[name](responses, params or {})


def evaluate(name, responses, params=None):
    """The offenders only: not applicable entries are checked on their own."""
    return [o for o in evaluate_all(name, responses, params) if not o.get("not_applicable")]


def catalog_check(check_id):
    data = json.loads(INVENTORY_JSON.read_text(encoding="utf-8"))
    return next(c for c in data["checks"] if c["id"] == check_id)


def params_of(check_id):
    return catalog_check(check_id)["verify"]["params"]


def ids(offenders):
    return [o["resource_id"] for o in offenders]


def responses(kind):
    """The inventory plus one get-resources answer per queried region ('compliant' or 'offenders')."""
    return {"__inventory__": fx("inventory-items"), "aliases": [(REGION, fx("kms-list-aliases")), (OTHER, {"Aliases": []})],
            "tags": [(REGION, fx(f"tagging-get-resources-{kind}-us")), (OTHER, fx(f"tagging-get-resources-{kind}-eu"))]}


class TagPresentTests(unittest.TestCase):
    def test_tag_present_pass_for_owner_emails(self):
        self.assertEqual(evaluate("tag_present", responses("compliant"), params_of("INV-001")), [])

    def test_tag_present_fail_reports_offenders(self):
        found = evaluate("tag_present", responses("offenders"), params_of("INV-001"))
        self.assertEqual([(o["resource_id"], o["region"]) for o in found],
                         [(BUCKET_LOGS, REGION), (BUCKET_BARE, REGION), (INSTANCE, OTHER)])
        self.assertEqual(found[0]["detail"]["value"], "ana")
        self.assertRegex(found[0]["detail"]["reason"], "email")
        self.assertRegex(found[1]["detail"]["reason"], "falta el tag VantaOwner")

    def test_tag_key_match_is_exact(self):
        items = [{"type": "s3_bucket", "id": "b", "arn": "", "name": "b", "region": REGION, "tags": {"vantaowner": "ana@acme-notes.example"}}]
        found = evaluate("tag_present", {"__inventory__": items, "tags": []}, {"key": "VantaOwner", "pattern": "email", "inventory_types": ["s3_bucket"]})
        self.assertEqual(ids(found), ["b"])

    def test_email_pattern_rejects_what_is_not_an_address(self):
        for value in ("ana", "ana@", "@acme-notes.example", "ana@acme", "ana @acme-notes.example", "", "a@b@c.d"):
            items = [{"type": "s3_bucket", "id": "b", "arn": "", "name": "b", "region": REGION, "tags": {"VantaOwner": value}}]
            found = evaluate("tag_present", {"__inventory__": items, "tags": []}, {"key": "VantaOwner", "pattern": "email", "inventory_types": ["s3_bucket"]})
            self.assertEqual(ids(found), ["b"], value)

    def test_only_the_declared_types_are_inspected(self):
        found = evaluate("tag_present", responses("offenders"), {"key": "VantaOwner", "inventory_types": ["rds_instance"]})
        self.assertEqual(found, [])

    def test_tags_of_the_resource_come_from_the_inventory_and_the_tagging_api(self):
        # the RDS instance has its tags in the inventory only; the S3 bucket in the tagging answer only
        found = evaluate("tag_present", responses("offenders"), {"key": "Owner", "inventory_types": ["rds_instance", "s3_bucket"]})
        self.assertEqual(ids(found), [BUCKET_BARE])

    def test_a_resource_does_not_take_the_tags_of_a_namesake_in_another_region(self):
        rds = {"type": "rds_instance", "id": DB, "arn": f"arn:aws:rds:{REGION}:111122223333:db:{DB}", "name": DB, "region": REGION, "tags": {}}
        answer = {"ResourceTagMappingList": [{"ResourceARN": f"arn:aws:rds:us-west-2:111122223333:db:{DB}", "Tags": [{"Key": "Project", "Value": "elsewhere"}]}]}
        found = evaluate("tag_present", {"__inventory__": [rds], "tags": [(REGION, answer)]}, {"key": "Project", "inventory_types": ["rds_instance"]})
        self.assertEqual(ids(found), [DB])


class UserDataFlagTests(unittest.TestCase):
    def stores(self, *values):
        """Buckets whose VantaContainsUserData tag is each value (None = no tag)."""
        return [{"type": "s3_bucket", "id": f"b{n}", "arn": "", "name": f"b{n}", "region": REGION, "tags": {} if v is None else {"VantaContainsUserData": v}}
                for n, v in enumerate(values)]

    def run_with(self, items):
        return evaluate("user_data_flag", {"__inventory__": items, "tags": []}, params_of("INV-002"))

    def test_user_data_flag_pass_with_one_true_store_ignores_case(self):
        self.assertEqual(self.run_with(self.stores("False", "TRUE", "false")), [])
        self.assertEqual(evaluate("user_data_flag", responses("compliant"), params_of("INV-002")), [])

    def test_user_data_flag_fail_reports_offenders(self):
        found = self.run_with(self.stores("false", "False", None, "maybe"))
        self.assertEqual([(o["resource_id"], o["region"]) for o in found], [("account", REGION), ("b2", REGION), ("b3", REGION)])
        self.assertEqual(found[0]["detail"]["data_stores"], 4)
        self.assertNotIn("severity_override", found[0]["detail"])  # the check's own severity (high)
        self.assertEqual([o["detail"]["severity_override"] for o in found[1:]], ["low", "low"])
        self.assertRegex(found[1]["detail"]["reason"], "sin clasificar")
        self.assertEqual(found[2]["detail"]["value"], "maybe")

    def test_stores_without_the_tag_are_low_even_when_one_store_is_true(self):
        found = evaluate("user_data_flag", responses("offenders"), params_of("INV-002"))
        self.assertEqual(ids(found), [BUCKET_LOGS, BUCKET_BARE, TABLE])
        self.assertEqual({o["detail"]["severity_override"] for o in found}, {"low"})
        self.assertEqual([o["detail"].get("value") for o in found], ["maybe", None, "yes"])

    def test_without_data_stores_there_is_nothing_to_report(self):
        self.assertEqual(self.run_with([]), [])

    def test_only_the_data_stores_are_read(self):
        items = fx("inventory-items")
        self.assertEqual(evaluate("user_data_flag", {"__inventory__": items, "tags": []}, {"key": "VantaContainsUserData", "inventory_types": ["ec2_instance"]})[0]["resource_id"],
                         "account")


class AwsManagedKeyTests(unittest.TestCase):
    def test_aws_managed_keys_are_not_applicable_and_customer_keys_are_evaluated(self):
        for evaluator, check_id in (("tag_present", "INV-001"), ("tags_present", "INV-004"), ("nonprod_on_prod", "INV-003")):
            found = evaluate_all(evaluator, {"__inventory__": fx("inventory-items"), "aliases": [(REGION, fx("kms-list-aliases"))], "tags": []}, params_of(check_id))
            self.assertIn({"resource_id": AWS_KEY, "region": REGION, "detail": {}, "not_applicable": True}, found, check_id)
            self.assertNotIn(AWS_KEY, ids([o for o in found if not o.get("not_applicable")]), check_id)
            if evaluator != "nonprod_on_prod":  # the customer key has no tags in this answer
                self.assertIn(CUSTOMER_KEY, ids([o for o in found if not o.get("not_applicable")]), check_id)

    def test_a_key_without_alias_information_is_evaluated(self):
        found = evaluate("tag_present", {"__inventory__": fx("inventory-items"), "aliases": [], "tags": []}, params_of("INV-001"))
        self.assertLessEqual({AWS_KEY, CUSTOMER_KEY}, set(ids(found)))

    def test_only_the_alias_of_the_same_region_marks_a_key_as_aws_managed(self):
        found = evaluate("tag_present", {"__inventory__": fx("inventory-items"), "aliases": [(OTHER, fx("kms-list-aliases"))], "tags": []}, params_of("INV-001"))
        self.assertIn(AWS_KEY, ids(found))

    def test_a_customer_alias_does_not_make_a_key_aws_managed(self):
        aliases = {"Aliases": [{"AliasName": "alias/aws-prod", "TargetKeyId": CUSTOMER_KEY}]}
        found = evaluate("tag_present", {"__inventory__": fx("inventory-items"), "aliases": [(REGION, aliases)], "tags": []}, params_of("INV-001"))
        self.assertIn(CUSTOMER_KEY, ids(found))


class NonprodOnProdTests(unittest.TestCase):
    def test_nonprod_on_prod_pass(self):
        self.assertEqual(evaluate("nonprod_on_prod", responses("compliant"), params_of("INV-003")), [])

    def test_nonprod_on_prod_fail_reports_offenders(self):
        found = evaluate("nonprod_on_prod", responses("offenders"), params_of("INV-003"))
        self.assertEqual([(o["resource_id"], o["region"]) for o in found], [(BUCKET_LOGS, REGION)])
        self.assertEqual(found[0]["detail"], {"environment": "Production", "vanta_non_prod": "TRUE",
                                              "reason": "VantaNonProd=true en un recurso con Environment de producción"})

    def test_both_values_are_compared_ignoring_case_and_prod_aliases(self):
        for environment, flag, expected in (("prod", "true", True), ("PROD", "True", True), ("Production", "TRUE", True), ("production", "true", True),
                                            ("staging", "true", False), ("prod", "false", False), ("prod", "", False), ("preprod", "true", False), ("prod", " true", True), ("prod", "true ", True)):
            items = [{"type": "s3_bucket", "id": "b", "arn": "", "name": "b", "region": REGION, "tags": {"Environment": environment, "VantaNonProd": flag}}]
            found = evaluate("nonprod_on_prod", {"__inventory__": items, "tags": []}, {"inventory_types": ["s3_bucket"]})
            self.assertEqual(bool(found), expected, (environment, flag))

    def test_a_resource_without_either_tag_passes(self):
        items = [{"type": "s3_bucket", "id": "b", "arn": "", "name": "b", "region": REGION, "tags": {"Environment": "prod"}}]
        self.assertEqual(evaluate("nonprod_on_prod", {"__inventory__": items, "tags": []}, {"inventory_types": ["s3_bucket"]}), [])


class TagsPresentTests(unittest.TestCase):
    def test_tags_present_pass(self):
        self.assertEqual(evaluate("tags_present", responses("compliant"), params_of("INV-004")), [])

    def test_tags_present_fail_reports_offenders(self):
        found = evaluate("tags_present", responses("offenders"), params_of("INV-004"))
        self.assertEqual([(o["resource_id"], o["region"]) for o in found],
                         [(BUCKET_LOGS, REGION), (BUCKET_BARE, REGION), (TABLE, REGION), (INSTANCE, OTHER)])
        by_id = {o["resource_id"]: o["detail"]["missing"] for o in found}
        self.assertEqual(by_id[BUCKET_LOGS], ["Project"])
        self.assertEqual(by_id[BUCKET_BARE], ["Project", "Environment", "Owner"])
        self.assertEqual(by_id[TABLE], ["Owner"])  # an empty value counts as missing

    def test_the_required_keys_are_configurable(self):
        found = evaluate("tags_present", responses("offenders"), {"keys": ["CostCenter"], "inventory_types": ["s3_bucket"]})
        self.assertEqual(ids(found), [BUCKET_DATA, BUCKET_LOGS, BUCKET_BARE])
        self.assertEqual(found[0]["detail"]["missing"], ["CostCenter"])

    def test_the_default_keys_are_project_environment_owner(self):
        found = evaluate("tags_present", responses("offenders"), {"inventory_types": ["s3_bucket"]})
        self.assertEqual(ids(found), [BUCKET_LOGS, BUCKET_BARE])
        self.assertEqual(params_of("INV-004")["keys"], ["Project", "Environment", "Owner"])


class InventoryCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks = json.loads(INVENTORY_JSON.read_text(encoding="utf-8"))["checks"]

    def test_inventory_catalog_valid(self):
        data = json.loads(INVENTORY_JSON.read_text(encoding="utf-8"))
        for check in data["checks"]:
            check.setdefault("domain", data["domain"])
        tsc_ids, iso_ids = catalog.load_frameworks(REFS / "frameworks")
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        self.assertEqual(catalog.validate(data["checks"], tsc_ids, iso_ids, drata), [])
        self.assertEqual([c["id"] for c in data["checks"]], [f"INV-{n:03d}" for n in range(1, 5)])
        self.assertEqual(data["domain"], "inventory")

    def test_every_python_evaluator_is_registered(self):
        for check in self.checks:
            kind, _, name = check["verify"]["evaluator"].partition(":")
            self.assertEqual(kind, "python", check["id"])
            self.assertIn(name, evaluators.EVALUATORS, check["id"])

    def test_evaluators_severities_and_remediation_follow_the_brief(self):
        expected = {"INV-001": ("python:tag_present", "high", "cli_with_decision"), "INV-002": ("python:user_data_flag", "high", "cli_with_decision"),
                    "INV-003": ("python:nonprod_on_prod", "high", "cli_with_decision"), "INV-004": ("python:tags_present", "low", "cli_with_decision")}
        self.assertEqual({c["id"]: (c["verify"]["evaluator"], c["severity"], c["remediation"]["kind"]) for c in self.checks}, expected)

    def test_checks_are_per_resource_and_read_tags_in_every_enabled_region(self):
        for check in self.checks:
            self.assertEqual(check["scope"], "resource", check["id"])
            self.assertTrue(check["all_regions"], check["id"])
            call = check["verify"]["calls"][0]
            self.assertEqual((call["service"], call["operation"], call["name"], call["region"]),
                             ("resourcegroupstaggingapi", "get-resources", "tags", "each"), check["id"])
            self.assertIn("tag:GetResources", check["verify"]["needs"], check["id"])

    def test_checks_with_kms_keys_read_the_aliases_to_skip_aws_managed_keys(self):
        for check in self.checks:
            with_keys = "kms_key" in check["resource_types"]
            self.assertEqual([c["name"] for c in check["verify"]["calls"]], ["tags", "aliases"] if with_keys else ["tags"], check["id"])
            self.assertEqual("kms:ListAliases" in check["verify"]["needs"], with_keys, check["id"])
            if with_keys:
                call = check["verify"]["calls"][1]
                self.assertEqual((call["service"], call["operation"], call["region"]), ("kms", "list-aliases", "each"))
                self.assertRegex(check["verify"]["pass_when_text"], r"alias/aws/")
        self.assertNotIn("kms_key", catalog_check("INV-002")["resource_types"])

    def test_resource_types_equal_the_inventory_types_the_evaluator_reads(self):
        for check in self.checks:
            self.assertEqual(check["resource_types"], check["verify"]["params"]["inventory_types"], check["id"])
        specs = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))
        for check in self.checks:
            self.assertFalse(set(check["resource_types"]) - set(specs), check["id"])

    def test_inv_001_covers_the_vanta_supported_types_of_the_inventory_without_iam_and_network(self):
        types = set(catalog_check("INV-001")["resource_types"])
        self.assertLessEqual({"ec2_instance", "ebs_volume", "rds_instance", "efs", "asg", "s3_bucket", "dynamodb_table", "sqs_queue",
                              "lambda_function", "elbv2", "eks_cluster", "kms_key", "log_group", "cloudtrail_trail", "acm_certificate"}, types)
        self.assertFalse(types & {"iam_user", "iam_role", "security_group", "nacl", "vpc", "subnet", "rds_cluster", "ses_identity"})

    def test_inv_002_is_limited_to_the_data_stores(self):
        self.assertEqual(catalog_check("INV-002")["resource_types"], list(DATA_TYPES))

    def test_inv_001_and_inv_002_use_the_exact_vanta_tag_keys(self):
        self.assertEqual(params_of("INV-001")["key"], "VantaOwner")
        self.assertEqual(params_of("INV-001")["pattern"], "email")
        self.assertEqual(params_of("INV-002")["key"], "VantaContainsUserData")
        self.assertNotIn("pattern", params_of("INV-002"))

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

    def test_tagging_commands_use_placeholders_and_the_resourcegroupstaggingapi(self):
        text = "\n".join(catalog_check("INV-001")["remediation"]["commands"])
        self.assertIn("__COMPLETAR_OWNER_EMAIL__", text)
        self.assertIn('RESOURCE_ARN="{resource_arn}"', text)
        self.assertIn("tag-resources", text)
        self.assertIn("VantaOwner", text)
        text = "\n".join(catalog_check("INV-002")["remediation"]["commands"])
        self.assertIn("VantaContainsUserData", text)
        self.assertIn("__COMPLETAR_", text)
        self.assertIn("untag-resources", "\n".join(catalog_check("INV-003")["remediation"]["commands"]))
        self.assertIn("VantaNonProd", "\n".join(catalog_check("INV-003")["remediation"]["commands"]))

    @unittest.skipUnless(shutil.which("bash"), "bash not installed")
    def test_remediation_commands_and_verification_parse_as_bash(self):
        for check in self.checks:
            rem = check["remediation"]
            for text in [*rem["commands"], rem["verify_after"]]:
                script = (text.replace("{region}", "us-east-1").replace("{account_id}", "111122223333").replace("{resource_id}", "acme-notes-x")
                          .replace("{resource_arn}", "arn:aws:s3:::acme-notes-x"))
                done = subprocess.run(["bash", "-n"], input=script, capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, f"{check['id']}: {done.stderr}\n{script}")

    def test_no_drata_test_so_mappings_are_inferred(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        for check in self.checks:
            self.assertEqual(check["mappings"]["drata"], [], check["id"])
            resolved = catalog.resolve_mappings(check, drata)
            self.assertEqual([t["id"] for t in resolved["tsc"]], ["CC6.1"], check["id"])
            self.assertEqual([t["id"] for t in resolved["iso27001_2022"]], ["A.5.9"], check["id"])
            self.assertTrue(all(t["sourced"] is False for t in resolved["tsc"] + resolved["iso27001_2022"]), check["id"])

    def test_vanta_tests(self):
        self.assertEqual([m["test"] for m in catalog_check("INV-001")["mappings"]["vanta"]], ["Inventory items have active owners"])
        self.assertEqual([m["test"] for m in catalog_check("INV-002")["mappings"]["vanta"]],
                         ["Inventory list tracks resources that contain user data"])

    def test_inv_002_follows_the_vanta_test_and_documents_the_severities(self):
        text = catalog_check("INV-002")["verify"]["pass_when_text"]
        self.assertRegex(text, r"al menos un bucket")
        self.assertRegex(text, r"resource_id account")
        self.assertRegex(text, r"sin clasificar")
        self.assertRegex(text, r"N/A")

    def test_no_command_uses_the_old_arn_placeholder(self):
        for check in self.checks:
            rem = check["remediation"]
            self.assertNotIn("__COMPLETAR_ARN", "\n".join([*rem["commands"], rem["verify_after"], rem["notes"]]), check["id"])
            self.assertIn("{resource_arn}", "\n".join([*rem["commands"], rem["verify_after"]]), check["id"])

    def test_pass_when_texts_name_the_tagging_api_limit(self):
        for check in self.checks:
            self.assertIn("Resource Groups Tagging API", check["verify"]["pass_when_text"], check["id"])


class InventoryCollectTests(unittest.TestCase):
    """The inventory catalog through collect.main with a fake AWS: tags are read in every enabled region and merged by ARN."""

    TYPES = ("s3_bucket", "dynamodb_table", "sqs_queue", "rds_instance", "ec2_instance", "kms_key")

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        (cls.tmp / "checks").mkdir()
        data = json.loads(INVENTORY_JSON.read_text(encoding="utf-8"))
        for check in data["checks"]:  # a test inventory with only the types the fake AWS lists
            check["resource_types"] = [t for t in check["resource_types"] if t in cls.TYPES]
            check["verify"]["params"]["inventory_types"] = list(check["resource_types"])
        (cls.tmp / "checks" / "inventory.json").write_text(json.dumps(data), encoding="utf-8")
        specs = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))
        (cls.tmp / "inventory.json").write_text(json.dumps({t: specs[t] for t in cls.TYPES}), encoding="utf-8")
        scope = {"platform": "Acme Notes", "mode": "full", "target": None, "regions": [REGION, OTHER], "profile": None, "resources": [], "domains": None}
        (cls.tmp / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
        cls.runner = RuleRunner(cls.rules())
        out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            cls.code = collect.main(
                ["--scope", str(cls.tmp / "scope.json"), "--out", str(out), "--checks-dir", str(cls.tmp / "checks"),
                 "--inventory", str(cls.tmp / "inventory.json"), "--quiet"],
                runner=cls.runner, sleep=lambda s: None, which=lambda name: None)
        cls.result = json.loads((out / "checks-result.json").read_text(encoding="utf-8"))

    @classmethod
    def rules(cls):
        core = lambda name: ok(load_fixture(f"aws/core/{name}.json"))
        empty = lambda key: ok({key: []})
        db = {"DBInstances": [{"DBInstanceIdentifier": DB, "DBInstanceArn": f"arn:aws:rds:{REGION}:111122223333:db:{DB}",
                               "TagList": [{"Key": "VantaOwner", "Value": "ana@acme-notes.example"}]}]}
        return [
            ("sts", "get-caller-identity", None, "", core("sts-get-caller-identity")),
            ("ec2", "describe-regions", None, "", core("ec2-describe-regions")),
            ("iam", "list-attached-user-policies", None, "", ok({"AttachedPolicies": []})),
            ("s3api", "list-buckets", None, "", ok({"Buckets": [{"Name": b} for b in (BUCKET_DATA, BUCKET_LOGS, BUCKET_BARE)]})),
            ("dynamodb", "list-tables", REGION, "", ok({"TableNames": [TABLE]})),
            ("dynamodb", "list-tables", OTHER, "", empty("TableNames")),
            ("sqs", "list-queues", REGION, "", ok({"QueueUrls": [QUEUE]})),
            ("sqs", "list-queues", OTHER, "", empty("QueueUrls")),
            ("rds", "describe-db-instances", REGION, "", ok(db)),
            ("rds", "describe-db-instances", OTHER, "", empty("DBInstances")),
            ("kms", "list-keys", REGION, "", ok({"Keys": [{"KeyId": k, "KeyArn": f"arn:aws:kms:{REGION}:111122223333:key/{k}"} for k in (AWS_KEY, CUSTOMER_KEY)]})),
            ("kms", "list-keys", OTHER, "", empty("Keys")),
            ("kms", "list-aliases", REGION, "", ok(fx("kms-list-aliases"))),
            ("kms", "list-aliases", OTHER, "", empty("Aliases")),
            ("ec2", "describe-instances", REGION, "", ok({"Reservations": []})),
            ("ec2", "describe-instances", OTHER, "", ok({"Reservations": [{"Instances": [{"InstanceId": INSTANCE, "Tags": []}]}]})),
            ("resourcegroupstaggingapi", "get-resources", REGION, "", ok(fx("tagging-get-resources-offenders-us"))),
            ("resourcegroupstaggingapi", "get-resources", OTHER, "", ok(fx("tagging-get-resources-offenders-eu"))),
        ]

    def rows(self, check_id):
        return [(r["status"], r["resource_id"]) for r in self.result["results"] if r["check_id"] == check_id]

    def test_run_succeeds_and_nothing_is_unverified(self):
        self.assertEqual(self.code, 0)
        self.assertEqual([r for r in self.result["results"] if r["status"] == "NO_VERIFICADO"], [])

    def test_owner_outcomes(self):
        by_id = dict((i, s) for s, i in self.rows("INV-001"))
        self.assertEqual(by_id, {BUCKET_DATA: "PASS", BUCKET_LOGS: "FAIL", BUCKET_BARE: "FAIL", TABLE: "PASS", QUEUE: "PASS", DB: "PASS", INSTANCE: "FAIL",
                                 CUSTOMER_KEY: "PASS"})  # the AWS-managed key has no row

    def test_data_user_data_outcomes_only_cover_the_data_stores(self):
        by_id = dict((i, s) for s, i in self.rows("INV-002"))
        self.assertEqual(set(by_id), {BUCKET_DATA, BUCKET_LOGS, BUCKET_BARE, TABLE, QUEUE, DB})
        self.assertEqual(by_id, {BUCKET_DATA: "PASS", BUCKET_LOGS: "FAIL", BUCKET_BARE: "FAIL", TABLE: "FAIL", QUEUE: "PASS", DB: "FAIL"})

    def test_nonprod_outcomes(self):
        fails = [i for s, i in self.rows("INV-003") if s == "FAIL"]
        self.assertEqual(fails, [BUCKET_LOGS])

    def test_tags_are_read_in_every_enabled_region(self):
        regions = sorted(c[c.index("--region") + 1] for c in self.runner.calls if c[2] == "get-resources")
        self.assertEqual(regions, [OTHER, REGION])  # the four INV checks share one memoized call per region

    def test_aws_managed_keys_get_no_row_in_any_check(self):
        self.assertEqual([r for r in self.result["results"] if r["resource_id"] == AWS_KEY], [])
        self.assertEqual(self.rows("INV-004").count(("PASS", CUSTOMER_KEY)), 1)


if __name__ == "__main__":
    unittest.main()
