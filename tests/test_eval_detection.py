import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import helpers
from helpers import SKILL_DIR, load_fixture

import aws_runner
import catalog
import collect
import evaluators
from test_eval_iam import RuleRunner, err, ok

try:
    import jmespath
except ImportError:  # the skill itself is stdlib-only; the JMESPath expressions are only verified when it is installed
    jmespath = None

DETECTION_JSON = SKILL_DIR / "references" / "checks" / "detection.json"
REFS = SKILL_DIR / "references"
REGION = "us-east-1"
OTHER = "eu-west-1"
ACCOUNT = "111122223333"
DETECTOR_ID = "12abc34d567e8fa901bc2d34e56789f0"
RULE = "acme-notes-guardduty-findings"
INSTANCE = "i-0a1b2c3d4e5f60718"


def fx(name):
    return load_fixture(f"aws/detection/{name}.json")


def evaluate(name, responses, params=None):
    return evaluators.EVALUATORS[name](responses, params or {})


def catalog_check(check_id):
    data = json.loads(DETECTION_JSON.read_text(encoding="utf-8"))
    return next(c for c in data["checks"] if c["id"] == check_id)


def params_of(check_id):
    return catalog_check(check_id)["verify"].get("params") or {}


def item(type_, id_, region=REGION):
    return {"type": type_, "id": id_, "arn": "", "name": id_, "region": region, "tags": []}


def guardduty(*regions):
    """regions: (region, list-detectors fixture, get-detector fixture | None) -> evaluator view of both calls."""
    detectors = [(region, fx(listing)) for region, listing, _ in regions]
    detail = [(region, fx(name)) for region, _, name in regions if name]
    return {"detectors": detectors, "detector": detail, "__for_each__": {"detector": [DETECTOR_ID] * len(detail)}}


def with_inventory(responses, *items):
    return {**responses, "__inventory__": list(items)}


class GuardDutyRegionsTests(unittest.TestCase):
    PARAMS = params_of("DET-001")

    def test_guardduty_regions_pass(self):
        responses = with_inventory(
            guardduty((REGION, "guardduty-list-detectors-one", "guardduty-get-detector-enabled"),
                      (OTHER, "guardduty-list-detectors-one", "guardduty-get-detector-enabled")),
            item("ec2_instance", INSTANCE))
        self.assertEqual(evaluate("guardduty_regions", responses, self.PARAMS), [])

    def test_guardduty_regions_fail_reports_offenders(self):
        responses = with_inventory(
            guardduty((REGION, "guardduty-list-detectors-none", None), (OTHER, "guardduty-list-detectors-none", None)),
            item("ec2_instance", INSTANCE))
        offenders = evaluate("guardduty_regions", responses, self.PARAMS)
        self.assertEqual([(o["resource_id"], o["region"]) for o in offenders], [("account", REGION), ("account", OTHER)])

    def test_region_with_resources_is_a_real_offender_and_an_empty_one_is_low(self):
        responses = with_inventory(
            guardduty((REGION, "guardduty-list-detectors-none", None), (OTHER, "guardduty-list-detectors-none", None)),
            item("ec2_instance", INSTANCE))
        used, empty = evaluate("guardduty_regions", responses, self.PARAMS)
        self.assertNotIn("severity_override", used["detail"])
        self.assertTrue(used["detail"]["has_resources"])
        self.assertEqual(empty["detail"]["severity_override"], "low")
        self.assertFalse(empty["detail"]["has_resources"])

    def test_suspended_detector_counts_as_missing(self):
        responses = with_inventory(
            guardduty((REGION, "guardduty-list-detectors-one", "guardduty-get-detector-suspended")),
            item("ec2_instance", INSTANCE))
        (offender,) = evaluate("guardduty_regions", responses, self.PARAMS)
        self.assertEqual((offender["region"], offender["detail"]["reason"]), (REGION, "detector de GuardDuty deshabilitado"))

    def test_s3_buckets_make_the_default_region_a_region_with_resources(self):
        responses = with_inventory(guardduty((REGION, "guardduty-list-detectors-none", None)), item("s3_bucket", "acme-notes-data"))
        (offender,) = evaluate("guardduty_regions", responses, self.PARAMS)
        self.assertNotIn("severity_override", offender["detail"])

    def test_global_and_default_resources_do_not_make_a_region_populated(self):
        responses = with_inventory(guardduty((OTHER, "guardduty-list-detectors-none", None)),
                                   item("iam_user", "alice.dev"), item("vpc", "vpc-0a1b2c3d4e5f60718", OTHER))
        (offender,) = evaluate("guardduty_regions", responses, self.PARAMS)
        self.assertEqual(offender["detail"]["severity_override"], "low")


class GuardDutyS3ProtectionTests(unittest.TestCase):
    BUCKET = item("s3_bucket", "acme-notes-data")

    def test_guardduty_s3_protection_pass(self):
        responses = with_inventory(guardduty((REGION, "guardduty-list-detectors-one", "guardduty-get-detector-enabled")), self.BUCKET)
        self.assertEqual(evaluate("guardduty_s3_protection", responses), [])

    def test_guardduty_s3_protection_pass_with_the_legacy_data_sources_shape(self):
        responses = with_inventory(guardduty((REGION, "guardduty-list-detectors-one", "guardduty-get-detector-legacy-s3")), self.BUCKET)
        self.assertEqual(evaluate("guardduty_s3_protection", responses), [])

    def test_guardduty_s3_protection_fail_reports_offenders(self):
        responses = with_inventory(guardduty((REGION, "guardduty-list-detectors-one", "guardduty-get-detector-s3-off")), self.BUCKET)
        (offender,) = evaluate("guardduty_s3_protection", responses)
        self.assertEqual((offender["resource_id"], offender["region"]), ("account", REGION))
        self.assertEqual(offender["detail"]["detector_id"], DETECTOR_ID)

    def test_legacy_shape_with_s3_logs_disabled_fails(self):
        responses = with_inventory(guardduty((REGION, "guardduty-list-detectors-one", "guardduty-get-detector-legacy-s3-off")), self.BUCKET)
        self.assertEqual([o["region"] for o in evaluate("guardduty_s3_protection", responses)], [REGION])

    def test_no_buckets_passes_like_drata(self):
        responses = with_inventory(guardduty((REGION, "guardduty-list-detectors-one", "guardduty-get-detector-s3-off")))
        self.assertEqual(evaluate("guardduty_s3_protection", responses), [])

    def test_without_any_enabled_detector_the_account_has_no_s3_protection(self):
        responses = with_inventory(guardduty((REGION, "guardduty-list-detectors-none", None)), self.BUCKET)
        (offender,) = evaluate("guardduty_s3_protection", responses)
        self.assertEqual((offender["resource_id"], offender["region"]), ("account", REGION))

    def test_a_suspended_detector_is_left_to_det_001(self):
        responses = with_inventory(
            guardduty((REGION, "guardduty-list-detectors-one", "guardduty-get-detector-enabled"),
                      (OTHER, "guardduty-list-detectors-one", "guardduty-get-detector-suspended")), self.BUCKET)
        self.assertEqual(evaluate("guardduty_s3_protection", responses), [])


class GuardDutyEventBridgeTests(unittest.TestCase):
    def responses(self, rules_fixture, targets_fixture=None, region=REGION):
        rules = fx(rules_fixture)
        names = [r["Name"] for r in rules["Rules"]]
        targets = [(region, fx(targets_fixture))] * len(names) if targets_fixture else []
        return {"rules": [(region, rules)], "targets": targets,
                "__for_each__": {"targets": names if targets_fixture else []}}

    def test_guardduty_eventbridge_pass(self):
        responses = self.responses("events-list-rules-guardduty", "events-list-targets-sns")
        self.assertEqual(evaluate("guardduty_eventbridge", responses), [])

    def test_guardduty_eventbridge_pass_when_only_one_region_has_the_rule(self):
        responses = self.responses("events-list-rules-guardduty", "events-list-targets-sns")
        responses["rules"].append((OTHER, fx("events-list-rules-none")))
        self.assertEqual(evaluate("guardduty_eventbridge", responses), [])

    def test_guardduty_eventbridge_fail_reports_offenders(self):
        responses = self.responses("events-list-rules-other")
        (offender,) = evaluate("guardduty_eventbridge", responses)
        self.assertEqual((offender["resource_id"], offender["region"]), ("account", REGION))
        self.assertEqual(offender["detail"]["reason"], "sin regla de EventBridge para findings de GuardDuty")

    def test_rule_without_targets_fails(self):
        offenders = evaluate("guardduty_eventbridge", self.responses("events-list-rules-guardduty", "events-list-targets-empty"))
        (offender,) = offenders
        self.assertEqual(offender["detail"]["reason"], "la regla de GuardDuty no tiene destino")
        self.assertEqual(offender["detail"]["rules"], [RULE])

    def test_disabled_rule_fails(self):
        responses = self.responses("events-list-rules-disabled", "events-list-targets-sns")
        (offender,) = evaluate("guardduty_eventbridge", responses)
        self.assertEqual(offender["detail"]["reason"], "la regla de GuardDuty está deshabilitada")

    def test_patterns_that_are_not_modelled_are_not_covered(self):
        responses = self.responses("events-list-rules-prefix-source", "events-list-targets-sns")
        (offender,) = evaluate("guardduty_eventbridge", responses)
        self.assertEqual(offender["detail"]["reason"], "sin regla de EventBridge para findings de GuardDuty")

    def test_no_rules_at_all_fails(self):
        (offender,) = evaluate("guardduty_eventbridge", self.responses("events-list-rules-none"))
        self.assertEqual(offender["resource_id"], "account")


class SecurityHubStandardsTests(unittest.TestCase):
    def responses(self, *fixtures):
        regions = (REGION, OTHER)
        return {"standards": [(regions[i], fx(f)) for i, f in enumerate(fixtures)]}

    def test_securityhub_standards_pass_with_fsbp(self):
        self.assertEqual(evaluate("securityhub_standards", self.responses("securityhub-get-enabled-standards-fsbp")), [])

    def test_securityhub_standards_pass_with_cis_next_to_other_standards(self):
        self.assertEqual(evaluate("securityhub_standards", self.responses("securityhub-get-enabled-standards-cis")), [])

    def test_securityhub_standards_fail_reports_offenders(self):
        responses = self.responses("securityhub-get-enabled-standards-fsbp", "securityhub-get-enabled-standards-none")
        (offender,) = evaluate("securityhub_standards", responses)
        self.assertEqual((offender["resource_id"], offender["region"]), ("account", OTHER))

    def test_other_standards_only_is_not_enough(self):
        (offender,) = evaluate("securityhub_standards", self.responses("securityhub-get-enabled-standards-other"))
        self.assertEqual(offender["detail"]["standards"], [{"standard": "pci-dss", "status": "READY"}])

    def test_standard_that_is_not_ready_does_not_count(self):
        (offender,) = evaluate("securityhub_standards", self.responses("securityhub-get-enabled-standards-pending"))
        self.assertEqual(offender["detail"]["standards"], [{"standard": "aws-foundational-security-best-practices", "status": "PENDING"}])


class ConfigRecorderTests(unittest.TestCase):
    def responses(self, recorders="ok", status="recording", channels="ok", region=REGION):
        return {"recorders": [(region, fx(f"configservice-describe-configuration-recorders-{recorders}"))],
                "status": [(region, fx(f"configservice-describe-configuration-recorder-status-{status}"))],
                "channels": [(region, fx(f"configservice-describe-delivery-channels-{channels}"))]}

    def problems(self, **kwargs):
        offenders = evaluate("config_recorder", self.responses(**kwargs))
        return [p for o in offenders for p in o["detail"]["problems"]]

    def test_config_recorder_pass(self):
        self.assertEqual(evaluate("config_recorder", self.responses()), [])

    def test_config_recorder_pass_with_iam_recorded_daily_by_default(self):
        self.assertEqual(evaluate("config_recorder", self.responses(recorders="daily-default")), [])

    def test_config_recorder_pass_with_the_all_supported_strategy(self):
        self.assertEqual(evaluate("config_recorder", self.responses(recorders="all-strategy")), [])

    def test_config_recorder_pass_without_sns(self):
        self.assertEqual(evaluate("config_recorder", self.responses(channels="no-sns")), [])

    def test_config_recorder_fail_reports_offenders(self):
        responses = {**self.responses(), **{k: [(OTHER, d)] for k, d in (
            ("recorders", fx("configservice-describe-configuration-recorders-none")),
            ("status", fx("configservice-describe-configuration-recorder-status-none")),
            ("channels", fx("configservice-describe-delivery-channels-none")))}}
        (offender,) = evaluate("config_recorder", responses)
        self.assertEqual((offender["resource_id"], offender["region"]), ("account", OTHER))
        self.assertEqual(offender["detail"]["problems"], ["sin grabador de AWS Config"])

    def test_stopped_recorder(self):
        self.assertEqual(self.problems(status="stopped"), ["el grabador está detenido (recording=false)"])

    def test_recorder_whose_last_delivery_failed(self):
        self.assertEqual(self.problems(status="failure"), ["el último estado del grabador es FAILURE"])

    def test_recorder_without_status_entry_is_not_recording(self):
        self.assertEqual(self.problems(status="none"), ["el grabador está detenido (recording=false)"])

    def test_not_all_resource_types(self):
        self.assertEqual(self.problems(recorders="selected-types"), ["no graba todos los tipos de recurso"])

    def test_exclusion_strategy_is_not_all_types(self):
        self.assertEqual(self.problems(recorders="exclusion"), ["no graba todos los tipos de recurso"])

    def test_iam_types_must_be_daily(self):
        expected = ["los tipos IAM globales no se graban a diario (override DAILY)"]
        self.assertEqual(self.problems(recorders="continuous-iam"), expected)
        self.assertEqual(self.problems(recorders="no-mode"), expected)

    def test_daily_override_must_cover_all_four_iam_types(self):
        self.assertEqual(self.problems(recorders="partial-iam"),
                         ["los tipos IAM globales no se graban a diario (override DAILY)"])

    def test_missing_delivery_channel(self):
        self.assertEqual(self.problems(channels="none"), ["sin delivery channel con bucket de S3"])

    def test_every_problem_is_reported(self):
        self.assertEqual(len(self.problems(recorders="selected-types", status="stopped", channels="none")), 3)


class InspectorStatusTests(unittest.TestCase):
    PARAMS = params_of("DET-006")

    def responses(self, fixture, region=REGION):
        return {"status": [(region, fx(f"inspector2-batch-get-account-status-{fixture}"))]}

    def test_inspector_status_pass(self):
        self.assertEqual(evaluate("inspector_status", self.responses("all"), self.PARAMS), [])

    def test_inspector_status_fail_reports_offenders(self):
        (offender,) = evaluate("inspector_status", self.responses("ec2-only"), self.PARAMS)
        self.assertEqual((offender["resource_id"], offender["region"]), ("account", REGION))
        self.assertEqual(offender["detail"]["not_enabled"], ["ecr", "lambda"])

    def test_fully_disabled_inspector(self):
        (offender,) = evaluate("inspector_status", self.responses("disabled"), self.PARAMS)
        self.assertEqual(offender["detail"]["not_enabled"], ["ec2", "ecr", "lambda"])

    def test_enabling_is_not_enabled_yet(self):
        (offender,) = evaluate("inspector_status", self.responses("enabling"), self.PARAMS)
        self.assertEqual(offender["detail"]["not_enabled"], ["ecr"])

    def test_account_missing_from_the_response_fails(self):
        (offender,) = evaluate("inspector_status", self.responses("failed"), self.PARAMS)
        self.assertEqual(offender["detail"]["not_enabled"], ["ec2", "ecr", "lambda"])


class InspectorFindingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.check = catalog_check("DET-007")

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_det_007_offenders_expression_projects_resource_and_detail(self):
        self.assertEqual(jmespath.search(self.check["verify"]["offenders"], fx("inspector2-list-findings-raw")),
                         fx("inspector2-list-findings-offenders"))
        self.assertEqual(jmespath.search(self.check["verify"]["offenders"], {"findings": []}), [])

    def test_det_007_filters_active_critical_and_high_findings_server_side(self):
        (call,) = self.check["verify"]["calls"]
        criteria = json.loads(call["args"][call["args"].index("--filter-criteria") + 1])
        self.assertEqual(criteria["findingStatus"], [{"comparison": "EQUALS", "value": "ACTIVE"}])
        self.assertEqual({f["value"] for f in criteria["severity"]}, {"CRITICAL", "HIGH"})
        self.assertIn("--max-items", call["args"])


class DetectionCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks = json.loads(DETECTION_JSON.read_text(encoding="utf-8"))["checks"]

    def test_detection_catalog_valid(self):
        data = json.loads(DETECTION_JSON.read_text(encoding="utf-8"))
        for check in data["checks"]:
            check.setdefault("domain", data["domain"])
        tsc_ids, iso_ids = catalog.load_frameworks(REFS / "frameworks")
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        self.assertEqual(catalog.validate(data["checks"], tsc_ids, iso_ids, drata), [])
        self.assertEqual([c["id"] for c in data["checks"]], [f"DET-{n:03d}" for n in range(1, 8)])

    def test_every_python_evaluator_is_registered(self):
        for check in self.checks:
            kind, _, name = check["verify"]["evaluator"].partition(":")
            if kind == "python":
                self.assertIn(name, evaluators.EVALUATORS, check["id"])

    def test_evaluator_kinds_follow_the_brief(self):
        expected = {"DET-001": "python:guardduty_regions", "DET-002": "python:guardduty_s3_protection",
                    "DET-003": "python:guardduty_eventbridge", "DET-004": "python:securityhub_standards",
                    "DET-005": "python:config_recorder", "DET-006": "python:inspector_status", "DET-007": "jmespath"}
        self.assertEqual({c["id"]: c["verify"]["evaluator"] for c in self.checks}, expected)

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
            self.assertTrue(rem["verify_after"].startswith("aws "), check["id"])

    def test_det_001_enables_guardduty_with_s3_protection_in_the_offending_region(self):
        commands = catalog_check("DET-001")["remediation"]["commands"]
        self.assertIn('aws guardduty create-detector --enable --region "{region}" --features '
                      '\'[{"Name":"S3_DATA_EVENTS","Status":"ENABLED"}]\'', commands[0])

    def test_det_001_reenables_a_suspended_detector_only_after_looking_it_up(self):
        suspended = catalog_check("DET-001")["remediation"]["commands"][1]
        self.assertRegex(suspended, r"DETECTOR_ID=\$\(aws guardduty list-detectors [^\n]*\) && aws guardduty update-detector")

    def test_det_002_updates_the_detector_found_by_the_lookup(self):
        (command,) = catalog_check("DET-002")["remediation"]["commands"]
        self.assertRegex(command, r"DETECTOR_ID=\$\(aws guardduty list-detectors [^\n]*\) && aws guardduty update-detector")
        self.assertIn("S3_DATA_EVENTS", command)

    def test_det_003_creates_the_target_only_after_the_rule(self):
        (command,) = catalog_check("DET-003")["remediation"]["commands"]
        self.assertRegex(command, r"events put-rule [^\n]*&& aws events put-targets")

    def test_det_005_starts_the_recorder_only_after_the_channel_exists(self):
        commands = "\n".join(catalog_check("DET-005")["remediation"]["commands"])
        self.assertRegex(commands, r"put-configuration-recorder [^\n]*&& aws configservice put-delivery-channel [^\n]*"
                                   r"&& aws configservice start-configuration-recorder")
        self.assertRegex(catalog_check("DET-005")["remediation"]["notes"], r"(?i)costo")

    def test_det_007_is_a_planned_change_with_a_warning(self):
        rem = catalog_check("DET-007")["remediation"]
        self.assertEqual(rem["kind"], "planned_change")
        self.assertRegex(rem["notes"], r"(?i)reinici")

    def test_enablement_checks_treat_a_disabled_service_as_a_failure(self):
        for check_id in ("DET-001", "DET-004", "DET-005", "DET-006"):
            self.assertEqual(catalog_check(check_id)["not_enabled_means"], "fail", check_id)

    def test_all_regions_flags(self):
        expected = {"DET-001": True, "DET-002": True, "DET-003": False, "DET-004": False, "DET-005": True,
                    "DET-006": False, "DET-007": False}
        self.assertEqual({c["id"]: c["all_regions"] for c in self.checks}, expected)

    def test_drata_mapped_checks_resolve_from_the_dcf_file(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        for check_id in ("DET-001", "DET-002"):
            resolved = catalog.resolve_mappings(catalog_check(check_id), drata)
            self.assertEqual([m["test"] for m in resolved["drata"]], [105], check_id)
            self.assertTrue(resolved["tsc"] and all(t["sourced"] == catalog.DCF_SOURCE for t in resolved["tsc"]), check_id)

    def test_checks_without_a_resolvable_drata_test_carry_inferred_mappings(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        for check_id in ("DET-003", "DET-004", "DET-005", "DET-006", "DET-007"):
            resolved = catalog.resolve_mappings(catalog_check(check_id), drata)
            self.assertTrue(resolved["tsc"] and resolved["iso27001_2022"], check_id)
            self.assertTrue(all(m["sourced"] is False for m in resolved["tsc"] + resolved["iso27001_2022"]), check_id)
        for check_id in ("DET-006", "DET-007"):
            self.assertEqual([m["test"] for m in catalog_check(check_id)["mappings"]["drata"]], [21], check_id)

    def test_severities_follow_the_brief(self):
        expected = {"DET-001": "high", "DET-002": "high", "DET-003": "medium", "DET-004": "high", "DET-005": "high",
                    "DET-006": "high", "DET-007": "high"}
        self.assertEqual({c["id"]: c["severity"] for c in self.checks}, expected)

    def test_remediation_kinds_follow_the_brief(self):
        expected = {"DET-001": "cli", "DET-002": "cli", "DET-003": "cli_with_decision", "DET-004": "cli",
                    "DET-005": "cli_with_decision", "DET-006": "cli", "DET-007": "planned_change"}
        self.assertEqual({c["id"]: c["remediation"]["kind"] for c in self.checks}, expected)


class DetectionCollectTests(unittest.TestCase):
    """The whole detection catalog through collect.main with a fake AWS: wiring of calls, for_each, args and statuses."""

    TYPES = ("ec2_instance", "s3_bucket")

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        (cls.tmp / "checks").mkdir()
        shutil.copy(DETECTION_JSON, cls.tmp / "checks" / "detection.json")
        specs = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))
        (cls.tmp / "inventory.json").write_text(json.dumps({t: specs[t] for t in cls.TYPES}), encoding="utf-8")
        scope = {"platform": "Acme Notes", "mode": "full", "target": None, "regions": [REGION], "profile": None,
                 "resources": [], "domains": None}
        (cls.tmp / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
        cls.runner = RuleRunner(cls.rules())
        out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            cls.code = collect.main(
                ["--scope", str(cls.tmp / "scope.json"), "--out", str(out), "--checks-dir", str(cls.tmp / "checks"),
                 "--inventory", str(cls.tmp / "inventory.json")],
                runner=cls.runner, sleep=lambda s: None, which=lambda name: None)
        cls.result = json.loads((out / "checks-result.json").read_text(encoding="utf-8"))

    @staticmethod
    def rules():
        core = lambda name: ok(load_fixture(f"aws/core/{name}.json"))
        det = lambda name: ok(fx(name))
        not_subscribed = err("An error occurred (InvalidAccessException) when calling the GetEnabledStandards operation: "
                             f"Account {ACCOUNT} is not subscribed to AWS Security Hub")
        instances = {"Reservations": [{"Instances": [{"InstanceId": INSTANCE, "Tags": []}]}]}
        return [
            ("sts", "get-caller-identity", None, "", core("sts-get-caller-identity")),
            ("ec2", "describe-regions", None, "", core("ec2-describe-regions")),
            ("iam", "list-attached-user-policies", None, "", ok({"AttachedPolicies": []})),
            ("ec2", "describe-instances", None, "", ok(instances)),
            ("s3api", "list-buckets", None, "", core("s3api-list-buckets")),
            ("guardduty", "list-detectors", REGION, "", det("guardduty-list-detectors-one")),
            ("guardduty", "list-detectors", OTHER, "", det("guardduty-list-detectors-none")),
            ("guardduty", "get-detector", REGION, DETECTOR_ID, det("guardduty-get-detector-s3-off")),
            ("events", "list-rules", REGION, "", det("events-list-rules-guardduty")),
            ("events", "list-targets-by-rule", REGION, RULE, det("events-list-targets-empty")),
            ("events", "list-targets-by-rule", REGION, "acme-notes-nightly-report", det("events-list-targets-sns")),
            ("securityhub", "get-enabled-standards", REGION, "", not_subscribed),
            ("configservice", "describe-configuration-recorders", REGION, "", det("configservice-describe-configuration-recorders-ok")),
            ("configservice", "describe-configuration-recorder-status", REGION, "", det("configservice-describe-configuration-recorder-status-recording")),
            ("configservice", "describe-delivery-channels", REGION, "", det("configservice-describe-delivery-channels-ok")),
            ("configservice", "describe-configuration-recorders", OTHER, "", det("configservice-describe-configuration-recorders-none")),
            ("configservice", "describe-configuration-recorder-status", OTHER, "", det("configservice-describe-configuration-recorder-status-none")),
            ("configservice", "describe-delivery-channels", OTHER, "", det("configservice-describe-delivery-channels-none")),
            ("inspector2", "batch-get-account-status", REGION, "", det("inspector2-batch-get-account-status-ec2-only")),
            ("inspector2", "list-findings", REGION, "--query", det("inspector2-list-findings-offenders")),
        ]

    def rows(self, check_id):
        return [(r["status"], r["resource_id"], r["region"]) for r in self.result["results"] if r["check_id"] == check_id]

    def row_details(self, check_id):
        return [r["detail"] for r in self.result["results"] if r["check_id"] == check_id]

    def test_run_succeeds_and_nothing_is_unverified(self):
        self.assertEqual(self.code, 0)
        unverified = [(r["check_id"], r["detail"]) for r in self.result["results"] if r["status"] == "NO_VERIFICADO"]
        self.assertEqual(unverified, [])

    def test_guardduty_runs_in_every_enabled_region_and_an_empty_one_is_low(self):
        self.assertEqual(self.rows("DET-001"), [("FAIL", "account", OTHER)])
        self.assertEqual(self.row_details("DET-001")[0]["severity_override"], "low")

    def test_guardduty_s3_protection_and_events(self):
        self.assertEqual(self.rows("DET-002"), [("FAIL", "account", REGION)])
        self.assertEqual(self.rows("DET-003"), [("FAIL", "account", REGION)])

    def test_services_that_are_not_enabled_fail(self):
        self.assertEqual(self.rows("DET-004"), [("FAIL", "account", REGION)])
        self.assertEqual(self.row_details("DET-004")[0]["reason"], "servicio no habilitado")

    def test_config_inspector_and_findings(self):
        self.assertEqual(self.rows("DET-005"), [("FAIL", "account", OTHER)])
        self.assertEqual(self.rows("DET-006"), [("FAIL", "account", REGION)])
        self.assertEqual(self.rows("DET-007"), [("FAIL", "acme-notes-api/sha256:0a1b2c3d", REGION), ("FAIL", INSTANCE, REGION)])

    def test_only_read_only_calls_were_made(self):
        for argv in self.runner.calls:
            aws_runner.assert_read_only(argv[1], argv[2], [])

    def test_rule_targets_are_listed_per_rule_name(self):
        rules = [a[a.index("--rule") + 1] for a in self.runner.calls if a[2] == "list-targets-by-rule"]
        self.assertEqual(sorted(rules), ["acme-notes-guardduty-findings", "acme-notes-nightly-report"])


if __name__ == "__main__":
    unittest.main()
