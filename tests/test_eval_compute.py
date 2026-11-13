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

COMPUTE_JSON = SKILL_DIR / "references" / "checks" / "compute.json"
REFS = SKILL_DIR / "references"
REGION = "us-east-1"
OTHER = "eu-west-1"
I1, I2, I3 = "i-0a1b2c3d4e5f60718", "i-0b2c3d4e5f6071829", "i-0c3d4e5f60718293a"
LT_WEB, LT_WORK, LT_BATCH = "lt-0a1b2c3d4e5f60718", "lt-0b2c3d4e5f6071829", "lt-0c3d4e5f60718293a"
NOT_FOUND = "InvalidLaunchTemplateId.NotFound"


def fx(name):
    return load_fixture(f"aws/compute/{name}.json")


def evaluate(name, responses, params=None):
    return evaluators.EVALUATORS[name](responses, params or {})


def catalog_check(check_id):
    data = json.loads(COMPUTE_JSON.read_text(encoding="utf-8"))
    return next(c for c in data["checks"] if c["id"] == check_id)


def instance(id_, region=REGION):
    return {"type": "ec2_instance", "id": id_, "arn": "", "name": "", "region": region, "tags": []}


def ids(offenders):
    return [o["resource_id"] for o in offenders]


class JmespathChecksTests(unittest.TestCase):
    def search(self, check_id, document):
        return jmespath.search(catalog_check(check_id)["verify"]["offenders"], document)

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_cmp_001_reports_instances_that_do_not_require_imdsv2(self):
        raw = fx("ec2-describe-instances-raw")
        self.assertEqual(self.search("CMP-001", raw), fx("ec2-describe-instances-imds-offenders"))
        self.assertEqual(self.search("CMP-001", {"Reservations": []}), [])

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_cmp_001_required_is_the_only_value_that_passes(self):
        for tokens, expected in (("required", []), ("optional", ["i-1"]), (None, ["i-1"])):
            document = {"Reservations": [{"Instances": [{"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": tokens}}]}]}
            self.assertEqual([o["resource_id"] for o in self.search("CMP-001", document)], expected, tokens)

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_cmp_003_reports_instances_without_an_instance_profile(self):
        raw = fx("ec2-describe-instances-raw")
        self.assertEqual(self.search("CMP-003", raw), fx("ec2-describe-instances-profile-offenders"))
        self.assertEqual(self.search("CMP-003", {"Reservations": []}), [])

    def test_instance_checks_list_only_active_instances(self):
        for check_id in ("CMP-001", "CMP-003"):
            (call,) = catalog_check(check_id)["verify"]["calls"]
            self.assertEqual(call["args"], ["--filters", "Name=instance-state-name,Values=pending,running,stopping,stopped"])


class LaunchTemplateImdsTests(unittest.TestCase):
    def responses(self, *, web="web-latest-required", workers="workers", batch="batch-default-required", names=None):
        groups = fx("autoscaling-describe-auto-scaling-groups-lt")
        if names:
            groups = {"AutoScalingGroups": [g for g in groups["AutoScalingGroups"] if g["AutoScalingGroupName"] in names]}
        plain = [(LT_WEB, web), (LT_BATCH, batch)]
        plain = [(lt, name) for lt, name in plain if lt in str(groups.get("AutoScalingGroups"))]
        mixed = [(LT_WORK, workers)] if "acme-notes-workers" in str(groups) else []
        pair = lambda rows: [(REGION, fx(f"ec2-describe-launch-template-versions-{n}")) for _, n in rows]
        return {"asgs": [(REGION, groups)],
                "versions": pair(plain), "mixed_versions": pair(mixed),
                "__for_each__": {"versions": [lt for lt, _ in plain], "mixed_versions": [lt for lt, _ in mixed]}}

    def test_lt_imdsv2_pass(self):
        responses = self.responses(names={"acme-notes-web", "acme-notes-batch"})
        self.assertEqual(evaluate("lt_imdsv2", responses), [])

    def test_lt_imdsv2_fail_reports_offenders(self):
        responses = self.responses(web="web-latest-optional")
        offenders = evaluate("lt_imdsv2", responses)
        self.assertEqual(ids(offenders), ["acme-notes-web", "acme-notes-workers"])
        self.assertEqual({o["region"] for o in offenders}, {REGION})

    def test_latest_resolves_to_the_highest_version_not_to_the_default(self):
        (offender,) = evaluate("lt_imdsv2", self.responses(web="web-latest-optional", names={"acme-notes-web"}))
        self.assertEqual((offender["detail"]["version_spec"], offender["detail"]["version"], offender["detail"]["http_tokens"]),
                         ("$Latest", 2, "optional"))

    def test_default_resolves_to_the_default_version_not_to_the_latest(self):
        responses = self.responses(batch="batch-default-required", names={"acme-notes-batch"})
        self.assertEqual(evaluate("lt_imdsv2", responses), [])

    def test_numbered_version_is_the_one_that_counts(self):
        # workers uses version 2 (optional) while the latest, version 3, is already required
        (offender,) = evaluate("lt_imdsv2", self.responses(names={"acme-notes-workers"}))
        self.assertEqual((offender["resource_id"], offender["detail"]["version"], offender["detail"]["http_tokens"]),
                         ("acme-notes-workers", 2, "optional"))

    def test_template_without_metadata_options_does_not_require_imdsv2(self):
        responses = self.responses(batch="batch-no-metadata", names={"acme-notes-batch"})
        (offender,) = evaluate("lt_imdsv2", responses)
        self.assertEqual((offender["resource_id"], offender["detail"]["http_tokens"]), ("acme-notes-batch", None))

    def test_launch_configuration_is_reported(self):
        responses = {"asgs": [(REGION, fx("autoscaling-describe-auto-scaling-groups-legacy"))], "versions": [],
                     "mixed_versions": [], "__for_each__": {"versions": [], "mixed_versions": []}}
        (offender,) = evaluate("lt_imdsv2", responses)
        self.assertEqual(offender["resource_id"], "acme-notes-legacy")
        self.assertEqual(offender["detail"]["launch_configuration"], "acme-notes-legacy-lc-2024")

    def test_missing_launch_template_is_reported(self):
        responses = self.responses(names={"acme-notes-web"})
        responses["versions"] = [(REGION, {"__error__": NOT_FOUND})]
        (offender,) = evaluate("lt_imdsv2", responses)
        self.assertEqual(offender["detail"]["reason"], "launch template does not exist or is not accessible")

    def test_no_groups_no_offenders(self):
        responses = {"asgs": [(REGION, fx("autoscaling-describe-auto-scaling-groups-empty"))], "versions": [],
                     "mixed_versions": [], "__for_each__": {"versions": [], "mixed_versions": []}}
        self.assertEqual(evaluate("lt_imdsv2", responses), [])


class LoadBalancerAzTests(unittest.TestCase):
    def responses(self, alb="multi-az", clb="none", region=REGION, *items):
        return {"alb": [(region, fx(f"elbv2-describe-load-balancers-{alb}"))],
                "clb": [(region, fx(f"elb-describe-load-balancers-{clb}"))],
                "__inventory__": list(items) or [instance(I1), instance(I2)]}

    def test_lb_multi_az_pass(self):
        self.assertEqual(evaluate("lb_multi_az", self.responses()), [])

    def test_lb_multi_az_pass_with_a_classic_balancer(self):
        self.assertEqual(evaluate("lb_multi_az", self.responses(alb="none", clb="multi-az")), [])

    def test_lb_multi_az_fail_reports_offenders(self):
        offenders = evaluate("lb_multi_az", self.responses(alb="single-az", clb="single-az"))
        self.assertEqual(ids(offenders), [I1, I2])
        self.assertEqual(offenders[0]["detail"]["load_balancers"], [{"name": "acme-notes-alb", "zones": 1},
                                                                    {"name": "acme-notes-classic", "zones": 1}])

    def test_region_without_any_balancer_fails(self):
        (offender, _) = evaluate("lb_multi_az", self.responses(alb="none", clb="none"))
        self.assertEqual(offender["detail"]["reason"], "the region has no load balancer spanning 2 or more availability zones")

    def test_one_multi_az_balancer_is_enough_even_next_to_a_single_az_one(self):
        self.assertEqual(evaluate("lb_multi_az", self.responses(alb="multi-az", clb="single-az")), [])

    def test_only_instances_of_regions_without_a_multi_az_balancer_fail(self):
        responses = self.responses("multi-az", "none", REGION, instance(I1), instance(I2, OTHER))
        responses["alb"].append((OTHER, fx("elbv2-describe-load-balancers-single-az")))
        responses["clb"].append((OTHER, fx("elb-describe-load-balancers-none")))
        offenders = evaluate("lb_multi_az", responses)
        self.assertEqual([(o["resource_id"], o["region"]) for o in offenders], [(I2, OTHER)])

    def test_region_without_answers_fails_instead_of_passing(self):
        responses = self.responses("multi-az", "none", REGION, instance(I2, OTHER))
        self.assertEqual(ids(evaluate("lb_multi_az", responses)), [I2])

    def test_no_instances_no_offenders(self):
        responses = self.responses("none", "none", REGION, {"type": "vpc", "id": "vpc-1", "arn": "", "name": "", "region": REGION, "tags": []})
        self.assertEqual(evaluate("lb_multi_az", responses), [])


class AsgPresentTests(unittest.TestCase):
    def responses(self, fixture, *items, region=REGION):
        return {"asgs": [(region, fx(f"autoscaling-describe-auto-scaling-groups-{fixture}"))],
                "__inventory__": list(items) or [instance(I1), instance(I2)]}

    def test_asg_present_pass(self):
        self.assertEqual(evaluate("asg_present", self.responses("lt")), [])

    def test_asg_present_fail_reports_offenders(self):
        offenders = evaluate("asg_present", self.responses("empty"))
        self.assertEqual([(o["resource_id"], o["region"]) for o in offenders], [(I1, REGION), (I2, REGION)])
        self.assertEqual(offenders[0]["detail"]["reason"], "the region has EC2 instances and no Auto Scaling group")

    def test_only_regions_with_instances_need_a_group(self):
        responses = self.responses("lt", instance(I1), instance(I3, OTHER))
        responses["asgs"].append((OTHER, fx("autoscaling-describe-auto-scaling-groups-empty")))
        self.assertEqual(ids(evaluate("asg_present", responses)), [I3])

    def test_region_without_answers_fails_instead_of_passing(self):
        self.assertEqual(ids(evaluate("asg_present", self.responses("lt", instance(I3, OTHER)))), [I3])

    def test_no_instances_no_offenders(self):
        self.assertEqual(evaluate("asg_present", {"asgs": [(REGION, fx("autoscaling-describe-auto-scaling-groups-empty"))],
                                                  "__inventory__": []}), [])


class SsmManagedTests(unittest.TestCase):
    @staticmethod
    def patch_states(instance_id, fixture):
        """The patch-states fixture answered for `instance_id` (the fixture itself names the first instance)."""
        states = fx(f"ssm-describe-instance-patch-states-{fixture}")["InstancePatchStates"]
        return {"InstancePatchStates": [{**state, "InstanceId": instance_id} for state in states]}

    def responses(self, info, patched, *items):
        """patched: {instance id: patch states fixture}; one describe-instance-patch-states call per managed instance."""
        listing = fx(f"ssm-describe-instance-information-{info}")
        managed = [i["InstanceId"] for i in listing["InstanceInformationList"]]
        return {"instances": [(REGION, self.instances(*(items or [instance(I1)])))],
                "info": [(REGION, listing)],
                "patches": [(REGION, self.patch_states(i, patched.get(i, "none"))) for i in managed],
                "__for_each__": {"patches": managed},
                "__inventory__": list(items) or [instance(I1)]}

    @staticmethod
    def instances(*items, state="running", **states):
        """describe-instances answer for the inventory items; states: {instance id: state name}."""
        return {"Reservations": [{"Instances": [{"InstanceId": i["id"], "State": {"Name": states.get(i["id"], state)}}]}
                                 for i in items]}

    def test_ssm_managed_pass(self):
        self.assertEqual(evaluate("ssm_managed", self.responses("online", {I1: "patched"})), [])

    def test_ssm_managed_fail_reports_offenders(self):
        responses = self.responses("online", {I1: "patched"}, instance(I1), instance(I2), instance(I3))
        offenders = evaluate("ssm_managed", responses)
        self.assertEqual(ids(offenders), [I2, I3])
        self.assertEqual(offenders[0]["detail"]["problems"], ["no patch association (Patch Manager)"])
        self.assertEqual(offenders[1]["detail"]["problems"], ["not registered in Systems Manager"])

    def test_ssm_unreachable_flag_ignores_patch_only_problems(self):
        responses = self.responses("online", {I1: "patched"}, instance(I1), instance(I2), instance(I3))
        offenders = evaluate("ssm_managed", responses)
        self.assertEqual([(o["resource_id"], o["detail"]["ssm_unreachable"]) for o in offenders], [(I2, False), (I3, True)])
        lost = evaluate("ssm_managed", self.responses("lost", {I2: "patched"}, instance(I2)))
        self.assertTrue(lost[0]["detail"]["ssm_unreachable"])

    def test_agent_that_lost_connection_is_reported(self):
        responses = self.responses("lost", {I1: "patched", I2: "patched"}, instance(I2))
        (offender,) = evaluate("ssm_managed", responses)
        self.assertEqual(offender["detail"]["problems"], ["the SSM agent is not online (ConnectionLost)"])

    def test_every_problem_is_listed(self):
        responses = self.responses("lost", {}, instance(I2))
        (offender,) = evaluate("ssm_managed", responses)
        self.assertEqual(len(offender["detail"]["problems"]), 2)

    def test_patch_state_belongs_to_its_own_instance(self):
        responses = self.responses("online", {I2: "patched"}, instance(I1), instance(I2))
        self.assertEqual(ids(evaluate("ssm_managed", responses)), [I1])

    def test_instances_of_other_regions_are_not_matched_by_id_alone(self):
        responses = self.responses("online", {I1: "patched"}, instance(I1, OTHER))
        self.assertEqual(ids(evaluate("ssm_managed", responses)), [I1])

    def test_instances_that_are_not_running_are_not_applicable(self):
        responses = self.responses("online", {I1: "patched"}, instance(I1), instance(I3))
        responses["instances"] = [(REGION, self.instances(instance(I1), instance(I3), **{I3: "stopped"}))]
        offenders = evaluate("ssm_managed", responses)
        self.assertEqual([(o["resource_id"], o.get("not_applicable")) for o in offenders], [(I3, True)])

    def test_a_stopped_instance_is_not_reported_even_when_ssm_has_a_stale_record(self):
        responses = self.responses("lost", {I1: "patched"}, instance(I2))
        responses["instances"] = [(REGION, self.instances(instance(I2), state="stopped"))]
        (entry,) = evaluate("ssm_managed", responses)
        self.assertTrue(entry["not_applicable"])
        self.assertNotIn("problems", entry["detail"])

    def test_no_instances_no_offenders(self):
        self.assertEqual(evaluate("ssm_managed", {"instances": [], "info": [(REGION, fx("ssm-describe-instance-information-none"))],
                                                  "patches": [], "__for_each__": {"patches": []}, "__inventory__": []}), [])


class ComputeCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks = json.loads(COMPUTE_JSON.read_text(encoding="utf-8"))["checks"]

    def test_compute_catalog_valid(self):
        data = json.loads(COMPUTE_JSON.read_text(encoding="utf-8"))
        for check in data["checks"]:
            check.setdefault("domain", data["domain"])
        tsc_ids, iso_ids = catalog.load_frameworks(REFS / "frameworks")
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        self.assertEqual(catalog.validate(data["checks"], tsc_ids, iso_ids, drata), [])
        self.assertEqual([c["id"] for c in data["checks"]], [f"CMP-{n:03d}" for n in range(1, 7)])

    def test_every_python_evaluator_is_registered(self):
        for check in self.checks:
            kind, _, name = check["verify"]["evaluator"].partition(":")
            if kind == "python":
                self.assertIn(name, evaluators.EVALUATORS, check["id"])

    def test_evaluator_kinds_follow_the_brief(self):
        expected = {"CMP-001": "jmespath", "CMP-002": "python:lt_imdsv2", "CMP-003": "jmespath",
                    "CMP-004": "python:lb_multi_az", "CMP-005": "python:asg_present", "CMP-006": "python:ssm_managed"}
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

    def test_cmp_001_requires_tokens_and_warns_about_apps_that_still_use_imdsv1(self):
        rem = catalog_check("CMP-001")["remediation"]
        (command,) = rem["commands"]
        self.assertIn('aws ec2 modify-instance-metadata-options --instance-id "{resource_id}" --http-tokens required', command)
        self.assertRegex(rem["notes"], r"MetadataNoToken")

    def test_cmp_002_new_version_becomes_the_default_only_after_it_was_created(self):
        first = catalog_check("CMP-002")["remediation"]["commands"][0]
        self.assertRegex(first, r"create-launch-template-version [^\n]*HttpTokens[^\n]*required[^\n]*&& aws ec2 modify-launch-template ")
        self.assertIn("--default-version", first)

    def test_cmp_002_instance_refresh_runs_after_the_default_version_was_verified_and_warns(self):
        rem = catalog_check("CMP-002")["remediation"]
        refresh = rem["commands"][-1]
        self.assertRegex(refresh, r'= "required" \]\s*&&\s*aws autoscaling update-auto-scaling-group [^\n]*&&\s*aws autoscaling start-instance-refresh')
        self.assertRegex(rem["notes"], r"(?i)replaces")

    def test_cmp_003_instance_profile_is_associated_only_after_it_was_created(self):
        commands = catalog_check("CMP-003")["remediation"]["commands"]
        self.assertRegex(commands[0], r"create-role [^\n]*&& aws iam create-instance-profile [^\n]*&& aws iam add-role-to-instance-profile")
        self.assertIn("associate-iam-instance-profile", commands[-1])
        self.assertNotIn("associate-iam-instance-profile", commands[0])

    def test_cmp_004_balancer_resources_are_created_in_dependency_order(self):
        command = "\n".join(catalog_check("CMP-004")["remediation"]["commands"])
        self.assertRegex(command, r"create-load-balancer [^\n]*&&[^\n]*create-target-group [^\n]*&&[^\n]*register-targets [^\n]*&&[^\n]*create-listener")

    def test_cmp_005_template_is_created_only_after_the_image_is_available(self):
        command = "\n".join(catalog_check("CMP-005")["remediation"]["commands"])
        self.assertRegex(command, r"create-image [^\n]*--no-reboot[^\n]*&&[^\n]*wait image-available[^\n]*&&[^\n]*create-launch-template [^\n]*&&[^\n]*create-auto-scaling-group")

    def test_cmp_006_creates_a_patch_scan_association(self):
        command = "\n".join(catalog_check("CMP-006")["remediation"]["commands"])
        self.assertIn("create-association", command)
        self.assertIn("AWS-RunPatchBaseline", command)

    def test_cmp_006_reads_the_instance_state(self):
        calls = {c["name"]: c for c in catalog_check("CMP-006")["verify"]["calls"]}
        self.assertEqual(calls["instances"]["operation"], "describe-instances")
        self.assertIn("ec2:DescribeInstances", catalog_check("CMP-006")["verify"]["needs"])

    def test_planned_changes_warn_in_notes(self):
        for check in self.checks:
            if check["remediation"]["kind"] == "planned_change":
                self.assertGreaterEqual(len(check["remediation"]["steps"]), 2, check["id"])
                self.assertTrue(check["remediation"]["notes"].strip(), check["id"])

    def test_scopes_and_regions(self):
        expected = {"CMP-001": ("resource", False), "CMP-002": ("resource", False), "CMP-003": ("resource", False),
                    "CMP-004": ("resource", False), "CMP-005": ("resource", False), "CMP-006": ("resource", False)}
        self.assertEqual({c["id"]: (c["scope"], c["all_regions"]) for c in self.checks}, expected)
        self.assertEqual(catalog_check("CMP-002")["resource_types"], ["asg"])
        for check_id in ("CMP-001", "CMP-003", "CMP-004", "CMP-005", "CMP-006"):
            self.assertEqual(catalog_check(check_id)["resource_types"], ["ec2_instance"], check_id)

    def test_launch_template_lookups_tolerate_deleted_templates(self):
        for call in catalog_check("CMP-002")["verify"]["calls"]:
            if call["name"] != "asgs":
                self.assertEqual(call["ok_errors"], [NOT_FOUND, "InvalidLaunchTemplateName.NotFoundException"], call["name"])

    def test_drata_mapped_checks_resolve_from_the_dcf_file(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        expected = {"CMP-001": 292, "CMP-002": 292, "CMP-004": 130, "CMP-005": 131}
        for check_id, test in expected.items():
            resolved = catalog.resolve_mappings(catalog_check(check_id), drata)
            self.assertEqual([m["test"] for m in resolved["drata"]], [test], check_id)
            self.assertTrue(resolved["tsc"] and all(t["sourced"] == catalog.DCF_SOURCE for t in resolved["tsc"]), check_id)

    def test_checks_without_a_resolvable_drata_test_carry_inferred_mappings(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        for check_id in ("CMP-003", "CMP-006"):
            resolved = catalog.resolve_mappings(catalog_check(check_id), drata)
            self.assertTrue(resolved["tsc"] and resolved["iso27001_2022"], check_id)
            self.assertTrue(all(m["sourced"] is False for m in resolved["tsc"] + resolved["iso27001_2022"]), check_id)

    def test_severities_follow_the_brief(self):
        expected = {"CMP-001": "high", "CMP-002": "high", "CMP-003": "medium", "CMP-004": "high", "CMP-005": "high",
                    "CMP-006": "medium"}
        self.assertEqual({c["id"]: c["severity"] for c in self.checks}, expected)

    def test_remediation_kinds_follow_the_brief(self):
        expected = {"CMP-001": "cli", "CMP-002": "planned_change", "CMP-003": "cli_with_decision",
                    "CMP-004": "planned_change", "CMP-005": "planned_change", "CMP-006": "planned_change"}
        self.assertEqual({c["id"]: c["remediation"]["kind"] for c in self.checks}, expected)


class ComputeCollectTests(unittest.TestCase):
    """The whole compute catalog through collect.main with a fake AWS: wiring of calls, for_each and args."""

    TYPES = ("ec2_instance", "asg")

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        (cls.tmp / "checks").mkdir()
        shutil.copy(COMPUTE_JSON, cls.tmp / "checks" / "compute.json")
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
                 "--inventory", str(cls.tmp / "inventory.json"), "--quiet"],
                runner=cls.runner, sleep=lambda s: None, which=lambda name: None)
        cls.result = json.loads((out / "checks-result.json").read_text(encoding="utf-8"))

    @staticmethod
    def rules():
        core = lambda name: ok(load_fixture(f"aws/core/{name}.json"))
        cmp = lambda name: ok(fx(name))
        return [
            ("sts", "get-caller-identity", None, "", core("sts-get-caller-identity")),
            ("ec2", "describe-regions", None, "", core("ec2-describe-regions")),
            ("iam", "list-attached-user-policies", None, "", ok({"AttachedPolicies": []})),
            # CMP-001 and CMP-003 use --query expressions; the inventory lists instances without one
            ("ec2", "describe-instances", None, "HttpTokens", cmp("ec2-describe-instances-imds-offenders")),
            ("ec2", "describe-instances", None, "IamInstanceProfile", cmp("ec2-describe-instances-profile-offenders")),
            ("ec2", "describe-instances", None, "", cmp("ec2-describe-instances-raw")),
            ("autoscaling", "describe-auto-scaling-groups", None, "", cmp("autoscaling-describe-auto-scaling-groups-lt")),
            ("ec2", "describe-launch-template-versions", None, LT_WEB, cmp("ec2-describe-launch-template-versions-web-latest-optional")),
            ("ec2", "describe-launch-template-versions", None, LT_WORK, cmp("ec2-describe-launch-template-versions-workers")),
            ("ec2", "describe-launch-template-versions", None, LT_BATCH, cmp("ec2-describe-launch-template-versions-batch-default-required")),
            ("elbv2", "describe-load-balancers", None, "", cmp("elbv2-describe-load-balancers-single-az")),
            ("elb", "describe-load-balancers", None, "", cmp("elb-describe-load-balancers-none")),
            ("ssm", "describe-instance-information", None, "", cmp("ssm-describe-instance-information-lost")),
            ("ssm", "describe-instance-patch-states", None, I1, cmp("ssm-describe-instance-patch-states-patched")),
            ("ssm", "describe-instance-patch-states", None, I2, cmp("ssm-describe-instance-patch-states-none")),
        ]

    def rows(self, check_id):
        return [(r["status"], r["resource_id"], r["region"]) for r in self.result["results"] if r["check_id"] == check_id]

    def test_run_succeeds_and_nothing_is_unverified(self):
        self.assertEqual(self.code, 0)
        unverified = [(r["check_id"], r["detail"]) for r in self.result["results"] if r["status"] == "NOT_VERIFIED"]
        self.assertEqual(unverified, [])

    def test_instance_metadata_and_profile_outcomes(self):
        self.assertEqual(self.rows("CMP-001"), [("PASS", I1, REGION), ("FAIL", I2, REGION), ("FAIL", I3, REGION)])
        self.assertEqual(self.rows("CMP-003"), [("PASS", I1, REGION), ("FAIL", I2, REGION), ("PASS", I3, REGION)])

    def test_launch_template_outcomes_per_asg(self):
        self.assertEqual(self.rows("CMP-002"), [("PASS", "acme-notes-batch", REGION), ("FAIL", "acme-notes-web", REGION),
                                                ("FAIL", "acme-notes-workers", REGION)])

    def test_region_level_checks_report_every_instance_of_the_region(self):
        self.assertEqual(self.rows("CMP-004"), [("FAIL", I1, REGION), ("FAIL", I2, REGION), ("FAIL", I3, REGION)])
        self.assertEqual(self.rows("CMP-005"), [("PASS", I1, REGION), ("PASS", I2, REGION), ("PASS", I3, REGION)])

    def test_ssm_outcomes(self):
        self.assertEqual(self.rows("CMP-006"), [("PASS", I1, REGION), ("FAIL", I2, REGION), ("FAIL", I3, REGION)])

    def test_patch_states_are_requested_only_for_managed_instances(self):
        asked = [a[a.index("--instance-ids") + 1] for a in self.runner.calls if a[2] == "describe-instance-patch-states"]
        self.assertEqual(sorted(asked), [I1, I2])

    def test_launch_template_versions_are_requested_once_per_template(self):
        asked = [a[a.index("--launch-template-id") + 1] for a in self.runner.calls if a[2] == "describe-launch-template-versions"]
        self.assertEqual(sorted(asked), sorted([LT_WEB, LT_WORK, LT_BATCH]))

    def test_only_read_only_calls_were_made(self):
        for argv in self.runner.calls:
            aws_runner.assert_read_only(argv[1], argv[2], [])


if __name__ == "__main__":
    unittest.main()
