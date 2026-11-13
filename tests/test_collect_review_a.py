"""Review 2, area A: no vacuous PASS (bad regions, failed describe-regions, failed inventory), cancellation, CMP-006 evidence."""
import json
import unittest

from helpers import SKILL_DIR, FakeRunner, load_fixture

import collect
from test_collect import ENGINE_DIR, ROOT_OFFENDER, SCP_DENIED, CollectCase, base_responses, err, ok

REGIONS_DENIED = "An error occurred (UnauthorizedOperation) when calling the DescribeRegions operation: not authorized to perform: ec2:DescribeRegions"
INSTANCES_DENIED = "An error occurred (UnauthorizedOperation) when calling the DescribeInstances operation: not authorized to perform: ec2:DescribeInstances"
ONE_INSTANCE = {"Reservations": [{"Instances": [{"InstanceId": "i-0acme00000000001", "State": {"Name": "running"}}]}]}


class ReviewCase(CollectCase):
    def run_collect(self, *args, **kwargs):
        try:
            return super().run_collect(*args, **kwargs)
        except FileNotFoundError:  # exit 2 before anything was written
            self.result = None
            return None


class ScopeRegionsValidationTests(ReviewCase):
    def assert_rejected(self, regions, needle="regions"):
        self.run_collect(scope=self.scope_file(regions=regions))
        self.assertEqual(self.code, 2, regions)
        self.assertIn(needle, self.stdout)
        self.assertEqual(self.runner.calls, [], "nothing may reach AWS with an invalid scope")

    def test_a_bare_string_is_an_error_not_a_list_of_characters(self):
        self.assert_rejected("us-east-1")
        self.assertIn("lista", self.stdout)

    def test_an_empty_list_is_an_error(self):
        self.assert_rejected([])

    def test_names_that_are_not_regions_are_an_error(self):
        for bad in (["Us-East-1"], ["us east 1"], [1], [None], ["--profile"], [""], ["us-east-1", "../x"], {"us-east-1": 1}, 5):
            with self.subTest(regions=bad):
                self.assert_rejected(bad)

    def test_auto_and_a_missing_key_are_still_accepted(self):
        responses = base_responses()
        responses[("ec2", "describe-instances", "eu-west-1")] = ok({"Reservations": []})
        self.run_collect(responses, scope=self.scope_file(regions="auto"))
        self.assertEqual(self.code, 0)
        scope = {k: v for k, v in load_fixture("scope-full.json").items() if k != "regions"}
        path = self.tmp / "no-regions.json"
        path.write_text(json.dumps(scope), encoding="utf-8")
        self.run_collect(responses, scope=path)
        self.assertEqual(self.code, 0)

    def test_when_no_listed_region_is_enabled_the_run_stops_with_a_clear_message(self):
        self.run_collect(scope=self.scope_file(regions=["ap-nowhere-9"]))
        self.assertEqual(self.code, 2)
        self.assertIn("ap-nowhere-9", self.stdout)
        self.assertEqual({c[1] for c in self.runner.calls}, {"sts", "ec2"})
        self.assertEqual(len(self.calls("ec2", "describe-instances")), 0)


class NoVacuousPassWithoutRegionsTests(ReviewCase):
    @staticmethod
    def regional(check):
        check["id"] = "IAM-902"
        check["all_regions"] = False
        check["verify"]["calls"][0]["region"] = "each"

    def test_every_listed_region_blocked_by_an_scp_leaves_regional_checks_unverified_not_passed(self):
        responses = base_responses()
        responses[("ec2", "describe-instances", "eu-west-1")] = err(SCP_DENIED.replace("GetAccountSummary", "DescribeInstances"))
        self.run_collect(responses, scope=self.scope_file(regions=["eu-west-1"]), checks_dir=self.catalog_with(self.regional))
        (row,) = self.rows("IAM-902")
        self.assertEqual((row["status"], row["vacuous"]), ("NO_VERIFICADO", False))
        self.assertEqual(row["detail"]["reason"], "sin regiones en el alcance")
        self.assertEqual(self.calls("iam", "get-account-summary"), [])


class DescribeRegionsFailureTests(ReviewCase):
    @staticmethod
    def regional_not_all(check):
        check["id"] = "IAM-902"
        check["all_regions"] = False
        check["verify"]["calls"][0]["region"] = "each"

    def broken(self, message=REGIONS_DENIED):
        responses = base_responses()
        responses[("ec2", "describe-regions", "us-east-1")] = err(message)
        return responses

    def test_all_regions_checks_are_unverified_with_the_reason_and_never_evaluate_us_east_1_alone(self):
        self.run_collect(self.broken())
        (row,) = self.rows("DET-901")
        self.assertEqual(row["status"], "NO_VERIFICADO")
        self.assertEqual(row["detail"]["reason"], "no se pudieron listar las regiones")
        self.assertEqual(self.calls("securityhub", "describe-hub"), [])
        self.assertTrue(any("regiones" in w for w in self.result["warnings"]))

    def test_the_missing_permission_is_named_when_the_listing_was_denied(self):
        self.run_collect(self.broken())
        self.assertEqual(self.rows("DET-901")[0]["missing"], ["ec2:DescribeRegions"])

    def test_another_error_asks_for_no_permission(self):
        self.run_collect(self.broken("An error occurred (ServiceFailure) boom"))
        row = self.rows("DET-901")[0]
        self.assertEqual((row["status"], row["missing"]), ("NO_VERIFICADO", []))

    def test_checks_that_do_not_need_the_region_list_still_run(self):
        self.run_collect(self.broken())
        self.assertEqual([(r["status"], r["resource_id"]) for r in self.rows("IAM-901")], [("FAIL", "root")])
        self.assertEqual([r["status"] for r in self.rows("LOG-901")], ["PASS"])

    def test_regional_checks_scoped_to_explicit_regions_may_still_run(self):
        responses = self.broken()
        responses[("iam", "get-account-summary", "us-east-1")] = ok(ROOT_OFFENDER)
        self.run_collect(responses, scope=self.scope_file(regions=["us-east-1"]), checks_dir=self.catalog_with(self.regional_not_all))
        self.assertEqual([(r["status"], r["region"]) for r in self.rows("IAM-902")], [("FAIL", "us-east-1")])

    def test_auto_regions_with_an_unknown_region_list_cannot_certify_regional_resource_checks(self):
        def ec2_resource_check(check):
            check["id"] = "CMP-901"
            check["scope"], check["resource_types"] = "resource", ["ec2_instance"]
            check["verify"]["calls"] = [{"name": "instances", "service": "ec2", "operation": "describe-instances", "args": [], "region": "each"}]
            check["verify"]["evaluator"] = "python:always_empty"
            check["verify"].pop("offenders")

        responses = self.broken()
        responses[("ec2", "describe-instances", "us-east-1")] = ok(ONE_INSTANCE)
        self.run_collect(responses, scope=self.scope_file(regions="auto"), checks_dir=self.catalog_with(ec2_resource_check))
        statuses = {(r["status"], r["resource_id"], r["region"]) for r in self.rows("CMP-901")}
        self.assertIn(("PASS", "i-0acme00000000001", "us-east-1"), statuses)
        gap = [r for r in self.rows("CMP-901") if r["status"] == "NO_VERIFICADO"]
        self.assertEqual(len(gap), 1)
        self.assertEqual(gap[0]["missing"], ["ec2:DescribeRegions"])
        self.assertEqual(gap[0]["detail"]["reason"], "no se pudieron listar las regiones")


class PartialInventoryTests(ReviewCase):
    @staticmethod
    def volumes_per_instance(check):
        check["id"] = "ENC-901"
        check["scope"], check["resource_types"] = "resource", ["ec2_instance"]
        check["verify"]["calls"] = [{"name": "volumes", "service": "ec2", "operation": "describe-volumes", "args": [],
                                     "region": "each", "for_each": {"from": "__inventory__", "path": "id", "arg": "--instance-id"}}]
        check["verify"]["evaluator"] = "python:always_empty"
        check["verify"].pop("offenders")

    def responses(self, us, eu):
        responses = base_responses()
        responses[("ec2", "describe-instances", "us-east-1")] = us
        responses[("ec2", "describe-instances", "eu-west-1")] = eu
        responses[("ec2", "describe-volumes", "us-east-1")] = ok({"Volumes": []})
        return responses

    def run_two_regions(self, us, eu, **scope):
        scope_file = self.scope_file(regions=["us-east-1", "eu-west-1"], **scope)
        return self.run_collect(self.responses(us, eu), scope=scope_file, checks_dir=self.catalog_with(self.volumes_per_instance))

    def test_a_region_whose_listing_failed_gets_its_own_unverified_row_next_to_the_other_regions_pass(self):
        self.run_two_regions(ok(ONE_INSTANCE), err(INSTANCES_DENIED))
        rows = [(r["status"], r["resource_id"], r["region"]) for r in self.rows("ENC-901")]
        self.assertEqual(rows, [("NO_VERIFICADO", "account", "eu-west-1"), ("PASS", "i-0acme00000000001", "us-east-1")])
        gap = self.rows("ENC-901")[0]
        self.assertEqual(gap["missing"], ["inventory:ec2_instance"])
        self.assertEqual((gap["detail"]["reason"], gap["detail"]["type"], gap["detail"]["error_kind"]),
                         ("inventario incompleto", "ec2_instance", "ACCESS_DENIED"))

    def test_a_failed_listing_is_never_a_vacuous_not_applicable(self):
        self.run_two_regions(ok({"Reservations": []}), err(INSTANCES_DENIED))
        self.assertEqual([(r["status"], r["region"], r["vacuous"]) for r in self.rows("ENC-901")], [("NO_VERIFICADO", "eu-west-1", False)])

    def test_when_every_listing_succeeds_nothing_changes(self):
        self.run_two_regions(ok(ONE_INSTANCE), ok({"Reservations": []}))
        self.assertEqual([r["status"] for r in self.rows("ENC-901")], ["PASS"])

    def test_resource_scope_only_reports_the_regions_of_the_scoped_resources(self):
        scope = self.scope_file(regions=["us-east-1", "eu-west-1"], mode="resource", target="i-0acme00000000001", resources=[
            {"type": "ec2_instance", "id": "i-0acme00000000001", "region": "us-east-1"}])
        self.run_collect(self.responses(ok(ONE_INSTANCE), err(INSTANCES_DENIED)), scope=scope,
                         checks_dir=self.catalog_with(self.volumes_per_instance))
        self.assertEqual([(r["status"], r["region"]) for r in self.rows("ENC-901")], [("PASS", "us-east-1")])

    def test_the_inventory_warning_is_still_reported(self):
        self.run_two_regions(ok(ONE_INSTANCE), err(INSTANCES_DENIED))
        self.assertTrue(any("ec2_instance" in w and "eu-west-1" in w for w in self.result["warnings"]))

    def test_checks_declaring_the_type_in_params_still_collapse_to_one_row(self):
        def depends(check):
            check["id"] = "DET-905"
            check["verify"]["evaluator"] = "python:always_empty"
            check["verify"].pop("offenders")
            check["verify"]["params"] = {"inventory_types": ["ec2_instance"]}

        self.run_collect(self.responses(ok(ONE_INSTANCE), err(INSTANCES_DENIED)), checks_dir=self.catalog_with(depends),
                         scope=self.scope_file(regions=["us-east-1", "eu-west-1"]))
        (row,) = self.rows("DET-905")
        self.assertEqual((row["status"], row["missing"]), ("NO_VERIFICADO", ["inventory:ec2_instance"]))


class ReviewedAllowlistAtRunTimeTests(ReviewCase):
    def test_a_catalog_call_that_was_never_reviewed_is_not_executed(self):
        def unreviewed(check):
            check["id"] = "IAM-905"
            check["verify"]["calls"][0].update(service="ec2", operation="describe-key-pairs", region="global")
            check["verify"]["evaluator"] = "python:always_empty"
            check["verify"].pop("offenders")

        self.run_collect(checks_dir=self.catalog_with(unreviewed))
        self.assertEqual(self.calls("ec2", "describe-key-pairs"), [])
        (row,) = self.rows("IAM-905")
        self.assertEqual(row["status"], "NO_VERIFICADO")


class CancellationTests(ReviewCase):
    def make_ctx(self, responses):
        runner = FakeRunner(responses)
        ctx = collect.Ctx(runner=runner, sleep=lambda s: None, which=lambda n: None, out=self.tmp,
                          allowed=frozenset({("iam", "get-account-summary")}))
        return ctx, runner

    def check(self):
        import catalog
        return next(c for c in catalog.load_checks(ENGINE_DIR) if c["id"] == "IAM-901")

    def test_calls_refused_after_a_cancel_leave_no_raw_file_behind(self):
        ctx, runner = self.make_ctx({})
        ctx.cancelled.set()
        collect._run_calls(ctx, self.check(), [])
        self.assertEqual(runner.calls, [])
        self.assertFalse((self.tmp / "raw").exists())

    def test_a_throttled_call_stops_retrying_once_the_run_is_cancelled(self):
        throttled = err("An error occurred (Throttling) when calling: Rate exceeded")
        ctx, runner = self.make_ctx({("iam", "get-account-summary", "us-east-1"): throttled})
        ctx.sleep = lambda seconds: ctx.cancelled.set()
        res = collect._aws(ctx, "iam", "get-account-summary", [], "us-east-1")
        self.assertFalse(res.ok)
        self.assertEqual(len(runner.calls), 2)
        self.assertIn("cancelada", res.error_message)


# ---------------------------------------------------------------- CMP-006 evidence for attached instances

NET_CHECK = "NET-001"
SG_OPEN = {"SecurityGroups": [{"GroupId": "sg-0acme0000000001", "GroupName": "web", "VpcId": "vpc-0acme0000000001", "IpPermissions": [
    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]}
ENIS = {"NetworkInterfaces": [
    {"NetworkInterfaceId": "eni-1", "Status": "in-use", "Groups": [{"GroupId": "sg-0acme0000000001"}], "Description": "primary",
     "Attachment": {"InstanceId": "i-0acme00000000001"}},
    {"NetworkInterfaceId": "eni-2", "Status": "in-use", "Groups": [{"GroupId": "sg-0acme0000000001"}], "Description": "ELB app/x"}]}
TWO_INSTANCES = {"Reservations": [{"Instances": [
    {"InstanceId": "i-0acme00000000001", "State": {"Name": "running"}},
    {"InstanceId": "i-0acme00000000002", "State": {"Name": "running"}}]}]}


class AttachedInstanceEvidenceTests(ReviewCase):
    def catalog_dir(self):
        refs = SKILL_DIR / "references" / "checks"
        wanted = {"NET-001": "network.json", "CMP-006": "compute.json"}
        checks = []
        for check_id, name in wanted.items():
            data = json.loads((refs / name).read_text(encoding="utf-8"))
            checks += [{**c, "domain": data["domain"]} for c in data["checks"] if c["id"] == check_id]
        directory = self.tmp / "evidence-catalog"
        directory.mkdir()
        (directory / "evidence.json").write_text(json.dumps({"domain": "network", "checks": checks}), encoding="utf-8")
        return directory

    def inventory_file(self):
        specs = json.loads((SKILL_DIR / "references" / "inventory.json").read_text(encoding="utf-8"))
        path = self.tmp / "inventory-sg.json"
        path.write_text(json.dumps({k: specs[k] for k in ("security_group", "ec2_instance")}), encoding="utf-8")
        return path

    def responses(self, instances=TWO_INSTANCES):
        responses = base_responses()
        for key in [k for k in responses if k[0] not in ("sts",) and k[:2] != ("ec2", "describe-regions")]:
            del responses[key]
        responses[("ec2", "describe-security-groups", "us-east-1")] = ok(SG_OPEN)
        responses[("ec2", "describe-network-interfaces", "us-east-1")] = ok(ENIS)
        responses[("ec2", "describe-instances", "us-east-1")] = ok(instances)
        responses[("ssm", "describe-instance-information", "us-east-1")] = ok({"InstanceInformationList": []})
        responses[("iam", "list-attached-user-policies", "us-east-1")] = ok({"AttachedPolicies": []})
        return responses

    def run_scope(self, scope_file, instances=TWO_INSTANCES):
        return self.run_collect(self.responses(instances), scope=scope_file, checks_dir=self.catalog_dir(), inventory=self.inventory_file())

    def sg_scope(self, **extra):
        resources = [{"type": "security_group", "id": "sg-0acme0000000001", "region": "us-east-1"}, *extra.pop("more", [])]
        return self.scope_file(mode="resource", target="sg-0acme0000000001", resources=resources, **extra)

    def test_resource_scope_evaluates_cmp_006_for_the_instances_attached_to_a_failing_group(self):
        self.run_scope(self.sg_scope())
        self.assertEqual([(r["status"], r["resource_id"]) for r in self.rows(NET_CHECK)], [("FAIL", "sg-0acme0000000001")])
        rows = self.rows("CMP-006")
        self.assertEqual([(r["status"], r["resource_id"], r["region"]) for r in rows], [("FAIL", "i-0acme00000000001", "us-east-1")])
        self.assertIs(rows[0]["detail"]["ssm_unreachable"], True)
        self.assertEqual(rows[0]["detail"]["context_for"], [NET_CHECK])

    def test_instances_that_do_not_use_the_group_are_not_evaluated(self):
        self.run_scope(self.sg_scope())
        self.assertNotIn("i-0acme00000000002", {r["resource_id"] for r in self.result["results"]})

    def test_a_cmp_006_already_in_scope_keeps_its_rows_and_gains_the_attached_instances(self):
        more = [{"type": "ec2_instance", "id": "i-0acme00000000002", "region": "us-east-1"}]
        self.run_scope(self.sg_scope(more=more))
        rows = {r["resource_id"]: r for r in self.rows("CMP-006")}
        self.assertEqual(sorted(rows), ["i-0acme00000000001", "i-0acme00000000002"])
        self.assertEqual(rows["i-0acme00000000001"]["detail"].get("context_for"), [NET_CHECK])
        self.assertNotIn("context_for", rows["i-0acme00000000002"]["detail"])

    def test_full_mode_runs_cmp_006_normally_without_a_context_marker(self):
        self.run_scope(self.scope_file(regions=["us-east-1"]))
        self.assertEqual(len(self.rows("CMP-006")), 2)
        for row in self.rows("CMP-006"):
            self.assertNotIn("context_for", row["detail"])

    def test_an_attached_instance_missing_from_the_inventory_is_reported(self):
        self.run_scope(self.sg_scope(), instances={"Reservations": []})
        self.assertEqual([(r["status"], r["vacuous"]) for r in self.rows("CMP-006")], [])
        self.assertTrue(any("i-0acme00000000001" in w for w in self.result["warnings"]))

    def test_no_failing_group_means_no_extra_check(self):
        responses = self.responses()
        responses[("ec2", "describe-security-groups", "us-east-1")] = ok({"SecurityGroups": []})
        self.run_collect(responses, scope=self.sg_scope(), checks_dir=self.catalog_dir(), inventory=self.inventory_file())
        self.assertEqual(self.rows("CMP-006"), [])
        self.assertEqual(self.calls("ssm", "describe-instance-information"), [])


if __name__ == "__main__":
    unittest.main()
