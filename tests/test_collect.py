import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import helpers
from helpers import FIXTURES_DIR, SKILL_DIR, FakeRunner, load_fixture

import aws_runner
import collect
import evaluators

ENGINE_DIR = FIXTURES_DIR / "catalog-engine"
INVENTORY_MIN = FIXTURES_DIR / "inventory-min.json"
NOT_ENABLED = "An error occurred (InvalidAccessException) when calling the DescribeHub operation: Account 111122223333 is not subscribed to AWS Security Hub"
ACCESS_DENIED = "An error occurred (AccessDenied) when calling the GetAccountSummary operation: not authorized to perform: iam:GetAccountSummary"
NO_CREDS = "Unable to locate credentials. You can configure credentials by running aws configure."


def ok(data):
    return {"stdout": json.dumps(data), "returncode": 0}


def err(stderr):
    return {"stdout": "", "stderr": stderr, "returncode": 255}


def base_responses():
    """Responses for a clean run of the 4 engine checks in us-east-1 (eu-west-1 only for Security Hub)."""
    return {
        ("sts", "get-caller-identity", "us-east-1"): ok(load_fixture("aws/core/sts-get-caller-identity.json")),
        ("ec2", "describe-regions", "us-east-1"): ok(load_fixture("aws/core/ec2-describe-regions.json")),
        ("ec2", "describe-instances", "us-east-1"): ok({"Reservations": []}),
        ("s3api", "list-buckets", "us-east-1"): ok(load_fixture("aws/core/s3api-list-buckets.json")),
        ("iam", "get-account-summary", "us-east-1"): ok(load_fixture("aws/core/iam-get-account-summary-offenders.json")),
        # sequential: acme-notes-data (clean), then acme-notes-logs (offender)
        ("s3api", "get-bucket-versioning", "us-east-1"): [
            ok([]), ok(load_fixture("aws/core/s3api-get-bucket-versioning-offenders.json"))],
        ("cloudtrail", "describe-trails", "us-east-1"): ok({"trailList": []}),
        ("securityhub", "describe-hub", "us-east-1"): ok([]),
        ("securityhub", "describe-hub", "eu-west-1"): err(NOT_ENABLED),
        ("iam", "list-attached-user-policies", "us-east-1"): ok({"AttachedPolicies": [{"PolicyName": "ReadOnlyAccess"}]}),
    }


class CollectCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def scope_file(self, name="scope-full.json", **overrides):
        scope = {**load_fixture(name), **overrides}
        path = self.tmp / "scope.json"
        path.write_text(json.dumps(scope), encoding="utf-8")
        return path

    def run_collect(self, responses=None, scope=None, checks_dir=ENGINE_DIR, inventory=INVENTORY_MIN,
                    which=lambda name: "/usr/bin/dig" if name == "dig" else None):
        runner = FakeRunner(base_responses() if responses is None else responses)
        out = self.tmp / "out"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = collect.main(
                ["--scope", str(scope or self.scope_file()), "--out", str(out),
                 "--checks-dir", str(checks_dir), "--inventory", str(inventory)],
                runner=runner, sleep=lambda s: None, which=which,
            )
        self.runner, self.out, self.stdout, self.code = runner, out, stdout.getvalue(), code
        self.result = json.loads((out / "checks-result.json").read_text(encoding="utf-8"))
        return self.result

    def rows(self, check_id):
        return sorted(
            (r for r in self.result["results"] if r["check_id"] == check_id),
            key=lambda r: (r["resource_id"], str(r["region"])),
        )

    def calls(self, service, operation):
        return [c for c in self.runner.calls if c[1:3] == [service, operation]]

    def catalog_with(self, *checks, base="IAM-901"):
        """Temp catalog dir with copies of engine checks mutated by the given callables."""
        data = json.loads((ENGINE_DIR / "engine.json").read_text(encoding="utf-8"))
        template = next(c for c in data["checks"] if c["id"] == base)
        out = []
        for mutate in checks:
            check = json.loads(json.dumps(template))
            mutate(check)
            out.append(check)
        directory = self.tmp / "catalog"
        directory.mkdir(exist_ok=True)
        (directory / "extra.json").write_text(json.dumps({"domain": "test", "checks": out}), encoding="utf-8")
        return directory


class EngineTests(CollectCase):
    def test_full_mode_runs_account_and_resource_checks(self):
        self.run_collect()
        self.assertEqual(self.code, 0)
        self.assertEqual([(r["status"], r["resource_id"]) for r in self.rows("IAM-901")], [("FAIL", "root")])
        self.assertEqual(
            [(r["status"], r["resource_id"], r["region"]) for r in self.rows("DAT-901")],
            [("PASS", "acme-notes-data", "us-east-1"), ("FAIL", "acme-notes-logs", "us-east-1")],
        )
        self.assertEqual(self.rows("DAT-901")[1]["detail"], {"Status": "Suspended"})
        self.assertEqual([(r["status"], r["resource_id"]) for r in self.rows("LOG-901")], [("PASS", "account")])
        aws = self.result["aws"]
        self.assertEqual((aws["account_id"], aws["regions"], aws["enabled_regions"]),
                         ("111122223333", ["us-east-1"], ["eu-west-1", "us-east-1"]))
        inventory = json.loads((self.out / "inventory.json").read_text(encoding="utf-8"))
        self.assertEqual([i["id"] for i in inventory], ["acme-notes-data", "acme-notes-logs"])
        self.assertEqual(set(inventory[0]), {"type", "id", "arn", "name", "region", "tags"})

    def test_results_are_sorted_and_complete_rows(self):
        self.run_collect()
        keys = [(r["check_id"], r["resource_id"], str(r["region"])) for r in self.result["results"]]
        self.assertEqual(keys, sorted(keys))
        for row in self.result["results"]:
            self.assertEqual(set(row), {"check_id", "status", "resource_id", "region", "detail", "missing", "vacuous"})

    def test_resource_mode_filters_to_scope_ids(self):
        responses = base_responses()
        responses[("s3api", "get-bucket-versioning", "us-east-1")] = ok(
            load_fixture("aws/core/s3api-get-bucket-versioning-offenders.json"))

        @evaluators.register("test_all_buckets_offend")
        def all_buckets(resp, params):
            return [{"resource_id": b["id"], "region": b["region"], "detail": {}} for b in resp["__inventory__"]]

        self.addCleanup(evaluators.EVALUATORS.pop, "test_all_buckets_offend")

        def python_check(check):
            check["id"] = "DAT-902"
            check["scope"], check["resource_types"] = "resource", ["s3_bucket"]
            check["verify"]["calls"] = [{"name": "buckets", "service": "s3api", "operation": "list-buckets", "args": [], "region": "global"}]
            check["verify"]["evaluator"] = "python:test_all_buckets_offend"

        catalog_dir = self.tmp / "both"
        catalog_dir.mkdir()
        shutil.copy(ENGINE_DIR / "engine.json", catalog_dir / "engine.json")
        shutil.copy(self.catalog_with(python_check) / "extra.json", catalog_dir / "extra.json")
        self.run_collect(responses, scope=self.scope_file("scope-resource.json"), checks_dir=catalog_dir)
        self.assertEqual([(r["status"], r["resource_id"]) for r in self.rows("DAT-901")], [("FAIL", "acme-notes-logs")])
        self.assertEqual([(r["status"], r["resource_id"]) for r in self.rows("DAT-902")], [("FAIL", "acme-notes-logs")])
        self.assertEqual(len(self.calls("s3api", "get-bucket-versioning")), 1)
        self.assertEqual(self.rows("IAM-901"), [])

    def test_feature_mode_includes_account_context_checks(self):
        responses = base_responses()
        responses[("s3api", "get-bucket-versioning", "us-east-1")] = ok([])
        scope = self.scope_file(mode="feature", target="logging", resources=[
            {"type": "s3_bucket", "id": "acme-notes-data", "region": "us-east-1"}])
        self.run_collect(responses, scope=scope)
        self.assertEqual([r["resource_id"] for r in self.rows("DAT-901")], ["acme-notes-data"])
        self.assertEqual([r["status"] for r in self.rows("LOG-901")], ["PASS"])
        self.assertEqual(self.rows("IAM-901"), [])
        self.assertEqual(self.rows("DET-901"), [])

    def test_domains_filter_applies(self):
        self.run_collect(scope=self.scope_file(domains=["iam"]))
        self.assertEqual({r["check_id"] for r in self.result["results"]}, {"IAM-901"})

    def test_access_denied_is_not_verified(self):
        responses = base_responses()
        responses[("iam", "get-account-summary", "us-east-1")] = err(ACCESS_DENIED)
        self.run_collect(responses)
        (row,) = self.rows("IAM-901")
        self.assertEqual(row["status"], "NO_VERIFICADO")
        self.assertEqual(row["missing"], ["iam:GetAccountSummary"])
        self.assertEqual(row["detail"]["failed_calls"][0]["error_kind"], "ACCESS_DENIED")
        self.assertNotIn("PASS", [r["status"] for r in self.rows("IAM-901")])

    def test_unexpected_error_is_not_verified_without_missing(self):
        responses = base_responses()
        responses[("iam", "get-account-summary", "us-east-1")] = err("An error occurred (ServiceFailure) boom")
        self.run_collect(responses)
        (row,) = self.rows("IAM-901")
        self.assertEqual((row["status"], row["missing"]), ("NO_VERIFICADO", []))

    def test_not_enabled_means_fail_when_declared(self):
        self.run_collect()
        rows = self.rows("DET-901")
        self.assertEqual([(r["status"], r["region"], r["resource_id"]) for r in rows], [("FAIL", "eu-west-1", "account")])
        self.assertEqual(rows[0]["detail"]["reason"], "servicio no habilitado")

    def test_not_enabled_is_not_verified_otherwise(self):
        data = json.loads((ENGINE_DIR / "engine.json").read_text(encoding="utf-8"))
        det = next(c for c in data["checks"] if c["id"] == "DET-901")
        det["not_enabled_means"] = "not_verified"
        catalog_dir = self.tmp / "nv"
        catalog_dir.mkdir()
        (catalog_dir / "nv.json").write_text(json.dumps({"domain": "detection", "checks": [det]}), encoding="utf-8")
        self.run_collect(checks_dir=catalog_dir)
        (row,) = self.rows("DET-901")
        self.assertEqual((row["status"], row["missing"]), ("NO_VERIFICADO", []))

    def test_no_resources_is_vacuous_na(self):
        responses = base_responses()
        responses[("s3api", "list-buckets", "us-east-1")] = ok({"Buckets": []})
        self.run_collect(responses)
        (row,) = self.rows("DAT-901")
        self.assertEqual((row["status"], row["vacuous"], row["resource_id"]), ("N/A", True, "account"))
        self.assertEqual(self.calls("s3api", "get-bucket-versioning"), [])

    def test_inventory_listing_denied_is_not_verified_not_vacuous(self):
        responses = base_responses()
        responses[("s3api", "list-buckets", "us-east-1")] = err("An error occurred (AccessDenied) when calling the ListBuckets operation: not authorized")
        self.run_collect(responses)
        (row,) = self.rows("DAT-901")
        self.assertEqual(row["status"], "NO_VERIFICADO")
        self.assertTrue(any("s3_bucket" in w for w in self.result["warnings"]))

    def test_for_each_expands_calls(self):
        self.run_collect()
        calls = self.calls("s3api", "get-bucket-versioning")
        self.assertEqual(len(calls), 2)
        self.assertEqual([c[c.index("--bucket") + 1] for c in calls], ["acme-notes-data", "acme-notes-logs"])
        raw = self.out / "raw" / "DAT-901"
        self.assertEqual(sorted(p.name for p in raw.iterdir()),
                         ["versioning-us-east-1-0.json", "versioning-us-east-1-1.json"])

    def test_for_each_from_call_response(self):
        def chained(check):
            check["id"] = "DAT-903"
            check["scope"], check["resource_types"] = "resource", ["s3_bucket"]
            check["verify"]["calls"] = [
                {"name": "buckets", "service": "s3api", "operation": "list-buckets", "args": [], "region": "global"},
                {"name": "versioning", "service": "s3api", "operation": "get-bucket-versioning", "args": [], "region": "global",
                 "for_each": {"from": "buckets", "path": "Buckets[].Name", "arg": "--bucket"}},
            ]
            check["verify"]["evaluator"] = "python:test_seen"

        seen = {}

        @evaluators.register("test_seen")
        def probe(resp, params):
            seen.update(resp)
            return []

        self.addCleanup(evaluators.EVALUATORS.pop, "test_seen")
        responses = base_responses()
        self.run_collect(responses, checks_dir=self.catalog_with(chained))
        self.assertEqual(seen["__for_each__"]["versioning"], ["acme-notes-data", "acme-notes-logs"])
        self.assertEqual([region for region, _ in seen["versioning"]], ["us-east-1", "us-east-1"])
        self.assertEqual(len(seen["buckets"]), 1)

    def test_all_regions_flag_uses_enabled_regions(self):
        self.run_collect()
        self.assertEqual(sorted(c[c.index("--region") + 1] for c in self.calls("securityhub", "describe-hub")),
                         ["eu-west-1", "us-east-1"])
        self.assertEqual(len(self.calls("iam", "get-account-summary")), 1)

    def test_scope_regions_not_enabled_are_dropped_with_warning(self):
        self.run_collect(scope=self.scope_file(regions=["us-east-1", "ap-nowhere-9"]))
        self.assertEqual(self.result["aws"]["regions"], ["us-east-1"])
        self.assertTrue(any("ap-nowhere-9" in w for w in self.result["warnings"]))

    def test_auto_regions_use_regions_with_resources(self):
        responses = base_responses()
        responses[("ec2", "describe-instances", "eu-west-1")] = ok(load_fixture("aws/core/ec2-describe-instances-eu.json"))
        self.run_collect(responses, scope=self.scope_file(regions="auto"))
        self.assertEqual(self.result["aws"]["regions"], ["eu-west-1", "us-east-1"])
        inventory = json.loads((self.out / "inventory.json").read_text(encoding="utf-8"))
        instance = next(i for i in inventory if i["type"] == "ec2_instance")
        self.assertEqual((instance["id"], instance["name"], instance["region"], instance["tags"]),
                         ("i-0acme00000000001", "web-1", "eu-west-1", {"Name": "web-1", "Env": "prod"}))

    def test_no_credentials_exits_2(self):
        runner_responses = {("sts", "get-caller-identity", "us-east-1"): err(NO_CREDS)}
        self.run_collect(runner_responses)
        self.assertEqual(self.code, 2)
        self.assertIsNone(self.result["aws"])
        self.assertEqual([c[1:3] for c in self.runner.calls], [["sts", "get-caller-identity"]])

    def test_raw_outputs_written(self):
        self.run_collect()
        raw = json.loads((self.out / "raw" / "IAM-901" / "summary-us-east-1.json").read_text(encoding="utf-8"))
        self.assertTrue(raw["ok"])
        self.assertEqual(raw["data"][0]["resource_id"], "root")
        self.assertEqual(raw["argv"][:3], ["aws", "iam", "get-account-summary"])
        failed = json.loads((self.out / "raw" / "DET-901" / "hub-eu-west-1.json").read_text(encoding="utf-8"))
        self.assertEqual(failed["error_kind"], "NOT_ENABLED")

    def test_stdout_summary_is_bounded(self):
        responses = base_responses()
        offenders = [{"resource_id": f"user-{i:03d}", "detail": {"n": i}} for i in range(300)]
        responses[("iam", "get-account-summary", "us-east-1")] = ok(offenders)
        self.run_collect(responses)
        self.assertEqual(len([r for r in self.rows("IAM-901") if r["status"] == "FAIL"]), 300)
        lines = self.stdout.splitlines()
        self.assertLessEqual(len(lines), 40)
        self.assertIn(str(self.out), self.stdout)
        self.assertIn("NO_VERIFICADO: 0", self.stdout)
        self.assertEqual(sum(1 for line in lines if line.startswith("  critical")), 10)

    def test_admin_identity_warning(self):
        responses = base_responses()
        responses[("iam", "list-attached-user-policies", "us-east-1")] = ok(
            {"AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]})
        self.run_collect(responses)
        self.assertTrue(any("AdministratorAccess" in w for w in self.result["warnings"]))
        call = self.calls("iam", "list-attached-user-policies")[0]
        self.assertEqual(call[call.index("--user-name") + 1], "auditor")

    def test_admin_check_access_denied_is_ignored(self):
        responses = base_responses()
        responses[("iam", "list-attached-user-policies", "us-east-1")] = err(ACCESS_DENIED)
        self.run_collect(responses)
        self.assertEqual(self.code, 0)
        self.assertFalse(any("AdministratorAccess" in w for w in self.result["warnings"]))

    def test_claude_evaluator_marks_pending(self):
        def claude(check):
            check["id"] = "IAM-902"
            check["verify"]["evaluator"] = "claude"
            check["verify"].pop("offenders")

        self.run_collect(checks_dir=self.catalog_with(claude))
        (row,) = self.rows("IAM-902")
        self.assertEqual((row["status"], row["resource_id"]), ("PENDING_CLAUDE", "account"))
        self.assertTrue((self.out / "raw" / "IAM-902" / "summary-us-east-1.json").exists())

    def test_scope_entry_by_arn_matches_inventory_item(self):
        spec = json.loads(INVENTORY_MIN.read_text(encoding="utf-8"))
        spec["s3_bucket"]["arn_path"] = "Arn"
        inventory_file = self.tmp / "inventory-arn.json"
        inventory_file.write_text(json.dumps(spec), encoding="utf-8")
        buckets = {"Buckets": [{"Name": "acme-notes-data", "Arn": "arn:aws:s3:::acme-notes-data"},
                               {"Name": "acme-notes-logs", "Arn": "arn:aws:s3:::acme-notes-logs"}]}
        responses = base_responses()
        responses[("s3api", "list-buckets", "us-east-1")] = ok(buckets)
        responses[("s3api", "get-bucket-versioning", "us-east-1")] = ok(
            load_fixture("aws/core/s3api-get-bucket-versioning-offenders.json"))
        scope = self.scope_file("scope-resource.json", resources=[
            {"type": "s3_bucket", "id": "arn:aws:s3:::acme-notes-logs", "region": "us-east-1"}])
        self.run_collect(responses, scope=scope, inventory=inventory_file)
        self.assertEqual([(r["status"], r["resource_id"]) for r in self.rows("DAT-901")], [("FAIL", "acme-notes-logs")])
        self.assertFalse(any("sin coincidencia" in w for w in self.result["warnings"]))

    def test_unmatched_scope_entry_warns_and_is_not_silent(self):
        scope = self.scope_file("scope-resource.json", resources=[
            {"type": "s3_bucket", "id": "acme-notes-ghost", "region": "us-east-1"}])
        self.run_collect(scope=scope)
        self.assertTrue(any("acme-notes-ghost" in w and "sin coincidencia" in w for w in self.result["warnings"]))
        (row,) = self.rows("DAT-901")
        self.assertEqual((row["status"], row["vacuous"]), ("N/A", True))

    def test_crashing_check_does_not_lose_the_run(self):
        def bad_path(check):
            check["id"] = "DAT-905"
            check["scope"], check["resource_types"] = "resource", ["s3_bucket"]
            check["verify"]["calls"][0]["for_each"] = {"from": "__inventory__", "path": "id[0]", "arg": "--bucket"}

        directory = self.tmp / "crash"
        directory.mkdir()
        shutil.copy(ENGINE_DIR / "engine.json", directory / "engine.json")
        shutil.copy(self.catalog_with(bad_path) / "extra.json", directory / "extra.json")
        self.run_collect(checks_dir=directory)
        (row,) = self.rows("DAT-905")
        self.assertEqual(row["status"], "NO_VERIFICADO")
        self.assertIn("reason", row["detail"])
        self.assertEqual([r["status"] for r in self.rows("IAM-901")], ["FAIL"])

    def policy_check(self, ok_errors):
        def check_with_policy(check):
            check["id"] = "TLS-901"
            check["scope"], check["resource_types"] = "resource", ["s3_bucket"]
            call = {"name": "policy", "service": "s3api", "operation": "get-bucket-policy", "args": [], "region": "global",
                    "for_each": {"from": "__inventory__", "path": "id", "arg": "--bucket"}}
            if ok_errors:
                call["ok_errors"] = ok_errors
            check["verify"]["calls"] = [call]
            check["verify"]["evaluator"] = "python:test_policy_probe"
            check["verify"].pop("offenders")

        @evaluators.register("test_policy_probe")
        def probe(responses, params):
            return [{"resource_id": bucket, "region": region, "detail": {}}
                    for (region, data), bucket in zip(responses["policy"], responses["__for_each__"]["policy"])
                    if data == {"__error__": "NoSuchBucketPolicy"}]

        self.addCleanup(evaluators.EVALUATORS.pop, "test_policy_probe")
        return self.catalog_with(check_with_policy)

    def test_ok_errors_reach_evaluator_as_data(self):
        responses = base_responses()
        responses[("s3api", "get-bucket-policy", "us-east-1")] = [
            err("An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation: The bucket policy does not exist"),
            ok({"Policy": "{}"})]
        self.run_collect(responses, checks_dir=self.policy_check(["NoSuchBucketPolicy"]))
        self.assertEqual([(r["status"], r["resource_id"]) for r in self.rows("TLS-901")],
                         [("FAIL", "acme-notes-data"), ("PASS", "acme-notes-logs")])
        raw = json.loads((self.out / "raw" / "TLS-901" / "policy-us-east-1-0.json").read_text(encoding="utf-8"))
        self.assertEqual(raw["error_kind"], "ERROR")

    def test_unlisted_error_is_still_not_verified(self):
        responses = base_responses()
        responses[("s3api", "get-bucket-policy", "us-east-1")] = err("An error occurred (InternalFailure) boom")
        self.run_collect(responses, checks_dir=self.policy_check(["NoSuchBucketPolicy"]))
        (row,) = self.rows("TLS-901")
        self.assertEqual(row["status"], "NO_VERIFICADO")

    def test_ok_errors_never_hides_access_denied(self):
        responses = base_responses()
        responses[("s3api", "get-bucket-policy", "us-east-1")] = err(
            "An error occurred (AccessDenied) when calling the GetBucketPolicy operation: not authorized to perform")
        self.run_collect(responses, checks_dir=self.policy_check(["AccessDenied"]))
        (row,) = self.rows("TLS-901")
        self.assertEqual((row["status"], row["missing"]), ("NO_VERIFICADO", ["iam:GetAccountSummary"]))

    def test_not_applicable_entries_suppress_the_pass_row_and_are_not_failures(self):
        @evaluators.register("test_na")
        def na(responses, params):
            return [{"resource_id": "acme-notes-data", "region": "us-east-1", "detail": {}, "not_applicable": True}]

        self.addCleanup(evaluators.EVALUATORS.pop, "test_na")

        def python_check(check):
            check["id"] = "DAT-903"
            check["scope"] = "resource"
            check["resource_types"] = ["s3_bucket"]
            check["verify"]["evaluator"] = "python:test_na"

        self.run_collect(checks_dir=self.catalog_with(python_check))
        self.assertEqual([(r["status"], r["resource_id"]) for r in self.rows("DAT-903")], [("PASS", "acme-notes-logs")])

    def test_all_items_not_applicable_yields_one_na_row(self):
        @evaluators.register("test_na_all")
        def na_all(responses, params):
            return [{"resource_id": b, "region": "us-east-1", "detail": {}, "not_applicable": True}
                    for b in ("acme-notes-data", "acme-notes-logs")]

        self.addCleanup(evaluators.EVALUATORS.pop, "test_na_all")

        def python_check(check):
            check["id"] = "DAT-904"
            check["scope"] = "resource"
            check["resource_types"] = ["s3_bucket"]
            check["verify"]["evaluator"] = "python:test_na_all"

        self.run_collect(checks_dir=self.catalog_with(python_check))
        (row,) = self.rows("DAT-904")
        self.assertEqual((row["status"], row["resource_id"], row["vacuous"]), ("N/A", "account", True))
        self.assertEqual(row["detail"], {"reason": "ningún recurso aplica"})

    def test_inventory_available_to_evaluators(self):
        seen = {}

        @evaluators.register("test_probe")
        def probe(responses, params):
            seen["inventory"] = responses["__inventory__"]
            seen["params"] = params
            return [{"resource_id": "acme-notes-data", "region": "us-east-1", "detail": {"why": "probe"}}]

        self.addCleanup(evaluators.EVALUATORS.pop, "test_probe")

        def python_check(check):
            check["id"] = "LOG-902"
            check["verify"]["evaluator"] = "python:test_probe"
            check["verify"]["params"] = {"k": 1}

        self.run_collect(checks_dir=self.catalog_with(python_check))
        self.assertEqual([i["id"] for i in seen["inventory"]], ["acme-notes-data", "acme-notes-logs"])
        self.assertEqual(seen["params"], {"k": 1})
        (row,) = self.rows("LOG-902")
        self.assertEqual((row["status"], row["resource_id"], row["detail"]), ("FAIL", "acme-notes-data", {"why": "probe"}))

    def test_unregistered_or_crashing_evaluator_is_not_verified(self):
        @evaluators.register("test_boom")
        def boom(responses, params):
            raise RuntimeError("kaboom")

        self.addCleanup(evaluators.EVALUATORS.pop, "test_boom")

        def missing(check):
            check["id"] = "LOG-903"
            check["verify"]["evaluator"] = "python:does_not_exist"

        def crash(check):
            check["id"] = "LOG-904"
            check["verify"]["evaluator"] = "python:test_boom"

        self.run_collect(checks_dir=self.catalog_with(missing, crash))
        for check_id in ("LOG-903", "LOG-904"):
            (row,) = self.rows(check_id)
            self.assertEqual(row["status"], "NO_VERIFICADO")

    def test_write_operation_in_catalog_is_not_executed(self):
        def write(check):
            check["id"] = "IAM-903"
            check["verify"]["calls"][0]["operation"] = "delete-account-alias"

        self.run_collect(checks_dir=self.catalog_with(write))
        (row,) = self.rows("IAM-903")
        self.assertEqual(row["status"], "NO_VERIFICADO")
        self.assertEqual(self.calls("iam", "delete-account-alias"), [])


class DnsEvaluatorTests(CollectCase):
    PARAMS = {"rrtype": "TXT", "name_template": "_dmarc.{domain}", "must_match": "^\"?v=DMARC1"}

    def dns_run(self, identities, dig, params=None, which=None):
        spec = json.loads(INVENTORY_MIN.read_text(encoding="utf-8"))
        spec["ses_identity"] = {"service": "sesv2", "operation": "list-email-identities", "args": [], "region": "each",
                                "items_path": "EmailIdentities[]", "id_path": "IdentityName", "name_path": "",
                                "tags_path": "", "arn_path": ""}
        inventory_file = self.tmp / "inventory-ses.json"
        inventory_file.write_text(json.dumps(spec), encoding="utf-8")

        def dns_check(check):
            check["id"] = "EML-901"
            check["scope"], check["resource_types"] = "resource", ["ses_identity"]
            check["verify"]["calls"] = []
            check["verify"]["evaluator"] = "dns"
            check["verify"]["params"] = params or self.PARAMS
            check["verify"].pop("offenders")

        responses = base_responses()
        responses[("sesv2", "list-email-identities", "us-east-1")] = ok(
            {"EmailIdentities": [{"IdentityName": name} for name in identities]})
        if dig is not None:
            responses[("dig", None, None)] = dig
        kwargs = {} if which is None else {"which": which}
        self.run_collect(responses, checks_dir=self.catalog_with(dns_check), inventory=inventory_file, **kwargs)
        return [c for c in self.runner.calls if c[0] == "dig"]

    def test_dmarc_present_and_absent(self):
        dig_calls = self.dns_run(
            ["noreply@acme-notes.example", "mail.acme-notes.example", "acme-notes.example"],
            [{"stdout": '"v=DMARC1; p=reject"\n'}, {"stdout": ""}])
        self.assertEqual([c[2:] for c in dig_calls],
                         [["TXT", "_dmarc.acme-notes.example"], ["TXT", "_dmarc.mail.acme-notes.example"]])
        self.assertEqual(
            [(r["status"], r["resource_id"]) for r in self.rows("EML-901")],
            [("PASS", "acme-notes.example"), ("FAIL", "mail.acme-notes.example")])
        self.assertEqual(self.rows("EML-901")[1]["detail"], {"record": "_dmarc.mail.acme-notes.example", "found": []})

    def test_no_domain_identities_is_vacuous(self):
        dig_calls = self.dns_run(["noreply@acme-notes.example"], None)
        self.assertEqual(dig_calls, [])
        (row,) = self.rows("EML-901")
        self.assertEqual((row["status"], row["vacuous"]), ("N/A", True))

    def test_invalid_names_are_rejected_before_any_query(self):
        for bad in ("-x.example", "+x.example", "a b.example"):
            with self.subTest(bad=bad):
                dig_calls = self.dns_run([bad], [{"stdout": '"v=DMARC1"\n'}], params={**self.PARAMS, "name_template": "{domain}"})
                self.assertEqual(dig_calls, [])
                (row,) = self.rows("EML-901")
                self.assertEqual(row["status"], "NO_VERIFICADO")
                self.assertEqual(row["detail"]["reason"], "nombre DNS inválido")

    def test_dig_missing_is_not_verified(self):
        self.dns_run(["acme-notes.example"], None, which=lambda name: None)
        (row,) = self.rows("EML-901")
        self.assertEqual(row["status"], "NO_VERIFICADO")
        self.assertEqual(row["detail"]["reason"], "consulta DNS fallida")


class InventorySpecTests(unittest.TestCase):
    REQUIRED_TYPES = {
        "ec2_instance", "ebs_volume", "security_group", "nacl", "vpc", "subnet", "rds_instance", "rds_cluster",
        "s3_bucket", "dynamodb_table", "efs", "elbv2", "asg", "launch_template", "lambda_function", "sqs_queue",
        "sns_topic", "kms_key", "log_group", "cloudtrail_trail", "iam_user", "iam_role", "eks_cluster",
        "elasticache_group", "ses_identity", "wafv2_web_acl", "acm_certificate", "secret",
    }

    def setUp(self):
        self.spec = json.loads((SKILL_DIR / "references" / "inventory.json").read_text(encoding="utf-8"))

    def test_covers_required_types(self):
        self.assertTrue(self.REQUIRED_TYPES <= set(self.spec))

    def test_every_entry_is_read_only_and_well_formed(self):
        import paths
        keys = {"service", "operation", "args", "region", "items_path", "id_path", "name_path", "tags_path", "arn_path"}
        for name, entry in self.spec.items():
            self.assertEqual(set(entry), keys, name)
            self.assertIn(entry["region"], ("global", "each"), name)
            aws_runner.assert_read_only(entry["service"], entry["operation"], entry["args"])
            for key in keys - {"service", "operation", "args", "region"}:
                paths.extract({}, entry[key])  # parses

    def test_secrets_listing_never_reads_values(self):
        self.assertEqual((self.spec["secret"]["service"], self.spec["secret"]["operation"]),
                         ("secretsmanager", "list-secrets"))


if __name__ == "__main__":
    unittest.main()
