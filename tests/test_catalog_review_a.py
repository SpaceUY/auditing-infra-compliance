"""Review 2, area A: the validator checks the engine contract and every call against a reviewed allowlist."""
import contextlib
import copy
import io
import json
import unittest

from helpers import SKILL_DIR

import catalog
import evaluators
import validate_catalog

REFS = SKILL_DIR / "references"
CHECKS = catalog.load_checks(REFS / "checks")
SPECS = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))
TSC, ISO = catalog.load_frameworks(REFS / "frameworks")
DRATA = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
RULES = json.loads((REFS / "conflict-rules.json").read_text(encoding="utf-8"))


def validate(checks, **extra):
    contract = {"inventory_types": set(SPECS), "registered": set(evaluators.EVALUATORS),
                "required_params": evaluators.REQUIRED_PARAMS, **extra}
    return catalog.validate(checks, TSC, ISO, DRATA, RULES, **contract)


def one(check_id="IAM-004"):
    return copy.deepcopy(next(c for c in CHECKS if c["id"] == check_id))


def with_mutation(check_id, mutate):
    checks = copy.deepcopy(CHECKS)
    mutate(next(c for c in checks if c["id"] == check_id))
    return validate(checks)


class ShippedCatalogTests(unittest.TestCase):
    def test_the_shipped_catalog_passes_the_full_contract(self):
        self.assertEqual(validate(copy.deepcopy(CHECKS)), [])

    def test_every_shipped_operation_is_in_the_reviewed_allowlist(self):
        pairs = {(c["service"], c["operation"]) for check in CHECKS for c in check["verify"]["calls"]}
        pairs |= {(s["service"], s["operation"]) for s in SPECS.values()}
        self.assertEqual(sorted(pairs - catalog.REVIEWED_OPERATIONS), [])

    def test_the_reviewed_allowlist_has_no_denied_or_unreadable_pair(self):
        import aws_runner
        for service, operation in catalog.REVIEWED_OPERATIONS:
            with self.subTest(op=f"{service} {operation}"):
                aws_runner.assert_read_only(service, operation, [])

    def test_inventory_spec_is_validated_too(self):
        self.assertEqual(catalog.validate_inventory(SPECS), [])
        broken = copy.deepcopy(SPECS)
        broken["s3_bucket"]["operation"] = "delete-bucket"
        broken["vpc"]["region"] = "everywhere"
        del broken["kms_key"]["id_path"]
        broken["ebs_volume"]["operation"] = "describe-snapshot-attribute"  # read-only by prefix, never reviewed
        errors = catalog.validate_inventory(broken)
        for needle in ("s3_bucket", "vpc", "kms_key", "ebs_volume"):
            self.assertTrue(any(needle in e for e in errors), (needle, errors))


class ReviewedAllowlistTests(unittest.TestCase):
    def test_a_read_only_by_prefix_but_unreviewed_operation_is_rejected(self):
        def mutate(check):
            check["verify"]["calls"][0].update(service="ec2", operation="describe-key-pairs")
        errors = with_mutation("IAM-004", mutate)
        self.assertTrue(any("IAM-004" in e and "revisad" in e for e in errors), errors)

    def test_a_credential_returning_operation_is_rejected_by_the_runner_rules_first(self):
        def mutate(check):
            check["verify"]["calls"][0].update(service="kinesis", operation="get-records")
        errors = with_mutation("IAM-004", mutate)
        self.assertTrue(any("IAM-004" in e and "solo lectura" in e for e in errors), errors)


class ContractTests(unittest.TestCase):
    def assert_error(self, check_id, mutate, needle):
        errors = with_mutation(check_id, mutate)
        self.assertTrue(any(check_id in e and needle in e for e in errors), (needle, errors))

    def test_scope_must_be_account_or_resource(self):
        self.assert_error("IAM-004", lambda c: c.update(scope="Resource"), "scope")

    def test_not_enabled_means_must_be_fail_or_not_verified(self):
        self.assert_error("DET-001", lambda c: c.update(not_enabled_means="Fail"), "not_enabled_means")

    def test_all_regions_must_be_a_boolean(self):
        self.assert_error("DET-001", lambda c: c.update(all_regions="true"), "all_regions")

    def test_call_region_must_be_each_or_global(self):
        self.assert_error("IAM-004", lambda c: c["verify"]["calls"][0].update(region="all"), "region")

    def test_unknown_call_keys_are_rejected(self):
        self.assert_error("IAM-004", lambda c: c["verify"]["calls"][0].update(retries=3), "retries")

    def test_call_args_must_be_a_list_of_text(self):
        self.assert_error("IAM-004", lambda c: c["verify"]["calls"][0].update(args="--x"), "args")

    def test_call_names_must_be_unique(self):
        def mutate(check):
            call = copy.deepcopy(check["verify"]["calls"][0])
            check["verify"]["calls"].append(call)
        self.assert_error("IAM-004", mutate, "duplicad")

    def test_for_each_must_come_from_an_earlier_call_or_the_inventory(self):
        def later(check):
            calls = check["verify"]["calls"]
            calls.reverse()
        def unknown(check):
            check["verify"]["calls"][-1]["for_each"]["from"] = "nope"
        self.assert_error("CMP-006", later, "for_each")
        self.assert_error("CMP-006", unknown, "for_each")

    def test_for_each_needs_path_and_arg(self):
        def mutate(check):
            del check["verify"]["calls"][-1]["for_each"]["arg"]
        self.assert_error("CMP-006", mutate, "for_each")

    def test_inventory_for_each_requires_resource_types(self):
        def mutate(check):
            check["verify"]["calls"][0]["for_each"] = {"from": "__inventory__", "path": "id", "arg": "--x"}
        self.assert_error("IAM-004", mutate, "__inventory__")

    def test_resource_types_must_exist_in_the_inventory_spec(self):
        self.assert_error("CMP-006", lambda c: c.update(resource_types=["ec2_server"]), "ec2_server")

    def test_account_context_for_must_exist_in_the_inventory_spec(self):
        self.assert_error("DET-001", lambda c: c.update(account_context_for=["no_such_type"]), "no_such_type")

    def test_params_inventory_types_must_exist_in_the_inventory_spec(self):
        def mutate(check):
            check["verify"].setdefault("params", {})["inventory_types"] = ["no_such_type"]
        self.assert_error("DET-001", mutate, "no_such_type")

    def test_python_evaluator_must_be_registered(self):
        self.assert_error("IAM-004", lambda c: c["verify"].update(evaluator="python:root_usages"), "root_usages")

    def test_required_params_must_be_present(self):
        self.assert_error("IAM-004", lambda c: c["verify"].update(params={"days": 7}), "max")

    def test_needs_must_be_a_list_of_text(self):
        self.assert_error("IAM-004", lambda c: c["verify"].update(needs="cloudtrail:LookupEvents"), "needs")

    def test_calls_must_not_be_empty(self):
        self.assert_error("IAM-004", lambda c: c["verify"].update(calls=[]), "calls")

    def test_every_registered_evaluator_with_required_params_is_declared(self):
        self.assertTrue(set(evaluators.REQUIRED_PARAMS) <= set(evaluators.EVALUATORS))
        for check in CHECKS:
            name = check["verify"]["evaluator"].partition(":")[2]
            for key in evaluators.REQUIRED_PARAMS.get(name, ()):
                self.assertIn(key, check["verify"].get("params") or {}, check["id"])

    def test_contract_arguments_are_optional_for_other_callers(self):
        self.assertEqual(catalog.validate(copy.deepcopy(CHECKS), TSC, ISO, DRATA, RULES), [])


class Iam004NotesTests(unittest.TestCase):
    def test_notes_describe_the_all_regions_behaviour_not_only_us_east_1(self):
        check = one("IAM-004")
        self.assertTrue(check["all_regions"])
        notes = check["remediation"]["notes"]
        self.assertNotIn("solo us-east-1", notes)
        self.assertIn("todas las regiones", notes)


class CliTests(unittest.TestCase):
    def test_validate_catalog_cli_passes_the_contract_arguments(self):
        contract = validate_catalog.contract_arguments(SPECS)
        self.assertEqual(set(contract), {"inventory_types", "registered", "required_params"})
        self.assertEqual(contract["inventory_types"], set(SPECS))

    def test_cli_ok_on_the_shipped_catalog(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = validate_catalog.main([])
        self.assertEqual((code, out.getvalue().startswith("OK:")), (0, True), out.getvalue())


if __name__ == "__main__":
    unittest.main()
