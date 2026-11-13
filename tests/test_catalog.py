import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = ROOT / "auditing-infra-compliance"
sys.path.insert(0, str(SKILL_DIR / "scripts"))

import catalog  # noqa: E402

FIXTURE_DIR = ROOT / "tests" / "fixtures" / "catalog-min"
REFS = SKILL_DIR / "references"


class CatalogTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = catalog.load_checks(FIXTURE_DIR)
        cls.tsc_ids, cls.iso_ids = catalog.load_frameworks(REFS / "frameworks")
        cls.drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")

    def checks(self):
        return copy.deepcopy(self.base)

    def run_validate(self, checks):
        return catalog.validate(checks, self.tsc_ids, self.iso_ids, self.drata)

    def assert_errors_for(self, checks, check_id):
        errors = self.run_validate(checks)
        self.assertTrue(
            any(check_id in e for e in errors),
            f"expected an error mentioning {check_id}, got {errors}",
        )
        return errors


class LoadingTests(CatalogTestCase):
    def test_constants(self):
        self.assertEqual(catalog.SEVERITIES, ("critical", "high", "medium", "low"))
        self.assertEqual(catalog.EVALUATOR_KINDS, ("jmespath", "python", "claude", "dns"))
        self.assertEqual(catalog.DCF_SOURCE, "drata-dcf-2026-11-12")
        self.assertIn("NO_VERIFICADO", catalog.STATUSES)
        self.assertEqual(
            catalog.REMEDIATION_KINDS,
            ("cli", "cli_with_decision", "planned_change", "console_only"),
        )
        self.assertEqual(catalog.RISKS, ("low", "medium", "high"))

    def test_load_checks_merges_files(self):
        self.assertEqual([c["id"] for c in self.base], ["IAM-001", "LOG-001"])

    def test_load_frameworks_includes_annex_clauses_and_parents(self):
        self.assertIn("CC6.1", self.tsc_ids)
        self.assertIn("A.8.2", self.iso_ids)
        self.assertIn("7.5.3", self.iso_ids)
        for parent in ("7.5", "9.2", "9.3", "6.1", "8.1", "9.1"):
            self.assertIn(parent, self.iso_ids)

    def test_load_drata_map_indexed_by_test_id(self):
        self.assertIn(214, self.drata)
        self.assertEqual(self.drata[214]["test_name"], "MFA for AWS Root Account")

    def test_every_dcf_mapping_resolves_to_known_ids(self):
        for test_id, test in self.drata.items():
            resolved = catalog.resolve_mappings(
                {"mappings": {"drata": [{"test": test_id}]}}, self.drata
            )
            for tsc in resolved["tsc"]:
                self.assertIn(tsc["id"], self.tsc_ids, test_id)
            for iso in resolved["iso27001_2022"]:
                self.assertIn(iso["id"], self.iso_ids, test_id)


class ResolveMappingsTests(CatalogTestCase):
    def test_resolve_mappings_from_dcf(self):
        resolved = catalog.resolve_mappings(self.base[0], self.drata)
        self.assertEqual({t["id"] for t in resolved["tsc"]}, {"CC6.1", "CC7.2"})
        self.assertEqual({i["id"] for i in resolved["iso27001_2022"]}, {"A.8.2", "A.8.16"})
        for item in resolved["tsc"] + resolved["iso27001_2022"]:
            self.assertEqual(item["sourced"], catalog.DCF_SOURCE)
        self.assertEqual(resolved["security_hub"], ["IAM.9"])
        self.assertEqual(resolved["cis_aws"], ["1.5"])
        self.assertEqual(resolved["drata"][0]["test"], 214)

    def test_resolve_mappings_inferred(self):
        resolved = catalog.resolve_mappings(self.base[1], self.drata)
        self.assertEqual([t["id"] for t in resolved["tsc"]], ["CC7.2"])
        self.assertEqual([i["id"] for i in resolved["iso27001_2022"]], ["A.8.15"])
        for item in resolved["tsc"] + resolved["iso27001_2022"]:
            self.assertIs(item["sourced"], False)

    def test_unresolvable_drata_test_falls_back_to_inferred(self):
        check = self.checks()[1]
        check["mappings"]["drata"] = [{"test": 999999, "name": "x", "source": "u"}]
        resolved = catalog.resolve_mappings(check, self.drata)
        self.assertIs(resolved["tsc"][0]["sourced"], False)

    def test_null_dcf_lists_are_treated_as_empty(self):
        drata = {1: {"controls": [{"soc2": None, "iso27001_2022": None}, {"soc2": ["CC6.1"]}]}}
        check = {"mappings": {"drata": [{"test": 1}]}}
        resolved = catalog.resolve_mappings(check, drata)
        self.assertEqual([t["id"] for t in resolved["tsc"]], ["CC6.1"])
        self.assertEqual(resolved["iso27001_2022"], [])


class ValidateTests(CatalogTestCase):
    def test_valid_catalog_has_no_errors(self):
        self.assertEqual(self.run_validate(self.checks()), [])

    def test_missing_required_field_is_reported_not_raised(self):
        checks = self.checks()
        del checks[0]["verify"]
        self.assert_errors_for(checks, "IAM-001")

    def test_rule_1_rejects_duplicate_ids(self):
        checks = self.checks()
        checks[1]["id"] = "IAM-001"
        self.assert_errors_for(checks, "IAM-001")

    def test_rule_1_rejects_bad_id_format(self):
        checks = self.checks()
        checks[0]["id"] = "iam-1"
        self.assert_errors_for(checks, "iam-1")

    def test_rule_2_rejects_invalid_severity(self):
        checks = self.checks()
        checks[0]["severity"] = "urgent"
        self.assert_errors_for(checks, "IAM-001")

    def test_rule_2_rejects_invalid_remediation_kind(self):
        checks = self.checks()
        checks[1]["remediation"]["kind"] = "magic"
        self.assert_errors_for(checks, "LOG-001")

    def test_rule_2_rejects_invalid_risk(self):
        checks = self.checks()
        checks[1]["remediation"]["risk"] = "extreme"
        self.assert_errors_for(checks, "LOG-001")

    def test_rule_2_rejects_invalid_evaluator(self):
        checks = self.checks()
        checks[1]["verify"]["evaluator"] = "perl"
        self.assert_errors_for(checks, "LOG-001")

    def test_rule_2_rejects_python_evaluator_without_name(self):
        checks = self.checks()
        checks[1]["verify"]["evaluator"] = "python:"
        self.assert_errors_for(checks, "LOG-001")

    def test_rule_3_rejects_write_operation(self):
        checks = self.checks()
        checks[1]["verify"]["calls"][0].update(
            {"service": "ec2", "operation": "modify-instance-attribute"}
        )
        self.assert_errors_for(checks, "LOG-001")

    def test_rule_3_accepts_lookup_events_and_credential_report(self):
        checks = self.checks()
        checks[1]["verify"]["calls"] = [
            {"name": "a", "service": "cloudtrail", "operation": "lookup-events", "args": [], "region": "each"},
            {"name": "b", "service": "iam", "operation": "generate-credential-report", "args": [], "region": "global"},
        ]
        self.assertEqual(self.run_validate(checks), [])

    def test_rule_4_rejects_unknown_tsc(self):
        checks = self.checks()
        checks[1]["mappings"]["tsc_inferred"] = ["CC99.9"]
        self.assert_errors_for(checks, "LOG-001")

    def test_rule_4_rejects_unknown_iso(self):
        checks = self.checks()
        checks[1]["mappings"]["iso_inferred"] = ["A.99.9"]
        self.assert_errors_for(checks, "LOG-001")

    def test_rule_5_rejects_non_int_drata_test(self):
        checks = self.checks()
        checks[0]["mappings"]["drata"][0]["test"] = "214"
        # Give inferred mappings so rule 10 cannot be what produces the error.
        checks[0]["mappings"]["tsc_inferred"] = ["CC6.1"]
        checks[0]["mappings"]["iso_inferred"] = ["A.8.2"]
        errors = self.run_validate(checks)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("IAM-001", errors[0])
        self.assertIn("debe ser int", errors[0])

    def test_rule_6_rejects_jmespath_with_two_calls(self):
        checks = self.checks()
        checks[0]["verify"]["calls"].append(copy.deepcopy(checks[0]["verify"]["calls"][0]))
        self.assert_errors_for(checks, "IAM-001")

    def test_rule_6_rejects_jmespath_without_offenders(self):
        checks = self.checks()
        checks[0]["verify"]["offenders"] = ""
        self.assert_errors_for(checks, "IAM-001")

    def test_rule_7_rejects_empty_verify_after(self):
        checks = self.checks()
        checks[1]["remediation"]["verify_after"] = ""
        self.assert_errors_for(checks, "LOG-001")

    def test_rule_7_console_only_may_omit_verify_after(self):
        self.assertEqual(self.checks()[0]["remediation"]["verify_after"], "")
        self.assertEqual(self.run_validate(self.checks()), [])

    def test_rule_8_rejects_planned_change_with_one_step(self):
        checks = self.checks()
        checks[1]["remediation"].update(
            {"kind": "planned_change", "steps": ["solo uno"], "notes": "Puede haber downtime"}
        )
        self.assert_errors_for(checks, "LOG-001")

    def test_rule_8_rejects_planned_change_without_notes(self):
        checks = self.checks()
        checks[1]["remediation"].update(
            {"kind": "planned_change", "steps": ["uno", "dos"], "notes": ""}
        )
        self.assert_errors_for(checks, "LOG-001")

    def test_rule_8_accepts_complete_planned_change(self):
        checks = self.checks()
        checks[1]["remediation"].update(
            {"kind": "planned_change", "steps": ["uno", "dos"], "notes": "Advertencia"}
        )
        self.assertEqual(self.run_validate(checks), [])

    def test_rule_9_rejects_heredoc_placeholder(self):
        checks = self.checks()
        checks[1]["remediation"]["commands"] = ["aws s3 mb s3://<<COMPLETAR: bucket>>"]
        self.assert_errors_for(checks, "LOG-001")

    def test_rule_10_requires_inferred_when_no_resolvable_drata(self):
        checks = self.checks()
        checks[1]["mappings"]["tsc_inferred"] = []
        checks[1]["mappings"]["iso_inferred"] = []
        self.assert_errors_for(checks, "LOG-001")

    def test_rule_10_unresolvable_drata_test_still_requires_inferred(self):
        checks = self.checks()
        checks[0]["mappings"]["drata"][0]["test"] = 999999
        self.assert_errors_for(checks, "IAM-001")

    def test_rule_11_rejects_resource_scope_without_resource_types(self):
        checks = self.checks()
        checks[1]["resource_types"] = []
        self.assert_errors_for(checks, "LOG-001")

    def test_ok_errors_must_be_list_of_strings(self):
        checks = self.checks()
        checks[1]["verify"]["calls"][0]["ok_errors"] = ["NoSuchBucketPolicy"]
        self.assertEqual(self.run_validate(checks), [])
        for bad in ("NoSuchBucketPolicy", [1], [""]):
            checks = self.checks()
            checks[1]["verify"]["calls"][0]["ok_errors"] = bad
            self.assert_errors_for(checks, "LOG-001")

    def test_item_errors_only_on_for_each_calls_of_python_checks(self):
        def with_item_errors(value, for_each=True, evaluator="python:x"):
            checks = self.checks()
            call = checks[1]["verify"]["calls"][0]
            call.pop("for_each", None)
            if for_each:
                call["for_each"] = {"from": "__inventory__", "path": "id", "arg": "--bucket"}
            call["item_errors"] = value
            checks[1]["verify"]["evaluator"] = evaluator
            return checks

        self.assertEqual(self.run_validate(with_item_errors("evaluator")), [])
        for bad in (with_item_errors("evaluator", for_each=False), with_item_errors("fail"), with_item_errors(True),
                    with_item_errors("evaluator", evaluator="jmespath")):
            self.assert_errors_for(bad, "LOG-001")

    def test_dns_params_validated(self):
        def dns_check(params):
            checks = self.checks()
            checks[1]["verify"]["evaluator"] = "dns"
            checks[1]["verify"]["params"] = params
            return checks

        good = {"rrtype": "TXT", "name_template": "_dmarc.{domain}", "must_match": "v=DMARC1"}
        self.assertEqual(self.run_validate(dns_check(good)), [])
        self.assertEqual(self.run_validate(dns_check({**good, "domains_from": "ses_identity"})), [])
        for bad in (
            {k: v for k, v in good.items() if k != "rrtype"},
            {k: v for k, v in good.items() if k != "name_template"},
            {k: v for k, v in good.items() if k != "must_match"},
            {**good, "name_template": "_dmarc.example"},
            {**good, "must_match": "("},
            {**good, "rrtype": "-x"},
        ):
            self.assert_errors_for(dns_check(bad), "LOG-001")


if __name__ == "__main__":
    unittest.main()


class ListCliTests(unittest.TestCase):
    """R63: validate_catalog.py --list [--type T] [--grep TEXT]."""

    @staticmethod
    def run_cli(*argv):
        import contextlib
        import io
        import validate_catalog

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = validate_catalog.main(list(argv))
        return code, out.getvalue().splitlines()

    def test_list_prints_every_check_as_four_columns(self):
        code, lines = self.run_cli("--list")
        self.assertEqual(code, 0)
        checks = catalog.load_checks(REFS / "checks")
        self.assertEqual(len(lines), len(checks))
        for line, check in zip(lines, checks):
            columns = line.split(" | ")
            self.assertEqual(len(columns), 4, line)
            self.assertEqual((columns[0], columns[1], columns[3]), (check["id"], check["title"], check["severity"]))
            self.assertEqual(columns[2], ",".join(check["resource_types"]) or "account")

    def test_type_filter_includes_resource_checks_and_account_context_checks(self):
        _, lines = self.run_cli("--list", "--type", "rds_instance")
        ids = {line.split(" | ")[0] for line in lines}
        self.assertIn("ENC-003", ids)
        self.assertIn("DET-001", ids)  # account check that declares rds_instance in account_context_for
        self.assertNotIn("ENC-002", ids)  # EBS volumes only

    def test_grep_filter_is_case_insensitive_and_combines_with_type(self):
        _, lines = self.run_cli("--list", "--grep", "cifrado")
        self.assertTrue(lines and all("cifrado" in line.lower() for line in lines))
        _, both = self.run_cli("--list", "--type", "rds_instance", "--grep", "CIFRADO")
        self.assertTrue({l.split(" | ")[0] for l in both} <= {l.split(" | ")[0] for l in lines})
        self.assertIn("ENC-003", {l.split(" | ")[0] for l in both})
        self.assertEqual(self.run_cli("--list", "--grep", "zzz-no-existe"), (0, []))

    def test_filters_without_list_are_rejected_and_plain_run_still_validates(self):
        import contextlib
        import io
        import validate_catalog

        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            validate_catalog.main(["--type", "rds_instance"])
        code, lines = self.run_cli()
        self.assertEqual(code, 0)
        self.assertTrue(lines[-1].startswith("OK:"))
