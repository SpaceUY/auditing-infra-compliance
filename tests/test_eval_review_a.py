"""Review 2, area A: evaluator fixes (root usage in every region, filtered lifecycle rules, credential report gaps, policy decoding)."""
import json
import unittest
from datetime import datetime, timedelta

from helpers import SKILL_DIR

from evaluators import integration
from test_eval_iam import NOW, REGION, cred_row, evaluate, one, report_responses
from test_eval_logging import TRAIL_BUCKET, LifecycleTests

IAM_CHECKS = json.loads((SKILL_DIR / "references" / "checks" / "iam.json").read_text(encoding="utf-8"))["checks"]


def login(days_ago, hours=0):
    when = datetime.fromisoformat(NOW) - timedelta(days=days_ago, hours=hours)
    return {"EventName": "ConsoleLogin", "EventTime": when.isoformat(), "Username": "root"}


class RootUsageInEveryRegionTests(unittest.TestCase):
    PARAMS = {"days": 7, "max": 1, "now": NOW}

    def test_the_catalog_asks_every_enabled_region(self):
        check = next(c for c in IAM_CHECKS if c["id"] == "IAM-004")
        self.assertTrue(check["all_regions"])
        self.assertEqual({c["region"] for c in check["verify"]["calls"]}, {"each"})

    def test_logins_in_different_regions_are_added_up(self):
        responses = {"events": [("us-east-1", {"Events": [login(1)]}), ("eu-west-1", {"Events": [login(2)]})]}
        (offender,) = evaluate("root_usage", responses, self.PARAMS)
        self.assertEqual(offender["detail"]["console_logins"], 2)
        self.assertEqual(offender["detail"]["regions"], ["eu-west-1", "us-east-1"])

    def test_one_login_in_each_of_two_regions_is_not_hidden_by_looking_at_one(self):
        responses = {"events": [("us-east-1", {"Events": []}), ("eu-west-1", {"Events": [login(1), login(2)]})]}
        (offender,) = evaluate("root_usage", responses, self.PARAMS)
        self.assertEqual((offender["region"], offender["detail"]["console_logins"]), ("eu-west-1", 2))

    def test_a_single_region_keeps_the_previous_detail(self):
        (offender,) = evaluate("root_usage", one("events", {"Events": [login(1), login(2)]}), self.PARAMS)
        self.assertEqual((offender["region"], offender["detail"]), (REGION, {"console_logins": 2, "days": 7}))

    def test_clean_regions_pass(self):
        responses = {"events": [("us-east-1", {"Events": [login(1)]}), ("eu-west-1", {"Events": []})]}
        self.assertEqual(evaluate("root_usage", responses, self.PARAMS), [])


class CredentialReportGapTests(unittest.TestCase):
    NEWBIE = {"type": "iam_user", "id": "newbie", "arn": "arn:aws:iam::111122223333:user/newbie", "name": "newbie",
              "region": REGION, "tags": {}}
    ALICE = {"type": "iam_user", "id": "alice.dev", "arn": "", "name": "alice.dev", "region": REGION, "tags": {}}
    EVALUATORS = (("cred_report_console_mfa", {}), ("cred_report_key_age", {"fail_at_days": 90, "now": NOW}),
                  ("cred_report_unused", {"max_days": 45, "now": NOW}), ("cred_report_multi_keys", {}), ("iam_human_users", {}))

    def responses(self, inventory):
        return {**report_responses(cred_row("alice.dev")), "__inventory__": inventory}

    def test_a_user_missing_from_the_report_is_unverified_never_a_pass(self):
        for name, params in self.EVALUATORS:
            with self.subTest(evaluator=name):
                found = evaluate(name, self.responses([self.ALICE, self.NEWBIE]), params)
                entries = [o for o in found if o["resource_id"] == "newbie"]
                self.assertEqual(len(entries), 1)
                self.assertTrue(entries[0]["unverified"])
                self.assertEqual(entries[0]["region"], REGION)
                self.assertIn("reporte de credenciales", entries[0]["detail"]["reason"])
                self.assertEqual([o for o in found if o["resource_id"] == "alice.dev"], [])

    def test_without_an_inventory_nothing_changes(self):
        for name, params in self.EVALUATORS:
            with self.subTest(evaluator=name):
                self.assertEqual([o for o in evaluate(name, report_responses(cred_row("alice.dev")), params) if o.get("unverified")], [])


class FilteredLifecycleRuleTests(unittest.TestCase):
    INVENTORY, PARAMS, responses = LifecycleTests.INVENTORY, LifecycleTests.PARAMS, LifecycleTests.responses

    def evaluate_rules(self, *rules):
        return evaluate("log_bucket_lifecycle", self.responses(**{TRAIL_BUCKET: {"Rules": list(rules)}}), self.PARAMS)

    @staticmethod
    def rule(**extra):
        return {"ID": "short", "Status": "Enabled", "Expiration": {"Days": 30}, **extra}

    def offenders(self, *rules):
        return [o for o in self.evaluate_rules(*rules) if not o.get("not_applicable")]

    def test_a_rule_for_the_whole_bucket_is_reported_as_before(self):
        for extra in ({}, {"Filter": {}}, {"Filter": {"Prefix": ""}}, {"Prefix": ""}):
            with self.subTest(rule=extra):
                (offender,) = self.offenders(self.rule(**extra))
                self.assertNotIn("severity_override", offender["detail"])

    def test_a_rule_filtered_by_tag_or_size_does_not_expire_the_logs_and_is_ignored(self):
        for extra in ({"Filter": {"Tag": {"Key": "tmp", "Value": "true"}}}, {"Filter": {"ObjectSizeLessThan": 1024}},
                      {"Filter": {"And": {"Prefix": "tmp/", "Tags": [{"Key": "a", "Value": "b"}]}}},
                      {"Filter": {"ObjectSizeGreaterThan": 10}}):
            with self.subTest(rule=extra):
                self.assertEqual(self.offenders(self.rule(**extra)), [])

    def test_a_prefix_rule_is_reported_at_low_severity_with_its_prefix(self):
        for extra, prefix in (({"Filter": {"Prefix": "tmp/"}}, "tmp/"), ({"Prefix": "AWSLogs/"}, "AWSLogs/"),
                              ({"Filter": {"And": {"Prefix": "x/"}}}, "x/")):
            with self.subTest(rule=extra):
                (offender,) = self.offenders(self.rule(**extra))
                self.assertEqual(offender["detail"]["severity_override"], "low")
                self.assertEqual(offender["detail"]["rules"][0]["prefix"], prefix)

    def test_a_whole_bucket_rule_next_to_a_prefix_rule_keeps_the_normal_severity(self):
        (offender,) = self.offenders(self.rule(Filter={"Prefix": "tmp/"}, ID="a"), self.rule(ID="b"))
        self.assertNotIn("severity_override", offender["detail"])
        self.assertEqual([r["rule"] for r in offender["detail"]["rules"]], ["a", "b"])


class PolicyDocumentDecodingTests(unittest.TestCase):
    def test_a_raw_json_policy_is_not_url_decoded(self):
        raw = '{"Version": "2012-10-17", "Statement": [{"Sid": "a%22b%25", "Effect": "Allow"}]}'
        self.assertEqual(integration._document(raw)["Statement"][0]["Sid"], "a%22b%25")

    def test_a_url_encoded_policy_is_still_decoded(self):
        self.assertEqual(integration._document("%7B%22Version%22%3A%222012-10-17%22%7D"), {"Version": "2012-10-17"})

    def test_objects_and_empty_values_are_unchanged(self):
        self.assertEqual(integration._document({"a": 1}), {"a": 1})
        self.assertEqual(integration._document(None), {})


if __name__ == "__main__":
    unittest.main()
