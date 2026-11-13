import contextlib
import io
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import helpers
from helpers import SKILL_DIR, load_fixture

import catalog
import collect
import evaluators
from test_eval_iam import RuleRunner, err, ok

try:
    import jmespath
except ImportError:  # the skill itself is stdlib-only; the JMESPath expressions are only verified when it is installed
    jmespath = None

LOGGING_JSON = SKILL_DIR / "references" / "checks" / "logging.json"
REFS = SKILL_DIR / "references"
REGION = "us-east-1"
NOW = "2026-11-12T12:00:00+00:00"
ACCOUNT = "111122223333"
TRAIL_ARN = f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/acme-notes-trail"
TRAIL_BUCKET = "acme-notes-trail-logs"
VPC_MAIN = "vpc-0a1b2c3d4e5f60718"
VPC_SECOND = "vpc-0b2c3d4e5f6071829"
ALB_ARN = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/acme-notes-alb/50dc6c495c0c9188"
NLB_ARN = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/net/acme-notes-nlb/6d0ecf831eec9f09"
WEB_ACL_ARN = f"arn:aws:wafv2:us-east-1:{ACCOUNT}:regional/webacl/acme-notes-web-acl/a1b2c3d4-5678-90ab-cdef-111122223333"


def fx(name):
    return load_fixture(f"aws/logging/{name}.json")


def evaluate(name, responses, params=None):
    return evaluators.EVALUATORS[name](responses, params or {})


def ids(offenders):
    return [o["resource_id"] for o in offenders]


def offending(offenders):
    """The entries that are real offenders (R20: not_applicable entries are not)."""
    return [o for o in offenders if not o.get("not_applicable")]


def not_applicable(offenders):
    return [o["resource_id"] for o in offenders if o.get("not_applicable")]


def trails(*fixtures, region=REGION):
    return {"trails": [(region, fx(f)) for f in fixtures]}


def for_each(call, pairs, region=REGION):
    """pairs: [(for_each value, response data)] -> the evaluator view of a call with for_each."""
    return {call: [(region, data) for _, data in pairs], "__for_each__": {call: [value for value, _ in pairs]}}


def merge(*parts):
    merged = {}
    for part in parts:
        for key, value in part.items():
            merged[key] = {**merged.get(key, {}), **value} if key == "__for_each__" else value
    return merged


def catalog_check(check_id):
    data = json.loads(LOGGING_JSON.read_text(encoding="utf-8"))
    return next(c for c in data["checks"] if c["id"] == check_id)


class CloudtrailActiveTests(unittest.TestCase):
    def responses(self, trail_fixture, status_fixture):
        trail_list = fx(trail_fixture)["trailList"]
        data = [(t["TrailARN"], fx(status_fixture)) for t in trail_list]
        return merge(trails(trail_fixture), for_each("status", data))

    def test_cloudtrail_active_pass(self):
        responses = self.responses("cloudtrail-describe-trails-ok", "cloudtrail-get-trail-status-logging")
        self.assertEqual(evaluate("cloudtrail_active", responses), [])

    def test_cloudtrail_active_fail_reports_offenders(self):
        responses = self.responses("cloudtrail-describe-trails-ok", "cloudtrail-get-trail-status-stopped")
        (offender,) = evaluate("cloudtrail_active", responses)
        self.assertEqual((offender["resource_id"], offender["region"]), ("acme-notes-trail", REGION))
        self.assertIn("IsLogging", offender["detail"]["reason"])

    def test_cloudtrail_active_fail_without_trails(self):
        responses = merge(trails("cloudtrail-describe-trails-empty"), for_each("status", []))
        (offender,) = evaluate("cloudtrail_active", responses)
        self.assertEqual(offender["resource_id"], "account")

    def test_cloudtrail_active_fail_when_no_trail_is_multi_region(self):
        responses = self.responses("cloudtrail-describe-trails-single-region", "cloudtrail-get-trail-status-logging")
        (offender,) = evaluate("cloudtrail_active", responses)
        self.assertEqual(offender["resource_id"], "account")
        self.assertEqual(offender["detail"]["trails"], ["acme-notes-regional"])

    def test_cloudtrail_active_one_healthy_multi_region_trail_is_enough(self):
        stopped = {**fx("cloudtrail-describe-trails-ok")["trailList"][0], "Name": "acme-notes-old",
                   "TrailARN": TRAIL_ARN.replace("acme-notes-trail", "acme-notes-old")}
        responses = {"trails": [(REGION, {"trailList": [fx("cloudtrail-describe-trails-ok")["trailList"][0], stopped]})],
                     **for_each("status", [(TRAIL_ARN, fx("cloudtrail-get-trail-status-logging")),
                                           (stopped["TrailARN"], fx("cloudtrail-get-trail-status-stopped"))])}
        self.assertEqual(evaluate("cloudtrail_active", responses), [])


class TrailS3DataEventsTests(unittest.TestCase):
    def responses(self, trail_fixture, selector_fixtures):
        trail_list = fx(trail_fixture)["trailList"]
        pairs = [(t["TrailARN"], fx(s)) for t, s in zip(trail_list, selector_fixtures)]
        return merge(trails(trail_fixture), for_each("selectors", pairs))

    def test_trail_s3_data_events_pass_advanced_selectors(self):
        responses = self.responses("cloudtrail-describe-trails-ok", ["cloudtrail-get-event-selectors-advanced-all"])
        self.assertEqual(evaluate("trail_s3_data_events", responses), [])

    def test_trail_s3_data_events_pass_advanced_read_and_write_selectors(self):
        responses = self.responses("cloudtrail-describe-trails-ok", ["cloudtrail-get-event-selectors-advanced-split"])
        self.assertEqual(evaluate("trail_s3_data_events", responses), [])

    def test_trail_s3_data_events_pass_classic_selectors(self):
        responses = self.responses("cloudtrail-describe-trails-ok", ["cloudtrail-get-event-selectors-classic-all"])
        self.assertEqual(evaluate("trail_s3_data_events", responses), [])

    def test_trail_s3_data_events_read_and_write_may_come_from_different_trails(self):
        first = fx("cloudtrail-describe-trails-ok")["trailList"][0]
        second = {**first, "Name": "acme-notes-reads", "TrailARN": TRAIL_ARN.replace("acme-notes-trail", "acme-notes-reads")}
        responses = {"trails": [(REGION, {"trailList": [first, second]})],
                     **for_each("selectors", [(first["TrailARN"], fx("cloudtrail-get-event-selectors-advanced-write-only")),
                                              (second["TrailARN"], fx("cloudtrail-get-event-selectors-classic-read-only"))])}
        self.assertEqual(evaluate("trail_s3_data_events", responses), [])

    def test_trail_s3_data_events_fail_reports_offenders(self):
        responses = self.responses("cloudtrail-describe-trails-ok", ["cloudtrail-get-event-selectors-advanced-write-only"])
        (offender,) = evaluate("trail_s3_data_events", responses)
        self.assertEqual((offender["resource_id"], offender["region"]), ("account", REGION))
        self.assertEqual(offender["detail"]["missing"], ["read"])

    def test_trail_s3_data_events_fail_without_any_data_events(self):
        responses = self.responses("cloudtrail-describe-trails-ok", ["cloudtrail-get-event-selectors-management-only"])
        (offender,) = evaluate("trail_s3_data_events", responses)
        self.assertEqual(offender["detail"]["missing"], ["read", "write"])

    def test_trail_s3_data_events_selectors_for_one_bucket_do_not_count(self):
        responses = self.responses("cloudtrail-describe-trails-ok", ["cloudtrail-get-event-selectors-advanced-one-bucket"])
        (offender,) = evaluate("trail_s3_data_events", responses)
        self.assertEqual(offender["detail"]["missing"], ["read", "write"])

    def test_trail_s3_data_events_read_only_selector_with_another_operator_is_not_coverage(self):
        data = fx("cloudtrail-get-event-selectors-advanced-all")
        data["AdvancedEventSelectors"][1]["FieldSelectors"].append({"Field": "readOnly", "NotEquals": ["true"]})
        responses = merge(trails("cloudtrail-describe-trails-ok"), for_each("selectors", [(TRAIL_ARN, data)]))
        (offender,) = evaluate("trail_s3_data_events", responses)
        self.assertEqual(offender["detail"]["missing"], ["read", "write"])

    def test_trail_s3_data_events_fail_when_no_trail_is_multi_region(self):
        responses = self.responses("cloudtrail-describe-trails-single-region", ["cloudtrail-get-event-selectors-advanced-all"])
        (offender,) = evaluate("trail_s3_data_events", responses)
        self.assertEqual(offender["detail"]["reason"], "ningún trail multi-región")

    def test_trail_s3_data_events_fail_without_trails(self):
        responses = merge(trails("cloudtrail-describe-trails-empty"), for_each("selectors", []))
        (offender,) = evaluate("trail_s3_data_events", responses)
        self.assertEqual(offender["detail"]["reason"], "sin trails de CloudTrail")


class TrailBucketTests(unittest.TestCase):
    def logging(self, *pairs):
        return merge(trails("cloudtrail-describe-trails-ok"), for_each("bucket_logging", list(pairs)))

    def test_trail_bucket_logging_pass(self):
        responses = self.logging((TRAIL_BUCKET, fx("s3api-get-bucket-logging-enabled")))
        self.assertEqual(evaluate("trail_bucket_logging", responses), [])

    def test_trail_bucket_logging_fail_reports_offenders(self):
        responses = self.logging((TRAIL_BUCKET, fx("s3api-get-bucket-logging-disabled")))
        (offender,) = evaluate("trail_bucket_logging", responses)
        self.assertEqual((offender["resource_id"], offender["region"]), (TRAIL_BUCKET, REGION))
        self.assertEqual(offender["detail"]["trails"], ["acme-notes-trail"])

    def test_trail_bucket_logging_missing_bucket_is_reported(self):
        (offender,) = evaluate("trail_bucket_logging", self.logging((TRAIL_BUCKET, {"__error__": "NoSuchBucket"})))
        self.assertEqual((offender["resource_id"], offender["detail"]["reason"]), (TRAIL_BUCKET, "el bucket no existe"))

    def test_trail_bucket_logging_unreadable_bucket_is_unverified(self):
        (entry,) = evaluate("trail_bucket_logging", self.logging((TRAIL_BUCKET, {"__error__": "ACCESS_DENIED"})))
        self.assertEqual((entry["resource_id"], entry.get("unverified"), entry["detail"]["error_code"]),
                         (TRAIL_BUCKET, True, "ACCESS_DENIED"))

    def test_trail_bucket_logging_reports_a_shared_bucket_once(self):
        second = {**fx("cloudtrail-describe-trails-ok")["trailList"][0], "Name": "acme-notes-second",
                  "TrailARN": TRAIL_ARN.replace("acme-notes-trail", "acme-notes-second")}
        responses = {"trails": [(REGION, {"trailList": [fx("cloudtrail-describe-trails-ok")["trailList"][0], second]})],
                     **for_each("bucket_logging", [(TRAIL_BUCKET, fx("s3api-get-bucket-logging-disabled")),
                                                   (TRAIL_BUCKET, fx("s3api-get-bucket-logging-disabled"))])}
        (offender,) = evaluate("trail_bucket_logging", responses)
        self.assertEqual(offender["detail"]["trails"], ["acme-notes-trail", "acme-notes-second"])

    def hardening(self, versioning, policy):
        return merge(trails("cloudtrail-describe-trails-ok"),
                     for_each("versioning", [(TRAIL_BUCKET, versioning)]),
                     for_each("policy", [(TRAIL_BUCKET, policy)]))

    def test_trail_bucket_hardening_pass(self):
        responses = self.hardening(fx("s3api-get-bucket-versioning-enabled"), fx("s3api-get-bucket-policy-sourcearn"))
        self.assertEqual(evaluate("trail_bucket_hardening", responses), [])

    def test_trail_bucket_hardening_fail_reports_offenders(self):
        responses = self.hardening(fx("s3api-get-bucket-versioning-never"), fx("s3api-get-bucket-policy-no-sourcearn"))
        (offender,) = evaluate("trail_bucket_hardening", responses)
        self.assertEqual((offender["resource_id"], offender["region"]), (TRAIL_BUCKET, REGION))
        self.assertEqual(offender["detail"]["problems"],
                         ["versionado no habilitado", "la bucket policy de CloudTrail no restringe aws:SourceArn"])

    def test_trail_bucket_hardening_fail_without_bucket_policy(self):
        responses = self.hardening(fx("s3api-get-bucket-versioning-enabled"), {"__error__": "NoSuchBucketPolicy"})
        (offender,) = evaluate("trail_bucket_hardening", responses)
        self.assertEqual(offender["detail"]["problems"], ["el bucket no tiene bucket policy"])

    def test_trail_bucket_hardening_suspended_versioning_fails(self):
        responses = self.hardening({"Status": "Suspended"}, fx("s3api-get-bucket-policy-sourcearn"))
        (offender,) = evaluate("trail_bucket_hardening", responses)
        self.assertEqual(offender["detail"]["problems"], ["versionado no habilitado"])

    def test_trail_bucket_hardening_unreadable_calls_are_unverified_not_fail(self):
        good_v, good_p = fx("s3api-get-bucket-versioning-enabled"), fx("s3api-get-bucket-policy-sourcearn")
        for versioning, policy in (({"__error__": "ACCESS_DENIED"}, good_p), (good_v, {"__error__": "ACCESS_DENIED"}),
                                   ({"__error__": "ERROR"}, {"__error__": "NoSuchBucketPolicy"})):
            (entry,) = evaluate("trail_bucket_hardening", self.hardening(versioning, policy))
            self.assertEqual((entry["resource_id"], entry.get("unverified")), (TRAIL_BUCKET, True))
            self.assertIn(entry["detail"]["error_code"], ("ACCESS_DENIED", "ERROR"))

    def test_trail_bucket_hardening_missing_bucket_is_reported(self):
        responses = self.hardening({"__error__": "NoSuchBucket"}, {"__error__": "NoSuchBucket"})
        (offender,) = evaluate("trail_bucket_hardening", responses)
        self.assertEqual(offender["detail"]["problems"], ["el bucket no existe"])


class MetricFilterTests(unittest.TestCase):
    def responses(self, trail_fixture, filters_fixture):
        return {**trails(trail_fixture), "filters": [(REGION, fx(filters_fixture))]}

    def test_trail_cw_metric_filters_pass(self):
        responses = self.responses("cloudtrail-describe-trails-ok", "logs-describe-metric-filters-cis")
        self.assertEqual(evaluate("trail_cw_metric_filters", responses, catalog_check("LOG-007")["verify"]["params"]), [])

    def test_trail_cw_metric_filters_fail_reports_offenders(self):
        responses = self.responses("cloudtrail-describe-trails-ok", "logs-describe-metric-filters-partial")
        (offender,) = evaluate("trail_cw_metric_filters", responses, catalog_check("LOG-007")["verify"]["params"])
        self.assertEqual((offender["resource_id"], offender["region"]), ("acme-notes-trail", REGION))
        self.assertEqual(offender["detail"]["missing"], ["iam_policy_changes"])

    def test_trail_cw_metric_filters_fail_without_filters(self):
        responses = self.responses("cloudtrail-describe-trails-ok", "logs-describe-metric-filters-none")
        (offender,) = evaluate("trail_cw_metric_filters", responses, catalog_check("LOG-007")["verify"]["params"])
        self.assertEqual(offender["detail"]["missing"], ["unauthorized_api_calls", "root_usage", "iam_policy_changes"])

    def test_trail_cw_metric_filters_fail_without_cloudwatch_logs_integration(self):
        responses = self.responses("cloudtrail-describe-trails-no-cwl", "logs-describe-metric-filters-cis")
        (offender,) = evaluate("trail_cw_metric_filters", responses, catalog_check("LOG-007")["verify"]["params"])
        self.assertEqual((offender["resource_id"], offender["detail"]["reason"]),
                         ("account", "ningún trail multi-región envía sus logs a CloudWatch Logs"))

    def test_trail_cw_metric_filters_ignore_filters_of_other_log_groups(self):
        filters = fx("logs-describe-metric-filters-cis")
        for f in filters["metricFilters"]:
            f["logGroupName"] = "acme-notes-other"
        responses = {**trails("cloudtrail-describe-trails-ok"), "filters": [(REGION, filters)]}
        (offender,) = evaluate("trail_cw_metric_filters", responses, catalog_check("LOG-007")["verify"]["params"])
        self.assertEqual(len(offender["detail"]["missing"]), 3)


class FlowLogTests(unittest.TestCase):
    INVENTORY = [{"type": "vpc", "id": VPC_MAIN, "arn": "", "name": VPC_MAIN, "region": REGION, "tags": {}},
                 {"type": "vpc", "id": VPC_SECOND, "arn": "", "name": VPC_SECOND, "region": "eu-west-1", "tags": {}},
                 {"type": "subnet", "id": "subnet-1", "arn": "", "name": "subnet-1", "region": REGION, "tags": {}}]

    def responses(self, us_fixture, eu_fixture="ec2-describe-flow-logs-none"):
        return {"flow_logs": [(REGION, fx(us_fixture)), ("eu-west-1", fx(eu_fixture))], "__inventory__": self.INVENTORY}

    def test_vpc_flow_logs_pass(self):
        responses = self.responses("ec2-describe-flow-logs-vpc-main", "ec2-describe-flow-logs-vpc-main")
        responses["flow_logs"][1] = ("eu-west-1", {"FlowLogs": [{**fx("ec2-describe-flow-logs-vpc-main")["FlowLogs"][0],
                                                                  "ResourceId": VPC_SECOND}]})
        self.assertEqual(evaluate("vpc_flow_logs", responses), [])

    def test_vpc_flow_logs_fail_reports_offenders(self):
        (offender,) = evaluate("vpc_flow_logs", self.responses("ec2-describe-flow-logs-vpc-main"))
        self.assertEqual((offender["resource_id"], offender["region"]), (VPC_SECOND, "eu-west-1"))
        self.assertEqual(offender["detail"]["reason"], "sin flow logs")

    def test_vpc_flow_logs_failed_delivery_is_not_active(self):
        responses = self.responses("ec2-describe-flow-logs-vpc-main-failed")
        offenders = {o["resource_id"]: o for o in evaluate("vpc_flow_logs", responses)}
        self.assertEqual(sorted(offenders), [VPC_MAIN, VPC_SECOND])
        self.assertEqual(offenders[VPC_MAIN]["detail"]["flow_log_status"], "FAILED")

    def test_vpc_flow_logs_on_a_subnet_do_not_cover_the_vpc(self):
        responses = self.responses("ec2-describe-flow-logs-subnet-only")
        self.assertEqual(ids(evaluate("vpc_flow_logs", responses)), [VPC_MAIN, VPC_SECOND])

    def test_vpc_flow_logs_match_the_region_of_the_vpc(self):
        responses = {"flow_logs": [(REGION, fx("ec2-describe-flow-logs-none")),
                                   ("eu-west-1", fx("ec2-describe-flow-logs-vpc-main"))], "__inventory__": self.INVENTORY}
        self.assertEqual(ids(evaluate("vpc_flow_logs", responses)), [VPC_MAIN, VPC_SECOND])


class LifecycleTests(unittest.TestCase):
    INVENTORY = [{"type": "s3_bucket", "id": b, "arn": "", "name": b, "region": REGION, "tags": {}}
                 for b in (TRAIL_BUCKET, "acme-notes-access-logs", "acme-notes-data", "acme-notes-blog")]
    PARAMS = {"min_days": 365, "name_regex": "(^|[^a-z])logs?([^a-z]|$)", "now": NOW}

    def responses(self, **by_bucket):
        pairs = [(bucket, by_bucket.get(bucket, {"__error__": "NoSuchLifecycleConfiguration"})) for bucket in
                 (TRAIL_BUCKET, "acme-notes-access-logs", "acme-notes-data", "acme-notes-blog")]
        return merge(trails("cloudtrail-describe-trails-ok"), for_each("lifecycle", pairs), {"__inventory__": self.INVENTORY})

    def test_log_bucket_lifecycle_pass(self):
        responses = self.responses(**{TRAIL_BUCKET: fx("s3api-get-bucket-lifecycle-ok")})
        self.assertEqual(offending(evaluate("log_bucket_lifecycle", responses, self.PARAMS)), [])

    def test_log_bucket_lifecycle_fail_reports_offenders(self):
        responses = self.responses(**{TRAIL_BUCKET: fx("s3api-get-bucket-lifecycle-short")})
        (offender,) = offending(evaluate("log_bucket_lifecycle", responses, self.PARAMS))
        self.assertEqual((offender["resource_id"], offender["region"]), (TRAIL_BUCKET, REGION))
        self.assertEqual(offender["detail"]["rules"], [{"rule": "expire-90", "expires_after_days": 90}])

    def test_log_bucket_lifecycle_unreadable_log_bucket_is_unverified(self):
        responses = self.responses(**{TRAIL_BUCKET: {"__error__": "ACCESS_DENIED"}})
        (entry,) = [o for o in evaluate("log_bucket_lifecycle", responses, self.PARAMS) if o.get("unverified")]
        self.assertEqual((entry["resource_id"], entry["detail"]["error_code"]), (TRAIL_BUCKET, "ACCESS_DENIED"))

    def test_log_bucket_lifecycle_unreadable_non_log_bucket_stays_not_applicable(self):
        responses = self.responses(**{"acme-notes-data": {"__error__": "ACCESS_DENIED"}})
        self.assertEqual([o for o in evaluate("log_bucket_lifecycle", responses, self.PARAMS) if o.get("unverified")], [])

    def test_log_bucket_lifecycle_buckets_without_lifecycle_pass(self):
        self.assertEqual(offending(evaluate("log_bucket_lifecycle", self.responses(), self.PARAMS)), [])

    def test_log_bucket_lifecycle_identifies_log_buckets_by_name(self):
        short = fx("s3api-get-bucket-lifecycle-short")
        responses = self.responses(**{"acme-notes-access-logs": short})
        self.assertEqual(ids(offending(evaluate("log_bucket_lifecycle", responses, self.PARAMS))), ["acme-notes-access-logs"])

    def test_log_bucket_lifecycle_ignores_buckets_that_are_not_log_buckets(self):
        short = fx("s3api-get-bucket-lifecycle-short")
        responses = self.responses(**{"acme-notes-data": short, "acme-notes-blog": short})
        self.assertEqual(offending(evaluate("log_bucket_lifecycle", responses, self.PARAMS)), [])

    def test_log_bucket_lifecycle_trail_bucket_counts_even_without_log_in_its_name(self):
        short = fx("s3api-get-bucket-lifecycle-short")
        trail = {**fx("cloudtrail-describe-trails-ok")["trailList"][0], "S3BucketName": "acme-notes-data"}
        responses = {**self.responses(**{"acme-notes-data": short}), "trails": [(REGION, {"trailList": [trail]})]}
        self.assertEqual(ids(offending(evaluate("log_bucket_lifecycle", responses, self.PARAMS))), ["acme-notes-data"])

    def test_log_bucket_lifecycle_non_log_buckets_are_reported_as_not_applicable(self):
        found = not_applicable(evaluate("log_bucket_lifecycle", self.responses(), self.PARAMS))
        self.assertEqual(found, ["acme-notes-data", "acme-notes-blog"])

    def rule_responses(self, rule):
        return self.responses(**{TRAIL_BUCKET: {"Rules": [rule]}})

    def test_log_bucket_lifecycle_days_boundary(self):
        for days, expected in ((364, [TRAIL_BUCKET]), (365, []), (366, [])):
            responses = self.rule_responses({"ID": "r", "Status": "Enabled", "Expiration": {"Days": days}})
            self.assertEqual(ids(offending(evaluate("log_bucket_lifecycle", responses, self.PARAMS))), expected, days)

    def test_log_bucket_lifecycle_fixed_date_boundary(self):
        now = datetime.fromisoformat(NOW)
        for delta, expected in ((timedelta(days=365), []), (timedelta(days=365) - timedelta(hours=1), [TRAIL_BUCKET])):
            responses = self.rule_responses({"ID": "r", "Status": "Enabled", "Expiration": {"Date": (now + delta).isoformat()}})
            self.assertEqual(ids(offending(evaluate("log_bucket_lifecycle", responses, self.PARAMS))), expected, delta)

    def test_log_bucket_lifecycle_disabled_and_noncurrent_rules_are_ignored(self):
        rules = [{"ID": "off", "Status": "Disabled", "Expiration": {"Days": 1}},
                 {"ID": "versions", "Status": "Enabled", "NoncurrentVersionExpiration": {"NoncurrentDays": 7}},
                 {"ID": "multipart", "Status": "Enabled", "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}}]
        self.assertEqual(offending(evaluate("log_bucket_lifecycle", self.responses(**{TRAIL_BUCKET: {"Rules": rules}}), self.PARAMS)), [])


class LoadBalancerAndWafTests(unittest.TestCase):
    INVENTORY = [{"type": "elbv2", "id": "acme-notes-alb", "arn": ALB_ARN, "name": "acme-notes-alb", "region": REGION, "tags": {}},
                 {"type": "elbv2", "id": "acme-notes-nlb", "arn": NLB_ARN, "name": "acme-notes-nlb", "region": REGION, "tags": {}},
                 {"type": "wafv2_web_acl", "id": "acme-notes-web-acl", "arn": WEB_ACL_ARN, "name": "acme-notes-web-acl",
                  "region": REGION, "tags": {}}]

    def alb(self, fixture, arn=ALB_ARN):
        return {**for_each("attrs", [(arn, fx(fixture))]), "__inventory__": self.INVENTORY}

    def test_alb_access_logs_pass(self):
        self.assertEqual(offending(evaluate("alb_access_logs", self.alb("elbv2-describe-load-balancer-attributes-logs-on"))), [])

    def test_alb_access_logs_fail_reports_offenders(self):
        (offender,) = offending(evaluate("alb_access_logs", self.alb("elbv2-describe-load-balancer-attributes-logs-off")))
        self.assertEqual((offender["resource_id"], offender["region"]), ("acme-notes-alb", REGION))
        self.assertEqual(offender["detail"]["arn"], ALB_ARN)

    def test_alb_access_logs_network_load_balancers_are_not_evaluated(self):
        self.assertEqual(offending(evaluate("alb_access_logs", self.alb("elbv2-describe-load-balancer-attributes-logs-off", NLB_ARN))), [])

    def test_alb_access_logs_network_load_balancers_are_reported_as_not_applicable(self):
        responses = self.alb("elbv2-describe-load-balancer-attributes-logs-off", NLB_ARN)
        self.assertEqual(not_applicable(evaluate("alb_access_logs", responses)), ["acme-notes-nlb"])

    def waf(self, data):
        return {**for_each("logging", [(WEB_ACL_ARN, data)]), "__inventory__": self.INVENTORY}

    def test_waf_logging_pass(self):
        self.assertEqual(evaluate("waf_logging", self.waf(fx("wafv2-get-logging-configuration-on"))), [])

    def test_waf_logging_fail_reports_offenders(self):
        (offender,) = evaluate("waf_logging", self.waf({"__error__": "WAFNonexistentItemException"}))
        self.assertEqual((offender["resource_id"], offender["region"]), ("acme-notes-web-acl", REGION))
        self.assertEqual(offender["detail"]["arn"], WEB_ACL_ARN)

    def test_waf_logging_fail_without_destinations(self):
        (offender,) = evaluate("waf_logging", self.waf(fx("wafv2-get-logging-configuration-empty")))
        self.assertEqual(offender["resource_id"], "acme-notes-web-acl")


@unittest.skipIf(jmespath is None, "jmespath is not installed")
class JmespathExpressionTests(unittest.TestCase):
    """The catalog's --query expressions, run against raw (unqueried) AWS output."""

    @staticmethod
    def query(check_id, raw):
        return jmespath.search(catalog_check(check_id)["verify"]["offenders"], fx(raw))

    def test_log_002_reports_trails_without_validation(self):
        self.assertEqual(self.query("LOG-002", "cloudtrail-describe-trails-raw"),
                         fx("cloudtrail-describe-trails-validation-offenders"))

    def test_log_003_reports_trails_without_kms_key(self):
        self.assertEqual(self.query("LOG-003", "cloudtrail-describe-trails-raw"),
                         fx("cloudtrail-describe-trails-kms-offenders"))

    def test_log_009_reports_retention_below_365_only(self):
        self.assertEqual(self.query("LOG-009", "logs-describe-log-groups-raw"), fx("logs-describe-log-groups-offenders"))

    def test_log_009_retention_boundary(self):
        for days, expected in ((364, 1), (365, 0), (366, 0)):
            groups = {"logGroups": [{"logGroupName": "g", "retentionInDays": days}]}
            result = jmespath.search(catalog_check("LOG-009")["verify"]["offenders"], groups)
            self.assertEqual(len(result), expected, days)

    def test_log_009_group_without_retention_passes(self):
        groups = {"logGroups": [{"logGroupName": "never-expires"}]}
        self.assertEqual(jmespath.search(catalog_check("LOG-009")["verify"]["offenders"], groups), [])

    def test_log_013_reports_clusters_without_audit_logs(self):
        expression = catalog_check("LOG-013")["verify"]["offenders"]
        self.assertEqual(jmespath.search(expression, fx("eks-describe-cluster-audit-off")),
                         fx("eks-describe-cluster-audit-offenders"))
        self.assertEqual(jmespath.search(expression, fx("eks-describe-cluster-audit-partial")),
                         [{"detail": {"logging": fx("eks-describe-cluster-audit-partial")["cluster"]["logging"]["clusterLogging"]}}])
        self.assertEqual(jmespath.search(expression, fx("eks-describe-cluster-audit-on")), [])


@unittest.skipIf(jmespath is None, "jmespath is not installed")
class CatalogJmespathQueryTests(unittest.TestCase):
    """The other jmespath `offenders` queries of the catalog (the LOG ones are above), against synthetic AWS-shaped output."""

    COVERED = ("CMP-001", "CMP-003", "DAT-003", "DAT-004", "DAT-011", "DET-007", "EML-001", "ENC-002", "ENC-004", "ENC-008",
               "IAM-001", "IAM-003", "IAM-014", "IAM-015", "LOG-002", "LOG-003", "LOG-009", "LOG-013")  # LOG-* in the class above

    @staticmethod
    def query(check_id, data):
        for path in sorted((REFS / "checks").glob("*.json")):
            for check in json.loads(path.read_text(encoding="utf-8"))["checks"]:
                if check["id"] == check_id:
                    return jmespath.search(check["verify"]["offenders"], data)
        raise AssertionError(check_id)

    def test_every_jmespath_query_of_the_catalog_compiles_and_has_a_test(self):
        found = set()
        for path in (REFS / "checks").glob("*.json"):
            for check in json.loads(path.read_text(encoding="utf-8"))["checks"]:
                if check["verify"]["evaluator"] == "jmespath":
                    jmespath.compile(check["verify"]["offenders"])
                    found.add(check["id"])
        self.assertEqual(sorted(found), sorted(self.COVERED), "a jmespath check was added or removed: update the tests")

    def test_cmp_001_instances_without_imdsv2(self):
        data = {"Reservations": [{"Instances": [
            {"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": "optional"}},
            {"InstanceId": "i-2", "MetadataOptions": {"HttpTokens": "required"}}]}]}
        self.assertEqual(self.query("CMP-001", data), [{"resource_id": "i-1", "detail": {"http_tokens": "optional"}}])

    def test_cmp_003_instances_without_instance_profile(self):
        data = {"Reservations": [{"Instances": [
            {"InstanceId": "i-1", "IamInstanceProfile": None, "Tags": [{"Key": "Name", "Value": "web"}]},
            {"InstanceId": "i-2", "IamInstanceProfile": {"Arn": "arn:aws:iam::111122223333:instance-profile/p"}}]}]}
        self.assertEqual(self.query("CMP-003", data), [{"resource_id": "i-1", "detail": {"name": "web"}}])

    def test_dat_003_and_004_rds_flags(self):
        data = {"DBInstances": [
            {"DBInstanceIdentifier": "a", "AutoMinorVersionUpgrade": False, "DeletionProtection": False, "Engine": "postgres",
             "EngineVersion": "16.3", "DBClusterIdentifier": None},
            {"DBInstanceIdentifier": "b", "AutoMinorVersionUpgrade": True, "DeletionProtection": True, "Engine": "postgres"}]}
        self.assertEqual(self.query("DAT-003", data),
                         [{"resource_id": "a", "detail": {"engine": "postgres", "engine_version": "16.3"}}])
        self.assertEqual(self.query("DAT-004", data), [{"resource_id": "a", "detail": {"engine": "postgres", "cluster": None}}])

    def test_dat_011_replication_groups_without_multi_az(self):
        data = {"ReplicationGroups": [{"ReplicationGroupId": "r1", "MultiAZ": "disabled", "AutomaticFailover": "disabled"},
                                      {"ReplicationGroupId": "r2", "MultiAZ": "enabled", "AutomaticFailover": "enabled"}]}
        self.assertEqual(self.query("DAT-011", data),
                         [{"resource_id": "r1", "detail": {"multi_az": "disabled", "automatic_failover": "disabled"}}])

    def test_det_007_active_critical_findings(self):
        data = {"findings": [{"resources": [{"id": "i-1"}], "severity": "HIGH", "title": "t",
                              "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2026-0001"}}]}
        self.assertEqual(self.query("DET-007", data),
                         [{"resource_id": "i-1", "detail": {"severity": "HIGH", "title": "t", "vulnerability": "CVE-2026-0001"}}])
        self.assertEqual(self.query("DET-007", {"findings": []}), [])

    def test_eml_001_identity_verification_and_dkim(self):
        good = {"IdentityType": "DOMAIN", "VerifiedForSendingStatus": True,
                "DkimAttributes": {"Status": "SUCCESS", "SigningEnabled": True, "SigningAttributesOrigin": "AWS_SES"}}
        self.assertEqual(self.query("EML-001", good), [])
        self.assertEqual(len(self.query("EML-001", {**good, "VerifiedForSendingStatus": False})), 1)
        (bad,) = self.query("EML-001", {**good, "DkimAttributes": {**good["DkimAttributes"], "Status": "PENDING"}})
        self.assertEqual(bad["detail"]["dkim_status"], "PENDING")
        address = {"IdentityType": "EMAIL_ADDRESS", "VerifiedForSendingStatus": True, "DkimAttributes": {"Status": "NOT_STARTED"}}
        self.assertEqual(self.query("EML-001", address), [])

    def test_enc_002_unencrypted_volumes(self):
        data = {"Volumes": [{"VolumeId": "v1", "Encrypted": False, "State": "in-use", "Size": 8, "VolumeType": "gp3",
                             "Attachments": [{"InstanceId": "i-1"}]},
                            {"VolumeId": "v2", "Encrypted": True}]}
        self.assertEqual(self.query("ENC-002", data), [{"resource_id": "v1", "detail": {
            "State": "in-use", "Size": 8, "VolumeType": "gp3", "Instances": ["i-1"]}}])

    def test_enc_004_unencrypted_file_systems(self):
        data = {"FileSystems": [{"FileSystemId": "fs-1", "Encrypted": False, "Name": "n", "LifeCycleState": "available"},
                                {"FileSystemId": "fs-2", "Encrypted": True}]}
        self.assertEqual(self.query("ENC-004", data), [{"resource_id": "fs-1", "detail": {"Name": "n", "LifeCycleState": "available"}}])

    def test_enc_008_secrets_without_rotation(self):
        data = {"SecretList": [{"Name": "a", "RotationEnabled": True}, {"Name": "b", "LastChangedDate": 1}]}
        self.assertEqual(self.query("ENC-008", data), [{"resource_id": "b", "detail": {"RotationEnabled": None, "LastChangedDate": 1}}])

    def test_iam_001_root_without_mfa(self):
        self.assertEqual(self.query("IAM-001", {"SummaryMap": {"AccountMFAEnabled": 0}}),
                         [{"resource_id": "root", "detail": {"AccountMFAEnabled": 0}}])
        self.assertEqual(self.query("IAM-001", {"SummaryMap": {"AccountMFAEnabled": 1}}), [])

    def test_iam_003_root_access_keys(self):
        self.assertEqual(len(self.query("IAM-003", {"SummaryMap": {"AccountAccessKeysPresent": 1}})), 1)
        self.assertEqual(self.query("IAM-003", {"SummaryMap": {"AccountAccessKeysPresent": 0}}), [])

    def test_iam_014_support_role_missing(self):
        self.assertEqual(self.query("IAM-014", {"PolicyRoles": []}),
                         [{"resource_id": "account", "detail": {"policy": "AWSSupportAccess", "roles": 0}}])
        self.assertEqual(self.query("IAM-014", {"PolicyRoles": [{"RoleName": "support"}]}), [])

    def test_iam_015_no_active_analyzer(self):
        self.assertEqual(self.query("IAM-015", {"analyzers": [{"status": "CREATING", "type": "ACCOUNT"},
                                                              {"status": "ACTIVE", "type": "ACCOUNT_UNUSED_ACCESS"}]}),
                         [{"detail": {"active_analyzers": 0}}])
        self.assertEqual(self.query("IAM-015", {"analyzers": [{"status": "ACTIVE", "type": "ORGANIZATION"}]}), [])


class LoggingCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks = json.loads(LOGGING_JSON.read_text(encoding="utf-8"))["checks"]

    def test_logging_catalog_valid(self):
        data = json.loads(LOGGING_JSON.read_text(encoding="utf-8"))
        for check in data["checks"]:
            check.setdefault("domain", data["domain"])
        tsc_ids, iso_ids = catalog.load_frameworks(REFS / "frameworks")
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        self.assertEqual(catalog.validate(data["checks"], tsc_ids, iso_ids, drata), [])
        self.assertEqual([c["id"] for c in data["checks"]], [f"LOG-{n:03d}" for n in range(1, 14)])

    def test_every_python_evaluator_is_registered(self):
        for check in self.checks:
            kind, _, name = check["verify"]["evaluator"].partition(":")
            if kind == "python":
                self.assertIn(name, evaluators.EVALUATORS, check["id"])

    def test_steps_are_not_numbered_by_hand(self):
        for check in self.checks:
            for step in check["remediation"]["steps"]:
                self.assertNotRegex(step, r"^\d+\.\s", check["id"])

    def test_remediation_commands_follow_cloudshell_rules(self):
        for check in self.checks:
            rem = check["remediation"]
            for command in rem["commands"]:
                self.assertTrue(command.startswith('REGION="{region}"\nACCOUNT_ID="{account_id}"\n'), check["id"])
                self.assertNotIn("set -e", command, check["id"])
            self.assertTrue(rem["verify_after"].startswith("aws "), check["id"])
            self.assertTrue(rem["commands"], check["id"])

    def test_lookups_run_before_the_command_that_uses_them(self):
        (alb,) = catalog_check("LOG-011")["remediation"]["commands"]
        self.assertLess(alb.index("LB_ARN=$(aws elbv2 describe-load-balancers"), alb.index('modify-load-balancer-attributes --load-balancer-arn "$LB_ARN"'))
        waf = "\n".join(catalog_check("LOG-012")["remediation"]["commands"])
        self.assertLess(waf.index("WEB_ACL_ARN=$(aws wafv2 list-web-acls"), waf.index('ResourceArn="$WEB_ACL_ARN"'))

    def test_waf_logging_is_enabled_only_after_the_log_group_has_retention(self):
        waf = "\n".join(catalog_check("LOG-012")["remediation"]["commands"])
        self.assertRegex(waf, r"put-retention-policy [^\n]*&& aws wafv2 put-logging-configuration")

    def test_cloudtrail_is_started_only_after_it_was_created(self):
        (create, _) = catalog_check("LOG-001")["remediation"]["commands"]
        self.assertRegex(create, r"create-trail [^\n]*&& aws cloudtrail start-logging")

    def test_event_selectors_are_reviewed_in_a_separate_block_before_they_are_replaced(self):
        (review, replace) = catalog_check("LOG-004")["remediation"]["commands"]
        self.assertIn("get-event-selectors", review)
        self.assertNotIn("put-event-selectors", review)
        self.assertIn("put-event-selectors", replace)

    def test_policy_and_lifecycle_replacements_come_after_a_review_block(self):
        for check_id, replacing in (("LOG-006", "put-bucket-policy"), ("LOG-010", "put-bucket-lifecycle-configuration")):
            commands = catalog_check(check_id)["remediation"]["commands"]
            index = next(i for i, c in enumerate(commands) if replacing in c)
            self.assertGreater(index, 0, check_id)
            self.assertNotIn(replacing, commands[index - 1], check_id)

    def test_bucket_config_calls_declare_ok_errors(self):
        expected = {("LOG-005", "bucket_logging"): ["NoSuchBucket"],
                    ("LOG-006", "versioning"): ["NoSuchBucket"],
                    ("LOG-006", "policy"): ["NoSuchBucketPolicy", "NoSuchBucket"],
                    ("LOG-010", "lifecycle"): ["NoSuchLifecycleConfiguration", "NoSuchBucket"],
                    ("LOG-012", "logging"): ["WAFNonexistentItemException"]}
        for (check_id, call_name), codes in expected.items():
            call = next(c for c in catalog_check(check_id)["verify"]["calls"] if c["name"] == call_name)
            self.assertEqual(call["ok_errors"], codes, (check_id, call_name))

    def test_log_009_command_sets_365_day_retention_and_warns_about_cost(self):
        rem = catalog_check("LOG-009")["remediation"]
        (command,) = rem["commands"]
        self.assertIn('aws logs put-retention-policy --log-group-name "{resource_id}" --retention-in-days 365', command)
        self.assertRegex(rem["notes"], r"(?i)costo")

    def test_log_009_threshold_is_in_the_query(self):
        self.assertIn("`365`", catalog_check("LOG-009")["verify"]["offenders"])

    def test_drata_mapped_checks_resolve_from_the_dcf_file(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        expected = {"LOG-002": 205, "LOG-003": 222, "LOG-004": 226, "LOG-005": 221, "LOG-008": 224, "LOG-013": 310}
        for check_id, test in expected.items():
            resolved = catalog.resolve_mappings(catalog_check(check_id), drata)
            self.assertEqual([m["test"] for m in resolved["drata"]], [test], check_id)
            self.assertTrue(resolved["tsc"] and all(t["sourced"] == catalog.DCF_SOURCE for t in resolved["tsc"]), check_id)

    def test_checks_without_a_resolvable_drata_test_carry_inferred_mappings(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        for check_id in ("LOG-001", "LOG-006", "LOG-007", "LOG-009", "LOG-010", "LOG-011", "LOG-012"):
            resolved = catalog.resolve_mappings(catalog_check(check_id), drata)
            self.assertTrue(resolved["tsc"] and resolved["iso27001_2022"], check_id)
            self.assertTrue(all(m["sourced"] is False for m in resolved["tsc"] + resolved["iso27001_2022"]), check_id)
        log_009 = catalog_check("LOG-009")["mappings"]["drata"]
        self.assertEqual([m["test"] for m in log_009], [111])

    def test_severities_follow_the_brief(self):
        expected = {"LOG-001": "high", "LOG-002": "high", "LOG-003": "high", "LOG-004": "high", "LOG-005": "high",
                    "LOG-006": "medium", "LOG-007": "medium", "LOG-008": "high", "LOG-009": "high", "LOG-010": "medium",
                    "LOG-011": "medium", "LOG-012": "medium", "LOG-013": "high"}
        self.assertEqual({c["id"]: c["severity"] for c in self.checks}, expected)

    def test_remediation_kinds_follow_the_brief(self):
        expected = {"LOG-001": "cli_with_decision", "LOG-002": "cli", "LOG-003": "planned_change",
                    "LOG-004": "cli_with_decision", "LOG-005": "cli_with_decision", "LOG-006": "cli_with_decision",
                    "LOG-007": "planned_change", "LOG-008": "cli_with_decision", "LOG-009": "cli",
                    "LOG-010": "cli_with_decision", "LOG-011": "cli_with_decision", "LOG-012": "cli_with_decision",
                    "LOG-013": "cli"}
        self.assertEqual({c["id"]: c["remediation"]["kind"] for c in self.checks}, expected)


class LoggingCollectTests(unittest.TestCase):
    """The whole logging catalog through collect.main with a fake AWS: wiring of calls, for_each, args and ok_errors."""

    TYPES = ("cloudtrail_trail", "vpc", "log_group", "s3_bucket", "elbv2", "wafv2_web_acl", "eks_cluster")

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        (cls.tmp / "checks").mkdir()
        shutil.copy(LOGGING_JSON, cls.tmp / "checks" / "logging.json")
        specs = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))
        (cls.tmp / "inventory.json").write_text(json.dumps({t: specs[t] for t in cls.TYPES}), encoding="utf-8")
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
        core = lambda name: ok(load_fixture(f"aws/core/{name}.json"))
        log = lambda name: ok(fx(name))
        no_policy = err("An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation: The bucket policy does not exist")
        no_lifecycle = err("An error occurred (NoSuchLifecycleConfiguration) when calling the GetBucketLifecycleConfiguration operation: not found")
        no_waf_logging = err("An error occurred (WAFNonexistentItemException) when calling the GetLoggingConfiguration operation: not found")
        buckets = {"Buckets": [{"Name": b} for b in (TRAIL_BUCKET, "acme-notes-data", "acme-notes-access-logs")]}
        vpcs = {"Vpcs": [{"VpcId": VPC_MAIN}, {"VpcId": VPC_SECOND}]}
        lbs = {"LoadBalancers": [{"LoadBalancerName": "acme-notes-alb", "LoadBalancerArn": ALB_ARN},
                                 {"LoadBalancerName": "acme-notes-nlb", "LoadBalancerArn": NLB_ARN}]}
        web_acls = {"WebACLs": [{"Name": "acme-notes-web-acl", "ARN": WEB_ACL_ARN}]}
        return [
            ("sts", "get-caller-identity", None, "", core("sts-get-caller-identity")),
            ("ec2", "describe-regions", None, "", core("ec2-describe-regions")),
            ("iam", "list-attached-user-policies", None, "", ok({"AttachedPolicies": []})),
            ("ec2", "describe-vpcs", None, "", ok(vpcs)),
            ("s3api", "list-buckets", None, "", ok(buckets)),
            ("elbv2", "describe-load-balancers", None, "", ok(lbs)),
            ("wafv2", "list-web-acls", None, "", ok(web_acls)),
            ("eks", "list-clusters", None, "", ok({"clusters": ["acme-notes-eks"]})),
            # LOG-002 / LOG-003 use --query; the inventory and the other checks list trails without it
            ("cloudtrail", "describe-trails", None, "LogFileValidationEnabled", log("cloudtrail-describe-trails-validation-offenders")),
            ("cloudtrail", "describe-trails", None, "KmsKeyId", ok([])),
            ("cloudtrail", "describe-trails", "eu-west-1", "", log("cloudtrail-describe-trails-empty")),
            ("cloudtrail", "describe-trails", None, "", log("cloudtrail-describe-trails-ok")),
            ("cloudtrail", "get-trail-status", None, TRAIL_ARN, log("cloudtrail-get-trail-status-logging")),
            ("cloudtrail", "get-event-selectors", None, TRAIL_ARN, log("cloudtrail-get-event-selectors-advanced-write-only")),
            ("s3api", "get-bucket-logging", None, f"--bucket {TRAIL_BUCKET}", log("s3api-get-bucket-logging-disabled")),
            ("s3api", "get-bucket-versioning", None, f"--bucket {TRAIL_BUCKET}", log("s3api-get-bucket-versioning-enabled")),
            ("s3api", "get-bucket-policy", None, f"--bucket {TRAIL_BUCKET}", no_policy),
            ("logs", "describe-metric-filters", "us-east-1", "", log("logs-describe-metric-filters-partial")),
            ("logs", "describe-metric-filters", "eu-west-1", "", log("logs-describe-metric-filters-none")),
            ("ec2", "describe-flow-logs", "us-east-1", "", log("ec2-describe-flow-logs-vpc-main")),
            ("ec2", "describe-flow-logs", "eu-west-1", "", log("ec2-describe-flow-logs-none")),
            ("logs", "describe-log-groups", None, "--query", log("logs-describe-log-groups-offenders")),
            ("logs", "describe-log-groups", None, "", log("logs-describe-log-groups-raw")),
            ("s3api", "get-bucket-lifecycle-configuration", None, f"--bucket {TRAIL_BUCKET}", log("s3api-get-bucket-lifecycle-short")),
            ("s3api", "get-bucket-lifecycle-configuration", None, "acme-notes-access-logs", log("s3api-get-bucket-lifecycle-ok")),
            ("s3api", "get-bucket-lifecycle-configuration", None, "acme-notes-data", no_lifecycle),
            ("elbv2", "describe-load-balancer-attributes", None, ALB_ARN, log("elbv2-describe-load-balancer-attributes-logs-off")),
            ("elbv2", "describe-load-balancer-attributes", None, NLB_ARN, log("elbv2-describe-load-balancer-attributes-logs-off")),
            ("wafv2", "get-logging-configuration", None, WEB_ACL_ARN, no_waf_logging),
            ("eks", "describe-cluster", None, "--query", log("eks-describe-cluster-audit-offenders")),
        ]

    def rows(self, check_id):
        return [(r["status"], r["resource_id"], r["region"]) for r in self.result["results"] if r["check_id"] == check_id]

    def test_run_succeeds_and_nothing_is_unverified(self):
        self.assertEqual(self.code, 0)
        unverified = [(r["check_id"], r["detail"]) for r in self.result["results"] if r["status"] == "NO_VERIFICADO"]
        self.assertEqual(unverified, [])

    def test_trail_checks_outcomes(self):
        self.assertEqual(self.rows("LOG-001"), [("PASS", "account", None)])
        self.assertEqual(self.rows("LOG-002"), [("FAIL", "acme-notes-audit", REGION), ("FAIL", "acme-notes-legacy", REGION),
                                                ("PASS", "acme-notes-trail", REGION)])
        self.assertEqual(self.rows("LOG-003"), [("PASS", "acme-notes-trail", REGION)])
        self.assertEqual(self.rows("LOG-004"), [("FAIL", "account", REGION)])
        self.assertEqual(self.rows("LOG-005"), [("FAIL", TRAIL_BUCKET, REGION)])
        self.assertEqual(self.rows("LOG-006"), [("FAIL", TRAIL_BUCKET, REGION)])
        self.assertEqual(self.rows("LOG-007"), [("FAIL", "acme-notes-trail", REGION)])

    def test_resource_checks_outcomes(self):
        self.assertEqual(self.rows("LOG-008"), [("PASS", VPC_MAIN, REGION), ("FAIL", VPC_SECOND, REGION)])
        self.assertEqual(self.rows("LOG-009"), [("PASS", "/aws/ecs/acme-notes-web", REGION),
                                                ("FAIL", "/aws/ecs/acme-notes-worker", REGION),
                                                ("FAIL", "/aws/lambda/acme-notes-api", REGION),
                                                ("PASS", "acme-notes-cloudtrail", REGION)])
        self.assertEqual(self.rows("LOG-010"), [("PASS", "acme-notes-access-logs", REGION), ("FAIL", TRAIL_BUCKET, REGION)])
        # the NLB and the non-log buckets (LOG-010 above) are not applicable: no PASS and no FAIL row (R20)
        self.assertEqual(self.rows("LOG-011"), [("FAIL", "acme-notes-alb", REGION)])
        self.assertEqual(self.rows("LOG-012"), [("FAIL", "acme-notes-web-acl", REGION)])
        self.assertEqual(self.rows("LOG-013"), [("FAIL", "acme-notes-eks", REGION)])

    def test_only_read_only_calls_were_made(self):
        for argv in self.runner.calls:
            self.assertTrue(argv[2].startswith(("get-", "list-", "describe-")), argv)

    def test_for_each_calls_get_one_value_per_item(self):
        waf = [a for a in self.runner.calls if a[2] == "get-logging-configuration"]
        self.assertEqual([a[a.index("--resource-arn") + 1] for a in waf], [WEB_ACL_ARN])
        eks = [a for a in self.runner.calls if a[1:3] == ["eks", "describe-cluster"]]
        self.assertEqual([a[a.index("--name") + 1] for a in eks], ["acme-notes-eks"])


if __name__ == "__main__":
    unittest.main()
