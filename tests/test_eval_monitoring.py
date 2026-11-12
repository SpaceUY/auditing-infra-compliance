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
from test_eval_iam import RuleRunner, err, ok

MONITORING_JSON = SKILL_DIR / "references" / "checks" / "monitoring.json"
REFS = SKILL_DIR / "references"
REGION = "us-east-1"
OTHER = "eu-west-1"
ACCOUNT = "111122223333"
TOPIC = f"arn:aws:sns:{REGION}:{ACCOUNT}:acme-notes-alerts"
LB_ARN = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/acme-notes-alb/50dc6c495c0c9188"
LB_DIM = "app/acme-notes-alb/50dc6c495c0c9188"
NLB_ARN = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/net/acme-notes-nlb/6d0ecf831eec9f09"
QUEUE_URL = f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/acme-notes-jobs"
WEB_I, SOLO_I = "i-0a1b2c3d4e5f60718", "i-0b2c3d4e5f6071829"
METRIC_CHECKS = {"MON-001": ("AWS/RDS", ["CPUUtilization"]), "MON-002": ("AWS/RDS", ["FreeStorageSpace"]),
                 "MON-003": ("AWS/RDS", ["ReadIOPS", "WriteIOPS"]), "MON-004": ("AWS/RDS", ["FreeableMemory"]),
                 "MON-005": ("AWS/EC2", ["CPUUtilization"]),
                 "MON-006": ("AWS/ApplicationELB", ["HTTPCode_Target_5XX_Count", "UnHealthyHostCount", "TargetResponseTime"]),
                 "MON-007": ("AWS/SQS", ["ApproximateAgeOfOldestMessage"]), "MON-008": ("AWS/Lambda", ["Errors"])}


def fx(name):
    return load_fixture(f"aws/monitoring/{name}.json")


def subs(kind):
    return fx(f"sns-list-subscriptions-by-topic-{kind}")


def catalog_check(check_id):
    data = json.loads(MONITORING_JSON.read_text(encoding="utf-8"))
    return next(c for c in data["checks"] if c["id"] == check_id)


def params_of(check_id):
    return catalog_check(check_id)["verify"]["params"]


def item(type_, id_, region=REGION, arn="", tags=None):
    return {"type": type_, "id": id_, "arn": arn, "name": id_, "region": region, "tags": tags or {}}


def rds(name="acme-notes-db", region=REGION):
    return item("rds_instance", name, region, f"arn:aws:rds:{region}:{ACCOUNT}:db:{name}")


def alarm(metric, dims, ns="AWS/RDS", name=None, actions=(TOPIC,), enabled=True, region=REGION, account=ACCOUNT):
    name = name or f"alarm-{metric}"
    return {"AlarmName": name, "AlarmArn": f"arn:aws:cloudwatch:{region}:{account}:alarm:{name}", "ActionsEnabled": enabled,
            "AlarmActions": list(actions), "Namespace": ns, "MetricName": metric,
            "Dimensions": [{"Name": n, "Value": v} for n, v in dims.items()]}


def db_alarm(metric, db="acme-notes-db", **kwargs):
    return alarm(metric, {"DBInstanceIdentifier": db}, **kwargs)


def build(alarms, inventory, topics=None, region=REGION):
    """responses of the two calls: the alarms of `region` and one subscriptions answer per topic ({topic arn: data}).
    By default every SNS topic named by an alarm of the same region answers 'confirmed'."""
    documents = alarms if isinstance(alarms, dict) else {region: alarms}
    responses = {"alarms": [(r, {"MetricAlarms": a}) for r, a in documents.items()]}
    wanted = [(r, t) for r, a in documents.items() for al in a for t in al["AlarmActions"]]
    answers = {key: subs("confirmed") for key in dict.fromkeys(wanted)}
    answers.update({(region, arn) if isinstance(arn, str) else arn: data for arn, data in (topics or {}).items()})
    responses["subs"] = [(r, data) for (r, _), data in answers.items()]
    responses["__for_each__"] = {"subs": [arn for (_, arn) in answers]}
    responses["__inventory__"] = inventory
    return responses


def evaluate(responses, check_id="MON-001"):
    return evaluators.EVALUATORS["alarm_coverage"](responses, params_of(check_id))


def ids(offenders):
    return [o["resource_id"] for o in offenders]


def flags(offenders):
    return [(o["resource_id"], "not_applicable" if o.get("not_applicable") else "unverified" if o.get("unverified") else "offender")
            for o in offenders]


def covered(check_id):
    """(alarms, inventory) with the fully covered Acme Notes resources of the check's type, from the shared fixture."""
    inventory = {"MON-005": [item("ec2_instance", WEB_I, tags={"aws:autoscaling:groupName": "acme-notes-web"}),
                             item("ec2_instance", SOLO_I)],
                 "MON-006": [item("elbv2", "acme-notes-alb", arn=LB_ARN)],
                 "MON-007": [item("sqs_queue", QUEUE_URL)],
                 "MON-008": [item("lambda_function", "acme-notes-resizer")],
                 "MON-009": [item("dynamodb_table", "acme-notes-sessions"), item("elasticache_group", "acme-notes-cache")]
                 }.get(check_id, [rds()])
    return fx("cloudwatch-describe-alarms-covered")["MetricAlarms"], inventory


class AlarmCoveragePassTests(unittest.TestCase):
    def test_alarm_coverage_pass(self):
        for check_id in (*METRIC_CHECKS, "MON-009"):
            alarms, inventory = covered(check_id)
            self.assertEqual(evaluate(build(alarms, inventory), check_id), [], check_id)

    def test_alarm_coverage_fail_reports_offenders(self):
        for check_id in METRIC_CHECKS:
            alarms, inventory = covered(check_id)
            extra = {"MON-005": item("ec2_instance", "i-0c3d4e5f60718293a"),
                     "MON-006": item("elbv2", "acme-notes-admin", arn=LB_ARN.replace("acme-notes-alb/50dc6c495c0c9188", "acme-notes-admin/1a2b3c4d5e6f7a8b")),
                     "MON-007": item("sqs_queue", QUEUE_URL.replace("jobs", "mail")),
                     "MON-008": item("lambda_function", "acme-notes-exporter")}.get(check_id, rds("acme-notes-replica"))
            offenders = evaluate(build(alarms, [*inventory, extra]), check_id)
            self.assertEqual(set(ids(offenders)), {extra["id"]}, check_id)
            self.assertEqual({o["detail"]["missing_part"] for o in offenders}, {"alarm"}, check_id)
            self.assertEqual({o["region"] for o in offenders}, {REGION}, check_id)

    def test_resources_of_other_types_are_ignored(self):
        self.assertEqual(evaluate(build([], [item("sqs_queue", QUEUE_URL), item("vpc", "vpc-1")])), [])


class MissingPartTests(unittest.TestCase):
    def run_one(self, alarms, topics=None, inventory=None, check_id="MON-001"):
        return evaluate(build(alarms, inventory or [rds()], topics), check_id)

    def test_no_alarm_at_all_is_missing_alarm(self):
        (offender,) = self.run_one([])
        self.assertEqual(offender["resource_id"], "acme-notes-db")
        self.assertEqual(offender["detail"]["missing_part"], "alarm")
        self.assertEqual(offender["detail"]["metric"], "CPUUtilization")
        self.assertEqual(offender["detail"]["dimension"], {"name": "DBInstanceIdentifier", "value": "acme-notes-db"})

    def test_alarm_for_another_resource_does_not_count(self):
        (offender,) = self.run_one([db_alarm("CPUUtilization", "acme-notes-replica")])
        self.assertEqual(offender["detail"]["missing_part"], "alarm")

    def test_alarm_for_another_metric_or_namespace_does_not_count(self):
        for wrong in (db_alarm("FreeableMemory"), db_alarm("CPUUtilization", ns="AWS/EC2")):
            (offender,) = self.run_one([wrong])
            self.assertEqual(offender["detail"]["missing_part"], "alarm")

    def test_alarm_in_another_region_does_not_count(self):
        responses = build({OTHER: [db_alarm("CPUUtilization", region=OTHER,
                                            actions=(f"arn:aws:sns:{OTHER}:{ACCOUNT}:acme-notes-alerts",))],
                           REGION: []}, [rds()], region=OTHER)
        (offender,) = evaluate(responses)
        self.assertEqual((offender["detail"]["missing_part"], offender["region"]), ("alarm", REGION))

    def test_alarm_without_actions_is_missing_action(self):
        (offender,) = self.run_one([db_alarm("CPUUtilization", actions=())])
        self.assertEqual(offender["detail"]["missing_part"], "action")
        self.assertEqual(offender["detail"]["alarms"], ["alarm-CPUUtilization"])

    def test_alarm_with_a_non_sns_action_is_missing_action(self):
        scaling = f"arn:aws:autoscaling:{REGION}:{ACCOUNT}:scalingPolicy:1a2b3c4d:autoScalingGroupName/acme-notes-web:policyName/up"
        (offender,) = self.run_one([db_alarm("CPUUtilization", actions=(scaling,))])
        self.assertEqual(offender["detail"]["missing_part"], "action")

    def test_alarm_with_actions_disabled_is_missing_action(self):
        (offender,) = self.run_one([db_alarm("CPUUtilization", enabled=False)])
        self.assertEqual(offender["detail"]["missing_part"], "action")

    def test_pending_subscription_is_missing_confirmed_subscription(self):
        (offender,) = self.run_one([db_alarm("CPUUtilization")], {TOPIC: subs("pending")})
        self.assertEqual(offender["detail"]["missing_part"], "confirmed_subscription")
        self.assertEqual(offender["detail"]["topics"], [TOPIC])

    def test_deleted_subscription_is_missing_confirmed_subscription(self):
        (offender,) = self.run_one([db_alarm("CPUUtilization")], {TOPIC: subs("deleted")})
        self.assertEqual(offender["detail"]["missing_part"], "confirmed_subscription")

    def test_topic_without_subscriptions_is_missing_confirmed_subscription(self):
        (offender,) = self.run_one([db_alarm("CPUUtilization")], {TOPIC: subs("empty")})
        self.assertEqual(offender["detail"]["missing_part"], "confirmed_subscription")

    def test_deleted_topic_is_missing_confirmed_subscription(self):
        (offender,) = self.run_one([db_alarm("CPUUtilization")], {TOPIC: {"__error__": "NotFound"}})
        self.assertEqual(offender["detail"]["missing_part"], "confirmed_subscription")

    def test_one_confirmed_subscription_next_to_pending_ones_passes(self):
        self.assertEqual(self.run_one([db_alarm("CPUUtilization")], {TOPIC: subs("mixed")}), [])

    def test_confirmation_state_is_compared_case_insensitively(self):
        data = {"Subscriptions": [{"SubscriptionArn": "pendingconfirmation"}]}
        (offender,) = self.run_one([db_alarm("CPUUtilization")], {TOPIC: data})
        self.assertEqual(offender["detail"]["missing_part"], "confirmed_subscription")

    def test_subscription_without_an_arn_is_not_confirmed(self):
        (offender,) = self.run_one([db_alarm("CPUUtilization")], {TOPIC: {"Subscriptions": [{"Protocol": "email"}]}})
        self.assertEqual(offender["detail"]["missing_part"], "confirmed_subscription")

    def test_a_second_alarm_that_works_rescues_the_resource(self):
        alarms = [db_alarm("CPUUtilization", name="a-no-actions", actions=()), db_alarm("CPUUtilization", name="b-good")]
        self.assertEqual(self.run_one(alarms), [])

    def test_the_furthest_step_reached_is_reported(self):
        other = f"arn:aws:sns:{REGION}:{ACCOUNT}:acme-notes-old"
        alarms = [db_alarm("CPUUtilization", name="a-no-actions", actions=()), db_alarm("CPUUtilization", name="b-pending", actions=(other,))]
        (offender,) = self.run_one(alarms, {other: subs("pending")})
        self.assertEqual(offender["detail"]["missing_part"], "confirmed_subscription")

    def test_any_confirmed_topic_is_enough(self):
        other = f"arn:aws:sns:{REGION}:{ACCOUNT}:acme-notes-old"
        alarm_ = db_alarm("CPUUtilization", actions=(other, TOPIC))
        self.assertEqual(self.run_one([alarm_], {other: subs("pending")}), [])

    def test_alarm_with_extra_dimensions_still_counts(self):
        wide = alarm("CPUUtilization", {"DBInstanceIdentifier": "acme-notes-db", "EngineName": "postgres"})
        self.assertEqual(self.run_one([wide]), [])

    def test_metric_math_alarm_counts_through_its_metric_queries(self):
        math = {"AlarmName": "db-cpu-math", "AlarmArn": f"arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:db-cpu-math",
                "ActionsEnabled": True, "AlarmActions": [TOPIC],
                "Metrics": [{"Id": "e1", "Expression": "m1 * 2", "ReturnData": True},
                            {"Id": "m1", "ReturnData": False, "MetricStat": {"Period": 300, "Stat": "Average", "Metric": {
                                "Namespace": "AWS/RDS", "MetricName": "CPUUtilization",
                                "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": "acme-notes-db"}]}}}]}
        self.assertEqual(self.run_one([math]), [])

    def test_missing_actions_field_means_no_action(self):
        bare = db_alarm("CPUUtilization")
        del bare["AlarmActions"]
        responses = build([db_alarm("CPUUtilization")], [rds()])
        responses["alarms"] = [(REGION, {"MetricAlarms": [bare]})]
        (offender,) = evaluate(responses)
        self.assertEqual(offender["detail"]["missing_part"], "action")

    def test_subscriptions_answered_as_null_are_not_confirmed(self):
        (offender,) = self.run_one([db_alarm("CPUUtilization")], {TOPIC: None})
        self.assertEqual(offender["detail"]["missing_part"], "confirmed_subscription")


class UnverifiedTopicTests(unittest.TestCase):
    def test_topic_in_another_region_is_unverified_not_failed(self):
        foreign = f"arn:aws:sns:{OTHER}:{ACCOUNT}:acme-notes-alerts"
        responses = build([db_alarm("CPUUtilization", actions=(foreign,))], [rds()], {foreign: {"__error__": "ERROR"}})
        (entry,) = evaluate(responses)
        self.assertEqual(flags([entry]), [("acme-notes-db", "unverified")])
        self.assertEqual(entry["region"], REGION)
        self.assertIn("otra cuenta o región", entry["detail"]["reason"])

    def test_topic_in_another_account_is_unverified_not_failed(self):
        foreign = f"arn:aws:sns:{REGION}:999988887777:shared-alerts"
        responses = build([db_alarm("CPUUtilization", actions=(foreign,))], [rds()], {foreign: {"__error__": "ERROR"}})
        self.assertEqual(flags(evaluate(responses)), [("acme-notes-db", "unverified")])

    def test_a_confirmed_local_topic_wins_over_a_foreign_one(self):
        foreign = f"arn:aws:sns:{OTHER}:{ACCOUNT}:acme-notes-alerts"
        responses = build([db_alarm("CPUUtilization", actions=(foreign, TOPIC))], [rds()], {foreign: {"__error__": "ERROR"}})
        self.assertEqual(evaluate(responses), [])

    def test_blocked_topic_is_unverified_only_for_the_resources_that_use_it(self):
        blocked = f"arn:aws:sns:{REGION}:{ACCOUNT}:acme-notes-private"
        alarms = [db_alarm("CPUUtilization", "acme-notes-db"), db_alarm("CPUUtilization", "acme-notes-replica", actions=(blocked,))]
        inventory = [rds(), rds("acme-notes-replica"), rds("acme-notes-bare")]
        entries = evaluate(build(alarms, inventory, {blocked: {"__error__": "ACCESS_DENIED"}}))
        self.assertEqual(flags(entries), [("acme-notes-replica", "unverified"), ("acme-notes-bare", "offender")])
        self.assertEqual(entries[0]["detail"]["error_code"], "ACCESS_DENIED")
        self.assertEqual(entries[0]["detail"]["topic"], blocked)

    def test_topic_whose_subscriptions_were_not_read_is_unverified(self):
        responses = build([db_alarm("CPUUtilization")], [rds()])
        responses.update(subs=[], __for_each__={"subs": []})
        self.assertEqual(flags(evaluate(responses)), [("acme-notes-db", "unverified")])

    def test_unverified_topic_does_not_hide_a_resource_without_alarm(self):
        responses = build([], [rds()])
        (entry,) = evaluate(responses)
        self.assertEqual(flags([entry]), [("acme-notes-db", "offender")])


class DimensionTests(unittest.TestCase):
    """Every resource type is matched through the dimension value CloudWatch uses for it."""

    def test_alb_dimension_is_the_arn_suffix_not_the_name(self):
        alb = item("elbv2", "acme-notes-alb", arn=LB_ARN)
        by_name = [alarm(m, {"LoadBalancer": "acme-notes-alb"}, ns="AWS/ApplicationELB") for m in METRIC_CHECKS["MON-006"][1]]
        names = evaluate(build(by_name, [alb]), "MON-006")
        self.assertEqual([o["detail"]["missing_part"] for o in names], ["alarm"] * 3)
        self.assertEqual(names[0]["detail"]["dimension"], {"name": "LoadBalancer", "value": LB_DIM})
        right = [alarm(m, {"LoadBalancer": LB_DIM}, ns="AWS/ApplicationELB") for m in METRIC_CHECKS["MON-006"][1]]
        self.assertEqual(evaluate(build(right, [alb]), "MON-006"), [])

    def test_alb_alarm_may_add_the_target_group_dimension(self):
        tg = {"LoadBalancer": LB_DIM, "TargetGroup": "targetgroup/acme-notes-web/73e2d6bc24d8a067"}
        alarms = [alarm("UnHealthyHostCount", tg, ns="AWS/ApplicationELB")]
        offenders = evaluate(build(alarms, [item("elbv2", "acme-notes-alb", arn=LB_ARN)]), "MON-006")
        self.assertEqual([o["detail"]["metric"] for o in offenders], ["HTTPCode_Target_5XX_Count", "TargetResponseTime"])

    def test_network_load_balancer_is_not_applicable(self):
        nlb = item("elbv2", "acme-notes-nlb", arn=NLB_ARN)
        self.assertEqual(flags(evaluate(build([], [nlb]), "MON-006")), [("acme-notes-nlb", "not_applicable")])

    def test_sqs_dimension_is_the_queue_name_taken_from_the_url(self):
        queue = item("sqs_queue", QUEUE_URL)
        by_url = [alarm("ApproximateAgeOfOldestMessage", {"QueueName": QUEUE_URL}, ns="AWS/SQS")]
        (offender,) = evaluate(build(by_url, [queue]), "MON-007")
        self.assertEqual((offender["resource_id"], offender["detail"]["dimension"]), (QUEUE_URL, {"name": "QueueName", "value": "acme-notes-jobs"}))
        right = [alarm("ApproximateAgeOfOldestMessage", {"QueueName": "acme-notes-jobs"}, ns="AWS/SQS")]
        self.assertEqual(evaluate(build(right, [queue]), "MON-007"), [])

    def test_sqs_fifo_queue_keeps_its_suffix(self):
        queue = item("sqs_queue", QUEUE_URL + ".fifo")
        right = [alarm("ApproximateAgeOfOldestMessage", {"QueueName": "acme-notes-jobs.fifo"}, ns="AWS/SQS")]
        self.assertEqual(evaluate(build(right, [queue]), "MON-007"), [])

    def test_lambda_dimension_is_the_function_name(self):
        right = [alarm("Errors", {"FunctionName": "acme-notes-resizer"}, ns="AWS/Lambda")]
        self.assertEqual(evaluate(build(right, [item("lambda_function", "acme-notes-resizer")]), "MON-008"), [])

    def test_instance_alarm_counts(self):
        right = [alarm("CPUUtilization", {"InstanceId": SOLO_I}, ns="AWS/EC2")]
        self.assertEqual(evaluate(build(right, [item("ec2_instance", SOLO_I)]), "MON-005"), [])

    def test_instance_in_an_auto_scaling_group_passes_with_the_group_alarm(self):
        member = item("ec2_instance", WEB_I, tags={"aws:autoscaling:groupName": "acme-notes-web"})
        group = [alarm("CPUUtilization", {"AutoScalingGroupName": "acme-notes-web"}, ns="AWS/EC2")]
        self.assertEqual(evaluate(build(group, [member]), "MON-005"), [])

    def test_instance_in_an_auto_scaling_group_passes_with_its_own_alarm(self):
        member = item("ec2_instance", WEB_I, tags={"aws:autoscaling:groupName": "acme-notes-web"})
        own = [alarm("CPUUtilization", {"InstanceId": WEB_I}, ns="AWS/EC2")]
        self.assertEqual(evaluate(build(own, [member]), "MON-005"), [])

    def test_group_alarm_of_another_group_does_not_cover_the_instance(self):
        member = item("ec2_instance", WEB_I, tags={"aws:autoscaling:groupName": "acme-notes-web"})
        other = [alarm("CPUUtilization", {"AutoScalingGroupName": "acme-notes-workers"}, ns="AWS/EC2")]
        (offender,) = evaluate(build(other, [member]), "MON-005")
        self.assertEqual(offender["detail"]["missing_part"], "alarm")

    def test_group_alarm_does_not_cover_an_instance_outside_any_group(self):
        group = [alarm("CPUUtilization", {"AutoScalingGroupName": "acme-notes-web"}, ns="AWS/EC2")]
        (offender,) = evaluate(build(group, [item("ec2_instance", SOLO_I)]), "MON-005")
        self.assertEqual(offender["resource_id"], SOLO_I)

    def test_dynamodb_table_needs_both_throttle_alarms(self):
        table = item("dynamodb_table", "acme-notes-sessions")
        one = [alarm("ReadThrottleEvents", {"TableName": "acme-notes-sessions"}, ns="AWS/DynamoDB")]
        (offender,) = evaluate(build(one, [table]), "MON-009")
        self.assertEqual((offender["resource_id"], offender["detail"]["metric"]), ("acme-notes-sessions", "WriteThrottleEvents"))

    def test_elasticache_group_is_matched_by_group_id_or_by_a_member_node(self):
        group = item("elasticache_group", "acme-notes-cache")
        for dims in ({"ReplicationGroupId": "acme-notes-cache"}, {"CacheClusterId": "acme-notes-cache-001"},
                     {"CacheClusterId": "acme-notes-cache-0001-002"}):
            right = [alarm("DatabaseMemoryUsagePercentage", dims, ns="AWS/ElastiCache")]
            self.assertEqual(evaluate(build(right, [group]), "MON-009"), [], dims)

    def test_elasticache_node_of_another_group_does_not_count(self):
        group = item("elasticache_group", "acme-notes-cache")
        for node in ("acme-notes-cache2-001", "acme-notes-cache-extra-001", "acme-notes-cache-0001-0002", "other-acme-notes-cache-001"):
            wrong = [alarm("DatabaseMemoryUsagePercentage", {"CacheClusterId": node}, ns="AWS/ElastiCache")]
            (offender,) = evaluate(build(wrong, [group]), "MON-009")
            self.assertEqual(offender["detail"]["missing_part"], "alarm", node)

    def test_mon_009_judges_each_type_with_its_own_namespace_and_metric(self):
        table, group = item("dynamodb_table", "acme-notes-sessions"), item("elasticache_group", "acme-notes-cache")
        offenders = evaluate(build([], [table, group]), "MON-009")
        self.assertEqual([(o["resource_id"], o["detail"]["namespace"], o["detail"]["metric"]) for o in offenders],
                         [("acme-notes-sessions", "AWS/DynamoDB", "ReadThrottleEvents"),
                          ("acme-notes-sessions", "AWS/DynamoDB", "WriteThrottleEvents"),
                          ("acme-notes-cache", "AWS/ElastiCache", "DatabaseMemoryUsagePercentage")])


class MultiMetricTests(unittest.TestCase):
    def test_mon_003_reports_one_offender_per_missing_metric(self):
        offenders = evaluate(build([], [rds()]), "MON-003")
        self.assertEqual([(o["resource_id"], o["detail"]["metric"]) for o in offenders],
                         [("acme-notes-db", "ReadIOPS"), ("acme-notes-db", "WriteIOPS")])

    def test_mon_003_reports_only_the_metric_that_is_missing(self):
        offenders = evaluate(build([db_alarm("ReadIOPS")], [rds()]), "MON-003")
        self.assertEqual([o["detail"]["metric"] for o in offenders], ["WriteIOPS"])

    def test_mon_003_each_metric_has_its_own_missing_part(self):
        alarms = [db_alarm("ReadIOPS", actions=()), db_alarm("WriteIOPS")]
        offenders = evaluate(build(alarms, [rds()], {TOPIC: subs("pending")}), "MON-003")
        self.assertEqual([(o["detail"]["metric"], o["detail"]["missing_part"]) for o in offenders],
                         [("ReadIOPS", "action"), ("WriteIOPS", "confirmed_subscription")])

    def test_mon_006_reports_three_offenders_per_balancer(self):
        offenders = evaluate(build([], [item("elbv2", "acme-notes-alb", arn=LB_ARN)]), "MON-006")
        self.assertEqual([o["detail"]["metric"] for o in offenders],
                         ["HTTPCode_Target_5XX_Count", "UnHealthyHostCount", "TargetResponseTime"])
        self.assertEqual(set(ids(offenders)), {"acme-notes-alb"})


class AlarmCoverageCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks = json.loads(MONITORING_JSON.read_text(encoding="utf-8"))["checks"]

    def test_monitoring_catalog_valid(self):
        data = json.loads(MONITORING_JSON.read_text(encoding="utf-8"))
        for check in data["checks"]:
            check.setdefault("domain", data["domain"])
        tsc_ids, iso_ids = catalog.load_frameworks(REFS / "frameworks")
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        self.assertEqual(catalog.validate(data["checks"], tsc_ids, iso_ids, drata), [])
        self.assertEqual([c["id"] for c in data["checks"]], [f"MON-{n:03d}" for n in range(1, 10)])
        self.assertEqual(data["domain"], "monitoring")

    def test_every_check_runs_alarm_coverage_with_the_documented_params(self):
        for check in self.checks:
            self.assertEqual(check["verify"]["evaluator"], "python:alarm_coverage", check["id"])
            self.assertIn("alarm_coverage", evaluators.EVALUATORS)
            if check["id"] == "MON-009":
                continue
            namespace, metrics = METRIC_CHECKS[check["id"]]
            params = check["verify"]["params"]
            self.assertEqual(params["namespace"], namespace, check["id"])
            self.assertEqual([params["metric"]] if isinstance(params["metric"], str) else params["metric"], metrics, check["id"])
            self.assertIsInstance(params["resource_dimension"], str, check["id"])

    def test_mon_009_declares_a_spec_per_resource_type(self):
        by_type = params_of("MON-009")["by_type"]
        self.assertEqual(set(by_type), {"dynamodb_table", "elasticache_group"})
        self.assertEqual((by_type["dynamodb_table"]["namespace"], by_type["dynamodb_table"]["resource_dimension"]), ("AWS/DynamoDB", "TableName"))
        self.assertEqual(by_type["elasticache_group"]["namespace"], "AWS/ElastiCache")

    def test_resource_types_scope_and_regions(self):
        types = {"MON-001": ["rds_instance"], "MON-002": ["rds_instance"], "MON-003": ["rds_instance"], "MON-004": ["rds_instance"],
                 "MON-005": ["ec2_instance"], "MON-006": ["elbv2"], "MON-007": ["sqs_queue"], "MON-008": ["lambda_function"],
                 "MON-009": ["dynamodb_table", "elasticache_group"]}
        self.assertEqual({c["id"]: c["resource_types"] for c in self.checks}, types)
        for check in self.checks:
            self.assertEqual((check["scope"], check["all_regions"], check["severity"]), ("resource", False, "high"), check["id"])

    def test_calls_read_alarms_and_the_subscriptions_of_their_topics(self):
        for check in self.checks:
            alarms, subscriptions = check["verify"]["calls"]
            self.assertEqual((alarms["service"], alarms["operation"], alarms["region"]), ("cloudwatch", "describe-alarms", "each"))
            self.assertEqual((subscriptions["service"], subscriptions["operation"]), ("sns", "list-subscriptions-by-topic"))
            self.assertEqual(subscriptions["for_each"], {"from": alarms["name"], "path": "MetricAlarms[].AlarmActions[]", "arg": "--topic-arn"})
            self.assertEqual(subscriptions["item_errors"], "evaluator")
            self.assertEqual(subscriptions["ok_errors"], ["NotFound"])
            self.assertEqual(check["verify"]["needs"], ["cloudwatch:DescribeAlarms", "sns:ListSubscriptionsByTopic"])
            self.assertEqual(alarms["name"], "alarms")
            self.assertEqual(subscriptions["name"], "subs")

    def test_drata_mappings_follow_the_brief_and_resolve_from_the_dcf_file(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        expected = {"MON-001": [112], "MON-002": [113], "MON-003": [114, 290], "MON-004": [206], "MON-005": [118],
                    "MON-006": [296, 298, 294], "MON-007": [115], "MON-008": [300], "MON-009": [117]}
        for check_id, tests in expected.items():
            resolved = catalog.resolve_mappings(catalog_check(check_id), drata)
            self.assertEqual([m["test"] for m in resolved["drata"]], tests, check_id)
            self.assertTrue(resolved["tsc"] and all(t["sourced"] == catalog.DCF_SOURCE for t in resolved["tsc"]), check_id)
            self.assertTrue(catalog_check(check_id)["mappings"]["vanta"], check_id)

    def test_remediation_is_cli_with_decision_and_steps_are_not_numbered_by_hand(self):
        for check in self.checks:
            rem = check["remediation"]
            self.assertEqual(rem["kind"], "cli_with_decision", check["id"])
            for step in rem["steps"]:
                self.assertNotRegex(step, r"^\d+\.\s", check["id"])

    def test_remediation_commands_follow_cloudshell_rules(self):
        for check in self.checks:
            rem = check["remediation"]
            for command in rem["commands"]:
                self.assertTrue(command.startswith('REGION="{region}"\nACCOUNT_ID="{account_id}"\n'), check["id"])
                self.assertNotIn("set -e", command, check["id"])
                self.assertNotIn("<<", command, check["id"])
            self.assertTrue(rem["verify_after"].startswith("aws "), check["id"])

    @unittest.skipUnless(shutil.which("bash"), "bash not installed")
    def test_remediation_commands_and_verification_parse_as_bash(self):
        for check in self.checks:
            rem = check["remediation"]
            for text in [*rem["commands"], rem["verify_after"]]:
                script = text.replace("{region}", REGION).replace("{account_id}", ACCOUNT).replace("{resource_id}", "acme-notes-x")
                done = subprocess.run(["bash", "-n"], input=script, capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, f"{check['id']}: {done.stderr}\n{script}")

    def alarm_commands(self, check_id):
        return [c for c in catalog_check(check_id)["remediation"]["commands"] if "put-metric-alarm" in c]

    def test_alarm_commands_use_the_dimension_of_the_resource_and_the_placeholders(self):
        expected = {"MON-001": ("AWS/RDS", "CPUUtilization", "DBInstanceIdentifier"), "MON-002": ("AWS/RDS", "FreeStorageSpace", "DBInstanceIdentifier"),
                    "MON-004": ("AWS/RDS", "FreeableMemory", "DBInstanceIdentifier"), "MON-007": ("AWS/SQS", "ApproximateAgeOfOldestMessage", "QueueName"),
                    "MON-008": ("AWS/Lambda", "Errors", "FunctionName")}
        for check_id, (namespace, metric, dimension) in expected.items():
            (command,) = self.alarm_commands(check_id)
            self.assertIn(f"--namespace {namespace}", command, check_id)
            self.assertIn(f"--metric-name {metric}", command, check_id)
            self.assertIn(f"Name={dimension},Value=", command, check_id)
            self.assertIn("--threshold __COMPLETAR_UMBRAL__", command, check_id)
            self.assertIn("--alarm-actions", command, check_id)
            self.assertIn("__COMPLETAR_SNS_TOPIC_ARN__", command, check_id)

    def test_multi_metric_checks_have_one_alarm_command_per_metric(self):
        for check_id, count in (("MON-003", 2), ("MON-006", 3), ("MON-009", 3)):
            commands = self.alarm_commands(check_id)
            self.assertEqual(len(commands), count, check_id)
        for command, metric in zip(self.alarm_commands("MON-003"), ("ReadIOPS", "WriteIOPS")):
            self.assertIn(f"--metric-name {metric}", command)
            self.assertIn("Name=DBInstanceIdentifier,Value=", command)
        self.assertEqual([m for c in self.alarm_commands("MON-006") for m in METRIC_CHECKS["MON-006"][1] if f"--metric-name {m} " in c],
                         METRIC_CHECKS["MON-006"][1])

    def test_alb_commands_derive_the_dimension_from_the_arn(self):
        for command in self.alarm_commands("MON-006"):
            self.assertIn("describe-load-balancers", command)
            self.assertIn("Name=LoadBalancer,Value=", command)
            self.assertIn(":loadbalancer/", command)
        self.assertIn("Name=TargetGroup,Value=", [c for c in self.alarm_commands("MON-006") if "UnHealthyHostCount" in c][0])

    def test_sqs_command_derives_the_queue_name_from_the_url(self):
        (command,) = self.alarm_commands("MON-007")
        self.assertIn('${QUEUE_URL##*/}', command)

    def test_instance_command_has_a_variant_for_auto_scaling_group_members(self):
        commands = self.alarm_commands("MON-005")
        self.assertEqual(len(commands), 2)
        self.assertIn("Name=InstanceId,Value=", commands[0])
        self.assertIn("Name=AutoScalingGroupName,Value=", commands[1])
        self.assertIn("describe-auto-scaling-instances", commands[1])

    def test_every_check_has_a_separate_subscribe_block_and_a_confirmation_note(self):
        for check in self.checks:
            rem = check["remediation"]
            blocks = [c for c in rem["commands"] if "sns subscribe" in c]
            self.assertEqual(len(blocks), 1, check["id"])
            self.assertNotIn("put-metric-alarm", blocks[0], check["id"])
            self.assertIn("--protocol email", blocks[0], check["id"])
            self.assertIn("__COMPLETAR_SNS_TOPIC_ARN__", blocks[0], check["id"])
            self.assertIn("__COMPLETAR_OWNER_EMAIL__", blocks[0], check["id"])
            self.assertRegex(rem["notes"], r"(?i)confirm", check["id"])
            self.assertRegex(rem["notes"], r"PendingConfirmation", check["id"])

    def test_notes_state_that_no_threshold_is_dictated(self):
        for check in self.checks:
            self.assertRegex(check["remediation"]["notes"], r"umbral", check["id"])

    def test_no_threshold_is_hardcoded(self):
        for check in self.checks:
            for command in check["remediation"]["commands"]:
                for threshold in ("--threshold ",):
                    for line in command.splitlines():
                        if threshold in line:
                            self.assertIn("--threshold __COMPLETAR_UMBRAL__", line, check["id"])


class MonitoringCollectTests(unittest.TestCase):
    """The monitoring catalog through collect.main with a fake AWS: wiring of calls, for_each, dedupe and item_errors."""

    TYPES = ("rds_instance", "sqs_queue")
    BLOCKED = f"arn:aws:sns:{REGION}:{ACCOUNT}:acme-notes-private"
    CHECKS = ("MON-001", "MON-002", "MON-007")

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        (cls.tmp / "checks").mkdir()
        data = json.loads(MONITORING_JSON.read_text(encoding="utf-8"))
        data["checks"] = [c for c in data["checks"] if c["id"] in cls.CHECKS]
        (cls.tmp / "checks" / "monitoring.json").write_text(json.dumps(data), encoding="utf-8")
        specs = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))
        (cls.tmp / "inventory.json").write_text(json.dumps({t: specs[t] for t in cls.TYPES}), encoding="utf-8")
        scope = {"platform": "Acme Notes", "mode": "full", "target": None, "regions": [REGION], "profile": None, "resources": [], "domains": None}
        (cls.tmp / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
        cls.runner = RuleRunner(cls.rules())
        cls.out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            cls.code = collect.main(
                ["--scope", str(cls.tmp / "scope.json"), "--out", str(cls.out), "--checks-dir", str(cls.tmp / "checks"),
                 "--inventory", str(cls.tmp / "inventory.json")],
                runner=cls.runner, sleep=lambda s: None, which=lambda name: None)
        cls.result = json.loads((cls.out / "checks-result.json").read_text(encoding="utf-8"))

    @classmethod
    def rules(cls):
        core = lambda name: ok(load_fixture(f"aws/core/{name}.json"))
        alarms = [db_alarm("CPUUtilization", "acme-notes-db"),
                  db_alarm("CPUUtilization", "acme-notes-replica", actions=(cls.BLOCKED, f"arn:aws:autoscaling:{REGION}:{ACCOUNT}:scalingPolicy:x")),
                  db_alarm("FreeStorageSpace", "acme-notes-db", name="storage-a"), db_alarm("FreeStorageSpace", "acme-notes-db", name="storage-b"),
                  alarm("ApproximateAgeOfOldestMessage", {"QueueName": "acme-notes-jobs"}, ns="AWS/SQS", actions=())]
        denied = err("An error occurred (AuthorizationError) when calling the ListSubscriptionsByTopic operation: AccessDenied: not authorized")
        return [
            ("sts", "get-caller-identity", None, "", core("sts-get-caller-identity")),
            ("ec2", "describe-regions", None, "", core("ec2-describe-regions")),
            ("iam", "list-attached-user-policies", None, "", ok({"AttachedPolicies": []})),
            ("rds", "describe-db-instances", None, "", ok({"DBInstances": [
                {"DBInstanceIdentifier": n, "DBInstanceArn": f"arn:aws:rds:{REGION}:{ACCOUNT}:db:{n}"} for n in ("acme-notes-db", "acme-notes-replica")]})),
            ("sqs", "list-queues", None, "", ok({"QueueUrls": [QUEUE_URL]})),
            ("cloudwatch", "describe-alarms", None, "", ok({"MetricAlarms": alarms, "CompositeAlarms": []})),
            ("sns", "list-subscriptions-by-topic", None, "acme-notes-alerts", ok(fx("sns-list-subscriptions-by-topic-raw"))),
            ("sns", "list-subscriptions-by-topic", None, "acme-notes-private", denied),
            ("sns", "list-subscriptions-by-topic", None, "scalingPolicy", err("An error occurred (InvalidParameter) when calling the ListSubscriptionsByTopic operation: Invalid parameter: TopicArn")),
        ]

    def rows(self, check_id):
        return sorted((r["status"], r["resource_id"]) for r in self.result["results"] if r["check_id"] == check_id)

    def test_run_succeeds_and_every_resource_gets_its_own_verdict(self):
        self.assertEqual(self.code, 0)
        self.assertEqual(self.rows("MON-001"), [("NO_VERIFICADO", "acme-notes-replica"), ("PASS", "acme-notes-db")])
        self.assertEqual(self.rows("MON-002"), [("FAIL", "acme-notes-replica"), ("PASS", "acme-notes-db")])
        self.assertEqual(self.rows("MON-007"), [("FAIL", QUEUE_URL)])

    def test_fail_rows_carry_the_missing_part(self):
        parts = {(r["check_id"], r["resource_id"]): r["detail"]["missing_part"] for r in self.result["results"] if r["status"] == "FAIL"}
        self.assertEqual(parts, {("MON-002", "acme-notes-replica"): "alarm", ("MON-007", QUEUE_URL): "action"})

    def test_blocked_topic_is_unverified_with_the_missing_permission_for_that_resource_only(self):
        (row,) = [r for r in self.result["results"] if r["status"] == "NO_VERIFICADO"]
        self.assertEqual((row["check_id"], row["resource_id"]), ("MON-001", "acme-notes-replica"))
        self.assertEqual(row["missing"], ["cloudwatch:DescribeAlarms", "sns:ListSubscriptionsByTopic"])

    def test_each_distinct_topic_is_read_once_per_check(self):
        calls = [c for c in self.runner.calls if c[1:3] == ["sns", "list-subscriptions-by-topic"]]
        topics = [c[c.index("--topic-arn") + 1] for c in calls]
        per_check = len(self.CHECKS)
        self.assertEqual(len(topics), len(set(topics)) * per_check)

    def test_subscriber_endpoints_never_reach_the_raw_files(self):
        raw = "\n".join(p.read_text(encoding="utf-8") for p in (self.out / "raw").rglob("*.json"))
        self.assertIn("SubscriptionArn", raw)
        self.assertNotIn("oncall@", raw)
        self.assertNotIn("Endpoint", raw)


class EngineParamsTests(unittest.TestCase):
    def test_every_domain_module_registers_its_evaluators(self):
        self.assertEqual(evaluators.EVALUATORS["alarm_coverage"].__module__, "evaluators.monitoring")


if __name__ == "__main__":
    unittest.main()
