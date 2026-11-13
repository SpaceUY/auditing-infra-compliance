import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import helpers
from helpers import SKILL_DIR, load_fixture

import catalog
import collect
import evaluators
from test_eval_encryption import flags, for_each, ids, merge
from test_eval_iam import RuleRunner, err, ok

try:
    import jmespath
except ImportError:  # the skill itself is stdlib-only; the JMESPath expressions are only verified when it is installed
    jmespath = None

DATA_JSON = SKILL_DIR / "references" / "checks" / "data.json"
REFS = SKILL_DIR / "references"
REGION = "us-east-1"
OTHER = "eu-west-1"
NOW = "2026-11-12T12:00:00+00:00"
DB, LEGACY, STAGING, UNTAGGED, AURORA = ("acme-notes-db", "acme-notes-legacy", "acme-notes-staging", "acme-notes-untagged", "acme-notes-aurora-1")
R_DB = "arn:aws:rds:us-east-1:111122223333:db:acme-notes-db"
R_TABLE = "arn:aws:dynamodb:us-east-1:111122223333:table/acme-notes-sessions"
R_EFS = "arn:aws:elasticfilesystem:us-east-1:111122223333:file-system/fs-0a1b2c3d4e5f60718"
PLAN_ID = "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d"
WEEKLY_ID = "8b9c0d1e-2f3a-4b4c-9d5e-6f7a8b9c0d1e"


def fx(name):
    return load_fixture(f"aws/data/{name}.json")


def evaluate(name, responses, params=None):
    return evaluators.EVALUATORS[name](responses, params or {})


def catalog_check(check_id):
    data = json.loads(DATA_JSON.read_text(encoding="utf-8"))
    return next(c for c in data["checks"] if c["id"] == check_id)


def real(offenders):
    return [o for o in offenders if not o.get("not_applicable")]


def instance(name, **fields):
    return {"DBInstanceIdentifier": name, "Engine": "postgres", **fields}


def instances(*dbs, region=REGION):
    return {"instances": [(region, {"DBInstances": list(dbs)})]}


class RdsBackupsTests(unittest.TestCase):
    def test_rds_backups_pass(self):
        self.assertEqual(evaluate("rds_backups", instances(instance(DB, BackupRetentionPeriod=7), instance("x", BackupRetentionPeriod=35)), {"min_days": 7}), [])

    def test_rds_backups_fail_reports_offenders(self):
        found = evaluate("rds_backups", {"instances": [(REGION, fx("rds-describe-db-instances-raw"))]}, {"min_days": 7})
        self.assertEqual([(o["resource_id"], o["region"]) for o in found], [(LEGACY, REGION), (STAGING, REGION), (UNTAGGED, REGION), (AURORA, REGION)])
        self.assertEqual(found[0]["detail"], {"backup_retention_period": 0, "reason": "los backups automáticos están desactivados"})
        self.assertNotIn("severity_override", found[0]["detail"])
        self.assertEqual(found[1]["detail"], {"backup_retention_period": 3, "severity_override": "low",
                                              "reason": "la retención es de 3 días, menos que los 7 recomendados"})

    def test_retention_boundaries(self):
        def outcome(days):
            (found,) = evaluate("rds_backups", instances(instance("x", BackupRetentionPeriod=days)), {"min_days": 7}) or [None]
            return None if found is None else found["detail"].get("severity_override", "high")
        self.assertEqual(outcome(0), "high")
        self.assertEqual(outcome(1), "low")
        self.assertEqual(outcome(6), "low")
        self.assertIsNone(outcome(7))
        self.assertIsNone(outcome(8))

    def test_missing_retention_counts_as_disabled(self):
        (found,) = evaluate("rds_backups", instances(instance("x")), {"min_days": 7})
        self.assertEqual(found["detail"]["backup_retention_period"], 0)
        self.assertNotIn("severity_override", found["detail"])

    def test_the_recommended_days_come_from_the_params(self):
        self.assertEqual(evaluate("rds_backups", instances(instance("x", BackupRetentionPeriod=3)), {"min_days": 3}), [])


class RdsMultiAzTests(unittest.TestCase):
    @staticmethod
    def check(*dbs):
        return evaluate("rds_multi_az", instances(*dbs))

    def test_rds_multi_az_pass(self):
        self.assertEqual(self.check(instance(DB, MultiAZ=True, TagList=[{"Key": "Environment", "Value": "production"}])), [])

    def test_rds_multi_az_fail_reports_offenders(self):
        found = evaluate("rds_multi_az", {"instances": [(REGION, fx("rds-describe-db-instances-raw"))]})
        self.assertEqual(flags(found), [(LEGACY, "offender"), (STAGING, "not_applicable"), (UNTAGGED, "offender"), (AURORA, "not_applicable")])
        self.assertEqual((found[0]["resource_id"], found[0]["region"]), (LEGACY, REGION))
        self.assertEqual(found[0]["detail"]["environment"], "prod")
        self.assertIsNone(found[2]["detail"]["environment"])

    def test_prod_values_are_compared_ignoring_case_and_spaces(self):
        for value in ("prod", "production", "Prod", "PRODUCTION", " production "):
            tags = [{"Key": "Environment", "Value": value}]
            self.assertEqual(ids(self.check(instance("x", MultiAZ=False, TagList=tags))), ["x"], value)

    def test_other_environments_are_not_applicable(self):
        for value in ("staging", "dev", "test", "prod-eu", "qa"):
            found = self.check(instance("x", MultiAZ=False, TagList=[{"Key": "Environment", "Value": value}]))
            self.assertEqual(flags(found), [("x", "not_applicable")], value)

    def test_untagged_or_empty_environment_tag_applies(self):
        self.assertEqual(ids(self.check(instance("x", MultiAZ=False))), ["x"])
        self.assertEqual(ids(self.check(instance("x", MultiAZ=False, TagList=[{"Key": "Environment", "Value": ""}]))), ["x"])
        self.assertEqual(ids(self.check(instance("x", MultiAZ=False, TagList=[{"Key": "Team", "Value": "notes"}]))), ["x"])

    def test_cluster_members_are_not_applicable(self):
        found = self.check(instance("x", MultiAZ=False, DBClusterIdentifier="acme-notes-aurora"))
        self.assertEqual(flags(found), [("x", "not_applicable")])

    def test_missing_multi_az_counts_as_single_az(self):
        self.assertEqual(ids(self.check(instance("x"))), ["x"])


class DynamoPitrTests(unittest.TestCase):
    @staticmethod
    def tables(**tables):
        return for_each("backups", list(tables.items()))

    def test_ddb_pitr_pass(self):
        self.assertEqual(evaluate("ddb_pitr", self.tables(a=fx("dynamodb-describe-continuous-backups-enabled"))), [])

    def test_ddb_pitr_fail_reports_offenders(self):
        found = evaluate("ddb_pitr", self.tables(a=fx("dynamodb-describe-continuous-backups-enabled"), b=fx("dynamodb-describe-continuous-backups-disabled")))
        self.assertEqual([(o["resource_id"], o["region"]) for o in found], [("b", REGION)])
        self.assertEqual(found[0]["detail"], {"pitr_status": "DISABLED", "reason": "la recuperación a un punto en el tiempo (PITR) no está habilitada"})

    def test_status_is_compared_ignoring_case_and_a_missing_description_fails(self):
        self.assertEqual(evaluate("ddb_pitr", self.tables(a={"ContinuousBackupsDescription": {"PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "enabled"}}})), [])
        self.assertEqual(ids(evaluate("ddb_pitr", self.tables(a={"ContinuousBackupsDescription": {}}, b={}))), ["a", "b"])

    def test_deleted_table_is_not_applicable_and_a_blocked_table_is_unverified(self):
        found = evaluate("ddb_pitr", self.tables(a={"__error__": "TableNotFoundException"}, b={"__error__": "ACCESS_DENIED"},
                                                  c=fx("dynamodb-describe-continuous-backups-disabled")))
        self.assertEqual(flags(found), [("a", "not_applicable"), ("b", "unverified"), ("c", "offender")])
        self.assertEqual(found[1]["detail"]["error_code"], "ACCESS_DENIED")


class S3VersioningTests(unittest.TestCase):
    @staticmethod
    def buckets(**buckets):
        return for_each("versioning", list(buckets.items()))

    def test_s3_versioning_pass(self):
        self.assertEqual(evaluate("s3_versioning", self.buckets(a=fx("s3api-get-bucket-versioning-enabled"))), [])
        self.assertEqual(evaluate("s3_versioning", self.buckets(a={"Status": "enabled"})), [])

    def test_s3_versioning_fail_reports_offenders(self):
        found = evaluate("s3_versioning", self.buckets(a=fx("s3api-get-bucket-versioning-enabled"), b=fx("s3api-get-bucket-versioning-suspended"), c=None, d={}))
        self.assertEqual([(o["resource_id"], o["region"]) for o in found], [("b", REGION), ("c", REGION), ("d", REGION)])
        self.assertEqual(found[0]["detail"], {"status": "Suspended", "reason": "el versionado está suspendido"})
        self.assertEqual(found[1]["detail"], {"status": None, "reason": "el versionado nunca se habilitó"})

    def test_deleted_bucket_is_not_applicable_and_a_blocked_bucket_is_unverified(self):
        found = evaluate("s3_versioning", self.buckets(a={"__error__": "NoSuchBucket"}, b={"__error__": "ACCESS_DENIED"}, c={"__error__": "ERROR"},
                                                        d=fx("s3api-get-bucket-versioning-suspended")))
        self.assertEqual(flags(found), [("a", "not_applicable"), ("b", "unverified"), ("c", "unverified"), ("d", "offender")])
        self.assertEqual((found[1]["detail"]["error_code"], found[2]["detail"]["error_code"]), ("ACCESS_DENIED", "ERROR"))


class S3BpaTests(unittest.TestCase):
    @staticmethod
    def buckets(**buckets):
        return for_each("bpa", list(buckets.items()))

    def test_s3_bpa_pass(self):
        self.assertEqual(evaluate("s3_bpa", self.buckets(a=fx("s3api-get-public-access-block-all"))), [])

    def test_s3_bpa_fail_reports_offenders(self):
        found = evaluate("s3_bpa", self.buckets(a=fx("s3api-get-public-access-block-all"), b=fx("s3api-get-public-access-block-partial"),
                                                c={"__error__": "NoSuchPublicAccessBlockConfiguration"}))
        self.assertEqual([(o["resource_id"], o["region"]) for o in found], [("b", REGION), ("c", REGION)])
        self.assertEqual(found[0]["detail"], {"missing_flags": ["BlockPublicPolicy", "RestrictPublicBuckets"],
                                              "reason": "el Block Public Access del bucket no tiene los 4 ajustes activos"})
        self.assertEqual(found[1]["detail"]["missing_flags"], ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"])
        self.assertEqual(found[1]["detail"]["reason"], "el bucket no tiene configuración de Block Public Access")

    def test_each_flag_alone_makes_the_bucket_fail(self):
        for flag in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"):
            config = {f: True for f in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
            config[flag] = False
            (found,) = evaluate("s3_bpa", self.buckets(a={"PublicAccessBlockConfiguration": config}))
            self.assertEqual(found["detail"]["missing_flags"], [flag])

    def test_a_missing_flag_or_configuration_counts_as_off(self):
        (found,) = evaluate("s3_bpa", self.buckets(a={"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}}))
        self.assertEqual(found["detail"]["missing_flags"], ["IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"])
        self.assertEqual(ids(evaluate("s3_bpa", self.buckets(a={}, b=None))), ["a", "b"])

    def test_deleted_bucket_is_not_applicable_and_a_blocked_bucket_is_unverified(self):
        found = evaluate("s3_bpa", self.buckets(a={"__error__": "NoSuchBucket"}, b={"__error__": "ACCESS_DENIED"}, c=fx("s3api-get-public-access-block-partial")))
        self.assertEqual(flags(found), [("a", "not_applicable"), ("b", "unverified"), ("c", "offender")])
        self.assertEqual(found[1]["detail"]["error_code"], "ACCESS_DENIED")


class BackupJobsRecentTests(unittest.TestCase):
    PARAMS = {"window_hours": 24, "now": NOW}

    @staticmethod
    def responses(jobs="backup-list-backup-jobs-mixed", vaults="backup-list-backup-vaults", region=REGION):
        data = fx(jobs) if isinstance(jobs, str) else jobs
        return {"jobs": [(region, data)], "vaults": [(region, fx(vaults) if isinstance(vaults, str) else vaults)]}

    @staticmethod
    def at(delta):
        return (datetime.fromisoformat(NOW) - delta).isoformat()

    def one_job(self, state, delta, vault="acme-notes-vault"):
        return {"BackupJobs": [{"BackupJobId": "j", "ResourceArn": R_DB, "State": state, "CreationDate": self.at(delta), "BackupVaultName": vault}]}

    @staticmethod
    def one_vault(points=12):
        return {"BackupVaultList": [{"BackupVaultName": "acme-notes-vault", "NumberOfRecoveryPoints": points}]}

    def test_backup_jobs_recent_pass(self):
        data = {"BackupJobs": [j for j in fx("backup-list-backup-jobs-mixed")["BackupJobs"] if j["BackupVaultName"] == "acme-notes-vault"]}
        self.assertEqual(evaluate("backup_jobs_recent", self.responses(data, self.one_vault()), self.PARAMS), [])

    def test_backup_jobs_recent_fail_reports_offenders(self):
        found = evaluate("backup_jobs_recent", self.responses(), self.PARAMS)
        self.assertEqual(flags(found), [("acme-notes-quiet", "offender"), ("Default", "not_applicable")])
        self.assertEqual((found[0]["resource_id"], found[0]["region"]), ("acme-notes-quiet", REGION))
        self.assertEqual(found[0]["detail"], {"resources": [{"arn": R_EFS, "states": ["EXPIRED", "FAILED"]}],
                                              "reason": "hay recursos sin ningún job completado en las últimas 24 horas"})

    def test_a_retry_that_completed_clears_the_failure(self):
        found = evaluate("backup_jobs_recent", self.responses(), self.PARAMS)
        self.assertNotIn("acme-notes-vault", ids(found))

    def test_jobs_older_than_the_window_are_ignored(self):
        data = {"BackupJobs": [dict(j, State="FAILED") for j in fx("backup-list-backup-jobs-mixed")["BackupJobs"] if j["BackupJobId"] == "1f"]}
        found = evaluate("backup_jobs_recent", self.responses(data, self.one_vault()), self.PARAMS)
        self.assertEqual(found[0]["detail"]["reason"], "la bóveda tiene puntos de recuperación y ningún job en las últimas 24 horas")

    def test_window_boundaries_use_total_seconds(self):
        def outcome(delta):
            (found,) = evaluate("backup_jobs_recent", self.responses(self.one_job("FAILED", delta), self.one_vault()), self.PARAMS)
            return "failed" if "resources" in found["detail"] else "no job"
        self.assertEqual(outcome(timedelta(hours=24)), "failed")
        self.assertEqual(outcome(timedelta(hours=23, minutes=59, seconds=59)), "failed")
        self.assertEqual(outcome(timedelta(hours=24, seconds=1)), "no job")
        self.assertEqual(outcome(timedelta(days=1, minutes=1)), "no job")
        self.assertEqual(outcome(timedelta(seconds=-1)), "no job")

    def test_jobs_still_running_are_neither_a_failure_nor_a_success(self):
        for state in ("CREATED", "PENDING", "RUNNING", "ABORTING"):
            self.assertEqual(evaluate("backup_jobs_recent", self.responses(self.one_job(state, timedelta(hours=1)), self.one_vault()), self.PARAMS), [], state)

    def test_unsuccessful_terminal_states_fail(self):
        for state in ("FAILED", "EXPIRED", "ABORTED", "PARTIAL", "COMPLETED_WITH_ISSUES"):
            (found,) = evaluate("backup_jobs_recent", self.responses(self.one_job(state, timedelta(hours=1)), self.one_vault()), self.PARAMS)
            self.assertEqual(found["detail"]["resources"], [{"arn": R_DB, "states": [state]}], state)

    def test_states_are_compared_ignoring_case(self):
        self.assertEqual(evaluate("backup_jobs_recent", self.responses(self.one_job("completed", timedelta(hours=1)), self.one_vault()), self.PARAMS), [])

    def test_a_vault_with_recovery_points_and_no_job_in_the_window_fails_but_an_empty_one_is_not_applicable(self):
        jobs = "backup-list-backup-jobs-none"
        (offender,) = evaluate("backup_jobs_recent", self.responses(jobs, self.one_vault()), self.PARAMS)
        self.assertEqual((offender["resource_id"], offender["region"]), ("acme-notes-vault", REGION))
        self.assertEqual(flags(evaluate("backup_jobs_recent", self.responses(jobs, self.one_vault(0)), self.PARAMS)), [("acme-notes-vault", "not_applicable")])

    def test_without_vaults_there_is_nothing_to_report(self):
        self.assertEqual(evaluate("backup_jobs_recent", self.responses("backup-list-backup-jobs-none", {"BackupVaultList": []}), self.PARAMS), [])

    def test_jobs_are_matched_to_the_vault_of_their_own_region(self):
        responses = {"jobs": [(REGION, self.one_job("COMPLETED", timedelta(hours=1))), (OTHER, fx("backup-list-backup-jobs-none"))],
                     "vaults": [(REGION, self.one_vault()), (OTHER, self.one_vault())]}
        self.assertEqual([(o["resource_id"], o["region"]) for o in evaluate("backup_jobs_recent", responses, self.PARAMS)], [("acme-notes-vault", OTHER)])

    def test_the_clock_is_injectable_and_the_window_is_a_param(self):
        data = self.one_job("FAILED", timedelta(hours=30))
        (found,) = evaluate("backup_jobs_recent", self.responses(data, self.one_vault()), {"window_hours": 48, "now": NOW})
        self.assertIn("resources", found["detail"])


class BackupVaultNotificationsTests(unittest.TestCase):
    @staticmethod
    def responses(**notifications):
        return merge({"vaults": [(REGION, fx("backup-list-backup-vaults"))]}, for_each("notifications", list(notifications.items())))

    def test_backup_vault_notifications_pass(self):
        responses = self.responses(**{"acme-notes-vault": fx("backup-get-backup-vault-notifications-failed"), "Default": {"__error__": "ResourceNotFoundException"}})
        self.assertEqual(real(evaluate("backup_vault_notifications", responses)), [])

    def test_backup_vault_notifications_fail_reports_offenders(self):
        responses = self.responses(**{"acme-notes-vault": fx("backup-get-backup-vault-notifications-failed"),
                                      "acme-notes-quiet": fx("backup-get-backup-vault-notifications-completed-only")})
        (offender,) = evaluate("backup_vault_notifications", responses)
        self.assertEqual((offender["resource_id"], offender["region"]), ("acme-notes-quiet", REGION))
        self.assertEqual(offender["detail"], {"events": ["BACKUP_JOB_COMPLETED"], "reason": "la bóveda no notifica BACKUP_JOB_FAILED a un tópico de SNS"})

    def test_vault_without_notification_configuration_fails(self):
        (offender,) = evaluate("backup_vault_notifications", self.responses(**{"acme-notes-vault": {"__error__": "ResourceNotFoundException"}}))
        self.assertEqual(offender["resource_id"], "acme-notes-vault")
        self.assertEqual(offender["detail"]["reason"], "la bóveda no tiene notificaciones configuradas")

    def test_vault_without_a_topic_fails_and_events_are_compared_ignoring_case(self):
        data = fx("backup-get-backup-vault-notifications-failed")
        self.assertEqual(ids(evaluate("backup_vault_notifications", self.responses(**{"acme-notes-vault": {**data, "SNSTopicArn": ""}}))), ["acme-notes-vault"])
        self.assertEqual(evaluate("backup_vault_notifications", self.responses(**{"acme-notes-vault": {**data, "BackupVaultEvents": ["backup_job_failed"]}})), [])

    def test_vaults_without_recovery_points_are_not_applicable(self):
        found = evaluate("backup_vault_notifications", self.responses(Default={"__error__": "ResourceNotFoundException"}))
        self.assertEqual(flags(found), [("Default", "not_applicable")])

    def test_a_blocked_vault_is_unverified_and_does_not_hide_the_others(self):
        found = evaluate("backup_vault_notifications", self.responses(**{"acme-notes-vault": {"__error__": "ACCESS_DENIED"},
                                                                         "acme-notes-quiet": fx("backup-get-backup-vault-notifications-completed-only")}))
        self.assertEqual(flags(found), [("acme-notes-vault", "unverified"), ("acme-notes-quiet", "offender")])
        self.assertEqual(found[0]["detail"]["error_code"], "ACCESS_DENIED")

    def test_unexpected_call_errors_are_unverified(self):
        found = evaluate("backup_vault_notifications", self.responses(**{"acme-notes-vault": {"__error__": "THROTTLED"}}))
        self.assertEqual(flags(found), [("acme-notes-vault", "unverified")])


class BackupPlanRulesTests(unittest.TestCase):
    PARAMS = {"min_days": 7}

    @staticmethod
    def responses(plans="backup-list-backup-plans-one", **details):
        return merge({"plans": [(REGION, fx(plans))]}, for_each("details", list(details.items())))

    @staticmethod
    def plan(*rules):
        return {"BackupPlanId": PLAN_ID, "BackupPlan": {"BackupPlanName": "acme-notes-daily", "Rules": list(rules)}}

    @staticmethod
    def rule(schedule="cron(0 5 ? * * *)", days=35):
        rule = {"RuleName": "r", "TargetBackupVaultName": "v", "ScheduleExpression": schedule}
        if days is not None:
            rule["Lifecycle"] = {"DeleteAfterDays": days}
        return rule

    def test_backup_plan_rules_pass(self):
        self.assertEqual(evaluate("backup_plan_rules", self.responses(**{PLAN_ID: fx("backup-get-backup-plan-daily")}), self.PARAMS), [])

    def test_backup_plan_rules_fail_reports_offenders(self):
        (offender,) = evaluate("backup_plan_rules", self.responses("backup-list-backup-plans-one", **{WEEKLY_ID: fx("backup-get-backup-plan-weekly")}), self.PARAMS)
        self.assertEqual((offender["resource_id"], offender["region"]), ("aws-backup", REGION))
        self.assertEqual(offender["detail"]["plans"], [{"plan": "acme-notes-weekly", "region": REGION,
                                                        "rules": [{"name": "weekly", "schedule": "cron(0 5 ? * SUN *)", "daily": False, "retention_days": 35}]}])
        self.assertEqual(offender["detail"]["reason"], "ningún plan de AWS Backup tiene una regla diaria con retención de al menos 7 días")

    def test_weekly_or_archive_plans_do_not_fail_when_a_qualifying_daily_plan_exists(self):
        responses = self.responses("backup-list-backup-plans-two", **{PLAN_ID: fx("backup-get-backup-plan-daily"), WEEKLY_ID: fx("backup-get-backup-plan-weekly")})
        self.assertEqual(evaluate("backup_plan_rules", responses, self.PARAMS), [])
        reverse = self.responses("backup-list-backup-plans-two", **{WEEKLY_ID: fx("backup-get-backup-plan-weekly"), PLAN_ID: fx("backup-get-backup-plan-daily")})
        self.assertEqual(evaluate("backup_plan_rules", reverse, self.PARAMS), [])

    def test_no_plan_qualifies_when_the_daily_one_keeps_too_little_and_the_other_is_weekly(self):
        responses = self.responses("backup-list-backup-plans-two", **{PLAN_ID: fx("backup-get-backup-plan-short"), WEEKLY_ID: fx("backup-get-backup-plan-weekly")})
        (offender,) = evaluate("backup_plan_rules", responses, self.PARAMS)
        self.assertEqual([p["plan"] for p in offender["detail"]["plans"]], ["acme-notes-short", "acme-notes-weekly"])

    def test_retention_boundaries(self):
        def passes(days):
            return not evaluate("backup_plan_rules", self.responses(**{PLAN_ID: self.plan(self.rule(days=days))}), self.PARAMS)
        self.assertFalse(passes(1))
        self.assertFalse(passes(6))
        self.assertTrue(passes(7))
        self.assertTrue(passes(8))

    def test_no_expiry_means_kept_forever_and_passes(self):
        self.assertEqual(evaluate("backup_plan_rules", self.responses(**{PLAN_ID: self.plan(self.rule(days=None))}), self.PARAMS), [])

    def test_daily_and_more_frequent_schedules_pass(self):
        for schedule in ("cron(0 5 ? * * *)", "cron(0 5 * * ? *)", "cron(0 */6 ? * * *)", "cron(0 * ? * * *)", "CRON(15 3 ? * * *)"):
            self.assertEqual(evaluate("backup_plan_rules", self.responses(**{PLAN_ID: self.plan(self.rule(schedule))}), self.PARAMS), [], schedule)

    def test_less_frequent_or_unmodelled_schedules_fail(self):
        for schedule in ("cron(0 5 ? * SUN *)", "cron(0 5 ? * MON-FRI *)", "cron(0 5 1 * ? *)", "cron(0 5 ? 1 * *)", "cron(0 5 ? * * 2026)",
                         "rate(1 day)", "cron(0 5 ? * *)", "", "not a schedule"):
            self.assertEqual(ids(evaluate("backup_plan_rules", self.responses(**{PLAN_ID: self.plan(self.rule(schedule))}), self.PARAMS)),
                             ["aws-backup"], schedule)

    def test_the_daily_rule_must_be_the_one_with_enough_retention(self):
        plan = self.plan(self.rule("cron(0 5 ? * * *)", 3), self.rule("cron(0 5 ? * SUN *)", 90))
        self.assertEqual(ids(evaluate("backup_plan_rules", self.responses(**{PLAN_ID: plan}), self.PARAMS)), ["aws-backup"])
        plan = self.plan(self.rule("cron(0 5 ? * * *)", 3), self.rule("cron(0 6 ? * * *)", 30))
        self.assertEqual(evaluate("backup_plan_rules", self.responses(**{PLAN_ID: plan}), self.PARAMS), [])

    def test_plan_without_rules_fails(self):
        self.assertEqual(ids(evaluate("backup_plan_rules", self.responses(**{PLAN_ID: self.plan()}), self.PARAMS)), ["aws-backup"])

    def test_no_plan_in_any_region_fails_once(self):
        found = evaluate("backup_plan_rules", {**self.responses("backup-list-backup-plans-none"), "plans": [(REGION, fx("backup-list-backup-plans-none")),
                                                                                                          (OTHER, fx("backup-list-backup-plans-none"))]}, self.PARAMS)
        self.assertEqual([(o["resource_id"], o["region"]) for o in found], [("aws-backup", REGION)])
        self.assertEqual(found[0]["detail"]["plans"], [])

    def test_deleted_plan_is_skipped_and_a_blocked_plan_is_unverified_unless_another_plan_qualifies(self):
        responses = self.responses("backup-list-backup-plans-two", **{PLAN_ID: {"__error__": "ResourceNotFoundException"}, WEEKLY_ID: {"__error__": "ACCESS_DENIED"}})
        found = evaluate("backup_plan_rules", responses, self.PARAMS)
        self.assertEqual(flags(found), [(WEEKLY_ID, "unverified")])
        self.assertEqual(found[0]["detail"]["error_code"], "ACCESS_DENIED")
        qualifying = self.responses("backup-list-backup-plans-two", **{PLAN_ID: fx("backup-get-backup-plan-daily"), WEEKLY_ID: {"__error__": "ACCESS_DENIED"}})
        self.assertEqual(evaluate("backup_plan_rules", qualifying, self.PARAMS), [])


class DataCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks = json.loads(DATA_JSON.read_text(encoding="utf-8"))["checks"]

    def search(self, check_id, document):
        return jmespath.search(catalog_check(check_id)["verify"]["offenders"], document)

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_dat_003_reports_instances_without_auto_minor_upgrade(self):
        self.assertEqual(self.search("DAT-003", fx("rds-describe-db-instances-raw")), fx("rds-describe-db-instances-minor-offenders"))
        self.assertEqual(self.search("DAT-003", {"DBInstances": []}), [])

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_dat_003_a_missing_field_is_not_enabled(self):
        found = self.search("DAT-003", {"DBInstances": [{"DBInstanceIdentifier": "x", "Engine": "mysql"}]})
        self.assertEqual([o["resource_id"] for o in found], ["x"])

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_dat_004_reports_instances_without_deletion_protection(self):
        self.assertEqual(self.search("DAT-004", fx("rds-describe-db-instances-raw")), fx("rds-describe-db-instances-deletion-offenders"))
        self.assertEqual(self.search("DAT-004", {"DBInstances": []}), [])

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_dat_011_reports_replication_groups_without_multi_az(self):
        self.assertEqual(self.search("DAT-011", fx("elasticache-describe-replication-groups-raw")), fx("elasticache-describe-replication-groups-offenders"))
        self.assertEqual(self.search("DAT-011", {"ReplicationGroups": []}), [])

    def test_data_catalog_valid(self):
        data = json.loads(DATA_JSON.read_text(encoding="utf-8"))
        for check in data["checks"]:
            check.setdefault("domain", data["domain"])
        tsc_ids, iso_ids = catalog.load_frameworks(REFS / "frameworks")
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        self.assertEqual(catalog.validate(data["checks"], tsc_ids, iso_ids, drata), [])
        self.assertEqual([c["id"] for c in data["checks"]], [f"DAT-{n:03d}" for n in range(1, 12)])
        self.assertEqual(data["domain"], "data")

    def test_every_python_evaluator_is_registered(self):
        for check in self.checks:
            kind, _, name = check["verify"]["evaluator"].partition(":")
            if kind == "python":
                self.assertIn(name, evaluators.EVALUATORS, check["id"])

    def test_evaluator_kinds(self):
        expected = {"DAT-001": "python:rds_backups", "DAT-002": "python:rds_multi_az", "DAT-003": "jmespath", "DAT-004": "jmespath",
                    "DAT-005": "python:ddb_pitr", "DAT-006": "python:s3_versioning", "DAT-007": "python:s3_bpa",
                    "DAT-008": "python:backup_jobs_recent", "DAT-009": "python:backup_vault_notifications", "DAT-010": "python:backup_plan_rules",
                    "DAT-011": "jmespath"}
        self.assertEqual({c["id"]: c["verify"]["evaluator"] for c in self.checks}, expected)

    def test_severities_follow_the_brief(self):
        expected = {"DAT-001": "high", "DAT-002": "high", "DAT-003": "high", "DAT-004": "medium", "DAT-005": "high", "DAT-006": "high",
                    "DAT-007": "critical", "DAT-008": "high", "DAT-009": "high", "DAT-010": "medium", "DAT-011": "high"}
        self.assertEqual({c["id"]: c["severity"] for c in self.checks}, expected)

    def test_remediation_kinds_follow_the_brief(self):
        expected = {"DAT-001": "planned_change", "DAT-002": "planned_change", "DAT-003": "cli", "DAT-004": "cli", "DAT-005": "cli", "DAT-006": "cli_with_decision",
                    "DAT-007": "cli_with_decision", "DAT-008": "planned_change", "DAT-009": "cli_with_decision", "DAT-010": "cli_with_decision",
                    "DAT-011": "planned_change"}
        self.assertEqual({c["id"]: c["remediation"]["kind"] for c in self.checks}, expected)

    def test_scopes_resource_types_and_regions(self):
        expected = {"DAT-001": ["rds_instance"], "DAT-002": ["rds_instance"], "DAT-003": ["rds_instance"], "DAT-004": ["rds_instance"],
                    "DAT-005": ["dynamodb_table"], "DAT-006": ["s3_bucket"], "DAT-007": ["s3_bucket"], "DAT-008": ["backup_vault"],
                    "DAT-009": ["backup_vault"], "DAT-011": ["elasticache_group"]}
        self.assertEqual({c["id"]: c["resource_types"] for c in self.checks if c["scope"] == "resource"}, expected)
        self.assertEqual({c["id"] for c in self.checks if c["scope"] == "account"}, {"DAT-010"})
        self.assertFalse([c["id"] for c in self.checks if c["all_regions"]])

    def test_per_item_reads_declare_the_errors_the_evaluator_handles(self):
        expected = {"DAT-005": ("describe-continuous-backups", ["TableNotFoundException"]),
                    "DAT-006": ("get-bucket-versioning", ["NoSuchBucket"]),
                    "DAT-007": ("get-public-access-block", ["NoSuchPublicAccessBlockConfiguration", "NoSuchBucket"])}
        for check_id, (operation, ok_errors) in expected.items():
            (call,) = catalog_check(check_id)["verify"]["calls"]
            self.assertEqual((call["operation"], call["ok_errors"], call["item_errors"]), (operation, ok_errors, "evaluator"), check_id)
            self.assertEqual(call["for_each"]["from"], "__inventory__", check_id)

    def test_dat_007_reads_every_bucket_through_global_us_east_1(self):
        (call,) = catalog_check("DAT-007")["verify"]["calls"]
        self.assertEqual((call["service"], call["region"], call["for_each"]), ("s3api", "global", {"from": "__inventory__", "path": "id", "arg": "--bucket"}))

    def test_backup_checks_read_the_right_operations_and_declare_item_errors(self):
        calls = {c["name"]: c for c in catalog_check("DAT-009")["verify"]["calls"]}
        self.assertEqual((calls["vaults"]["operation"], calls["notifications"]["operation"]), ("list-backup-vaults", "get-backup-vault-notifications"))
        self.assertEqual(calls["notifications"]["for_each"], {"from": "__inventory__", "path": "id", "arg": "--backup-vault-name"})
        self.assertEqual((calls["notifications"]["ok_errors"], calls["notifications"]["item_errors"]), (["ResourceNotFoundException"], "evaluator"))
        calls = {c["name"]: c for c in catalog_check("DAT-010")["verify"]["calls"]}
        self.assertEqual(calls["details"]["for_each"], {"from": "plans", "path": "BackupPlansList[].BackupPlanId", "arg": "--backup-plan-id"})
        self.assertEqual((calls["details"]["ok_errors"], calls["details"]["item_errors"]), (["ResourceNotFoundException"], "evaluator"))
        calls = {c["name"]: c["operation"] for c in catalog_check("DAT-008")["verify"]["calls"]}
        self.assertEqual(calls, {"jobs": "list-backup-jobs", "vaults": "list-backup-vaults"})

    def test_backup_jobs_and_notifications_are_never_a_vacuous_pass(self):
        for check_id in ("DAT-008", "DAT-009"):
            check = catalog_check(check_id)
            self.assertEqual((check["scope"], check["resource_types"]), ("resource", ["backup_vault"]), check_id)
            self.assertRegex(check["verify"]["pass_when_text"], r"N/A", check_id)

    def test_dat_010_is_account_level_and_says_so(self):
        check = catalog_check("DAT-010")
        self.assertEqual(check["scope"], "account")
        self.assertRegex(check["title"], r"(?i)al menos un plan")
        self.assertRegex(check["verify"]["pass_when_text"], r"semanales o de archivo no fallan")

    def test_dat_011_has_a_standalone_block_for_groups_that_already_have_a_replica(self):
        commands = catalog_check("DAT-011")["remediation"]["commands"]
        standalone = [c for c in commands if "increase-replica-count" not in c]
        self.assertEqual(len(standalone), 1)
        self.assertIn("modify-replication-group --replication-group-id \"$RG_ID\" --automatic-failover-enabled --multi-az-enabled", standalone[0])

    def test_thresholds_are_params(self):
        self.assertEqual(catalog_check("DAT-001")["verify"]["params"], {"min_days": 7})
        self.assertEqual(catalog_check("DAT-008")["verify"]["params"], {"window_hours": 24})
        self.assertEqual(catalog_check("DAT-010")["verify"]["params"], {"min_days": 7})

    def test_dat_005_and_006_read_each_inventory_item(self):
        for check_id, arg in (("DAT-005", "--table-name"), ("DAT-006", "--bucket")):
            (call,) = catalog_check(check_id)["verify"]["calls"]
            self.assertEqual(call["for_each"], {"from": "__inventory__", "path": "id", "arg": arg}, check_id)

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

    @unittest.skipUnless(shutil.which("bash"), "bash not installed")
    def test_remediation_commands_and_verification_parse_as_bash(self):
        for check in self.checks:
            rem = check["remediation"]
            for text in [*rem["commands"], rem["verify_after"]]:
                script = text.replace("{region}", "us-east-1").replace("{account_id}", "111122223333").replace("{resource_id}", "acme-notes-x")
                done = subprocess.run(["bash", "-n"], input=script, capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, f"{check['id']}: {done.stderr}\n{script}")

    def test_planned_changes_warn_in_notes(self):
        for check in self.checks:
            if check["remediation"]["kind"] == "planned_change":
                self.assertGreaterEqual(len(check["remediation"]["steps"]), 2, check["id"])
                self.assertTrue(check["remediation"]["notes"].strip(), check["id"])

    def test_drata_mapped_checks_resolve_from_the_dcf_file(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        expected = {"DAT-001": 107, "DAT-002": 30, "DAT-003": 219, "DAT-005": 301, "DAT-006": 108, "DAT-007": 104, "DAT-008": 132, "DAT-009": 133,
                    "DAT-011": 30}
        for check_id, test in expected.items():
            resolved = catalog.resolve_mappings(catalog_check(check_id), drata)
            self.assertEqual([m["test"] for m in resolved["drata"]], [test], check_id)
            self.assertTrue(resolved["tsc"] and all(t["sourced"] == catalog.DCF_SOURCE for t in resolved["tsc"]), check_id)

    def test_checks_without_a_drata_test_carry_inferred_mappings(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        for check_id in ("DAT-004", "DAT-010"):
            self.assertEqual(catalog_check(check_id)["mappings"]["drata"], [])
            resolved = catalog.resolve_mappings(catalog_check(check_id), drata)
            self.assertTrue(resolved["tsc"] and resolved["iso27001_2022"], check_id)
            self.assertTrue(all(m["sourced"] is False for m in resolved["tsc"] + resolved["iso27001_2022"]), check_id)

    def test_vanta_tests_follow_the_cis_table(self):
        expected = {"DAT-003": ["Auto minor version upgrade is enabled for RDS instances"], "DAT-007": ["Buckets use Block Public Access settings"]}
        for check in self.checks:
            self.assertEqual([m["test"] for m in check["mappings"]["vanta"]], expected.get(check["id"], []), check["id"])

    def test_security_hub_controls_follow_the_brief(self):
        expected = {"DAT-001": "RDS.11", "DAT-002": "RDS.5", "DAT-003": "RDS.13", "DAT-004": "RDS.8", "DAT-005": "DynamoDB.2", "DAT-007": "S3.8",
                    "DAT-011": "ElastiCache.3"}
        for check in self.checks:
            self.assertEqual(check["mappings"]["security_hub"], [expected[check["id"]]] if check["id"] in expected else [], check["id"])

    def test_dat_001_documents_the_severity_override_and_the_threshold(self):
        check = catalog_check("DAT-001")
        self.assertRegex(check["verify"]["pass_when_text"], r"severity_override|severidad")
        self.assertIn("7", check["verify"]["pass_when_text"])

    def test_dat_002_applies_to_prod_or_untagged(self):
        text = catalog_check("DAT-002")["verify"]["pass_when_text"]
        self.assertIn("Environment", text)
        self.assertIn("production", text)

    def test_dat_007_command_sets_the_four_flags(self):
        text = "\n".join(catalog_check("DAT-007")["remediation"]["commands"])
        self.assertIn("BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", text)

    def test_dat_001_commands_cover_instances_and_cluster_members(self):
        text = "\n".join(catalog_check("DAT-001")["remediation"]["commands"])
        self.assertIn("modify-db-instance", text)
        self.assertIn("modify-db-cluster", text)
        self.assertIn("--backup-retention-period 7", text)

    def test_dat_009_does_not_replace_an_existing_topic_policy(self):
        text = "\n".join(catalog_check("DAT-009")["remediation"]["commands"])
        self.assertIn("put-backup-vault-notifications", text)
        self.assertIn("BACKUP_JOB_FAILED", text)
        self.assertRegex(catalog_check("DAT-009")["remediation"]["notes"], r"(?i)policy")

    def test_dat_002_and_dat_011_are_planned_changes_that_warn_about_cost(self):
        for check_id in ("DAT-002", "DAT-011"):
            self.assertRegex(catalog_check(check_id)["remediation"]["notes"], r"(?i)costo", check_id)


class DataCollectTests(unittest.TestCase):
    """The whole data catalog through collect.main with a fake AWS: wiring of calls, for_each, ok_errors, item_errors and args."""

    TYPES = ("rds_instance", "dynamodb_table", "s3_bucket", "elasticache_group", "backup_vault")
    TABLES = ("acme-notes-sessions", "acme-notes-audit", "acme-notes-gone", "acme-notes-denied")

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        (cls.tmp / "checks").mkdir()
        data = json.loads(DATA_JSON.read_text(encoding="utf-8"))
        for check in data["checks"]:
            if check["id"] == "DAT-008":
                check["verify"]["params"]["now"] = NOW
        (cls.tmp / "checks" / "data.json").write_text(json.dumps(data), encoding="utf-8")
        specs = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))
        (cls.tmp / "inventory.json").write_text(json.dumps({t: specs[t] for t in cls.TYPES}), encoding="utf-8")
        scope = {"platform": "Acme Notes", "mode": "full", "target": None, "regions": [REGION], "profile": None, "resources": [], "domains": None}
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
        data = lambda name: ok(fx(name))
        no_table = err("An error occurred (TableNotFoundException) when calling the DescribeContinuousBackups operation: Table not found")
        denied_table = err("An error occurred (AccessDeniedException) when calling the DescribeContinuousBackups operation: User is not authorized to perform: "
                           "dynamodb:DescribeContinuousBackups")
        no_bpa = err("An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation: "
                     "The public access block configuration was not found")
        denied_bucket = err("An error occurred (AccessDenied) when calling the GetBucketVersioning operation: Access Denied")
        no_notifications = err("An error occurred (ResourceNotFoundException) when calling the GetBackupVaultNotifications operation: no notifications")
        return [
            ("sts", "get-caller-identity", None, "", core("sts-get-caller-identity")),
            ("ec2", "describe-regions", None, "", core("ec2-describe-regions")),
            ("iam", "list-attached-user-policies", None, "", ok({"AttachedPolicies": []})),
            # inventory listings (no --query) next to the checks that use --query
            ("rds", "describe-db-instances", None, "AutoMinorVersionUpgrade", data("rds-describe-db-instances-minor-offenders")),
            ("rds", "describe-db-instances", None, "DeletionProtection", data("rds-describe-db-instances-deletion-offenders")),
            ("rds", "describe-db-instances", None, "", data("rds-describe-db-instances-raw")),
            ("elasticache", "describe-replication-groups", None, "MultiAZ", data("elasticache-describe-replication-groups-offenders")),
            ("elasticache", "describe-replication-groups", None, "", data("elasticache-describe-replication-groups-raw")),
            ("dynamodb", "list-tables", None, "", ok({"TableNames": list(cls.TABLES)})),
            ("dynamodb", "describe-continuous-backups", None, "acme-notes-sessions", data("dynamodb-describe-continuous-backups-enabled")),
            ("dynamodb", "describe-continuous-backups", None, "acme-notes-audit", data("dynamodb-describe-continuous-backups-disabled")),
            ("dynamodb", "describe-continuous-backups", None, "acme-notes-gone", no_table),
            ("dynamodb", "describe-continuous-backups", None, "acme-notes-denied", denied_table),
            ("s3api", "list-buckets", None, "", core("s3api-list-buckets")),
            ("s3api", "get-bucket-versioning", None, "acme-notes-data", data("s3api-get-bucket-versioning-enabled")),
            ("s3api", "get-bucket-versioning", None, "acme-notes-logs", denied_bucket),
            ("s3api", "get-public-access-block", None, "acme-notes-data", data("s3api-get-public-access-block-all")),
            ("s3api", "get-public-access-block", None, "acme-notes-logs", no_bpa),
            ("backup", "list-backup-jobs", None, "", data("backup-list-backup-jobs-mixed")),
            ("backup", "list-backup-plans", None, "", data("backup-list-backup-plans-two")),
            ("backup", "list-backup-vaults", None, "", data("backup-list-backup-vaults")),
            ("backup", "get-backup-vault-notifications", None, "acme-notes-vault", data("backup-get-backup-vault-notifications-failed")),
            ("backup", "get-backup-vault-notifications", None, "acme-notes-quiet", data("backup-get-backup-vault-notifications-completed-only")),
            ("backup", "get-backup-vault-notifications", None, "Default", no_notifications),
            ("backup", "get-backup-plan", None, PLAN_ID, data("backup-get-backup-plan-daily")),
            ("backup", "get-backup-plan", None, WEEKLY_ID, data("backup-get-backup-plan-weekly")),
        ]

    def rows(self, check_id):
        return [(r["status"], r["resource_id"], r["region"]) for r in self.result["results"] if r["check_id"] == check_id]

    def test_run_succeeds_and_only_the_blocked_items_are_unverified(self):
        self.assertEqual(self.code, 0)
        unverified = [(r["check_id"], r["resource_id"]) for r in self.result["results"] if r["status"] == "NO_VERIFICADO"]
        self.assertEqual(unverified, [("DAT-005", "acme-notes-denied"), ("DAT-006", "acme-notes-logs")])

    def test_rds_outcomes(self):
        self.assertEqual(self.rows("DAT-001"), [("FAIL", AURORA, REGION), ("PASS", DB, REGION), ("FAIL", LEGACY, REGION), ("FAIL", STAGING, REGION),
                                                ("FAIL", UNTAGGED, REGION)])
        self.assertEqual(self.rows("DAT-002"), [("PASS", DB, REGION), ("FAIL", LEGACY, REGION), ("FAIL", UNTAGGED, REGION)])
        self.assertEqual(self.rows("DAT-003"), [("PASS", AURORA, REGION), ("PASS", DB, REGION), ("FAIL", LEGACY, REGION), ("PASS", STAGING, REGION),
                                                ("FAIL", UNTAGGED, REGION)])
        self.assertEqual(self.rows("DAT-004"), [("FAIL", AURORA, REGION), ("PASS", DB, REGION), ("FAIL", LEGACY, REGION), ("FAIL", STAGING, REGION),
                                                ("PASS", UNTAGGED, REGION)])

    def test_dat_001_keeps_the_severity_override_in_the_row_detail(self):
        rows = {r["resource_id"]: r for r in self.result["results"] if r["check_id"] == "DAT-001"}
        self.assertNotIn("severity_override", rows[LEGACY]["detail"])
        self.assertEqual(rows[STAGING]["detail"]["severity_override"], "low")

    def test_dynamodb_and_s3_outcomes(self):
        self.assertEqual(self.rows("DAT-005"), [("FAIL", "acme-notes-audit", REGION), ("NO_VERIFICADO", "acme-notes-denied", REGION),
                                                ("PASS", "acme-notes-sessions", REGION)])
        self.assertEqual(self.rows("DAT-006"), [("PASS", "acme-notes-data", REGION), ("NO_VERIFICADO", "acme-notes-logs", REGION)])
        self.assertEqual(self.rows("DAT-007"), [("PASS", "acme-notes-data", REGION), ("FAIL", "acme-notes-logs", REGION)])

    def test_a_blocked_item_names_the_missing_permissions_and_does_not_hide_the_others(self):
        for check_id, resource in (("DAT-005", "acme-notes-denied"), ("DAT-006", "acme-notes-logs")):
            (row,) = [r for r in self.result["results"] if r["check_id"] == check_id and r["resource_id"] == resource]
            self.assertEqual(row["detail"]["error_code"], "ACCESS_DENIED")
            self.assertEqual(row["missing"], catalog_check(check_id)["verify"]["needs"])

    def test_elasticache_outcomes(self):
        self.assertEqual(self.rows("DAT-011"), [("PASS", "acme-notes-cache", REGION), ("FAIL", "acme-notes-queue", REGION), ("FAIL", "acme-notes-sessions", REGION)])

    def test_backup_outcomes(self):
        self.assertEqual(self.rows("DAT-008"), [("FAIL", "acme-notes-quiet", REGION), ("PASS", "acme-notes-vault", REGION)])
        self.assertEqual(self.rows("DAT-009"), [("FAIL", "acme-notes-quiet", REGION), ("PASS", "acme-notes-vault", REGION)])
        self.assertEqual(self.rows("DAT-010"), [("PASS", "account", None)])

    def test_every_dynamodb_table_and_bucket_is_read_once(self):
        tables = [c[c.index("--table-name") + 1] for c in self.runner.calls if c[2] == "describe-continuous-backups"]
        self.assertEqual(sorted(tables), sorted(self.TABLES))
        buckets = sorted(c[c.index("--bucket") + 1] for c in self.runner.calls if c[2] == "get-public-access-block")
        self.assertEqual(buckets, ["acme-notes-data", "acme-notes-logs"])


class DataBackupVacuousTests(unittest.TestCase):
    """Accounts without AWS Backup: DAT-008 and DAT-009 are N/A (vacuous), never PASS."""

    def run_collect(self, vaults, jobs):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "checks").mkdir()
        shutil.copy(DATA_JSON, tmp / "checks" / "data.json")
        specs = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))
        (tmp / "inventory.json").write_text(json.dumps({"backup_vault": specs["backup_vault"]}), encoding="utf-8")
        scope = {"platform": "Acme Notes", "mode": "full", "target": None, "regions": [REGION], "profile": None, "resources": [], "domains": None}
        (tmp / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
        core = lambda name: ok(load_fixture(f"aws/core/{name}.json"))
        runner = RuleRunner([
            ("sts", "get-caller-identity", None, "", core("sts-get-caller-identity")), ("ec2", "describe-regions", None, "", core("ec2-describe-regions")),
            ("iam", "list-attached-user-policies", None, "", ok({"AttachedPolicies": []})),
            ("backup", "list-backup-vaults", None, "", ok(vaults)), ("backup", "list-backup-jobs", None, "", ok(jobs)),
            ("backup", "list-backup-plans", None, "", ok({"BackupPlansList": []})),
            ("backup", "get-backup-vault-notifications", None, "", err("An error occurred (ResourceNotFoundException) when calling the GetBackupVaultNotifications operation"))])
        with contextlib.redirect_stdout(io.StringIO()):
            collect.main(["--scope", str(tmp / "scope.json"), "--out", str(tmp / "out"), "--checks-dir", str(tmp / "checks"),
                          "--inventory", str(tmp / "inventory.json"), "--quiet"], runner=runner, sleep=lambda s: None, which=lambda name: None)
        results = json.loads((tmp / "out" / "checks-result.json").read_text(encoding="utf-8"))["results"]
        return {c: [(r["status"], r["vacuous"]) for r in results if r["check_id"] == c] for c in ("DAT-008", "DAT-009", "DAT-010")}

    def test_no_vaults_means_na_vacuous(self):
        rows = self.run_collect({"BackupVaultList": []}, {"BackupJobs": []})
        self.assertEqual(rows["DAT-008"], [("N/A", True)])
        self.assertEqual(rows["DAT-009"], [("N/A", True)])

    def test_only_empty_vaults_mean_na_too(self):
        rows = self.run_collect(fx("backup-list-backup-vaults-empty"), {"BackupJobs": []})
        self.assertEqual(rows["DAT-008"], [("N/A", True)])
        self.assertEqual(rows["DAT-009"], [("N/A", True)])

    def test_dat_010_still_fails_once_when_there_is_no_plan(self):
        self.assertEqual(self.run_collect({"BackupVaultList": []}, {"BackupJobs": []})["DAT-010"], [("FAIL", False)])


if __name__ == "__main__":
    unittest.main()
