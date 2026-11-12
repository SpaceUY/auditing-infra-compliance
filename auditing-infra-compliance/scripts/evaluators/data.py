"""Data evaluators: RDS, DynamoDB, S3 and AWS Backup."""

import re
from datetime import datetime, timedelta

from evaluators import (_first, _for_each_pairs, _not_applicable, _now, _offender, _parse_time, _unverified,
                        register)

BACKUP_ACCOUNT = "aws-backup"


def _item_failure(resource_id: str, region: str, code: str, call: str, tolerated: frozenset[str] = frozenset()) -> dict:
    """Entry for a failed per-item call (item_errors): tolerated codes mean the item is gone, the rest is unverified."""
    if code in tolerated:
        return _not_applicable(resource_id, region)
    reason = "permisos insuficientes para consultar el recurso" if code == "ACCESS_DENIED" else "no se pudo consultar el recurso"
    return _unverified(resource_id, region, error_code=code, call=call, reason=reason)


# ---------------------------------------------------------------- RDS

def _databases(responses: dict) -> list[tuple[str, dict]]:
    return [(region, db) for region, data in responses.get("instances", []) for db in (data or {}).get("DBInstances", [])]


@register("rds_backups")
def rds_backups(responses: dict, params: dict) -> list[dict]:
    """Drata 107: automatic backups on (retention > 0). A retention below params["min_days"] is still reported, with
    severity_override low: 0 is the Drata failure, 1..min_days-1 is the catalog's recommendation."""
    minimum = int(params.get("min_days", 7))
    offenders = []
    for region, db in _databases(responses):
        days = db.get("BackupRetentionPeriod")
        days = days if isinstance(days, int) else 0
        if days == 0:
            offenders.append(_offender(db["DBInstanceIdentifier"], region, backup_retention_period=0, reason="los backups automáticos están desactivados"))
        elif days < minimum:
            unit = "día" if days == 1 else "días"
            offenders.append(_offender(db["DBInstanceIdentifier"], region, backup_retention_period=days, severity_override="low",
                                       reason=f"la retención es de {days} {unit}, menos que los {minimum} recomendados"))
    return offenders


PROD_ENVIRONMENTS = frozenset({"prod", "production"})


def _environment(db: dict) -> str | None:
    return next((tag.get("Value") for tag in db.get("TagList") or [] if tag.get("Key") == "Environment"), None)


@register("rds_multi_az")
def rds_multi_az(responses: dict, params: dict) -> list[dict]:
    """Drata 30: Multi-AZ on production instances (Environment tag prod/production, or no Environment tag).
    Other environments and members of a cluster (judged through their cluster) are not applicable."""
    offenders = []
    for region, db in _databases(responses):
        name, environment = db["DBInstanceIdentifier"], _environment(db)
        in_prod_scope = not (environment or "").strip() or environment.strip().lower() in PROD_ENVIRONMENTS
        if db.get("DBClusterIdentifier") or not in_prod_scope:
            offenders.append(_not_applicable(name, region))
        elif not db.get("MultiAZ"):
            offenders.append(_offender(name, region, environment=environment, engine=db.get("Engine"), reason="la instancia no es Multi-AZ"))
    return offenders


# ---------------------------------------------------------------- DynamoDB and S3

TABLE_GONE = frozenset({"TableNotFoundException"})
BUCKET_GONE = frozenset({"NoSuchBucket"})


@register("ddb_pitr")
def ddb_pitr(responses: dict, params: dict) -> list[dict]:
    """Drata 301: point-in-time recovery enabled on every table."""
    offenders = []
    for table, region, data in _for_each_pairs(responses, "backups"):
        if "__error__" in (data or {}):
            offenders.append(_item_failure(table, region, data["__error__"], "describe-continuous-backups", TABLE_GONE))
            continue
        status = (((data or {}).get("ContinuousBackupsDescription") or {}).get("PointInTimeRecoveryDescription") or {}).get("PointInTimeRecoveryStatus")
        if str(status).lower() != "enabled":
            offenders.append(_offender(table, region, pitr_status=status, reason="la recuperación a un punto en el tiempo (PITR) no está habilitada"))
    return offenders


def _versioning_reason(status: object) -> str:
    if status is None:
        return "el versionado nunca se habilitó"
    return "el versionado está suspendido" if str(status).lower() == "suspended" else f"el versionado no está habilitado ({status})"


@register("s3_versioning")
def s3_versioning(responses: dict, params: dict) -> list[dict]:
    """Drata 108: versioning Enabled on every bucket (an empty answer means it was never enabled)."""
    offenders = []
    for bucket, region, data in _for_each_pairs(responses, "versioning"):
        if "__error__" in (data or {}):
            offenders.append(_item_failure(bucket, region, data["__error__"], "get-bucket-versioning", BUCKET_GONE))
            continue
        status = (data or {}).get("Status")
        if str(status).lower() != "enabled":
            offenders.append(_offender(bucket, region, status=status, reason=_versioning_reason(status)))
    return offenders


BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
NO_BPA = "NoSuchPublicAccessBlockConfiguration"


@register("s3_bpa")
def s3_bpa(responses: dict, params: dict) -> list[dict]:
    """Drata 104 / Vanta #16: the bucket's own Block Public Access has all four flags true (account-level is not evaluated).
    A bucket without configuration fails (NoSuchPublicAccessBlockConfiguration)."""
    offenders = []
    for bucket, region, data in _for_each_pairs(responses, "bpa"):
        error = (data or {}).get("__error__")
        if error == NO_BPA:
            offenders.append(_offender(bucket, region, missing_flags=list(BPA_FLAGS), reason="el bucket no tiene configuración de Block Public Access"))
        elif error:
            offenders.append(_item_failure(bucket, region, error, "get-public-access-block", BUCKET_GONE))
        else:
            config = (data or {}).get("PublicAccessBlockConfiguration") or {}
            missing = [flag for flag in BPA_FLAGS if config.get(flag) is not True]
            if missing:
                offenders.append(_offender(bucket, region, missing_flags=missing, reason="el Block Public Access del bucket no tiene los 4 ajustes activos"))
    return offenders


# ---------------------------------------------------------------- AWS Backup

UNSUCCESSFUL_STATES = frozenset({"FAILED", "EXPIRED", "ABORTED", "PARTIAL", "COMPLETED_WITH_ISSUES"})


def _plans_by_region(responses: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for region, data in responses.get("plans", []):
        counts[region] = counts.get(region, 0) + len((data or {}).get("BackupPlansList") or [])
    return counts


def _jobs_in_window(data: dict, now: datetime, window: timedelta) -> list[dict]:
    """Jobs created in [now - window, now], compared with total seconds."""
    def inside(job: dict) -> bool:
        created = _parse_time(job.get("CreationDate"))
        return created is not None and 0 <= (now - created).total_seconds() <= window.total_seconds()
    return [job for job in (data or {}).get("BackupJobs", []) if inside(job)]


def _resource_verdicts(jobs: list[dict]) -> dict[str, set[str]]:
    """{resource ARN: states of its jobs}."""
    states: dict[str, set[str]] = {}
    for job in jobs:
        states.setdefault(job.get("ResourceArn", "desconocido"), set()).add(str(job.get("State", "")).upper())
    return states


@register("backup_jobs_recent")
def backup_jobs_recent(responses: dict, params: dict) -> list[dict]:
    """Drata 132: every resource with an AWS Backup job in the last params["window_hours"] (default 24, clock from
    params["now"]) has a COMPLETED one. A resource whose jobs all ended unsuccessfully fails; jobs still running are neither.
    A region with backup plans and no job at all in the window fails as a whole."""
    now, window = _now(params), timedelta(hours=float(params.get("window_hours", 24)))
    hours = int(window.total_seconds() // 3600)
    plans = _plans_by_region(responses)
    offenders = []
    for region, data in responses.get("jobs", []):
        jobs = _jobs_in_window(data, now, window)
        if not jobs and plans.get(region):
            offenders.append(_offender(BACKUP_ACCOUNT, region, reason=f"hay planes de AWS Backup y ningún job en las últimas {hours} horas"))
        for resource, states in sorted(_resource_verdicts(jobs).items()):
            failed = sorted(states & UNSUCCESSFUL_STATES)
            if "COMPLETED" not in states and failed:
                offenders.append(_offender(resource, region, states=failed, reason=f"ningún job completado en las últimas {hours} horas"))
    return offenders


FAILURE_EVENT = "BACKUP_JOB_FAILED"
NOT_FOUND = "ResourceNotFoundException"


def _vault_recovery_points(responses: dict) -> dict[tuple[str, str], int | None]:
    return {(region, v["BackupVaultName"]): v.get("NumberOfRecoveryPoints")
            for region, data in responses.get("vaults", []) for v in (data or {}).get("BackupVaultList", [])}


@register("backup_vault_notifications")
def backup_vault_notifications(responses: dict, params: dict) -> list[dict]:
    """Drata 133: every vault that holds recovery points notifies BACKUP_JOB_FAILED to an SNS topic."""
    recovery_points = _vault_recovery_points(responses)
    offenders = []
    for vault, region, data in _for_each_pairs(responses, "notifications"):
        if recovery_points.get((region, vault)) == 0:
            continue
        error = (data or {}).get("__error__")
        if error == NOT_FOUND:
            offenders.append(_offender(vault, region, reason="la bóveda no tiene notificaciones configuradas"))
        elif error:
            offenders.append(_item_failure(vault, region, error, "get-backup-vault-notifications"))
        else:
            events = list((data or {}).get("BackupVaultEvents") or [])
            if not (data or {}).get("SNSTopicArn") or FAILURE_EVENT not in [str(e).upper() for e in events]:
                offenders.append(_offender(vault, region, events=events, reason=f"la bóveda no notifica {FAILURE_EVENT} a un tópico de SNS"))
    return offenders


def _is_daily(expression: object) -> bool:
    """cron(min hour day-of-month month day-of-week year) that fires at least once a day. Anything else (rate(), lists of
    weekdays, month or year restrictions) is not modelled and does not count."""
    match = re.fullmatch(r"cron\((.*)\)", str(expression or "").strip(), re.IGNORECASE)
    fields = match.group(1).split() if match else []
    if len(fields) != 6:
        return False
    day_of_month, month, day_of_week, year = fields[2:]
    return day_of_month in ("*", "?") and day_of_week in ("*", "?") and month == "*" and year == "*"


def _summarise_rule(rule: dict) -> dict:
    days = (rule.get("Lifecycle") or {}).get("DeleteAfterDays")
    return {"name": rule.get("RuleName"), "schedule": rule.get("ScheduleExpression"), "daily": _is_daily(rule.get("ScheduleExpression")),
            "retention_days": days if isinstance(days, int) else None}


def _qualifies(rule: dict, minimum: int) -> bool:
    return rule["daily"] and (rule["retention_days"] is None or rule["retention_days"] >= minimum)


@register("backup_plan_rules")
def backup_plan_rules(responses: dict, params: dict) -> list[dict]:
    """A backup plan has a daily rule whose retention is at least params["min_days"] (no expiry counts as kept).
    No plan at all in the evaluated regions is reported once, as 'aws-backup'."""
    minimum = int(params.get("min_days", 7))
    if not sum(_plans_by_region(responses).values()):
        return [_offender(BACKUP_ACCOUNT, _first(responses, "plans")[0], reason="no hay ningún plan de AWS Backup en las regiones evaluadas")]
    offenders = []
    for plan_id, region, data in _for_each_pairs(responses, "details"):
        error = (data or {}).get("__error__")
        if error == NOT_FOUND:
            continue
        if error or "BackupPlan" not in (data or {}):
            offenders.append(_item_failure(plan_id, region, error or "ERROR", "get-backup-plan"))
            continue
        plan = data["BackupPlan"]
        rules = [_summarise_rule(rule) for rule in plan.get("Rules") or []]
        if not any(_qualifies(rule, minimum) for rule in rules):
            offenders.append(_offender(plan.get("BackupPlanName", plan_id), region, plan_id=plan_id, rules=rules,
                                       reason=f"ninguna regla corre a diario con retención de al menos {minimum} días"))
    return offenders
