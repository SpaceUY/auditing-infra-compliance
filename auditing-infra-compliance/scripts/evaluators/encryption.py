"""Encryption evaluators: at rest (EBS, RDS, S3, KMS) and in transit (S3, ALB, RDS, ACM)."""

import json
import re
from datetime import timedelta

from evaluators import (_for_each_pairs, _inventory_by_arn, _not_applicable, _now, _offender, _parse_time, _unreadable,
                        _unverified, register)
from evaluators.policy_glob import glob_match


# ---------------------------------------------------------------- At rest: EBS and RDS

@register("ebs_default_encryption")
def ebs_default_encryption(responses: dict, params: dict) -> list[dict]:
    """Drata 218: default EBS encryption on in every region with EC2 instances.

    The setting is per region, so every instance of a region where it is off is reported (one fix clears them all);
    a region with instances and no answer is unverified, never a pass.
    """
    enabled = {region: bool((data or {}).get("EbsEncryptionByDefault")) for region, data in responses.get("status", [])}
    offenders = []
    for instance in (i for i in responses.get("__inventory__", []) if i["type"] == "ec2_instance"):
        region = instance["region"]
        if region not in enabled:
            offenders.append(_unverified(instance["id"], region, reason="no response from get-ebs-encryption-by-default"))
        elif not enabled[region]:
            offenders.append(_offender(instance["id"], region, reason="EBS encryption by default is disabled in the region"))
    return offenders


def _rds_databases(responses: dict) -> tuple[list[tuple[str, dict]], list[tuple[str, dict]], set[tuple[str, str]]]:
    """([(region, instance)], [(region, cluster)], {(region, cluster id)})."""
    instances = [(region, db) for region, data in responses.get("instances", []) for db in (data or {}).get("DBInstances", [])]
    clusters = [(region, db) for region, data in responses.get("clusters", []) for db in (data or {}).get("DBClusters", [])]
    return instances, clusters, {(region, db["DBClusterIdentifier"]) for region, db in clusters}


def _is_cluster_member(region: str, db: dict, cluster_keys: set[tuple[str, str]]) -> bool:
    return (region, db.get("DBClusterIdentifier")) in cluster_keys


@register("rds_encrypted")
def rds_encrypted(responses: dict, params: dict) -> list[dict]:
    """Drata 68: instances and clusters with StorageEncrypted. Members of a listed cluster are judged through it."""
    instances, clusters, cluster_keys = _rds_databases(responses)
    offenders = []
    for region, db in instances:
        if _is_cluster_member(region, db, cluster_keys):
            offenders.append(_not_applicable(db["DBInstanceIdentifier"], region))
        elif not db.get("StorageEncrypted"):
            offenders.append(_offender(db["DBInstanceIdentifier"], region, kind="instance", engine=db.get("Engine"),
                                       reason="unencrypted storage"))
    offenders += [_offender(db["DBClusterIdentifier"], region, kind="cluster", engine=db.get("Engine"), reason="unencrypted storage")
                  for region, db in clusters if not db.get("StorageEncrypted")]
    return offenders


# ---------------------------------------------------------------- At rest: S3 and KMS

SSE_ALGORITHMS = frozenset({"aes256", "aws:kms", "aws:kms:dsse"})


def _default_algorithms(data: dict) -> set[str]:
    rules = (data.get("ServerSideEncryptionConfiguration") or {}).get("Rules") or []
    return {str((rule.get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm", "")).lower() for rule in rules}


@register("s3_default_encryption")
def s3_default_encryption(responses: dict, params: dict) -> list[dict]:
    """Drata 69: a default encryption rule (SSE-S3, SSE-KMS or DSSE-KMS). No configuration is signalled by an error."""
    offenders = []
    for bucket, region, data in _for_each_pairs(responses, "encryption"):
        error = (data or {}).get("__error__")
        if error == "NoSuchBucket":
            offenders.append(_not_applicable(bucket, region))
        elif error == "ServerSideEncryptionConfigurationNotFoundError":
            offenders.append(_offender(bucket, region, reason="no default encryption configured"))
        elif error:
            offenders.append(_unreadable(bucket, region, error, "get-bucket-encryption"))
        elif not _default_algorithms(data or {}) & SSE_ALGORITHMS:
            offenders.append(_offender(bucket, region, reason="the encryption rule does not define a valid algorithm"))
    return offenders


def _kms_item_error(key_id: str, region: str, code: str, call: str, tolerated: frozenset[str]) -> dict:
    """Entry for a failed per-key call (item_errors): tolerated codes mean the key is out of scope, the rest is unverified."""
    if code in tolerated:
        return _not_applicable(key_id, region)
    reason = "the key policy does not allow the auditor to query the key" if code == "ACCESS_DENIED" else "could not query the key"
    return _unverified(key_id, region, error_code=code, call=call, reason=reason)


DESCRIBE_TOLERATED = frozenset({"NotFoundException"})
ROTATION_TOLERATED = frozenset({"UnsupportedOperationException", "KMSInvalidStateException", "DisabledException", "NotFoundException"})


def _in_rotation_scope(meta: dict) -> bool:
    """Enabled customer-managed symmetric keys with KMS-generated material (the only ones that can rotate)."""
    spec = str(meta.get("KeySpec") or meta.get("CustomerMasterKeySpec") or "SYMMETRIC_DEFAULT").upper()
    return (str(meta.get("KeyManager", "")).upper() == "CUSTOMER" and spec == "SYMMETRIC_DEFAULT"
            and str(meta.get("KeyState", "")).lower() == "enabled" and str(meta.get("Origin") or "AWS_KMS").upper() == "AWS_KMS")


@register("kms_rotation")
def kms_rotation(responses: dict, params: dict) -> list[dict]:
    """Drata 223: rotation on for customer-managed symmetric keys; anything else is not applicable.

    Both calls declare item_errors: a key whose policy blocks the auditor (ACCESS_DENIED) or whose call failed otherwise is
    unverified for that key only, the other keys are still evaluated.
    """
    rotation = {(region, key): data or {} for key, region, data in _for_each_pairs(responses, "rotation")}
    offenders = []
    for key_id, region, described in _for_each_pairs(responses, "describe"):
        if "__error__" in (described or {}):
            offenders.append(_kms_item_error(key_id, region, described["__error__"], "describe-key", DESCRIBE_TOLERATED))
            continue
        meta = (described or {}).get("KeyMetadata")
        if not meta or not _in_rotation_scope(meta):
            offenders.append(_not_applicable(key_id, region))
            continue
        status = rotation.get((region, key_id))
        if status is None:
            offenders.append(_unverified(key_id, region, reason="no response from get-key-rotation-status"))
        elif "__error__" in status:
            offenders.append(_kms_item_error(key_id, region, status["__error__"], "get-key-rotation-status", ROTATION_TOLERATED))
        elif not status.get("KeyRotationEnabled"):
            offenders.append(_offender(key_id, region, arn=meta.get("Arn"), reason="automatic rotation disabled"))
    return offenders


PENDING_DELETION_STATES = frozenset({"pendingdeletion", "pendingreplicadeletion"})


@register("kms_pending_deletion")
def kms_pending_deletion(responses: dict, params: dict) -> list[dict]:
    """Keys in PendingDeletion / PendingReplicaDeletion. A key deleted meanwhile is not applicable; a key that could not
    be described (item_errors, e.g. ACCESS_DENIED) is unverified for that key only."""
    offenders = []
    for key_id, region, described in _for_each_pairs(responses, "describe"):
        if "__error__" in (described or {}):
            offenders.append(_kms_item_error(key_id, region, described["__error__"], "describe-key", DESCRIBE_TOLERATED))
            continue
        meta = (described or {}).get("KeyMetadata") or {}
        if str(meta.get("KeyState", "")).lower() in PENDING_DELETION_STATES:
            offenders.append(_offender(key_id, region, key_state=meta.get("KeyState"), deletion_date=meta.get("DeletionDate"),
                                       reason="key scheduled for deletion"))
    return offenders


# ---------------------------------------------------------------- In transit: S3

def _as_list(value: object) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _is_everyone(principal: object) -> bool:
    if principal == "*":
        return True
    return isinstance(principal, dict) and set(principal) == {"AWS"} and "*" in _as_list(principal["AWS"])


def _covers_every_s3_action(statement: dict) -> bool:
    return any(str(action).lower() in ("s3:*", "*") for action in _as_list(statement.get("Action")))


def _only_secure_transport_false(condition: object) -> bool:
    """The condition is exactly Bool aws:SecureTransport = false: any other element narrows the Deny."""
    if not isinstance(condition, dict) or len(condition) != 1:
        return False
    (operator, keys), = condition.items()
    if str(operator).lower() not in ("bool", "boolifexists") or not isinstance(keys, dict) or len(keys) != 1:
        return False
    (key, value), = keys.items()
    values = _as_list(value)
    return str(key).lower() == "aws:securetransport" and bool(values) and all(str(v).lower() == "false" for v in values)


def _is_deny_without_tls(statement: object) -> bool:
    """A Deny for everyone, all S3 actions, only when the request is not over TLS (negated elements are not modelled)."""
    if not isinstance(statement, dict) or any(k in statement for k in ("NotPrincipal", "NotAction", "NotResource")):
        return False
    return (statement.get("Effect") == "Deny" and _is_everyone(statement.get("Principal")) and _covers_every_s3_action(statement)
            and _only_secure_transport_false(statement.get("Condition")))


def _resource_matches(pattern: object, arn: str) -> bool:
    """IAM wildcard match (* and ?) of a Resource entry; the partition of the pattern is ignored."""
    normalized = re.sub(r"^arn:[^:*?]+:", "arn:aws:", str(pattern))
    return glob_match(normalized, arn)


def _denies_insecure_transport(policy: dict, bucket: str) -> bool:
    statements = _as_list(policy.get("Statement"))
    resources = [r for s in statements if _is_deny_without_tls(s) for r in _as_list(s.get("Resource"))]
    covers = lambda arn: any(_resource_matches(r, arn) for r in resources)
    return covers(f"arn:aws:s3:::{bucket}") and covers(f"arn:aws:s3:::{bucket}/object")


def _bucket_policy_document(data: dict) -> dict | None:
    try:
        document = json.loads(data["Policy"])
    except (KeyError, TypeError, ValueError):
        return None
    return document if isinstance(document, dict) else None


@register("s3_tls_only")
def s3_tls_only(responses: dict, params: dict) -> list[dict]:
    """Drata 234 / Vanta 15: an explicit Deny on aws:SecureTransport=false covering the bucket and its objects.

    A bucket without a policy (NoSuchBucketPolicy) fails.
    """
    offenders = []
    for bucket, region, data in _for_each_pairs(responses, "policy"):
        error = (data or {}).get("__error__")
        if error == "NoSuchBucket":
            offenders.append(_not_applicable(bucket, region))
        elif error == "NoSuchBucketPolicy":
            offenders.append(_offender(bucket, region, reason="no bucket policy"))
        elif error:
            offenders.append(_unreadable(bucket, region, error, "get-bucket-policy"))
        elif (document := _bucket_policy_document(data or {})) is None:
            offenders.append(_offender(bucket, region, reason="the bucket policy could not be read as JSON"))
        elif not _denies_insecure_transport(document, bucket):
            offenders.append(_offender(bucket, region, reason="no statement denies aws:SecureTransport=false on the bucket and its objects"))
    return offenders


# ---------------------------------------------------------------- In transit: ALB listeners

# TLS 1.2 or later: TLS13-1-2 / TLS13-1-3 (TLS 1.3 only), FS-1-2 and TLS-1-2 families. Everything else (TLS13-1-0/1-1, FS-1-1,
# FS-2018-06, TLS-1-0/1-1, 2016-08 and older, unknown names) is not proven to refuse TLS 1.0 / 1.1.
MODERN_TLS_POLICY = re.compile(r"^ELBSecurityPolicy-(TLS13-1-[23]|FS-1-2|TLS-1-2)-", re.IGNORECASE)
REDIRECT_STATUS_CODES = frozenset({"HTTP_301", "HTTP_302"})


def _is_alb(arn: str) -> bool:
    return ":loadbalancer/app/" in arn


def _alb_offenders(responses: dict, judge) -> list[dict]:
    """Network and gateway balancers are not applicable; an ALB is reported with the listeners `judge` rejects."""
    balancers = _inventory_by_arn(responses, "elbv2")
    offenders = [_not_applicable(i["id"], i["region"]) for i in balancers.values() if not _is_alb(i["arn"])]
    for arn, region, data in _for_each_pairs(responses, "listeners"):
        if not _is_alb(arn):
            continue
        failing = [problem for listener in (data or {}).get("Listeners", []) if (problem := judge(listener))]
        if failing:
            offenders.append(_offender(balancers.get(arn, {}).get("id", arn), region, arn=arn, listeners=failing))
    return offenders


def _redirects_to_https(action: dict) -> bool:
    config = action.get("RedirectConfig") or {}
    return (str(action.get("Type", "")).lower() == "redirect" and str(config.get("Protocol", "")).upper() == "HTTPS"
            and str(config.get("Port")) == "443" and str(config.get("StatusCode", "")).upper() in REDIRECT_STATUS_CODES)


def _http_listener_problem(listener: dict) -> dict | None:
    if str(listener.get("Protocol", "")).upper() != "HTTP" or any(_redirects_to_https(a) for a in listener.get("DefaultActions") or []):
        return None
    return {"port": listener.get("Port"), "reason": "the default action does not redirect to HTTPS:443 with 301 or 302"}


def _tls_listener_problem(listener: dict) -> dict | None:
    policy = listener.get("SslPolicy")
    if str(listener.get("Protocol", "")).upper() != "HTTPS" or (policy and MODERN_TLS_POLICY.match(policy)):
        return None
    return {"port": listener.get("Port"), "ssl_policy": policy}


@register("alb_http_redirect")
def alb_http_redirect(responses: dict, params: dict) -> list[dict]:
    """Drata 299: every HTTP listener of an ALB redirects to HTTPS:443 with 301 or 302 by default."""
    return _alb_offenders(responses, _http_listener_problem)


@register("alb_tls_policy")
def alb_tls_policy(responses: dict, params: dict) -> list[dict]:
    """Every HTTPS listener of an ALB uses a security policy that refuses TLS 1.0 and 1.1."""
    return _alb_offenders(responses, _tls_listener_problem)


# ---------------------------------------------------------------- In transit: RDS and ACM

def _ssl_parameter(engine: str | None) -> tuple[str, frozenset[str]] | None:
    """(parameter, accepted values in lower case) that forces SSL for the engine; None when the engine has none."""
    engine = (engine or "").lower()
    if engine.startswith(("postgres", "aurora-postgresql", "sqlserver")):
        return "rds.force_ssl", frozenset({"1"})
    if engine == "aurora" or engine.startswith(("mysql", "mariadb", "aurora-mysql")):
        return "require_secure_transport", frozenset({"on", "1"})
    return None


def _parameter_groups(responses: dict, call: str) -> dict[tuple[str, str], dict[str, object]]:
    """{(region, group): {parameter: value}}; a group that could not be read maps to {"__error__": code}."""
    groups = {}
    for group, region, data in _for_each_pairs(responses, call):
        if "__error__" in (data or {}):
            groups[(region, group)] = {"__error__": data["__error__"]}
        else:
            groups[(region, group)] = {p["ParameterName"]: p.get("ParameterValue") for p in (data or {}).get("Parameters", [])}
    return groups


def _force_ssl_entry(kind: str, ident: str, region: str, db: dict, group: str | None, groups: dict) -> dict | None:
    """None when the engine has no SSL parameter or the parameter is on; otherwise a not applicable/unverified/offender entry."""
    spec = _ssl_parameter(db.get("Engine"))
    if spec is None:
        return _not_applicable(ident, region)
    values = groups.get((region, group))
    if values is None or "__error__" in values:
        return _unverified(ident, region, kind=kind, parameter_group=group, error_code=(values or {}).get("__error__"),
                           reason="could not read the parameters of the parameter group")
    name, accepted = spec
    value = values.get(name)
    if value is not None and str(value).lower() in accepted:
        return None
    return _offender(ident, region, kind=kind, engine=db.get("Engine"), parameter_group=group, parameter=name, value=value)


@register("rds_force_ssl")
def rds_force_ssl(responses: dict, params: dict) -> list[dict]:
    """rds.force_ssl=1 (PostgreSQL, Aurora PostgreSQL, SQL Server) or require_secure_transport=ON (MySQL family).

    Instances read their DB parameter group, clusters their cluster parameter group; members of a listed cluster are
    judged through the cluster, and engines without such a parameter are not applicable.
    """
    instances, clusters, cluster_keys = _rds_databases(responses)
    instance_groups, cluster_groups = _parameter_groups(responses, "params"), _parameter_groups(responses, "cparams")
    entries = []
    for region, db in instances:
        ident = db["DBInstanceIdentifier"]
        if _is_cluster_member(region, db, cluster_keys):
            entries.append(_not_applicable(ident, region))
            continue
        group = ((db.get("DBParameterGroups") or [{}])[0]).get("DBParameterGroupName")
        entries.append(_force_ssl_entry("instance", ident, region, db, group, instance_groups))
    entries += [_force_ssl_entry("cluster", db["DBClusterIdentifier"], region, db, db.get("DBClusterParameterGroup"), cluster_groups)
                for region, db in clusters]
    return [entry for entry in entries if entry]


# Certificates that were never issued have no expiry to judge.
UNISSUED_CERTIFICATE_STATES = frozenset({"PENDING_VALIDATION", "VALIDATION_TIMED_OUT", "FAILED"})


@register("acm_expiry")
def acm_expiry(responses: dict, params: dict) -> list[dict]:
    """Certificates must have MORE than params.min_days left; exactly min_days, or less, fails (exact seconds)."""
    now, minimum = _now(params), timedelta(days=params["min_days"])
    offenders = []
    for arn, region, data in _for_each_pairs(responses, "certificate"):
        cert = (data or {}).get("Certificate") or {}
        not_after = _parse_time(cert.get("NotAfter"))
        if not cert or not_after is None or str(cert.get("Status", "")).upper() in UNISSUED_CERTIFICATE_STATES:
            offenders.append(_not_applicable(arn, region))
            continue
        remaining = not_after - now
        if remaining <= minimum:
            offenders.append(_offender(arn, region, domain=cert.get("DomainName"), type=cert.get("Type"), status=cert.get("Status"),
                                       not_after=cert.get("NotAfter"), days_left=remaining.days, in_use=bool(cert.get("InUseBy")),
                                       renewal=(cert.get("RenewalSummary") or {}).get("RenewalStatus"), min_days=params["min_days"]))
    return offenders
