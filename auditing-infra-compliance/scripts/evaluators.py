"""Registry of `python:<name>` evaluators run by collect.py.

An evaluator is `fn(responses, params) -> offenders`:
  responses[call_name]    list of (region, data), one per successful call (one per expansion
                          when the call has for_each)
  responses["__for_each__"]  {call_name: [value, ...]} aligned with responses[call_name]; the
                          for_each value of each expansion (None when the call has no for_each)
  responses["__inventory__"] the inventory (list of {type, id, arn, name, region, tags})
  params                  check["verify"]["params"] (or {})
An offender is {"resource_id": str, "region": str, "detail": dict}. No offenders = the check passes.
An entry {"resource_id": str, "region": str, "not_applicable": True} is NOT an offender: the resource was not
evaluated (e.g. a bucket that is not a log bucket), so the engine emits neither a FAIL nor a PASS row for it.
It only has effect in resource-scope checks; use the helper `_not_applicable(resource_id, region)`.
A call declared with "ok_errors" whose error was one of those codes shows up as {"__error__": "<code>"}.
Evaluators that depend on the clock read an optional params["now"] (ISO 8601) so tests can pin it.

Domain sections below are separated by banners; helpers shared inside a domain are private (_prefix).
"""

import base64
import csv
import io
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Callable
from urllib.parse import unquote

Evaluator = Callable[[dict, dict], list[dict]]
EVALUATORS: dict[str, Evaluator] = {}


def register(name: str) -> Callable[[Evaluator], Evaluator]:
    def decorator(fn: Evaluator) -> Evaluator:
        if name in EVALUATORS:
            raise ValueError(f"evaluador duplicado: {name}")
        EVALUATORS[name] = fn
        return fn

    return decorator


@register("always_empty")
def always_empty(responses: dict, params: dict) -> list[dict]:
    return []


# ---------------------------------------------------------------- shared helpers

DEFAULT_REGION = "us-east-1"


def _first(responses: dict, call: str) -> tuple[str, object]:
    """(region, data) of the first response of `call`."""
    return (responses.get(call) or [(DEFAULT_REGION, None)])[0]


def _offender(resource_id: str, region: str, **detail) -> dict:
    return {"resource_id": resource_id, "region": region, "detail": detail}


def _not_applicable(resource_id: str, region: str) -> dict:
    return {"resource_id": resource_id, "region": region, "detail": {}, "not_applicable": True}


def _now(params: dict) -> datetime:
    raw = params.get("now")
    return datetime.fromisoformat(raw) if raw else datetime.now(timezone.utc)


def _parse_time(value: object) -> datetime | None:
    """Timestamps of AWS CLI output (ISO 8601 or epoch seconds); None for 'N/A', 'no_information', ..."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    if not isinstance(value, str) or not value[:1].isdigit():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _age(value: object, now: datetime) -> timedelta | None:
    parsed = _parse_time(value)
    return None if parsed is None else now - parsed


# ---------------------------------------------------------------- IAM: root account

ROOT_VIRTUAL_MFA_SERIAL = "mfa/root-account-mfa-device"


def _is_root_virtual_device(device: dict) -> bool:
    user_arn = (device.get("User") or {}).get("Arn", "")
    return user_arn.endswith(":root") or device.get("SerialNumber", "").endswith(ROOT_VIRTUAL_MFA_SERIAL)


@register("root_hardware_mfa")
def root_hardware_mfa(responses: dict, params: dict) -> list[dict]:
    region, summary = _first(responses, "summary")
    _, devices = _first(responses, "virtual_mfa")
    if not summary["SummaryMap"]["AccountMFAEnabled"]:
        return [_offender("root", region, reason="sin MFA")]
    if any(_is_root_virtual_device(d) for d in devices.get("VirtualMFADevices", [])):
        return [_offender("root", region, reason="MFA virtual")]
    return []


def _is_recent_login(event: dict, cutoff: datetime) -> bool:
    when = _parse_time(event.get("EventTime"))
    return event.get("EventName") == "ConsoleLogin" and when is not None and when >= cutoff


@register("root_usage")
def root_usage(responses: dict, params: dict) -> list[dict]:
    region, data = _first(responses, "events")
    cutoff = _now(params) - timedelta(days=params["days"])
    logins = [e for e in (data or {}).get("Events", []) if _is_recent_login(e, cutoff)]
    if len(logins) > params["max"]:
        return [_offender("root", region, console_logins=len(logins), days=params["days"])]
    return []


# ---------------------------------------------------------------- IAM: credential report

KEY_SLOTS = ("access_key_1", "access_key_2")


def _credential_users(responses: dict) -> tuple[str, list[dict]]:
    """Rows of the credential report (CSV in base64) without the root row."""
    region, data = _first(responses, "report")
    content = base64.b64decode(data["Content"]).decode("utf-8")
    return region, [row for row in csv.DictReader(io.StringIO(content)) if row["user"] != "<root_account>"]


def _is_true(value: str | None) -> bool:
    return value == "true"


def _active_keys(user: dict) -> list[str]:
    return [slot for slot in KEY_SLOTS if _is_true(user.get(f"{slot}_active"))]


def _first_age(user: dict, fields: tuple[str, ...], now: datetime) -> timedelta | None:
    """Age of the first field holding a timestamp (never-used credentials fall back to creation)."""
    return next((age for f in fields if (age := _age(user.get(f), now)) is not None), None)


@register("cred_report_console_mfa")
def cred_report_console_mfa(responses: dict, params: dict) -> list[dict]:
    region, users = _credential_users(responses)
    return [_offender(u["user"], region, password_enabled=True, mfa_active=False)
            for u in users if _is_true(u["password_enabled"]) and not _is_true(u["mfa_active"])]


@register("cred_report_key_age")
def cred_report_key_age(responses: dict, params: dict) -> list[dict]:
    """Drata 232 fails a key at `fail_at_days` or more (>=), i.e. fail_at_days is NOT the maximum allowed age."""
    region, users = _credential_users(responses)
    now, fail_at = _now(params), timedelta(days=params["fail_at_days"])
    offenders = []
    for user in users:
        old = [{"key": slot, "age_days": age.days} for slot in _active_keys(user)
               if (age := _age(user[f"{slot}_last_rotated"], now)) is not None and age >= fail_at]
        if old:
            offenders.append(_offender(user["user"], region, keys=old, fail_at_days=params["fail_at_days"]))
    return offenders


def _unused_credentials(user: dict, now: datetime, max_days: int) -> list[dict]:
    """Credentials unused for MORE than max_days (exact, to the second: 45d 1h is already 'more than 45 days')."""
    candidates = []
    if _is_true(user["password_enabled"]):
        candidates.append(("password", ("password_last_used", "password_last_changed", "user_creation_time")))
    candidates += [(slot, (f"{slot}_last_used_date", f"{slot}_last_rotated")) for slot in _active_keys(user)]
    ages = [(name, _first_age(user, fields, now)) for name, fields in candidates]
    return [{"credential": name, "unused_days": age.days} for name, age in ages
            if age is not None and age.total_seconds() > max_days * 86400]


@register("cred_report_unused")
def cred_report_unused(responses: dict, params: dict) -> list[dict]:
    region, users = _credential_users(responses)
    now, max_days = _now(params), params["max_days"]
    found = [(u["user"], _unused_credentials(u, now, max_days)) for u in users]
    return [_offender(name, region, credentials=stale, max_days=max_days) for name, stale in found if stale]


@register("cred_report_multi_keys")
def cred_report_multi_keys(responses: dict, params: dict) -> list[dict]:
    region, users = _credential_users(responses)
    return [_offender(u["user"], region, active_keys=len(_active_keys(u)))
            for u in users if len(_active_keys(u)) > 1]


@register("iam_human_users")
def iam_human_users(responses: dict, params: dict) -> list[dict]:
    """IAM users with console access are the human ones; Identity Center is the recommended replacement."""
    region, users = _credential_users(responses)
    return [_offender(u["user"], region, console_access=True, mfa_active=_is_true(u["mfa_active"]))
            for u in users if _is_true(u["password_enabled"])]


# ---------------------------------------------------------------- IAM: policies, password policy, contacts

def _password_policy(responses: dict) -> tuple[str, dict | None]:
    """The account password policy, or None when the account has none (NoSuchEntity)."""
    region, data = _first(responses, "policy")
    return region, None if "__error__" in data else data["PasswordPolicy"]


def _no_password_policy(region: str) -> dict:
    return _offender("account", region, reason="sin política de contraseñas")


@register("password_min_length")
def password_min_length(responses: dict, params: dict) -> list[dict]:
    region, policy = _password_policy(responses)
    if policy is None:
        return [_no_password_policy(region)]
    length = policy.get("MinimumPasswordLength", 0)
    if length < params["min_length"]:
        return [_offender("account", region, minimum_password_length=length, required=params["min_length"])]
    return []


@register("password_reuse_prevention")
def password_reuse_prevention(responses: dict, params: dict) -> list[dict]:
    region, policy = _password_policy(responses)
    if policy is None:
        return [_no_password_policy(region)]
    remembered = policy.get("PasswordReusePrevention", 0)
    if remembered < params["min_reuse"]:
        return [_offender("account", region, password_reuse_prevention=remembered, required=params["min_reuse"])]
    return []


@register("user_direct_policies")
def user_direct_policies(responses: dict, params: dict) -> list[dict]:
    """Users with a directly attached managed policy or an inline policy (permissions must come from groups)."""
    region, data = _first(responses, "details")
    offenders = []
    for user in data.get("UserDetailList", []):
        attached = [p["PolicyName"] for p in user.get("AttachedManagedPolicies", [])]
        inline = [p["PolicyName"] for p in user.get("UserPolicyList", [])]
        if attached or inline:
            offenders.append(_offender(user["UserName"], region, attached_policies=attached, inline_policies=inline))
    return offenders


def _policy_document(version: dict) -> dict:
    document = version.get("Document") or {}
    return json.loads(unquote(document)) if isinstance(document, str) else document


def _has_wildcard(value: object) -> bool:
    return value == "*" or (isinstance(value, list) and "*" in value)


def _is_full_admin(document: dict) -> bool:
    statements = document.get("Statement", [])
    statements = [statements] if isinstance(statements, dict) else statements
    return any(s.get("Effect") == "Allow" and _has_wildcard(s.get("Action")) and _has_wildcard(s.get("Resource"))
               for s in statements)


@register("admin_policies")
def admin_policies(responses: dict, params: dict) -> list[dict]:
    """Attached customer-managed policies whose default version allows Action * on Resource *."""
    region, data = _first(responses, "details")
    offenders = []
    for policy in data.get("Policies", []):
        default = next((v for v in policy.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), None)
        if policy.get("AttachmentCount", 0) > 0 and default and _is_full_admin(_policy_document(default)):
            offenders.append(_offender(policy["Arn"], region, policy_name=policy["PolicyName"],
                                       attachment_count=policy["AttachmentCount"]))
    return offenders


@register("alternate_contact_present")
def alternate_contact_present(responses: dict, params: dict) -> list[dict]:
    region, data = _first(responses, "contact")
    if "__error__" in data or not (data.get("AlternateContact") or {}).get("EmailAddress"):
        return [_offender("account", region, reason="sin contacto alternativo SECURITY")]
    return []


# ---------------------------------------------------------------- Logging: shared helpers

def _trail_list(responses: dict) -> list[tuple[str, dict]]:
    """[(region, trail)] of every describe-trails response; a trail seen from several regions counts once."""
    seen, found = set(), []
    for region, data in responses.get("trails", []):
        for trail in (data or {}).get("trailList", []):
            if trail["TrailARN"] not in seen:
                seen.add(trail["TrailARN"])
                found.append((region, trail))
    return found


def _for_each_pairs(responses: dict, call: str) -> list[tuple[str, str, object]]:
    """[(for_each value, region, data)] of a call that has for_each."""
    values = responses.get("__for_each__", {}).get(call, [])
    return [(value, region, data) for value, (region, data) in zip(values, responses.get(call, []))]


def _by_value(responses: dict, call: str) -> dict[str, tuple[str, object]]:
    """{for_each value: (region, data)}, first answer wins (two trails may share one bucket)."""
    found: dict[str, tuple[str, object]] = {}
    for value, region, data in _for_each_pairs(responses, call):
        found.setdefault(value, (region, data))
    return found


def _no_trails(responses: dict) -> dict:
    return _offender("account", _first(responses, "trails")[0], reason="sin trails de CloudTrail")


def _multi_region_trails(responses: dict) -> list[tuple[str, dict]]:
    return [(region, trail) for region, trail in _trail_list(responses) if trail.get("IsMultiRegionTrail")]


def _trail_names_by_bucket(responses: dict) -> dict[str, list[str]]:
    owners: dict[str, list[str]] = {}
    for _, trail in _trail_list(responses):
        owners.setdefault(trail["S3BucketName"], []).append(trail["Name"])
    return owners


def _inventory_by_arn(responses: dict, type_: str) -> dict[str, dict]:
    return {i["arn"]: i for i in responses.get("__inventory__", []) if i["type"] == type_ and i["arn"]}


# ---------------------------------------------------------------- Logging: CloudTrail

@register("cloudtrail_active")
def cloudtrail_active(responses: dict, params: dict) -> list[dict]:
    """At least one multi-region trail with IsLogging=true (a trail that exists but is stopped logs nothing)."""
    trails = _trail_list(responses)
    if not trails:
        return [_no_trails(responses)]
    logging = {arn: (data or {}).get("IsLogging") is True for arn, _, data in _for_each_pairs(responses, "status")}
    multi = _multi_region_trails(responses)
    if any(logging.get(trail["TrailARN"]) for _, trail in multi):
        return []
    if not multi:
        return [_offender("account", trails[0][0], reason="ningún trail es multi-región",
                          trails=[t["Name"] for _, t in trails])]
    return [_offender(t["Name"], r, reason="trail multi-región sin logging (IsLogging=false)") for r, t in multi]


ALL_S3_PREFIXES = ("arn:aws:s3", "arn:aws:s3:::")
READ_WRITE_COVERAGE = {"All": {"read", "write"}, "ReadOnly": {"read"}, "WriteOnly": {"write"}}
ADVANCED_FIELDS = {"eventCategory", "resources.type", "readOnly", "resources.ARN"}


def _classic_s3_coverage(selectors: list[dict]) -> set[str]:
    covered: set[str] = set()
    for selector in selectors:
        all_buckets = any(r.get("Type") == "AWS::S3::Object" and any(v in ALL_S3_PREFIXES for v in r.get("Values", []))
                          for r in selector.get("DataResources", []))
        if all_buckets:
            covered |= READ_WRITE_COVERAGE.get(selector.get("ReadWriteType", "All"), set())
    return covered


def _covers_all_s3_objects(fields: dict[str, dict]) -> bool:
    """Data events of every S3 object: only eventCategory, resources.type, readOnly and a catch-all resources.ARN."""
    if set(fields) - ADVANCED_FIELDS:
        return False
    # any operator other than Equals (NotEquals, StartsWith...) on these fields is not understood: not covered
    if any(set(fields[f]) - {"Field", "Equals"} for f in ("eventCategory", "resources.type", "readOnly") if f in fields):
        return False
    if "Data" not in fields.get("eventCategory", {}).get("Equals", []):
        return False
    if "AWS::S3::Object" not in fields.get("resources.type", {}).get("Equals", []):
        return False
    arn = fields.get("resources.ARN")
    return arn is None or (set(arn) <= {"Field", "StartsWith"} and any(v in ALL_S3_PREFIXES for v in arn.get("StartsWith", [])))


def _advanced_s3_coverage(selectors: list[dict]) -> set[str]:
    covered: set[str] = set()
    for selector in selectors:
        fields = {f["Field"]: f for f in selector.get("FieldSelectors", [])}
        if not _covers_all_s3_objects(fields):
            continue
        read_only = fields.get("readOnly", {}).get("Equals")
        covered |= {"read", "write"} if read_only is None else {d for d, v in (("read", "true"), ("write", "false")) if v in read_only}
    return covered


@register("trail_s3_data_events")
def trail_s3_data_events(responses: dict, params: dict) -> list[dict]:
    """Drata 226 / Vanta #17-#18: S3 data events, read AND write, on a multi-region trail (union across trails)."""
    trails = _trail_list(responses)
    if not trails:
        return [_no_trails(responses)]
    multi = _multi_region_trails(responses)
    if not multi:
        return [_offender("account", trails[0][0], reason="ningún trail multi-región", trails=[t["Name"] for _, t in trails])]
    multi_arns = {trail["TrailARN"] for _, trail in multi}
    covered: set[str] = set()
    for arn, _, data in _for_each_pairs(responses, "selectors"):
        if arn in multi_arns:
            covered |= _classic_s3_coverage((data or {}).get("EventSelectors") or [])
            covered |= _advanced_s3_coverage((data or {}).get("AdvancedEventSelectors") or [])
    missing = [d for d in ("read", "write") if d not in covered]
    if not missing:
        return []
    return [_offender("account", multi[0][0], reason="faltan data events de S3 en todos los buckets", missing=missing,
                      trails=[t["Name"] for _, t in multi])]


# ---------------------------------------------------------------- Logging: CloudTrail bucket

@register("trail_bucket_logging")
def trail_bucket_logging(responses: dict, params: dict) -> list[dict]:
    """Server access logging on the S3 bucket of every trail (Drata 221 / Vanta #19)."""
    owners = _trail_names_by_bucket(responses)
    offenders = []
    for bucket, (region, data) in _by_value(responses, "bucket_logging").items():
        if "__error__" in data:
            reason = "el bucket no existe"
        elif not data.get("LoggingEnabled"):
            reason = "access logging deshabilitado"
        else:
            continue
        offenders.append(_offender(bucket, region, reason=reason, trails=owners.get(bucket, [])))
    return offenders


def _is_cloudtrail_principal(principal: object) -> bool:
    service = principal.get("Service", []) if isinstance(principal, dict) else []
    return "cloudtrail.amazonaws.com" in ([service] if isinstance(service, str) else service)


def _restricts_source_arn(statement: dict) -> bool:
    conditions = statement.get("Condition") or {}
    return any(key.lower() == "aws:sourcearn" for operator in conditions.values() for key in operator)


def _policy_limits_cloudtrail_by_arn(policy: dict) -> bool:
    """Every Allow statement for the CloudTrail service principal carries an aws:SourceArn condition (confused deputy)."""
    statements = policy.get("Statement", [])
    statements = [statements] if isinstance(statements, dict) else statements
    mine = [s for s in statements if s.get("Effect") == "Allow" and _is_cloudtrail_principal(s.get("Principal"))]
    return bool(mine) and all(_restricts_source_arn(s) for s in mine)


def _bucket_problems(versioning: dict, policy: dict) -> list[str]:
    if "NoSuchBucket" in (versioning.get("__error__"), policy.get("__error__")):
        return ["el bucket no existe"]
    problems = []
    if versioning.get("Status") != "Enabled":
        problems.append("versionado no habilitado")
    if "__error__" in policy:
        problems.append("el bucket no tiene bucket policy")
    elif not _policy_limits_cloudtrail_by_arn(json.loads(policy["Policy"])):
        problems.append("la bucket policy de CloudTrail no restringe aws:SourceArn")
    return problems


@register("trail_bucket_hardening")
def trail_bucket_hardening(responses: dict, params: dict) -> list[dict]:
    """Trail bucket: versioning Enabled and a bucket policy whose CloudTrail statements use aws:SourceArn."""
    policies = _by_value(responses, "policy")
    offenders = []
    for bucket, (region, versioning) in _by_value(responses, "versioning").items():
        problems = _bucket_problems(versioning, policies.get(bucket, (region, {}))[1])
        if problems:
            offenders.append(_offender(bucket, region, problems=problems))
    return offenders


# ---------------------------------------------------------------- Logging: CloudWatch Logs, flow logs, lifecycle

LOG_GROUP_ARN = re.compile(r"^arn:[^:]+:logs:([^:]+):[^:]+:log-group:(.+?)(?::\*)?$")


@register("trail_cw_metric_filters")
def trail_cw_metric_filters(responses: dict, params: dict) -> list[dict]:
    """A multi-region trail delivers to CloudWatch Logs and its log group has a metric filter per CIS category.

    params.categories: {category: [text every filter pattern of that category must contain]}.
    """
    trails = [(t, LOG_GROUP_ARN.match(t.get("CloudWatchLogsLogGroupArn", ""))) for _, t in _multi_region_trails(responses)]
    trails = [(trail, match) for trail, match in trails if match]
    if not trails:
        return [_offender("account", _first(responses, "trails")[0],
                          reason="ningún trail multi-región envía sus logs a CloudWatch Logs")]
    patterns: dict[tuple[str, str], list[str]] = {}
    for region, data in responses.get("filters", []):
        for metric_filter in (data or {}).get("metricFilters", []):
            patterns.setdefault((region, metric_filter.get("logGroupName")), []).append(metric_filter.get("filterPattern", ""))
    offenders = []
    for trail, match in trails:
        region, group = match.groups()
        found = patterns.get((region, group), [])
        missing = [name for name, tokens in params["categories"].items()
                   if not any(all(token in pattern for token in tokens) for pattern in found)]
        if not missing:
            return []
        offenders.append(_offender(trail["Name"], region, log_group=group, missing=missing))
    return offenders


@register("vpc_flow_logs")
def vpc_flow_logs(responses: dict, params: dict) -> list[dict]:
    """Every VPC has an ACTIVE flow log on the VPC itself (a flow log on a subnet or ENI does not count)."""
    statuses: dict[tuple[str, str], list[str]] = {}
    for region, data in responses.get("flow_logs", []):
        for flow_log in (data or {}).get("FlowLogs", []):
            statuses.setdefault((region, flow_log["ResourceId"]), []).append(flow_log.get("FlowLogStatus", ""))
    offenders = []
    for vpc in (i for i in responses.get("__inventory__", []) if i["type"] == "vpc"):
        found = statuses.get((vpc["region"], vpc["id"]), [])
        if "ACTIVE" in found:
            continue
        if found:
            offenders.append(_offender(vpc["id"], vpc["region"], reason="flow log no activo", flow_log_status=found[0]))
        else:
            offenders.append(_offender(vpc["id"], vpc["region"], reason="sin flow logs"))
    return offenders


def _short_expiration(rule: dict, now: datetime, minimum: timedelta) -> dict | None:
    """The enabled rule's current-version expiration when it is shorter than `minimum` (exact, not floored days)."""
    if rule.get("Status") != "Enabled":
        return None
    expiration = rule.get("Expiration") or {}
    if "Days" in expiration and timedelta(days=expiration["Days"]) < minimum:
        return {"rule": rule.get("ID", ""), "expires_after_days": expiration["Days"]}
    date = _parse_time(expiration.get("Date"))
    if date is not None and date - now < minimum:
        return {"rule": rule.get("ID", ""), "expires_on": expiration["Date"]}
    return None


@register("log_bucket_lifecycle")
def log_bucket_lifecycle(responses: dict, params: dict) -> list[dict]:
    """Log buckets (trail destinations, or named like params.name_regex) must not expire objects before min_days.

    Buckets that are not log buckets are reported as not applicable. A log bucket without a lifecycle
    configuration keeps everything and passes. Rules about noncurrent versions and
    incomplete uploads do not shorten log retention and are ignored.
    """
    now, minimum, pattern = _now(params), timedelta(days=params["min_days"]), re.compile(params["name_regex"])
    log_buckets = {t.get("S3BucketName") for _, t in _trail_list(responses)}
    log_buckets |= {i["id"] for i in responses.get("__inventory__", []) if i["type"] == "s3_bucket" and pattern.search(i["id"].lower())}
    offenders = [_not_applicable(i["id"], i["region"]) for i in responses.get("__inventory__", [])
                 if i["type"] == "s3_bucket" and i["id"] not in log_buckets]
    for bucket, (region, data) in _by_value(responses, "lifecycle").items():
        if bucket not in log_buckets or "__error__" in data:
            continue
        short = [found for rule in data.get("Rules", []) if (found := _short_expiration(rule, now, minimum))]
        if short:
            offenders.append(_offender(bucket, region, rules=short, min_days=params["min_days"]))
    return offenders


# ---------------------------------------------------------------- Logging: ALB and WAF

@register("alb_access_logs")
def alb_access_logs(responses: dict, params: dict) -> list[dict]:
    """ALBs with access_logs.s3.enabled != true; network and gateway load balancers are reported as not applicable."""
    load_balancers = _inventory_by_arn(responses, "elbv2")
    offenders = [_not_applicable(i["id"], i["region"]) for i in load_balancers.values()
                 if ":loadbalancer/app/" not in i["arn"]]
    for arn, region, data in _for_each_pairs(responses, "attrs"):
        if ":loadbalancer/app/" not in arn:
            continue
        attributes = {a["Key"]: a["Value"] for a in (data or {}).get("Attributes", [])}
        if attributes.get("access_logs.s3.enabled") != "true":
            name = load_balancers.get(arn, {}).get("id", arn)
            offenders.append(_offender(name, region, arn=arn, reason="access logs deshabilitados"))
    return offenders


@register("waf_logging")
def waf_logging(responses: dict, params: dict) -> list[dict]:
    """Web ACLs without a logging configuration (WAFNonexistentItemException) or without log destinations."""
    web_acls = _inventory_by_arn(responses, "wafv2_web_acl")
    offenders = []
    for arn, region, data in _for_each_pairs(responses, "logging"):
        destinations = ((data or {}).get("LoggingConfiguration") or {}).get("LogDestinationConfigs") or []
        if "__error__" in data or not destinations:
            offenders.append(_offender(web_acls.get(arn, {}).get("id", arn), region, arn=arn, reason="logging del WAF deshabilitado"))
    return offenders


# ---------------------------------------------------------------- Detection: GuardDuty

GLOBAL_INVENTORY_TYPES = frozenset({"s3_bucket", "iam_user", "iam_role"})
S3_PROTECTION_FEATURE = "S3_DATA_EVENTS"


def _regions_with_resources(responses: dict, params: dict) -> set[str]:
    """Regions holding workload resources (params["resource_types"]); S3 buckets count for the default region."""
    inventory = responses.get("__inventory__", [])
    types = set(params.get("resource_types", ())) - GLOBAL_INVENTORY_TYPES
    regions = {i["region"] for i in inventory if i["type"] in types}
    return regions | ({DEFAULT_REGION} if any(i["type"] == "s3_bucket" for i in inventory) else set())


def _detectors(responses: dict) -> dict[tuple[str, str], dict]:
    """{(region, detector id): get-detector data}."""
    return {(region, detector_id): data or {} for detector_id, region, data in _for_each_pairs(responses, "detector")}


def _s3_protection_enabled(detector: dict) -> bool:
    """New API shape (Features) wins; the legacy DataSources shape is only used when Features has no S3 entry."""
    s3 = [f for f in detector.get("Features") or [] if f.get("Name") == S3_PROTECTION_FEATURE]
    if s3:
        return s3[0].get("Status") == "ENABLED"
    return ((detector.get("DataSources") or {}).get("S3Logs") or {}).get("Status") == "ENABLED"


@register("guardduty_regions")
def guardduty_regions(responses: dict, params: dict) -> list[dict]:
    """Drata 105: an enabled detector in every region with resources. Regions without resources are reported too,
    at low severity (attackers use unmonitored regions)."""
    populated = _regions_with_resources(responses, params)
    detectors = _detectors(responses)
    offenders = []
    for region, listing in responses.get("detectors", []):
        ids = (listing or {}).get("DetectorIds") or []
        if any(detectors.get((region, d), {}).get("Status") == "ENABLED" for d in ids):
            continue
        reason = "detector de GuardDuty deshabilitado" if ids else "sin detector de GuardDuty"
        extra = {} if region in populated else {"severity_override": "low"}
        offenders.append(_offender("account", region, reason=reason, has_resources=region in populated, **extra))
    return offenders


@register("guardduty_s3_protection")
def guardduty_s3_protection(responses: dict, params: dict) -> list[dict]:
    """Drata 105 passes without S3 buckets; with buckets every enabled detector needs S3 protection."""
    if not any(i["type"] == "s3_bucket" for i in responses.get("__inventory__", [])):
        return []
    enabled = {k: d for k, d in _detectors(responses).items() if d.get("Status") == "ENABLED"}
    if not enabled:
        region = _first(responses, "detectors")[0]
        return [_offender("account", region, reason="GuardDuty no está habilitado: sin S3 Protection")]
    return [_offender("account", region, reason="S3 Protection de GuardDuty deshabilitado", detector_id=detector_id)
            for (region, detector_id), detector in sorted(enabled.items()) if not _s3_protection_enabled(detector)]


def _is_guardduty_findings_rule(rule: dict) -> bool:
    """Only patterns that provably select GuardDuty findings; operators that are not modelled (prefix, ...) do not count."""
    try:
        pattern = json.loads(rule.get("EventPattern") or "")
    except ValueError:
        return False
    if not isinstance(pattern, dict):
        return False
    source, detail_type = pattern.get("source"), pattern.get("detail-type")
    return (isinstance(source, list) and "aws.guardduty" in source
            and (detail_type is None or (isinstance(detail_type, list) and "GuardDuty Finding" in detail_type)))


@register("guardduty_eventbridge")
def guardduty_eventbridge(responses: dict, params: dict) -> list[dict]:
    """Drata 105 how-to: an enabled EventBridge rule for GuardDuty findings with at least one target (any region)."""
    has_target = {(region, name) for name, region, data in _for_each_pairs(responses, "targets") if (data or {}).get("Targets")}
    found = [(region, rule) for region, data in responses.get("rules", []) for rule in (data or {}).get("Rules", [])
             if _is_guardduty_findings_rule(rule)]
    if any(rule.get("State") == "ENABLED" and (region, rule["Name"]) in has_target for region, rule in found):
        return []
    region = _first(responses, "rules")[0]
    if not found:
        return [_offender("account", region, reason="sin regla de EventBridge para findings de GuardDuty")]
    reason = ("la regla de GuardDuty está deshabilitada" if all(r.get("State") != "ENABLED" for _, r in found)
              else "la regla de GuardDuty no tiene destino")
    return [_offender("account", region, reason=reason, rules=[r["Name"] for _, r in found])]


# ---------------------------------------------------------------- Detection: Security Hub, Config, Inspector

SECURITY_HUB_STANDARDS = ("aws-foundational-security-best-practices", "cis-aws-foundations-benchmark")


def _standard_name(arn: str) -> str:
    """'arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1' -> 'pci-dss'."""
    parts = arn.split("/")
    return parts[1] if len(parts) > 1 else arn


@register("securityhub_standards")
def securityhub_standards(responses: dict, params: dict) -> list[dict]:
    """Per region with Security Hub: FSBP or CIS in READY state (a hub with other standards only does not count)."""
    offenders = []
    for region, data in responses.get("standards", []):
        subscriptions = (data or {}).get("StandardsSubscriptions") or []
        standards = [{"standard": _standard_name(s["StandardsArn"]), "status": s.get("StandardsStatus")} for s in subscriptions]
        if not any(s["standard"] in SECURITY_HUB_STANDARDS and s["status"] == "READY" for s in standards):
            offenders.append(_offender("account", region, reason="sin el estándar FSBP ni CIS en estado READY", standards=standards))
    return offenders


IAM_GLOBAL_TYPES = frozenset({"AWS::IAM::User", "AWS::IAM::Role", "AWS::IAM::Group", "AWS::IAM::Policy"})


def _records_all_types(recorder: dict) -> bool:
    group = recorder.get("recordingGroup") or {}
    return group.get("allSupported") is True or (group.get("recordingStrategy") or {}).get("useOnly") == "ALL_SUPPORTED_RESOURCE_TYPES"


def _records_iam_daily(recorder: dict) -> bool:
    """Vanta: IAM global types overridden to DAILY (or everything recorded daily)."""
    mode = recorder.get("recordingMode") or {}
    if mode.get("recordingFrequency") == "DAILY":
        return True
    daily = {t for o in mode.get("recordingModeOverrides") or [] if o.get("recordingFrequency") == "DAILY"
             for t in o.get("resourceTypes") or []}
    return IAM_GLOBAL_TYPES <= daily


def _config_problems(recorders: list[dict], statuses: list[dict], channels: list[dict]) -> list[str]:
    if not recorders:
        return ["sin grabador de AWS Config"]
    recorder = recorders[0]
    status = next((s for s in statuses if s.get("name") == recorder.get("name")), {})
    problems = [] if status.get("recording") is True else ["el grabador está detenido (recording=false)"]
    if status.get("lastStatus") == "FAILURE":
        problems.append("el último estado del grabador es FAILURE")
    if not _records_all_types(recorder):
        problems.append("no graba todos los tipos de recurso")
    if not _records_iam_daily(recorder):
        problems.append("los tipos IAM globales no se graban a diario (override DAILY)")
    if not any(c.get("s3BucketName") for c in channels):
        problems.append("sin delivery channel con bucket de S3")
    return problems


@register("config_recorder")
def config_recorder(responses: dict, params: dict) -> list[dict]:
    """Vanta 'AWS Config is enabled correctly in all regions': recording, all types, IAM daily, delivery channel."""
    statuses = {r: (d or {}).get("ConfigurationRecordersStatus") or [] for r, d in responses.get("status", [])}
    channels = {r: (d or {}).get("DeliveryChannels") or [] for r, d in responses.get("channels", [])}
    offenders = []
    for region, data in responses.get("recorders", []):
        problems = _config_problems((data or {}).get("ConfigurationRecorders") or [], statuses.get(region, []), channels.get(region, []))
        if problems:
            offenders.append(_offender("account", region, reason="AWS Config incompleto", problems=problems))
    return offenders


@register("inspector_status")
def inspector_status(responses: dict, params: dict) -> list[dict]:
    """Inspector scanning ENABLED (not ENABLING) for each of params["required"] (ec2, ecr, lambda) in every region."""
    offenders = []
    for region, data in responses.get("status", []):
        accounts = (data or {}).get("accounts") or []
        states = (accounts[0].get("resourceState") or {}) if accounts else {}
        missing = [t for t in params["required"] if (states.get(t) or {}).get("status") != "ENABLED"]
        if missing:
            offenders.append(_offender("account", region, reason="Inspector no está activo para todos los tipos de recurso",
                                       not_enabled=missing, statuses={t: (states.get(t) or {}).get("status") for t in missing}))
    return offenders


# ---------------------------------------------------------------- Compute: launch templates

def _template_spec(group: dict) -> dict | None:
    mixed = ((group.get("MixedInstancesPolicy") or {}).get("LaunchTemplate") or {}).get("LaunchTemplateSpecification")
    return group.get("LaunchTemplate") or mixed


def _resolve_version(versions: list[dict], spec_version: str | None) -> dict | None:
    """'$Latest' = highest number, '$Default' (also when omitted) = the default version, a number = that version."""
    wanted = spec_version or "$Default"
    if wanted == "$Latest":
        return max(versions, key=lambda v: v["VersionNumber"], default=None)
    if wanted == "$Default":
        return next((v for v in versions if v.get("DefaultVersion")), None)
    return next((v for v in versions if str(v["VersionNumber"]) == wanted), None)


def _versions_by_template(responses: dict) -> dict[tuple[str, str], dict]:
    found: dict[tuple[str, str], dict] = {}
    for call in ("versions", "mixed_versions"):
        for template_id, region, data in _for_each_pairs(responses, call):
            found.setdefault((region, template_id), data or {})
    return found


def _group_imds_problem(group: dict, region: str, templates: dict[tuple[str, str], dict]) -> dict | None:
    spec = _template_spec(group)
    if spec is None:
        return {"reason": "el grupo usa una launch configuration (obsoleta): migrar a launch template con IMDSv2 required",
                "launch_configuration": group.get("LaunchConfigurationName")}
    data = templates.get((region, spec["LaunchTemplateId"]), {})
    if "__error__" in data or "LaunchTemplateVersions" not in data:
        return {"reason": "launch template inexistente o inaccesible", "launch_template": spec["LaunchTemplateId"]}
    version = _resolve_version(data["LaunchTemplateVersions"], spec.get("Version"))
    base = {"launch_template": spec["LaunchTemplateId"], "version_spec": spec.get("Version") or "$Default"}
    if version is None:
        return {**base, "reason": "no se encontró la versión del launch template que usa el grupo"}
    tokens = ((version.get("LaunchTemplateData") or {}).get("MetadataOptions") or {}).get("HttpTokens")
    if tokens == "required":
        return None
    return {**base, "reason": "la versión del launch template no exige IMDSv2", "version": version["VersionNumber"], "http_tokens": tokens}


@register("lt_imdsv2")
def lt_imdsv2(responses: dict, params: dict) -> list[dict]:
    """Drata 292 / Vanta ASG variant: the launch template version each ASG uses has HttpTokens=required."""
    templates = _versions_by_template(responses)
    found = [(region, group, _group_imds_problem(group, region, templates))
             for region, data in responses.get("asgs", []) for group in (data or {}).get("AutoScalingGroups", [])]
    return [_offender(group["AutoScalingGroupName"], region, **problem) for region, group, problem in found if problem]


# ---------------------------------------------------------------- Compute: availability and patching

def _instances(responses: dict) -> list[dict]:
    """EC2 instances of the inventory. The region-level tests below (Drata 130 / 131) report every instance of a
    failing region, so that the instances of the other regions still get their own PASS row."""
    return [i for i in responses.get("__inventory__", []) if i["type"] == "ec2_instance"]


def _balancer_zones(responses: dict) -> dict[str, list[dict]]:
    """{region: [{"name", "zones"}]} of application/network and classic load balancers."""
    found: dict[str, list[dict]] = {}
    for region, data in responses.get("alb", []):
        found.setdefault(region, []).extend({"name": lb["LoadBalancerName"], "zones": len(lb.get("AvailabilityZones") or [])}
                                            for lb in (data or {}).get("LoadBalancers", []))
    for region, data in responses.get("clb", []):
        found.setdefault(region, []).extend({"name": lb["LoadBalancerName"], "zones": len(lb.get("AvailabilityZones") or [])}
                                            for lb in (data or {}).get("LoadBalancerDescriptions", []))
    return found


@register("lb_multi_az")
def lb_multi_az(responses: dict, params: dict) -> list[dict]:
    """Drata 130: every region with EC2 has a load balancer spanning 2 or more AZs (no EC2 = nothing to report)."""
    balancers = _balancer_zones(responses)
    reason = "la región no tiene un balanceador en 2 o más zonas de disponibilidad"
    return [_offender(i["id"], i["region"], reason=reason, load_balancers=balancers.get(i["region"], []))
            for i in _instances(responses) if not any(lb["zones"] >= 2 for lb in balancers.get(i["region"], []))]


@register("asg_present")
def asg_present(responses: dict, params: dict) -> list[dict]:
    """Drata 131: every region with EC2 has at least one Auto Scaling group."""
    with_groups = {region for region, data in responses.get("asgs", []) if (data or {}).get("AutoScalingGroups")}
    return [_offender(i["id"], i["region"], reason="la región tiene instancias EC2 y ningún grupo de Auto Scaling")
            for i in _instances(responses) if i["region"] not in with_groups]


@register("ssm_managed")
def ssm_managed(responses: dict, params: dict) -> list[dict]:
    """Instances registered in Systems Manager with a live agent and a Patch Manager patch state."""
    managed = {(region, i["InstanceId"]): i for region, data in responses.get("info", [])
               for i in (data or {}).get("InstanceInformationList", [])}
    patched = {(region, s["InstanceId"]) for _, region, data in _for_each_pairs(responses, "patches")
               for s in (data or {}).get("InstancePatchStates", [])}
    offenders = []
    for instance in _instances(responses):
        key = (instance["region"], instance["id"])
        info = managed.get(key)
        if info is None:
            problems = ["no registrada en Systems Manager"]
        else:
            problems = ([] if info.get("PingStatus") == "Online" else [f"el agente SSM no está en línea ({info.get('PingStatus')})"])
            problems += [] if key in patched else ["sin asociación de parches (Patch Manager)"]
        if problems:
            offenders.append(_offender(instance["id"], instance["region"], problems=problems))
    return offenders
