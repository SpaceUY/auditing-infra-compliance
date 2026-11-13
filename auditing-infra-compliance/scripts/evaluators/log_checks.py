"""Logging evaluators: CloudTrail, trail bucket, CloudWatch Logs, flow logs, lifecycle, ALB and WAF."""

import json
import re
from datetime import datetime, timedelta

from evaluators import (_by_value, _first, _for_each_pairs, _inventory_by_arn, _not_applicable, _now, _offender,
                        _parse_time, _unreadable, register)


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


def _no_trails(responses: dict) -> dict:
    return _offender("account", _first(responses, "trails")[0], reason="no CloudTrail trails")


def _multi_region_trails(responses: dict) -> list[tuple[str, dict]]:
    return [(region, trail) for region, trail in _trail_list(responses) if trail.get("IsMultiRegionTrail")]


def _trail_names_by_bucket(responses: dict) -> dict[str, list[str]]:
    owners: dict[str, list[str]] = {}
    for _, trail in _trail_list(responses):
        owners.setdefault(trail["S3BucketName"], []).append(trail["Name"])
    return owners


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
        return [_offender("account", trails[0][0], reason="no trail is multi-region",
                          trails=[t["Name"] for _, t in trails])]
    return [_offender(t["Name"], r, reason="multi-region trail without logging (IsLogging=false)") for r, t in multi]


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
        return [_offender("account", trails[0][0], reason="no multi-region trail", trails=[t["Name"] for _, t in trails])]
    multi_arns = {trail["TrailARN"] for _, trail in multi}
    covered: set[str] = set()
    for arn, _, data in _for_each_pairs(responses, "selectors"):
        if arn in multi_arns:
            covered |= _classic_s3_coverage((data or {}).get("EventSelectors") or [])
            covered |= _advanced_s3_coverage((data or {}).get("AdvancedEventSelectors") or [])
    missing = [d for d in ("read", "write") if d not in covered]
    if not missing:
        return []
    return [_offender("account", multi[0][0], reason="S3 data events are missing for all buckets", missing=missing,
                      trails=[t["Name"] for _, t in multi])]


# ---------------------------------------------------------------- Logging: CloudTrail bucket

@register("trail_bucket_logging")
def trail_bucket_logging(responses: dict, params: dict) -> list[dict]:
    """Server access logging on the S3 bucket of every trail (Drata 221 / Vanta #19)."""
    owners = _trail_names_by_bucket(responses)
    offenders = []
    for bucket, (region, data) in _by_value(responses, "bucket_logging").items():
        data = data or {}  # empty CLI stdout parses to None: no LoggingEnabled
        if data.get("__error__") not in (None, "NoSuchBucket"):
            offenders.append(_unreadable(bucket, region, data["__error__"], "get-bucket-logging"))
            continue
        if "__error__" in data:
            reason = "the bucket does not exist"
        elif not data.get("LoggingEnabled"):
            reason = "access logging disabled"
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


POLICY_ABSENT = "NoSuchBucketPolicy"


def _unreadable_call(versioning: dict, policy: dict) -> tuple[str, str] | None:
    """(code, call) of the first call whose failure says nothing about the bucket (denied, throttled, ...), if any."""
    if versioning.get("__error__") not in (None, "NoSuchBucket"):
        return versioning["__error__"], "get-bucket-versioning"
    if policy.get("__error__") not in (None, "NoSuchBucket", POLICY_ABSENT):
        return policy["__error__"], "get-bucket-policy"
    return None


def _bucket_problems(versioning: dict, policy: dict) -> list[str]:
    if "NoSuchBucket" in (versioning.get("__error__"), policy.get("__error__")):
        return ["the bucket does not exist"]
    problems = []
    if versioning.get("Status") != "Enabled":
        problems.append("versioning not enabled")
    if "__error__" in policy or "Policy" not in policy:
        problems.append("the bucket has no bucket policy")
    elif not _policy_limits_cloudtrail_by_arn(json.loads(policy["Policy"])):
        problems.append("the CloudTrail bucket policy does not restrict aws:SourceArn")
    return problems


@register("trail_bucket_hardening")
def trail_bucket_hardening(responses: dict, params: dict) -> list[dict]:
    """Trail bucket: versioning Enabled and a bucket policy whose CloudTrail statements use aws:SourceArn."""
    policies = _by_value(responses, "policy")
    offenders = []
    for bucket, (region, versioning) in _by_value(responses, "versioning").items():
        versioning = versioning or {}
        policy = policies.get(bucket, (region, {}))[1] or {}
        if unreadable := _unreadable_call(versioning, policy):
            offenders.append(_unreadable(bucket, region, *unreadable))
            continue
        problems = _bucket_problems(versioning, policy)
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
                          reason="no multi-region trail sends its logs to CloudWatch Logs")]
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
            offenders.append(_offender(vpc["id"], vpc["region"], reason="flow log not active", flow_log_status=found[0]))
        else:
            offenders.append(_offender(vpc["id"], vpc["region"], reason="no flow logs"))
    return offenders


_NARROWING_FILTERS = ("Tag", "Tags", "ObjectSizeGreaterThan", "ObjectSizeLessThan")


def _rule_prefix(rule: dict) -> str | bool | None:
    """None when the rule covers the whole bucket; the prefix when it only covers a sub-tree; False when a tag or object-size
    filter selects objects that are not the logs as a whole."""
    filt = rule.get("Filter") or {}
    conditions = filt.get("And") or {}
    if any(key in filt or key in conditions for key in _NARROWING_FILTERS):
        return False
    return filt.get("Prefix") or conditions.get("Prefix") or rule.get("Prefix") or None


def _short_expiration(rule: dict, now: datetime, minimum: timedelta) -> dict | None:
    """The enabled rule's current-version expiration when it is shorter than `minimum` (exact, not floored days). A rule that
    selects objects by tag or size is ignored (it does not expire the logs); one limited to a prefix is reported with it."""
    if rule.get("Status") != "Enabled":
        return None
    prefix = _rule_prefix(rule)
    if prefix is False:
        return None
    expiration = rule.get("Expiration") or {}
    found = None
    if "Days" in expiration and timedelta(days=expiration["Days"]) < minimum:
        found = {"rule": rule.get("ID", ""), "expires_after_days": expiration["Days"]}
    else:
        date = _parse_time(expiration.get("Date"))
        if date is not None and date - now < minimum:
            found = {"rule": rule.get("ID", ""), "expires_on": expiration["Date"]}
    return found if found is None or prefix is None else {**found, "prefix": prefix}


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
        if bucket not in log_buckets:
            continue
        data = data or {}
        if data.get("__error__") not in (None, "NoSuchLifecycleConfiguration", "NoSuchBucket"):
            offenders.append(_unreadable(bucket, region, data["__error__"], "get-bucket-lifecycle-configuration"))
            continue
        if "__error__" in data:  # no lifecycle rules (or the bucket is gone): nothing expires early
            continue
        short = [found for rule in data.get("Rules", []) if (found := _short_expiration(rule, now, minimum))]
        if short:
            # only prefix rules: they may expire a sub-tree that is not logs (tmp/), so the finding is a hygiene one
            extra = {"severity_override": "low"} if all("prefix" in found for found in short) else {}
            offenders.append(_offender(bucket, region, rules=short, min_days=params["min_days"], **extra))
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
            offenders.append(_offender(name, region, arn=arn, reason="access logs disabled"))
    return offenders


@register("waf_logging")
def waf_logging(responses: dict, params: dict) -> list[dict]:
    """Web ACLs without a logging configuration (WAFNonexistentItemException) or without log destinations."""
    web_acls = _inventory_by_arn(responses, "wafv2_web_acl")
    offenders = []
    for arn, region, data in _for_each_pairs(responses, "logging"):
        destinations = ((data or {}).get("LoggingConfiguration") or {}).get("LogDestinationConfigs") or []
        if "__error__" in (data or {}) or not destinations:
            offenders.append(_offender(web_acls.get(arn, {}).get("id", arn), region, arn=arn, reason="WAF logging disabled"))
    return offenders
