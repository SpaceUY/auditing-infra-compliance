"""Detection evaluators: GuardDuty, Security Hub, Config, Inspector."""

import json

from evaluators import DEFAULT_REGION, _first, _for_each_pairs, _offender, _unverified, register


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


def _records_global_types(recorder: dict) -> bool:
    """allSupported only covers the IAM global types when includeGlobalResourceTypes is true."""
    return (recorder.get("recordingGroup") or {}).get("includeGlobalResourceTypes") is True


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
    if str(status.get("lastStatus", "")).upper() == "FAILURE":  # the API enum is Success / Failure / Not_Applicable
        problems.append("el último estado del grabador es FAILURE")
    if not _records_all_types(recorder):
        problems.append("no graba todos los tipos de recurso")
    elif not _records_global_types(recorder):
        problems.append("no graba los tipos IAM globales (includeGlobalResourceTypes=false)")
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
        failed = (data or {}).get("failedAccounts") or []
        if failed:  # the account state could not be read: not evidence of a disabled Inspector
            offenders.append(_unverified("account", region, reason="Inspector no pudo informar el estado de la cuenta",
                                         error_code=failed[0].get("errorCode"), error_message=failed[0].get("errorMessage")))
            continue
        accounts = (data or {}).get("accounts") or []
        states = (accounts[0].get("resourceState") or {}) if accounts else {}
        missing = [t for t in params["required"] if (states.get(t) or {}).get("status") != "ENABLED"]
        if missing:
            offenders.append(_offender("account", region, reason="Inspector no está activo para todos los tipos de recurso",
                                       not_enabled=missing, statuses={t: (states.get(t) or {}).get("status") for t in missing}))
    return offenders
