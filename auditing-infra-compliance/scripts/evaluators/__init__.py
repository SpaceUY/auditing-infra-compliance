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
An entry {"resource_id", "region", "detail", "unverified": True} (helper `_unverified`) is a result the evaluator could
not decide for that region: the engine emits a NOT_VERIFIED row for it (missing = the check's permissions when
detail["error_code"] is ACCESS_DENIED), never a FAIL or a PASS.
responses["__inventory_errors__"] is the set of inventory types whose listing failed (the engine already returns
NOT_VERIFIED for checks that declare those types in params.inventory_types).
A call declared with "ok_errors" whose error was one of those codes shows up as {"__error__": "<code>"}.
Evaluators that depend on the clock read an optional params["now"] (ISO 8601) so tests can pin it.

This package holds the registry and the helpers several domains share; each domain lives in its own module
(iam, log_checks, detection, compute, encryption, network, data, monitoring, inventory_checks, integration, email), imported at the bottom so that its `@register` calls run.
Helpers private to one domain keep a `_prefix` inside that module.
"""

from datetime import datetime, timedelta, timezone
from typing import Callable

Evaluator = Callable[[dict, dict], list[dict]]
EVALUATORS: dict[str, Evaluator] = {}


def register(name: str) -> Callable[[Evaluator], Evaluator]:
    def decorator(fn: Evaluator) -> Evaluator:
        if name in EVALUATORS:
            raise ValueError(f"duplicate evaluator: {name}")
        EVALUATORS[name] = fn
        return fn

    return decorator


# Keys an evaluator reads with params["key"] (a missing one would crash it at run time): validate_catalog.py requires them in the
# check's verify.params. Keep in sync when an evaluator starts reading a new mandatory parameter.
REQUIRED_PARAMS: dict[str, tuple[str, ...]] = {
    "inspector_status": ("required",),
    "acm_expiry": ("min_days",),
    "root_usage": ("days", "max"),
    "cred_report_key_age": ("fail_at_days",),
    "cred_report_unused": ("max_days",),
    "password_min_length": ("min_length",),
    "password_reuse_prevention": ("min_reuse",),
    "drata_role": ("role_name",),
    "drata_backup_perms": ("role_name", "actions"),
    "vanta_role": ("role_name", "additional_policy"),
    "kms_auditor_access": ("auditors",),
    "tag_present": ("inventory_types", "key"),
    "user_data_flag": ("inventory_types", "key"),
    "nonprod_on_prod": ("inventory_types",),
    "tags_present": ("inventory_types",),
    "alarm_coverage": ("metric", "namespace", "resource_dimension"),
    "trail_cw_metric_filters": ("categories",),
    "log_bucket_lifecycle": ("min_days", "name_regex"),
    "sg_open_port": ("port",),
}


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


def _unverified(resource_id: str, region: str, **detail) -> dict:
    return {"resource_id": resource_id, "region": region, "detail": detail, "unverified": True}


def _unreadable(resource_id: str, region: str, code: str, call: str) -> dict:
    """Entry for a per-item call that failed (item_errors) with a code the evaluator does not interpret: unverified."""
    reason = "insufficient permissions to query the resource" if code == "ACCESS_DENIED" else "could not query the resource"
    return _unverified(resource_id, region, error_code=code, call=call, reason=reason)


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


def _inventory_by_arn(responses: dict, type_: str) -> dict[str, dict]:
    return {i["arn"]: i for i in responses.get("__inventory__", []) if i["type"] == type_ and i["arn"]}


# Domain modules register their evaluators on import; they import the helpers above, so this stays last.
from . import (compute, data, detection, email, encryption, iam, integration, inventory_checks, log_checks,  # noqa: E402,F401
               monitoring, network)
