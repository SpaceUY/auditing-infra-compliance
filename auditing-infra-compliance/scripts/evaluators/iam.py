"""IAM evaluators: root account, credential report, policies, password policy, contacts."""

import base64
import csv
import io
import json
from datetime import datetime, timedelta
from urllib.parse import unquote

from evaluators import _age, _first, _now, _offender, _parse_time, register


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
