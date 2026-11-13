"""Integration evaluators: the roles Drata (DrataAutopilotRole) and Vanta (vanta-auditor) assume, and the KMS key policies
that must let them read keys (Drata 123, 132, 133, 223; Vanta AWS permissions).

The role checks are per iam_role: only the integration role is evaluated, every other role is not applicable. An account
without the role therefore ends up N/A (vacuous), never PASS.
"""

import json
import re
from collections.abc import Callable
from urllib.parse import unquote

from evaluators import _first, _for_each_pairs, _not_applicable, _offender, _unverified, register
from evaluators.policy_glob import glob_match

SECURITY_AUDIT = re.compile(r"^arn:aws[a-z-]*:iam::aws:policy/SecurityAudit$")
PENDING_DELETION_STATES = frozenset({"pendingdeletion", "pendingreplicadeletion"})


# ---------------------------------------------------------------- policy documents

def _document(raw: object) -> dict:
    """A policy document as an object. IAM returns URL-encoded JSON (starts with %7B) in some calls and raw JSON in others
    (KMS get-key-policy); only the encoded form is decoded, a raw one may legitimately contain a '%'."""
    if not isinstance(raw, str):
        return raw or {}
    return json.loads(raw if raw.lstrip().startswith(("{", "[")) else unquote(raw))


def _statements(document: dict) -> list[dict]:
    statements = document.get("Statement") or []
    return [statements] if isinstance(statements, dict) else [s for s in statements if isinstance(s, dict)]


def _as_list(value: object) -> list:
    return value if isinstance(value, list) else [] if value is None else [value]


def _action_matches(statement: dict, action: str) -> bool:
    return any(glob_match(p, action, ignore_case=True) for p in _as_list(statement.get("Action")) if isinstance(p, str))


def _grants(statements: list[dict], action: str, applies: Callable[[dict], bool]) -> bool:
    """An Allow for `action` that nothing denies. Allow statements this check does not model (Condition, NotAction,
    NotPrincipal) are never counted; a Deny it cannot rule out (NotAction, any Condition) counts as denying; a Deny with NotPrincipal denies every principal not listed."""
    allowed = any(s.get("Effect") == "Allow" and not s.get("Condition") and not s.get("NotAction") and not s.get("NotPrincipal")
                  and _action_matches(s, action) and applies(s) for s in statements)
    denied = any(s.get("Effect") == "Deny" and (_action_matches(s, action) or s.get("NotAction")) and applies(s) for s in statements)
    return allowed and not denied


# ---------------------------------------------------------------- roles

def _role_results(responses: dict, params: dict, judge: Callable[[dict], list[dict]]) -> list[dict]:
    """Every iam_role of the inventory is not applicable except params.role_name, which `judge(item)` decides:
    [] = fine, [offender] = fails, [not applicable entry] = the role vanished or has nothing to evaluate."""
    found = []
    for item in (i for i in responses.get("__inventory__", []) if i["type"] == "iam_role"):
        found += judge(item) if item["id"] == params["role_name"] else [_not_applicable(item["id"], item["region"])]
    return found


def _attached(responses: dict) -> list[dict] | None:
    """Managed policies attached to the role; None when the role does not exist (NoSuchEntity)."""
    _, data = _first(responses, "attached")
    return None if "__error__" in (data or {}) else (data or {}).get("AttachedPolicies") or []


def _is_security_audit(policy: dict) -> bool:
    return bool(SECURITY_AUDIT.match(policy.get("PolicyArn") or ""))


@register("drata_role")
def drata_role(responses: dict, params: dict) -> list[dict]:
    """Drata 123 (connection health): DrataAutopilotRole needs the AWS-managed SecurityAudit policy."""
    attached = _attached(responses)

    def judge(item: dict) -> list[dict]:
        if attached is None:
            return [_not_applicable(item["id"], item["region"])]
        if any(_is_security_audit(p) for p in attached):
            return []
        return [_offender(item["id"], item["region"], missing_policy="SecurityAudit", reason="the SecurityAudit managed policy is missing",
                          attached_policies=[p.get("PolicyName") for p in attached])]
    return _role_results(responses, params, judge)


def _role_statements(role: dict, local_policies: dict[str, dict]) -> tuple[list[dict], list[str]]:
    """(statements of the inline and customer-managed policies of the role, names of the AWS-managed policies not read)."""
    statements, not_read = [], []
    for inline in role.get("RolePolicyList") or []:
        statements += _statements(_document(inline.get("PolicyDocument")))
    for attached in role.get("AttachedManagedPolicies") or []:
        policy = local_policies.get(attached.get("PolicyArn"))
        default = next((v for v in (policy or {}).get("PolicyVersionList") or [] if v.get("IsDefaultVersion")), None)
        if default:
            statements += _statements(_document(default.get("Document")))
        elif attached.get("PolicyName") and not _is_security_audit(attached):
            not_read.append(attached["PolicyName"])
    return statements, not_read


def _allows_on_all_resources(statement: dict) -> bool:
    return "*" in _as_list(statement.get("Resource"))


@register("drata_backup_perms")
def drata_backup_perms(responses: dict, params: dict) -> list[dict]:
    """Drata 132/133: the role needs params.actions on Resource '*' in an inline or customer-managed policy (the AWS-managed
    policies are not read: they are named in the detail)."""
    _, data = _first(responses, "details")
    roles = {r.get("RoleName"): r for r in (data or {}).get("RoleDetailList") or []}
    local = {p.get("Arn"): p for p in (data or {}).get("Policies") or []}

    def judge(item: dict) -> list[dict]:
        if item["id"] not in roles:
            return [_not_applicable(item["id"], item["region"])]
        statements, not_read = _role_statements(roles[item["id"]], local)
        # a Deny of the action is judged on every resource; an Allow only counts on Resource "*"
        usable = [s for s in statements if s.get("Effect") != "Allow" or _allows_on_all_resources(s)]
        missing = [a for a in params["actions"] if not _grants(usable, a, lambda s: True)]
        if not missing:
            return []
        return [_offender(item["id"], item["region"], missing_actions=missing, aws_managed_not_evaluated=not_read,
                          reason="AWS Backup permissions are missing in an inline or customer-managed policy")]
    return _role_results(responses, params, judge)


_CUSTOMER_MANAGED = "^arn:aws[a-z-]*:iam::\\d{{12}}:policy/(?:.+/)?{name}$"


@register("vanta_role")
def vanta_role(responses: dict, params: dict) -> list[dict]:
    """Vanta: vanta-auditor needs SecurityAudit plus the customer-managed VantaAdditionalPermissions; an inline policy
    with that name is not detected by Vanta."""
    attached = _attached(responses)
    _, inline_data = _first(responses, "inline")
    inline = [] if "__error__" in (inline_data or {}) else (inline_data or {}).get("PolicyNames") or []
    name = params["additional_policy"]
    customer_managed = re.compile(_CUSTOMER_MANAGED.format(name=re.escape(name)))

    def judge(item: dict) -> list[dict]:
        if attached is None:
            return [_not_applicable(item["id"], item["region"])]
        missing = [] if any(_is_security_audit(p) for p in attached) else ["SecurityAudit"]
        if any(customer_managed.match(p.get("PolicyArn") or "") for p in attached):
            extra = "customer-managed"
        else:
            extra = "inline" if name in inline else "absent"
            missing.append(name)
        if not missing:
            return []
        return [_offender(item["id"], item["region"], missing_policies=missing, additional_permissions=extra,
                          reason="the role is missing policies that Vanta detects")]
    return _role_results(responses, params, judge)


# ---------------------------------------------------------------- KMS key policies

def _key_error(key_id: str, region: str, code: str, call: str) -> dict:
    """Entry for a failed per-key call (item_errors): a vanished key is out of scope, the rest could not be verified."""
    if code == "NotFoundException":
        return _not_applicable(key_id, region)
    reason = "the key policy does not allow the auditor to query the key" if code == "ACCESS_DENIED" else "could not query the key"
    return _unverified(key_id, region, error_code=code, call=call, reason=reason)


def _names_role(principal: object, role_arn: str) -> bool:
    """A Principal / NotPrincipal value that is '*', the role, its account root or the bare account id."""
    account = role_arn.split(":")[4]
    names = _as_list(principal.get("AWS") if isinstance(principal, dict) else principal)
    return any(n in ("*", role_arn, account) or n == f"arn:{role_arn.split(':')[1]}:iam::{account}:root" for n in names)


def _principal_covers(statement: dict, role_arn: str) -> bool:
    """The statement applies to the role: its Principal is the role, its account root or '*'; a Deny with NotPrincipal applies
    to every principal that is NOT listed, so it applies unless the role (or its account root) is listed."""
    if "NotPrincipal" in statement:
        return not _names_role(statement["NotPrincipal"], role_arn)
    return _names_role(statement.get("Principal"), role_arn)


def _missing_actions(statements: list[dict], role_arn: str, actions: list[str]) -> list[str]:
    return [a for a in actions if not _grants(statements, a, lambda s: _principal_covers(s, role_arn))]


@register("kms_auditor_access")
def kms_auditor_access(responses: dict, params: dict) -> list[dict]:
    """Drata 223 / Vanta: the key policy of each customer-managed key must let the existing auditor roles read the key, either
    with statements naming them or with the account-root delegation. params.auditors = {role name: [kms actions]}."""
    roles = {i["id"]: i["arn"] for i in responses.get("__inventory__", [])
             if i["type"] == "iam_role" and i["id"] in params["auditors"] and i["arn"]}
    policies = {(region, key): data for key, region, data in _for_each_pairs(responses, "policy")}
    found = []
    for key_id, region, described in _for_each_pairs(responses, "describe"):
        if "__error__" in (described or {}):
            found.append(_key_error(key_id, region, described["__error__"], "describe-key"))
            continue
        meta = (described or {}).get("KeyMetadata") or {}
        if not roles or str(meta.get("KeyManager", "")).upper() != "CUSTOMER" or str(meta.get("KeyState", "")).lower() in PENDING_DELETION_STATES:
            found.append(_not_applicable(key_id, region))
            continue
        answer = policies.get((region, key_id)) or {}
        if "__error__" in answer or "Policy" not in answer:
            found.append(_key_error(key_id, region, answer.get("__error__", "NO_RESPONSE"), "get-key-policy"))
            continue
        statements = _statements(_document(answer["Policy"]))
        missing = {name: gone for name, arn in roles.items() if (gone := _missing_actions(statements, arn, params["auditors"][name]))}
        if missing:
            found.append(_offender(key_id, region, arn=meta.get("Arn"), missing_actions=missing,
                                   reason="the key policy does not allow the auditor roles the read actions"))
    return found
