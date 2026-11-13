"""Email (SES v2) evaluators. Neither Drata nor Vanta publishes SES tests: these are the skill's own checks, per ses_identity.

The configuration-set checks follow the default configuration set of each identity (get-email-identity ->
ConfigurationSetName); a configuration set chosen at send time is not evaluated.
"""

from collections.abc import Callable

from evaluators import _for_each_pairs, _not_applicable, _offender, _unverified, register


def _read_error(identity: str, region: str, code: str, call: str, **detail) -> dict:
    """Entry for a failed per-item call (item_errors): a vanished identity is out of scope, the rest could not be verified."""
    if code == "NotFoundException":
        return _not_applicable(identity, region)
    reason = "the auditor does not have permission to read it" if code == "ACCESS_DENIED" else "could not be read"
    return _unverified(identity, region, error_code=code, call=call, reason=reason, **detail)


def _default_config_set(responses: dict, call: str, operation: str, judge: Callable[[dict], dict | None]) -> list[dict]:
    """Per identity: its default configuration set (call "identity"), then `judge(answer of call)` -> problem detail or None."""
    sets = {(region, name): data or {} for name, region, data in _for_each_pairs(responses, call)}
    found = []
    for identity, region, data in _for_each_pairs(responses, "identity"):
        error = (data or {}).get("__error__")
        if error:
            found.append(_read_error(identity, region, error, "get-email-identity"))
            continue
        name = (data or {}).get("ConfigurationSetName")
        if not name:
            found.append(_offender(identity, region, reason="no default configuration set"))
            continue
        answer = sets.get((region, name))
        if answer is None:
            found.append(_unverified(identity, region, call=operation, config_set=name, reason="no response"))
        elif answer.get("__error__") == "NotFoundException":
            found.append(_offender(identity, region, config_set=name, reason="the default configuration set does not exist"))
        elif "__error__" in answer:
            found.append(_read_error(identity, region, answer["__error__"], operation, config_set=name))
        elif problem := judge(answer):
            found.append(_offender(identity, region, config_set=name, **problem))
    return found


def _tls_problem(answer: dict) -> dict | None:
    policy = (answer.get("DeliveryOptions") or {}).get("TlsPolicy") or "OPTIONAL"
    if policy.upper() == "REQUIRE":
        return None
    return {"tls_policy": policy, "reason": "the default configuration set does not require TLS (TlsPolicy other than REQUIRE)"}


def _events_problem(answer: dict) -> dict | None:
    destinations = answer.get("EventDestinations") or []
    if any(d.get("Enabled") for d in destinations):
        return None
    return {"event_destinations": len(destinations), "reason": "the default configuration set has no enabled event destination"}


@register("ses_default_config_tls")
def ses_default_config_tls(responses: dict, params: dict) -> list[dict]:
    return _default_config_set(responses, "cset", "get-configuration-set", _tls_problem)


@register("ses_default_config_events")
def ses_default_config_events(responses: dict, params: dict) -> list[dict]:
    return _default_config_set(responses, "events", "get-configuration-set-event-destinations", _events_problem)


@register("ses_account_sending")
def ses_account_sending(responses: dict, params: dict) -> list[dict]:
    """Production access and an account-level suppression list (at least one reason: bounces, complaints) of the SES account of each region that has
    identities; reported once per identity of that region."""
    accounts = {region: data or {} for region, data in responses.get("account", [])}
    found = []
    for item in (i for i in responses.get("__inventory__", []) if i["type"] == "ses_identity"):
        account = accounts.get(item["region"])
        if account is None:
            continue
        reasons = []
        if not account.get("ProductionAccessEnabled"):
            reasons.append("the SES account is in the sandbox (no production access)")
        if not (account.get("SuppressionAttributes") or {}).get("SuppressedReasons"):
            reasons.append("the account suppression list does not suppress bounces or complaints")
        if reasons:
            found.append(_offender(item["id"], item["region"], reasons=reasons))
    return found
