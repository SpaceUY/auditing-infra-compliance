"""Catalog schema, mapping resolution and validation for auditing-infra-compliance."""

import json
import re
from pathlib import Path

import aws_runner

SEVERITIES = ("critical", "high", "medium", "low")
STATUSES = (
    "FAIL",
    "PASS",
    "DRIFT",
    "DOCUMENTED_ONLY",
    "DOCUMENTED_GAP",
    "UNDOCUMENTED",
    "NO_VERIFICADO",
    "N/A",
)
REMEDIATION_KINDS = ("cli", "cli_with_decision", "planned_change", "console_only")
RISKS = ("low", "medium", "high")
EVALUATOR_KINDS = ("jmespath", "python", "claude", "dns")
DCF_SOURCE = "drata-dcf-2026-11-12"

_ID_RE = re.compile(r"^[A-Z]{3}-\d{3}$")
_REQUIRED_FIELDS = (
    "id", "title", "domain", "scope", "resource_types", "all_regions", "severity",
    "not_enabled_means", "verify", "vault_signals", "mappings", "remediation", "sources",
)
_REQUIRED_VERIFY = ("calls", "evaluator", "pass_when_text", "needs")
_REQUIRED_REMEDIATION = ("kind", "risk", "downtime", "steps", "commands", "verify_after", "notes")
_DNS_REQUIRED_PARAMS = ("rrtype", "name_template", "must_match")
_REQUIRED_MAPPINGS = ("drata", "vanta", "tsc_inferred", "iso_inferred", "security_hub", "cis_aws")
SCOPES = ("account", "resource")
NOT_ENABLED_MEANS = ("fail", "not_verified")
CALL_REGIONS = ("each", "global")
INVENTORY_SOURCE = "__inventory__"
_CALL_KEYS = frozenset({"name", "service", "operation", "args", "region", "for_each", "ok_errors", "item_errors"})
_INVENTORY_SPEC_KEYS = ("service", "operation", "args", "region", "items_path", "id_path", "name_path", "tags_path", "arn_path")
RULE_STATUSES = ("CONFLICTO", "REVISAR")
RULE_SCOPES = ("same_resource", "same_account")

# Every (service, operation) a catalog call or the inventory spec may run. aws_runner.assert_read_only (verb allowlist plus
# denylist and sensitive-name rule) is the floor; this list is the explicit review gate: adding a call means reading what the
# operation returns (no secret values, no object data) and adding the pair here. Nothing else is accepted by validate_catalog.
_REVIEWED = {
    "accessanalyzer": ("list-analyzers",),
    "account": ("get-alternate-contact",),
    "acm": ("describe-certificate", "list-certificates"),
    "apigateway": ("get-rest-apis", "get-stages"),
    "apigatewayv2": ("get-apis",),
    "autoscaling": ("describe-auto-scaling-groups",),
    "backup": ("get-backup-plan", "get-backup-vault-notifications", "list-backup-jobs", "list-backup-plans", "list-backup-vaults"),
    "cloudfront": ("list-distributions",),
    "cloudtrail": ("describe-trails", "get-event-selectors", "get-trail-status", "lookup-events"),
    "cloudwatch": ("describe-alarms",),
    "configservice": ("describe-configuration-recorder-status", "describe-configuration-recorders", "describe-delivery-channels"),
    "dynamodb": ("describe-continuous-backups", "list-tables"),
    "ec2": ("describe-flow-logs", "describe-instances", "describe-launch-template-versions", "describe-launch-templates",
            "describe-network-acls", "describe-network-interfaces", "describe-regions", "describe-route-tables",
            "describe-security-groups", "describe-subnets", "describe-volumes", "describe-vpcs", "get-ebs-encryption-by-default"),
    "efs": ("describe-file-systems",),
    "eks": ("describe-cluster", "list-clusters"),
    "elasticache": ("describe-replication-groups",),
    "elb": ("describe-load-balancers",),
    "elbv2": ("describe-listeners", "describe-load-balancer-attributes", "describe-load-balancers"),
    "events": ("list-rules", "list-targets-by-rule"),
    "guardduty": ("get-detector", "list-detectors"),
    "iam": ("generate-credential-report", "get-account-authorization-details", "get-account-password-policy",
            "get-account-summary", "get-credential-report", "list-attached-role-policies", "list-attached-user-policies",
            "list-entities-for-policy", "list-role-policies", "list-roles", "list-users", "list-virtual-mfa-devices"),
    "inspector2": ("batch-get-account-status", "list-findings"),
    "kms": ("describe-key", "get-key-policy", "get-key-rotation-status", "list-aliases", "list-keys"),
    "lambda": ("list-functions",),
    "logs": ("describe-log-groups", "describe-metric-filters"),
    "rds": ("describe-db-cluster-parameter-groups", "describe-db-cluster-parameters", "describe-db-clusters",
            "describe-db-instances", "describe-db-parameter-groups", "describe-db-parameters"),
    "resourcegroupstaggingapi": ("get-resources",),
    "s3api": ("get-bucket-encryption", "get-bucket-lifecycle-configuration", "get-bucket-logging", "get-bucket-policy",
              "get-bucket-versioning", "get-public-access-block", "list-buckets"),
    "secretsmanager": ("list-secrets",),
    "securityhub": ("describe-hub", "get-enabled-standards"),
    "sesv2": ("get-account", "get-configuration-set", "get-configuration-set-event-destinations", "get-email-identity",
              "list-email-identities"),
    "sns": ("list-subscriptions-by-topic", "list-topics"),
    "sqs": ("list-queues",),
    "ssm": ("describe-instance-information", "describe-instance-patch-states"),
    "sts": ("get-caller-identity",),
    "wafv2": ("get-logging-configuration", "list-resources-for-web-acl", "list-web-acls"),
}
REVIEWED_OPERATIONS = frozenset((service, op) for service, ops in _REVIEWED.items() for op in ops)


def _read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_checks(checks_dir: Path) -> list[dict]:
    checks = []
    for path in sorted(Path(checks_dir).glob("*.json")):
        data = _read_json(path)
        for check in data["checks"]:
            check.setdefault("domain", data["domain"])
            checks.append(check)
    return checks


def load_frameworks(frameworks_dir: Path) -> tuple[set[str], set[str]]:
    frameworks_dir = Path(frameworks_dir)
    tsc = _read_json(frameworks_dir / "tsc-2017.json")
    iso = _read_json(frameworks_dir / "iso27001-2022.json")
    tsc_ids = {c["id"] for c in tsc["criteria"]}
    iso_ids = {c["id"] for c in iso["controls"]}
    for clause in iso["clauses"]:
        iso_ids.add(clause["id"])
        parts = clause["id"].split(".")
        if len(parts) > 2:
            iso_ids.add(".".join(parts[:2]))
    return tsc_ids, iso_ids


def load_drata_map(path: Path) -> dict[int, dict]:
    return {t["test_id"]: t for t in _read_json(path)["tests"]}


def _ordered_union(lists):
    seen = []
    for items in lists:
        for item in items or []:
            if item not in seen:
                seen.append(item)
    return seen


def _resolvable_drata_tests(check, drata):
    return [
        drata[m["test"]]
        for m in check.get("mappings", {}).get("drata", [])
        if isinstance(m.get("test"), int) and m["test"] in drata
    ]


def resolve_mappings(check: dict, drata: dict[int, dict]) -> dict:
    mappings = check.get("mappings", {})
    tests = _resolvable_drata_tests(check, drata)
    if tests:
        controls = [c for t in tests for c in (t.get("controls") or [])]
        tsc = [{"id": i, "sourced": DCF_SOURCE} for i in _ordered_union(c.get("soc2") for c in controls)]
        iso = [
            {"id": i, "sourced": DCF_SOURCE}
            for i in _ordered_union(c.get("iso27001_2022") for c in controls)
        ]
    else:
        tsc = [{"id": i, "sourced": False} for i in mappings.get("tsc_inferred") or []]
        iso = [{"id": i, "sourced": False} for i in mappings.get("iso_inferred") or []]
    return {
        "drata": list(mappings.get("drata") or []),
        "vanta": list(mappings.get("vanta") or []),
        "tsc": tsc,
        "iso27001_2022": iso,
        "security_hub": list(mappings.get("security_hub") or []),
        "cis_aws": list(mappings.get("cis_aws") or []),
    }


def _is_read_only(service: str, operation: str, args=()) -> bool:
    try:
        aws_runner.assert_read_only(service, operation, list(args))
    except aws_runner.ReadOnlyViolation:
        return False
    return True


def _missing_fields(check):
    cid = check.get("id", "<sin id>")
    errors = [f"{cid}: falta el campo '{f}'" for f in _REQUIRED_FIELDS if f not in check]
    for key, required in (
        ("verify", _REQUIRED_VERIFY),
        ("remediation", _REQUIRED_REMEDIATION),
        ("mappings", _REQUIRED_MAPPINGS),
    ):
        section = check.get(key)
        if isinstance(section, dict):
            errors += [f"{cid}: falta el campo '{key}.{f}'" for f in required if f not in section]
    return errors


def _check_identity(check, seen_ids):
    cid = check.get("id", "<sin id>")
    errors = []
    if not isinstance(cid, str) or not _ID_RE.match(cid):
        errors.append(f"{cid}: id con formato invalido (esperado AAA-000)")
    if cid in seen_ids:
        errors.append(f"{cid}: id duplicado")
    seen_ids.add(cid)
    return errors


def _check_enums(check):
    cid = check["id"]
    errors = []
    if check["severity"] not in SEVERITIES:
        errors.append(f"{cid}: severity invalida '{check['severity']}'")
    rem = check["remediation"]
    if rem["kind"] not in REMEDIATION_KINDS:
        errors.append(f"{cid}: remediation.kind invalido '{rem['kind']}'")
    if rem["risk"] not in RISKS:
        errors.append(f"{cid}: remediation.risk invalido '{rem['risk']}'")
    evaluator = check["verify"]["evaluator"]
    kind, _, name = evaluator.partition(":")
    if kind not in EVALUATOR_KINDS:
        errors.append(f"{cid}: evaluador invalido '{evaluator}'")
    elif kind == "python" and not name:
        errors.append(f"{cid}: evaluador python sin nombre '{evaluator}'")
    elif kind != "python" and name:
        errors.append(f"{cid}: evaluador '{evaluator}' no admite nombre")
    return errors


def _call_operation_errors(label, call):
    """Read-only by the runner's rules AND reviewed (an explicit allowlist): both must hold for a call to be accepted."""
    service, operation = call.get("service", ""), call.get("operation", "")
    args = call.get("args") or []
    if not _is_read_only(service, operation, args if isinstance(args, list) else []):
        return [f"{label} no es de solo lectura ({service} {operation})"]
    if (service, operation) not in REVIEWED_OPERATIONS:
        return [f"{label} usa una operación no revisada ({service} {operation}): leer qué devuelve y agregarla a REVIEWED_OPERATIONS"]
    return []


def _check_calls_read_only(check):
    cid = check["id"]
    return [e for c in check["verify"]["calls"] for e in _call_operation_errors(f"{cid}: llamada '{c.get('name')}'", c)]


def validate_inventory(specs) -> list[str]:
    """references/inventory.json: every entry is complete, read-only, reviewed and has a valid region mode."""
    if not isinstance(specs, dict):
        return ["inventory: se esperaba un objeto {tipo: especificación}"]
    errors = []
    for type_, spec in specs.items():
        label = f"inventory {type_}"
        if not isinstance(spec, dict):
            errors.append(f"{label}: la especificación debe ser un objeto")
            continue
        errors += [f"{label}: falta el campo '{k}'" for k in _INVENTORY_SPEC_KEYS if k not in spec]
        if spec.get("region") not in CALL_REGIONS:
            errors.append(f"{label}: region invalida '{spec.get('region')}'")
        if "service" in spec and "operation" in spec:
            errors += _call_operation_errors(label, spec)
    return errors


def _inventory_type_errors(cid, field, types, known):
    if not isinstance(types, list) or not all(isinstance(t, str) for t in types):
        return [f"{cid}: {field} debe ser una lista de textos"]
    return [f"{cid}: {field} cita un tipo de inventario inexistente '{t}'" for t in types if known is not None and t not in known]


def _check_contract(check, inventory_types, registered, required_params):
    """What collect.py needs from a check: enums, region modes, call shape, for_each sources, inventory types, evaluator and params."""
    cid = check["id"]
    errors = []
    if check["scope"] not in SCOPES:
        errors.append(f"{cid}: scope invalido '{check['scope']}' (account | resource)")
    if check["not_enabled_means"] not in NOT_ENABLED_MEANS:
        errors.append(f"{cid}: not_enabled_means invalido '{check['not_enabled_means']}' (fail | not_verified)")
    if not isinstance(check["all_regions"], bool):
        errors.append(f"{cid}: all_regions debe ser booleano")
    errors += _inventory_type_errors(cid, "resource_types", check["resource_types"], inventory_types)
    if "account_context_for" in check:
        errors += _inventory_type_errors(cid, "account_context_for", check["account_context_for"], inventory_types)
    verify = check["verify"]
    params = verify.get("params")
    if params is not None and not isinstance(params, dict):
        errors.append(f"{cid}: verify.params debe ser un objeto")
        params = None
    if params and "inventory_types" in params:
        errors += _inventory_type_errors(cid, "params.inventory_types", params["inventory_types"], inventory_types)
    if not (isinstance(verify["needs"], list) and all(isinstance(n, str) and n for n in verify["needs"])):
        errors.append(f"{cid}: verify.needs debe ser una lista de textos no vacios")
    errors += _check_call_shapes(check)
    errors += _check_evaluator_contract(check, params or {}, registered, required_params)
    return errors


def _check_call_shapes(check):
    cid, calls = check["id"], check["verify"]["calls"]
    dns = check["verify"]["evaluator"] == "dns"  # the engine runs the dns evaluator itself: it makes no AWS call
    if not isinstance(calls, list) or (not calls and not dns) or not all(isinstance(c, dict) for c in calls):
        return [f"{cid}: verify.calls debe ser una lista no vacia de objetos"]
    errors, earlier = [], set()
    for call in calls:
        label = f"{cid}: llamada '{call.get('name')}'"
        errors += [f"{label} tiene un campo desconocido '{k}'" for k in sorted(set(call) - _CALL_KEYS)]
        errors += [f"{label}: falta '{k}'" for k in ("name", "service", "operation") if not (isinstance(call.get(k), str) and call[k])]
        if call.get("name") in earlier:
            errors.append(f"{label}: nombre duplicado")
        if "args" in call and not (isinstance(call["args"], list) and all(isinstance(a, str) for a in call["args"])):
            errors.append(f"{label}: args debe ser una lista de textos")
        if call.get("region", "global") not in CALL_REGIONS:
            errors.append(f"{label}: region invalida '{call.get('region')}' (each | global)")
        if "for_each" in call:
            errors += _for_each_errors(label, call["for_each"], earlier, check)
        earlier.add(call.get("name"))
    return errors


def _for_each_errors(label, for_each, earlier, check):
    if not isinstance(for_each, dict) or not all(isinstance(for_each.get(k), str) and for_each[k] for k in ("from", "path", "arg")):
        return [f"{label}: for_each requiere {{from, path, arg}} como textos no vacios"]
    if for_each["from"] == INVENTORY_SOURCE:
        return [] if check["resource_types"] else [f"{label}: for_each de {INVENTORY_SOURCE} requiere resource_types no vacio"]
    if for_each["from"] not in earlier:
        return [f"{label}: for_each.from '{for_each['from']}' no es una llamada anterior ni {INVENTORY_SOURCE}"]
    return []


def _check_evaluator_contract(check, params, registered, required_params):
    cid = check["id"]
    kind, _, name = check["verify"]["evaluator"].partition(":")
    if kind != "python" or not name:
        return []
    errors = []
    if registered is not None and name not in registered:
        errors.append(f"{cid}: evaluador python '{name}' no esta registrado")
    errors += [f"{cid}: el evaluador '{name}' requiere params.{key}" for key in (required_params or {}).get(name, ()) if key not in params]
    return errors


def _check_framework_ids(check, tsc_ids, iso_ids):
    cid = check["id"]
    m = check["mappings"]
    errors = [f"{cid}: tsc_inferred desconocido '{i}'" for i in m["tsc_inferred"] if i not in tsc_ids]
    errors += [f"{cid}: iso_inferred desconocido '{i}'" for i in m["iso_inferred"] if i not in iso_ids]
    errors += [
        f"{cid}: mappings.drata.test debe ser int, no {m_['test']!r}"
        for m_ in m["drata"]
        if not isinstance(m_.get("test"), int) or isinstance(m_.get("test"), bool)
    ]
    return errors


def _check_jmespath(check):
    verify = check["verify"]
    if verify["evaluator"] != "jmespath":
        return []
    cid = check["id"]
    errors = []
    if len(verify["calls"]) != 1:
        errors.append(f"{cid}: jmespath requiere exactamente 1 call")
    if not str(verify.get("offenders", "")).strip():
        errors.append(f"{cid}: jmespath requiere 'offenders' no vacio")
    return errors


def _check_call_options(check):
    cid = check["id"]
    errors = []
    for call in check["verify"]["calls"]:
        ok_errors = call.get("ok_errors")
        if ok_errors is not None and not (
            isinstance(ok_errors, list) and all(isinstance(e, str) and e for e in ok_errors)
        ):
            errors.append(f"{cid}: call '{call.get('name')}' ok_errors debe ser lista de textos no vacios")
    errors += _check_item_errors(check)
    if check["verify"]["evaluator"] == "dns":
        errors += _check_dns_params(cid, check["verify"].get("params") or {})
    return errors


def _check_item_errors(check):
    cid = check["id"]
    python = check["verify"]["evaluator"].startswith("python:")
    errors = []
    for call in check["verify"]["calls"]:
        if "item_errors" not in call:
            continue
        if call["item_errors"] != "evaluator":
            errors.append(f"{cid}: call '{call.get('name')}' item_errors solo admite 'evaluator'")
        elif "for_each" not in call:
            errors.append(f"{cid}: call '{call.get('name')}' item_errors requiere for_each")
        elif not python:
            errors.append(f"{cid}: call '{call.get('name')}' item_errors requiere un evaluador python")
    return errors


def _check_dns_params(cid, params):
    errors = [
        f"{cid}: evaluador dns requiere params.{key}"
        for key in _DNS_REQUIRED_PARAMS
        if not isinstance(params.get(key), str) or not params[key].strip()
    ]
    if isinstance(params.get("rrtype"), str) and not re.fullmatch(r"[A-Za-z0-9]+", params["rrtype"]):
        errors.append(f"{cid}: params.rrtype invalido '{params['rrtype']}'")
    if isinstance(params.get("name_template"), str) and "{domain}" not in params["name_template"]:
        errors.append(f"{cid}: params.name_template debe contener {{domain}}")
    if isinstance(params.get("must_match"), str):
        try:
            re.compile(params["must_match"])
        except re.error:
            errors.append(f"{cid}: params.must_match no es una regex valida")
    return errors


def _check_remediation(check):
    cid = check["id"]
    rem = check["remediation"]
    errors = []
    if rem["kind"] != "console_only" and not str(rem["verify_after"]).strip():
        errors.append(f"{cid}: remediation.verify_after vacio")
    if rem["kind"] == "planned_change":
        if len(rem["steps"]) < 2:
            errors.append(f"{cid}: planned_change requiere al menos 2 steps")
        if not str(rem["notes"]).strip():
            errors.append(f"{cid}: planned_change requiere notes (advertencia)")
    errors += [f"{cid}: comando con '<<' (abre un heredoc en bash)" for c in rem["commands"] if "<<" in c]
    return errors


def _check_coverage(check, drata):
    cid = check["id"]
    errors = []
    if not _resolvable_drata_tests(check, drata):
        m = check["mappings"]
        if not m["tsc_inferred"]:
            errors.append(f"{cid}: sin test de Drata resoluble requiere >= 1 tsc_inferred")
        if not m["iso_inferred"]:
            errors.append(f"{cid}: sin test de Drata resoluble requiere >= 1 iso_inferred")
    if check["scope"] == "resource" and not check["resource_types"]:
        errors.append(f"{cid}: scope resource requiere resource_types no vacio")
    return errors


def _rule_check_refs(when):
    """(key, check id) for every check cited in a rule's `when`."""
    refs = []
    for key in ("all_fail", "any_fail", "fail"):
        value = when.get(key)
        refs += [(key, v) for v in (value if isinstance(value, list) else [value] if value is not None else [])]
    attached = when.get("attached_instance_fail")
    if isinstance(attached, dict) and "check" in attached:
        refs.append(("attached_instance_fail", attached["check"]))
    return refs


def _non_empty_text(value):
    return isinstance(value, str) and bool(value)


def _rule_when_errors(rid, when):
    if not isinstance(when, dict):
        return [f"{rid}: 'when' debe ser un objeto"]
    forms = [k for k in ("all_fail", "any_fail", "fail") if k in when]
    if len(forms) != 1:
        return [f"{rid}: 'when' requiere exactamente una de all_fail, any_fail o fail"]
    errors = []
    conditions = [k for k in ("attachment_description_prefix", "attached_instance_fail") if k in when]
    if forms[0] == "fail" and len(conditions) != 1:
        errors.append(f"{rid}: 'when.fail' requiere exactamente una de attachment_description_prefix o attached_instance_fail")
    if forms[0] != "fail" and conditions:
        errors.append(f"{rid}: {conditions[0]} solo se usa con 'when.fail'")
    for key, value in when.items():
        if key == "command_contains":
            if not (isinstance(value, list) and all(_non_empty_text(v) for v in value)):
                errors.append(f"{rid}: when.command_contains debe ser lista de textos no vacios")
        elif key == "attachment_description_prefix":
            if not _non_empty_text(value):
                errors.append(f"{rid}: when.attachment_description_prefix debe ser un texto no vacio")
        elif key == "attached_instance_fail":
            if not (isinstance(value, dict) and _non_empty_text(value.get("check")) and _non_empty_text(value.get("evidence_true"))):
                errors.append(f"{rid}: when.attached_instance_fail requiere {{check, evidence_true}} no vacios")
        elif key not in ("all_fail", "any_fail", "fail"):
            errors.append(f"{rid}: when.{key} desconocido")
    return errors


def _rule_errors(rule, check_ids):
    rid = rule.get("id", "<sin id>") if isinstance(rule, dict) else "<regla invalida>"
    if not isinstance(rule, dict):
        return [f"{rid}: la regla debe ser un objeto"]
    errors = [f"{rid}: falta el campo '{f}'" for f in ("id", "when", "scope", "status", "message", "order") if f not in rule]
    if errors:
        return errors
    if rule["status"] not in RULE_STATUSES:
        errors.append(f"{rid}: status invalido '{rule['status']}'")
    if rule["scope"] not in RULE_SCOPES:
        errors.append(f"{rid}: scope invalido '{rule['scope']}'")
    if not str(rule["message"]).strip():
        errors.append(f"{rid}: message vacio")
    errors += _rule_when_errors(rid, rule["when"])
    cited = _rule_check_refs(rule["when"]) if isinstance(rule["when"], dict) else []
    pairs = rule["order"] if isinstance(rule["order"], list) else []
    if not isinstance(rule["order"], list) or not all(isinstance(p, list) and len(p) == 2 for p in pairs):
        errors.append(f"{rid}: order debe ser una lista de pares [antes, despues]")
        pairs = [p for p in pairs if isinstance(p, list) and len(p) == 2]
    cited += [("order", c) for pair in pairs for c in pair]
    errors += [f"{rid}: {key} cita un chequeo inexistente '{c}'" for key, c in cited if c not in check_ids]
    return errors


def validate_conflict_rules(rules, checks) -> list[str]:
    """Rule ids must be unique and every check id cited in `when` or `order` must exist in the catalog."""
    if not isinstance(rules, list):
        return ["conflict-rules: se esperaba una lista de reglas"]
    check_ids = {c.get("id") for c in checks}
    errors, seen = [], set()
    for rule in rules:
        errors += _rule_errors(rule, check_ids)
        rid = rule.get("id") if isinstance(rule, dict) else None
        if rid in seen:
            errors.append(f"{rid}: id de regla duplicado")
        seen.add(rid)
    return errors


def validate(checks, tsc_ids, iso_ids, drata, conflict_rules=None, *, inventory_types=None, registered=None,
             required_params=None) -> list[str]:
    """`inventory_types` (keys of inventory.json), `registered` (python evaluator names) and `required_params`
    ({evaluator: keys}) enable the checks that need them; validate_catalog.py always passes all three."""
    errors = []
    seen_ids = set()
    for check in checks:
        errors += _check_identity(check, seen_ids)
        missing = _missing_fields(check)
        if missing:
            errors += missing
            continue
        errors += _check_enums(check)
        errors += _check_contract(check, inventory_types, registered, required_params)
        errors += _check_calls_read_only(check)
        errors += _check_framework_ids(check, tsc_ids, iso_ids)
        errors += _check_jmespath(check)
        errors += _check_call_options(check)
        errors += _check_remediation(check)
        errors += _check_coverage(check, drata)
    if conflict_rules is not None:
        errors += validate_conflict_rules(conflict_rules, checks)
    return errors
