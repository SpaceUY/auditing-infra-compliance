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
_REQUIRED_MAPPINGS = ("drata", "vanta", "tsc_inferred", "iso_inferred", "security_hub", "cis_aws")


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


def _is_read_only(service: str, operation: str) -> bool:
    try:
        aws_runner.assert_read_only(service, operation, [])
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


def _check_calls_read_only(check):
    cid = check["id"]
    return [
        f"{cid}: llamada '{c.get('name')}' no es de solo lectura "
        f"({c.get('service')} {c.get('operation')})"
        for c in check["verify"]["calls"]
        if not _is_read_only(c.get("service", ""), c.get("operation", ""))
    ]


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


def validate(checks, tsc_ids, iso_ids, drata) -> list[str]:
    errors = []
    seen_ids = set()
    for check in checks:
        errors += _check_identity(check, seen_ids)
        missing = _missing_fields(check)
        if missing:
            errors += missing
            continue
        errors += _check_enums(check)
        errors += _check_calls_read_only(check)
        errors += _check_framework_ids(check, tsc_ids, iso_ids)
        errors += _check_jmespath(check)
        errors += _check_remediation(check)
        errors += _check_coverage(check, drata)
    return errors
