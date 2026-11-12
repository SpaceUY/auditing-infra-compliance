"""Builds <run-dir>/findings.json from collect outputs, the vault index and Claude's vault claims.

Inputs: <run-dir>/checks-result.json and inventory.json (collect.py), an optional vault-index.json (vault_index.py)
and an optional vault-claims.json (written by Claude; see references/report-format.md).

Rules worth knowing:
- Findings come from collect rows (every status, PASS and N/A included), vault claims (DRIFT, UNDOCUMENTED,
  DOCUMENTED_ONLY, DOCUMENTED_GAP) and one critical FAIL per secret the vault indexer detected.
- PENDING_CLAUDE rows are replaced by the EVAL claims with the same check_id (claim resource must match unless the row
  is the account-level one); without a claim they become NO_VERIFICADO plus a warning.
- Severity: detail.severity_override > explicit claim severity > catalog severity (UNDOCUMENTED and claims without a
  check default to low). A claim with breaks_tests becomes a DRIFT of at least high severity.
- Remediation placeholders are filled with plain regex substitution (commands contain literal JSON braces, never
  str.format): {resource_id} {region} {account_id} {resource_name} {resource_arn} {detail_json:<key>}. A value that is
  unknown stays as a __COMPLETAR_*__ marker. Identifiers are substituted unmasked (only keys/secrets are masked) but
  only when they pass an allow-list (R51: no quotes, spaces, $, backticks, newlines); a value that fails becomes its
  __COMPLETAR_<NAME>__ marker and the finding adds a warning. Placeholders are filled in steps, commands, verify_after
  and notes. A claim-sourced regional resource without region gets __COMPLETAR_REGION__ (account/global: us-east-1).
  Evidence, vault_claim, warnings and notes go through redact.mask_obj with the VantaOwner emails kept.
- Coverage never turns into a percentage: each ISO/TSC id is FAIL, NO_VERIFICADO, PASS or NOT_TOUCHED.
"""

import argparse
import json
import re
import shlex
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import catalog
import redact

SKILL_DIR = Path(__file__).resolve().parent.parent
ACCOUNT = "account"
DEFAULT_REGION = "us-east-1"
OWNER_TAG = "VantaOwner"
STATUS_ORDER = ("FAIL", "DRIFT", "UNDOCUMENTED", "DOCUMENTED_GAP", "NO_VERIFICADO", "DOCUMENTED_ONLY", "PASS", "N/A")
CLAIM_KINDS = ("DRIFT", "UNDOCUMENTED", "DOCUMENTED_ONLY", "DOCUMENTED_GAP")
EVAL_STATUSES = ("PASS", "FAIL", "NO_VERIFICADO", "N/A")
COVERAGE_RANK = {"PASS": 0, "NO_VERIFICADO": 1, "FAIL": 2}
SAFE_VALUE = re.compile(r"[A-Za-z0-9_.:/@=+,#-]{1,512}")  # R51: nothing the shell would interpret
SAFE_REGION = re.compile(r"[a-z]{2}(-[a-z]+)+-\d")
SAFE_ACCOUNT = re.compile(r"\d{12}")
UNSAFE_WARNING = "{id}: identificador con caracteres no seguros, completar a mano"
PLACEHOLDER = re.compile(r"\{(resource_id|region|account_id|resource_name|resource_arn|detail_json:[A-Za-z0-9_]+)\}")
EMPTY_MAPPINGS = {"drata": [], "vanta": [], "tsc": [], "iso27001_2022": [], "security_hub": [], "cis_aws": []}
CLAIM_TITLES = {
    "DRIFT": "El vault no coincide con lo que hay en AWS",
    "UNDOCUMENTED": "Recurso o configuración sin documentar en el vault",
    "DOCUMENTED_ONLY": "Documentado en el vault, sin recurso verificable en AWS",
    "DOCUMENTED_GAP": "Brecha reconocida en el vault",
}
SECRET_TITLE = "Credenciales en texto plano en el vault"
SECRET_REMEDIATION = {
    "kind": "console_only", "risk": "low", "downtime": False,
    "steps": ["Revocar o rotar la credencial expuesta desde la consola de AWS (IAM) antes de editar la nota.",
              "Quitar el valor de la nota del vault y guardar la referencia al gestor de secretos en su lugar.",
              "Revisar el historial del vault y de los repos que lo sincronizan por copias de la credencial."],
    "commands": [], "verify_after": "", "notes": "Una credencial escrita en el vault debe darse por comprometida.",
}


@dataclass
class Env:
    checks: dict
    drata: dict
    inventory: list
    account_id: str | None
    keep: frozenset
    specs: dict


def _read_json(path, default):
    path = Path(path)
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError
        raise ValueError(f"{path}: JSON inválido ({' '.join(str(exc).split())})") from exc


def _unmasked(text):
    """Identifiers keep their emails; only keys and secrets are masked (they end up in commands)."""
    return redact.mask_secrets(text) if isinstance(text, str) else text


# ---------------------------------------------------------------- resources and remediation

def _lookup(env, resource_id, region):
    found = [i for i in env.inventory if resource_id in (i["id"], i["arn"], i["name"])]
    return next((i for i in found if i["region"] == region), found[0] if found else None)


def _resource(env, check, resource_id, region, type_hint=None):
    """(resource dict, arn) for a finding. A missing id (claim without resource) yields an all-None resource."""
    if resource_id is None:
        return {"type": type_hint, "id": None, "region": region, "name": None}, None
    resource_id = _unmasked(resource_id)
    item = None if resource_id == ACCOUNT else _lookup(env, resource_id, region)
    if resource_id == ACCOUNT:
        rtype = ACCOUNT
    elif item:
        rtype = item["type"]
    else:
        rtype = type_hint or (check["resource_types"][0] if check and check["resource_types"] else None)
    name = _unmasked(item["name"]) if item else resource_id
    arn = _unmasked(item["arn"]) if item and item["arn"] else (resource_id if resource_id.startswith("arn:") else None)
    return {"type": rtype, "id": resource_id, "region": region, "name": name}, arn


def _fill(text, values, detail, used):
    def substitute(match):
        key = match.group(1)
        if not key.startswith("detail_json:"):
            used.add(key)
            return values[key]
        name = key.split(":", 1)[1]
        if name not in detail:
            return f"__COMPLETAR_{name.upper()}__"
        compact = json.dumps(detail[name], separators=(",", ":"))
        return shlex.quote(redact.mask_secrets(compact))

    return PLACEHOLDER.sub(substitute, text)


def _is_global(env, check, resource):
    """True when a missing region means us-east-1: account rows, global resource types, account checks."""
    if resource["id"] == ACCOUNT:
        return True
    if resource["id"] is None:
        return bool(check) and check["scope"] == "account"
    return (env.specs.get(resource["type"]) or {}).get("region") == "global"


def _safe_values(env, check, resource, arn):
    """Plain values for the placeholders; (values, names that failed the allow-list). Unsafe -> __COMPLETAR_<NAME>__."""
    region = resource["region"] or (DEFAULT_REGION if _is_global(env, check, resource) else None)
    candidates = {
        "resource_id": (resource["id"], SAFE_VALUE),
        "region": (region, SAFE_REGION),
        "account_id": (env.account_id, SAFE_ACCOUNT),
        "resource_name": (resource["name"] or resource["id"], SAFE_VALUE),
        "resource_arn": (arn, SAFE_VALUE),
    }
    values, bad = {}, set()
    for key, (value, pattern) in candidates.items():
        if value is not None and pattern.fullmatch(value):
            values[key] = value
            continue
        values[key] = f"__COMPLETAR_{key.upper()}__"
        if value is not None:
            bad.add(key)
    return values, bad


def _remediation(env, check, resource, arn, detail):
    """(instantiated remediation | None, True when an unsafe value was replaced by a marker)."""
    if not check:
        return None, False
    values, bad = _safe_values(env, check, resource, arn)
    used = set()
    rem = check["remediation"]
    filled = {**rem,
              "steps": [_fill(t, values, detail, used) for t in rem["steps"]],
              "commands": [_fill(t, values, detail, used) for t in rem["commands"]],
              "verify_after": _fill(rem["verify_after"], values, detail, used),
              "notes": _fill(rem["notes"], values, detail, used)}
    return filled, bool(used & bad)


# ---------------------------------------------------------------- finding construction

def _mappings(env, check):
    return catalog.resolve_mappings(check, env.drata) if check else {k: [] for k in EMPTY_MAPPINGS}


def _severity(check, detail, explicit=None, default="low"):
    override = detail.get("severity_override")
    if override in catalog.SEVERITIES:
        return override
    if explicit in catalog.SEVERITIES:
        return explicit
    return check["severity"] if check else default


def _finding(env, check, *, status, severity, resource, arn=None, detail=None, evidence=None, title=None,
             vault_claim=None, vault_note=None, evaluated_by="script", vacuous=False, breaks_tests=(), missing=(),
             check_id=None):
    detail = detail or {}
    remediation, unsafe = _remediation(env, check, resource, arn, detail)
    return {
        "id": None,
        "check_id": check["id"] if check else check_id,
        "title": check["title"] if check else title,
        "domain": check["domain"] if check else "vault",
        "status": status,
        "severity": severity,
        "resource": resource,
        "evidence": redact.mask_obj(detail if evidence is None else evidence, keep_emails=env.keep),
        "vault_claim": redact.mask(vault_claim, keep_emails=env.keep) if vault_claim else None,
        "vault_note": redact.mask(vault_note, keep_emails=env.keep) if vault_note else None,
        "mappings": _mappings(env, check),
        "remediation": remediation,
        "_unsafe": unsafe,
        "evaluated_by": evaluated_by,
        "vacuous": vacuous,
        "breaks_tests": [dict(b) for b in breaks_tests],
        "missing": list(missing),
        "depends_on_me": [],
    }


def _row_finding(env, row, status=None, detail=None, warnings=None):
    check = env.checks.get(row["check_id"])
    if check is None and warnings is not None:
        warnings.append(f"chequeo {row['check_id']} ausente del catálogo: sin título, mapeos ni remediación")
    detail = (row.get("detail") or {}) if detail is None else detail
    resource, arn = _resource(env, check, row["resource_id"], row.get("region"))
    return _finding(env, check, status=status or row["status"], severity=_severity(check, detail), resource=resource,
                    arn=arn, detail=detail, title=row["check_id"], check_id=row["check_id"],
                    vacuous=bool(row.get("vacuous")), missing=row.get("missing") or [])


def _claim_resource(env, check, claim):
    ref = claim.get("resource")
    if not ref:
        return {"type": None, "id": None, "region": None, "name": None}, None
    return _resource(env, check, ref.get("id"), ref.get("region"), ref.get("type"))


def _eval_finding(env, row, claim, warnings):
    check = env.checks.get(claim["check_id"])
    status = claim.get("status")
    if status not in EVAL_STATUSES:
        warnings.append(f"claim EVAL de {claim['check_id']} con estado inválido {status!r}: queda NO_VERIFICADO")
        status = "NO_VERIFICADO"
    detail = dict(claim.get("detail") or {})
    evidence = {**detail, **({"actual": claim["actual"]} if claim.get("actual") else {})}
    if claim.get("resource"):
        resource, arn = _claim_resource(env, check, claim)
    else:
        resource, arn = _resource(env, check, row["resource_id"], row.get("region"))
    return _finding(env, check, status=status, severity=_severity(check, detail, claim.get("severity")),
                    resource=resource, arn=arn, detail=detail, evidence=evidence, title=claim["check_id"], check_id=claim["check_id"],
                    vault_claim=claim.get("vault_claim"), vault_note=claim.get("vault_note"),
                    evaluated_by="claude", vacuous=status == "N/A")


def _eval_matches(row, claim):
    ref = claim.get("resource") or {}
    return claim.get("check_id") == row["check_id"] and (
        row["resource_id"] == ACCOUNT or (ref.get("id") or ACCOUNT) == row["resource_id"])


def _row_findings(env, rows, evals, warnings):
    findings, pending = [], list(evals)
    for row in rows:
        if row["status"] != "PENDING_CLAUDE":
            findings.append(_row_finding(env, row, warnings=warnings))
            continue
        matched = [c for c in pending if _eval_matches(row, c)]
        pending = [c for c in pending if c not in matched]
        if matched:
            findings += [_eval_finding(env, row, c, warnings) for c in matched]
            continue
        warnings.append(f"{row['check_id']} espera una evaluación de Claude (EVAL) que no llegó: queda NO_VERIFICADO")
        detail = {**(row.get("detail") or {}), "reason": "evaluación de Claude pendiente"}
        findings.append(_row_finding(env, row, status="NO_VERIFICADO", detail=detail, warnings=warnings))
    warnings += [f"claim EVAL de {c.get('check_id')} sin fila PENDING_CLAUDE que resolver" for c in pending]
    return findings


def _claim_severity(check, claim, kind):
    explicit = claim.get("severity") if claim.get("severity") in catalog.SEVERITIES else None
    if claim.get("breaks_tests"):
        ranked = [s for s in ("high", explicit) if s]
        return min(ranked, key=catalog.SEVERITIES.index)
    if explicit:
        return explicit
    if kind == "UNDOCUMENTED" or not check:
        return "low"
    return check["severity"]


def _claim_finding(env, claim, warnings):
    kind, cid = claim["kind"], claim.get("check_id")
    check = env.checks.get(cid) if cid else None
    if cid and check is None:
        warnings.append(f"claim {kind} con check_id {cid} ausente del catálogo")
    if claim.get("breaks_tests"):
        kind = "DRIFT"
    resource, arn = _claim_resource(env, check, claim)
    evidence = {"actual": claim["actual"]} if claim.get("actual") else {}
    return _finding(env, check, status=kind, severity=_claim_severity(check, claim, kind), resource=resource,
                    arn=arn, evidence=evidence, title=CLAIM_TITLES[kind], check_id=cid,
                    vault_claim=claim.get("vault_claim"), vault_note=claim.get("vault_note"), evaluated_by="claude",
                    breaks_tests=claim.get("breaks_tests") or [])


def _claim_findings(env, claims, warnings):
    findings = []
    for claim in claims:
        if claim.get("kind") in CLAIM_KINDS:
            findings.append(_claim_finding(env, claim, warnings))
        elif claim.get("kind") != "EVAL":
            warnings.append(f"claim con kind desconocido {claim.get('kind')!r}: ignorado")
    return findings


def _secret_findings(env, vault_index):
    findings = []
    for secret in (vault_index or {}).get("secrets_detected") or []:
        path = redact.mask_secrets(secret["path"])
        resource = {"type": "vault_note", "id": path, "region": None, "name": path}
        findings.append(_finding(
            env, None, status="FAIL", severity="critical", resource=resource, title=SECRET_TITLE,
            evidence={"path": path, "pattern": secret["pattern"]}, vault_note=path))
        findings[-1]["remediation"] = json.loads(json.dumps(SECRET_REMEDIATION))
    return findings


# ---------------------------------------------------------------- ordering, dependencies, coverage, summary

def _sort_key(finding):
    resource = finding["resource"]
    return (catalog.SEVERITIES.index(finding["severity"]), STATUS_ORDER.index(finding["status"]),
            finding["check_id"] is None, finding["check_id"] or "", resource["id"] or "", str(resource["region"]))


def _tests(mappings):
    tests = [{"tool": "drata", "test": m["test"], "name": m.get("name", "")} for m in mappings["drata"]]
    return tests + [{"tool": "vanta", "test": m["test"], "name": m.get("name", m["test"])} for m in mappings["vanta"]]


def _dependencies(findings):
    grouped = {}
    for f in findings:
        resource = f["resource"]
        if f["status"] != "PASS" or resource["id"] in (None, ACCOUNT):
            continue
        entry = grouped.setdefault(resource["id"], {"resource_id": resource["id"], "resource_type": resource["type"],
                                                    "tests": []})
        entry["tests"] += [t for t in _tests(f["mappings"]) if t not in entry["tests"]]
    return [e for e in grouped.values() if e["tests"]]


def _worst_status(findings):
    worst = {"iso27001_2022": {}, "tsc": {}}
    for f in findings:
        if f["status"] not in COVERAGE_RANK:
            continue
        for key, seen in worst.items():
            for mapping in f["mappings"][key]:
                current = seen.get(mapping["id"])
                if current is None or COVERAGE_RANK[f["status"]] > COVERAGE_RANK[current]:
                    seen[mapping["id"]] = f["status"]
    return worst


def _iso_category(control):
    if control.get("responsibility") == "inherited":
        return "inherited"
    return "technical" if control.get("technical") else "organizational"


def _coverage_entries(items, statuses, category):
    entries = [{"id": i["id"], "name": i["name"], "status": statuses.get(i["id"], "NOT_TOUCHED"),
                "category": category(i)} for i in items]
    known = {i["id"] for i in items}
    entries += [{"id": i, "name": "", "status": s, "category": "organizational"}
                for i, s in sorted(statuses.items()) if i not in known]
    return entries


def _coverage(findings, skill_dir):
    frameworks = Path(skill_dir) / "references" / "frameworks"
    iso = _read_json(frameworks / "iso27001-2022.json", {"controls": [], "clauses": []})
    tsc = _read_json(frameworks / "tsc-2017.json", {"criteria": []})
    worst = _worst_status(findings)
    return {
        "iso": _coverage_entries(iso["controls"] + iso["clauses"], worst["iso27001_2022"], _iso_category),
        "tsc": _coverage_entries(tsc["criteria"], worst["tsc"],
                                 lambda c: "technical" if c.get("technical") else "organizational"),
    }


def _summary(findings):
    failing = [f for f in findings if f["status"] == "FAIL"]
    drata = {t["test"] for f in failing for t in _tests(f["mappings"]) if t["tool"] == "drata"}
    vanta = {t["test"] for f in failing for t in _tests(f["mappings"]) if t["tool"] == "vanta"}
    by_status, by_severity = Counter(f["status"] for f in findings), Counter(f["severity"] for f in failing)
    return {"by_status": {s: by_status[s] for s in STATUS_ORDER},
            "by_severity_fail": {s: by_severity[s] for s in catalog.SEVERITIES},
            "drata_tests_failing": sorted(drata), "vanta_tests_failing": sorted(vanta),
            "not_verified": by_status["NO_VERIFICADO"]}


# ---------------------------------------------------------------- assemble and CLI

def _vault_warnings(vault_index):
    if not vault_index:
        return []
    warnings = [f"link roto en {b['from']}: [[{b['target']}]]" for b in vault_index.get("broken_links") or []]
    return warnings + [f"credencial detectada en el vault: {s['path']} ({s['pattern']})"
                       for s in vault_index.get("secrets_detected") or []]


def _notes(aws, vault_index):
    notes = []
    if not aws:
        notes.append("Sin credenciales AWS: solo se informan los hallazgos del vault.")
    if not vault_index:
        notes.append("Sin vault: no se comparó la documentación con AWS.")
    return notes


def assemble(run_dir: Path, vault_index: dict | None, claims: list, meta: dict, skill_dir: Path) -> dict:
    run_dir, skill_dir = Path(run_dir), Path(skill_dir)
    checks = catalog.load_checks(skill_dir / "references" / "checks")
    result = _read_json(run_dir / "checks-result.json", {})
    aws = result.get("aws")
    inventory = _read_json(run_dir / "inventory.json", []) if aws else []
    specs = _read_json(skill_dir / "references" / "inventory.json", {})
    owners = frozenset(i["tags"][OWNER_TAG] for i in inventory if (i.get("tags") or {}).get(OWNER_TAG))
    env = Env({c["id"]: c for c in checks},
              catalog.load_drata_map(skill_dir / "references" / "mappings" / "drata-dcf.json"),
              inventory, (aws or {}).get("account_id"), owners, specs)
    claims = claims or []
    warnings = list(result.get("warnings") or []) + _vault_warnings(vault_index)

    rows = (result.get("results") or []) if aws else []
    findings = _row_findings(env, rows, [c for c in claims if c.get("kind") == "EVAL"], warnings)
    findings += _claim_findings(env, claims, warnings) + _secret_findings(env, vault_index)
    findings.sort(key=_sort_key)
    dependencies = _dependencies(findings)
    tests_by_resource = {d["resource_id"]: d["tests"] for d in dependencies}
    for number, finding in enumerate(findings, start=1):
        finding["id"] = f"F-{number:04d}"
        if finding.pop("_unsafe"):
            warnings.append(UNSAFE_WARNING.format(id=finding["id"]))
        finding["depends_on_me"] = list(tests_by_resource.get(finding["resource"]["id"], []))

    return {
        "meta": {"platform": meta.get("platform"), "mode": meta.get("mode"), "target": meta.get("target"),
                 "generated_at": meta.get("generated_at") or datetime.now().astimezone().isoformat(timespec="seconds"),
                 "lang": meta.get("lang", "es"), "catalog_checks": len(checks),
                 "vault": {"path": vault_index.get("root"), "kind": vault_index.get("kind")} if vault_index else None,
                 "aws": redact.mask_obj({k: aws.get(k) for k in ("account_id", "identity_arn", "regions")},
                                        keep_emails=env.keep) if aws else None},
        "summary": _summary(findings),
        "findings": findings,
        "dependencies": dependencies,
        "coverage": _coverage(findings, skill_dir),
        "warnings": redact.mask_obj(warnings, keep_emails=env.keep),
        "notes": redact.mask_obj(_notes(aws, vault_index), keep_emails=env.keep),
    }


def _list_of_dicts(value, label):
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise ValueError(f"{label}: se esperaba una lista de objetos")
    return value


def _load_claims(path):
    claims = _list_of_dicts(_read_json(path, None), f"{path}")
    for claim in claims:
        problems = [
            not isinstance(claim.get("kind"), str),
            claim.get("check_id") is not None and not isinstance(claim["check_id"], str),
            claim.get("resource") is not None and not isinstance(claim["resource"], dict),
            claim.get("detail") is not None and not isinstance(claim["detail"], dict),
            not isinstance(claim.get("breaks_tests") or [], list)
            or not all(isinstance(b, dict) for b in claim.get("breaks_tests") or []),
        ]
        if any(problems):
            raise ValueError(f"{path}: claim con forma inválida (kind, check_id, resource, detail o breaks_tests)")
    return claims


def _load_index(path):
    index = _read_json(path, None)
    if not isinstance(index, dict) or not isinstance(index.get("kind"), str):
        raise ValueError(f"{path}: no es un vault-index.json (falta 'kind')")
    for key, required in (("broken_links", ("from", "target")), ("secrets_detected", ("path", "pattern"))):
        items = _list_of_dicts(index.get(key) or [], f"{path} {key}")
        if any(field not in item for item in items for field in required):
            raise ValueError(f"{path}: {key} con forma inválida (faltan {', '.join(required)})")
    return index


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Arma findings.json a partir de collect, el vault y los claims")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--vault-index")
    parser.add_argument("--vault-claims")
    parser.add_argument("--platform", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--target")
    parser.add_argument("--lang", default="es")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(f"el directorio de la corrida no existe: {run_dir}", file=sys.stderr)
        return 2
    meta = {"platform": args.platform, "mode": args.mode, "target": args.target, "lang": args.lang}
    try:
        index = _load_index(args.vault_index) if args.vault_index else None
        claims = _load_claims(args.vault_claims) if args.vault_claims else []
        findings = assemble(run_dir, index, claims, meta, SKILL_DIR)
        (run_dir / "findings.json").write_text(json.dumps(findings, indent=2, ensure_ascii=False) + "\n",
                                               encoding="utf-8")
    except (ValueError, OSError) as exc:
        print(f"error: {' '.join(str(exc).split())}", file=sys.stderr)
        return 2
    counts = findings["summary"]["by_status"]
    print(f"{len(findings['findings'])} hallazgos ("
          + ", ".join(f"{s}: {n}" for s, n in counts.items() if n) + f"). Detalle en: {run_dir / 'findings.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
