"""Builds <run-dir>/findings.json from collect outputs, the vault index and Claude's vault claims.

Inputs: <run-dir>/checks-result.json and inventory.json (collect.py), an optional vault-index.json (vault_index.py)
and an optional vault-claims.json (written by Claude; see references/report-format.md).

Rules worth knowing:
- Findings come from collect rows (every status, PASS and N/A included), vault claims (DRIFT, UNDOCUMENTED,
  DOCUMENTED_ONLY, DOCUMENTED_GAP) and one critical FAIL per secret the vault indexer detected.
- PENDING_CLAUDE rows are replaced by the EVAL claims with the same check_id (claim resource must match unless the row
  is the account-level one); without a claim they become NOT_VERIFIED plus a warning.
- Remediation by status: FAIL, DOCUMENTED_GAP and a DRIFT or UNDOCUMENTED claim with actual_status "FAIL" keep the full fix; the other
  statuses (DOCUMENTED_ONLY, PASS, N/A, NOT_VERIFIED, any other DRIFT or UNDOCUMENTED) carry no steps/commands/notes and no kind, risk or
  downtime (null), only verify_after and a remediation.note_status. A DOCUMENTED_ONLY finding is severity low with evidence.catalog_severity (the check's severity).
- Severity: detail.severity_override > explicit claim severity > catalog severity (UNDOCUMENTED and claims without a
  check default to low). A claim with breaks_tests becomes a DRIFT of at least high severity.
- Remediation placeholders are filled with plain regex substitution (commands contain literal JSON braces, never
  str.format): {resource_id} {region} {account_id} {resource_name} {resource_arn} {detail_json:<key>}. A value that is
  unknown stays as a __FILL_IN_*__ marker. Identifiers are substituted unmasked (only keys/secrets are masked) but
  only when they pass an allow-list (R51: no quotes, spaces, $, backticks, newlines); a value that fails becomes its
  __FILL_IN_<NAME>__ marker and the finding adds a warning. Placeholders are filled in steps, commands, verify_after
  and notes. A claim-sourced regional resource without region gets __FILL_IN_REGION__ (account/global: us-east-1).
  Evidence, vault_claim, warnings, notes, breaks_tests and meta.platform/target go through redact.mask_obj with the VantaOwner
  emails kept. meta.vault.path is the vault folder name, never the absolute path.
- Coverage never turns into a percentage: each ISO/TSC id is FAIL, NOT_VERIFIED, PASS or NOT_TOUCHED (a control touched only by
  DOCUMENTED_ONLY / DOCUMENTED_GAP findings is NOT_VERIFIED: the vault says so, nothing checked it).
- summary.verdict is exactly one of NOT_OPTIMAL, NOT_VERIFIABLE and OPTIMAL, and summary.verdict_basis says what it rests on: "aws"
  (credentials, no vault), "vault" (no credentials) or "aws+vault". verdict_text is the one-line English version and always names the
  basis; there are no scores. With credentials ("aws", "aws+vault"): NOT_OPTIMAL for any FAIL, any finding whose actual_status is FAIL
  (DRIFT, UNDOCUMENTED or another) or a critical/high DOCUMENTED_GAP; NOT_VERIFIABLE for a partial run, blocked regions, an incomplete
  inventory, a DRIFT from breaks_tests without a failing actual_status, no evaluated PASS/FAIL at all, or anything not verified
  (NOT_VERIFIED, DOCUMENTED_ONLY, DOCUMENTED_GAP, scoped components without claims); OPTIMAL otherwise. Vault only ("vault"): NOT_OPTIMAL for a
  critical/high DOCUMENTED_GAP, a secret or sensitive-file FAIL or a claim with actual_status FAIL; OPTIMAL when at least one control is
  documented (DOCUMENTED_ONLY), there is no DOCUMENTED_GAP at all, nothing else is unresolved (DRIFT, UNDOCUMENTED, NOT_VERIFIED) and no
  scoped component lacks claims; otherwise NOT_VERIFIABLE with the reasons. A vault-only verdict never says AWS verified anything, and the
  DOCUMENTED_* statuses stay as they are (nothing is marked PASS or FAIL from the vault).
- <run-dir>/scope.json (optional) lists the scoped components: those with no finding at all come out in `unverified_scope`.
- Without a vault index, claims or AWS credentials there is nothing to report: assemble stops ("no sources") and writes nothing.
"""

import argparse
import hashlib
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
STATUS_ORDER = ("FAIL", "DRIFT", "UNDOCUMENTED", "DOCUMENTED_GAP", "NOT_VERIFIED", "DOCUMENTED_ONLY", "PASS", "N/A")
CLAIM_KINDS = ("DRIFT", "UNDOCUMENTED", "DOCUMENTED_ONLY", "DOCUMENTED_GAP")
EVAL_STATUSES = ("PASS", "FAIL", "NOT_VERIFIED", "N/A")
COVERAGE_RANK = {"PASS": 0, "NOT_VERIFIED": 1, "FAIL": 2}
COVERAGE_STATUS = {"DOCUMENTED_ONLY": "NOT_VERIFIED", "DOCUMENTED_GAP": "NOT_VERIFIED"}
SAFE_VALUE = re.compile(r"[A-Za-z0-9_.:/@=+,#-]{1,512}")  # R51: nothing the shell would interpret
SAFE_REGION = re.compile(r"[a-z]{2}(-[a-z]+)+-[0-9]", re.ASCII)
SAFE_ACCOUNT = re.compile(r"[0-9]{12}", re.ASCII)
UNSAFE_WARNING = "{id}: identifier with unsafe characters, fill in by hand"
PLACEHOLDER = re.compile(r"\{(resource_id|region|account_id|resource_name|resource_arn|detail_json:[A-Za-z0-9_]+)\}")
EMPTY_MAPPINGS = {"drata": [], "vanta": [], "tsc": [], "iso27001_2022": [], "security_hub": [], "cis_aws": []}
CLAIM_TITLES = {
    "DRIFT": "The vault does not match what is in AWS",
    "UNDOCUMENTED": "Resource or configuration not documented in the vault",
    "DOCUMENTED_ONLY": "Documented in the vault, with no verifiable resource in AWS",
    "DOCUMENTED_GAP": "Gap acknowledged in the vault",
}
NOTE_STATUS = "not verified: do not apply without confirming"
NOTE_STATUS_BY_STATUS = {"PASS": "verified in AWS: compliant, no fix needed (the command is only useful to re-check it)",
                         "N/A": "does not apply in this scope: no fix needed"}
NO_SOURCES = "no sources: a vault or read-only AWS credentials are required"
TOOLS = ("drata", "vanta", "both")
BASIS_TEXT = {"aws": "based on AWS", "aws+vault": "based on AWS and the vault",
              "vault": "based on what the vault documents (not verified against AWS)"}
UNTYPED_WARNING = "untyped vault: the component map is inferred and less reliable"
VAULT_STATEMENTS = frozenset({"DOCUMENTED_ONLY", "DOCUMENTED_GAP"})  # transcribed from the vault, not evaluated
FIX_STATUSES = frozenset({"FAIL", "DOCUMENTED_GAP"})
FIX_IF_ACTUAL_FAILS = frozenset({"DRIFT", "UNDOCUMENTED"})  # only when the claim says its `actual` fails
SECRET_TITLE = "Plaintext credentials in the vault"
SENSITIVE_TITLE = "Sensitive file inside the vault (probable plaintext credentials)"
SENSITIVE_REMEDIATION = {
    "kind": "console_only", "risk": "low", "downtime": False,
    "steps": ["Rotate any credentials the file may contain (it was not opened: it was detected by name only).",
              "Remove the file from the vault and from the repository that syncs it, and store the credentials in a secrets manager.",
              "Review the history of the vault and of the repos for copies of the file."],
    "commands": [], "verify_after": "", "notes": "The skill never opens this kind of file: treat whatever it contains as compromised.",
}
TEMPLATE_NAME = re.compile(r"(\.env\.[^/]*|\.pem|credentials[^/]*\.md)$", re.I)
TEMPLATE_HINT = "review: it may be a template or a public certificate"
SECRET_REMEDIATION = {
    "kind": "console_only", "risk": "low", "downtime": False,
    "steps": ["Revoke or rotate the exposed credential from the AWS console (IAM) before editing the note.",
              "Remove the value from the vault note and keep a reference to the secrets manager in its place.",
              "Review the history of the vault and of the repos that sync it for copies of the credential."],
    "commands": [], "verify_after": "", "notes": "A credential written in the vault must be treated as compromised.",
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
        raise ValueError(f"{path}: invalid JSON ({' '.join(str(exc).split())})") from exc


def _unmasked(text):
    """Identifiers keep their emails; only keys and secrets are masked (they end up in commands)."""
    return redact.mask_secrets(text) if isinstance(text, str) else text


# ---------------------------------------------------------------- resources and remediation

def _lookup(env, resource_id, region, types=None):
    """The inventory item for an id, ARN or name. Names repeat across types (a bucket and a role called acme-prod), so the
    wanted types (the claim's type or the check's resource_types) filter first; an item of another type is never used."""
    found = [i for i in env.inventory if resource_id in (i["id"], i["arn"], i["name"]) and (not types or i["type"] in types)]
    return next((i for i in found if i["region"] == region), found[0] if found else None)


def _wanted_types(check, type_hint):
    if type_hint:
        return [type_hint]
    return list(check["resource_types"]) if check and check.get("resource_types") else None


def _resource(env, check, resource_id, region, type_hint=None):
    """(resource dict, arn) for a finding. A missing id (claim without resource) yields an all-None resource."""
    if resource_id is None:
        return {"type": type_hint, "id": None, "region": region, "name": None}, None
    resource_id = _unmasked(resource_id)
    item = None if resource_id == ACCOUNT else _lookup(env, resource_id, region, _wanted_types(check, type_hint))
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
            return f"__FILL_IN_{name.upper()}__"
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
    """Plain values for the placeholders; (values, names that failed the allow-list). Unsafe -> __FILL_IN_<NAME>__."""
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
        values[key] = f"__FILL_IN_{key.upper()}__"
        if value is not None:
            bad.add(key)
    return values, bad


def _remediation(env, check, resource, arn, detail, keep_fix=True, status=None):
    """(instantiated remediation | None, True when an unsafe value was replaced by a marker).

    Without keep_fix (the status is not verified: DOCUMENTED_ONLY, PASS, N/A, NOT_VERIFIED...) the remediation carries no
    steps, commands or notes, only the verify_after command and a `note_status`.
    """
    if not check:
        return None, False
    values, bad = _safe_values(env, check, resource, arn)
    used = set()
    rem = check["remediation"]
    if not keep_fix:
        verify = _fill(rem["verify_after"], values, detail, used)
        # nothing to apply: no kind, risk or downtime either (a consumer must not read a pending high-risk change into it)
        return {**rem, "kind": None, "risk": None, "downtime": None, "steps": [], "commands": [], "verify_after": verify, "notes": "",
                "note_status": NOTE_STATUS_BY_STATUS.get(status, NOTE_STATUS)}, bool(used & bad)
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
             check_id=None, actual_fails=False):
    detail = detail or {}
    keep_fix = status in FIX_STATUSES or (status in FIX_IF_ACTUAL_FAILS and actual_fails)
    remediation, unsafe = _remediation(env, check, resource, arn, detail, keep_fix, status)
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
        "actual_status": "FAIL" if actual_fails else None,
        "vacuous": vacuous,
        "breaks_tests": redact.mask_obj([dict(b) for b in breaks_tests], keep_emails=env.keep),
        "missing": list(missing),
        "depends_on_me": [],
    }


def _row_finding(env, row, status=None, detail=None, warnings=None):
    check = env.checks.get(row["check_id"])
    if check is None and warnings is not None:
        warnings.append(f"check {row['check_id']} missing from the catalog: no title, mappings or remediation")
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
        warnings.append(f"EVAL claim for {claim['check_id']} with invalid status {status!r}: stays NOT_VERIFIED")
        status = "NOT_VERIFIED"
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


def _valid_row(row):
    return (isinstance(row, dict) and all(isinstance(row.get(k), str) for k in ("check_id", "status", "resource_id"))
            and (row.get("region") is None or isinstance(row["region"], str)))


def _row_findings(env, rows, evals, warnings):
    findings, pending = [], list(evals)
    for row in rows:
        if not _valid_row(row):
            warnings.append("invalid row ignored in checks-result.json (check_id, status or text resource_id missing)")
            continue
        if row["status"] != "PENDING_CLAUDE":
            findings.append(_row_finding(env, row, warnings=warnings))
            continue
        matched = [c for c in pending if _eval_matches(row, c)]
        pending = [c for c in pending if c not in matched]
        if matched:
            findings += [_eval_finding(env, row, c, warnings) for c in matched]
            continue
        warnings.append(f"{row['check_id']} expects a Claude evaluation (EVAL) that did not arrive: stays NOT_VERIFIED")
        detail = {**(row.get("detail") or {}), "reason": "Claude evaluation pending"}
        findings.append(_row_finding(env, row, status="NOT_VERIFIED", detail=detail, warnings=warnings))
    warnings += [f"EVAL claim for {c.get('check_id')} without a PENDING_CLAUDE row to resolve" for c in pending]
    return findings


def _claim_severity(check, claim, kind):
    if kind == "DOCUMENTED_ONLY":  # not verified: the check's own severity goes to evidence.catalog_severity
        return "low"
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
        warnings.append(f"{kind} claim with check_id {cid} missing from the catalog")
    if claim.get("breaks_tests"):
        kind = "DRIFT"
    resource, arn = _claim_resource(env, check, claim)
    evidence = {"actual": claim["actual"]} if claim.get("actual") else {}
    if kind == "DOCUMENTED_ONLY":
        evidence = {**evidence, "catalog_severity": check["severity"] if check else None, "note": "not verified"}
    return _finding(env, check, status=kind, severity=_claim_severity(check, claim, kind), resource=resource,
                    arn=arn, evidence=evidence, title=CLAIM_TITLES[kind], check_id=cid,
                    vault_claim=claim.get("vault_claim"), vault_note=claim.get("vault_note"),
                    evaluated_by="vault" if kind in VAULT_STATEMENTS else "claude",
                    breaks_tests=claim.get("breaks_tests") or [], actual_fails=claim.get("actual_status") == "FAIL")


def _claim_findings(env, claims, warnings):
    findings = []
    for claim in claims:
        if claim.get("kind") in CLAIM_KINDS:
            findings.append(_claim_finding(env, claim, warnings))
        elif claim.get("kind") != "EVAL":
            warnings.append(f"claim with unknown kind {claim.get('kind')!r}: ignored")
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
    for sensitive in (vault_index or {}).get("sensitive_files") or []:
        path = redact.mask_secrets(sensitive["path"])
        resource = {"type": "vault_note", "id": path, "region": None, "name": path}
        findings.append(_finding(
            env, None, status="FAIL", severity="critical", resource=resource, title=SENSITIVE_TITLE,
            evidence={"path": path, "detection": "file name"}, vault_note=path))
        findings[-1]["remediation"] = json.loads(json.dumps(SENSITIVE_REMEDIATION))
        if TEMPLATE_NAME.search(path):
            findings[-1]["remediation"]["steps"].append(TEMPLATE_HINT)
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
        status = COVERAGE_STATUS.get(f["status"], f["status"])
        if status not in COVERAGE_RANK:
            continue
        for key, seen in worst.items():
            for mapping in f["mappings"][key]:
                current = seen.get(mapping["id"])
                if current is None or COVERAGE_RANK[status] > COVERAGE_RANK[current]:
                    seen[mapping["id"]] = status
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


def _ref_names(value):
    """A scope reference as the names a finding may carry: the text itself and, for an ARN, its last segment."""
    names = {value}
    if value.startswith("arn:"):
        names.add(value.rsplit(":", 1)[-1].rsplit("/", 1)[-1])
    return names


def _read_scope(run_dir):
    """scope.json as an object, or None when there is none; a file of another shape is an error (not a traceback)."""
    path = Path(run_dir) / "scope.json"
    scope = _read_json(path, None)
    if scope is not None and (not isinstance(scope, dict) or not isinstance(scope.get("resources") or [], list)):
        raise ValueError(f"{path}: scope.json with an invalid shape (an object with a 'resources' list was expected)")
    return scope


def _unverified_scope(scope, findings):
    """Scoped components (scope.json) without any finding other than N/A: nothing says anything about them."""
    resources = [r for r in (scope or {}).get("resources") or [] if isinstance(r, dict) and isinstance(r.get("id"), str)]
    covered = set()
    for f in findings:
        if f["status"] != "N/A":
            covered |= {v for v in (f["resource"]["id"], f["resource"]["name"]) if v}
    return [{"type": r.get("type"), "id": r["id"], "region": r.get("region"),
             "reason": "no AWS result or vault claim for this component"}
            for r in resources if not _ref_names(r["id"]) & covered]


def _run_state(result, aws):
    """What the collection could not do: (reasons the run is incomplete)."""
    reasons = []
    if aws and result.get("partial"):
        reasons.append("the collection ended up partial")
    blocked = (aws or {}).get("blocked_regions")
    if isinstance(blocked, list) and blocked:
        reasons.append(f"{len(blocked)} region(s) blocked by an SCP")
    if aws and any(str(w).startswith("incomplete inventory") for w in result.get("warnings") or []):
        reasons.append("the inventory is incomplete")
    return reasons


def _opens_a_failure(f):
    """A FAIL, anything whose real state (claim actual_status) fails, or a critical/high gap the vault admits."""
    return (f["status"] == "FAIL" or f.get("actual_status") == "FAIL"
            or (f["status"] == "DOCUMENTED_GAP" and f["severity"] in ("critical", "high")))


def _failure_reasons(failing):
    gaps = [f for f in failing if f["status"] == "DOCUMENTED_GAP" and f.get("actual_status") != "FAIL"]
    reasons = []
    if len(failing) > len(gaps):
        reasons.append(f"{len(failing) - len(gaps)} failing finding(s)")
    if gaps:
        reasons.append(f"{len(gaps)} documented gap(s) of critical or high severity (stated by the vault, not verified)")
    return reasons


def _basis(aws_used, vault_used):
    """What the verdict rests on. Without credentials the vault is the only possible basis."""
    if not aws_used:
        return "vault"
    return "aws+vault" if vault_used else "aws"


def _names(entries, limit=5):
    shown = [f"{e.get('type') or 'component'} {e['id']}" for e in entries[:limit]]
    return ", ".join(shown) + (f" and {len(entries) - limit} more" if len(entries) > limit else "")


def _vault_reasons(findings, unverified_scope):
    """Why a vault-only run cannot be called optimal (empty list = it can)."""
    reasons = []
    gaps = sum(1 for f in findings if f["status"] == "DOCUMENTED_GAP")
    if gaps:
        reasons.append(f"{gaps} gap(s) documented in the vault: what is documented admits something is missing")
    if not any(f["status"] == "DOCUMENTED_ONLY" for f in findings):
        reasons.append("the vault documents no control in scope")
    if unverified_scope:
        reasons.append(f"the vault does not document {len(unverified_scope)} component(s) in scope: {_names(unverified_scope)}")
    open_items = sum(1 for f in findings if f["status"] in ("DRIFT", "UNDOCUMENTED", "NOT_VERIFIED"))
    if open_items:
        reasons.append(f"{open_items} unresolved finding(s) (DRIFT, UNDOCUMENTED or NOT_VERIFIED)")
    return reasons


def _verdict(findings, basis, incomplete, counts, unverified_scope=()):
    """(verdict, one-line English text, reasons). NOT_OPTIMAL > NOT_VERIFIABLE > OPTIMAL. The text always names the basis."""
    where = BASIS_TEXT[basis]
    failing = [f for f in findings if _opens_a_failure(f)]
    severe = sum(1 for f in failing if f["severity"] in ("critical", "high"))
    if failing:
        text = f"Not optimal {where}: {len(failing)} open finding(s), {severe} of critical or high severity."
        return "NOT_OPTIMAL", text, _failure_reasons(failing)
    if basis == "vault":
        reasons = _vault_reasons(findings, list(unverified_scope))
        if reasons:
            return "NOT_VERIFIABLE", f"Not verifiable {where}: " + "; ".join(reasons) + ".", reasons
        documented = sum(1 for f in findings if f["status"] == "DOCUMENTED_ONLY")
        return "OPTIMAL", (f"Optimal {where}: {documented} documented control(s) in scope, with no gaps or undocumented components. "
                          "What is documented is not what is verified: this is not an audit opinion."), []
    reasons = []
    if not any(f["status"] in ("PASS", "FAIL") for f in findings):
        reasons.append("no check was evaluated (there are no PASS or FAIL results)")
    reasons += incomplete
    unconfirmed = sum(1 for f in findings if f["status"] == "DRIFT" and f.get("breaks_tests") and f.get("actual_status") != "FAIL")
    if unconfirmed:  # a recommendation that would break tests, with no real state checked: nothing says the account is fine
        reasons.append(f"{unconfirmed} difference(s) with a recommendation that would break Drata or Vanta tests, with no real state verified")
    if counts["total"]:
        reasons.append(f"{counts['total']} item(s) not verified in AWS")
    if reasons:
        return "NOT_VERIFIABLE", f"Not verifiable {where}: " + "; ".join(reasons) + ".", reasons
    differences = sum(1 for f in findings if f["status"] in ("DRIFT", "UNDOCUMENTED"))
    extra = (f" There are {differences} difference(s) between the vault and AWS (DRIFT / UNDOCUMENTED) with no confirmed failure: review them."
             if differences else "")
    return "OPTIMAL", (f"Optimal {where} in the evaluated scope: complete run with read-only AWS credentials, "
                      "with no failures or unverified items." + extra + " This is not an audit opinion."), []


def _summary(findings, aws_used=False, incomplete=(), unverified_scope=(), vault_used=False):
    failing = [f for f in findings if f["status"] == "FAIL"]
    drata = {t["test"] for f in failing for t in _tests(f["mappings"]) if t["tool"] == "drata"}
    vanta = {t["test"] for f in failing for t in _tests(f["mappings"]) if t["tool"] == "vanta"}
    by_status, by_severity = Counter(f["status"] for f in findings), Counter(f["severity"] for f in failing)
    counts = {"not_verified": by_status["NOT_VERIFIED"], "documented_only": by_status["DOCUMENTED_ONLY"],
              "documented_gap": by_status["DOCUMENTED_GAP"], "scope_without_claims": len(unverified_scope)}
    counts["total"] = sum(counts.values())
    basis = _basis(aws_used, vault_used)
    verdict, text, reasons = _verdict(findings, basis, list(incomplete), counts, unverified_scope)
    return {"verdict": verdict, "verdict_basis": basis, "verdict_text": text, "verdict_reasons": reasons, "aws_verified": bool(aws_used),
            "unverified": counts,
            "by_status": {s: by_status[s] for s in STATUS_ORDER},
            "by_severity_fail": {s: by_severity[s] for s in catalog.SEVERITIES},
            "drata_tests_failing": sorted(drata), "vanta_tests_failing": sorted(vanta),
            "not_verified": by_status["NOT_VERIFIED"]}


# ---------------------------------------------------------------- assemble and CLI

def _fix_digest(finding):
    rem = finding.get("remediation") if isinstance(finding.get("remediation"), dict) else {}
    parts = [rem.get("kind"), rem.get("risk"), rem.get("downtime"), rem.get("steps"), rem.get("commands"), rem.get("verify_after"),
             rem.get("notes")]
    return hashlib.sha256(json.dumps(parts, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")).hexdigest()[:16]


def findings_digest(document: dict) -> str:
    """Digest of the finding ids, check_ids, resource ids, statuses and fixes (kind, risk, steps, commands, verify_after, notes)
    of a findings.json: binds verification.json to it, because the positional ids (F-0001...) shift when assemble runs again with
    different claims and a re-collected run can keep the ids while the statuses or the commands change."""
    keys = [[f.get("id"), f.get("check_id"), (f.get("resource") or {}).get("id"), f.get("status"), _fix_digest(f)]
            for f in document.get("findings", []) if isinstance(f, dict)]
    return hashlib.sha256(json.dumps(keys, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _vault_warnings(vault_index):
    if not vault_index:
        return []
    warnings = [UNTYPED_WARNING] if vault_index.get("kind") == "free" else []
    warnings += [f"broken link in {b['from']}: [[{b['target']}]]" for b in vault_index.get("broken_links") or []]
    warnings += [f"note truncated while indexing (too large, only the beginning was read): {p}" for p in vault_index.get("truncated_notes") or []
                 if isinstance(p, str)]
    warnings += [f"credential detected in the vault: {s['path']} ({s['pattern']})"
                 for s in vault_index.get("secrets_detected") or []]
    return warnings + [f"sensitive file in the vault (not opened): {s['path']}"
                       for s in vault_index.get("sensitive_files") or []]


def _run_warnings(result):
    """Warnings for an incomplete collection: a partial run (interrupted) and regions blocked by an SCP."""
    warnings = []
    if result.get("partial"):
        pending = result.get("pending_checks")
        names = ", ".join(sorted(str(c) for c in pending)) if isinstance(pending, list) and pending else None
        detail = f"checks not finished: {names}" if names else "some checks are not finished"
        warnings.append(f"PARTIAL result: the collection was interrupted ({detail}); what is missing is not verified: re-run collect.py")
    blocked = ((result.get("aws") or {}).get("blocked_regions"))
    if isinstance(blocked, list) and blocked:
        warnings.append(f"blocked by SCP in regions {', '.join(sorted(str(r) for r in blocked))}: their resources were not verified")
    return warnings


def _vault_mentions(vault_index, target):
    """True when some note of the index names the target (id, name or the last segment of an ARN) in its title, path, aliases, ids,
    key/values, links or headings."""
    needles = {n.lower() for n in _ref_names(target)}
    for note in vault_index.get("notes") or []:
        if not isinstance(note, dict):
            continue
        kv = note.get("kv") if isinstance(note.get("kv"), dict) else {}
        ids = [i.get("value") for i in note.get("aws_ids") or [] if isinstance(i, dict)]
        texts = [note.get("title"), note.get("path"), *(note.get("aliases") or []), *ids, *kv.keys(), *kv.values(),
                 *(note.get("links") or []), *(note.get("headings") or [])]
        if any(isinstance(t, str) and n in t.lower() for t in texts for n in needles):
            return True
    return False


def _notes(aws, vault_index, meta=None):
    notes = []
    if not aws:
        notes.append("No AWS credentials: only the vault findings are reported.")
    if not vault_index:
        notes.append("No vault: the documentation was not compared with AWS.")
    target = (meta or {}).get("target")
    if vault_index and (meta or {}).get("mode") == "resource" and isinstance(target, str) and target.strip() \
            and not _vault_mentions(vault_index, target):
        notes.append(f"The vault does not mention {target}: there is no documentation for this resource to compare it with, "
                     "what is reported comes from AWS only.")
    return notes


def _vault_used(vault_index, claims):
    """True when the vault contributed: an index, or any claim other than an EVAL (EVAL claims judge AWS data)."""
    return vault_index is not None or any(c.get("kind") != "EVAL" for c in claims)


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
    if not aws and vault_index is None and not claims:
        raise ValueError(NO_SOURCES)
    warnings = _run_warnings(result) + list(result.get("warnings") or []) + _vault_warnings(vault_index)

    rows = (result.get("results") or []) if aws else []
    findings = _row_findings(env, rows, [c for c in claims if c.get("kind") == "EVAL"], warnings)
    findings += _claim_findings(env, claims, warnings) + _secret_findings(env, vault_index)
    findings.sort(key=_sort_key)
    unverified = _unverified_scope(_read_scope(run_dir), findings)
    dependencies = _dependencies(findings)
    tests_by_resource = {d["resource_id"]: d["tests"] for d in dependencies}
    for number, finding in enumerate(findings, start=1):
        finding["id"] = f"F-{number:04d}"
        if finding.pop("_unsafe"):
            warnings.append(UNSAFE_WARNING.format(id=finding["id"]))
        finding["depends_on_me"] = list(tests_by_resource.get(finding["resource"]["id"], []))

    return {
        "meta": {"platform": redact.mask_obj(meta.get("platform"), keep_emails=env.keep), "mode": meta.get("mode"),
                 "target": redact.mask_obj(meta.get("target"), keep_emails=env.keep),
                 "generated_at": meta.get("generated_at") or datetime.now().astimezone().isoformat(timespec="seconds"),
                 "lang": meta.get("lang", "en"), "tool": meta.get("tool"), "catalog_checks": len(checks),
                 "vault": {"path": Path(vault_index.get("root") or "").name or None, "kind": vault_index.get("kind")} if vault_index else None,
                 "aws": redact.mask_obj({k: aws.get(k) for k in ("account_id", "identity_arn", "regions")},
                                        keep_emails=env.keep) if aws else None},
        "summary": _summary(findings, bool(aws), _run_state(result, aws), unverified, _vault_used(vault_index, claims)),
        "findings": findings,
        "unverified_scope": unverified,
        "dependencies": dependencies,
        "coverage": _coverage(findings, skill_dir),
        "warnings": redact.mask_obj(warnings, keep_emails=env.keep),
        "notes": redact.mask_obj(_notes(aws, vault_index, meta), keep_emails=env.keep),
    }


def _list_of_dicts(value, label):
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise ValueError(f"{label}: a list of objects was expected")
    return value


def _must_exist(path, what):
    if not Path(path).is_file():
        raise ValueError(f"{what} does not exist: {path}")


def _load_claims(path):
    _must_exist(path, "the claims file")
    claims = _list_of_dicts(_read_json(path, None), f"{path}")
    for claim in claims:
        problems = [
            not isinstance(claim.get("kind"), str),
            claim.get("check_id") is not None and not isinstance(claim["check_id"], str),
            claim.get("resource") is not None and not isinstance(claim["resource"], dict),
            isinstance(claim.get("resource"), dict) and any(
                claim["resource"].get(k) is not None and not isinstance(claim["resource"][k], str) for k in ("id", "region", "type")),
            claim.get("detail") is not None and not isinstance(claim["detail"], dict),
            not isinstance(claim.get("breaks_tests") or [], list)
            or not all(isinstance(b, dict) for b in claim.get("breaks_tests") or []),
        ]
        if any(problems):
            raise ValueError(f"{path}: claim with an invalid shape (kind, check_id, resource with text type, id and region, detail or breaks_tests)")
    return claims


def _load_index(path):
    _must_exist(path, "the vault index")
    index = _read_json(path, None)
    if not isinstance(index, dict) or not isinstance(index.get("kind"), str):
        raise ValueError(f"{path}: not a vault-index.json ('kind' missing)")
    for key, required in (("broken_links", ("from", "target")), ("secrets_detected", ("path", "pattern")),
                          ("sensitive_files", ("path",))):
        items = _list_of_dicts(index.get(key) or [], f"{path} {key}")
        if any(field not in item for item in items for field in required):
            raise ValueError(f"{path}: {key} with an invalid shape (missing {', '.join(required)})")
    return index


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Builds findings.json from collect, the vault and the claims")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--vault-index")
    parser.add_argument("--vault-claims")
    parser.add_argument("--platform", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--target")
    parser.add_argument("--tool", choices=TOOLS, help="compliance tool the HTML preselects in the filter (both stay visible)")
    parser.add_argument("--lang", default="en", choices=("en",), help="reserved: the report is English only")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(f"the run directory does not exist: {run_dir}", file=sys.stderr)
        return 2
    meta = {"platform": args.platform, "mode": args.mode, "target": args.target, "lang": args.lang, "tool": args.tool}
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
    print(f"{len(findings['findings'])} findings ("
          + ", ".join(f"{s}: {n}" for s, n in counts.items() if n) + f"). Detail in: {run_dir / 'findings.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
