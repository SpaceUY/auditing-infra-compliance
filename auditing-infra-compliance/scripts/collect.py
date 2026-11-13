"""Read-only inventory and check-collection engine.

Writes <out>/checks-result.json, <out>/inventory.json and <out>/raw/<check_id>/<call>-<region>[-<n>].json
and prints a bounded summary; one progress line per finished check goes to stderr ("[n/total] CHECK-ID", --quiet
silences it). inventory.json is written as soon as the inventory is known and checks-result.json is refreshed while the
run progresses, flagged "partial": true with "pending_checks" until the end, so a killed run (Ctrl-C/SIGTERM exit 130, or
an exception) keeps what it collected. Identical AWS calls (service, operation, args, region, query) run once per run.
A malformed scope (unknown mode or domain, malformed resources, bad regions) exits 2 with a message before any AWS call. A well-formed
scope that no catalog check covers (types such as sns_topic or subnet) exits 0 with no results and the warning "ningún chequeo del catálogo
aplica a: <types>"; its components then come out as unverified scope in the assembled report.
Only (service, operation) pairs of the loaded catalog, the inventory spec and the preflight are ever executed.
A failing region does not collapse a check: the healthy regions are evaluated and the failing ones get their own
NO_VERIFICADO row ("bloqueado por SCP", without `missing`, when AccessDenied names a service control policy). Global calls run in us-east-1 and report that region.
Everything written or printed goes through redact (keys, secrets, emails); evaluation uses the unmasked data in
memory. Resource identifiers (row resource_id; inventory id/arn/name) only lose keys/secrets, never emails: they
end up in remediation commands. The values of the VantaOwner tag stay unmasked in inventory.json (owner emails, INV-001).

Check conventions (catalog): a jmespath check's `offenders` expression is passed as --query and must
project {resource_id, detail}; resource_id may be omitted when the call has for_each (the for_each
value is used). A call's for_each is {"from": <earlier call name> | "__inventory__", "path", "arg"}:
"__inventory__" iterates the check's evaluated inventory items (resource_types, narrowed to scope in
feature/resource mode). A call may list "ok_errors" (error codes): if its stderr contains one, a
python evaluator receives {"__error__": <code>} as that call's data instead of the check becoming
NO_VERIFICADO (never for ACCESS_DENIED / NO_CREDENTIALS, never for jmespath).
A for_each call may also declare "item_errors": "evaluator" (python evaluators only): when one expanded item call fails
(any error kind, including ACCESS_DENIED, except NO_CREDENTIALS) the evaluator gets that item's data as
{"__error__": <ok_errors code or error kind, e.g. "ACCESS_DENIED">} and the check no longer collapses to NO_VERIFICADO.
No vacuous PASS: a check whose regions are unknown or empty (describe-regions failed, every scoped region blocked) is
NO_VERIFICADO with the reason, and a resource-scope check gets a NO_VERIFICADO row for every (type, region) whose inventory
listing failed, next to the PASS/FAIL rows of the regions that were listed. N/A only when the listing worked and found nothing.
When NET-001..004 fail on a security group, CMP-006 is also evaluated for the instances attached to it (the conflict rule
CR-003 needs it), even in feature/resource scope; those rows carry detail.context_for.
A check that declares `params.inventory_types` depends on those inventory types (`account_context_for` is only a
feature-mode selection key and never blocks evaluation): if the listing of any of them failed, the check is NO_VERIFICADO (missing "inventory:<type>") instead of being evaluated
on an incomplete inventory. Python evaluators also see `responses["__inventory_errors__"]` (set of broken types).
An evaluator entry {"resource_id", "region", "detail", "unverified": True} becomes a NO_VERIFICADO row for that region.
The "dns" evaluator is run by the engine: params {rrtype, name_template with {domain}, must_match regex,
domains_from (inventory type, default ses_identity)}; every domain-like inventory id of that type must
have a record of rrtype at the templated name matching must_match.
"""

import argparse
import dataclasses
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import aws_runner
import catalog
import evaluators
import inventory
import paths
import redact

SKILL_DIR = Path(__file__).resolve().parent.parent
DEFAULT_REGION = inventory.DEFAULT_REGION
INVENTORY_SOURCE = "__inventory__"
WORKERS = inventory.WORKERS
SEVERITY_ORDER = {s: i for i, s in enumerate(catalog.SEVERITIES)}
ADMIN_POLICY = "AdministratorAccess"
OWNER_TAG = "VantaOwner"
ENABLED_REGIONS_FILTER = "Name=opt-in-status,Values=opt-in-not-required,opted-in"
REGIONS_REASON = "no se pudieron listar las regiones"
NO_REGIONS_REASON = "sin regiones en el alcance"
REGIONS_UNKNOWN = "REGIONS_UNKNOWN"  # pseudo error kind of the inventory when the enabled regions are unknown
ALL_REGIONS = "*"
SG_CHECKS = frozenset({"NET-001", "NET-002", "NET-003", "NET-004"})  # their FAIL rows list the attached instances
SSM_CHECK = "CMP-006"  # evidence the conflict rule CR-003 reads for those instances
_REGION_NAME = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d+$")
SCP_REASON = "bloqueado por SCP"
_SCP = re.compile(r"service control polic", re.IGNORECASE)
CHECKPOINT_SECONDS = 15
NEVER_CACHED = frozenset({("iam", "generate-credential-report")})  # polled until the report is ready
CACHEABLE_FAILURES = frozenset({"ACCESS_DENIED", "NOT_ENABLED"})  # deterministic; throttling and timeouts may pass on retry
PREFLIGHT_OPERATIONS = frozenset({("sts", "get-caller-identity"), ("ec2", "describe-regions"),
                                  ("iam", "list-attached-user-policies"), ("iam", "list-attached-role-policies")})


@dataclass
class Ctx:
    runner: Callable
    sleep: Callable
    which: Callable
    out: Path
    profile: str | None = None
    enabled_regions: list = field(default_factory=list)
    regions: list = field(default_factory=list)
    inventory: list = field(default_factory=list)
    inventory_errors: dict = field(default_factory=dict)  # type -> {(region, error kind)}; region "*" = every other region
    specs: dict = field(default_factory=dict)  # inventory spec (type -> spec)
    regions_error: str | None = None  # error kind when describe-regions failed (the enabled regions are unknown)
    regions_guessed: bool = False  # scope.regions is "auto" and the enabled regions are unknown: only us-east-1 was listed
    scope_entries: list | None = None  # [(type, ref)] in feature/resource mode, None in full mode
    scope_resources: list = field(default_factory=list)  # the scope's resources as written ({type, id, region})
    allowed: frozenset | None = None  # {(service, operation)} the run may execute; None = unrestricted (tests only)
    blocked_regions: list = field(default_factory=list)  # regions whose inventory is denied by an SCP
    cache: dict = field(default_factory=dict)  # call key -> _Slot
    cache_lock: threading.Lock = field(default_factory=threading.Lock)
    cancelled: threading.Event = field(default_factory=threading.Event)


class _Slot:
    """One memoized call: the lock serializes identical in-flight calls so only the first one reaches AWS."""

    def __init__(self):
        self.lock = threading.Lock()
        self.result = None


def _oneline(text, limit):
    return " ".join(str(text).split())[:limit]


def _masked_line(text, limit):
    """Mask first, truncate after: a secret cut in the middle would otherwise survive as an unmatched prefix."""
    return _oneline(redact.mask(str(text or "")), limit)


def allowed_operations(checks, specs):
    """Closed allowlist: every (service, operation) of the catalog calls and the inventory spec, plus the preflight."""
    pairs = {(c["service"], c["operation"]) for check in checks for c in check["verify"]["calls"]}
    pairs |= {(s["service"], s["operation"]) for s in specs.values()} | PREFLIGHT_OPERATIONS
    return frozenset(pairs & catalog.REVIEWED_OPERATIONS)  # a call nobody reviewed (see catalog.REVIEWED_OPERATIONS) never runs


def _refused(message):
    return aws_runner.CallResult(False, None, "ERROR", message, ())


def _run_aws(ctx, service, operation, args, region, query):
    try:
        return aws_runner.run_aws(service, operation, args, region=region, profile=ctx.profile,
                                  query=query, runner=ctx.runner, sleep=ctx.sleep, cancelled=ctx.cancelled.is_set)
    except aws_runner.ReadOnlyViolation as exc:
        return _refused(str(exc))


def _aws(ctx, service, operation, args, region, query=None):
    if ctx.allowed is not None and (service, operation) not in ctx.allowed:
        return _refused(f"operación fuera del catálogo revisado, no se ejecuta: {service} {operation}")
    if ctx.cancelled.is_set():
        return _refused("ejecución cancelada")
    if (service, operation) in NEVER_CACHED:
        return _run_aws(ctx, service, operation, args, region, query)
    key = repr((service, operation, tuple(args), region, query))
    with ctx.cache_lock:
        slot = ctx.cache.setdefault(key, _Slot())
    with slot.lock:
        if slot.result is None:
            res = _run_aws(ctx, service, operation, args, region, query)
            if res.ok or res.error_kind in CACHEABLE_FAILURES:
                slot.result = res
            return res
        return slot.result


def _is_scp(res):
    return res.error_kind == "ACCESS_DENIED" and bool(_SCP.search(res.error_message or ""))


def _row(check, status, resource_id, region, detail=None, missing=None, vacuous=False):
    return {"check_id": check["id"], "status": status, "resource_id": resource_id, "region": region,
            "detail": detail or {}, "missing": missing or [], "vacuous": vacuous}


# ---------------------------------------------------------------- inventory

def _inventory_warnings(ctx, errors):
    grouped = {}
    for type_, region, kind in errors:
        ctx.inventory_errors.setdefault(type_, set()).add((region, kind))
        grouped.setdefault((type_, kind), []).append(region)
    return [f"inventario incompleto: {t} {k} en {', '.join(sorted(rs))}" for (t, k), rs in sorted(grouped.items())]


def _enabled_regions(ctx, warnings):
    """(enabled region names, known). When the listing fails nothing is guessed: ([], False) and ctx.regions_error is set."""
    res = _aws(ctx, "ec2", "describe-regions", ["--filters", ENABLED_REGIONS_FILTER], DEFAULT_REGION)
    if res.ok:
        return sorted(paths.extract(res.data, "Regions[].RegionName")), True
    ctx.regions_error = res.error_kind
    warnings.append(f"no se pudieron listar las regiones habilitadas ({res.error_kind}): los chequeos de todas las regiones "
                    "quedan sin verificar y solo se audita el alcance indicado")
    return [], False


def _regions_problem(wanted):
    """Why scope.regions is unusable (a message), or None. It is "auto" or a non-empty list of region names."""
    if wanted == "auto":
        return None
    if not isinstance(wanted, list):
        return ('scope.regions debe ser "auto" o una lista de regiones, por ejemplo ["us-east-1"]; '
                f"se recibió {_oneline(json.dumps(wanted, ensure_ascii=False), 60)}")
    if not wanted:
        return 'scope.regions está vacío: usar "auto" o al menos una región, por ejemplo ["us-east-1"]'
    bad = [w for w in wanted if not (isinstance(w, str) and _REGION_NAME.fullmatch(w))]
    if bad:
        return f"scope.regions tiene nombres que no son regiones de AWS: {_oneline(json.dumps(bad, ensure_ascii=False), 80)}"
    return None


MODES = ("full", "feature", "resource")


def _resource_problem(resources):
    if not isinstance(resources, list) or not resources:
        return 'scope.resources debe ser una lista no vacía de objetos {"type", "id"} en modo feature/resource'
    if not all(isinstance(r, dict) and all(isinstance(r.get(k), str) and r[k] for k in ("type", "id")) for r in resources):
        return 'cada elemento de scope.resources necesita "type" e "id" de texto'
    return None


def _scope_problem(scope, checks):
    """Why the scope is malformed (a message), or None. Checked before any AWS call. A well-formed scope that no catalog check covers
    (sns_topic, subnet...) is not malformed: it runs with no results and a warning."""
    if not isinstance(scope, dict):
        return "scope.json debe ser un objeto"
    if scope.get("mode") not in MODES:
        return f"scope.mode debe ser uno de {', '.join(MODES)}; se recibió {_oneline(json.dumps(scope.get('mode')), 40)}"
    domains, known = scope.get("domains"), sorted({c["domain"] for c in checks})
    if domains is not None and not (isinstance(domains, list) and all(isinstance(d, str) for d in domains)):
        return "scope.domains debe ser null o una lista de nombres de dominio"
    if unknown := [d for d in domains or [] if d not in known]:
        return f"scope.domains tiene dominios desconocidos: {_oneline(', '.join(unknown), 80)} (válidos: {', '.join(known)})"
    if scope["mode"] != "full" and (problem := _resource_problem(scope.get("resources"))):
        return problem
    return None


def _scope_failure(message):
    print(redact.mask(f"{message}. Corregir scope.json y reintentar."))
    return 2


# ---------------------------------------------------------------- calls

def _regional_calls(check):
    return [c for c in check["verify"]["calls"] if c.get("region", "global") == "each"]


def _regions_gap_row(ctx, check):
    """NO_VERIFICADO when a regional call has no region to run in, or when its regions are only a guess: with the enabled
    regions unknown (describe-regions failed, scope "auto") an account check never gets a PASS from us-east-1 alone."""
    regional = _regional_calls(check)
    if not regional:
        return None
    if ctx.regions_error is not None and (check["all_regions"] or (ctx.regions_guessed and check["scope"] == "account")):
        detail = {"reason": REGIONS_REASON, "error_kind": ctx.regions_error}
        missing = ["ec2:DescribeRegions"] if ctx.regions_error == "ACCESS_DENIED" else []
    elif any(not _call_regions(ctx, check, c) for c in regional):
        detail, missing = {"reason": NO_REGIONS_REASON}, []
    else:
        return None
    return _row(check, "NO_VERIFICADO", "account", None, detail, missing=missing)


def _call_regions(ctx, check, call):
    if call.get("region", "global") == "global":
        return [DEFAULT_REGION]
    return ctx.enabled_regions if check["all_regions"] else ctx.regions


def _matches(item, type_, ref):
    return item["type"] == type_ and bool(ref) and ref in (item["id"], item["arn"], item["name"])


def _scoped(ctx, items):
    if ctx.scope_entries is None:
        return items
    return [i for i in items if any(_matches(i, t, ref) for t, ref in ctx.scope_entries)]


def _items_for(ctx, check):
    return _scoped(ctx, [i for i in ctx.inventory if i["type"] in set(check["resource_types"])])


def _for_each_values(call, region, items, responses):
    source = call["for_each"]
    if source["from"] == INVENTORY_SOURCE:
        is_global = call.get("region", "global") == "global"
        pool = [i for i in items if is_global or i["region"] == region]
        return [v for item in pool for v in paths.extract(item, source["path"])]
    values = [v for r, data in responses.get(source["from"], []) if r == region for v in paths.extract(data, source["path"])]
    return list(dict.fromkeys(values))  # one call per distinct value: many alarms share a few SNS topics


def _args_for(call, value):
    base = list(call.get("args", []))
    if value is None:
        return base
    flag, text = call["for_each"]["arg"], str(value)
    return base + ([f"{flag}={text}"] if text.startswith("-") else [flag, text])


def _execute(ctx, call, region, args, query):
    return _aws(ctx, call["service"], call["operation"], args, region, query)


def _write_raw(directory, call_name, region, index, res):
    suffix = "" if index is None else f"-{index}"
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{call_name}-{region}{suffix}")
    payload = {"argv": list(res.argv), "ok": res.ok}
    if res.ok:
        payload["data"] = res.data
    else:
        payload.update(error_kind=res.error_kind, error_message=_masked_line(res.error_message, 300))
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{safe}.json").write_text(json.dumps(redact.mask_obj(payload), indent=2, ensure_ascii=False),
                                            encoding="utf-8")


def _ok_error(call, res, query):
    if query is not None or res.error_kind in ("ACCESS_DENIED", "NO_CREDENTIALS"):
        return None
    return next((c for c in call.get("ok_errors") or [] if c in (res.error_message or "")), None)


def _item_error(call, res, query):
    """Error code handed to the evaluator as the item's data: an ok_errors match, or (call declares
    "item_errors": "evaluator", for_each calls only, never jmespath) any failure except NO_CREDENTIALS, as its error kind."""
    code = _ok_error(call, res, query)
    if code or query is not None or "for_each" not in call:
        return code
    if call.get("item_errors") == "evaluator" and res.error_kind != "NO_CREDENTIALS":
        return res.error_kind
    return None


def _failure(name, region, value, res):
    failure = {"call": name, "region": region, "error_kind": res.error_kind,
               "error_message": _masked_line(res.error_message, 300)}
    if value is not None:
        failure["item"] = _oneline(value, 120)
    if _is_scp(res):
        failure["reason"] = SCP_REASON  # decided on the full message: the phrase may sit past the truncation point
    return failure


def _run_calls(ctx, check, items):
    verify = check["verify"]
    query = verify.get("offenders") if verify["evaluator"] == "jmespath" else None
    collected = {"responses": {}, "values": {}, "failures": []}
    for call in verify["calls"]:
        name = call["name"]
        collected["responses"][name], collected["values"][name] = [], []
        for region in _call_regions(ctx, check, call):
            if "for_each" in call:
                values = _for_each_values(call, region, items, collected["responses"])
            else:
                values = [None]
            for index, value in enumerate(values):
                res = _execute(ctx, call, region, _args_for(call, value), query)
                if ctx.cancelled.is_set():  # the run was cancelled: no raw file and no evaluation of partial data
                    return collected
                _write_raw(ctx.out / "raw" / check["id"], name, region, index if "for_each" in call else None, res)
                if res.ok:
                    collected["responses"][name].append((region, res.data))
                    collected["values"][name].append(value)
                elif code := _item_error(call, res, query):
                    collected["responses"][name].append((region, {"__error__": code}))
                    collected["values"][name].append(value)
                else:
                    collected["failures"].append(_failure(name, region, value, res))
    return collected


# ---------------------------------------------------------------- evaluation

def _jmespath_offenders(collected, call_name):
    offenders = []
    for (region, data), value in zip(collected["responses"][call_name], collected["values"][call_name]):
        if not data:
            continue
        for element in data if isinstance(data, list) else [data]:
            if isinstance(element, dict):
                resource_id, detail = element.get("resource_id") or value or "account", element.get("detail") or {}
            else:
                resource_id, detail = element, {}
            offenders.append({"resource_id": str(resource_id), "region": region, "detail": detail})
    return offenders


def _python_offenders(ctx, check, name, collected, items):
    fn = evaluators.EVALUATORS.get(name)
    if fn is None:
        raise LookupError(f"evaluador python '{name}' no registrado")
    responses = {**collected["responses"], "__for_each__": collected["values"], "__inventory__": items,
                 "__inventory_errors__": set(ctx.inventory_errors)}
    return [{"resource_id": str(o["resource_id"]), "region": o.get("region"), "detail": o.get("detail") or {},
             **{flag: True for flag in ("not_applicable", "unverified") if o.get(flag)}}
            for o in fn(responses, check["verify"].get("params") or {})]


def _unverified(check, failures, detail=None):
    denied = any(f["error_kind"] == "ACCESS_DENIED" and f.get("reason") != SCP_REASON for f in failures)
    regions = sorted({f["region"] for f in failures})
    detail = detail or {"failed_calls": failures[:20]}
    if failures and all(f.get("reason") == SCP_REASON for f in failures):
        detail = {"reason": SCP_REASON, **detail}  # adding IAM permissions will not help
    return _row(check, "NO_VERIFICADO", "account", regions[0] if len(regions) == 1 else None, detail,
                missing=list(check["verify"]["needs"]) if denied else [])


def _call_region_set(ctx, check):
    return {r for call in check["verify"]["calls"] for r in _call_regions(ctx, check, call)}


def _without_regions(collected, regions):
    """The collected calls minus the answers of `regions` (an evaluator must not conclude from half the data of a region)."""
    keep = {name: [i for i, (region, _) in enumerate(answers) if region not in regions]
            for name, answers in collected["responses"].items()}
    return {"responses": {n: [a[i] for i in keep[n]] for n, a in collected["responses"].items()},
            "values": {n: [v[i] for i in keep[n]] for n, v in collected["values"].items()},
            "failures": collected["failures"]}


class _Unverifiable(Exception):
    """An evaluator could not decide; args[0] is the NO_VERIFICADO detail."""


def _dns_source(check):
    return (check["verify"].get("params") or {}).get("domains_from", "ses_identity")


def _dns_items(ctx, check):
    return _scoped(ctx, [i for i in ctx.inventory if i["type"] == _dns_source(check)
                         and "." in i["id"] and "@" not in i["id"]])


def _dns_offenders(ctx, check, domains):
    params = check["verify"]["params"]
    rrtype = params["rrtype"]
    names = {d["id"]: params["name_template"].format(domain=d["id"]) for d in domains}
    bad = [n for n in (rrtype, *names.values()) if n.startswith(("-", "+", "@")) or any(c.isspace() for c in n)]
    if bad:
        raise _Unverifiable({"reason": "nombre DNS inválido", "names": [_oneline(n, 80) for n in bad[:5]]})
    offenders, failed = [], []
    for item in domains:
        res = aws_runner.run_dns(names[item["id"]], rrtype, runner=ctx.runner, which=ctx.which)
        if not res.ok:
            failed.append({"domain": item["id"], "error": _oneline(res.error_message, 200)})
        elif not any(re.search(params["must_match"], line) for line in res.data):
            offenders.append({"resource_id": item["id"], "region": item["region"],
                              "detail": {"record": names[item["id"]], "found": res.data[:10]}})
    if failed:
        raise _Unverifiable({"reason": "consulta DNS fallida", "failed": failed[:20]})
    return offenders


def _vacuous_row(check):
    return _row(check, "N/A", "account", None, {"reason": "sin recursos en el alcance"}, vacuous=True)


def _gap_in_scope(ctx, type_, region):
    """In feature/resource mode only the regions of the scoped resources of that type matter (global types: any region)."""
    if ctx.scope_entries is None:
        return True
    anywhere = region == ALL_REGIONS or ctx.specs.get(type_, {}).get("region") == "global"
    return any(r.get("type") == type_ and (anywhere or r.get("region") in (None, region)) for r in ctx.scope_resources)


def _inventory_gap_rows(ctx, check, types):
    """One NO_VERIFICADO row per (type, region) whose listing failed: the items of that region are unknown, so the PASS rows
    of the other regions must not be read as covering the whole account."""
    rows = []
    for type_ in sorted(types):
        for region, kind in sorted(ctx.inventory_errors.get(type_, ()), key=lambda e: (e[0], e[1])):
            if not _gap_in_scope(ctx, type_, region):
                continue
            if kind == REGIONS_UNKNOWN:
                detail = {"reason": REGIONS_REASON, "type": type_, "error_kind": ctx.regions_error}
                missing = ["ec2:DescribeRegions"] if ctx.regions_error == "ACCESS_DENIED" else []
            else:
                detail, missing = {"reason": "inventario incompleto", "type": type_, "error_kind": kind}, [f"inventory:{type_}"]
            rows.append(_row(check, "NO_VERIFICADO", "account", None if region == ALL_REGIONS else region, detail, missing=missing))
    return rows


def _inventory_dependencies(check):
    params = check["verify"].get("params") or {}
    return list(params.get("inventory_types") or [])


def _broken_dependencies(ctx, check):
    return sorted({t for t in _inventory_dependencies(check) if t in ctx.inventory_errors})


def _run_check(ctx, check):
    try:
        return _check_rows(ctx, check)
    except Exception as exc:  # one broken check must not lose the whole run
        detail = {"reason": "error interno del motor", "error": _oneline(f"{type(exc).__name__}: {exc}", 300)}
        return [_row(check, "NO_VERIFICADO", "account", None, detail)]


def _check_rows(ctx, check):
    gap = _regions_gap_row(ctx, check)
    if gap:
        return [gap]
    broken = _broken_dependencies(ctx, check)
    if broken:
        return [_row(check, "NO_VERIFICADO", "account", None, {"reason": "inventario no disponible", "types": broken},
                     missing=[f"inventory:{t}" for t in broken])]
    kind = check["verify"]["evaluator"].partition(":")[0]
    types = [_dns_source(check)] if kind == "dns" else check["resource_types"] if check["scope"] == "resource" else []
    gaps = _inventory_gap_rows(ctx, check, types)
    rows = _evaluated_rows(ctx, check)
    if gaps:  # a "nothing applies" N/A would claim the unlisted regions are empty
        rows = [r for r in rows if not (r["status"] == "N/A" and r["vacuous"])]
    return gaps + rows


def _evaluated_rows(ctx, check):
    kind, _, name = check["verify"]["evaluator"].partition(":")
    is_resource = check["scope"] == "resource"
    items = _dns_items(ctx, check) if kind == "dns" else _items_for(ctx, check)
    if (is_resource or kind == "dns") and not items:
        return [_vacuous_row(check)]
    collected = _run_calls(ctx, check, items)
    failures = collected["failures"]
    blocking = [f for f in failures if f["error_kind"] != "NOT_ENABLED" or check["not_enabled_means"] != "fail"]
    blocked = {f["region"] for f in blocking}
    if blocking and blocked >= _call_region_set(ctx, check):
        return [_unverified(check, blocking)]  # nothing could be verified: one row, as a whole-check failure
    rows = [_unverified(check, [f for f in blocking if f["region"] == region]) for region in sorted(blocked)]
    collected = _without_regions(collected, blocked)
    rows += [_row(check, "FAIL", "account", region, {"reason": "servicio no habilitado", "call": call})
             for region, call in sorted({(f["region"], f["call"]) for f in failures if f["region"] not in blocked})]
    if kind == "claude":
        return rows + [_row(check, "PENDING_CLAUDE", "account", None,
                            {"evaluator": kind, "calls": [c["name"] for c in check["verify"]["calls"]]})]
    try:
        if kind == "jmespath":
            offenders = _jmespath_offenders(collected, check["verify"]["calls"][0]["name"])
        elif kind == "dns":
            offenders = _dns_offenders(ctx, check, items)
        else:
            offenders = _python_offenders(ctx, check, name, collected,
                                          [i for i in ctx.inventory if i["region"] not in blocked])
    except _Unverifiable as exc:
        return rows + [_unverified(check, [], exc.args[0])]
    except Exception as exc:  # evaluator code is third-party to the engine
        detail = {"reason": "error del evaluador", "error": _oneline(f"{type(exc).__name__}: {exc}", 300)}
        return rows + [_unverified(check, [], detail)]
    offenders = [o for o in offenders if o["region"] not in blocked]  # that region already has its NO_VERIFICADO row
    if is_resource and ctx.scope_entries is not None:
        allowed = {(x, i["region"]) for i in items for x in _ids(i)}
        # an account-level unverified entry is about the check, not about a resource: it is never scoped out
        offenders = [o for o in offenders if _in_scope(o, allowed) or (o.get("unverified") and o["resource_id"] == "account")]
    unverified = [o for o in offenders if o.get("unverified")]
    # R20: not applicable resources get no FAIL and no PASS row; unverified ones get no PASS either
    skipped = {(o["resource_id"], o["region"]) for o in offenders if o.get("not_applicable") or o.get("unverified")}
    offenders = [o for o in offenders if not o.get("not_applicable") and not o.get("unverified")]
    rows += [_row(check, "NO_VERIFICADO", o["resource_id"], o["region"], o["detail"],
                  missing=list(check["verify"]["needs"]) if o["detail"].get("error_code") == "ACCESS_DENIED" else [])
             for o in unverified]
    rows += [_row(check, "FAIL", o["resource_id"], o["region"], o["detail"]) for o in offenders]
    rows += _pass_rows(check, items, offenders, skipped, {f["region"] for f in failures}, bool(rows))
    if is_resource and not rows:  # R23: every in-scope item was not applicable
        return [_row(check, "N/A", "account", None, {"reason": "ningún recurso aplica"}, vacuous=True)]
    return rows


def _ids(item):
    return [x for x in (item["id"], item["arn"], item["name"]) if x]


def _in_scope(offender, allowed):
    """Keyed on (resource_id, region); an offender without region matches by id alone."""
    if offender["region"] is None:
        return any(offender["resource_id"] == rid for rid, _ in allowed)
    return (offender["resource_id"], offender["region"]) in allowed


def _pass_rows(check, items, offenders, skipped, failed_regions, any_fail):
    if check["scope"] == "account":
        return [] if any_fail else [_row(check, "PASS", "account", None)]
    bad = {(o["resource_id"], o["region"]) for o in offenders} | skipped
    return [_row(check, "PASS", i["id"], i["region"]) for i in items
            if i["region"] not in failed_regions
            and not any((x, i["region"]) in bad or (x, None) in bad for x in _ids(i))]


def _attached_instances(rows):
    """{(instance id, region): {NET check ids}} for the failing security groups (their detail.attachments)."""
    found = {}
    for row in rows:
        attachments = row["detail"].get("attachments") if row["status"] == "FAIL" and row["check_id"] in SG_CHECKS else None
        for attachment in attachments if isinstance(attachments, list) else []:
            instance = attachment.get("instance_id") if isinstance(attachment, dict) else None
            if isinstance(instance, str) and instance:
                found.setdefault((instance, row["region"]), set()).add(row["check_id"])
    return found


def _evidence_rows(ctx, checks, selected, rows, warnings):
    """CMP-006 for the instances attached to a failing security group: the conflict rule CR-003 needs to know whether closing
    SSH/RDP leaves them without Systems Manager. In feature/resource scope CMP-006 would not run for them otherwise.
    Returns the rows with the CMP-006 rows replaced by the evaluation of the scope plus those instances."""
    wanted = _attached_instances(rows)
    check = next((c for c in checks if c["id"] == SSM_CHECK), None)
    in_run = any(c["id"] == SSM_CHECK for c in selected)
    if not wanted or check is None or (in_run and ctx.scope_entries is None):  # full mode: every instance was evaluated
        return rows
    known = {(i["id"], i["region"]) for i in ctx.inventory if i["type"] == "ec2_instance"}
    warnings += [f"instancia adjunta a un security group sin coincidencia en el inventario, no se evalúa {SSM_CHECK}: {i}"
                 for i, region in sorted(wanted) if (i, region) not in known]
    found = {i: sorted(ids) for (i, region), ids in sorted(wanted.items()) if (i, region) in known}
    if not found:
        return rows
    existing = list(ctx.scope_entries or [])
    new = _run_check(dataclasses.replace(ctx, scope_entries=existing + [("ec2_instance", i) for i in found]), check)
    by_id = {i["id"]: i for i in ctx.inventory if i["type"] == "ec2_instance"}
    for row in new:  # the instances nobody asked about (by id, name or ARN) are there because of the security group
        item = by_id.get(row["resource_id"])
        if row["resource_id"] in found and not (item and any(_matches(item, t, ref) for t, ref in existing)):
            row["detail"] = {**row["detail"], "context_for": found[row["resource_id"]]}
    return [r for r in rows if r["check_id"] != SSM_CHECK] + new


def _select(checks, scope):
    domains = scope.get("domains")
    pool = [c for c in checks if not domains or c["domain"] in domains]
    if scope["mode"] == "full":
        return pool
    types = {r["type"] for r in scope.get("resources") or []}
    return [c for c in pool
            if (c["scope"] == "resource" and types & set(c["resource_types"]))
            or (c["scope"] == "account" and types & set(c.get("account_context_for") or []))]


# ---------------------------------------------------------------- identity, summary, main

def _identity_partition(arn):
    """The partition of the caller's ARN (aws, aws-cn, aws-us-gov), or None when it cannot be read."""
    match = re.match(r"arn:(aws[a-z-]*):", arn or "")
    return match.group(1) if match else None


def _admin_warning(ctx, arn):
    match = re.match(r"arn:[^:]*:(?:iam|sts)::\d+:(user|assumed-role|role)/(.+)$", arn)
    if not match:
        return None
    kind, parts = match.group(1), match.group(2).split("/")
    if kind == "user":
        operation, flag, name = "list-attached-user-policies", "--user-name", parts[-1]
    else:
        operation, flag, name = "list-attached-role-policies", "--role-name", parts[0 if kind == "assumed-role" else -1]
    res = _aws(ctx, "iam", operation, [flag, name], DEFAULT_REGION)
    policies = paths.extract(res.data, "AttachedPolicies[].PolicyName") if res.ok else []
    if ADMIN_POLICY in policies:
        return (f"La identidad usada tiene {ADMIN_POLICY} adjunto; para auditar alcanza con un rol de "
                "solo lectura (SecurityAudit + ViewOnlyAccess)")
    return None


def _summary(rows, severities, warnings, aws, out, pending=()):
    counts = Counter(r["status"] for r in rows)
    lines = [f"Cuenta {aws['account_id']}: {len(rows)} resultados en {len(aws['regions'])} regiones"]
    if pending:
        lines.append(f"PARCIAL: la ejecución se interrumpió, {len(pending)} chequeos sin terminar")
    lines += [f"  {s}: {counts[s]}" for s in (*catalog.STATUSES, "PENDING_CLAUDE") if counts[s]]
    fails = sorted((r for r in rows if r["status"] == "FAIL"),
                   key=lambda r: (SEVERITY_ORDER[severities[r["check_id"]]], r["check_id"], r["resource_id"]))
    if fails:
        lines.append(f"Top FAIL por severidad ({min(10, len(fails))} de {len(fails)}):")
        lines += [f"  {severities[r['check_id']]:<8} {r['check_id']} {_oneline(r['resource_id'], 60)} ({r['region']})"
                  for r in fails[:10]]
    lines.append(f"NO_VERIFICADO: {counts['NO_VERIFICADO']}")
    lines += [f"AVISO: {_oneline(w, 150)}" for w in warnings[:5]]
    if len(warnings) > 5:
        lines.append(f"  (+{len(warnings) - 5} avisos más en checks-result.json)")
    lines.append(f"Detalle en: {out}")
    return "\n".join(lines)


def _dump(path, masked):
    """Atomic: a temp file in the same directory, then os.replace, so a reader (or a kill) never sees half a file."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        tmp.write_text(json.dumps(masked, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _write_json(path, data):
    _dump(path, redact.mask_obj(data))


def _masked_rows(rows):
    return [{**redact.mask_obj(row), "resource_id": redact.mask_secrets(row["resource_id"])} for row in rows]


def _masked_inventory(items):
    """Masked copy of the inventory: id/arn/name keep emails, the VantaOwner tag value is kept when it is an email."""
    masked = []
    for item in items:
        copy = {k: redact.mask_secrets(v) if k in ("id", "arn", "name") else redact.mask_obj(v) for k, v in item.items()}
        owner = (item.get("tags") or {}).get(OWNER_TAG)
        if owner is not None:
            copy["tags"][OWNER_TAG] = redact.mask(owner, keep_emails=frozenset({owner}))
        masked.append(copy)
    return masked


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inventario y recolección de chequeos (solo lectura)")
    parser.add_argument("--scope", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--checks-dir", default=str(SKILL_DIR / "references" / "checks"))
    parser.add_argument("--inventory", default=str(SKILL_DIR / "references" / "inventory.json"))
    parser.add_argument("--quiet", action="store_true", help="sin líneas de progreso en stderr")
    return parser


def _progress(args, text):
    if not args.quiet:
        print(text, file=sys.stderr, flush=True)


def _scp_blocked_regions(specs, regions, errors, scp_calls):
    """Regions (never the default one, which also hosts the global services) where every regional inventory type
    was refused by a service control policy: nothing can run there, so they are left out of the audit and reported."""
    regional = {t: s for t, s in specs.items() if s["region"] == "each"}
    denied = {(t, r) for t, r, _ in errors}
    return sorted(r for r in regions if r != DEFAULT_REGION and regional
                  and all((t, r) in denied and (s["service"], s["operation"], r) in scp_calls for t, s in regional.items()))


def _results_payload(aws, rows, warnings, pending):
    ordered = sorted(rows, key=lambda r: (r["check_id"], r["resource_id"], str(r["region"])))
    payload = {"aws": redact.mask_obj(aws), "results": _masked_rows(ordered), "warnings": redact.mask_obj(warnings)}
    if pending is not None:
        payload.update(partial=True, pending_checks=sorted(pending))
    return payload


def _run_checks(ctx, args, selected, collect_rows):
    """Run the checks in the pool; `collect_rows(rows, pending)` is called as results arrive (checkpoint) and at the end.
    Returns (rows, interrupted)."""
    rows, pending, total = [], {c["id"] for c in selected}, len(selected)
    pool = ThreadPoolExecutor(max_workers=WORKERS)
    futures = {pool.submit(_run_check, ctx, c): c for c in selected}
    last = time.monotonic()
    try:
        collect_rows(rows, pending)  # first checkpoint: every check pending
        for done, future in enumerate(as_completed(futures), 1):
            rows += future.result()
            pending.discard(futures[future]["id"])
            _progress(args, f"[{done}/{total}] {futures[future]['id']}")
            if time.monotonic() - last >= CHECKPOINT_SECONDS:
                collect_rows(rows, pending)
                last = time.monotonic()
    except BaseException as exc:  # Ctrl-C, SIGTERM (as KeyboardInterrupt) or a bug: keep what was collected
        ctx.cancelled.set()  # running workers stop issuing AWS calls
        pool.shutdown(wait=False, cancel_futures=True)
        collect_rows(rows, pending)
        if isinstance(exc, KeyboardInterrupt):
            return rows, pending
        raise
    pool.shutdown()
    return rows, set()


def main(argv=None, runner=subprocess.run, sleep=time.sleep, which=shutil.which) -> int:
    args = build_parser().parse_args(argv)

    scope = json.loads(Path(args.scope).read_text(encoding="utf-8"))
    checks = catalog.load_checks(Path(args.checks_dir))
    if problem := _scope_problem(scope, checks):  # before any AWS call: a malformed scope is an error
        return _scope_failure(problem)
    wanted = scope.get("regions", "auto")
    if problem := _regions_problem(wanted):  # a bad region list must not turn into an empty audit either
        return _scope_failure(problem)
    specs = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ctx = Ctx(runner=runner, sleep=sleep, which=which, out=out, profile=scope.get("profile"),
              allowed=allowed_operations(checks, specs), specs=specs)
    warnings = []

    identity = _aws(ctx, "sts", "get-caller-identity", [], DEFAULT_REGION)
    if not identity.ok:
        message = f"sin credenciales AWS válidas ({identity.error_kind})"
        _write_json(out / "checks-result.json", {"aws": None, "results": [], "warnings": [message]})
        _write_json(out / "inventory.json", [])
        print(redact.mask(f"{message}. Configurar credenciales o --profile y reintentar.\nDetalle en: {out}"))
        return 2
    account_id, identity_arn = (identity.data or {}).get("Account"), (identity.data or {}).get("Arn", "")

    enabled, known = _enabled_regions(ctx, warnings)
    if wanted == "auto":
        inventory_regions = enabled if known else [DEFAULT_REGION]
    else:
        wanted = list(dict.fromkeys(wanted))
        inventory_regions = [r for r in wanted if r in enabled or not known]
        warnings += [f"región fuera de las habilitadas, se omite: {r}" for r in wanted if r not in inventory_regions]
        if not inventory_regions:
            return _scope_failure(f"ninguna región de scope.regions ({', '.join(wanted)}) está habilitada en la cuenta "
                                  f"(habilitadas: {', '.join(enabled)})")
    scp_calls = set()

    def list_inventory(service, op, call_args, region):
        res = _aws(ctx, service, op, call_args, region)
        if _is_scp(res):
            scp_calls.add((service, op, region))
        return res

    _progress(args, f"[inventario] {len(inventory_regions)} regiones")
    selected = _select(checks, scope)
    if not selected:
        types = sorted({r["type"] for r in scope.get("resources") or []})
        warnings.append(f"ningún chequeo del catálogo aplica a: {', '.join(types) or 'el alcance indicado'}")
    try:
        ctx.inventory, errors = inventory.build_inventory(list_inventory, specs, inventory_regions, account_id=account_id,
                                                         partition=_identity_partition(identity_arn))
    except KeyboardInterrupt:  # Ctrl-C or SIGTERM during the inventory: nothing was checked, every check is pending
        ctx.cancelled.set()
        aws = {"account_id": account_id, "identity_arn": identity_arn, "regions": sorted(inventory_regions),
               "enabled_regions": enabled, "blocked_regions": []}
        _dump(out / "checks-result.json", _results_payload(aws, [], warnings, {c["id"] for c in selected}))
        pending = {c["id"] for c in selected}
        print(redact.mask(_summary([], {c["id"]: c["severity"] for c in selected}, warnings, aws, out, pending)))
        return 130
    ctx.blocked_regions = _scp_blocked_regions(specs, inventory_regions, errors, scp_calls)
    warnings += [f"región bloqueada por una SCP (todos los tipos de inventario denegados), se omite: {r}"
                 for r in ctx.blocked_regions]
    errors = [e for e in errors if e[1] not in ctx.blocked_regions]
    inventory_regions = [r for r in inventory_regions if r not in ctx.blocked_regions]
    ctx.enabled_regions = [r for r in enabled if r not in ctx.blocked_regions]
    warnings += _inventory_warnings(ctx, errors)
    if not known and wanted == "auto":  # only us-east-1 was listed: the regional types are unknown everywhere else
        ctx.regions_guessed = True
        for type_ in (t for t, s in specs.items() if s["region"] == "each"):
            ctx.inventory_errors.setdefault(type_, set()).add((ALL_REGIONS, REGIONS_UNKNOWN))
    if wanted == "auto":
        with_resources = {i["region"] for i in ctx.inventory if specs[i["type"]]["region"] == "each"}
        ctx.regions = sorted(with_resources | {DEFAULT_REGION})
    else:
        ctx.regions = sorted(inventory_regions)
    _dump(out / "inventory.json", _masked_inventory(ctx.inventory))
    _progress(args, f"[inventario] {len(ctx.inventory)} recursos")
    if scope["mode"] != "full":
        ctx.scope_resources = [r for r in scope.get("resources") or [] if isinstance(r, dict)]
        ctx.scope_entries = [(r["type"], r["id"]) for r in ctx.scope_resources]
        warnings += [f"recurso del alcance sin coincidencia en el inventario: {t} {ref}" for t, ref in ctx.scope_entries
                     if not any(_matches(i, t, ref) for i in ctx.inventory)]

    aws = {"account_id": account_id, "identity_arn": identity_arn, "regions": ctx.regions,
           "enabled_regions": ctx.enabled_regions, "blocked_regions": ctx.blocked_regions}
    severities = {c["id"]: c["severity"] for c in selected}

    def checkpoint(rows, pending):
        _dump(out / "checks-result.json", _results_payload(aws, rows, warnings, pending))

    rows, pending = _run_checks(ctx, args, selected, checkpoint)
    if not pending:
        try:
            rows = _evidence_rows(ctx, checks, selected, rows, warnings)
        except KeyboardInterrupt:  # the first-pass CMP-006 rows lack the attached instances: pending means no rows
            ctx.cancelled.set()
            pending = {SSM_CHECK}
            rows = [r for r in rows if r["check_id"] != SSM_CHECK]
    severities.update({c["id"]: c["severity"] for c in checks if c["id"] == SSM_CHECK})
    if pending:
        checkpoint(rows, pending)
        print(redact.mask(_summary(rows, severities, warnings, aws, out, pending)))
        return 130
    admin = _admin_warning(ctx, identity_arn)
    if admin:
        warnings.append(admin)
    _dump(out / "checks-result.json", _results_payload(aws, rows, warnings, None))
    print(redact.mask(_summary(rows, severities, warnings, aws, out)))
    return 0


def _raise_interrupt(signum, frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _raise_interrupt)  # a killed run still writes its partial result
    raise SystemExit(main())
