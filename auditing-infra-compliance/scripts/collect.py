"""Read-only inventory and check-collection engine.

Writes <out>/checks-result.json, <out>/inventory.json and <out>/raw/<check_id>/<call>-<region>[-<n>].json
and prints a bounded summary. Global calls run in us-east-1 and report that region.
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
A check that declares `params.inventory_types` depends on those inventory types (`account_context_for` is only a
feature-mode selection key and never blocks evaluation): if the listing of any of them failed, the check is NO_VERIFICADO (missing "inventory:<type>") instead of being evaluated
on an incomplete inventory. Python evaluators also see `responses["__inventory_errors__"]` (set of broken types).
An evaluator entry {"resource_id", "region", "detail", "unverified": True} becomes a NO_VERIFICADO row for that region.
The "dns" evaluator is run by the engine: params {rrtype, name_template with {domain}, must_match regex,
domains_from (inventory type, default ses_identity)}; every domain-like inventory id of that type must
have a record of rrtype at the templated name matching must_match.
"""

import argparse
import json
import re
import shutil
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
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
    inventory_errors: dict = field(default_factory=dict)  # type -> {error kinds}
    scope_entries: list | None = None  # [(type, ref)] in feature/resource mode, None in full mode


def _oneline(text, limit):
    return " ".join(str(text).split())[:limit]


def _aws(ctx, service, operation, args, region, query=None):
    try:
        return aws_runner.run_aws(service, operation, args, region=region, profile=ctx.profile,
                                  query=query, runner=ctx.runner, sleep=ctx.sleep)
    except aws_runner.ReadOnlyViolation as exc:
        return aws_runner.CallResult(False, None, "ERROR", str(exc), ())


def _row(check, status, resource_id, region, detail=None, missing=None, vacuous=False):
    return {"check_id": check["id"], "status": status, "resource_id": resource_id, "region": region,
            "detail": detail or {}, "missing": missing or [], "vacuous": vacuous}


# ---------------------------------------------------------------- inventory

def _inventory_warnings(ctx, errors):
    grouped = {}
    for type_, region, kind in errors:
        ctx.inventory_errors.setdefault(type_, set()).add(kind)
        grouped.setdefault((type_, kind), []).append(region)
    return [f"inventario incompleto: {t} {k} en {', '.join(sorted(rs))}" for (t, k), rs in sorted(grouped.items())]


def _enabled_regions(ctx, wanted, warnings):
    res = _aws(ctx, "ec2", "describe-regions", ["--filters", ENABLED_REGIONS_FILTER], DEFAULT_REGION)
    if res.ok:
        return sorted(paths.extract(res.data, "Regions[].RegionName")), True
    warnings.append(f"no se pudieron listar las regiones habilitadas ({res.error_kind}); se usa el alcance")
    return (list(wanted) if isinstance(wanted, list) else [DEFAULT_REGION]), False


# ---------------------------------------------------------------- calls

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
        payload.update(error_kind=res.error_kind, error_message=_oneline(res.error_message, 300))
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
                _write_raw(ctx.out / "raw" / check["id"], name, region, index if "for_each" in call else None, res)
                if res.ok:
                    collected["responses"][name].append((region, res.data))
                    collected["values"][name].append(value)
                elif code := _item_error(call, res, query):
                    collected["responses"][name].append((region, {"__error__": code}))
                    collected["values"][name].append(value)
                else:
                    collected["failures"].append({"call": name, "region": region, "error_kind": res.error_kind,
                                                  "error_message": _oneline(res.error_message, 300)})
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


def _identifiers(items):
    return {x for i in items for x in (i["id"], i["arn"], i["name"]) if x}


def _unverified(check, failures, detail=None):
    denied = any(f["error_kind"] == "ACCESS_DENIED" for f in failures)
    regions = sorted({f["region"] for f in failures})
    detail = detail or {"failed_calls": failures[:20]}
    return _row(check, "NO_VERIFICADO", "account", regions[0] if len(regions) == 1 else None, detail,
                missing=list(check["verify"]["needs"]) if denied else [])


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


def _vacuous_row(ctx, check, types):
    broken = sorted(t for t in types if t in ctx.inventory_errors)
    if broken:
        return _row(check, "NO_VERIFICADO", "account", None,
                    {"reason": "inventario no disponible", "types": broken}, missing=[f"inventory:{t}" for t in broken])
    return _row(check, "N/A", "account", None, {"reason": "sin recursos en el alcance"}, vacuous=True)


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
    kind, _, name = check["verify"]["evaluator"].partition(":")
    is_resource = check["scope"] == "resource"
    items = _dns_items(ctx, check) if kind == "dns" else _items_for(ctx, check)
    if (is_resource or kind == "dns") and not items:
        return [_vacuous_row(ctx, check, [_dns_source(check)] if kind == "dns" else check["resource_types"])]
    broken = _broken_dependencies(ctx, check)
    if broken:
        return [_row(check, "NO_VERIFICADO", "account", None, {"reason": "inventario no disponible", "types": broken},
                     missing=[f"inventory:{t}" for t in broken])]
    collected = _run_calls(ctx, check, items)
    failures = collected["failures"]
    blocking = [f for f in failures if f["error_kind"] != "NOT_ENABLED" or check["not_enabled_means"] != "fail"]
    if blocking:
        return [_unverified(check, blocking)]
    rows = [_row(check, "FAIL", "account", region, {"reason": "servicio no habilitado", "call": call})
            for region, call in sorted({(f["region"], f["call"]) for f in failures})]
    if kind == "claude":
        return rows + [_row(check, "PENDING_CLAUDE", "account", None,
                            {"evaluator": kind, "calls": [c["name"] for c in check["verify"]["calls"]]})]
    try:
        if kind == "jmespath":
            offenders = _jmespath_offenders(collected, check["verify"]["calls"][0]["name"])
        elif kind == "dns":
            offenders = _dns_offenders(ctx, check, items)
        else:
            offenders = _python_offenders(ctx, check, name, collected, ctx.inventory)
    except _Unverifiable as exc:
        return rows + [_unverified(check, [], exc.args[0])]
    except Exception as exc:  # evaluator code is third-party to the engine
        detail = {"reason": "error del evaluador", "error": _oneline(f"{type(exc).__name__}: {exc}", 300)}
        return rows + [_unverified(check, [], detail)]
    if is_resource and ctx.scope_entries is not None:
        allowed = _identifiers(items)
        offenders = [o for o in offenders if o.get("unverified") or o["resource_id"] in allowed]  # never drop unverified
    unverified = [o for o in offenders if o.get("unverified")]
    # R20: not applicable resources get no FAIL and no PASS row; unverified ones get no PASS either
    skipped = {o["resource_id"] for o in offenders if o.get("not_applicable") or o.get("unverified")}
    offenders = [o for o in offenders if not o.get("not_applicable") and not o.get("unverified")]
    rows += [_row(check, "NO_VERIFICADO", o["resource_id"], o["region"], o["detail"],
                  missing=list(check["verify"]["needs"]) if o["detail"].get("error_code") == "ACCESS_DENIED" else [])
             for o in unverified]
    rows += [_row(check, "FAIL", o["resource_id"], o["region"], o["detail"]) for o in offenders]
    rows += _pass_rows(check, items, offenders, skipped, {f["region"] for f in failures}, bool(rows))
    if is_resource and not rows:  # R23: every in-scope item was not applicable
        return [_row(check, "N/A", "account", None, {"reason": "ningún recurso aplica"}, vacuous=True)]
    return rows


def _pass_rows(check, items, offenders, skipped, failed_regions, any_fail):
    if check["scope"] == "account":
        return [] if any_fail else [_row(check, "PASS", "account", None)]
    bad = {o["resource_id"] for o in offenders} | skipped
    return [_row(check, "PASS", i["id"], i["region"]) for i in items
            if i["region"] not in failed_regions and not (_identifiers([i]) & bad)]


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


def _summary(rows, severities, warnings, aws, out):
    counts = Counter(r["status"] for r in rows)
    lines = [f"Cuenta {aws['account_id']}: {len(rows)} resultados en {len(aws['regions'])} regiones"]
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
    path.write_text(json.dumps(masked, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


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
    return parser


def main(argv=None, runner=subprocess.run, sleep=time.sleep, which=shutil.which) -> int:
    args = build_parser().parse_args(argv)

    scope = json.loads(Path(args.scope).read_text(encoding="utf-8"))
    specs = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
    checks = catalog.load_checks(Path(args.checks_dir))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ctx = Ctx(runner=runner, sleep=sleep, which=which, out=out, profile=scope.get("profile"))
    warnings = []

    identity = _aws(ctx, "sts", "get-caller-identity", [], DEFAULT_REGION)
    if not identity.ok:
        message = f"sin credenciales AWS válidas ({identity.error_kind})"
        _write_json(out / "checks-result.json", {"aws": None, "results": [], "warnings": [message]})
        _write_json(out / "inventory.json", [])
        print(redact.mask(f"{message}. Configurar credenciales o --profile y reintentar.\nDetalle en: {out}"))
        return 2
    account_id, identity_arn = (identity.data or {}).get("Account"), (identity.data or {}).get("Arn", "")

    wanted = scope.get("regions", "auto")
    enabled, known = _enabled_regions(ctx, wanted, warnings)
    ctx.enabled_regions = enabled
    if wanted == "auto":
        inventory_regions = enabled
    else:
        inventory_regions = [r for r in wanted if r in enabled or not known]
        warnings += [f"región fuera de las habilitadas, se omite: {r}" for r in wanted if r not in inventory_regions]
    ctx.inventory, errors = inventory.build_inventory(
        lambda service, op, args, region: _aws(ctx, service, op, args, region), specs, inventory_regions)
    warnings += _inventory_warnings(ctx, errors)
    if wanted == "auto":
        with_resources = {i["region"] for i in ctx.inventory if specs[i["type"]]["region"] == "each"}
        ctx.regions = sorted(with_resources | {DEFAULT_REGION})
    else:
        ctx.regions = sorted(inventory_regions)
    if scope["mode"] != "full":
        ctx.scope_entries = [(r["type"], r["id"]) for r in scope.get("resources") or []]
        warnings += [f"recurso del alcance sin coincidencia en el inventario: {t} {ref}" for t, ref in ctx.scope_entries
                     if not any(_matches(i, t, ref) for i in ctx.inventory)]

    selected = _select(checks, scope)
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        rows = [row for result in pool.map(lambda c: _run_check(ctx, c), selected) for row in result]
    rows.sort(key=lambda r: (r["check_id"], r["resource_id"], str(r["region"])))

    admin = _admin_warning(ctx, identity_arn)
    if admin:
        warnings.append(admin)
    aws = {"account_id": account_id, "identity_arn": identity_arn, "regions": ctx.regions,
           "enabled_regions": enabled}
    _dump(out / "checks-result.json", {"aws": redact.mask_obj(aws), "results": _masked_rows(rows),
                                       "warnings": redact.mask_obj(warnings)})
    _dump(out / "inventory.json", _masked_inventory(ctx.inventory))
    print(redact.mask(_summary(rows, {c["id"]: c["severity"] for c in selected}, warnings, aws, out)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
