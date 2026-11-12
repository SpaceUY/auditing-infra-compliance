"""Read-only inventory and check-collection engine.

Writes <out>/checks-result.json, <out>/inventory.json and <out>/raw/<check_id>/<call>-<region>[-<n>].json
and prints a bounded summary. Global calls run in us-east-1 and report that region.

Check conventions (catalog): a jmespath check's `offenders` expression is passed as --query and must
project {resource_id, detail}; resource_id may be omitted when the call has for_each (the for_each
value is used). A call's for_each is {"from": <earlier call name> | "__inventory__", "path", "arg"}:
"__inventory__" iterates the check's evaluated inventory items (resource_types, narrowed to scope in
feature/resource mode). A dns call has args [name, rrtype] (the for_each value replaces name).
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
import paths

SKILL_DIR = Path(__file__).resolve().parent.parent
DEFAULT_REGION = "us-east-1"
INVENTORY_SOURCE = "__inventory__"
WORKERS = 8
SEVERITY_ORDER = {s: i for i, s in enumerate(catalog.SEVERITIES)}
ADMIN_POLICY = "AdministratorAccess"
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
    scope_pairs: set | None = None  # {(type, id)} in feature/resource mode, None in full mode


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

def _tags(nodes):
    tags = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        key = node.get("Key", node.get("key"))
        if key is not None:
            tags[str(key)] = str(node.get("Value", node.get("value", "")))
        else:
            tags.update({str(k): str(v) for k, v in node.items()})
    return tags


def _first(item, path):
    values = paths.extract(item, path)
    return str(values[0]) if values else ""


def _to_item(type_, spec, raw, region):
    item_id = _first(raw, spec["id_path"])
    if not item_id:
        return None
    tags = _tags(paths.extract(raw, spec["tags_path"]))
    name = _first(raw, spec["name_path"]) or tags.get("Name") or item_id
    return {"type": type_, "id": item_id, "arn": _first(raw, spec["arn_path"]), "name": name,
            "region": region, "tags": tags}


def _list_type(ctx, type_, spec, region):
    res = _aws(ctx, spec["service"], spec["operation"], spec["args"], region)
    if not res.ok:
        return [], res.error_kind
    items = (_to_item(type_, spec, raw, region) for raw in paths.extract(res.data, spec["items_path"]))
    return [i for i in items if i], None


def _build_inventory(ctx, specs, regions):
    """One job per region (ThreadPoolExecutor); global types run once in us-east-1."""
    jobs = {r: [t for t, s in specs.items() if s["region"] == "each"] for r in regions}
    jobs.setdefault(DEFAULT_REGION, [])
    jobs[DEFAULT_REGION] = jobs[DEFAULT_REGION] + [t for t, s in specs.items() if s["region"] == "global"]

    def run(region):
        found, errors = [], []
        for type_ in jobs[region]:
            items, error = _list_type(ctx, type_, specs[type_], region)
            found += items
            if error:
                errors.append((type_, region, error))
        return found, errors

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(run, sorted(jobs)))
    items = sorted((i for found, _ in results for i in found), key=lambda i: (i["type"], i["region"], i["id"]))
    return items, [e for _, errors in results for e in errors]


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


def _items_for(ctx, check):
    types = set(check["resource_types"])
    return [i for i in ctx.inventory if i["type"] in types
            and (ctx.scope_pairs is None or (i["type"], i["id"]) in ctx.scope_pairs)]


def _for_each_values(call, region, items, responses):
    source = call["for_each"]
    if source["from"] == INVENTORY_SOURCE:
        is_global = call.get("region", "global") == "global"
        pool = [i for i in items if is_global or i["region"] == region]
        return [v for item in pool for v in paths.extract(item, source["path"])]
    return [v for r, data in responses.get(source["from"], []) if r == region
            for v in paths.extract(data, source["path"])]


def _args_for(call, value):
    base = list(call.get("args", []))
    if value is None:
        return base
    if call["service"] == "dns":
        return [str(value), *base[-1:]]
    flag, text = call["for_each"]["arg"], str(value)
    return base + ([f"{flag}={text}"] if text.startswith("-") else [flag, text])


def _execute(ctx, call, region, args, query):
    if call["service"] != "dns":
        return _aws(ctx, call["service"], call["operation"], args, region, query)
    if len(args) < 2:
        return aws_runner.CallResult(False, None, "ERROR", "llamada dns requiere [nombre, rrtype]", ())
    return aws_runner.run_dns(args[0], args[-1], runner=ctx.runner, which=ctx.which)


def _write_raw(directory, call_name, region, index, res):
    suffix = "" if index is None else f"-{index}"
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{call_name}-{region}{suffix}")
    payload = {"argv": list(res.argv), "ok": res.ok}
    if res.ok:
        payload["data"] = res.data
    else:
        payload.update(error_kind=res.error_kind, error_message=_oneline(res.error_message, 300))
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{safe}.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


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


def _python_offenders(check, name, collected, inventory):
    fn = evaluators.EVALUATORS.get(name)
    if fn is None:
        raise LookupError(f"evaluador python '{name}' no registrado")
    responses = {**collected["responses"], "__for_each__": collected["values"], "__inventory__": inventory}
    return [{"resource_id": str(o["resource_id"]), "region": o.get("region"), "detail": o.get("detail") or {}}
            for o in fn(responses, check["verify"].get("params") or {})]


def _identifiers(items):
    return {x for i in items for x in (i["id"], i["arn"], i["name"]) if x}


def _unverified(check, failures, detail=None):
    denied = any(f["error_kind"] == "ACCESS_DENIED" for f in failures)
    regions = sorted({f["region"] for f in failures})
    detail = detail or {"failed_calls": failures[:20]}
    return _row(check, "NO_VERIFICADO", "account", regions[0] if len(regions) == 1 else None, detail,
                missing=list(check["verify"]["needs"]) if denied else [])


def _vacuous_row(ctx, check):
    broken = sorted(t for t in check["resource_types"] if t in ctx.inventory_errors)
    if broken:
        return _row(check, "NO_VERIFICADO", "account", None,
                    {"reason": "inventario no disponible", "types": broken}, missing=[f"inventory:{t}" for t in broken])
    return _row(check, "N/A", "account", None, {"reason": "sin recursos en el alcance"}, vacuous=True)


def _run_check(ctx, check):
    items = _items_for(ctx, check)
    is_resource = check["scope"] == "resource"
    if is_resource and not items:
        return [_vacuous_row(ctx, check)]
    collected = _run_calls(ctx, check, items)
    failures = collected["failures"]
    blocking = [f for f in failures if f["error_kind"] != "NOT_ENABLED" or check["not_enabled_means"] != "fail"]
    if blocking:
        return [_unverified(check, blocking)]
    rows = [_row(check, "FAIL", "account", region, {"reason": "servicio no habilitado", "call": call})
            for region, call in sorted({(f["region"], f["call"]) for f in failures})]
    kind, _, name = check["verify"]["evaluator"].partition(":")
    if kind in ("claude", "dns"):
        return rows + [_row(check, "PENDING_CLAUDE", "account", None,
                            {"evaluator": kind, "calls": [c["name"] for c in check["verify"]["calls"]]})]
    try:
        if kind == "jmespath":
            offenders = _jmespath_offenders(collected, check["verify"]["calls"][0]["name"])
        else:
            offenders = _python_offenders(check, name, collected, ctx.inventory)
    except Exception as exc:  # evaluator code is third-party to the engine
        return rows + [_unverified(check, [], {"reason": "error del evaluador", "error": _oneline(f"{type(exc).__name__}: {exc}", 300)})]
    if is_resource and ctx.scope_pairs is not None:
        allowed = _identifiers(items)
        offenders = [o for o in offenders if o["resource_id"] in allowed]
    rows += [_row(check, "FAIL", o["resource_id"], o["region"], o["detail"]) for o in offenders]
    return rows + _pass_rows(check, items, offenders, {f["region"] for f in failures}, bool(rows))


def _pass_rows(check, items, offenders, failed_regions, any_fail):
    if check["scope"] == "account":
        return [] if any_fail else [_row(check, "PASS", "account", None)]
    bad = {o["resource_id"] for o in offenders}
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


def _write_json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv=None, runner=subprocess.run, sleep=time.sleep, which=shutil.which) -> int:
    parser = argparse.ArgumentParser(description="Inventario y recolección de chequeos (solo lectura)")
    parser.add_argument("--scope", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--checks-dir", default=str(SKILL_DIR / "references" / "checks"))
    parser.add_argument("--inventory", default=str(SKILL_DIR / "references" / "inventory.json"))
    args = parser.parse_args(argv)

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
        print(f"{message}. Configurar credenciales o --profile y reintentar.\nDetalle en: {out}")
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
    ctx.inventory, errors = _build_inventory(ctx, specs, inventory_regions)
    warnings += _inventory_warnings(ctx, errors)
    if wanted == "auto":
        with_resources = {i["region"] for i in ctx.inventory if specs[i["type"]]["region"] == "each"}
        ctx.regions = sorted(with_resources | {DEFAULT_REGION})
    else:
        ctx.regions = sorted(inventory_regions)
    if scope["mode"] != "full":
        ctx.scope_pairs = {(r["type"], r["id"]) for r in scope.get("resources") or []}

    selected = _select(checks, scope)
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        rows = [row for result in pool.map(lambda c: _run_check(ctx, c), selected) for row in result]
    rows.sort(key=lambda r: (r["check_id"], r["resource_id"], str(r["region"])))

    admin = _admin_warning(ctx, identity_arn)
    if admin:
        warnings.append(admin)
    aws = {"account_id": account_id, "identity_arn": identity_arn, "regions": ctx.regions,
           "enabled_regions": enabled}
    _write_json(out / "checks-result.json", {"aws": aws, "results": rows, "warnings": warnings})
    _write_json(out / "inventory.json", ctx.inventory)
    print(_summary(rows, {c["id"]: c["severity"] for c in selected}, warnings, aws, out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
