"""Remediation verification stage: checks, without executing anything against AWS, whether the CloudShell fixes in
findings.json would break something or leave something out. Writes <run-dir>/verification.json.

What it does (spec 9bis):
- `bash -n` over each finding's commands, fed through stdin (parse only, the commands are never run);
- optional `aws <service> <operation> help` (local help text, no API call; only with --check-cli and an installed CLI);
  every --flag of an `aws ...` line must appear in that help;
- unresolved {placeholders}, pending __COMPLETAR_*__ values, heredocs / `set -e`, destructive operations without warning;
- the rules of references/conflict-rules.json, tests that depend on the resource, gaps and a suggested apply order;
- Claude's vault-based claims (verification-claims.json): the most severe status wins and a claim never lowers a
  CONFLICTO raised by the script.

Only FAIL findings with a remediation get a status (OK / REVISAR / CONFLICTO). Everything written goes through redact.

Usage: verify_remediation.py --run-dir DIR [--claims FILE] [--check-cli]
"""

import argparse
import heapq
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import assemble_findings
import redact

SKILL_DIR = Path(__file__).resolve().parent.parent
RULES_PATH = SKILL_DIR / "references" / "conflict-rules.json"
RANK = {"OK": 0, "REVISAR": 1, "CONFLICTO": 2}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
PROCESS_TIMEOUT = 30
KIND_STATE = {
    "syntax": "CONFLICTO", "cli_invalida": "CONFLICTO", "placeholder_sin_resolver": "CONFLICTO", "higiene": "CONFLICTO",
    "requiere_completar": "REVISAR", "destructivo_sin_aviso": "REVISAR", "impacto_dependencias": "REVISAR",
}

PENDING = re.compile(r"__COMPLETAR_[A-Z0-9_]+__")
HEREDOC = re.compile(r"<<")
SET_E = re.compile(r"(?:^|[;&|])\s*set\s+(?:-[a-zA-Z]*e[a-zA-Z]*\b|-o\s+errexit\b)", re.M)
AWS_OPERATION = re.compile(r"\baws\s+([a-z0-9-]+)\s+([a-z0-9-]+)")
DESTRUCTIVE_PREFIXES = ("delete-", "revoke-", "terminate-", "remove-", "deregister-", "detach-", "disable-", "stop-")
REPLACING_OPERATIONS = ("put-bucket-policy", "put-key-policy", "update-account-password-policy")
FORCE_FLAG = re.compile(r"(?<![\w-])--force\b")
OVERSTRIKE = re.compile(r".\x08")
GLOBAL_FLAGS = frozenset({
    "--debug", "--endpoint-url", "--no-verify-ssl", "--no-paginate", "--output", "--query", "--profile", "--region", "--version",
    "--color", "--no-sign-request", "--ca-bundle", "--cli-read-timeout", "--cli-connect-timeout", "--cli-binary-format",
    "--no-cli-pager", "--cli-auto-prompt", "--no-cli-auto-prompt", "--cli-input-json", "--cli-input-yaml", "--generate-cli-skeleton",
})
# Apply order: (group number, checked by domain / resource type). Spec 9bis.1: identity, logging and detection, KMS keys,
# encryption, network, data, monitoring, tags and integration. `compute` shares the network group (SSM before closing SSH).
DOMAIN_GROUP = {"iam": 0, "logging": 1, "detection": 1, "encryption": 3, "network": 4, "compute": 4, "data": 5, "monitoring": 6}
KMS_GROUP, OTHER_GROUP = 2, 7


def _issue(kind, message, rule_id=None, source="script"):
    return {"kind": kind, "message": message, "source": source, "rule_id": rule_id}


def _one_line(text, limit=200):
    return " ".join(str(text).split())[:limit]


def _commands(finding):
    rem = finding.get("remediation") or {}
    if rem.get("kind") == "console_only":
        return []
    return [c for c in rem.get("commands") or [] if isinstance(c, str)]


def _code_lines(commands):
    """Non-comment lines, with backslash continuations joined."""
    for command in commands:
        for line in command.replace("\\\n", " ").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                yield line


def _test_label(test):
    name = test.get("name") or ""
    if test.get("tool") == "drata":
        return f"Drata {test.get('test')}" + (f": {name}" if name else "")
    return "Vanta: " + (name or str(test.get("test")))


# ---------------------------------------------------------------- per-finding checks


def _syntax_issues(commands, runner):
    try:
        proc = runner(["bash", "-n"], input="\n".join(commands), text=True, capture_output=True, shell=False,
                      timeout=PROCESS_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return [], "no se pudo correr bash -n"
    if proc.returncode == 0:
        return [], None
    return [_issue("syntax", "error de sintaxis de bash: " + (_one_line(proc.stderr) or "bash -n falló"))], None


def _placeholder_issues(texts):
    names = sorted({m.group(0) for text in texts for m in assemble_findings.PLACEHOLDER.finditer(text)})
    if not names:
        return []
    return [_issue("placeholder_sin_resolver", "quedan placeholders sin resolver: " + ", ".join(names))]


def _hygiene_issues(commands):
    lines = "\n".join(_code_lines(commands))
    issues = []
    if HEREDOC.search(lines):
        issues.append(_issue("higiene", "usa '<<' (heredoc): pegado en CloudShell queda esperando el terminador"))
    if SET_E.search(lines):
        issues.append(_issue("higiene", "usa 'set -e': cierra la sesión de CloudShell ante el primer error"))
    return issues


def _destructive_operations(commands):
    found = []
    for line in _code_lines(commands):
        for service, operation in AWS_OPERATION.findall(line):
            if operation.startswith(DESTRUCTIVE_PREFIXES) or operation in REPLACING_OPERATIONS:
                found.append(f"{service} {operation}")
        if FORCE_FLAG.search(line):
            found.append("--force")
    return sorted(set(found))


def _has_warning(rem):
    return rem.get("kind") == "planned_change" or (rem.get("kind") == "cli_with_decision" and str(rem.get("notes") or "").strip())


def _destructive_issues(finding, commands):
    ops = _destructive_operations(commands)
    if not ops or _has_warning(finding.get("remediation") or {}):
        return []
    return [_issue("destructivo_sin_aviso", "operación destructiva o que reemplaza configuración sin aviso en el arreglo ("
                   + ", ".join(ops) + "): marcarlo como cambio planificado o con decisión previa y notas")]


def _pending_names(commands):
    return sorted({m.group(0) for command in commands for m in PENDING.finditer(command)})


def _pending_issues(names):
    if not names:
        return []
    return [_issue("requiere_completar", "faltan valores por completar antes de pegar: " + ", ".join(names))]


def _dependency_issues(finding):
    tests = [t for t in finding.get("depends_on_me") or [] if isinstance(t, dict)]
    if not tests:
        return []
    return [_issue("impacto_dependencias", "el recurso tiene tests que hoy pasan y dependen de él, el cambio podría ponerlos en rojo: "
                   + "; ".join(_test_label(t) for t in tests))]


# ---------------------------------------------------------------- aws help check


def _aws_invocations(commands):
    """(service, operation, flags) for every line that starts with `aws `; the line is cut at the first shell operator."""
    for line in _code_lines(commands):
        if not line.startswith("aws "):
            continue
        lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        try:
            tokens = list(lexer)
        except ValueError:
            continue  # unbalanced quotes: bash -n already reports it
        words = []
        for token in tokens:
            if all(ch in "();<>|&" for ch in token):
                break
            words.append(token)
        if len(words) < 3 or words[1].startswith("-") or words[2].startswith("-"):
            continue
        flags = [w.split("=", 1)[0] for w in words[3:] if w.startswith("--") and len(w) > 2]
        yield words[1], words[2], flags


def _help_text(service, operation, runner, cache):
    key = (service, operation)
    if key not in cache:
        env = dict(os.environ, PAGER="cat", AWS_PAGER="")
        try:
            proc = runner(["aws", service, operation, "help"], env=env, text=True, capture_output=True, shell=False,
                          timeout=PROCESS_TIMEOUT)
            cache[key] = OVERSTRIKE.sub("", proc.stdout or "") if proc.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            cache[key] = ""  # help unavailable: nothing to compare against
    return cache[key]


def _cli_issues(commands, runner, cache):
    issues = []
    for service, operation, flags in _aws_invocations(commands):
        text = _help_text(service, operation, runner, cache)
        if text is None:
            issues.append(_issue("cli_invalida", f"la operación '{service} {operation}' no existe en la AWS CLI instalada"))
            continue
        if not text:
            continue
        missing = [f for f in dict.fromkeys(flags) if f not in GLOBAL_FLAGS
                   and not re.search(rf"(?<![\w-]){re.escape(f)}(?![\w-])", text)]
        if missing:
            issues.append(_issue("cli_invalida", f"flags que no aparecen en la ayuda de '{service} {operation}': " + ", ".join(missing)))
    return issues


# ---------------------------------------------------------------- conflict rules


def _same_scope(a, b, scope):
    if scope == "same_resource":
        return a["resource"]["id"] == b["resource"]["id"]
    ra, rb = a["resource"].get("region"), b["resource"].get("region")
    return not ra or not rb or ra == rb


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _ids(findings):
    return [f["id"] for f in findings]


def _rule_hits(rule, fails, all_findings):
    """[(affected finding ids, involved finding ids)] for one rule."""
    when, scope = rule["when"], rule.get("scope", "same_account")
    by_check = defaultdict(list)
    for f in fails:
        by_check[f["check_id"]].append(f)
    if "all_fail" in when:
        checks = when["all_fail"]
        if scope == "same_resource":
            groups = defaultdict(list)
            for f in fails:
                if f["check_id"] in checks:
                    groups[f["resource"]["id"]].append(f)
            return [(_ids(g), _ids(g)) for g in groups.values() if {f["check_id"] for f in g} >= set(checks)]
        if all(by_check.get(c) for c in checks):
            involved = [f for c in checks for f in by_check[c]]
            return [(_ids(involved), _ids(involved))]
        return []
    if "any_fail" in when:
        needles = when.get("command_contains") or []
        matched = [f for f in fails if f["check_id"] in when["any_fail"]
                   or any(n in c for n in needles for c in _commands(f))]
        return [(_ids(matched), _ids(matched))] if matched else []
    if "fail" in when:
        if "and_fail" in when:
            pool = [f for f in fails if f["check_id"] == when["and_fail"]]
        else:
            pool = [f for f in all_findings if f.get("check_id") == when.get("related_check_any") and f.get("status") in ("PASS", "FAIL")]
        hits = []
        for f in (f for f in fails if f["check_id"] in _as_list(when["fail"])):
            related = [g for g in pool if g["id"] != f["id"] and _same_scope(f, g, scope)]
            if related:
                hits.append(([f["id"]], [f["id"]] + _ids(related)))
        return hits
    return []


def _apply_rules(rules, fails, all_findings):
    """Returns (conflicts, issues by finding id, order constraints as (before check, after check) per fired rule)."""
    conflicts, issues, order_pairs = [], defaultdict(list), []
    for rule in rules:
        hits = _rule_hits(rule, fails, all_findings)
        if not hits:
            continue
        order_pairs += [tuple(pair) for pair in rule.get("order") or []]
        for affected, involved in hits:
            related = [i for i in involved if i not in affected]
            note = " Relacionado con: " + ", ".join(related) + "." if related else ""
            for fid in affected:
                issues[fid].append(_issue("conflicto_regla", f"{rule['id']}: {rule['message']}{note}", rule_id=rule["id"]))
        # any_fail / all_fail rules report one conflict listing every finding; the others one per hit
        grouped = "fail" not in rule["when"]
        entries = [[i for _, involved in hits for i in involved]] if grouped else [involved for _, involved in hits]
        conflicts += [{"rule_id": rule["id"], "findings": list(dict.fromkeys(ids)), "message": rule["message"],
                       "status": rule["status"]} for ids in entries]
    return conflicts, issues, order_pairs


# ---------------------------------------------------------------- order and gaps


def _group(finding):
    if finding["resource"].get("type") == "kms_key":
        return KMS_GROUP
    return DOMAIN_GROUP.get(finding.get("domain"), OTHER_GROUP)


def _base_key(finding):
    planned = (finding.get("remediation") or {}).get("kind") == "planned_change"
    return (_group(finding), 1 if planned else 0, SEVERITY_RANK.get(finding.get("severity"), 4), finding["id"])


def _toposort(findings, edges):
    keys = {f["id"]: _base_key(f) for f in findings}
    after = defaultdict(set)
    indegree = {fid: 0 for fid in keys}
    for before, later in edges:
        if later not in after[before]:
            after[before].add(later)
            indegree[later] += 1
    heap = [(keys[fid], fid) for fid, n in indegree.items() if n == 0]
    heapq.heapify(heap)
    out = []
    while heap:
        _, fid = heapq.heappop(heap)
        out.append(fid)
        for later in after[fid]:
            indegree[later] -= 1
            if indegree[later] == 0:
                heapq.heappush(heap, (keys[later], later))
    return out if len(out) == len(keys) else None


def _apply_order(findings, order_pairs):
    by_check = defaultdict(list)
    for f in findings:
        by_check[f["check_id"]].append(f["id"])
    edges = {(a, b) for before, later in order_pairs for a in by_check.get(before, []) for b in by_check.get(later, []) if a != b}
    ordered = _toposort(findings, edges)
    if ordered is not None:
        return ordered, []
    gap = {"kind": "no_verificado", "ref": "apply_order",
           "message": "las reglas de orden forman un ciclo y se ignoraron: el orden sugerido sigue solo grupo y severidad"}
    return _toposort(findings, set()), [gap]


def _gap(kind, message, ref):
    return {"kind": kind, "message": message, "ref": ref}


def _finding_gaps(findings):
    gaps = []
    for f in findings:
        rem = f.get("remediation")
        if f.get("status") == "FAIL":
            if not rem or (rem.get("kind") != "console_only" and not _commands(f)):
                gaps.append(_gap("sin_arreglo", f"{f['id']}: falla y no tiene comandos de arreglo ni es de solo consola", f["id"]))
            elif rem.get("kind") != "console_only" and not str(rem.get("verify_after") or "").strip():
                gaps.append(_gap("sin_verify_after", f"{f['id']}: el arreglo no trae comando para verificar después", f["id"]))
        elif f.get("status") == "NO_VERIFICADO":
            missing = ", ".join(f.get("missing") or []) or "permiso no indicado"
            gaps.append(_gap("no_verificado", f"{f['id']}: no se pudo verificar; permiso que falta: {missing}", f["id"]))
    return gaps


def _inventory_gaps(findings, inventory):
    seen = set()
    for f in findings:
        resource = f.get("resource") or {}
        seen.update(v for v in (resource.get("id"), resource.get("name")) if v)
    orphans = defaultdict(list)
    for item in inventory:
        if isinstance(item, dict) and not {item.get("id"), item.get("arn"), item.get("name")} & seen:
            orphans[item.get("type", "?")].append(item.get("id") or item.get("name") or "?")
    gaps = []
    for type_, ids in sorted(orphans.items()):
        shown = ", ".join(sorted(ids)[:5]) + (f" (y {len(ids) - 5} más)" if len(ids) > 5 else "")
        gaps.append(_gap("recurso_sin_chequeo", f"{len(ids)} recurso(s) de tipo {type_} sin ningún chequeo que los evalúe: {shown}", type_))
    return gaps


# ---------------------------------------------------------------- claims


def _claim_issues(claims, per_finding):
    for claim in claims or []:
        fid = claim.get("finding_id") if isinstance(claim, dict) else None
        if fid not in per_finding or claim.get("status") == "OK":
            continue
        state = claim.get("status") if claim.get("status") in RANK else "REVISAR"
        message = _one_line(claim.get("message") or "revisión de Claude sin detalle", 600)
        if claim.get("vault_note"):
            message += f" (nota: {_one_line(claim['vault_note'], 200)})"
        per_finding[fid]["issues"].append(_issue("claude", message, source="claude"))
        per_finding[fid]["_floor"] = max(per_finding[fid].get("_floor", "OK"), state, key=RANK.get)


# ---------------------------------------------------------------- entry point


def _issue_state(issue, rules_status):
    if issue["kind"] == "conflicto_regla":
        return rules_status[issue["rule_id"]]
    return KIND_STATE[issue["kind"]]


def _analyse(finding, runner, cache, cli_on):
    rem = finding["remediation"]
    commands = _commands(finding)
    texts = commands + [str(rem["verify_after"])] if rem.get("verify_after") else commands
    issues, gaps = [], []
    if commands:
        syntax, problem = _syntax_issues(commands, runner)
        issues += syntax
        if problem:
            gaps.append(_gap("no_verificado", f"{finding['id']}: {problem}", finding["id"]))
        issues += _placeholder_issues(texts) + _hygiene_issues(commands)
        if cli_on:
            issues += _cli_issues(commands, runner, cache)
        issues += _destructive_issues(finding, commands)
    issues += _pending_issues(_pending_names(commands)) + _dependency_issues(finding)
    return issues, gaps


def verify(findings: dict, inventory: list, rules: list, *, claims: list | None = None, runner=subprocess.run,
           which=shutil.which, check_cli: bool = False) -> dict:
    all_findings = [f for f in findings.get("findings", []) if isinstance(f, dict)]
    fails = [f for f in all_findings if f.get("status") == "FAIL" and isinstance(f.get("remediation"), dict)]
    cli_on = bool(check_cli and which("aws"))
    gaps = _finding_gaps(all_findings) + _inventory_gaps(all_findings, inventory)
    if check_cli and not cli_on:
        gaps.append(_gap("no_verificado", "la AWS CLI no está instalada: no se comprobó la validez de operaciones y flags (cli_checked: false)", "aws-cli"))

    cache, per_finding, pending = {}, {}, 0
    for f in fails:
        issues, extra_gaps = _analyse(f, runner, cache, cli_on)
        gaps += extra_gaps
        per_finding[f["id"]] = {"issues": issues}
        pending += len(_pending_names(_commands(f)))

    rule_fails = [f for f in fails if f.get("check_id")]
    conflicts, rule_issues, order_pairs = _apply_rules(rules, rule_fails, all_findings)
    rules_status = {r["id"]: r["status"] for r in rules}
    for fid, issues in rule_issues.items():
        per_finding[fid]["issues"] += issues
    _claim_issues(claims, per_finding)

    for entry in per_finding.values():
        floor = entry.pop("_floor", "OK")
        entry["status"] = max([floor] + [_issue_state(i, rules_status) for i in entry["issues"] if i["kind"] != "claude"], key=RANK.get)
    order, order_gaps = _apply_order(fails, order_pairs)
    summary = {s: sum(1 for e in per_finding.values() if e["status"] == s) for s in RANK}
    result = {"per_finding": per_finding, "conflicts": conflicts, "gaps": gaps + order_gaps, "apply_order": order,
              "completar_pendientes": pending, "cli_checked": cli_on, "summary": summary}
    return redact.mask_obj(result)


# ---------------------------------------------------------------- CLI


def _read_json(path, expected, label):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, expected):
        raise ValueError(f"{label}: forma inesperada")
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verifica los comandos de remediación de findings.json sin ejecutarlos")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--claims", help="verification-claims.json escrito por Claude")
    parser.add_argument("--check-cli", action="store_true", help="comprobar operaciones y flags con 'aws <svc> <op> help' (local)")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(f"el directorio de la corrida no existe: {run_dir}", file=sys.stderr)
        return 2
    try:
        findings = _read_json(run_dir / "findings.json", dict, "findings.json")
        inventory = _read_json(run_dir / "inventory.json", list, "inventory.json")
        rules = _read_json(RULES_PATH, list, "conflict-rules.json")
        claims = _read_json(args.claims, list, args.claims) if args.claims else None
        result = verify(findings, inventory, rules, claims=claims, check_cli=args.check_cli)
        (run_dir / "verification.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"error: {' '.join(str(exc).split())}", file=sys.stderr)
        return 2
    s = result["summary"]
    print(f"verificación: OK {s['OK']}, REVISAR {s['REVISAR']}, CONFLICTO {s['CONFLICTO']}; "
          f"{len(result['conflicts'])} conflictos, {len(result['gaps'])} faltantes, {result['completar_pendientes']} valores por completar.")
    print(f"Detalle en: {run_dir / 'verification.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
