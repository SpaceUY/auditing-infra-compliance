"""Remediation verification stage: checks, without executing anything against AWS, whether the CloudShell fixes in
findings.json would break something or leave something out. Writes <run-dir>/verification.json.

What it does (spec 9bis):
- `bash -n` over each finding's commands, fed through stdin (parse only, the commands are never run);
- optional `aws <service> <operation> help` (local help text, no API call; only with --check-cli and an installed CLI);
  every --flag of an `aws ...` line must appear in that help;
- unresolved {placeholders}, pending __FILL_IN_*__ values, heredocs / `set -e`, destructive operations without warning;
- the rules of references/conflict-rules.json, tests that depend on the resource, gaps and a suggested apply order;
- a fix that declares downtime, or has risk high, is never OK (floor REVIEW);
- no green OK on missing evidence: a rule that needs a fact the run did not collect (a CMP-006 result for an instance that uses
  the security group) records a gap and floors the fix at REVIEW;
- steps-only fixes (console / DNS) are verified too, and the `__FILL_IN_*__` values of steps, verify_after and notes are counted;
- Claude's vault-based claims (verification-claims.json): the most severe status wins and a claim never lowers a
  CONFLICT raised by the script.

verification.json carries `findings_digest` (see assemble_findings.findings_digest): render_report ignores a verification
whose digest does not match findings.json.

Only findings that carry a fix get a status (OK / REVIEW / CONFLICT): FAIL ones and any other with commands or steps (DOCUMENTED_GAP...);
the verify-only ones (remediation.note_status) have nothing to verify. Everything written goes through redact.

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
RANK = {"OK": 0, "REVIEW": 1, "CONFLICT": 2}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
PROCESS_TIMEOUT = 30
KIND_STATE = {
    "syntax": "CONFLICT", "invalid_cli": "CONFLICT", "unresolved_placeholder": "CONFLICT", "hygiene": "CONFLICT",
    "requires_fill_in": "REVIEW", "destructive_without_warning": "REVIEW", "dependency_impact": "REVIEW", "downtime": "REVIEW",
    "high_risk": "REVIEW", "missing_evidence": "REVIEW",
}

PENDING = re.compile(r"__FILL_IN_[A-Z0-9_]+__")
HEREDOC = re.compile(r"(?<!<)<<(?!<)")  # `<<<` is a here-string, not a heredoc
SET_E = re.compile(r"(?:^|[;&|])\s*set\s+(?:-[a-zA-Z]*e[a-zA-Z]*\b|-o\s+errexit\b)", re.M)
# `aws` only counts as a command word: at line start, after ; & | ( or $(, or after do / then / else
AWS_OPERATION = re.compile(r"(?:^|[;&|(]|\b(?:do|then|else)\s)\s*aws\s+([a-z0-9-]+)\s+([a-z0-9-]+)")
DOUBLE_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
SUBSTITUTION = re.compile(r"\$\([^)]*\)")
DESTRUCTIVE_PREFIXES = ("delete-", "revoke-", "terminate-", "remove-", "deregister-", "detach-", "disable-", "stop-", "untag-")
# Operations that replace a whole configuration or policy (the old one is gone), so they need the same warning as a delete:
# put-*-policy (bucket, key, user, role, group, resource, retention), put-bucket-* (acl, lifecycle, logging, notification, tagging,
# encryption, versioning...), the public access blocks (bucket and account: they replace the current settings and can take a public
# site offline), update-account-password-policy, update-assume-role-policy, replace-*
# (network ACL entries, routes, associations) and the modify-* that rewrite a list or an action set (security groups of an
# instance or interface, listener / rule default actions).
REPLACING_OPERATIONS = re.compile(
    r"(?:put-[a-z0-9-]*-policy|put-bucket-[a-z0-9-]+|put-(?:account-)?public-access-block|put-(?:event-selectors|"
    r"insight-selectors|configuration-recorder|delivery-channel|metric-alarm)|update-account-password-policy|"
    r"update-assume-role-policy|replace-[a-z0-9-]+|modify-(?:instance-attribute|network-interface-attribute|listener|rule))")
DESTRUCTIVE_PAIRS = frozenset({("s3", "rm"), ("s3", "rb")})
# a bare --force, --force-delete* and --delete (aws s3 sync); not benign flags such as --force-new-deployment
DESTRUCTIVE_FLAG = re.compile(r"(?<![\w-])(--force(?:-delete[\w-]*)?|--delete)(?![\w-])")
OVERSTRIKE = re.compile(r".\x08")
HELP_ENV_KEEP = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE")
MISSING_OPERATION_CODES = (2, 252)
MISSING_OPERATION_STDERR = re.compile(r"invalid choice|usage:", re.I)
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


def _strip_quotes(line):
    """The line without quoted text (words inside strings are not commands or flags); $(...) inside double quotes stays."""
    out, i = [], 0
    while i < len(line):
        if line[i] == "'":
            end = line.find("'", i + 1)
            out.append("''")
            i = len(line) if end == -1 else end + 1
        elif line[i] == '"' and (match := DOUBLE_QUOTED.match(line, i)):
            out.append('"' + " ".join(SUBSTITUTION.findall(match.group(1))) + '"')
            i = match.end()
        else:
            out.append(line[i])
            i += 1
    return "".join(out)


def _code_text(commands):
    return "\n".join(_strip_quotes(line) for line in _code_lines(commands))


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
        return [], "could not run bash -n"
    if proc.returncode == 0:
        return [], None
    return [_issue("syntax", "bash syntax error: " + (_one_line(proc.stderr) or "bash -n failed"))], None


def _placeholder_issues(texts):
    names = sorted({m.group(0) for text in texts for m in assemble_findings.PLACEHOLDER.finditer(text)})
    if not names:
        return []
    return [_issue("unresolved_placeholder", "unresolved placeholders remain: " + ", ".join(names))]


def _hygiene_issues(commands):
    lines = _code_text(commands)
    issues = []
    if HEREDOC.search(lines):
        issues.append(_issue("hygiene", "uses '<<' (heredoc): pasted into CloudShell it waits for the terminator"))
    if SET_E.search(lines):
        issues.append(_issue("hygiene", "uses 'set -e': closes the CloudShell session on the first error"))
    return issues


def _destructive_operations(commands):
    found = []
    for line in _code_text(commands).splitlines():
        for service, operation in AWS_OPERATION.findall(line):
            if operation.startswith(DESTRUCTIVE_PREFIXES) or REPLACING_OPERATIONS.fullmatch(operation) or (service, operation) in DESTRUCTIVE_PAIRS:
                found.append(f"{service} {operation}")
        found += DESTRUCTIVE_FLAG.findall(line)
    return sorted(set(found))


# A cli_with_decision fix is "warned" only when its notes actually say so; any non-empty text is not a warning.
WARNING_WORDS = re.compile(
    r"(?i)\b(?:warning|caution|danger|risk\w*|irreversib\w*|destructive|data loss|loss of|overwrit\w*|replac\w*|"
    r"lose|lost|cuts?|cutting|delet\w*|remov\w*|cannot be undone|no access|without access|no traffic|downtime|lock(?:ed)?[ -]?out|permanent\w*)\b")


def _has_warning(rem):
    return rem.get("kind") == "planned_change" or (rem.get("kind") == "cli_with_decision" and bool(WARNING_WORDS.search(str(rem.get("notes") or ""))))


def _destructive_issues(finding, commands):
    ops = _destructive_operations(commands)
    if not ops or _has_warning(finding.get("remediation") or {}):
        return []
    return [_issue("destructive_without_warning", "destructive operation or one that replaces configuration with no warning in the fix ("
                   + ", ".join(ops) + "): mark it as a planned change or as needing a prior decision, and add notes")]


def _pending_names(texts):
    return sorted({m.group(0) for text in texts for m in PENDING.finditer(text)})


def _fix_texts(finding):
    """Every text of the fix that ends up in the report: commands, steps, verify_after and notes."""
    rem = finding.get("remediation") or {}
    steps = [t for t in rem.get("steps") or [] if isinstance(t, str)]
    return _commands(finding) + steps + [str(rem[k]) for k in ("verify_after", "notes") if rem.get(k)]


def _verify_only_texts(finding):
    """The only text a verify-only finding (DOCUMENTED_ONLY, PASS, N/A, NOT_VERIFIED...) puts in the report to be pasted: verify_after."""
    rem = finding.get("remediation")
    text = rem.get("verify_after") if isinstance(rem, dict) else None
    return [text] if isinstance(text, str) else []


def _has_fix(finding):
    """A FAIL, or any finding with commands or steps. Verify-only findings (remediation.note_status) have nothing to verify."""
    rem = finding.get("remediation")
    if not isinstance(rem, dict) or rem.get("note_status"):
        return False
    return finding.get("status") == "FAIL" or bool(_commands(finding)) or any(isinstance(t, str) and t.strip() for t in rem.get("steps") or [])


def _pending_issues(names):
    if not names:
        return []
    return [_issue("requires_fill_in", "values to fill in before pasting: " + ", ".join(names))]


def _dependency_issues(finding):
    tests = [t for t in finding.get("depends_on_me") or [] if isinstance(t, dict)]
    if not tests:
        return []
    return [_issue("dependency_impact", "the resource has tests that pass today and depend on it, the change could turn them red: "
                   + "; ".join(_test_label(t) for t in tests))]


def _downtime_issues(rem):
    if rem.get("downtime") is not True:
        return []
    return [_issue("downtime", "the fix declares downtime")]


def _risk_issues(rem):
    if rem.get("risk") != "high":
        return []
    return [_issue("high_risk", "high risk: pending review against the vault before applying")]


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


def _help_env():
    env = {k: os.environ[k] for k in HELP_ENV_KEEP if k in os.environ}
    return {**env, "PAGER": "cat", "AWS_PAGER": ""}


def _help_text(service, operation, runner, cache):
    """The help text; None when the CLI says the operation does not exist (rc 2/252 plus 'Invalid choice' or 'usage:');
    "" when the help could not be read for any other reason (groff missing, timeout, empty output): nothing to compare."""
    key = (service, operation)
    if key not in cache:
        try:
            proc = runner(["aws", service, operation, "help"], env=_help_env(), text=True, capture_output=True, shell=False,
                          timeout=PROCESS_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired):
            cache[key] = ""
            return cache[key]
        if proc.returncode == 0:
            cache[key] = OVERSTRIKE.sub("", proc.stdout or "").strip()
        elif proc.returncode in MISSING_OPERATION_CODES and MISSING_OPERATION_STDERR.search(proc.stderr or ""):
            cache[key] = None
        else:
            cache[key] = ""
    return cache[key]


def _cli_issues(commands, runner, cache):
    issues = []
    for service, operation, flags in _aws_invocations(commands):
        text = _help_text(service, operation, runner, cache)
        if text is None:
            issues.append(_issue("invalid_cli", f"the operation '{service} {operation}' does not exist in the installed AWS CLI"))
            continue
        if not text:
            continue
        missing = [f for f in dict.fromkeys(flags) if f not in GLOBAL_FLAGS
                   and not re.search(rf"(?<![\w-]){re.escape(f)}(?![\w-])", text)]
        if missing:
            issues.append(_issue("invalid_cli", f"flags that do not appear in the help of '{service} {operation}': " + ", ".join(missing)))
    return issues


# ---------------------------------------------------------------- conflict rules


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
        hits = []
        for f in (f for f in fails if f["check_id"] in _as_list(when["fail"])):
            related = _attachment_match(f, when, fails)
            if related is not None:
                hits.append(([f["id"]], [f["id"]] + _ids(related)))
        return hits
    return []


def _attachments(finding):
    evidence = finding.get("evidence")
    items = evidence.get("attachments") if isinstance(evidence, dict) else None
    return [a for a in items if isinstance(a, dict)] if isinstance(items, list) else []


def _attachment_match(finding, when, fails):
    """None when the finding's security group attachments (evidence.attachments, from the NET evaluators) do not satisfy
    the rule condition; otherwise the related findings (possibly none). No attachment data means no match."""
    attachments = _attachments(finding)
    prefix = when.get("attachment_description_prefix")
    if prefix:
        return [] if any(str(a.get("description") or "").startswith(prefix) for a in attachments) else None
    wanted = when.get("attached_instance_fail") or {}
    instances = {a["instance_id"] for a in attachments if a.get("instance_id")}
    related = [g for g in fails if g["check_id"] == wanted.get("check") and g["resource"]["id"] in instances
               and isinstance(g.get("evidence"), dict) and g["evidence"].get(wanted.get("evidence_true")) is True]
    return related or None


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
            note = " Related to: " + ", ".join(related) + "." if related else ""
            for fid in affected:
                issues[fid].append(_issue("rule_conflict", f"{rule['id']}: {rule['message']}{note}", rule_id=rule["id"]))
        # any_fail / all_fail rules report one conflict listing every finding; the others one per hit
        grouped = "fail" not in rule["when"]
        entries = [[i for _, involved in hits for i in involved]] if grouped else [involved for _, involved in hits]
        conflicts += [{"rule_id": rule["id"], "findings": list(dict.fromkeys(ids)), "message": rule["message"],
                       "status": rule["status"]} for ids in entries]
    return conflicts, issues, order_pairs


def _rule_instances(finding):
    return sorted({a["instance_id"] for a in _attachments(finding) if isinstance(a.get("instance_id"), str) and a["instance_id"]})


def _missing_evidence(rules, fails, all_findings):
    """Rules that need a fact about an attached instance (attached_instance_fail: a CMP-006 result) fire only when that fact says
    "unreachable". When the run has no usable result for the instance (check not run, NOT_VERIFIED, N/A) the rule cannot clear the
    fix either: returns (issues by finding id, gaps) so the fix is floored at REVIEW instead of showing a green OK."""
    issues, gaps = defaultdict(list), []
    for rule in rules:
        when = rule["when"]
        wanted = when.get("attached_instance_fail")
        if not wanted or "fail" not in when:
            continue
        for f in (f for f in fails if f["check_id"] in _as_list(when["fail"])):
            for instance in _rule_instances(f):
                results = [g for g in all_findings if g.get("check_id") == wanted.get("check")
                           and (g.get("resource") or {}).get("id") == instance and g.get("status") in ("PASS", "FAIL")]
                if results:
                    continue
                message = (f"{rule['id']}: no result of {wanted.get('check')} for the instance {instance} that uses this security group; "
                           "it is unknown whether it is reachable through Systems Manager and closing access could leave it with no way in")
                issues[f["id"]].append(_issue("missing_evidence", message, rule_id=rule["id"]))
                gaps.append(_gap("not_verified", f"{f['id']}: missing evidence, no {wanted.get('check')} result for {instance}", f["id"]))
    return issues, gaps


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
    gap = {"kind": "not_verified", "ref": "apply_order",
           "message": "the ordering rules form a cycle and were ignored: the suggested order follows only group and severity"}
    return _toposort(findings, set()), [gap]


def _gap(kind, message, ref):
    return {"kind": kind, "message": message, "ref": ref}


def _finding_gaps(findings):
    gaps = []
    for f in findings:
        rem = f.get("remediation")
        if f.get("status") == "FAIL":
            if not rem or (rem.get("kind") != "console_only" and not _commands(f)):
                gaps.append(_gap("no_fix", f"{f['id']}: fails and has no fix commands and is not console-only", f["id"]))
            elif rem.get("kind") != "console_only" and not str(rem.get("verify_after") or "").strip():
                gaps.append(_gap("no_verify_after", f"{f['id']}: the fix has no command to verify afterwards", f["id"]))
        elif f.get("status") == "NOT_VERIFIED":
            missing = ", ".join(f.get("missing") or []) or "permission not stated"
            gaps.append(_gap("not_verified", f"{f['id']}: could not be verified; missing permission: {missing}", f["id"]))
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
        shown = ", ".join(sorted(ids)[:5]) + (f" (and {len(ids) - 5} more)" if len(ids) > 5 else "")
        gaps.append(_gap("resource_without_check", f"{len(ids)} resource(s) of type {type_} with no check that evaluates them: {shown}", type_))
    return gaps


# ---------------------------------------------------------------- claims


CLAIM_FORM = "expected a text finding_id and status, and a text or null message and vault_note"


def _valid_claim(claim):
    return (isinstance(claim, dict) and isinstance(claim.get("finding_id"), str) and isinstance(claim.get("status"), str)
            and all(claim.get(k) is None or isinstance(claim[k], str) for k in ("message", "vault_note")))


def _claim_issues(claims, per_finding):
    """Adds Claude's claims to per_finding; returns warnings for claims that are skipped because of their shape."""
    if claims is not None and not isinstance(claims, list):
        return [f"claims ignored: {CLAIM_FORM} (a list was expected)"]
    warnings = []
    for number, claim in enumerate(claims or [], start=1):
        if not _valid_claim(claim):
            warnings.append(f"claim {number} ignored: invalid shape ({CLAIM_FORM})")
            continue
        fid = claim["finding_id"]
        if fid not in per_finding:
            warnings.append(f"claim {number} ignored: {_one_line(fid, 40)} has no fix to verify (nonexistent id or finding without a fix)")
            continue
        if claim["status"] == "OK":
            continue
        state = claim["status"] if claim["status"] in RANK else "REVIEW"
        message = _one_line(claim.get("message") or "Claude review with no detail", 600)
        if claim.get("vault_note"):
            message += f" (note: {_one_line(claim['vault_note'], 200)})"
        per_finding[fid]["issues"].append(_issue("claude", message, source="claude"))
        per_finding[fid]["_floor"] = max(per_finding[fid].get("_floor", "OK"), state, key=RANK.get)
    return warnings


# ---------------------------------------------------------------- entry point


def _issue_state(issue, rules_status):
    if issue["kind"] == "rule_conflict":
        return rules_status[issue["rule_id"]]
    return KIND_STATE[issue["kind"]]


def _analyse(finding, runner, cache, cli_on):
    rem = finding["remediation"]
    commands, texts = _commands(finding), _fix_texts(finding)
    issues, gaps = [], []
    if commands:
        syntax, problem = _syntax_issues(commands, runner)
        issues += syntax
        if problem:
            gaps.append(_gap("not_verified", f"{finding['id']}: {problem}", finding["id"]))
        issues += _hygiene_issues(commands)
        if cli_on:
            issues += _cli_issues(commands, runner, cache)
        issues += _destructive_issues(finding, commands)
    issues += _placeholder_issues(texts) + _pending_issues(_pending_names(texts)) + _dependency_issues(finding) + _downtime_issues(rem)
    issues += _risk_issues(rem)
    return issues, gaps


def verify(findings: dict, inventory: list, rules: list, *, claims: list | None = None, runner=subprocess.run,
           which=shutil.which, check_cli: bool = False) -> dict:
    all_findings = [f for f in findings.get("findings", []) if isinstance(f, dict)]
    # every finding that carries a fix gets a status: FAIL (console_only included) and any other status with commands or steps
    # (DOCUMENTED_GAP, DRIFT whose actual fails...); verify-only findings (DOCUMENTED_ONLY, PASS, N/A, NOT_VERIFIED) have nothing to verify
    fails = [f for f in all_findings if _has_fix(f)]
    cli_on = bool(check_cli and which("aws"))
    gaps = _finding_gaps(all_findings) + _inventory_gaps(all_findings, inventory)
    meta = findings.get("meta")
    if isinstance(meta, dict) and "aws" in meta and not meta["aws"]:
        gaps.append(_gap("not_verified", "no AWS credentials: no state was verified against AWS, the fixes were not checked against the account", "aws"))
    if check_cli and not cli_on:
        gaps.append(_gap("not_verified", "the AWS CLI is not installed: the validity of operations and flags was not checked (cli_checked: false)", "aws-cli"))

    cache, per_finding, pending = {}, {}, 0
    for f in fails:
        issues, extra_gaps = _analyse(f, runner, cache, cli_on)
        gaps += extra_gaps
        per_finding[f["id"]] = {"issues": issues}
        pending += len(_pending_names(_fix_texts(f)))

    pending += sum(len(_pending_names(_verify_only_texts(f))) for f in all_findings if f not in fails)

    rule_fails = [f for f in fails if f.get("check_id")]
    conflicts, rule_issues, order_pairs = _apply_rules(rules, rule_fails, all_findings)
    evidence_issues, evidence_gaps = _missing_evidence(rules, rule_fails, all_findings)
    gaps += evidence_gaps
    rules_status = {r["id"]: r["status"] for r in rules}
    for fid, issues in {**rule_issues, **{k: rule_issues.get(k, []) + v for k, v in evidence_issues.items()}}.items():
        per_finding[fid]["issues"] += issues
    warnings = _claim_issues(claims, per_finding)

    for entry in per_finding.values():
        floor = entry.pop("_floor", "OK")
        entry["status"] = max([floor] + [_issue_state(i, rules_status) for i in entry["issues"] if i["kind"] != "claude"], key=RANK.get)
    order, order_gaps = _apply_order(fails, order_pairs)
    unavailable = sorted(f"{service} {operation}" for (service, operation), text in cache.items() if text == "")
    if unavailable:
        gaps.append(_gap("not_verified", "CLI help not available, operations and flags were not checked for: " + ", ".join(unavailable), "aws-cli"))
    compared = sum(1 for text in cache.values() if text != "")
    summary = {s: sum(1 for e in per_finding.values() if e["status"] == s) for s in RANK}
    result = {"per_finding": per_finding, "conflicts": conflicts, "gaps": gaps + order_gaps, "apply_order": order,
              "fill_in_pending": pending, "cli_checked": cli_on and not unavailable and compared > 0,
              "cli_requested": bool(check_cli), "cli_operations_checked": compared if cli_on else 0, "summary": summary,
              "warnings": warnings, "findings_digest": assemble_findings.findings_digest(findings)}
    return redact.mask_obj(result)


# ---------------------------------------------------------------- CLI


def _read_json(path, expected, label):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, expected):
        raise ValueError(f"{label}: forma inesperada")
    return data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verifies the remediation commands of findings.json without executing them")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--claims", help="verification-claims.json written by Claude")
    parser.add_argument("--check-cli", action="store_true", help="check operations and flags with 'aws <svc> <op> help' (local)")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(f"the run directory does not exist: {run_dir}", file=sys.stderr)
        return 2
    if not (run_dir / "findings.json").is_file():
        print(f"error: {run_dir / 'findings.json'} does not exist: run assemble_findings.py before verifying", file=sys.stderr)
        return 2
    try:
        findings = _read_json(run_dir / "findings.json", dict, "findings.json")
        inventory = _read_json(run_dir / "inventory.json", list, "inventory.json") if (run_dir / "inventory.json").exists() else []
        rules = _read_json(RULES_PATH, list, "conflict-rules.json")
        missing_claims = bool(args.claims) and not Path(args.claims).is_file()
        claims = _read_json(args.claims, list, args.claims) if args.claims and not missing_claims else None
        result = verify(findings, inventory, rules, claims=claims, check_cli=args.check_cli)
        if missing_claims:
            result["warnings"].append(f"the claims file does not exist, verified without Claude claims: {redact.mask(args.claims)}")
        (run_dir / "verification.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"error: {' '.join(str(exc).split())}", file=sys.stderr)
        return 2
    s = result["summary"]
    print(f"verification: OK {s['OK']}, REVIEW {s['REVIEW']}, CONFLICT {s['CONFLICT']}; "
          f"{len(result['conflicts'])} conflicts, {len(result['gaps'])} gaps, {result['fill_in_pending']} values to fill in, "
          f"{len(result['warnings'])} warnings.")
    print(f"Detail in: {run_dir / 'verification.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
