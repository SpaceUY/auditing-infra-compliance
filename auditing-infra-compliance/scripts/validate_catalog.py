#!/usr/bin/env python3
"""Validate the check catalog under references/ (exit 1 on errors, 0 otherwise), or list it.

Usage:
  validate_catalog.py
  validate_catalog.py --list [--type <inventory type>] [--grep <text>]

--list prints one check per line as `id | title | resource_types | severity` (account-level checks show `account`
when they have no resource type) so a check_id can be picked without loading references/checks/*.json. --type keeps
the checks that apply to that inventory type (resource_types, or the account checks that declare it in
account_context_for); --grep keeps the checks whose id, title or resource types contain the text (case-insensitive).
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import catalog  # noqa: E402
import evaluators  # noqa: E402

SKILL_DIR = Path(__file__).resolve().parent.parent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validates the check catalog, or lists it with --list")
    parser.add_argument("--list", action="store_true", help="list checks: id | title | resource types | severity")
    parser.add_argument("--type", help="with --list: only checks of this inventory type")
    parser.add_argument("--grep", help="with --list: only checks whose id, title or types contain the text")
    return parser


def contract_arguments(specs) -> dict:
    """What the engine contract checks need: the inventory types, the registered python evaluators and their mandatory params."""
    return {"inventory_types": set(specs), "registered": set(evaluators.EVALUATORS), "required_params": evaluators.REQUIRED_PARAMS}


def _row(check):
    types = ",".join(check["resource_types"]) or "account"
    return f"{check['id']} | {check['title']} | {types} | {check['severity']}"


def _selected(checks, type_, grep):
    out = []
    for check in checks:
        if type_ and type_ not in check["resource_types"] and type_ not in (check.get("account_context_for") or []):
            continue
        if grep and grep.casefold() not in _row(check).casefold():
            continue
        out.append(check)
    return out


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if (args.type or args.grep) and not args.list:
        parser.error("--type and --grep are only used with --list")
    refs = SKILL_DIR / "references"
    checks = catalog.load_checks(refs / "checks")
    if args.list:
        for check in _selected(checks, args.type, args.grep):
            print(_row(check))
        return 0
    tsc_ids, iso_ids = catalog.load_frameworks(refs / "frameworks")
    drata = catalog.load_drata_map(refs / "mappings" / "drata-dcf.json")
    rules = json.loads((refs / "conflict-rules.json").read_text(encoding="utf-8"))
    specs = json.loads((refs / "inventory.json").read_text(encoding="utf-8"))
    errors = catalog.validate_inventory(specs)
    errors += catalog.validate(checks, tsc_ids, iso_ids, drata, rules, **contract_arguments(specs))
    for error in errors:
        print(error)
    if errors:
        return 1
    print(f"OK: {len(checks)} checks, {len(rules)} conflict rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
