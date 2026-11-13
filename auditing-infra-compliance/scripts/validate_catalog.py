#!/usr/bin/env python3
"""Validate the check catalog under references/. Exit 1 on errors, 0 otherwise."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import catalog  # noqa: E402

SKILL_DIR = Path(__file__).resolve().parent.parent


def main() -> int:
    refs = SKILL_DIR / "references"
    checks = catalog.load_checks(refs / "checks")
    tsc_ids, iso_ids = catalog.load_frameworks(refs / "frameworks")
    drata = catalog.load_drata_map(refs / "mappings" / "drata-dcf.json")
    rules = json.loads((refs / "conflict-rules.json").read_text(encoding="utf-8"))
    errors = catalog.validate(checks, tsc_ids, iso_ids, drata, rules)
    for error in errors:
        print(error)
    if errors:
        return 1
    print(f"OK: {len(checks)} checks, {len(rules)} reglas de conflicto")
    return 0


if __name__ == "__main__":
    sys.exit(main())
