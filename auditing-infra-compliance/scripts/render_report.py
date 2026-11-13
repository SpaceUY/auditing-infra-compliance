"""Renders findings.json into the single-file HTML report (assets/report-template.html).

The template holds exactly one marker, /*__FINDINGS__*/, inside <script id="data" type="application/json">.
render() replaces it with the findings JSON, escaping <, >, & and the U+2028/U+2029 line separators as \\u003c, \\u003e, \\u0026, \\u2028 and \\u2029 so no value
(a resource named "</script><script>…") can close the data block or open a tag. The template's JS builds the DOM only
through textContent/createElement, never innerHTML with data.

When a verification dict (verify_remediation.py) is given it is embedded in the same data block under the key
"verification"; without it the embedded JSON is exactly the findings. A verification carries the digest of the findings it was
computed from (`findings_digest`): when it does not match findings.json (or has no digest) it is ignored, "verification_stale": true is embedded
(the page shows a warning) and the CLI prints a warning. meta.vault.path is reduced to the vault folder name.

Usage: render_report.py <findings.json> [--verification <verification.json>] [-o <report.html>]
(default output: report.html next to findings.json)
"""

import argparse
import json
import sys
from pathlib import Path

import assemble_findings

SKILL_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = SKILL_DIR / "assets" / "report-template.html"
MARKER = "/*__FINDINGS__*/"
STALE_WARNING = "stale verification: re-run verify_remediation"
_ESCAPES = {"<": "\\u003c", ">": "\\u003e", "&": "\\u0026", "\u2028": "\\u2028", "\u2029": "\\u2029"}


def _embeddable_json(data: dict) -> str:
    text = json.dumps(data, ensure_ascii=False)
    return "".join(_ESCAPES.get(ch, ch) for ch in text)


def verification_is_stale(findings: dict, verification: dict | None) -> bool:
    """True when the verification was computed from other findings, or carries no digest (verify_remediation always writes one,
    so a verification without it is old or hand-made and cannot be tied to these findings)."""
    if not isinstance(verification, dict):
        return False
    return verification.get("findings_digest") != assemble_findings.findings_digest(findings)


def _vault_folder(findings: dict) -> dict:
    vault = (findings.get("meta") or {}).get("vault")
    if not isinstance(vault, dict) or not isinstance(vault.get("path"), str):
        return findings
    return {**findings, "meta": {**findings["meta"], "vault": {**vault, "path": Path(vault["path"]).name or None}}}


def render(findings: dict, template: str, verification: dict | None = None) -> str:
    """Pure: findings (+ optional verification) + template -> HTML."""
    if template.count(MARKER) != 1:
        raise ValueError(f"the template must contain exactly one {MARKER} marker")
    if not isinstance(findings, dict) or not isinstance(findings.get("findings"), list):
        raise ValueError("findings.json does not have the expected shape (the 'findings' list is missing)")
    if verification is not None and not isinstance(verification, dict):
        raise ValueError("verification.json does not have the expected shape (an object was expected)")
    findings = _vault_folder({k: v for k, v in findings.items() if k not in ("verification", "verification_stale")})
    if verification is not None and verification_is_stale(findings, verification):
        findings["verification_stale"] = True
    elif verification is not None:  # only the argument can add a verification
        findings["verification"] = verification
    return template.replace(MARKER, _embeddable_json(findings))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generates the HTML report from findings.json")
    parser.add_argument("findings", help="path to findings.json")
    parser.add_argument("--verification", help="path to verification.json (fix verification stage)")
    parser.add_argument("-o", "--output", help="path of the HTML (by default report.html next to findings.json)")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    source = Path(args.findings)
    output = Path(args.output) if args.output else source.with_name("report.html")
    if not source.is_file():
        print(f"error: {source} does not exist: run assemble_findings.py before generating the report", file=sys.stderr)
        return 2
    try:
        findings = json.loads(source.read_text(encoding="utf-8"))
        verification = json.loads(Path(args.verification).read_text(encoding="utf-8")) if args.verification else None
        html = render(findings, TEMPLATE_PATH.read_text(encoding="utf-8"), verification)
        if isinstance(findings, dict) and isinstance(verification, dict) and verification_is_stale(findings, verification):
            print(f"warning: {STALE_WARNING}", file=sys.stderr)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(html, encoding="utf-8")
    except (ValueError, OSError) as exc:  # JSONDecodeError and UnicodeDecodeError are ValueErrors
        print(f"error: {' '.join(str(exc).split())}", file=sys.stderr)
        return 2
    print(f"report written to {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
