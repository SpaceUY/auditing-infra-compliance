"""Renders findings.json into the single-file HTML report (assets/report-template.html).

The template holds exactly one marker, /*__FINDINGS__*/, inside <script id="data" type="application/json">.
render() replaces it with the findings JSON, escaping <, >, & and the U+2028/U+2029 line separators as \\u003c, \\u003e, \\u0026, \\u2028 and \\u2029 so no value
(a resource named "</script><script>…") can close the data block or open a tag. The template's JS builds the DOM only
through textContent/createElement, never innerHTML with data.

Usage: render_report.py <findings.json> [-o <report.html>]   (default output: report.html next to findings.json)
"""

import argparse
import json
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = SKILL_DIR / "assets" / "report-template.html"
MARKER = "/*__FINDINGS__*/"
_ESCAPES = {"<": "\\u003c", ">": "\\u003e", "&": "\\u0026", "\u2028": "\\u2028", "\u2029": "\\u2029"}


def _embeddable_json(findings: dict) -> str:
    text = json.dumps(findings, ensure_ascii=False)
    return "".join(_ESCAPES.get(ch, ch) for ch in text)


def render(findings: dict, template: str, verification: dict | None = None) -> str:
    """Pure: findings + template -> HTML. `verification` is reserved for the fix-verification section (not rendered yet)."""
    if template.count(MARKER) != 1:
        raise ValueError(f"la plantilla debe contener exactamente un marcador {MARKER}")
    if not isinstance(findings, dict) or not isinstance(findings.get("findings"), list):
        raise ValueError("findings.json no tiene la forma esperada (falta la lista 'findings')")
    return template.replace(MARKER, _embeddable_json(findings))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Genera el reporte HTML a partir de findings.json")
    parser.add_argument("findings", help="ruta de findings.json")
    parser.add_argument("-o", "--output", help="ruta del HTML (por defecto report.html junto a findings.json)")
    args = parser.parse_args(argv)

    source = Path(args.findings)
    output = Path(args.output) if args.output else source.with_name("report.html")
    try:
        findings = json.loads(source.read_text(encoding="utf-8"))
        html = render(findings, TEMPLATE_PATH.read_text(encoding="utf-8"))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(html, encoding="utf-8")
    except (ValueError, OSError) as exc:  # JSONDecodeError and UnicodeDecodeError are ValueErrors
        print(f"error: {' '.join(str(exc).split())}", file=sys.stderr)
        return 2
    print(f"reporte escrito en {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
