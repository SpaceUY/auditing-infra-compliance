"""Obsidian vault indexer and feature resolution (read-only, stdlib only).

Only regular *.md files are read (FIFOs, sockets and symlinks are skipped; so are notes whose name is sensitive,
e.g. *credentials*.md, which are only listed); dotfiles and dotdirs are skipped (.obsidian/plugins is only listed),
symlinks are not followed and the top-level _meta/ folder (relations, generated edges) is not indexed as notes.
Everything textual that enters the index (title, headings, kv, links, edges, sources) goes through redact.mask;
detected secrets are reported by path and pattern only. Sensitive files (.env, .env.*, *.pem, *.key, *credentials*) found
anywhere in the vault tree (except .git) are listed by NAME only in `sensitive_files` ({path, reason}) and never opened.

CLI:
  vault_index.py index <vault> [-o vault-index.json]
  vault_index.py feature <vault-index.json> "<text>"     (JSON on stdout)

Feature lookup levels (the first one with matches wins): exact title/alias, title/H1 substring, body substring, and finally
a token level (words of 4+ characters, accents folded, stopwords dropped, matched against titles/H1/aliases; the notes
with the most tokens win), so "envío de email" finds "Email delivery".
"""

import argparse
import json
import os
import re
import sys
import unicodedata
from pathlib import Path

import redact

EDGE = re.compile(r"^- (?P<rel>[a-z ]+) → \[\[(?P<target>[^\]|#]+)", re.M)
WIKILINK = re.compile(r"(?<!!)\[\[([^\]|#]+)")
HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.M)
SECTION = re.compile(r"^#{1,6}\s+(Structural|Associative)\s*$", re.I)
KEY_VALUE = re.compile(r"^([A-Za-z_][\w-]*):[ \t]*(.*)$")
SEPARATOR_ROW = re.compile(r"^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")
NON_NOTE_LINK = re.compile(r"\.(png|jpe?g|gif|svg|webp|pdf|mp[34])$", re.I)
ARN = re.compile(r"arn:aws[a-z-]*:[^\s)\]|\"',`<>}]+")
RESOURCE_ID = re.compile(r"\b(i|sg|vpc|subnet|vol|acl|rtb|igw|nat|eni|lt)-[0-9a-f]{8,17}\b")
RDS_ID = re.compile(r"\bdb-[A-Z0-9]{26}\b")
PII_WORDS = re.compile(r"\b(pii|datos personales|user data|personal data|emails?)\b")

ASSOCIATIVE = frozenset({"resembles", "contrasts with", "is a metaphor for", "opens a question about"})
OUTBOUND_RELATIONS = frozenset({"depends on", "requires", "enables"})
INBOUND_RELATIONS = frozenset({"is part of"})
INFERRED_TYPES = {"RDS": "rds_instance", "S3": "s3_bucket", "VPC": "vpc", "ALB": "elbv2", "EC2": "ec2_instance",
                  "SES": "ses_identity", "LAMBDA": "lambda_function", "SQS": "sqs_queue", "IAM": "iam_role",
                  "KMS": "kms_key"}
FREE_DEPTH = 2
BREADCRUMB = "←"  # "← [[Hub]]" lines point to the parent; they are not dependencies, so they are not in `links`


# ---------------------------------------------------------------- reading

def _read(path):
    with open(path, encoding="utf-8-sig", errors="replace") as handle:
        return handle.read()


def _note_files(vault):
    found = []
    for dirpath, dirs, files in os.walk(vault):
        top = Path(dirpath) == vault
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and not (top and d == "_meta"))
        for name in sorted(files):
            path = Path(dirpath) / name
            if (name.endswith(".md") and not name.startswith(".") and not _sensitive_reason(name)
                    and not path.is_symlink() and path.is_file()):
                found.append(path)
    return sorted(found, key=lambda p: p.relative_to(vault).as_posix())


SENSITIVE_SKIP_DIRS = frozenset({".git", "node_modules"})


def _sensitive_reason(name):
    lower = name.lower()
    if lower == ".env" or lower.startswith(".env."):
        return "archivo .env"
    if lower.endswith((".pem", ".key")):
        return "archivo de clave privada (.pem/.key)"
    if "credentials" in lower:
        return "nombre con 'credentials'"
    return None


def _sensitive_files(vault):
    """Sensitive files by NAME only (the files are never opened); symlinks are listed, not followed."""
    found = []
    for dirpath, dirs, files in os.walk(vault):
        dirs[:] = sorted(d for d in dirs if d not in SENSITIVE_SKIP_DIRS)
        for name in sorted(files):
            reason = _sensitive_reason(name)
            if reason:
                rel = (Path(dirpath) / name).relative_to(vault).as_posix()
                found.append({"path": redact.mask_secrets(rel), "reason": reason})
    return sorted(found, key=lambda item: item["path"])


def _plugins(vault):
    root = vault / ".obsidian" / "plugins"
    if not root.is_dir():
        return []
    with os.scandir(root) as entries:
        return sorted(e.name for e in entries if e.is_dir(follow_symlinks=False))


def _split_frontmatter(text):
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    for end in range(1, len(lines)):
        if lines[end].strip() == "---":
            return _frontmatter(lines[1:end]), "\n".join(lines[end + 1:])
    return {}, text


def _scalar(value):
    return value.strip().strip("\"'")


def _frontmatter(lines):
    fields, current = {}, None
    for line in lines:
        match = KEY_VALUE.match(line)
        if match:
            key, value = match.group(1), match.group(2).strip()
            if value.startswith("[") and value.endswith("]"):
                fields[key] = [_scalar(v) for v in value[1:-1].split(",") if v.strip()]
                current = None
            elif value:
                fields[key], current = _scalar(value), None
            else:
                fields[key] = current = []
        elif current is not None and (item := re.match(r"^\s*-\s+(.*)$", line)):
            current.append(_scalar(item.group(1)))
    return fields


def _as_list(value):
    return value if isinstance(value, list) else ([value] if value else [])


def _edges(body):
    edges, layer = [], None
    for line in body.splitlines():
        if section := SECTION.match(line):
            layer = section.group(1).lower()
            continue
        match = EDGE.match(line)
        if match:
            relation = match.group("rel").strip()
            kind = layer or ("associative" if relation in ASSOCIATIVE else "structural")
            edges.append({"relation": relation, "target": match.group("target").strip(), "layer": kind})
    return edges


def _kv(body):
    rows = [redact.mask(line.strip()) for line in body.splitlines()]  # mask whole rows: a secret name can be the key
    skip = set()
    for i, row in enumerate(rows):
        if row.startswith("|") and SEPARATOR_ROW.match(row):
            skip.update({i, i - 1})
    kv = {}
    for i, row in enumerate(rows):
        if i in skip or not row.startswith("|"):
            continue
        cells = [c.strip() for c in row.strip("|").split("|")]
        if len(cells) >= 2 and cells[0] and cells[1]:
            kv[cells[0]] = " | ".join(c for c in cells[1:] if c)
    return kv


def _aws_ids(text):
    found = [{"kind": "arn", "value": redact.mask_secrets(m.group(0).rstrip(".,;:'\"`"))} for m in ARN.finditer(text)]
    found += [{"kind": m.group(1), "value": m.group(0)} for m in RESOURCE_ID.finditer(text)]
    found += [{"kind": "db", "value": m.group(0)} for m in RDS_ID.finditer(text)]
    return [dict(t) for t in dict.fromkeys(tuple(i.items()) for i in found)]


def _secrets(text):
    return redact.detect(text)


def _inferred_type(stem):
    prefix = stem.split(" - ", 1)[0].split()[0] if stem.strip() else ""
    return INFERRED_TYPES.get(prefix.upper())


def _links(lines):
    return list(dict.fromkeys(m.group(1).strip() for line in lines for m in WIKILINK.finditer(line)))


def _link_name(target):
    name = target.strip().rsplit("/", 1)[-1]
    return (name[:-3] if name.lower().endswith(".md") else name).strip().lower()


def _parse_note(vault, path):
    text = _read(path)
    rel = path.relative_to(vault).as_posix()
    fields, body = _split_frontmatter(text)
    mask = redact.mask
    lines = body.splitlines()
    parents = _links([line for line in lines if line.lstrip().startswith(BREADCRUMB)])
    links = _links([line for line in lines if not line.lstrip().startswith(BREADCRUMB)])
    note = {
        "path": rel, "title": mask(path.stem),
        "type": mask(fields["type"]) if isinstance(fields.get("type"), str) else None,
        "status": mask(fields["status"]) if isinstance(fields.get("status"), str) else None,
        "source": [mask(s) for s in _as_list(fields.get("source"))],
        "aliases": [mask(a) for a in _as_list(fields.get("aliases"))],
        "edges": [{**e, "target": mask(e["target"])} for e in _edges(body)],
        "links": [mask(link) for link in links],
        "parents": [mask(link) for link in parents],
        "aws_ids": _aws_ids(text),
        "kv": {mask(k): mask(v) for k, v in _kv(body).items()},
        "headings": [mask(f"{m.group(1)} {m.group(2)}") for m in HEADING.finditer(body)],
        "inferred_type": None,
    }
    return note, links + parents, _secrets(text)


def build_index(vault: Path) -> dict:
    vault = Path(vault).resolve()
    if not vault.is_dir():
        raise ValueError(f"el vault no existe o no es un directorio: {vault}")
    files = _note_files(vault)
    notes, raw_links, secrets = [], {}, []
    for path in files:
        note, links, patterns = _parse_note(vault, path)
        notes.append(note)
        raw_links[note["path"]] = links
        secrets += [{"path": note["path"], "pattern": p} for p in patterns]
    meta = vault / "_meta"
    typed = (meta / "relations.md").is_file() or (meta / "edges.md").is_file() or (
        bool(notes) and 2 * sum(1 for n in notes if n["type"]) >= len(notes))
    if not typed:
        for note, path in zip(notes, files):
            note["inferred_type"] = _inferred_type(path.stem)
    names = {_key(path.stem) for path in files}
    broken = [{"from": rel, "target": redact.mask(target)} for rel, links in raw_links.items() for target in links
              if not NON_NOTE_LINK.search(target) and _key(target) not in names]
    return {"kind": "typed" if typed else "free", "root": str(vault), "notes": notes, "broken_links": broken,
            "secrets_detected": secrets, "sensitive_files": _sensitive_files(vault),
            "obsidian_plugins": _plugins(vault)}


# ---------------------------------------------------------------- feature resolution

def _norm(text):
    stripped = "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))
    return " ".join(stripped.casefold().split())


def _key(text):
    """Note-name key for wikilink targets and titles: path/.md/alias-free, case, accent (NFC/NFD) and whitespace insensitive."""
    return _norm(_link_name(text))


def _body(index, note):
    root = Path(index["root"])
    path = root / note["path"]
    if path.is_symlink() or not path.is_file():
        return ""
    try:
        parts = path.resolve().relative_to(root.resolve()).parts
        if path.suffix != ".md" or any(part.startswith(".") for part in parts):
            return ""
        return _split_frontmatter(_read(path))[1]
    except (OSError, ValueError):
        return ""


MIN_TOKEN = 4
STOPWORDS = frozenset({
    "de", "del", "la", "las", "el", "los", "un", "una", "unos", "unas", "para", "con", "sin", "por", "que", "como", "sobre",
    "entre", "desde", "hacia", "este", "esta", "estos", "estas", "feature", "funcionalidad", "modulo", "sistema",
    "the", "and", "for", "with", "from", "into", "about", "that", "this", "these", "those", "of", "to", "in", "on", "a", "an",
})


def _tokens(query):
    """Distinct accent-folded words of at least MIN_TOKEN characters that are not stopwords."""
    words = re.findall(r"[^\W_]+", _norm(query))
    return list(dict.fromkeys(w for w in words if len(w) >= MIN_TOKEN and w not in STOPWORDS))


def _token_matches(notes, query):
    """Notes whose title, H1 or aliases contain the most query tokens (at least one); same ambiguity rule as the other levels."""
    tokens = _tokens(query)
    scored = []
    for note in notes:
        text = " ".join([_norm(note["title"]), *(_norm(a) for a in note.get("aliases", [])),
                         *(_norm(h[2:]) for h in note["headings"] if h.startswith("# "))])
        score = sum(1 for t in tokens if t in text)
        if score:
            scored.append((score, note))
    best = max((s for s, _ in scored), default=0)
    return [n for s, n in scored if s == best]


def _candidates(index, query):
    q = _norm(query)
    if not q:
        return []
    notes = index["notes"]
    levels = (
        lambda n: q in {_norm(n["title"]), *(_norm(a) for a in n.get("aliases", []))},
        lambda n: q in _norm(n["title"]) or any(h.startswith("# ") and q in _norm(h[2:]) for h in n["headings"]),
        lambda n: q in _norm(_body(index, n)),
    )
    for matches in levels:
        found = [n for n in notes if matches(n)]
        if found:
            return found
    return _token_matches(notes, query)


def _component(note, depth, via):
    return {"path": note["path"], "title": note["title"], "via": via, "depth": depth,
            "aws_ids": note["aws_ids"], "status": note["status"]}


def _typed_walk(index, root, max_depth):
    by_title = {_key(n["title"]): n for n in index["notes"]}
    inbound = {}
    for note in index["notes"]:
        for edge in note["edges"]:
            if edge["layer"] == "structural" and edge["relation"] in INBOUND_RELATIONS:
                inbound.setdefault(_key(edge["target"]), []).append(note)

    def neighbours(note):
        for edge in note["edges"]:
            if edge["layer"] == "structural" and edge["relation"] in OUTBOUND_RELATIONS:
                target = by_title.get(_key(edge["target"]))
                if target:
                    yield target, edge["relation"]
        for source in inbound.get(_key(note["title"]), []):
            yield source, "is part of"

    components, constraints = {}, []
    frontier, seen = [root], {root["path"]}
    for depth in range(1, max_depth + 1):
        nxt = []
        for node in frontier:
            for target, relation in neighbours(node):
                if target["status"] == "superseded":
                    continue
                if target["path"].startswith("constraints/"):
                    if target["path"] not in constraints:
                        constraints.append(target["path"])
                elif target["path"] in components and components[target["path"]]["depth"] == depth:
                    if relation not in components[target["path"]]["via"]:
                        components[target["path"]]["via"].append(relation)
                elif target["path"].startswith("systems/") and target["path"] not in seen:
                    seen.add(target["path"])
                    components[target["path"]] = _component(target, depth, [relation])
                    nxt.append(target)
        frontier = nxt
    return list(components.values()), constraints


def _free_walk(index, root):
    by_name = {_key(n["title"]): n for n in index["notes"]}
    components, frontier, seen = [], [root], {root["path"]}
    for depth in range(1, FREE_DEPTH + 1):
        nxt = []
        for node in frontier:
            for link in node["links"]:
                target = by_name.get(_key(link))
                if target and target["path"] not in seen:
                    seen.add(target["path"])
                    nxt.append(target)
                    if target["inferred_type"] or target["aws_ids"]:
                        components.append(_component(target, depth, ["wikilink"]))
        frontier = nxt
    return components


def _mentions_pii(index, notes):
    for note in notes:
        text = " ".join([note["title"], *note["headings"], *note["kv"].values(), _body(index, note)])
        if PII_WORDS.search(_norm(text)):
            return True
    return False


def resolve_feature(index: dict, query: str, max_depth: int = 3) -> dict:
    typed = index["kind"] == "typed"
    result = {"candidates": [], "chosen": None, "components": [], "constraints": [], "pii": False,
              "confidence": "typed" if typed else "inferred"}
    found = _candidates(index, query)
    result["candidates"] = [n["path"] for n in found]
    if len(found) != 1:
        return result
    root = found[0]
    result["chosen"] = root["path"]
    if typed:
        result["components"], result["constraints"] = _typed_walk(index, root, max_depth)
    else:
        result["components"] = _free_walk(index, root)
    by_path = {n["path"]: n for n in index["notes"]}
    related = [root, *(by_path[c["path"]] for c in result["components"]),
               *(by_path[p] for p in result["constraints"])]
    result["pii"] = _mentions_pii(index, related)
    return result


# ---------------------------------------------------------------- CLI

def _inside(path, folder):
    try:
        path.resolve().relative_to(folder.resolve())
        return True
    except ValueError:
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Índice del vault y resolución de feature (solo lectura)")
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("index")
    build.add_argument("vault")
    build.add_argument("-o", "--output", default="vault-index.json")
    feature = sub.add_parser("feature")
    feature.add_argument("index")
    feature.add_argument("text")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "index":
        vault, output = Path(args.vault), Path(args.output)
        if _inside(output, vault):
            print("el índice no se escribe dentro del vault; usar otra ruta con -o", file=sys.stderr)
            return 2
        try:
            index = build_index(vault)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        output.write_text(json.dumps(index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Vault {index['kind']}: {len(index['notes'])} notas, {len(index['broken_links'])} links rotos, "
              f"{len(index['secrets_detected'])} secretos detectados (enmascarados), "
              f"{len(index['sensitive_files'])} archivos sensibles (solo el nombre). Índice en: {output}")
        return 0
    index = json.loads(Path(args.index).read_text(encoding="utf-8"))
    print(json.dumps(resolve_feature(index, args.text), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
