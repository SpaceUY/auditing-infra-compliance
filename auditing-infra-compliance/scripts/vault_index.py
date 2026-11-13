"""Obsidian vault indexer and feature resolution (read-only, stdlib only).

Only regular *.md files are read (FIFOs, sockets and symlinks are skipped; so are notes whose name is sensitive,
e.g. *credentials*.md, which are only listed); dotfiles and dotdirs are skipped (.obsidian/plugins is only listed),
symlinks are not followed and the top-level _meta/ folder (relations, generated edges) is not indexed as notes.
Everything textual that enters the index (title, headings, kv, links, edges, sources) goes through redact.mask, and every
path (notes, secrets_detected, broken_links, truncated_notes, sensitive_files) is valid UTF-8 (undecodable bytes become U+FFFD)
with secret-shaped names masked (two notes whose masked paths collide get " (2)", " (3)" before ".md", so none is shadowed); the real
file is still opened through a public-to-real path map built once per run. The index is
written through a temporary file and a rename, so a failure leaves no partial file ("error: ..." on stderr, exit 2).
Detected secrets are reported by path and pattern only. Sensitive files (SENSITIVE_NAMES: .env*, *.env, *.pem, *.key, *.pfx, *.p12,
*.jks, *.keystore, *.tfvars, terraform.tfstate*, id_rsa, id_ed25519, id_ecdsa, *credentials*, and *secret*; the last two only for files that can hold a secret: TEXT_EXTENSIONS, no images, PDFs or office
documents, and *secret* never for notes) found
anywhere in the vault tree (except .git) are listed by NAME only in `sensitive_files` ({path, reason}) and never opened.

CLI:
  vault_index.py index <vault> [-o vault-index.json]
  vault_index.py feature <vault-index.json> "<text>"     (JSON on stdout)

Feature lookup levels (the first one with matches wins): exact title/alias, title/H1 substring, body substring, and finally
a token level (words of 4+ characters, accents folded, stopwords dropped, matched against titles/H1/aliases; the notes
with the most tokens win), so "email sending" (or the Spanish "envío de email") finds "Email delivery". Superseded notes are candidates only when nothing else matches.
The matched note is itself a component (depth 0, via "matched") when it is under systems/ (typed) or names an AWS resource (free), so
asking for a leaf resource note does not drop that resource. Links resolve through title, alias and folder (`[[notes/Queue]]`; with two
notes of one name `systems/` wins). Notes are read up to MAX_NOTE_BYTES characters; longer ones are listed in `truncated_notes`.
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
# no `\s*$` after a lazy quantifier (quadratic on a long whitespace run): the text runs to the end of the line and is stripped in Python
HEADING = re.compile(r"^(#{1,6})[ \t]+(\S.*)$", re.M)
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

MAX_NOTE_BYTES = 2_000_000  # a note is read up to this many characters; the rest is ignored and the note is reported in `truncated_notes`


def _read(path):
    with open(path, encoding="utf-8-sig", errors="replace") as handle:
        return handle.read(MAX_NOTE_BYTES)


def _is_truncated(path):
    try:
        return path.stat().st_size > MAX_NOTE_BYTES
    except OSError:
        return False


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


# The one list of sensitive file names, matched case-insensitively on the file name: (kind, names, reason, applies to notes, text only).
# A note (.md) is treated as sensitive only by the rules marked True: "AWS Secrets Manager.md" is documentation, not a secret. A rule
# marked "text only" applies to other files only when they can hold a secret (TEXT_EXTENSIONS: no extension, config and text formats),
# never to images, PDFs, canvases or office documents: `secrets-manager-flow.png` is a diagram, not a credential.
TEXT_EXTENSIONS = frozenset({"", ".txt", ".json", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".toml", ".properties", ".xml", ".sh", ".ps1",
                             ".csv", ".env", ".secret", ".secrets"})
SENSITIVE_NAMES = (
    ("prefix", (".env",), ".env file", True, False),  # .env, .env.production, .env-prod, .envrc
    ("suffix", (".env",), ".env file", True, False),  # prod.env
    ("suffix", (".pem", ".key"), "private key file (.pem/.key)", True, False),
    ("suffix", (".pfx", ".p12", ".jks", ".keystore"), "certificate or key store (.pfx/.p12/.jks/.keystore)", True, False),
    ("suffix", (".tfvars",), "Terraform variables file (.tfvars)", True, False),
    ("prefix", ("terraform.tfstate",), "Terraform state file (terraform.tfstate*)", True, False),
    ("exact", ("id_rsa", "id_ed25519", "id_ecdsa"), "SSH private key (id_rsa, id_ed25519, id_ecdsa)", True, False),
    ("contains", ("credentials",), "name containing 'credentials'", True, True),
    ("contains", ("secret",), "name containing 'secret'", False, True),
)
_SENSITIVE_TESTS = {"prefix": lambda lower, names: lower.startswith(names), "suffix": lambda lower, names: lower.endswith(names),
                    "exact": lambda lower, names: lower in names, "contains": lambda lower, names: any(n in lower for n in names)}


def _sensitive_reason(name):
    lower = name.lower()
    is_note = lower.endswith(".md")
    text_like = os.path.splitext(lower)[1] in TEXT_EXTENSIONS
    for kind, names, reason, applies_to_notes, text_only in SENSITIVE_NAMES:
        if not (applies_to_notes or not is_note) or not _SENSITIVE_TESTS[kind](lower, names):
            continue
        if not text_only or is_note or text_like:
            return reason
    return None


def _clean(text):
    """A path or file name as valid UTF-8: bytes that are not (a Latin-1 name from a zip, say) become U+FFFD instead of the lone
    surrogates that os.walk leaves in the str and that json cannot encode."""
    return os.fsencode(text).decode("utf-8", "replace")


def _public_path(rel):
    """The vault-relative path as it is written to the index: valid UTF-8 and with secret-shaped file names masked."""
    return redact.mask_secrets(_clean(rel))


def _public_paths(vault, files):
    """The public path of each note file (same order as `files`), unique: two notes whose masked names are equal (access-key-id names with
    the same ends, U+FFFD names) get ` (2)`, ` (3)`... before `.md`, in the order of the sorted real paths, so no note is shadowed. A
    public path that is already some note's own name is never handed out."""
    natural = [_public_path(p.relative_to(vault).as_posix()) for p in files]
    reserved, used, out = set(natural), set(), []
    for name in natural:
        candidate, number = name, 1
        while candidate in used or (number > 1 and candidate in reserved):
            number += 1
            candidate = f"{name[:-3]} ({number}).md" if name.endswith(".md") else f"{name} ({number})"
        used.add(candidate)
        out.append(candidate)
    return out


def _sensitive_files(vault):
    """Sensitive files by NAME only (the files are never opened); symlinks are listed, not followed."""
    found = []
    for dirpath, dirs, files in os.walk(vault):
        dirs[:] = sorted(d for d in dirs if d not in SENSITIVE_SKIP_DIRS)
        for name in sorted(files):
            reason = _sensitive_reason(name)
            if reason:
                found.append({"path": _public_path((Path(dirpath) / name).relative_to(vault).as_posix()), "reason": reason})
    return sorted(found, key=lambda item: item["path"])


def _plugins(vault):
    root = vault / ".obsidian" / "plugins"
    if not root.is_dir():
        return []
    with os.scandir(root) as entries:
        return sorted(_clean(e.name) for e in entries if e.is_dir(follow_symlinks=False))


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
    # mask the whole body, then split: a secret name can be the key, and masking needs the table context (header rows)
    rows = [line.strip() for line in redact.mask(body).splitlines()]
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
    words = stem.split(" - ", 1)[0].split()
    return INFERRED_TYPES.get(words[0].upper()) if words else None


def _links(lines):
    return list(dict.fromkeys(m.group(1).strip() for line in lines for m in WIKILINK.finditer(line)))


def _link_name(target):
    name = target.strip().rsplit("/", 1)[-1]
    return (name[:-3] if name.lower().endswith(".md") else name).strip().lower()


def _parse_note(vault, path, rel):
    text = _read(path)  # rel: the public path of the note (see _public_paths); the real one is only used to open the file
    fields, body = _split_frontmatter(text)
    mask = redact.mask
    lines = body.splitlines()
    parents = _links([line for line in lines if line.lstrip().startswith(BREADCRUMB)])
    links = _links([line for line in lines if not line.lstrip().startswith(BREADCRUMB)])
    note = {
        "path": rel, "title": mask(_clean(path.stem)),
        "type": mask(fields["type"]) if isinstance(fields.get("type"), str) else None,
        "status": mask(fields["status"]) if isinstance(fields.get("status"), str) else None,
        "source": [mask(s) for s in _as_list(fields.get("source"))],
        "aliases": [mask(a) for a in _as_list(fields.get("aliases"))],
        "edges": [{**e, "target": mask(e["target"])} for e in _edges(body)],
        "links": [mask(link) for link in links],
        "parents": [mask(link) for link in parents],
        "aws_ids": _aws_ids(text),
        "kv": {mask(k): mask(v) for k, v in _kv(body).items()},
        "headings": [mask(f"{m.group(1)} {m.group(2).strip()}") for m in HEADING.finditer(body)],
        "inferred_type": None,
    }
    return note, links + parents, _secrets(text)


def build_index(vault: Path) -> dict:
    vault = Path(vault).resolve()
    if not vault.is_dir():
        raise ValueError(f"the vault does not exist or is not a directory: {vault}")
    files = _note_files(vault)
    notes, raw_links, secrets, truncated = [], [], [], []
    for path, public in zip(files, _public_paths(vault, files)):
        note, links, patterns = _parse_note(vault, path, public)
        notes.append(note)
        if _is_truncated(path):
            truncated.append(note["path"])
        raw_links.append((note["path"], links))
        secrets += [{"path": note["path"], "pattern": p} for p in patterns]
    meta = vault / "_meta"
    typed = (meta / "relations.md").is_file() or (meta / "edges.md").is_file() or (
        bool(notes) and 2 * sum(1 for n in notes if n["type"]) >= len(notes))
    if not typed:
        for note, path in zip(notes, files):
            note["inferred_type"] = _inferred_type(_clean(path.stem))
    names = {_key(_clean(path.stem)) for path in files} | {_key(a) for note in notes for a in note["aliases"]}
    broken = [{"from": rel, "target": redact.mask(target)} for rel, links in raw_links for target in links
              if not NON_NOTE_LINK.search(target) and _key(target) not in names]
    return {"kind": "typed" if typed else "free", "root": str(vault), "notes": notes, "broken_links": broken,
            "secrets_detected": secrets, "sensitive_files": _sensitive_files(vault),
            "obsidian_plugins": _plugins(vault), "truncated_notes": truncated}


# ---------------------------------------------------------------- feature resolution

def _norm(text):
    stripped = "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))
    return " ".join(stripped.casefold().split())


def _key(text):
    """Note-name key for wikilink targets and titles: path/.md/alias-free, case, accent (NFC/NFD) and whitespace insensitive."""
    return _norm(_link_name(text))


def _real_paths(root):
    """{public path: real file} for every note of the vault, built once per run. The index holds masked, valid-UTF-8, unique paths (see
    _public_paths), so a note whose real name differs is found through this map."""
    root = Path(root).resolve()
    files = _note_files(root)
    return dict(zip(_public_paths(root, files), files))


def _body(index, note, paths):
    root = Path(index["root"])
    path = paths.get(note["path"]) or root / note["path"]
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


def _candidates(index, query, paths):
    """Matches among the notes that are not superseded; only when there are none, among all of them."""
    active = [n for n in index["notes"] if n.get("status") != "superseded"]
    return _matching(index, query, active, paths) or _matching(index, query, index["notes"], paths)


def _matching(index, query, notes, paths):
    q = _norm(query)
    if not q:
        return []
    levels = (
        lambda n: q in {_norm(n["title"]), *(_norm(a) for a in n.get("aliases", []))},
        lambda n: q in _norm(n["title"]) or any(h.startswith("# ") and q in _norm(h[2:]) for h in n["headings"]),
        lambda n: q in _norm(_body(index, n, paths)),
    )
    for matches in levels:
        found = [n for n in notes if matches(n)]
        if found:
            return found
    return _token_matches(notes, query)


def _component(note, depth, via):
    return {"path": note["path"], "title": note["title"], "via": via, "depth": depth,
            "aws_ids": note["aws_ids"], "status": note["status"]}


def _link_folder(target):
    """The folder part of a qualified link ([[notes/Queue]] -> "notes/"), normalised; "" when the link has none."""
    name = target.strip()
    name = name[:-3] if name.lower().endswith(".md") else name
    return _norm(name.rsplit("/", 1)[0]) + "/" if "/" in name else ""


def _note_index(notes, prefer=None):
    """key -> notes sharing it (title or alias), the preferred folder first: two notes with one stem do not overwrite each other."""
    table = {}
    for note in sorted(notes, key=lambda n: (prefer is not None and not n["path"].startswith(prefer), n["path"])):
        for name in (note["title"], *note.get("aliases", [])):
            table.setdefault(_key(name), []).append(note)
    return table


def _resolve(table, target):
    """The note a wikilink target points to: a folder in the link picks the note in that folder, otherwise the preferred one."""
    found = table.get(_key(target)) or []
    folder = _link_folder(target)
    if folder:
        inside = [n for n in found if _norm(n["path"]).startswith(folder) or ("/" + folder) in _norm(n["path"])]
        found = inside or found
    return found[0] if found else None


def _typed_walk(index, root, max_depth):
    by_title = _note_index(index["notes"], prefer="systems/")
    inbound = {}
    for note in index["notes"]:
        for edge in note["edges"]:
            if edge["layer"] == "structural" and edge["relation"] in INBOUND_RELATIONS:
                owner = _resolve(by_title, edge["target"])
                if owner:
                    inbound.setdefault(owner["path"], []).append(note)

    def neighbours(note):
        for edge in note["edges"]:
            if edge["layer"] == "structural" and edge["relation"] in OUTBOUND_RELATIONS:
                target = _resolve(by_title, edge["target"])
                if target:
                    yield target, edge["relation"]
        for source in inbound.get(note["path"], []):
            yield source, "is part of"

    components, constraints = {}, []
    if root["path"].startswith("systems/"):  # the feature note is itself a resource of the feature (a leaf note has nothing else)
        components[root["path"]] = _component(root, 0, ["matched"])
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
    by_name = _note_index(index["notes"])
    components, frontier, seen = [], [root], {root["path"]}
    if root["inferred_type"] or root["aws_ids"]:
        components.append(_component(root, 0, ["matched"]))
    for depth in range(1, FREE_DEPTH + 1):
        nxt = []
        for node in frontier:
            for link in node["links"]:
                target = _resolve(by_name, link)
                if target and target["path"] not in seen:
                    seen.add(target["path"])
                    nxt.append(target)
                    if target["inferred_type"] or target["aws_ids"]:
                        components.append(_component(target, depth, ["wikilink"]))
        frontier = nxt
    return components


def _mentions_pii(index, notes, paths):
    for note in notes:
        text = " ".join([note["title"], *note["headings"], *note["kv"].values(), _body(index, note, paths)])
        if PII_WORDS.search(_norm(text)):
            return True
    return False


def resolve_feature(index: dict, query: str, max_depth: int = 3) -> dict:
    typed = index["kind"] == "typed"
    result = {"candidates": [], "chosen": None, "components": [], "constraints": [], "pii": False,
              "confidence": "typed" if typed else "inferred"}
    paths = _real_paths(index["root"])
    found = _candidates(index, query, paths)
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
    result["pii"] = _mentions_pii(index, related, paths)
    return result


# ---------------------------------------------------------------- CLI

def _inside(path, folder):
    try:
        path.resolve().relative_to(folder.resolve())
        return True
    except ValueError:
        return False


def _write_atomic(output, text):
    """Encode first, write a temporary file next to the output and rename it: a failure leaves no partial index (and keeps an old one)."""
    data = text.encode("utf-8")
    temp = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        temp.write_bytes(data)
        os.replace(temp, output)
    finally:
        temp.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Vault index and feature resolution (read-only)")
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
            print("the index is not written inside the vault; use another path with -o", file=sys.stderr)
            return 2
        try:
            index = build_index(vault)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        try:
            _write_atomic(output, json.dumps(index, indent=2, ensure_ascii=False) + "\n")
        except (ValueError, OSError) as exc:  # UnicodeEncodeError is a ValueError
            print(f"error: could not write the index to {output}: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
        kind = "Typed vault" if index["kind"] == "typed" else "Free-form (untyped) vault, the component map is inferred and less reliable"
        print(f"{kind}: {len(index['notes'])} notes, {len(index['broken_links'])} broken links, "
              f"{len(index['secrets_detected'])} secrets detected (masked), "
              f"{len(index['sensitive_files'])} sensitive files (name only). Index at: {output}")
        return 0
    index = json.loads(Path(args.index).read_text(encoding="utf-8"))
    print(json.dumps(resolve_feature(index, args.text), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
