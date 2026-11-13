"""Masking of sensitive values before anything is written to disk, stdout or HTML.

- AWS access key ids (AKIA/ASIA + 16 chars) -> first 4 + "…" + last 4
- aws_secret_access_key, secret key and session token assignments -> value replaced by [REDACTED]
- a bare `Secret` label (table cell or `Secret: value`) followed by a value that looks like a key (20+ base64 characters
  with upper case, lower case and a digit, so `secret: /acme/prod/db` is left alone), and `aws configure set <label> <value>`
- credential values behind a label, in any layout a vault uses: `password=x`, `password: x`, table cells (`| DBPassword | x |`),
  compound or camelCase labels (MasterUserPassword, db_password, x-db-password, contraseña), `--master-user-password x`;
  an unquoted password runs to the end of the line (or table cell), a quoted one to its closing quote, so values with spaces
  or punctuation are masked whole. api_key / apikey, token / access_token / auth_token / x-amz-security-token and
  client_secret labels (single word values of 8+ characters), `Bearer <token>` and the password of a URL userinfo
  (`scheme://user:password@host`). References are not secrets and stay as they are: `in Secrets Manager`, `ver ...`,
  `${VAR}`, `{{...}}`, `<...>`, N/A, `-`, empty, `*****`, [REDACTED], ARNs, `ssm:` / `/path` references, `*_file` / `*_path` /
  `*_arn` labels and password-policy settings (length, age, reuse, ...). A table header row (followed by a `|---|` row) is
  never a credential. Not covered: a bare `- password hunter2` with no separator (indistinguishable from prose).
- PEM private-key blocks (BEGIN ... PRIVATE KEY through END, or to the end of the text when unterminated)
- emails -> first char + "***@domain", except those listed in keep_emails (e.g. VantaOwner owners)

`mask_secrets` is `mask` without the email rule. `mask` is idempotent. `mask_obj` applies it to every string value and
every string key of nested dicts/lists/tuples and replaces the value of secret-named keys outright.
`detect` names the secret patterns present in a text (used by vault_index).
"""

import re

REDACTED = "[REDACTED]"
ACCESS_KEY = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")  # no lookarounds: glued or trailing text is still masked
# The match starts at the keyword (no unbounded prefix: that made matching quadratic); prefixes such as "prod_" stay
# in the text, only the value is replaced. Suffix and separators are bounded or only scanned once per keyword.
# Label may be decorated with markdown / escaped JSON quotes and have spaces between words ("Secret Access Key");
# separators are : = or |. Covers aws_secret_access_key, AWS_SECRET_ACCESS_KEY_PROD, SecretAccessKey, secret_key, session_token...
_LABEL = r"(?:secret[_ -]?(?:access[_ -]?)?key|session[_ -]?token)"
SECRET_ASSIGNMENT = re.compile(
    rf"(?i)(?<![:/])({_LABEL}\w{{0,40}}(?:[ \t]*\([^)\n|]{{0,30}}\))?)"
    r"""([*`'"\\ \t]*[:=|][*`'"\\ \t]*)[^\s"',;|`*\\]+""")
# Bare `Secret` label: the value must look like a key, otherwise "| Secret | Rotación |" or "secret: /acme/prod/db" would match.
# The lookaheads are bounded ({0,200}): unbounded they rescan the rest of the line at every "secret" (quadratic).
# `(?<!\d{12}:)` leaves Secrets Manager ARNs (...:111122223333:secret:name) alone.
_KEYLIKE = (r"(?=[A-Za-z0-9/+=]{0,200}\d)(?=[A-Za-z0-9/+=]{0,200}[a-z])(?=[A-Za-z0-9/+=]{0,200}[A-Z])"
            r"[A-Za-z0-9/+=]{20,}")
BARE_SECRET = re.compile(
    r"(?i)(?<![\w-])(?<!\d{12}:)(secret)"
    rf"""([*`'"\\ \t]*[:=|][*`'"\\ \t]*){_KEYLIKE}""")
# `aws configure set [flags] <label> <value>`: the value is separated by a space
CONFIGURE_SET = re.compile(
    rf"(?i)(\bconfigure[ \t]+set[ \t]+(?:[^\s]+[ \t]+){{0,3}}?\w{{0,20}}{_LABEL}\w{{0,40}}[ \t]+)(?!-)[^\s\"',;|`*\\]+")
# CLI form: --secret-access-key <value> (the "=" form is covered above)
CLI_FLAG = re.compile(rf"(?i)(--{_LABEL}[ \t]+)(?!-)[^\s\"',;|`*\\]+")

# ---- labelled credentials (passwords, api keys, tokens, client secrets). Everything here is line oriented and linear: the label
# regex has bounded prefix/suffix, values are located with str.find or a single regex match, and the scan resumes after each match.
_CRED_WORD = r"(?:password|passwd|pwd|contrase[ñn]a|api[_ -]?key|apikey|token|client[_ -]?secret)"
CRED_LABEL = re.compile(
    rf"(?i)({_CRED_WORD}[A-Za-z0-9_-]{{0,20}})([*`'\"\\ \t]*[:=|][ \t*]*)")
_LABEL_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
CLI_PASSWORD = re.compile(r"(?i)(?<![\w-])(--[A-Za-z0-9-]{0,40}(?:password|passwd|pwd)[A-Za-z0-9-]{0,10})([ \t]+)(?=[^\s-])")
BEARER = re.compile(r"(?i)(?<![\w-])(bearer[ \t]+)([A-Za-z0-9._~+/=-]{8,})")
URL_USERINFO = re.compile(r"(?i)(?<![\w+.-])([a-z][a-z0-9+.-]{1,15}://[^\s:/@?#\[\]]{1,64}:)([^\s/@]{1,200})(?=@)")
SEPARATOR_LINE = re.compile(r"\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*|\s*\|\s*:?-{2,}:?\s*\|?\s*")
_OPENING_QUOTE = re.compile(r"""\\*["'`]""")
_WORD_VALUE = re.compile(r"""[^\s"',;|`*\\]*""")
_SHELL_WORD = re.compile(r"""[^\s;|&]+""")
_LABEL_TOKEN = re.compile(r"[A-Z]+(?![^\W\d_A-Z])|[A-Z]?[^\W\d_A-Z]+|\d+")
PASSWORD_WORDS = frozenset({"password", "passwd", "pwd", "contraseña", "contrasena"})
# a label with one of these words is a setting, a location or a status, not a secret (password_policy, PasswordFile, ...)
NOT_SECRET_WORDS = frozenset({
    "policy", "policies", "length", "age", "expiry", "expiration", "expire", "expires", "expired", "complexity", "reuse", "history",
    "rotation", "rotate", "rotated", "min", "minimum", "max", "maximum", "require", "required", "requires", "enable", "enabled",
    "allow", "allowed", "lockout", "attempts", "strength", "last", "changed", "next", "used", "reset", "file", "path", "arn", "ref",
    "name", "url", "hint", "prompt", "type", "field", "label", "setting", "settings", "count", "status", "state", "version", "id",
    "manager"})
# first word of a value that describes where the secret lives, not the secret ("in Secrets Manager", "ver ...", "rotated ...")
REFERENCE_WORDS = frozenset({
    "in", "en", "ver", "see", "via", "vía", "from", "desde", "stored", "guardada", "guardado", "managed", "gestionada", "gestionado",
    "rotated", "rotada", "rotado", "rotation", "rotación", "rotacion", "rota", "rotates", "policy", "política", "politica",
    "enforced", "enabled", "habilitada", "habilitado", "required", "requerida", "requerido", "n/a", "none", "ninguna", "ninguno",
    "no", "yes", "si", "sí", "ssm", "secrets", "secret", "aws", "kms", "vault", "generated", "generada", "generado", "cada", "every",
    "unknown", "desconocida", "tbd", "pending", "pendiente", "placeholder", "redacted"})
REFERENCE_VALUE = re.compile(
    r"""(?ix)\A(?:
      [-–—.…?*_#x]*
      | n/?a | nul+ | nil | tbd | todo
      | \[redacted\] | \[\.\.\.\] | \$\{[^}]*\} | \$[A-Z_][A-Z0-9_]* | \$\([^)]*\) | %[A-Za-z_]+% | \{\{.*\}\} | \{[^{}]*\} | <[^<>]*>
      | arn:aws[a-z-]*:.* | (?:ssm|secretsmanager|secrets-manager|aws-secretsmanager|vault|kms):.* | /[\w./@+=:-]+
    )\Z""")
URL_PLACEHOLDERS = frozenset({"password", "pass", "pwd", "secret", "passwd", "user", "token"})


def _label_tokens(label):
    return [t.lower() for t in _LABEL_TOKEN.findall(label)]


def _family(tokens):
    """password | token | api_key | client_secret for a credential label, None for settings, locations and unrelated labels."""
    if any(t in PASSWORD_WORDS for t in tokens):
        return None if NOT_SECRET_WORDS.intersection(tokens) else "password"
    if tokens[-1:] == ["token"]:
        return "token"
    if tokens[-1:] == ["apikey"] or tokens[-2:] == ["api", "key"]:
        return "api_key"
    if tokens[-2:] == ["client", "secret"]:
        return "client_secret"
    return None


def is_secret_label(label):
    """True for a key or label that names a credential (DBPassword, api_key, access_token, client_secret, SecretAccessKey...)."""
    return label.lower() in SECRET_KEYS or _family(_label_tokens(label)) is not None


def _full_label(line, match):
    """The matched keyword with the identifier characters before it (at most 40): DB_ + PASSWORD, Master + User + Password."""
    start, floor = match.start(), max(0, match.start() - 40)
    while start > floor and line[start - 1] in _LABEL_CHARS:
        start -= 1
    return line[start:match.end(1)]


def _is_reference(value):
    value = value.strip()
    if REFERENCE_VALUE.match(value):
        return True
    word = re.match(r"[^\W\d_]+(?:/[^\W\d_]+)?", value)
    return bool(word) and word.group(0).lower() in REFERENCE_WORDS and (len(word.group(0)) == len(value) or not value[len(word.group(0))].isalnum())


def _closing(line, start, opener):
    """Index of the quote that closes a value opened by `opener` (backslashes + quote), or None."""
    quote = opener[-1]
    index = line.find(opener, start)
    while index > 0 and len(opener) == 1 and line[index - 1] == "\\":
        index = line.find(opener, index + 1)
    return None if index == -1 else index


def _value_span(line, pos, family, bar_ends):
    """(start, end) of the value that begins at pos, or None when there is none. Unquoted passwords run to the end of the line (or the
    table cell); the other families take one word. Trailing decoration (spaces, ** and backticks of the markdown) is not part of it."""
    opener = _OPENING_QUOTE.match(line, pos)
    if opener:
        start = opener.end()
        end = _closing(line, start, opener.group(0))
        return start, len(line) if end is None else end
    if family == "password":
        end = line.find("|", pos) if bar_ends else -1
        end = len(line) if end == -1 else end
    else:
        end = _WORD_VALUE.match(line, pos).end()
    while end > pos and line[end - 1] in " \t*`\r":
        end -= 1
    return pos, end


def _secret_value(value, family):
    if _is_reference(value):
        return False
    if family == "password":
        return True
    # tokens, api keys and client secrets: one word of 8+ characters that is not an ordinary word
    return len(value) >= 8 and not any(c.isspace() for c in value) and not (value.isalpha() and value.islower())


def _scan_line(line):
    """[(start, end, pattern)] of the credential values in one line, in order and not overlapping."""
    found = []
    table = line.lstrip().startswith("|")
    position = 0
    while match := CRED_LABEL.search(line, position):
        position = match.end()
        family = _family(_label_tokens(_full_label(line, match)))
        span = _value_span(line, match.end(), family, table or "|" in match.group(2)) if family else None
        if span and span[0] < span[1] and _secret_value(line[span[0]:span[1]], family):
            found.append((span[0], span[1], family))
            position = span[1]
    position = 0
    while match := CLI_PASSWORD.search(line, position):
        position = match.end()
        if _family(_label_tokens(match.group(1))) != "password":
            continue
        opener = _OPENING_QUOTE.match(line, position)
        if opener:
            start = opener.end()
            end = _closing(line, start, opener.group(0))
            end = len(line) if end is None else end
        else:
            start, end = position, _SHELL_WORD.match(line, position).end()
        if start < end and not _is_reference(line[start:end]):
            found.append((start, end, "password"))
        position = max(position, end)
    for match in BEARER.finditer(line):
        value = match.group(2)
        if (any(c.isdigit() for c in value) or "." in value) and not _is_reference(value):
            found.append((match.start(2), match.end(2), "bearer_token"))
    for match in URL_USERINFO.finditer(line):
        value = match.group(2)
        if value.lower() not in URL_PLACEHOLDERS and not _is_reference(value):
            found.append((match.start(2), match.end(2), "url_credentials"))
    found.sort()
    kept, last = [], 0
    for start, end, name in found:
        if start >= last:
            kept.append((start, end, name))
            last = end
    return kept


def _scan(text):
    """Yields (line, [(start, end, pattern)]) for the lines of text that hold credential values; table header rows are skipped."""
    lines = text.split("\n")
    for number, line in enumerate(lines):
        if len(line) < 4:
            continue
        if "|" in line and number + 1 < len(lines) and "|" in lines[number + 1] and SEPARATOR_LINE.fullmatch(lines[number + 1]):
            continue
        spans = _scan_line(line)
        if spans:
            yield number, line, spans


def _mask_credentials(text):
    lines = text.split("\n")
    for number, line, spans in _scan(text):
        out, last = [], 0
        for start, end, _ in spans:
            out += [line[last:start], REDACTED]
            last = end
        lines[number] = "".join(out) + line[last:]
    return "\n".join(lines)

PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----.*?(?:-----END [A-Z ]{0,30}PRIVATE KEY-----|\Z)", re.S)
EMAIL = re.compile(r"(?<![\w.+%\]-])([A-Za-z0-9._%+-]+)@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
SECRET_KEYS = frozenset({"secretaccesskey", "aws_secret_access_key", "secret_access_key", "sessiontoken",
                         "session_token", "aws_session_token", "password", "passwd", "pwd"})


def mask_secrets(text: str) -> str:
    """Access keys and secret/session-token assignments only (for identifiers that may legitimately hold emails)."""
    text = PRIVATE_KEY.sub(REDACTED, text)
    text = ACCESS_KEY.sub(lambda m: m.group(0)[:4] + "…" + m.group(0)[-4:], text)
    text = SECRET_ASSIGNMENT.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)
    text = BARE_SECRET.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)
    text = _mask_credentials(text)
    text = CONFIGURE_SET.sub(lambda m: m.group(1) + REDACTED, text)
    return CLI_FLAG.sub(lambda m: m.group(1) + REDACTED, text)


def detect(text: str) -> list[str]:
    """Names of the secret patterns present in text (never the values): aws_access_key_id, aws_secret_access_key,
    aws_session_token, password, api_key, token, client_secret, bearer_token, url_credentials, private_key."""
    found = []
    if ACCESS_KEY.search(text):
        found.append("aws_access_key_id")
    labelled = (*SECRET_ASSIGNMENT.finditer(text), *CONFIGURE_SET.finditer(text), *CLI_FLAG.finditer(text), *BARE_SECRET.finditer(text))
    for match in labelled:
        name = "aws_session_token" if "session" in match.group(1).lower() else "aws_secret_access_key"
        if name not in found:
            found.append(name)
    for _, _, spans in _scan(text):
        found += [name for _, _, name in spans if name not in found]
    if PRIVATE_KEY.search(text):
        found.append("private_key")
    return found


def mask(text: str, *, keep_emails: frozenset[str] = frozenset()) -> str:
    keep = {e.lower() for e in keep_emails}

    def email(match):
        if match.group(0).lower() in keep:
            return match.group(0)
        return f"{match.group(1)[0]}***@{match.group(2)}"

    return EMAIL.sub(email, mask_secrets(text))


def _secret_key(key):
    return isinstance(key, str) and is_secret_label(key)


def _unique(key, taken):
    """A key that two different keys masked to (a***@x.com) must not overwrite the other one."""
    if key not in taken:
        return key
    number = 2
    while f"{key}#{number}" in taken:
        number += 1
    return f"{key}#{number}"


def _tag_value_is_secret(obj):
    """`{"Key": "DBPassword", "Value": "..."}` tag pairs (AWS CLI output) hold the secret in a sibling of the label."""
    keys = {k.lower(): k for k in obj if isinstance(k, str)}
    return "key" in keys and "value" in keys and _secret_key(obj[keys["key"]]) and isinstance(obj[keys["value"]], str), keys.get("value")


def mask_obj(obj, **kw):
    if isinstance(obj, str):
        return mask(obj, **kw)
    if isinstance(obj, dict):
        tag_secret, value_key = _tag_value_is_secret(obj)
        out = {}
        for k, v in obj.items():
            redact_value = isinstance(v, str) and (_secret_key(k) or (tag_secret and k == value_key))
            out[_unique(mask(k, **kw) if isinstance(k, str) else k, out)] = REDACTED if redact_value else mask_obj(v, **kw)
        return out
    if isinstance(obj, (list, tuple)):
        return [mask_obj(v, **kw) for v in obj]
    return obj
