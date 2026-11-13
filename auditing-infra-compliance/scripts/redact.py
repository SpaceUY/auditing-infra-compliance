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
  `${VAR}`, `{{...}}`, `<...>`, N/A, `-`, empty, `*****`, [REDACTED], ARNs, `ssm:` / `/multi/segment/path` references, IaC references
  (`!Ref X`, `!GetAtt`, `var.x`, `data.aws_...`, `module.x`), `[[wiki links]]`, booleans (true, no, enabled, disabled...), phrases that
  say where the secret lives ("stored in / almacenada en / se guarda en Secrets Manager", Parameter Store, Vault, 1Password) and
  `*_file` / `*_path` / `*_arn` / `manage*` / `*authentication` labels and password-policy settings (length, age, reuse, ...). A value
  is a reference only as a whole: a reference word followed by punctuation (`Secret-Admin-2024!`) or `/hunter2` is a password.
  A table header row (followed by a separator row: only `|`, `-`, `:` and spaces, checked cell by cell) is never a credential. The body
  rows below a Password / Contraseña / Passwd / Pwd header are masked in that column unless the cell is a reference (see above, any phrase
  that names a secret store, `alias/...`, a slash-separated secret NAME that is not key-like); a Clave / Secret / Token / API key column
  is ambiguous (names, key aliases, descriptions) and is masked only when the value is key-like (20+ characters with upper, lower and a
  digit, or 32+ letters and digits). A `Clave | Valor` table is a key-value list and is left alone. Not covered: a bare `- password hunter2` with no
  separator (indistinguishable from prose). Every scan is linear: the value of a label is examined once and the scan resumes after it.
- more labels: pass / DB_PASS / passphrase (password family), contraseña / password / pwd followed by a connector and up to 3 words
  (`contraseña de root:`, `password for the db:`), private_key, psk, auth_key (one word values of 8+ characters), clave / clave secreta
  (one word, 8+ characters, not a plain lowercase word); a bare `pass` or `clave` only with ":" or "=" (never in a table cell) and a
  bare `pass` never with a number ("pass: 12" is a count). `AWS_SECRET_ACCESS_KEY <value>` / `secret_key <value>` separated by a space
  (the value must be key-like).
- token shapes without any label (TOKEN_SHAPES): GitHub ghp_/gho_/ghu_/ghs_/ghr_ and github_pat_, Slack xoxa/b/p/r/s tokens and
  `hooks.slack.com/services/...` webhooks, Stripe sk_live_ / rk_live_, Google AIza keys, JWTs (three dot-separated segments, the first
  two starting with eyJ), STS session tokens (FwoGZXIvYXdz..., IQoJb3JpZ2lu...)
- command lines and headers: `curl -u user:pass` / `--user`, `mysql... -pPASS` (glued), `sshpass -p PASS`, `Authorization: Basic <b64>`;
  placeholders (`user:password`) and references (`$PASS`) are not credentials
- PEM private-key blocks (BEGIN ... PRIVATE KEY through END, or to the end of the text when unterminated)
- emails -> first char + "***@domain", except those listed in keep_emails (e.g. VantaOwner owners)

`mask_secrets` is `mask` without the email rule. `mask` is idempotent. `mask_obj` applies it to every string value and
every string key of nested dicts/lists/tuples and replaces the value of secret-named keys outright (strings and whole containers), as
well as the Value of name/value pairs whose name is secret (Key/Value, Name/Value, OptionName/Value, ParameterKey/ParameterValue,
Variable/Value).
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
# `AWS_SECRET_ACCESS_KEY <value>` / `secret_key <value>` separated by a space only: the value must look like a key (as for the bare
# `Secret` label), otherwise "secret key rotation ..." would match. Scoped flag: the lookaheads of _KEYLIKE are case sensitive.
SPACE_SECRET = re.compile(rf"(?<![\w-])((?i:(?:aws[_-]?)?secret[_-]?(?:access[_-]?)?key)[ \t]+){_KEYLIKE}")

# Well-known token shapes, masked and detected without any label. Every pattern is linear: a literal prefix, then one character class
# run (a failed attempt scans less than the minimum length), or a lookbehind that keeps the start of a long run from being retried
# inside it (JWT segments).
TOKEN_SHAPES = (
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{50,}")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("stripe_key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("jwt", re.compile(r"(?<![\w-])eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]{8,}")),
    ("aws_session_token", re.compile(r"(?<![A-Za-z0-9/+=])(?:FwoGZXIvYXdz|IQoJb3JpZ2lu)[A-Za-z0-9/+=]{80,}")),
    ("slack_webhook", re.compile(r"(?<=hooks\.slack\.com/services/)[A-Za-z0-9_/-]{8,}")),
)

# ---- labelled credentials (passwords, api keys, tokens, client secrets). Everything here is line oriented and linear: the label
# regex has bounded prefix/suffix, values are located with str.find or a single regex match, and the scan resumes after each match.
# Password words may be followed by a connector and up to 3 words before the separator ("contraseña de root:", "password for the db:");
# the connector keeps prose such as "password in the vault:" out. `pass` and `clave` are weak labels (see _family): the scan only
# accepts them with a ":" or "=" separator.
_WORD_TAIL = r"[A-Za-z0-9_-]{0,20}"
_CRED_WORD = (rf"(?:(?:password|passwd|pwd|passphrase|contrase[ñn]a){_WORD_TAIL}"  # flat alternatives: the regex engine can skip by first letter
              r"(?:[ \t]+(?:de|del|para|for|of)(?:[ \t]+[A-Za-z0-9_-]{1,20}){1,3})?"
              rf"|pass{_WORD_TAIL}|api[_ -]?key{_WORD_TAIL}|apikey{_WORD_TAIL}|token{_WORD_TAIL}|client[_ -]?secret{_WORD_TAIL}"
              rf"|private[_-]?key{_WORD_TAIL}|psk{_WORD_TAIL}|auth[_-]?key{_WORD_TAIL}|clave{_WORD_TAIL}(?:[ \t]+secreta)?)")
CRED_LABEL = re.compile(
    rf"(?i)({_CRED_WORD})([*`'\"\\ \t]*[:=|][ \t*]*)")
_LABEL_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
CLI_PASSWORD = re.compile(r"(?i)(?<![\w-])(--[A-Za-z0-9-]{0,40}(?:password|passwd|pwd)[A-Za-z0-9-]{0,10})([ \t]+)(?=[^\s-])")
BEARER = re.compile(r"(?i)(?<![\w-])(bearer[ \t]+)([A-Za-z0-9._~+/=-]{8,})")
URL_USERINFO = re.compile(r"(?i)(?<![\w+.-])([a-z][a-z0-9+.-]{1,15}://[^\s:/@?#\[\]]{1,64}:)([^\s/@]{1,200})(?=@)")
_CLI_VALUE = r"""(?:"([^"\n]*)"|'([^'\n]*)'|([^\s"']+))"""
BASIC_AUTH = re.compile(r"""(?i)(?<![\w-])authorization["']?[ \t]*[:=][ \t]*["']?basic[ \t]+([A-Za-z0-9+/=]{8,})""")
CURL_USER = re.compile(rf"""(?<![\w-])(?:-u|--user)(?:[ \t]+|=)["']?[^\s:"']{{1,64}}:{_CLI_VALUE}""")
SSHPASS_P = re.compile(rf"""(?i)(?<![\w-])sshpass[ \t]+-p[ \t]*{_CLI_VALUE}""")
MYSQL_P = re.compile(r"""(?<=[ \t])-p(?:"([^"\n]*)"|'([^'\n]*)'|([^\s"'-][^\s"']*))""")
_PATTERN_NAMES = {"clave": "password"}  # pattern name reported by detect() when it differs from the label family
_OPENING_QUOTE = re.compile(r"""\\*["'`]""")
_WORD_VALUE = re.compile(r"""[^\s"',;|`*\\]*""")
_SHELL_WORD = re.compile(r"""[^\s;|&]+""")
_LABEL_TOKEN = re.compile(r"[A-Z]+(?![^\W\d_A-Z])|[A-Z]?[^\W\d_A-Z]+|\d+")
PASSWORD_WORDS = frozenset({"password", "passwd", "pwd", "passphrase", "contraseña", "contrasena"})
# a label with one of these words is a setting, a location or a status, not a secret (password_policy, PasswordFile, ...)
NOT_SECRET_WORDS = frozenset({
    "policy", "policies", "length", "age", "expiry", "expiration", "expire", "expires", "expired", "complexity", "reuse", "history",
    "rotation", "rotate", "rotated", "min", "minimum", "max", "maximum", "require", "required", "requires", "enable", "enabled",
    "allow", "allowed", "lockout", "attempts", "strength", "last", "changed", "next", "used", "reset", "file", "path", "arn", "ref",
    "name", "url", "hint", "prompt", "type", "field", "label", "setting", "settings", "count", "status", "state", "version", "id",
    "manager", "manage", "manages", "authentication"})
# A value that only says where the secret lives (or that there is none) is a reference. Every word of the value must be one of these
# (or a number followed by a time unit), or the value must start with a "stored in" lead word and name a store: a reference word
# followed by anything else ("Secret-Admin-2024!") is a password.
REFERENCE_VOCABULARY = frozenset({
    "in", "en", "at", "ver", "see", "via", "vía", "from", "desde", "por", "by", "with", "con", "to", "para", "the", "a", "an", "el", "la", "los", "las",
    "y", "e", "o", "u", "and", "or", "of", "de", "del", "se", "es", "is", "are", "esta", "está", "cuando", "when", "if", "si", "sí",
    "stored", "store", "storage", "kept", "held", "managed", "manual", "manually", "automatic", "automatically", "automática", "automático",
    "automaticamente", "automáticamente", "guarda", "guardada", "guardado", "guardan", "almacenada", "almacenado", "almacena", "gestionada",
    "gestionado", "gestiona", "rotated", "rotada", "rotado", "rota", "rotates", "rotation", "rotación", "rotacion", "cada", "every", "days",
    "day", "días", "dias", "día", "dia", "weeks", "semanas", "months", "meses", "mes", "years", "años", "policy", "política", "politica",
    "enforced", "required", "requerida", "requerido", "enabled", "disabled", "habilitada", "habilitado", "deshabilitada", "deshabilitado",
    "activada", "activado", "desactivada", "desactivado", "on", "off", "true", "false", "yes", "no", "not", "nunca", "never", "ninguna",
    "ninguno", "none", "n/a", "n/d", "na", "nd", "unknown", "desconocida", "desconocido", "tbd", "todo", "pending", "pendiente",
    "placeholder", "redacted", "secrets", "secretos", "gestor", "secretsmanager", "manager", "parameter", "ssm", "kms", "aws", "vault", "hashicorp", "1password",
    "bitwarden", "lastpass", "keeper", "sops", "doppler", "generated", "generada", "generado", "cuenta", "account"})
STORE_WORDS = frozenset({"secrets", "secretos", "gestor", "secretsmanager", "manager", "parameter", "ssm", "vault", "1password", "bitwarden", "lastpass",
                         "keeper", "sops", "doppler", "kms"})
LEAD_WORDS = frozenset({"in", "en", "ver", "see", "via", "vía", "from", "desde", "stored", "se", "guarda", "guardada", "guardado", "almacenada",
                        "almacenado", "managed", "gestionada", "gestionado", "rotated", "rotada", "rotado", "at", "por", "by"})
TIME_UNITS = frozenset({"days", "day", "días", "dias", "día", "dia", "weeks", "semanas", "months", "meses", "mes", "years", "años", "h", "min"})
MAX_REFERENCE_WORDS = 40
_PATH_SEGMENT = r"[\w.@+=:-]+"
REFERENCE_VALUE = re.compile(
    rf"""(?ix)\A(?:
      [-–—.…?*_#x]*
      | n/?a | nul+ | nil | tbd | todo
      | \[redacted\] | \[\.\.\.\] | (?:[\w./-]*\$\{{[^}}]*\}})+[\w./-]* | \$[A-Z_][A-Z0-9_]* | \$\([^)]*\) | %[A-Za-z_]+% | \{{\{{.*\}}\}} | \{{[^{{}}]*\}} | <[^<>]*>
      | arn:aws[a-z-]*:.* | (?:ssm|secretsmanager|secrets-manager|aws-secretsmanager|vault|kms):.*
      | /{_PATH_SEGMENT}(?:/{_PATH_SEGMENT})+/?
      | !(?:ref|getatt|sub|importvalue|join|select|findinmap|if|base64|split|vault|secret|env|env_var|include|reference)\b(?:[ \t].*)?
      | fn::\w+.*
      | (?:var|local|module|data|each|self|path)\.[\w.\[\]"*-]+ | aws_\w+\.[\w.\[\]*-]+
      | (?:\[\[[^\]]*\]\][ \t,]*)+ | \[[^\]]*\]\([^)]*\)
    )\Z""")
# Every label form the scanners recognise (used by the timing tests: each one is combined with each reference prefix) and the
# beginnings of the reference values they skip.
LABEL_FORMS = ("password", "passwd", "pwd", "contraseña", "contrasena", "api_key", "api key", "apikey", "token", "client_secret",
               "client secret", "DBPassword", "MasterUserPassword", "access_token", "x-amz-security-token", "aws_secret_access_key",
               "SecretAccessKey", "session_token", "secret", "--master-user-password", "DB_PASS", "private_key", "clave secreta",
               "contraseña de root")
REFERENCE_PREFIXES = ("/", "$", "${", "{{", "<", "[[", "arn:", "ssm:", "!Ref", "var.", "data.aws_", "module.", "en Secrets Manager",
                      "in Secrets Manager", "stored in", "almacenada en", "se guarda en", "guardada en", "Parameter Store", "Vault",
                      "1Password", "true", "N/A", "-", "(en")
URL_PLACEHOLDERS = frozenset({"password", "pass", "pwd", "secret", "passwd", "user", "token"})


def _is_separator(line):
    """True for a markdown table separator row (`|---|---|`, `|-|-|`, `|:-:|`, `| --- |`, `---|---`): it has a pipe and every cell
    between pipes is dashes with optional colons at the ends. One pass of str operations, no backtracking."""
    if "|" not in line:
        return False
    cells = line.split("|")
    if not cells[0].strip():
        cells = cells[1:]
    if cells and not cells[-1].strip():
        cells = cells[:-1]
    return bool(cells) and all(_is_separator_cell(cell) for cell in cells)


def _is_separator_cell(cell):
    core = cell.strip().removeprefix(":").removesuffix(":")
    return bool(core) and not core.strip("-")


def _label_tokens(label):
    return [t.lower() for t in _LABEL_TOKEN.findall(label)]


def _family(tokens, loose=False):
    """password | token | api_key | client_secret | private_key | psk (| clave when loose) for a credential label, None for settings,
    locations and unrelated labels. A bare `pass` or `clave` is only a credential label in running text (loose): DB_PASS is one
    anywhere, but a table cell "pass" is a test result and a key named `clave` is a Spanish word."""
    if any(t in PASSWORD_WORDS for t in tokens) or (tokens[-1:] == ["pass"] and (loose or len(tokens) > 1)):
        return None if NOT_SECRET_WORDS.intersection(tokens) else "password"
    if tokens[-1:] == ["token"]:
        return "token"
    if tokens[-1:] in (["apikey"], ["authkey"]) or tokens[-2:] in (["api", "key"], ["auth", "key"]):
        return "api_key"
    if tokens[-2:] == ["client", "secret"]:
        return "client_secret"
    if tokens[-2:] == ["private", "key"]:
        return "private_key"
    if tokens[-1:] == ["psk"]:
        return "psk"
    if loose and tokens in (["clave"], ["clave", "secreta"]):
        return "clave"
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


_WORD_EDGE = "()[]{}.,;:!¡¿?\"'*`_"


def _is_reference(value):
    """True when the whole value only says where the secret lives (or that there is none): a reference form (REFERENCE_VALUE) or a
    phrase made of reference words only, or one that starts with a "stored in" lead word and names a store. At most MAX_REFERENCE_WORDS
    words are looked at, so the test is linear in the value."""
    value = value.strip()
    if REFERENCE_VALUE.match(value):
        return True
    words = value.split(None, MAX_REFERENCE_WORDS + 1)
    if len(words) > MAX_REFERENCE_WORDS:
        return False
    tokens = [w.strip(_WORD_EDGE).lower() for w in words]
    tokens = [t for t in tokens if t]
    if not tokens:
        return False
    if tokens[0] in LEAD_WORDS and STORE_WORDS.intersection(tokens):
        return True
    for index, token in enumerate(tokens):
        if token in REFERENCE_VOCABULARY:
            continue
        if token.isdigit() and index + 1 < len(tokens) and tokens[index + 1] in TIME_UNITS:
            continue
        return False
    return True


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


def _cli_spans(line):
    """Credentials given on a command line or in an Authorization header: `curl -u user:pass`, `mysql -u root -pPASS`, `sshpass -p PASS`
    and `Authorization: Basic <base64>`. The command word only gates the scan (the flag regexes themselves are anchored on the flag), so
    every pattern is linear; placeholders (`user:password`) and references (`$PASS`, `${DB_PASS}`) are not credentials."""
    found = []
    lower = line.lower()
    sources = []
    if "authorization" in lower:
        sources.append((BASIC_AUTH, 0, "basic_auth"))
    if "sshpass" in lower:
        sources.append((SSHPASS_P, 0, "password"))
    if (at := lower.find("curl")) != -1:
        sources.append((CURL_USER, at, "password"))
    if (at := lower.find("mysql")) != -1:
        sources.append((MYSQL_P, at, "password"))
    for regex, start, name in sources:
        for match in regex.finditer(line, start):
            group = next((g for g in range(1, regex.groups + 1) if match.group(g) is not None), None)
            value = match.group(group) if group else None
            if value and value.lower() not in URL_PLACEHOLDERS and not _is_reference(value):
                found.append((match.start(group), match.end(group), name))
    return found


def _scan_line(line, extra=()):
    """[(start, end, pattern)] of the credential values in one line, in order and not overlapping (extra: spans found by the caller)."""
    found = list(extra)
    table = line.lstrip().startswith("|")
    position = 0
    while match := CRED_LABEL.search(line, position):
        position = match.end()
        tokens = _label_tokens(_full_label(line, match))
        family = _family(tokens, "|" not in match.group(2))
        span = _value_span(line, match.end(), family, table or "|" in match.group(2)) if family else None
        if span and span[0] < span[1]:
            position = span[1]  # the value is examined once, whatever it is: resuming inside it made long values quadratic
            value = line[span[0]:span[1]]
            if _secret_value(value, family) and not (tokens == ["pass"] and value.isdigit()):  # "pass: 12" is a count
                found.append((span[0], span[1], _PATTERN_NAMES.get(family, family)))
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
    found += _cli_spans(line)
    found.sort()
    kept, last = [], 0
    for start, end, name in found:
        if start >= last:
            kept.append((start, end, name))
            last = end
    return kept


def _cells(line):
    """[(start, end)] of the cells of a table row, trimmed of spaces, ** and backticks; the outer pipes are optional."""
    bars, index = [], line.find("|")
    while index != -1:
        if index == 0 or line[index - 1] != "\\":
            bars.append(index)
        index = line.find("|", index + 1)
    if not bars:
        return [_trim(line, 0, len(line))]
    edges = [-1] + bars + [len(line)]
    segments = [(edges[n] + 1, edges[n + 1]) for n in range(len(edges) - 1)]
    if not line[:bars[0]].strip():
        segments = segments[1:]
    if segments and not line[bars[-1] + 1:].strip():
        segments = segments[:-1]
    return [_trim(line, start, end) for start, end in segments]


def _trim(line, start, end):
    while start < end and line[start] in " \t*`":
        start += 1
    while end > start and line[end - 1] in " \t*`\r":
        end -= 1
    return start, end


KEY_VALUE_HEADERS = frozenset({"valor", "value", "valores", "values"})


def _column_kind(cell):
    """password | clave | secret | token | api_key | client_secret for the header cell of a credential column, else None."""
    tokens = _label_tokens(cell)
    if not tokens:
        return None
    family = _family(tokens)
    if family:
        return family
    if NOT_SECRET_WORDS.intersection(tokens):
        return None
    if tokens[-1] == "clave":
        return "clave"
    if tokens[-1] in ("secret", "secreto") or tokens[-2:] == ["secret", "key"]:
        return "secret"
    return None


def _table_columns(line):
    """{column index: kind} for the credential columns of a header row; {} when it has none (or is a key-value list)."""
    cells = [line[start:end] for start, end in _cells(line)]
    kinds = {number: kind for number, text in enumerate(cells) if (kind := _column_kind(text))}
    if any(_label_tokens(text) in (["valor"], ["value"]) for text in cells):
        kinds = {number: kind for number, kind in kinds.items() if kind != "clave"}
    return kinds


_KEYLIKE_CELL = re.compile(_KEYLIKE)
_LONG_ALNUM = re.compile(r"[A-Za-z0-9]{32,}")
_SECRET_NAME_PATH = re.compile(rf"/?{_PATH_SEGMENT}(?:/{_PATH_SEGMENT})+/?")
_STORE_MENTION = re.compile(r"(?i)(?<![\w-])(?:secrets?[ -]?manager|secretsmanager|parameter[ -]store|vault|1password)(?![\w-])")
_AMBIGUOUS_COLUMNS = ("clave", "secret", "token", "api_key", "client_secret", "private_key", "psk")


def _is_key_like(value):
    """A long mixed-class token (the heuristic of the bare `Secret` label) or 32+ letters and digits with a digit."""
    return bool(_KEYLIKE_CELL.fullmatch(value) or (_LONG_ALNUM.fullmatch(value) and any(c.isdigit() for c in value)))


def _is_cell_reference(value):
    """What a Password column holds when it is not a password: a reference form, a phrase that mentions a secret store, `alias/...`,
    or the NAME of a secret (`prod/rds/master`, no spaces, slash separated, not key-like)."""
    if _is_reference(value):
        return True
    if any(c.isspace() for c in value) and _STORE_MENTION.search(value):
        return True
    if value.startswith("alias/"):
        return True
    return bool(_SECRET_NAME_PATH.fullmatch(value)) and not _is_key_like(value)  # a real key may contain slashes


def _column_spans(line, columns):
    """[(start, end, pattern)] of the credential cells of a table body row. A Password column is masked unless the cell is a reference;
    Clave, Secret, Token and API key columns are ambiguous (names, key aliases, descriptions): masked only when the value is key-like."""
    found, cells = [], _cells(line)
    for number, kind in columns.items():
        if number >= len(cells):
            continue
        start, end = cells[number]
        value = line[start:end]
        if start == end or _is_label_cell(value) or _is_cell_reference(value):
            continue
        if kind == "password" or (kind in _AMBIGUOUS_COLUMNS and _is_key_like(value)):
            found.append((start, end, kind if kind in ("token", "api_key", "client_secret", "private_key", "psk") else "password"))
    return found


def _is_label_cell(value):
    return len(value) <= 60 and _column_kind(value) is not None


def _scan(text):
    """Yields (line number, line, [(start, end, pattern)]) for the lines of text that hold credential values. A table header row is
    never a credential; the body rows below a header with a credential column (Password, Contraseña, Clave, Secret, Token, API key)
    have that column masked."""
    lines = text.split("\n")
    columns = {}
    for number, line in enumerate(lines):
        if "|" not in line:
            columns = {}
        if len(line) < 4:
            continue
        if "|" in line and number + 1 < len(lines) and "|" in lines[number + 1] and _is_separator(lines[number + 1]):
            columns = _table_columns(line)
            continue
        extra = _column_spans(line, columns) if columns and "|" in line and not _is_separator(line) else []
        spans = _scan_line(line, extra)
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
    """Credentials without the email rule (for identifiers that may legitimately hold emails): access keys, secret/session-token
    assignments, well-known token shapes (TOKEN_SHAPES), labelled passwords and CLI credentials, PEM private keys."""
    text = PRIVATE_KEY.sub(REDACTED, text)
    text = ACCESS_KEY.sub(lambda m: m.group(0)[:4] + "…" + m.group(0)[-4:], text)
    text = SECRET_ASSIGNMENT.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)
    text = BARE_SECRET.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)
    text = SPACE_SECRET.sub(lambda m: m.group(1) + REDACTED, text)
    for _, shape in TOKEN_SHAPES:
        text = shape.sub(REDACTED, text)
    text = _mask_credentials(text)
    text = CONFIGURE_SET.sub(lambda m: m.group(1) + REDACTED, text)
    return CLI_FLAG.sub(lambda m: m.group(1) + REDACTED, text)


def detect(text: str) -> list[str]:
    """Names of the secret patterns present in text (never the values): aws_access_key_id, aws_secret_access_key,
    aws_session_token, password, api_key, token, client_secret, private_key, psk, bearer_token, basic_auth, url_credentials, and the
    token shapes github_token, slack_token, stripe_key, google_api_key, jwt, slack_webhook."""
    found = []
    if ACCESS_KEY.search(text):
        found.append("aws_access_key_id")
    labelled = (*SECRET_ASSIGNMENT.finditer(text), *CONFIGURE_SET.finditer(text), *CLI_FLAG.finditer(text), *BARE_SECRET.finditer(text),
                *SPACE_SECRET.finditer(text))
    for match in labelled:
        name = "aws_session_token" if "session" in match.group(1).lower() else "aws_secret_access_key"
        if name not in found:
            found.append(name)
    found += [name for name, shape in TOKEN_SHAPES if name not in found and shape.search(text)]
    for _, _, spans in _scan(text):
        found += [name for _, _, name in spans if name not in found]
    if PRIVATE_KEY.search(text):
        found.append("private_key")
    return list(dict.fromkeys(found))


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


_NAME_KEYS = ("key", "name", "optionname", "parametername", "parameterkey", "variable")
_VALUE_KEYS = ("value", "parametervalue")


def _tag_value_is_secret(obj):
    """`{"Key": "DBPassword", "Value": "..."}` pairs hold the secret in a sibling of the label. AWS CLI output names them Key/Value
    (tags), Name/Value (ECS environment, SSM), OptionName/Value (Beanstalk), ParameterKey/ParameterValue (CloudFormation)."""
    keys = {k.lower(): k for k in obj if isinstance(k, str)}
    value_key = next((keys[v] for v in _VALUE_KEYS if v in keys and isinstance(obj[keys[v]], (str, dict, list, tuple))), None)
    named = any(n in keys and _secret_key(obj[keys[n]]) for n in _NAME_KEYS)
    return named and value_key is not None, value_key


def mask_obj(obj, **kw):
    if isinstance(obj, str):
        return mask(obj, **kw)
    if isinstance(obj, dict):
        tag_secret, value_key = _tag_value_is_secret(obj)
        out = {}
        for k, v in obj.items():
            redact_value = isinstance(v, (str, dict, list, tuple)) and (_secret_key(k) or (tag_secret and k == value_key))
            out[_unique(mask(k, **kw) if isinstance(k, str) else k, out)] = REDACTED if redact_value else mask_obj(v, **kw)
        return out
    if isinstance(obj, (list, tuple)):
        return [mask_obj(v, **kw) for v in obj]
    return obj
