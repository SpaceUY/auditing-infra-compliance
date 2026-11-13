"""Masking of sensitive values before anything is written to disk, stdout or HTML.

- AWS access key ids (AKIA/ASIA + 16 chars) -> first 4 + "…" + last 4
- aws_secret_access_key, secret key and session token assignments -> value replaced by [REDACTED]
- a bare `Secret` label (table cell or `Secret: value`) followed by a value that looks like a key (20+ base64 characters
  with upper case, lower case and a digit, so `secret: /acme/prod/db` is left alone), and `aws configure set <label> <value>`
- values after password / passwd / pwd labels (`password=x`, `password: x`; the word alone is not masked)
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
    rf"(?i)({_LABEL}\w{{0,40}}(?:[ \t]*\([^)\n|]{{0,30}}\))?)"
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
# Label is exactly password/passwd/pwd with at most one short qualifier segment (db_password, password_db). Settings such as
# password_policy, PasswordPolicy, password_reuse_prevention, minimum_password_length are not secrets.
_NOT_SECRET_WORDS = r"(?:min|minimum|max|maximum|require|required|requires|enable|enabled|allow|old)"
_NOT_SECRET_SUFFIX = r"(?:policy|policies|length|age|expir\w*|complexity|reuse\w*|required|enabled|history|rotation|min\w*|max\w*)"
PASSWORD = re.compile(
    rf"""(?i)((?<![A-Za-z0-9_])(?:(?!{_NOT_SECRET_WORDS}[_-])[A-Za-z0-9]{{1,15}}[_-])?(?:password|passwd|pwd)"""
    rf"""(?:[_-](?!{_NOT_SECRET_SUFFIX}\b)[A-Za-z0-9]{{1,15}}(?![A-Za-z0-9_-]))?[*`'"\\ \t]*[:=][*`'"\\ \t]*)[^\s"',;|`*\\]+""")
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----.*?(?:-----END [A-Z ]{0,30}PRIVATE KEY-----|\Z)", re.S)
EMAIL = re.compile(r"(?<![\w.+%-])([A-Za-z0-9._%+-]+)@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
SECRET_KEYS = frozenset({"secretaccesskey", "aws_secret_access_key", "secret_access_key", "sessiontoken",
                         "session_token", "aws_session_token", "password", "passwd", "pwd"})


def mask_secrets(text: str) -> str:
    """Access keys and secret/session-token assignments only (for identifiers that may legitimately hold emails)."""
    text = PRIVATE_KEY.sub(REDACTED, text)
    text = ACCESS_KEY.sub(lambda m: m.group(0)[:4] + "…" + m.group(0)[-4:], text)
    text = SECRET_ASSIGNMENT.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)
    text = BARE_SECRET.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)
    text = PASSWORD.sub(lambda m: m.group(1) + REDACTED, text)
    text = CONFIGURE_SET.sub(lambda m: m.group(1) + REDACTED, text)
    return CLI_FLAG.sub(lambda m: m.group(1) + REDACTED, text)


def detect(text: str) -> list[str]:
    """Names of the secret patterns present in text (never the values): aws_access_key_id, aws_secret_access_key,
    aws_session_token, password, private_key."""
    found = []
    if ACCESS_KEY.search(text):
        found.append("aws_access_key_id")
    labelled = (*SECRET_ASSIGNMENT.finditer(text), *CONFIGURE_SET.finditer(text), *CLI_FLAG.finditer(text), *BARE_SECRET.finditer(text))
    for match in labelled:
        name = "aws_session_token" if "session" in match.group(1).lower() else "aws_secret_access_key"
        if name not in found:
            found.append(name)
    if PASSWORD.search(text):
        found.append("password")
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


def mask_obj(obj, **kw):
    if isinstance(obj, str):
        return mask(obj, **kw)
    if isinstance(obj, dict):
        return {(mask(k, **kw) if isinstance(k, str) else k):
                REDACTED if isinstance(k, str) and k.lower() in SECRET_KEYS and isinstance(v, str) else mask_obj(v, **kw)
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [mask_obj(v, **kw) for v in obj]
    return obj
