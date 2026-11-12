"""Masking of sensitive values before anything is written to disk, stdout or HTML.

- AWS access key ids (AKIA/ASIA + 16 chars) -> first 4 + "…" + last 4
- aws_secret_access_key, secret key and session token assignments -> value replaced by [REDACTED]
- emails -> first char + "***@domain", except those listed in keep_emails (e.g. VantaOwner owners)

`mask_secrets` is `mask` without the email rule. `mask` is idempotent. `mask_obj` applies it to every string value of nested dicts/lists/tuples
(dict keys are left alone) and replaces the value of secret-named keys outright.
"""

import re

REDACTED = "[REDACTED]"
ACCESS_KEY = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")  # no lookarounds: glued or trailing text is still masked
# Label (optionally decorated with markdown, prefixed/suffixed with word chars, spaces allowed between words)
# followed by : = or | and a value. Covers aws_secret_access_key, AWS_SECRET_ACCESS_KEY_PROD, SecretAccessKey,
# "Secret Access Key", secret_key, session_token, ...
SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\w*(?:secret[_ -]?(?:access[_ -]?)?key|session[_ -]?token)\w*)"
    r"""([*`'" \t]*[:=|][*`'" \t]*)[^\s"',;|`*]+""")
EMAIL = re.compile(r"(?<![\w.+%-])([A-Za-z0-9._%+-]+)@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
SECRET_KEYS = frozenset({"secretaccesskey", "aws_secret_access_key", "secret_access_key", "sessiontoken",
                         "session_token", "aws_session_token"})


def mask_secrets(text: str) -> str:
    """Access keys and secret/session-token assignments only (for identifiers that may legitimately hold emails)."""
    text = ACCESS_KEY.sub(lambda m: m.group(0)[:4] + "…" + m.group(0)[-4:], text)
    return SECRET_ASSIGNMENT.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)


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
        return {k: REDACTED if isinstance(k, str) and k.lower() in SECRET_KEYS and isinstance(v, str)
                else mask_obj(v, **kw) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [mask_obj(v, **kw) for v in obj]
    return obj
