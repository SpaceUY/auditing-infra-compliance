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
# The match starts at the keyword (no unbounded prefix: that made matching quadratic); prefixes such as "prod_" stay
# in the text, only the value is replaced. Suffix and separators are bounded or only scanned once per keyword.
# Label may be decorated with markdown / escaped JSON quotes and have spaces between words ("Secret Access Key");
# separators are : = or |. Covers aws_secret_access_key, AWS_SECRET_ACCESS_KEY_PROD, SecretAccessKey, secret_key, session_token...
_LABEL = r"(?:secret[_ -]?(?:access[_ -]?)?key|session[_ -]?token)"
SECRET_ASSIGNMENT = re.compile(
    rf"(?i)({_LABEL}\w{{0,40}})"
    r"""([*`'"\\ \t]*[:=|][*`'"\\ \t]*)[^\s"',;|`*\\]+""")
# CLI form: --secret-access-key <value> (the "=" form is covered above)
CLI_FLAG = re.compile(rf"(?i)(--{_LABEL}[ \t]+)(?!-)[^\s\"',;|`*\\]+")
EMAIL = re.compile(r"(?<![\w.+%-])([A-Za-z0-9._%+-]+)@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
SECRET_KEYS = frozenset({"secretaccesskey", "aws_secret_access_key", "secret_access_key", "sessiontoken",
                         "session_token", "aws_session_token"})


def mask_secrets(text: str) -> str:
    """Access keys and secret/session-token assignments only (for identifiers that may legitimately hold emails)."""
    text = ACCESS_KEY.sub(lambda m: m.group(0)[:4] + "…" + m.group(0)[-4:], text)
    text = SECRET_ASSIGNMENT.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)
    return CLI_FLAG.sub(lambda m: m.group(1) + REDACTED, text)


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
