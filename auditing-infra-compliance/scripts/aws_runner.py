"""Read-only AWS CLI runner. The only module that talks to AWS (and DNS tools)."""

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass

ALLOWED_PREFIXES = ("describe-", "list-", "get-")
ALLOWED_EXACT = frozenset({"lookup-events", "generate-credential-report"})
# Exact (service, operation) pairs that are read-only although they do not start with an allowed prefix. A bare
# operation name would be allowed for every service, and batch-get-secret-value / batch-get-item expose data.
ALLOWED_PAIRS = frozenset({("inspector2", "batch-get-account-status")})
DENYLIST = frozenset(
    {
        ("secretsmanager", "get-secret-value"),
        ("ssm", "get-parameter"),
        ("ssm", "get-parameters"),
        ("ssm", "get-parameters-by-path"),
        ("lambda", "get-function"),
        ("s3api", "get-object"),
        ("s3api", "get-object-torrent"),
        ("kms", "decrypt"),
        ("kms", "generate-data-key"),
        ("kms", "generate-data-key-without-plaintext"),
        ("ecr", "get-login-password"),
        ("ecr", "get-authorization-token"),
        ("sts", "get-session-token"),
        ("sts", "get-federation-token"),
        ("logs", "get-log-events"),
        ("logs", "filter-log-events"),
        ("dynamodb", "get-item"),
        ("dynamodb", "scan"),
        ("dynamodb", "query"),
        ("dynamodb", "batch-get-item"),
        ("ec2", "get-password-data"),
        ("rds-data", "*"),
        ("s3", "*"),
        ("sso", "get-role-credentials"),
        ("cognito-identity", "get-credentials-for-identity"),
        ("cognito-identity", "get-open-id-token"),
        ("cognito-identity", "get-open-id-token-for-developer-identity"),
        ("codeartifact", "get-authorization-token"),
        ("ecr-public", "get-authorization-token"),
        ("ecr", "get-login"),
        ("redshift", "get-cluster-credentials"),
        ("redshift", "get-cluster-credentials-with-iam"),
        ("redshift-serverless", "get-credentials"),
        ("ssm", "get-parameter-history"),
        ("logs", "get-query-results"),
        ("logs", "get-log-record"),
        ("logs", "get-log-object"),
        ("athena", "get-query-results"),
        ("ec2", "get-console-output"),
        ("ec2", "get-console-screenshot"),
        ("codecommit", "get-file"),
        ("codecommit", "get-blob"),
        ("codecommit", "get-folder"),
    }
)
FORBIDDEN_ARGS = frozenset({"--with-decryption"})
# Flags the runner sets itself or that could redirect/expand the call; rejected exactly,
# with "=value", and as argparse-style abbreviations (the real CLI honours any unambiguous
# prefix, so every prefix of at least 3 characters, e.g. "--end", is rejected).
FORBIDDEN_FLAGS = frozenset(
    {
        "--endpoint-url",
        "--debug",
        "--cli-input-json",
        "--cli-input-yaml",
        "--no-verify-ssl",
        "--ca-bundle",
        "--profile",
        "--region",
        "--query",
        "--output",
    }
)
_MIN_ABBREVIATION = 3
# Keys removed from parsed responses because they commonly carry secrets.
SCRUB: dict[tuple[str, str], frozenset[str]] = {
    ("lambda", "list-functions"): frozenset({"Environment"}),
    ("lambda", "get-function-configuration"): frozenset({"Environment"}),
    ("ecs", "describe-task-definition"): frozenset({"environment", "secrets"}),
    ("apigateway", "get-stages"): frozenset({"variables"}),
    ("apigatewayv2", "get-stages"): frozenset({"StageVariables"}),
    ("sns", "list-subscriptions-by-topic"): frozenset({"Endpoint"}),
}
# Keys whose value is replaced by PLACEHOLDER (the key stays, so evaluators can still see that it is present): bootstrap
# scripts, shared origin secrets and constant event payloads often carry credentials that no key name gives away.
PLACEHOLDER = "[REDACTED]"
MASK: dict[tuple[str, str], frozenset[str]] = {
    ("ec2", "describe-launch-template-versions"): frozenset({"UserData"}),
    ("cloudfront", "list-distributions"): frozenset({"HeaderValue"}),
    ("cloudfront", "get-distribution-config"): frozenset({"HeaderValue"}),
    ("cloudfront", "get-distribution"): frozenset({"HeaderValue"}),
    ("events", "list-targets-by-rule"): frozenset({"Input", "InputTransformer", "HttpParameters"}),
}
PAGINATION_TOKENS = ("NextToken", "NextMarker", "Marker")

TIMEOUT_SECONDS = 120
BACKOFF_SECONDS = (1, 2, 4, 8)
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_URL_ARG = re.compile(r"^(--[\w-]+=)?https?://", re.IGNORECASE)


class ReadOnlyViolation(Exception):
    """Raised when a call is not provably read-only."""


@dataclass(frozen=True)
class CallResult:
    ok: bool
    data: object | None
    error_kind: str | None  # ACCESS_DENIED | NOT_ENABLED | NO_CREDENTIALS | THROTTLED | ERROR
    error_message: str | None
    argv: tuple[str, ...]


def assert_read_only(service: str, operation: str, args: list[str]) -> None:
    if not _NAME_RE.fullmatch(service or "") or not _NAME_RE.fullmatch(operation or ""):
        raise ReadOnlyViolation(f"nombre de servicio/operación inválido: {service!r} {operation!r}")
    if (service, "*") in DENYLIST or (service, operation) in DENYLIST:
        raise ReadOnlyViolation(f"{service} {operation} está en la denylist (puede exponer secretos o datos)")
    allowed = (service, operation) in ALLOWED_PAIRS or operation in ALLOWED_EXACT or operation.startswith(ALLOWED_PREFIXES)
    if not allowed:
        raise ReadOnlyViolation(f"{service} {operation} no es una operación de solo lectura")
    for arg in args:
        _check_arg(arg)


def _check_arg(arg: object) -> None:
    if not isinstance(arg, str):
        raise ReadOnlyViolation(f"argumento no es texto: {arg!r}")
    if "file://" in arg or "fileb://" in arg:
        raise ReadOnlyViolation(f"argumento prohibido (lectura de archivo local): {arg}")
    if _URL_ARG.match(arg):  # the CLI replaces such an argument with the body fetched by GET
        raise ReadOnlyViolation(f"argumento prohibido (el CLI descargaría la URL): {arg}")
    flag = arg.split("=", 1)[0].strip()
    if flag.startswith("--with-dec") or flag in FORBIDDEN_ARGS:
        raise ReadOnlyViolation(f"argumento prohibido: {arg}")
    if flag.startswith("--") and len(flag) >= _MIN_ABBREVIATION:
        if any(forbidden.startswith(flag) for forbidden in FORBIDDEN_FLAGS):
            raise ReadOnlyViolation(f"argumento prohibido: {arg}")


def classify_error(stderr: str) -> str:
    text = stderr.lower()
    if any(p in text for p in ("accessdenied", "unauthorizedoperation", "not authorized to perform")):
        return "ACCESS_DENIED"
    if (
        any(
            p in text
            for p in (
                "optinrequired",
                "subscriptionrequiredexception",
                "invalidaccessexception",
                "is not subscribed",
                "nosuchconfigurationrecorder",
            )
        )
        or ("badrequestexception" in text and "not enabled" in text)
    ):
        return "NOT_ENABLED"
    if (
        any(p in text for p in ("unable to locate credentials", "expiredtoken", "invalidclienttokenid"))
        or ("config profile" in text and "could not be found" in text)
    ):
        return "NO_CREDENTIALS"
    # ReportInProgress/ReportNotPresent: the IAM credential report is still being generated; retrying fixes it
    if any(p in text for p in ("throttling", "rate exceeded", "toomanyrequests", "reportinprogress", "reportnotpresent")):
        return "THROTTLED"
    return "ERROR"


def _failure(kind: str, message: str, argv: list[str]) -> CallResult:
    return CallResult(ok=False, data=None, error_kind=kind, error_message=message, argv=tuple(argv))


def run_aws(
    service: str,
    operation: str,
    args: list[str],
    *,
    region: str | None,
    profile: str | None,
    query: str | None = None,
    runner=subprocess.run,
    sleep=time.sleep,
) -> CallResult:
    assert_read_only(service, operation, args)
    argv = ["aws", service, operation, *args, "--output", "json"]
    if region:
        argv += ["--region", region]
    if profile:
        argv += ["--profile", profile]
    if query:
        argv += ["--query", query]

    for attempt in range(len(BACKOFF_SECONDS) + 1):
        try:
            proc = runner(argv, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, shell=False,
                          stdin=subprocess.DEVNULL)  # a credential prompt must fail fast, not block the worker
        except subprocess.TimeoutExpired:
            return _failure("ERROR", f"timeout tras {TIMEOUT_SECONDS}s", argv)
        except OSError as exc:
            return _failure("ERROR", f"no se pudo ejecutar aws: {exc}", argv)
        if proc.returncode == 0:
            return _parse_success(proc.stdout, argv, SCRUB.get((service, operation), frozenset()),
                                  MASK.get((service, operation), frozenset()), _passes_max_items(args))
        kind = classify_error(proc.stderr or "")
        if kind == "THROTTLED" and attempt < len(BACKOFF_SECONDS):
            sleep(BACKOFF_SECONDS[attempt])
            continue
        return _failure(kind, (proc.stderr or "").strip(), argv)
    raise AssertionError("unreachable")


def _scrub(data: object, keys: frozenset[str]) -> object:
    if isinstance(data, dict):
        return {k: _scrub(v, keys) for k, v in data.items() if k not in keys}
    if isinstance(data, list):
        return [_scrub(item, keys) for item in data]
    return data


def _mask_values(data: object, keys: frozenset[str]) -> object:
    if isinstance(data, dict):
        return {k: PLACEHOLDER if k in keys else _mask_values(v, keys) for k, v in data.items()}
    if isinstance(data, list):
        return [_mask_values(item, keys) for item in data]
    return data


def _passes_max_items(args: list[str]) -> bool:
    return any(arg == "--max-items" or arg.startswith("--max-items=") for arg in args)


def _truncated(data: object) -> bool:
    """The top-level object still points at a next page (an operation without a CLI paginator, e.g. wafv2 list-web-acls)."""
    return isinstance(data, dict) and (data.get("IsTruncated") is True or any(data.get(k) for k in PAGINATION_TOKENS))


def _parse_success(stdout: str, argv: list[str], scrub_keys: frozenset[str] = frozenset(),
                   mask_keys: frozenset[str] = frozenset(), limited: bool = False) -> CallResult:
    if not stdout.strip():
        return CallResult(ok=True, data=None, error_kind=None, error_message=None, argv=tuple(argv))
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return _failure("ERROR", f"salida no es JSON válido: {exc}", argv)
    if not limited and _truncated(data):
        return _failure("ERROR", "respuesta truncada: la operación devolvió una página parcial (token de siguiente página)", argv)
    if scrub_keys:
        data = _scrub(data, scrub_keys)
    if mask_keys:
        data = _mask_values(data, mask_keys)
    return CallResult(ok=True, data=data, error_kind=None, error_message=None, argv=tuple(argv))


def run_dns(name: str, rrtype: str, runner=subprocess.run, which=shutil.which) -> CallResult:
    if which("dig"):
        argv = ["dig", "+short", rrtype, name]
    elif which("nslookup"):
        argv = ["nslookup", "-type=" + rrtype, name]
    else:
        return _failure("ERROR", "dig/nslookup no disponibles", [])
    try:
        proc = runner(argv, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, shell=False)
    except subprocess.TimeoutExpired:
        return _failure("ERROR", f"timeout tras {TIMEOUT_SECONDS}s", argv)
    except OSError as exc:
        return _failure("ERROR", f"no se pudo ejecutar {argv[0]}: {exc}", argv)
    if proc.returncode != 0:
        return _failure("ERROR", (proc.stderr or "").strip(), argv)
    lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
    return CallResult(ok=True, data=lines, error_kind=None, error_message=None, argv=tuple(argv))
