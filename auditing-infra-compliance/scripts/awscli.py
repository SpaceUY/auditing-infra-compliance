"""Read-only AWS CLI runner. The only module that talks to AWS (and DNS tools)."""

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass

ALLOWED_PREFIXES = ("describe-", "list-", "get-")
ALLOWED_EXACT = frozenset({"lookup-events", "generate-credential-report"})
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
    }
)
FORBIDDEN_ARGS = frozenset({"--with-decryption"})

TIMEOUT_SECONDS = 120
BACKOFF_SECONDS = (1, 2, 4, 8)
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


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
    if not _NAME_RE.match(service or "") or not _NAME_RE.match(operation or ""):
        raise ReadOnlyViolation(f"nombre de servicio/operación inválido: {service!r} {operation!r}")
    if (service, "*") in DENYLIST or (service, operation) in DENYLIST:
        raise ReadOnlyViolation(f"{service} {operation} está en la denylist (puede exponer secretos o datos)")
    if operation not in ALLOWED_EXACT and not operation.startswith(ALLOWED_PREFIXES):
        raise ReadOnlyViolation(f"{service} {operation} no es una operación de solo lectura")
    for arg in args:
        if arg.split("=", 1)[0] in FORBIDDEN_ARGS:
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
    if any(
        p in text
        for p in ("unable to locate credentials", "expiredtoken", "invalidclienttokenid", "could not be found")
    ):
        return "NO_CREDENTIALS"
    if any(p in text for p in ("throttling", "rate exceeded", "toomanyrequests")):
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
            proc = runner(argv, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, shell=False)
        except subprocess.TimeoutExpired:
            return _failure("ERROR", f"timeout tras {TIMEOUT_SECONDS}s", argv)
        except OSError as exc:
            return _failure("ERROR", f"no se pudo ejecutar aws: {exc}", argv)
        if proc.returncode == 0:
            return _parse_success(proc.stdout, argv)
        kind = classify_error(proc.stderr or "")
        if kind == "THROTTLED" and attempt < len(BACKOFF_SECONDS):
            sleep(BACKOFF_SECONDS[attempt])
            continue
        return _failure(kind, (proc.stderr or "").strip(), argv)
    raise AssertionError("unreachable")


def _parse_success(stdout: str, argv: list[str]) -> CallResult:
    if not stdout.strip():
        return CallResult(ok=True, data=None, error_kind=None, error_message=None, argv=tuple(argv))
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return _failure("ERROR", f"salida no es JSON válido: {exc}", argv)
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
