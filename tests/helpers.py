"""Shared test helpers: sys.path setup, FakeRunner, fixture loading, secret-note builder."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = ROOT / "auditing-infra-compliance"
SCRIPTS_DIR = SKILL_DIR / "scripts"
FIXTURES_DIR = ROOT / "tests" / "fixtures"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


class FakeRunner:
    """Imitates subprocess.run(argv, capture_output=True, text=True, timeout=..., shell=False).

    responses maps (service, operation, region | None) -> {"stdout", "stderr", "returncode"}
    or a list of such dicts, consumed in order (the last one repeats once exhausted).
    For non-aws tools (dig, nslookup) the key is (argv[0], None, None).
    Unknown keys raise AssertionError so tests notice unexpected calls.
    """

    def __init__(self, responses):
        self.responses = {k: (list(v) if isinstance(v, list) else v) for k, v in responses.items()}
        self.calls = []
        self.kwargs = []

    @staticmethod
    def _key(argv):
        if argv[0] != "aws":
            return (argv[0], None, None)
        region = argv[argv.index("--region") + 1] if "--region" in argv else None
        return (argv[1], argv[2], region)

    def __call__(self, argv, **kwargs):
        assert isinstance(argv, list), f"argv must be a list, got {type(argv).__name__}"
        assert kwargs.get("shell") is not True, "shell=True is forbidden"
        self.calls.append(list(argv))
        self.kwargs.append(kwargs)
        key = self._key(argv)
        if key not in self.responses:
            raise AssertionError(f"unexpected call {key}: {argv}")
        entry = self.responses[key]
        if isinstance(entry, list):
            response = entry.pop(0) if len(entry) > 1 else entry[0]
        else:
            response = entry
        return subprocess.CompletedProcess(
            argv,
            response.get("returncode", 0),
            stdout=response.get("stdout", ""),
            stderr=response.get("stderr", ""),
        )


def load_fixture(rel):
    """Load a JSON fixture from tests/fixtures/<rel>."""
    return json.loads((FIXTURES_DIR / rel).read_text(encoding="utf-8"))


def make_secret_note(directory):
    """Write a vault note containing a fake access key built at runtime; return its path."""
    key = "AKIA" + "TESTKEYABCDEMNOP"
    path = Path(directory) / "secret-note.md"
    path.write_text(f"# Credenciales\n\naws_access_key_id = {key}\n", encoding="utf-8")
    return path
