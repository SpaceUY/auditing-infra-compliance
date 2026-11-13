# Skill `auditing-infra-compliance`: implementation plan

> **Changes after approval:** this plan was executed with deviations (per-source verdict, report-only rule, `REVIEWED_OPERATIONS` allowlist, remediations, evaluators, `aws_runner.py`, among others). The list with their reasons is in section 16 of `docs/specs/2026-11-12-infra-compliance-audit-design.md`; where they differ, the spec governs.

> **For agents executing it:** REQUIRED SUB-SKILL. Use `superpowers:subagent-driven-development`
> (recommended) or `superpowers:executing-plans` to implement this plan task by task. The steps use
> checkboxes (`- [ ]`) for tracking.

**Goal:** build a Claude Code skill. From an Obsidian vault and/or read-only AWS credentials, the skill
audits AWS infrastructure against SOC 2 and ISO 27001:2022 and produces a self-contained `.html` with
copyable CloudShell commands to fix each finding.

**Architecture:**
- Deterministic Python scripts do everything that can be verified:
  - `vault_index.py` reads the vault;
  - `collect.py` runs read-only AWS checks with an allowlist;
  - `assemble_findings.py` combines and maps;
  - `render_report.py` generates the HTML.
- Claude orchestrates and supplies judgment:
  - resolves the scope and the feature;
  - compares the vault against reality, in `vault-claims.json`;
  - evaluates the few `evaluator: "claude"` checks.
- The check catalog is JSON per domain. The SOC 2/ISO mappings of the Drata tests come from the embedded
  DCF file.

**Stack:** Python ≥ 3.10, stdlib only at runtime. AWS CLI v2. `unittest` for the tests. Inline HTML, CSS and
JS. Markdown for the SKILL and the references.

**Spec:** `docs/specs/2026-11-12-infra-compliance-audit-design.md`. Supporting research in
`docs/research/`: `vanta-drata-tests.md`, `frameworks-aws-mapping.md`, `drata-dcf-mapping.json`,
`soc2-reference-infrastructures.md`, `github-skill-review.md`.

## Global constraints

**Security and execution**
- **An AWS write operation is never executed.**
  - `awscli.assert_read_only` admits only operations that start with `describe-`, `list-` or `get-`, or
    that are exactly `lookup-events` or `generate-credential-report`.
  - Every pair in the denylist (Task 3) is rejected even if it matches the prefix.
- `subprocess` always with an argument list and `shell=False`.
- `.env*` files, `~/.aws/credentials`, `*.pem` and `*.key` are **never** read.
  - `vault_index.py` ignores every file that is not `.md` and every file or folder that starts with `.`,
    except `.obsidian/` (only listed).
- Remediation commands are **never** executed; they are only written to `findings.json` and to the HTML.
- **Masking in everything written to disk or to the HTML:**
  - `AKIA`/`ASIA` keys → `AKIA…WXYZ` (last 4 characters);
  - emails → `u***@domain`, except values of the `VantaOwner` tag;
  - `aws_secret_access_key=...` and similar → `[REDACTED]`.
- **No file in the repo contains an access-key-shaped literal.** A hook blocks it.
  The fake keys in the tests are built at runtime by concatenating parts, for example
  `"AKIA" + "TESTKEYABCDEMNOP"`. Vault notes that contain them are generated in a temporary directory
  with `tests/helpers.make_secret_note(dir)`.

**Environment**
- Runtime: Python ≥ 3.10, no dependencies outside the stdlib.
- Tests: `python3 -m unittest discover -s tests -v`.
- Platforms: Linux and macOS. Windows is out of scope.

**Report**
- Output: `./compliance-reports/<platform>-<scope>-<YYYY-MM-DD-HHMM>/` with `report.html`,
  `findings.json`, `checks-result.json`, `inventory.json` and `raw/`. Never inside the vault.
- The HTML loads no external resources: no `<script src>`, `<link href>` or `<img src>` with `http`.
  `<a href>` links to sources are allowed.
- Default HTML language: English. IDs, commands and test names stay in their original language.
- No percentage or overall compliance grade anywhere.

**Data model**
- Severities: `critical` | `high` | `medium` | `low`.

| Severity | When |
|---|---|
| `critical` | Public exposure of data or credentials; root without MFA or with access keys |
| `high` | An automated Drata or Vanta test fails |
| `medium` | Relevant Security Hub, CIS or FSBP control, with no Drata/Vanta test |
| `low` | Hygiene |

- Statuses: `FAIL`, `PASS`, `DRIFT`, `DOCUMENTED_ONLY`, `DOCUMENTED_GAP`, `UNDOCUMENTED`, `NOT_VERIFIED`,
  `N/A`.
- `remediation.kind`: `cli` | `cli_with_decision` | `planned_change` | `console_only`.
- `remediation.risk`: `low` | `medium` | `high`.
- **Mappings:**
  - every TSC or ISO ID must exist in `references/frameworks/`;
  - the SOC 2/ISO mappings of checks with a Drata test present in `drata-dcf.json` are resolved from
    that file (`sourced: "drata-dcf-2026-11-12"`);
  - the rest carry `sourced: false` and are shown as "inferred".
- **Vacuous pass:** if there are no resources of the check's type in scope, the status is `N/A` with
  `vacuous: true`. Never `PASS`.

**Repository content**
- The repo contains no references to real projects, accounts, buckets or people.
- Fixtures use the fictional platform **"Acme Notes"**, account `111122223333`, region
  `us-east-1` and domain `acme-notes.example`.
- AICPA and ISO text: only IDs and short paraphrased names.

**Placeholders in CloudShell commands**
- Format `__FILL_IN_<NAME>__`, for example `__FILL_IN_OWNER_EMAIL__`.
- **Deviation from the spec:** the spec said `<<FILL_IN: …>>`, but in bash `<<` opens a heredoc, and pasting
  it leaves CloudShell hanging waiting for the terminator.
- Variables at the start of each block: `REGION="…"` and `ACCOUNT_ID="…"`. No `set -e`, because it would
  close the CloudShell session at the first error.

**Git**
- New local repo, branch `feature/auditing-infra-compliance`, conventional commits (`feat:`, `test:`,
  `chore:`, `docs:`).
- No push.
- Each commit ends with the co-author line:
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review focus

1. **Partial permissions.** A call with `AccessDenied` must produce `NOT_VERIFIED` with the missing
   permission, never `PASS` or `FAIL`. Pinned in Task 4 with `test_access_denied_is_not_verified`.
2. **Service not enabled.** GuardDuty, Security Hub, Config or Inspector turned off return
   `NOT_ENABLED`, and for the enablement checks that is `FAIL`, not `NOT_VERIFIED`. Pinned in
   Task 4 with `test_not_enabled_means_fail_when_declared`.
3. **Secrets in the vault.** A note with an access key or an `aws_secret_access_key` must not appear in
   the clear in `vault-index.json`, `findings.json` or the HTML. Pinned in Tasks 12 and 13 with
   `test_masks_keys_in_index` and `test_findings_are_masked`.
4. **Hostile names.** Resource names or tag values with `<script>`, `"`, `</script>` or backticks
   must be escaped in the HTML and in the copyable blocks. Pinned in Task 14 with
   `test_hostile_names_escaped`.
5. **Large account.** With many regions and hundreds of resources, the terminal output of `collect.py`
   must be a summary of ≤ 40 lines so as not to fill Claude's context; the detail goes to disk. Pinned in
   Task 4 with `test_stdout_summary_is_bounded`.

---

## File structure

```
infra-compliance-audit/
  README.md                                   what it is, installation (symlink to ~/.claude/skills), usage, tests
  .gitignore                                  compliance-reports/, __pycache__/, *.pyc
  docs/specs/… docs/research/… docs/plans/…   (existing)
  auditing-infra-compliance/
    SKILL.md                                  procedural flow (Task 16)
    references/
      vault-reading.md                        typed contract, free heuristics, feature/resource (T16)
      remediation-guidelines.md               CloudShell rules, placeholders, planned_change (T16)
      report-format.md                        scope.json, vault-claims.json, findings.json schemas (T16)
      drata-vanta.md                          roles, permissions, tags, vacuous pass, phase 2 (T16)
      inventory.json                          resource types → listing call (T4)
      conflict-rules.json                     conflict rules between fixes (T15)
      checks/{iam,logging,detection,compute,encryption,network,data,monitoring,inventory,
              integration,email}.json         catalog (T5–T11)
      frameworks/iso27001-2022.json           93 Annex A controls + clauses 4–10 (T1)
      frameworks/tsc-2017.json                61 criteria (T1)
      mappings/drata-dcf.json                 copy of docs/research/drata-dcf-mapping.json (T1)
    scripts/
      catalog.py                              constants, catalog loading and validation, mappings (T2)
      validate_catalog.py                     validator CLI (T2)
      awscli.py                               read-only runner, errors, retries, dns (T3)
      paths.py                                extract(data, path) with a path mini-language (T4)
      collect.py                              inventory + check execution (T4)
      evaluators.py                           registry of python:<name> evaluators (T4, T5–T11)
      vault_index.py                          vault index + feature resolution (T12)
      redact.py                               masking (T12 minimal, T13 complete)
      assemble_findings.py                    findings.json (T13)
      render_report.py                        HTML (T14; Verification section in T15)
      verify_remediation.py                   fix verification stage (T15)
    assets/report-template.html               template (T14)
  tests/
    helpers.py                                FakeRunner, load_fixture, make_secret_note
    fixtures/aws/<domain>/*.json              fake AWS responses (Acme Notes)
    fixtures/typed-vault/ fixtures/free-vault/
    fixtures/scope-*.json fixtures/vault-claims.json fixtures/findings-sample.json
    test_frameworks.py test_catalog.py test_awscli.py test_paths.py test_collect.py
    test_eval_<domain>.py test_vault_index.py test_redact.py test_assemble.py test_render.py test_e2e.py
    skill-scenarios.md
```

Script paths in commands: relative to `infra-compliance-audit/`. `SKILL_DIR` =
`auditing-infra-compliance`.

---

### Task 1: repo bootstrap and framework catalogs

**Files:**
- Create: `.gitignore`, `README.md` (skeleton: title, one line of purpose; completed in T17)
- Create: `auditing-infra-compliance/references/frameworks/iso27001-2022.json`
- Create: `auditing-infra-compliance/references/frameworks/tsc-2017.json`
- Create: `auditing-infra-compliance/references/mappings/drata-dcf.json` (exact copy of
  `docs/research/drata-dcf-mapping.json`)
- Test: `tests/test_frameworks.py`

**Interfaces:**
- **Produces `iso27001-2022.json`:**
  ```
  {"version": "ISO/IEC 27001:2022",
   "clauses": [{"id": "4.1", "name": …}, …],                    // 4.1 … 10.2
   "controls": [{"id": "A.5.1", "theme": "organizational|people|physical|technological",
                 "name": "<short paraphrase>",
                 "responsibility": "customer|shared|inherited",
                 "technical": bool}, …]}
  ```
  - `technical: true` = the skill can provide technical evidence: 5.9, 5.15–5.18, 5.23, 5.33, 8.x except
    8.1, 8.4, 8.7, 8.25–8.31 and 8.33.
  - `responsibility` per `frameworks-aws-mapping.md` §5: 7.x for what is hosted on AWS → `inherited`; 7.x
    for own offices or equipment → `shared`.
- **Produces `tsc-2017.json`:**
  ```
  {"version": "TSC 2017 (rev. 2022 PoF)",
   "criteria": [{"id": "CC6.1", "category": "security|availability|confidentiality|processing_integrity|privacy",
                 "name": …, "technical": bool}, …]}
  ```
- The source of the list and the names is `docs/research/frameworks-aws-mapping.md` §1.1, §1.3, §2.1 and §2.2.

- [ ] **Step 1:** `git init`, create the branch `feature/auditing-infra-compliance`, create `.gitignore` with
  `compliance-reports/`, `__pycache__/` and `*.pyc`, create the skeleton `README.md`.
- [ ] **Step 2: write the failing tests** in `tests/test_frameworks.py`:
  - `test_iso_has_93_controls_by_theme`: total count 93; by theme: organizational 37, people 8,
    physical 14, technological 34;
  - `test_iso_new_2022_controls_present`: A.5.7, A.5.23, A.5.30, A.7.4, A.8.9, A.8.10, A.8.11,
    A.8.12, A.8.16, A.8.23 and A.8.28 exist;
  - `test_iso_clauses_cover_4_to_10`: 4.1 and 10.2 exist, and no ID is repeated;
  - `test_tsc_has_61_criteria`: 61 in total, 33 `CC*`, unique IDs; `A1.3`, `C1.2`, `PI1.5` and
    `P8.1` exist; `C1.3` does **not** exist;
  - `test_physical_controls_not_customer_only`: every `A.7.*` has `responsibility` in {`inherited`,
    `shared`};
  - `test_drata_dcf_copied`: `mappings/drata-dcf.json` is identical to `docs/research/drata-dcf-mapping.json`
    and has 130 tests.
- [ ] **Step 3:** run `python3 -m unittest tests.test_frameworks -v`. Expected: FAIL (files
  do not exist).
- [ ] **Step 4:** create the three JSON files with paraphrased names.
- [ ] **Step 5:** run the tests. Expected: 6 OK.
- [ ] **Step 6:** commit with `chore: bootstrap repo and framework catalogs`.

---

### Task 2: catalog schema, mapping resolution and validator

**Files:**
- Create: `auditing-infra-compliance/scripts/catalog.py`
- Create: `auditing-infra-compliance/scripts/validate_catalog.py`
- Test: `tests/test_catalog.py`, `tests/fixtures/catalog-min/test.json`

**Interfaces:**
- **Produces, in `catalog.py`:**
  - Constants `SEVERITIES`, `STATUSES`, `REMEDIATION_KINDS`, `RISKS`, `EVALUATOR_KINDS = ("jmespath",
    "python", "claude", "dns")` and `DCF_SOURCE = "drata-dcf-2026-11-12"`.
  - `load_checks(checks_dir: Path) -> list[dict]`: merges all the `*.json` files in the folder; each file is
    `{"domain": str, "checks": [...]}`.
  - `load_frameworks(frameworks_dir: Path) -> tuple[set[str], set[str]]`: returns the TSC IDs and the ISO
    IDs; for the latter, Annex A and clauses.
  - `load_drata_map(path: Path) -> dict[int, dict]`: indexed by `test_id`.
  - `resolve_mappings(check: dict, drata: dict[int, dict]) -> dict`: returns
    `{"drata": [...], "vanta": [...], "tsc": [{"id", "sourced"}], "iso27001_2022": [...], "security_hub": [...], "cis_aws": [...]}`.
    - If any test in `check["mappings"]["drata"]` is in `drata`, it takes the union of `soc2` and
      `iso27001_2022` of its controls with `sourced = DCF_SOURCE`.
    - Otherwise, it uses `check["mappings"]["tsc_inferred"]` and `iso_inferred` with `sourced: false`.
  - `validate(checks, tsc_ids, iso_ids, drata) -> list[str]`: returns the error messages; an empty list
    means valid.
- **Schema of a check** (all fields are required except those marked optional):
  ```
  {"id": "IAM-001", "title": str (English), "domain": str,
   "scope": "account|resource",
   "resource_types": [str],                      // keys of inventory.json; [] for account scope
   "account_context_for": [str],                 // optional: types for which this account check applies in feature/resource mode
   "all_regions": bool,                          // runs in all enabled regions
   "severity": …, "not_enabled_means": "fail|not_verified",
   "verify": {"calls": [Call], "evaluator": "jmespath|python:<name>|claude|dns",
              "offenders": str,                  // JMESPath expression (only if evaluator == jmespath and 1 call)
              "params": {…},                     // optional, for python evaluators
              "pass_when_text": str, "needs": ["svc:Action", …]},
   "vault_signals": [str],
   "mappings": {"drata": [{"test": int, "name": str, "source": url}],
                "vanta": [{"test": str, "source": url}],
                "tsc_inferred": [str], "iso_inferred": [str],
                "security_hub": [str], "cis_aws": [str]},
   "remediation": {"kind": …, "risk": …, "downtime": bool,
                   "steps": [str], "commands": [str], "verify_after": str, "notes": str},
   "sources": [url]}
  ```
  - `Call = {"name": str, "service": str, "operation": str, "args": [str], "region": "global|each",
    "for_each": {"from": <call name>, "path": <paths.py path>, "arg": "--flag"}}`. The `for_each` is
    optional.
- **`validate` rules**, one test per rule:
  1. Unique IDs with format `^[A-Z]{3}-\d{3}$`.
  2. Valid severity, kind, risk and evaluator.
  3. Every `(service, operation)` in `calls` passes `awscli.assert_read_only` (imported in Task 3; in
     this task a local stub `_is_read_only` with the same prefix rules is used, which Task 3
     replaces with the import).
  4. Every `tsc_inferred` exists in TSC and every `iso_inferred` in ISO.
  5. Every `mappings.drata[].test` is an int.
  6. If `evaluator == "jmespath"`: there is exactly 1 call and `offenders` is not empty.
  7. `remediation.verify_after` is not empty, except for `console_only`.
  8. `planned_change` has ≥ 2 `steps` and `notes` is not empty (the warning).
  9. `commands` does not contain `<<`.
  10. If a check has no Drata test resolvable in the DCF, it has ≥ 1 `tsc_inferred` and ≥ 1
      `iso_inferred`.
  11. `scope == "resource"` implies non-empty `resource_types`.
- **`validate_catalog.py`:** CLI with no arguments. Loads from `SKILL_DIR/references`, prints the errors and
  exits with code 1 if there are errors, 0 if not. Last line: `OK: <n> checks`.

- [ ] **Step 1: write the failing tests** in `tests/test_catalog.py` with the fixture
  `catalog-min/test.json`, which has 2 valid checks: one with Drata 214 and one without Drata.
  - `test_valid_catalog_has_no_errors`.
  - `test_resolve_mappings_from_dcf`: the check with Drata 214 resolves TSC {CC6.1, CC7.2} and ISO
    {A.8.2, A.8.16} with `sourced == DCF_SOURCE`.
  - `test_resolve_mappings_inferred`: sourced `False`.
  - One test `test_rule_<n>_…` for each rule from 1 to 11. Each one mutates the fixture and expects ≥ 1 error
    containing the check ID. Examples:
    - `test_rule_3_rejects_write_operation` with `ec2 modify-instance-attribute`;
    - `test_rule_9_rejects_heredoc_placeholder`.
- [ ] **Step 2:** run `python3 -m unittest tests.test_catalog -v`. Expected: FAIL (import error).
- [ ] **Step 3:** implement `catalog.py` and `validate_catalog.py`.
- [ ] **Step 4:** run the tests. Expected: all OK.
- [ ] **Step 5:** commit with `feat: catalog schema, mapping resolution and validator`.

---

### Task 3: read-only AWS runner

**Files:**
- Create: `auditing-infra-compliance/scripts/awscli.py`
- Modify: `scripts/catalog.py` (replace the `_is_read_only` stub with `awscli.assert_read_only`)
- Test: `tests/test_awscli.py`, `tests/helpers.py`

**Interfaces:**
- **Produces:**
  - `class ReadOnlyViolation(Exception)`.
  - `ALLOWED_PREFIXES = ("describe-", "list-", "get-")`.
  - `ALLOWED_EXACT = frozenset({"lookup-events", "generate-credential-report"})`.
  - `DENYLIST` (frozenset of `(service, operation)` pairs; `"*"` as the operation blocks the whole service):
    - `("secretsmanager","get-secret-value")`;
    - `("ssm","get-parameter")`, `("ssm","get-parameters")`, `("ssm","get-parameters-by-path")`;
    - `("lambda","get-function")`;
    - `("s3api","get-object")`, `("s3api","get-object-torrent")`;
    - `("kms","decrypt")`, `("kms","generate-data-key")`, `("kms","generate-data-key-without-plaintext")`;
    - `("ecr","get-login-password")`, `("ecr","get-authorization-token")`;
    - `("sts","get-session-token")`, `("sts","get-federation-token")`;
    - `("logs","get-log-events")`, `("logs","filter-log-events")`;
    - `("dynamodb","get-item")`, `("dynamodb","scan")`, `("dynamodb","query")`,
      `("dynamodb","batch-get-item")`;
    - `("ec2","get-password-data")`;
    - `("rds-data","*")`, `("s3","*")`.
  - `FORBIDDEN_ARGS = frozenset({"--with-decryption"})`.
  - `assert_read_only(service: str, operation: str, args: list[str]) -> None`: raises `ReadOnlyViolation`
    with the reason.
  - `@dataclass(frozen=True) class CallResult`: `ok: bool`, `data: object | None`, `error_kind: str |
    None` (`ACCESS_DENIED`, `NOT_ENABLED`, `NO_CREDENTIALS`, `THROTTLED`, `ERROR`), `error_message: str |
    None`, `argv: tuple[str, ...]`.
  - `run_aws(service, operation, args, *, region: str | None, profile: str | None, query: str | None =
    None, runner=subprocess.run, sleep=time.sleep) -> CallResult`.
    - argv = `["aws", service, operation, *args, "--output", "json"]`, plus `--region`, `--profile` and
      `--query` if given.
    - `assert_read_only` before executing.
    - Timeout of 120 s.
    - Throttling: 4 retries with backoff of 1, 2, 4 and 8 s.
  - `classify_error(stderr: str) -> str`:

| Pattern in stderr | Result |
|---|---|
| `AccessDenied`, `UnauthorizedOperation`, `AccessDeniedException`, `not authorized to perform` | `ACCESS_DENIED` |
| `OptInRequired`, `SubscriptionRequiredException`, `InvalidAccessException` (Security Hub), `is not subscribed`, `NoSuchConfigurationRecorder`, `BadRequestException` with "not enabled" | `NOT_ENABLED` |
| `Unable to locate credentials`, `ExpiredToken`, `InvalidClientTokenId`, `could not be found` (nonexistent profile) | `NO_CREDENTIALS` |
| `Throttling`, `Rate exceeded`, `TooManyRequests` | `THROTTLED` |
| anything else | `ERROR` |

  - `run_dns(name: str, rrtype: str, runner=subprocess.run, which=shutil.which) -> CallResult`: uses
    `["dig", "+short", rrtype, name]` or, if that is not available, `["nslookup", "-type=" + rrtype, name]`. `data` is the
    list of response lines. If neither is available: `error_kind="ERROR"`, message
    `"dig/nslookup not available"`.
- **Produces, in `tests/helpers.py`:**
  - `class FakeRunner`: callable that imitates `subprocess.run`. It is initialized with
    `{(service, operation, region|None): {"stdout": str, "stderr": str, "returncode": int}}` and records
    each argv in `self.calls`. An entry can be a list of responses, which are consumed in order.
  - `load_fixture(rel: str) -> object`.
  - `make_secret_note(dir: Path) -> Path`: writes a `.md` note with `aws_access_key_id = ` followed by
    a key built at runtime (`"AKIA" + "TESTKEYABCDEMNOP"`). Returns the path.

- [ ] **Step 1: write the failing tests:**
  - `test_allows_describe_list_get` (3 cases) and `test_allows_exact_exceptions`;
  - `test_rejects_write_ops`: `ec2 modify-instance-metadata-options`, `iam create-user`,
    `s3api put-bucket-policy`, `iam delete-access-key`, `cloudtrail start-logging`;
  - `test_rejects_denylist`: each pair in `DENYLIST`, including `rds-data execute-statement` and
    `s3 ls` (because of the `*` wildcard);
  - `test_rejects_with_decryption`;
  - `test_never_uses_shell`: `FakeRunner` verifies that the `shell` kwarg is not `True` and that argv is a
    list;
  - `test_classify_error_table`: one assertion per table row;
  - `test_throttling_retries_then_succeeds`: 2 throttling responses and then OK; fake `sleep`
    records `[1, 2]`;
  - `test_access_denied_not_retried`;
  - `test_query_and_region_in_argv`;
  - `test_dns_falls_back_to_nslookup`;
  - `test_dns_missing_tools`.
- [ ] **Step 2:** run `python3 -m unittest tests.test_awscli -v`. Expected: FAIL.
- [ ] **Step 3:** implement `awscli.py` and `tests/helpers.py`, and replace the stub in `catalog.py`.
- [ ] **Step 4:** run `python3 -m unittest discover -s tests -v`. Expected: all OK.
- [ ] **Step 5:** commit with `feat: read-only aws cli runner with allowlist and denylist`.

---

### Task 4: inventory and the `collect.py` engine

**Files:**
- Create: `scripts/paths.py`, `scripts/collect.py`, `scripts/evaluators.py` (only the registry and an
  example evaluator)
- Create: `references/inventory.json`
- Test: `tests/test_paths.py`, `tests/test_collect.py`, `tests/fixtures/aws/core/*.json`,
  `tests/fixtures/scope-full.json`, `tests/fixtures/scope-resource.json`,
  `tests/fixtures/catalog-engine/engine.json` (4 synthetic checks: account jmespath, resource jmespath
  with `for_each`, python, and one with `not_enabled_means: fail`)

**Interfaces:**
- **Consumes:** `awscli.run_aws`, `awscli.run_dns`, `catalog.load_checks` and `catalog.resolve_mappings`.
- **Produces, in `paths.py`:** `extract(data: object, path: str) -> list`.
  - Mini-language: keys separated by `.`; `[]` flattens a list; `[*]` is a synonym for `[]`.
  - A nonexistent path returns `[]`.
  - Example: `extract({"Buckets":[{"Name":"a"}]}, "Buckets[].Name") == ["a"]`.
- **Produces `inventory.json`:**
  ```
  {"<type>": {"service", "operation", "args", "region": "global|each",
              "items_path", "id_path", "name_path", "tags_path", "arn_path"}}
  ```
  The `*_path` values are resolved with `paths.extract`, relative to each item. Minimum types: `ec2_instance`,
  `ebs_volume`, `security_group`, `nacl`, `vpc`, `subnet`, `rds_instance`, `rds_cluster`, `s3_bucket`,
  `dynamodb_table`, `efs`, `elbv2`, `asg`, `launch_template`, `lambda_function`, `sqs_queue`,
  `sns_topic`, `kms_key`, `log_group`, `cloudtrail_trail`, `iam_user`, `iam_role`, `eks_cluster`,
  `elasticache_group`, `ses_identity`, `wafv2_web_acl`, `acm_certificate` and `secret` (the latter only
  via `secretsmanager list-secrets`, without values).
- **Produces `scope.json`** (written by Claude or the fixture):
  ```
  {"platform": str, "mode": "full|feature|resource", "target": str|null,
   "regions": [str] | "auto", "profile": str|null,
   "resources": [{"type", "id", "region"}],       // empty in full
   "domains": [str] | null}                       // null = all
  ```
- **Produces, in `evaluators.py`:**
  - `EVALUATORS: dict[str, Callable[[dict[str, list[tuple[str, object]]], dict], list[dict]]]`;
  - decorator `@register(name)`.
  - Signature of each evaluator: `fn(responses, params) -> offenders`.
    - `responses[call_name]` = list of `(region, data)`.
    - `responses["__inventory__"]` = the inventory list.
    - Offender = `{"resource_id": str, "region": str, "detail": dict}`.
  - Example evaluator: `always_empty`.
- **Produces, in `collect.py`:** `main(argv) -> int` with arguments
  `--scope FILE --out DIR [--checks-dir DIR] [--inventory FILE]`.
  1. `sts get-caller-identity` → `account_id` and `identity_arn`. If it is `NO_CREDENTIALS`: writes
     `checks-result.json` with `{"aws": null}` and exits with 2.
  2. Enabled regions: `ec2 describe-regions --filters Name=opt-in-status,Values=opt-in-not-required,opted-in`.
     `scope.regions == "auto"` → enabled regions that have any inventory resource, plus
     `us-east-1`.
  3. Inventory: per type and region, in parallel with `ThreadPoolExecutor(max_workers=8)` per region.
     `inventory.json` is written as a list of `{"type", "id", "arn", "name", "region", "tags": {k: v}}`.
  4. Check selection:
     - `mode == full`: all those in `domains`.
     - `feature/resource`: those with `scope == "resource"` whose `resource_types` intersects the types of
       `scope.resources`, plus those with `scope == "account"` whose `account_context_for` intersects those
       types.
  5. Execution:
     - `region "global"` → `us-east-1`; `"each"` → regions of the scope, or all enabled ones if
       `all_regions`.
     - `for_each` expands one call for each extracted value.
     - `jmespath` passes `offenders` as `--query`, and the result (a list) is the offenders. The
       expressions must project `{resource_id: …, detail: {…}}`. This is documented in `report-format.md`.
     - `python:<n>` calls `EVALUATORS[n]`. `claude` runs no evaluation: it saves the responses and
       marks `status: "PENDING_CLAUDE"`. `dns` uses `run_dns`.
  6. Status per check and resource:

| Situation | Status |
|---|---|
| Any call `ACCESS_DENIED` | `NOT_VERIFIED`, with `missing: needs` |
| `NOT_ENABLED` and `not_enabled_means == "fail"` | `FAIL`, with `detail.reason = "service not enabled"` |
| `NOT_ENABLED` otherwise | `NOT_VERIFIED` |
| No resources of `resource_types` in scope | `N/A`, with `vacuous: true` |
| There are offenders | one `FAIL` per offender |
| No offenders | one `PASS` with `resource_id` = `"account"` or the list of evaluated IDs |

     - In feature/resource mode, the offenders and PASSes of `resource` checks are filtered to the IDs in
       `scope.resources`.
  7. Writes `raw/<check_id>/<call>-<region>[-<n>].json`, `checks-result.json` and `inventory.json`.
     - `checks-result.json` = `{"aws": {"account_id", "identity_arn", "regions": [...],
       "enabled_regions": [...]}, "results": [{"check_id", "status", "resource_id", "region", "detail",
       "missing", "vacuous"}], "warnings": [str]}`.
     - Broad permissions: if the identity has `AdministratorAccess` attached (verified with
       `iam list-attached-role-policies` or `list-attached-user-policies` on the identity), a
       warning is added. An `AccessDenied` here is ignored.
  8. stdout: summary of ≤ 40 lines with counts per status, top 10 `FAIL` by severity, number of
     `NOT_VERIFIED` and the directory path.

- [ ] **Step 1: write the failing tests:**
  - `test_paths.py`: `test_flatten`, `test_missing_key_returns_empty`, `test_nested_lists`,
    `test_star_alias`;
  - `test_collect.py`, all with `FakeRunner` and the `catalog-engine` catalog:
    - `test_full_mode_runs_account_and_resource_checks`;
    - `test_resource_mode_filters_to_scope_ids`;
    - `test_feature_mode_includes_account_context_checks`;
    - `test_access_denied_is_not_verified`;
    - `test_not_enabled_means_fail_when_declared`;
    - `test_no_resources_is_vacuous_na`;
    - `test_for_each_expands_calls`;
    - `test_all_regions_flag_uses_enabled_regions`;
    - `test_no_credentials_exits_2`;
    - `test_raw_outputs_written`;
    - `test_stdout_summary_is_bounded`: 300 offenders, ≤ 40 lines;
    - `test_admin_identity_warning`;
    - `test_claude_evaluator_marks_pending`;
    - `test_inventory_available_to_evaluators`.
- [ ] **Step 2:** run. Expected: FAIL.
- [ ] **Step 3:** implement `paths.py`, `inventory.json`, `evaluators.py` (registry) and `collect.py`.
- [ ] **Step 4:** run `python3 -m unittest discover -s tests -v`. Expected: all OK.
- [ ] **Step 5:** commit with `feat: inventory and read-only check collection engine`.

---

## Tasks 5 to 11: catalog per domain

**Common pattern for each domain task:**

**Files:**
- Create: `references/checks/<domain>.json`
- Modify: `scripts/evaluators.py` (add the domain's evaluators)
- Test: `tests/test_eval_<domain>.py`, `tests/fixtures/aws/<domain>/*.json`

**Content of each check:**
- real AWS CLI v2 calls;
- `pass_when_text` in English;
- `needs` with the IAM actions;
- mappings per the task's table;
- `remediation.commands` for CloudShell following the Global constraints. Each remediation command
  carries its verification variant in `verify_after`.

**Sources of the content:**
- thresholds, test names and URLs: `docs/research/vanta-drata-tests.md` (§1, §2 and §3) and
  `soc2-reference-infrastructures.md`;
- inferred TSC and ISO for checks without Drata ✓: `vanta-drata-tests.md` §5 and `frameworks-aws-mapping.md`
  §4.3.

**Steps of each domain task:**
- [ ] **Step 1: write the failing tests** for the domain. For each `python:` evaluator there are two
  tests, with one passing fixture and one failing fixture:
  - `test_<evaluator>_pass`;
  - `test_<evaluator>_fail_reports_offenders`, which verifies the exact `resource_id` from the fixture.

  In addition, `test_<domain>_catalog_valid` runs `catalog.validate` only on that file and expects `[]`.
- [ ] **Step 2:** run `python3 -m unittest tests.test_eval_<domain> -v`. Expected: FAIL.
- [ ] **Step 3:** write the domain JSON and the evaluators.
- [ ] **Step 4:** run the domain and `python3 auditing-infra-compliance/scripts/validate_catalog.py`.
  Expected: OK, no errors.
- [ ] **Step 5:** commit with `feat: <domain> checks`.

**Legend of the check tables:**
- **Eval:** `jq` = jmespath with `--query`; `py:<n>` = python evaluator; `cl` = Claude; `dns`.
- **Rem:** `cli` | `dec` (cli_with_decision) | `plan` (planned_change) | `con` (console_only).
- **Drata:** test number; with ✓ if it is in `drata-dcf.json` (authoritative mapping).
- **Vanta:** number from the CIS table of `vanta-drata-tests.md` §2.1, or short name.

### Task 5: IAM domain (`iam.json`)

| ID | Check | Eval | Sev | Rem | Drata | Vanta | SH/CIS |
|---|---|---|---|---|---|---|---|
| IAM-001 | MFA on root | jq `get-account-summary` | critical | con | 214 ✓ | #2 | IAM.9 / 1.4 |
| IAM-002 | Hardware MFA on root | py:`root_hardware_mfa` (`list-virtual-mfa-devices` + summary) | high | con | 225 ✓ | — | IAM.6 / 1.5 |
| IAM-003 | Root without access keys | jq (`AccountAccessKeysPresent`) | critical | con | — | #1 | IAM.4 / 1.3 |
| IAM-004 | Root not in use: 2+ root `ConsoleLogin` in 7 days = fail | py:`root_usage` (`cloudtrail lookup-events`, `params.days=7`, `params.max=1`) | high | con | 124 ✓ | — | — |
| IAM-005 | MFA on users with console access | py:`cred_report_console_mfa` | high | con | 88 ✓ | #5 | IAM.5 / 1.9 |
| IAM-006 | Password ≥ 14 | jq `get-account-password-policy` | high | cli | 215 ✓ | #3 | IAM.15 / 1.7 |
| IAM-007 | Password reuse = 24 | jq | high | cli | 216 ✓ | #4 | IAM.16 / 1.8 |
| IAM-008 | Access keys ≤ 90 days | py:`cred_report_key_age` (`params.max_days=90`) | high | plan | 232 ✓ | #8 | IAM.3 / 1.13 |
| IAM-009 | Credentials unused ≤ 45 days | py:`cred_report_unused` (`params.max_days=45`) | high | cli | 229 | #6 | IAM.22 / 1.11 |
| IAM-010 | ≤ 1 active access key per user | py:`cred_report_multi_keys` | medium | plan | — | #7 | — |
| IAM-011 | Permissions only via groups | py:`user_direct_policies` | high | plan | 217 ✓ | #9 | IAM.2 / 1.14 |
| IAM-012 | No own `*:*` policies attached | py:`admin_policies` | high | plan | 230 ✓ | #10 | IAM.1 |
| IAM-013 | Broad wildcards in own policies (review) | cl | medium | plan | 230 ✓ | — | — |
| IAM-014 | Role with `AWSSupportAccess` | jq `list-entities-for-policy` | low | dec | — | #11 | IAM.18 / 1.16 |
| IAM-015 | Access Analyzer in all regions (`all_regions`) | jq `accessanalyzer list-analyzers` | high | cli | — | #14 | IAM.28 / 1.19 |
| IAM-016 | SECURITY alternate contact | jq `account get-alternate-contact`; `ResourceNotFound` = fail | low | dec | — | — | Account.1 |
| IAM-017 | Human IAM users instead of Identity Center (informational) | py:`iam_human_users` | low | plan | — | — | — |

**Task notes:**
- **Credential report:** the `cred_report_*` evaluators share the call
  `iam generate-credential-report` followed by `iam get-credential-report`. The `Content` field comes as
  base64 CSV: it is decoded with the stdlib `base64` and `csv`.
- **Root, IAM-001 and IAM-003:** the remediation is `console_only` with numbered console steps; the CLI cannot
  enable root MFA.
- **Passwords, IAM-006 and IAM-007:** a single `update-account-password-policy` command with the
  complete set:

  ```
  --minimum-password-length 14 --password-reuse-prevention 24 --require-symbols
  --require-numbers --require-uppercase-characters --require-lowercase-characters
  --allow-users-to-change-password
  ```

  `notes` warns that it replaces the entire policy.

### Task 6: logging domain (`logging.json`)

| ID | Check | Eval | Sev | Rem | Drata | Vanta | SH/CIS |
|---|---|---|---|---|---|---|---|
| LOG-001 | Multi-region trail exists and `IsLogging=true` | py:`cloudtrail_active` (`describe-trails` + `get-trail-status` for_each) | high | dec | — | #25 | CloudTrail.1 / 3.1 |
| LOG-002 | Log file validation | jq `describe-trails` | high | cli | 205 ✓ | #26 | CloudTrail.4 / 3.2 |
| LOG-003 | Trail encrypted with CMK (`KmsKeyId` present) | jq | high | plan | 222 ✓ | #28 | CloudTrail.2 / 3.5 |
| LOG-004 | S3 data events, read and write | py:`trail_s3_data_events` (`get-event-selectors` for_each) | high | dec | 226 ✓ | #17, #18 | S3.22 / S3.23 |
| LOG-005 | Access logging on the CloudTrail bucket | py:`trail_bucket_logging` (`s3api get-bucket-logging`) | high | dec | 221 ✓ | #19 | CloudTrail.7 / 3.4 |
| LOG-006 | CloudTrail bucket: versioning and policy with `aws:SourceArn` | py:`trail_bucket_hardening` | medium | dec | — | — | — |
| LOG-007 | CloudTrail → CloudWatch Logs with CIS metric filters (root, IAM, unauthorized) | py:`trail_cw_metric_filters` | medium | plan | — | — | CloudWatch.1–.14 (CIS 1.4) |
| LOG-008 | Flow Logs on all VPCs in all regions (`all_regions`, `resource_types: [vpc]`) | py:`vpc_flow_logs` | high | dec | 224 ✓ | #30 | EC2.6 / 3.7 |
| LOG-009 | Log group retention ≥ 365 days (no retention = pass) | jq `logs describe-log-groups` | high | cli | 111 | "AWS Server Logs" | — |
| LOG-010 | Log buckets: lifecycle does not expire before 365 days | py:`log_bucket_lifecycle` | medium | dec | — | — | — |
| LOG-011 | ALB access logs | py:`alb_access_logs` (`describe-load-balancer-attributes` for_each) | medium | dec | — | — | ELB.5 |
| LOG-012 | WAF logging | py:`waf_logging` (`wafv2 get-logging-configuration` for_each) | medium | dec | — | — | WAF.11 |
| LOG-013 | EKS audit logs | jq `eks describe-cluster` for_each | high | cli | 310 ✓ | — | EKS.8 |

**Task notes:**
- **Retention (LOG-009):** the command is `aws logs put-retention-policy --log-group-name "{resource_id}"
  --retention-in-days 365`. `notes` warns about the cost.
- **Log bucket (LOG-010):** identified as the destination of trails and access logs, or by a tag/name
  that contains `log`.

### Task 7: detection and compute domains (`detection.json`, `compute.json`)

| ID | Check | Eval | Sev | Rem | Drata | Vanta | SH/CIS |
|---|---|---|---|---|---|---|---|
| DET-001 | GuardDuty active in every region with resources (`all_regions`; region without resources and without a detector = `low`, via `detail.severity_override`) | py:`guardduty_regions` | high | cli | 105 ✓ | — | GuardDuty.1 |
| DET-002 | GuardDuty S3 Protection | py:`guardduty_s3_protection` (`get-detector`) | high | cli | 105 ✓ | — | — |
| DET-003 | EventBridge rule for GuardDuty findings with a target | py:`guardduty_eventbridge` (`events list-rules` + `list-targets-by-rule`) | medium | dec | — | — | — |
| DET-004 | Security Hub enabled with FSBP or CIS (`not_enabled_means: fail`) | py:`securityhub_standards` | high | cli | — | #31 | — |
| DET-005 | AWS Config in all regions: recording, all types, daily IAM, delivery channel | py:`config_recorder` (`describe-configuration-recorders` + `...-status` + `describe-delivery-channels`) | high | dec | — | #27, "Config enabled correctly" | Config.1 / 3.3 |
| DET-006 | Inspector active for EC2, ECR and Lambda (`not_enabled_means: fail`) | py:`inspector_status` (`inspector2 batch-get-account-status`) | high | cli | 21 | "Critical vulnerabilities… (Inspector)" | Inspector.1–.4 |
| DET-007 | No open CRITICAL or HIGH findings in Inspector | jq `inspector2 list-findings --filter-criteria …` | high | plan | 21 | same | — |
| CMP-001 | IMDSv2 required on instances | jq `ec2 describe-instances` | high | cli | 292 ✓ | #36 | EC2.8 / 5.7 |
| CMP-002 | ASG launch templates with IMDSv2 | py:`lt_imdsv2` | high | plan | 292 ✓ | "IMDSv1 disabled (ASG)" | — |
| CMP-003 | Instances with an instance profile | jq | medium | dec | — | #12 | — |
| CMP-004 | LB in ≥ 2 AZs in regions with EC2 | py:`lb_multi_az` | high | plan | 130 ✓ | — | ELB.10/.13 |
| CMP-005 | Compute in an ASG | py:`asg_present` | high | plan | 131 ✓ | — | — |
| CMP-006 | Instances managed by SSM, with a patch association | py:`ssm_managed` (`ssm describe-instance-information` + `describe-instance-patch-states`) | medium | plan | — | — | SSM.1 |

**Task notes:**
- **DET-001 remediation:** one command is generated per offending region.

  ```
  aws guardduty create-detector --enable --region "{region}" --features '[{"Name":"S3_DATA_EVENTS","Status":"ENABLED"}]'
  ```
- **CMP-002 remediation:** steps to create a new version of the launch template with
  `MetadataOptions.HttpTokens=required`, set it as the default and run `start-instance-refresh`. `notes`
  warns that it replaces the instances.

### Task 8: encryption domain, at rest and in transit (`encryption.json`)

| ID | Check | Eval | Sev | Rem | Drata | Vanta | SH/CIS |
|---|---|---|---|---|---|---|---|
| ENC-001 | EBS encryption by default in every region with EC2 | jq `ec2 get-ebs-encryption-by-default` | high | cli | 218 ✓ | #20 | EC2.7 / 5.1.1 |
| ENC-002 | Encrypted EBS volumes | jq `describe-volumes` | high | plan | 218 ✓ | — | EC2.3 |
| ENC-003 | Encrypted RDS (instances and clusters) | jq | high | plan | 68 ✓ | #21 | RDS.3 / 2.2.1 |
| ENC-004 | Encrypted EFS | jq | high | plan | 231 ✓ | #24 | EFS.1 |
| ENC-005 | Default encryption on S3 | py:`s3_default_encryption` | high | cli | 69 ✓ | — | — |
| ENC-006 | Rotation of own symmetric CMKs | py:`kms_rotation` (`list-keys` + `describe-key` + `get-key-rotation-status`) | high | cli | 223 ✓ | #29 | KMS.4 / 3.6 |
| ENC-007 | CMKs not scheduled for deletion | jq `describe-key` for_each | medium | dec | — | — | KMS.3 |
| ENC-008 | Rotation enabled in Secrets Manager | jq `secretsmanager list-secrets` | medium | dec | — | — | SecretsManager.1 |
| TLS-001 | S3 buckets deny `aws:SecureTransport=false` | py:`s3_tls_only` (`get-bucket-policy` for_each; `NoSuchBucketPolicy` = fail) | high | dec | 234 ✓ | #15 | S3.5 / 2.1.1 |
| TLS-002 | ALB HTTP listeners redirect to HTTPS | py:`alb_http_redirect` | high | cli | 299 ✓ | — | ELB.1 |
| TLS-003 | ALB TLS policy ≥ 1.2 (`ELBSecurityPolicy-TLS13-1-2-2021-06` recommended) | py:`alb_tls_policy` | medium | cli | — | — | ELB.17 |
| TLS-004 | RDS forces SSL (`rds.force_ssl=1` / `require_secure_transport=ON`) | py:`rds_force_ssl` | medium | plan | — | — | — |
| TLS-005 | ACM certificates with > 30 days of validity | py:`acm_expiry` (`params.min_days=30`) | medium | plan | — | #13 (IAM certs) | ACM.1 |

**Task notes:**
- **ENC-003:** `planned_change` with the steps snapshot → `copy-db-snapshot --kms-key-id` → restore →
  endpoint switch. `downtime: true`.
- **TLS-001:** the command fetches the current policy into a file, adds the Deny statement with
  `python3 -c` (CloudShell has python3) and runs `put-bucket-policy`. `kind: cli_with_decision`, because the
  resulting policy has to be reviewed before applying it.
- **TLS-004:** no verified Security Hub control; uses only `tsc_inferred` CC6.7 and `iso_inferred`
  A.8.24.

### Task 9: network and data domains (`network.json`, `data.json`)

| ID | Check | Eval | Sev | Rem | Drata | Vanta | SH/CIS |
|---|---|---|---|---|---|---|---|
| NET-001 | No 0.0.0.0/0 or ::/0 to 22 in SGs of regions with active ENIs | py:`sg_open_port` (`params.port=22`) | high | cli | 102 ✓ | #33, #34 | EC2.53/.54 |
| NET-002 | Same for 3389 | py:`sg_open_port` (`port=3389`) | high | cli | 228 ✓ | #33, #34 | EC2.53/.54 |
| NET-003 | Same for 80 | py:`sg_open_port` (`port=80`) | high | dec | 291 ✓ | — | — |
| NET-004 | No "ALL traffic" rule from a CIDR | py:`sg_all_traffic` | high | cli | 119 ✓ | — | — |
| NET-005 | NACL without 0.0.0.0/0 or ::/0 to 22/3389 | py:`nacl_admin_ports` | high | dec | 227 ✓ | #32 | EC2.21 |
| NET-006 | Default SG with no rules, in all VPCs in all regions (`all_regions`) | py:`default_sg_empty` | high | cli | 233 ✓ | #35 | EC2.2 / 5.5 |
| NET-007 | RDS not public and not in a subnet with a route to an IGW | py:`rds_not_public` (`describe-db-instances` + `describe-route-tables`) | critical | plan | 220 ✓ | #23 | RDS.2 |
| NET-008 | WAF associated with public ALB, API GW and CloudFront | py:`waf_associated` (`wafv2 list-resources-for-web-acl`) | high | dec | 122 ✓ | — | — |
| DAT-001 | RDS automated backups: retention > 0 (FAIL); < 7 → offender with `severity_override: low` | py:`rds_backups` | high | cli | 107 ✓ | — | RDS.11 |
| DAT-002 | RDS Multi-AZ in prod (tag `Environment` in {prod, production}, or no tag) | jq | high | plan | 30 ✓ | — | RDS.5 |
| DAT-003 | RDS with auto minor upgrade | jq | high | cli | 219 ✓ | #22 | RDS.13 |
| DAT-004 | RDS with deletion protection | jq | medium | cli | — | — | RDS.8 |
| DAT-005 | DynamoDB PITR | jq `describe-continuous-backups` for_each | high | cli | 301 ✓ | — | DynamoDB.2 |
| DAT-006 | S3 versioning | jq `get-bucket-versioning` for_each | high | cli | 108 ✓ | — | — |
| DAT-007 | Block Public Access per bucket (all 4 flags) | py:`s3_bpa` | critical | cli | 104 ✓ | #16 | S3.8 |
| DAT-008 | AWS Backup jobs from the previous day OK | py:`backup_jobs_recent` | high | plan | 132 ✓ | — | — |
| DAT-009 | Backup failure alerts (vault notifications to SNS) | py:`backup_vault_notifications` | high | dec | 133 ✓ | — | — |
| DAT-010 | AWS Backup plan with a daily rule and retention ≥ 7 | py:`backup_plan_rules` | medium | dec | — | — | — |
| DAT-011 | ElastiCache Multi-AZ | jq | high | plan | 30 ✓ | — | ElastiCache.3 |

**Task notes:**
- **NET-003 (port 80):** `notes` explains that an ALB with a redirect still fails Drata test 291. The
  option is to expose only 443, or to exclude the resource in Drata with a justification.
- **Severity:** `severity_override` in `detail` is honored in Task 13.

### Task 10: monitoring domain (`monitoring.json`)

All use `py:alarm_coverage` with `params = {"namespace", "metric", "resource_dimension"}`.

**Logic of `alarm_coverage`:**
1. For each resource of the type, there is an alarm (`cloudwatch describe-alarms`) with that metric and that
   dimension.
2. That alarm has `AlarmActions` to an SNS topic.
3. That topic has ≥ 1 confirmed subscription: `sns list-subscriptions-by-topic`, with `SubscriptionArn`
   other than `PendingConfirmation`.

`detail.missing_part` says which of the three parts is missing: `alarm`, `action` or `confirmed_subscription`.

| ID | Resource | Metric | Sev | Drata | Vanta |
|---|---|---|---|---|---|
| MON-001 | RDS | `AWS/RDS CPUUtilization` | high | 112 ✓ | Alarm tests |
| MON-002 | RDS | `FreeStorageSpace` | high | 113 ✓ | same |
| MON-003 | RDS | `ReadIOPS` / `WriteIOPS` (2 possible offenders) | high | 114 ✓, 290 ✓ | same |
| MON-004 | RDS | `FreeableMemory` | high | 206 ✓ | same |
| MON-005 | EC2/ASG | `AWS/EC2 CPUUtilization` (dimension `InstanceId` or `AutoScalingGroupName`) | high | 118 ✓ | same |
| MON-006 | ALB | `HTTPCode_Target_5XX_Count`, `UnHealthyHostCount` and `TargetResponseTime` | high | 296 ✓, 298 ✓, 294 ✓ | same |
| MON-007 | SQS | `ApproximateAgeOfOldestMessage` | high | 115 ✓ | same |
| MON-008 | Lambda | `Errors` | high | 300 ✓ | same |
| MON-009 | DynamoDB/ElastiCache | storage or CPU depending on type | high | 117 ✓ | same |

**Remediation:** all the checks use `cli_with_decision`. The command is `put-metric-alarm`, with the
threshold as the placeholder `__FILL_IN_THRESHOLD__` and `--alarm-actions` with `__FILL_IN_SNS_TOPIC_ARN__`, plus
the step to subscribe and confirm the email.

### Task 11: inventory, integration and email domains (`inventory.json` in checks, `integration.json`, `email.json`)

| ID | Check | Eval | Sev | Rem | Drata | Vanta |
|---|---|---|---|---|---|---|
| INV-001 | `VantaOwner` tag with email format on resources of types supported by Vanta | py:`tag_present` (`params.key=VantaOwner`, `params.pattern=email`) over `__inventory__` | high | dec | — | "Inventory items have active owners" |
| INV-002 | `VantaContainsUserData` on S3, RDS, DynamoDB and SQS | py:`tag_present` | medium | dec | — | "…contain user data" |
| INV-003 | `VantaNonProd=true` is not on resources with `Environment` prod | py:`nonprod_on_prod` | high | cli | — | (scoping) |
| INV-004 | Configurable organizational tags (`params.keys`, by default `Project`, `Environment`, `Owner`) | py:`tags_present` | low | dec | — | — |
| INT-001 | If `DrataAutopilotRole` exists: it has `SecurityAudit`; if it does not exist → `N/A` | py:`drata_role` | high | cli | 123 ✓ | — |
| INT-002 | `DrataAutopilotRole` with `backup:ListRecoveryPointsByResource` and `backup:ListBackupJobs` | py:`drata_backup_perms` | medium | cli | 132 ✓, 133 ✓ | — |
| INT-003 | If `vanta-auditor` exists: `SecurityAudit` + managed (not inline) `VantaAdditionalPermissions` | py:`vanta_role` | high | dec | — | permissions doc |
| INT-004 | CMK key policies allow the auditor roles the read actions | py:`kms_auditor_access` | medium | dec | 223 ✓ | KMS doc |
| EML-001 | Verified SES identity with Easy DKIM `SUCCESS` | jq `sesv2 get-email-identity` for_each | medium | dec | — | — |
| EML-002 | Configuration set with `TlsPolicy=REQUIRE` | jq `sesv2 get-configuration-set` | medium | cli | — | — |
| EML-003 | Configuration set with an event destination | jq `get-configuration-set-event-destinations` | medium | dec | — | — |
| EML-004 | SPF on the sending domain | dns TXT (`v=spf1`) | medium | dec | — | — |
| EML-005 | DMARC `_dmarc.<domain>` with `p=quarantine` or `reject` (absent → `high`) | dns TXT | high | dec | — | — |
| EML-006 | SES account with production access and suppression list | jq `sesv2 get-account` | low | con | — | — |

**Task notes:**
- **File name:** the inventory checks file is named `checks/inventory.json`, distinct from
  `references/inventory.json` (resource types). Do not confuse them in `load_checks`, which only reads
  `checks/`.
- **Mappings:** for EML-*, INV-* and the checks without Drata ✓, fill in `tsc_inferred` and `iso_inferred`.
  - INV → CC6.1/A.5.9.
  - EML → CC6.7/A.8.24, A.5.14.
- **Closing:** when finished, `validate_catalog.py` prints `OK: 98 checks` (17 + 13 + 13 + 13 + 19 + 9 + 14).

---

### Task 12: vault index and feature resolution

**Files:**
- Create: `auditing-infra-compliance/scripts/vault_index.py`
- Create: `auditing-infra-compliance/scripts/redact.py` (minimal: `mask(text) -> str` for
  `AKIA`/`ASIA` keys and `aws_secret_access_key` assignments)
- Create: `tests/fixtures/typed-vault/`
  - structure from `creating-typed-knowledge-vaults`: `_meta/relations.md`, `_meta/edges.md`,
    `systems/`, `constraints/`, `decisions/`, `failures/`, `MOC/`;
  - fictional platform "Acme Notes" with the feature `systems/Email delivery.md`, which `depends on` →
    SES Identity, Mailer Lambda and Mail Queue (SQS);
  - `Mailer Lambda` `depends on` → `Mailer Role`;
  - a PII `constraints/` note;
  - a `status: proposed` note (DMARC reject);
  - fictional IDs inside the notes.
- Create: `tests/fixtures/free-vault/`
  - 6 handwritten notes: hub `Acme Notes.md` with `## Conectado a`, `RDS - acme-db.md` with a table
    `| Campo | Valor |` that claims "KMS: CMK propia", `S3 - uploads.md`, `VPC.md`
    (the Spanish headings and labels are deliberate: they stand for a user's Spanish-language vault);
  - a note with a broken link.
  - The note with a secret is **not** committed: the tests create it with `helpers.make_secret_note` in a
    temporary copy.
- Test: `tests/test_vault_index.py`

**Interfaces:**
- **Produces `vault_index.py`:**
  - `build_index(vault: Path) -> dict`;
  - `resolve_feature(index: dict, query: str, max_depth: int = 3) -> dict`;
  - CLI:
    - `vault_index.py index <vault> -o vault-index.json`;
    - `vault_index.py feature <vault-index.json> "<text>"` → JSON on stdout.
- **Index format:**
  ```
  {"kind": "typed|free", "root": str,
   "notes": [{"path", "title", "type"|null, "status"|null, "source": [str],
              "edges": [{"relation", "target", "layer": "structural|associative"}],
              "links": [str], "aws_ids": [{"kind", "value"}],
              "kv": {field: value}, "headings": [str], "inferred_type": str|null}],
   "broken_links": [{"from", "target"}],
   "secrets_detected": [{"path", "pattern"}],
   "obsidian_plugins": [str]}
  ```
- **Vault type detection:** it is `typed` if `_meta/relations.md` exists, or if ≥ 50 % of the notes
  have `type:` frontmatter.
- **Reading the notes:**
  - The frontmatter is parsed by hand: a `---` block with `key: value` and `- item` lists. No PyYAML.
  - Edges: regex `^- (?P<rel>[a-z ]+) → \[\[(?P<target>[^\]|#]+)`.
  - `aws_ids`, with these regexes:
    - `arn:aws[a-z-]*:[^\s)\]|]+`;
    - `\b(i|sg|vpc|subnet|vol|acl|rtb|igw|nat|eni|lt)-[0-9a-f]{8,17}\b`;
    - `\bdb-[A-Z0-9]{26}\b`.
  - Access keys: the pattern `(AKIA|ASIA)[0-9A-Z]{16}` goes **only** to `secrets_detected` (`pattern:
    "aws_access_key_id"`), never to `aws_ids`.
  - `inferred_type` (free vault): file-name prefix before ` - ` or first token, mapped to
    a type in `inventory.json`: `RDS`→`rds_instance`, `S3`→`s3_bucket`, `VPC`→`vpc`, `ALB`→`elbv2`,
    `EC2`→`ec2_instance`, `SES`→`ses_identity`, `Lambda`→`lambda_function`, `SQS`→`sqs_queue`,
    `IAM`→`iam_role`, `KMS`→`kms_key`.
- **Content of the notes:** all text that enters the index (`kv`, `title`, `headings`) goes through
  `redact.mask`.
- **Files that are read:** only `*.md`. Dotfiles and dotdirs are skipped; `.obsidian/plugins` is only listed.
- **`resolve_feature` response:**
  ```
  {"candidates": [path, …],
   "chosen": path|null,
   "components": [{"path", "title", "via": [relations], "depth", "aws_ids", "status"}],
   "constraints": [path], "pii": bool,
   "confidence": "typed|inferred"}
  ```
- **`resolve_feature` logic:**
  - **Candidates:** exact title match (case- and accent-insensitive), then match in the H1,
    then in the body.
  - **Several candidates:** if there is > 1 candidate at the same level, `chosen = null` (Claude asks).
  - **Typed vault:** BFS over outgoing structural edges `depends on`, `requires` and `enables`, plus
    incoming `is part of` (via `_meta/edges.md` or by scanning). Only notes in `systems/` are collected;
    the `constraints/` notes reached go to `constraints`.
  - **Free vault:** BFS over wikilinks, with depth 2.
  - **PII:** `pii` is true if a constraint or a component contains `PII`, `datos personales`,
    `user data`, `personal data` or `email` (`datos personales` is a deliberate Spanish term, since vaults may
    be written in Spanish).

- [ ] **Step 1: write the failing tests:**
  - `test_detects_typed`, `test_detects_free`;
  - `test_parses_frontmatter_and_edges`;
  - `test_extracts_aws_ids`;
  - `test_masks_keys_in_index`: temporary copy of the free vault plus `make_secret_note`. The built key
    does not appear in the index's serialized JSON, and `secrets_detected` contains the path;
  - `test_ignores_dotfiles_and_env`: create `.env` in a temporary copy of the fixture; it is not read (a
    mock of `open` that fails if it is opened is used);
  - `test_broken_links_reported`;
  - `test_feature_typed_email_components`: components = {SES Identity, Mailer Lambda, Mail Queue, Mailer
    Role}; `pii` is True; the `proposed` note appears with `status == "proposed"`;
  - `test_feature_ambiguous_returns_candidates`;
  - `test_feature_not_found_empty`;
  - `test_free_vault_inferred_types_and_kv`: the RDS `kv` includes the CMK claim.
- [ ] **Step 2:** run. Expected: FAIL.
- [ ] **Step 3:** implement `vault_index.py` and the minimal `redact.py`.
- [ ] **Step 4:** run everything. Expected: OK.
- [ ] **Step 5:** commit with `feat: vault indexer and feature resolution`.

---

### Task 13: masking and assembly of `findings.json`

**Files:**
- Modify: `auditing-infra-compliance/scripts/redact.py`
- Create: `auditing-infra-compliance/scripts/assemble_findings.py`
- Create: `tests/fixtures/vault-claims.json`, `tests/fixtures/run-sample/` (`collect` output with
  fictional `checks-result.json` and `inventory.json`)
- Test: `tests/test_redact.py`, `tests/test_assemble.py`

**Interfaces:**
- **Consumes:** `catalog.load_checks`, `catalog.resolve_mappings` and `catalog.load_frameworks`, plus
  `checks-result.json` and `inventory.json` (Task 4) and `vault-index.json` (Task 12).
- **Produces, in `redact.py`:**
  - `mask(text: str, *, keep_emails: frozenset[str] = frozenset()) -> str`;
  - `mask_obj(obj: object, **kw) -> object` (recursive).
- **Produces `vault-claims.json`** (written by Claude):
  ```
  [{"kind": "DRIFT|UNDOCUMENTED|DOCUMENTED_ONLY|DOCUMENTED_GAP|EVAL",
    "check_id": str|null, "resource": {"type","id","region"}|null,
    "vault_note": str|null, "vault_claim": str|null, "actual": str|null,
    "status": str|null, "detail": obj|null,      // only for EVAL (resolves a PENDING_CLAUDE)
    "severity": str|null,                         // required if check_id is null
    "breaks_tests": [{"tool","test"}]}]           // for vault recommendations that would break tests
  ```
- **Produces, in `assemble_findings.py`:**
  - CLI: `--run-dir DIR [--vault-index FILE] [--vault-claims FILE] --platform STR --mode STR [--target STR] [--lang en]`.
    Writes `DIR/findings.json`.
  - Function: `assemble(run_dir: Path, vault_index: dict|None, claims: list, meta: dict, skill_dir: Path) -> dict`.
- **Schema of `findings.json`:**
  ```
  {"meta": {"platform", "mode", "target", "generated_at" (ISO 8601 local), "lang",
            "catalog_checks": int, "vault": {"path", "kind"}|null,
            "aws": {"account_id", "identity_arn", "regions"}|null},
   "summary": {"by_status": {…}, "by_severity_fail": {…}, "drata_tests_failing": [int],
               "vanta_tests_failing": [str], "not_verified": int},
   "findings": [{"id": "F-0001", "check_id", "title", "domain", "status", "severity",
                 "resource": {"type","id","region","name"}, "evidence": obj, "vault_claim": str|null,
                 "vault_note": str|null, "mappings": <resolve_mappings>, "remediation": {…instantiated},
                 "evaluated_by": "script|claude", "vacuous": bool, "breaks_tests": [...],
                 "depends_on_me": [{"tool","test","name"}]}],
   "dependencies": [{"resource_id", "resource_type", "tests": [{"tool","test","name"}]}],
   "coverage": {"iso": [{"id","name","status": "FAIL|PASS|NOT_VERIFIED|NOT_TOUCHED","category": "technical|organizational|inherited"}],
                "tsc": [ … same … ]},
   "warnings": [str], "notes": [str]}
  ```
- **Rules of `assemble`:**
  1. **Order of the findings:** severity (`critical` → `low`), then status (`FAIL`, `DRIFT`,
     `UNDOCUMENTED`, `DOCUMENTED_GAP`, `NOT_VERIFIED`, `DOCUMENTED_ONLY`, `PASS`, `N/A`), then
     `check_id`. The `F-NNNN` IDs are assigned in that order.
  2. **Severity:** `severity_override` from `detail` wins over the catalog's. A claim with non-empty
     `breaks_tests` → `DRIFT` with severity `high`. `UNDOCUMENTED` without severity → `low`.
  3. **Remediation:** `{resource_id}`, `{region}`, `{account_id}` and `{resource_name}` are replaced in
     `commands`, `steps` and `verify_after`. The `__FILL_IN_*__` placeholders are left intact.
  4. **Dependencies:** each `PASS` with Drata/Vanta mappings adds its tests to the resource, deduplicated.
     Each finding's `depends_on_me` is the `dependencies` entry for its resource.
  5. **Coverage:** the status of each ISO/TSC ID is the worst of the findings that map it (`FAIL` >
     `NOT_VERIFIED` > `PASS`). With no findings: `NOT_TOUCHED`. The `category` comes from `technical` and
     `responsibility` in the framework JSONs: `inherited` wins; otherwise, `technical` → `technical`;
     otherwise `organizational`.
  6. **Masking:** `mask_obj` over `evidence`, `vault_claim` and `actual`, with `keep_emails` = values
     of the inventory's `VantaOwner` tags.
  7. **Warnings:** those from `collect`, the `broken_links` and the vault's `secrets_detected` are added. For
     each detected secret a `critical` finding is added with `check_id: null`, title "Plaintext credentials in
     the vault", and only the path and pattern as evidence.
  8. **EVAL claims:** they resolve the `PENDING_CLAUDE` entries with the same `check_id` and resource. The
     `PENDING_CLAUDE` entries without an EVAL claim stay `NOT_VERIFIED`, with a warning. Findings resolved by EVAL
     carry `evaluated_by: "claude"`.
  9. **No AWS** (`checks-result.json` with `"aws": null` or absent): there are only `DOCUMENTED_*` findings,
     vault `DRIFT` and detected secrets. `meta.aws` is null.

- [ ] **Step 1: write the failing tests:**
  - `test_redact.py`:
    - `test_mask_access_key`: the built key `"AKIA" + "TESTKEYABCDEMNOP"` → `AKIA…MNOP`;
    - `test_mask_secret_assignment`;
    - `test_mask_email_except_kept`;
    - `test_mask_obj_recursive`.
  - `test_assemble.py`:
    - `test_sort_order_and_ids`;
    - `test_severity_override`;
    - `test_breaks_tests_claim_is_high_drift`;
    - `test_remediation_placeholders_filled_and_fill_in_kept`;
    - `test_dependencies_from_passes`;
    - `test_coverage_worst_status_and_categories`: A.7.1 is `inherited` and `NOT_TOUCHED`;
    - `test_findings_are_masked`;
    - `test_secret_in_vault_creates_critical_finding_without_value`;
    - `test_eval_claim_resolves_pending`;
    - `test_pending_claude_unresolved_becomes_not_verified`;
    - `test_no_aws_only_documented_findings`;
    - `test_no_percentage_anywhere`: the serialized JSON contains no `%` or `score`/`compliance` keys.
- [ ] **Step 2:** run. Expected: FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run everything. Expected: OK.
- [ ] **Step 5:** commit with `feat: findings assembly with masking, dependencies and coverage`.

---

### Task 14: HTML template and renderer

**Files:**
- Create: `auditing-infra-compliance/assets/report-template.html`
- Create: `auditing-infra-compliance/scripts/render_report.py`
- Create: `tests/fixtures/findings-sample.json`
  - covers all statuses and severities, a `planned_change` and a hostile name
    `"<script>alert(1)</script>"`;
  - includes a tag `x"onmouseover=` and a command with a backtick.
- Test: `tests/test_render.py`

**Interfaces:**
- **Consumes:** `findings.json` (Task 13).
- **Produces:** `render_report.py <findings.json> -o <report.html>` and the function
  `render(findings: dict, template: str) -> str`.
- **Data injection:** the template contains a single marker
  `<script id="data" type="application/json">/*__FINDINGS__*/</script>`. `render` replaces the marker with
  the JSON, escaping `<` as `<`, `>` as `>` and `&` as `&`.
- **The template's JS renders:**
  1. **Header:** platform, mode and target, sources, account, identity, regions and date.
  2. **Summary:** count chips per status and per severity (only `FAIL`), list of failing Drata and
     Vanta tests, count of `NOT_VERIFIED`. No percentage.
  3. **Filters:** severity, status, domain, tool (Drata/Vanta) and framework (SOC 2/ISO), plus a
     search box. The chosen filter is saved in `localStorage`, inside `try/catch`.
  4. **Cards:**
     - title, resource and region, status and severity;
     - mapping chips: the inferred ones with dotted style and the text "inferred";
     - evidence in `<pre>`;
     - what the vault claims;
     - "Tests that depend on this resource" (`depends_on_me`);
     - remediation:
       - `<pre><code>` block with a **Copy** button per command, and a "Copy all" button for the block;
       - risk, downtime and kind labels;
       - `__FILL_IN_*__` highlighted with `<mark>`;
       - for `planned_change`, a red warning and numbered steps;
       - for `console_only`, steps without a code block;
       - "Verify after" with its own Copy.
  5. **Global button** "Copy low-risk fixes", by severity: concatenates the `commands` of the
     `FAIL` entries with `kind == "cli"` and `risk == "low"`, separated by `# F-NNNN …` comments.
  6. **"Do not touch without review":** table of `dependencies`.
  7. **Coverage:** two tables, ISO and TSC, grouped by category.
  8. **Warnings and notes.**
  9. **Fixed footer:** "Automated technical pre-audit. It is not an audit opinion and does not cover
     organizational controls (policies, HR, teams, vendors, ISMS)."
- **Copy:** `navigator.clipboard.writeText`. If it fails (for example, from `file://` without permissions), it uses a
  hidden `textarea` with `document.execCommand('copy')`. The confirmation is visual ("Copied").
- **Escaping:** all text enters the DOM via `textContent`, never `innerHTML` with data. `<mark>` for
  `__FILL_IN_*__` is built by splitting the text and creating nodes.
- **Theme:** CSS tokens in `:root`, dark mode with `@media (prefers-color-scheme: dark)`, `@media print`
  (expands everything and hides buttons and filters). Layout usable at 375 px wide.

- [ ] **Step 1: write the failing tests:**
  - `test_no_external_resources`: regex over the HTML with no `<script[^>]+src=`, `<link[^>]+href=`,
    `<img[^>]+src="http`, `@import` or `url(http`;
  - `test_data_injected_and_escaped`: the HTML contains neither `</script><script>alert` nor the literal
    `<script>alert(1)`, and contains `<script`;
  - `test_no_innerhtml_with_data`: regex `innerHTML\s*=\s*[^'"\s]` over the template → 0 matches;
  - `test_has_copy_fallback`: the template contains `navigator.clipboard` and `execCommand('copy')`;
  - `test_footer_disclaimer_present`;
  - `test_no_percentage_in_summary_strings`: the template's i18n strings contain no `%`;
  - `test_hostile_names_escaped`: render the fixture; then the stdlib `html.parser` verifies that there are
    exactly 2 `<script>` elements, the data one and the app one.
- [ ] **Step 2:** run. Expected: FAIL.
- [ ] **Step 3:** implement the template and the renderer.
- [ ] **Step 4:** run everything. Expected: OK.
- [ ] **Step 5: visual verification.** Render `findings-sample.json` to
  `compliance-reports/sample/report.html` and open it in the browser. Check:
  - copy a command and paste it into a terminal;
  - dark mode;
  - print view;
  - 375 px width.

  Note the problems and fix them before the commit.
- [ ] **Step 6:** commit with `feat: self-contained html report with copyable remediation`.

---

### Task 15: fix verification stage

User request of 2026-11-12. Spec §9bis.

**Files:**
- Create: `auditing-infra-compliance/scripts/verify_remediation.py`
- Create: `auditing-infra-compliance/references/conflict-rules.json` (CR-001 to CR-010 from spec §9bis.2)
- Modify: `scripts/validate_catalog.py` and `scripts/catalog.py`: validate that the `check_id` values cited in
  `conflict-rules.json` exist
- Modify: `scripts/render_report.py` and `assets/report-template.html`: badge per card, "Verification"
  section, and a low-risk button that excludes `CONFLICT`
- Test: `tests/test_verify.py`, `tests/fixtures/findings-verify.json`, `tests/fixtures/verification-claims.json`

**Interfaces:**
- **Consumes:** `findings.json` (Task 13), `inventory.json` (Task 4), `render(findings, template)` (Task 14).
- **Produces, in `verify_remediation.py`:**
  - `verify(findings: dict, inventory: list, rules: list, *, claims: list | None = None, runner=subprocess.run, which=shutil.which, check_cli: bool = False) -> dict`;
  - CLI: `verify_remediation.py --run-dir DIR [--claims FILE] [--check-cli]`. Reads `DIR/findings.json` and
    `DIR/inventory.json` and writes `DIR/verification.json`.
- **Schema of `verification.json`:**
  ```
  {"per_finding": {"F-0001": {"status": "OK|REVIEW|CONFLICT",
                               "issues": [{"kind", "message", "source": "script|claude", "rule_id"|null}]}},
   "conflicts": [{"rule_id", "findings": [ids], "message", "status"}],
   "gaps": [{"kind": "no_fix|not_verified|resource_without_check|no_verify_after", "message", "ref"}],
   "apply_order": ["F-0003", …],
   "fill_in_pending": int,
   "cli_checked": bool,
   "summary": {"OK": int, "REVIEW": int, "CONFLICT": int}}
  ```
- **Values of `kind` in `issues`:** `syntax`, `invalid_cli`, `unresolved_placeholder`,
  `requires_fill_in`, `hygiene`, `destructive_without_warning`, `rule_conflict`, `dependency_impact`,
  `claude`.
- **Format of `conflict-rules.json`:**
  ```
  [{"id": "CR-001", "when": {"all_fail": ["NET-003", "TLS-002"]} | {"any_fail": [...]} | {"fail": "NET-001", "same_resource_fail": "CMP-006"},
    "scope": "same_resource|same_account",
    "status": "CONFLICT|REVIEW",
    "message": str,
    "order": [["CMP-006", "NET-001"]] | []}]       // (before, after) pairs
  ```
  In CR-001, `same_resource` is resolved by the SG associated with the ALB. `TLS-002` in `PASS` (redirect already
  configured) also counts, so the condition is `{"fail": "NET-003", "related_check_any": "TLS-002"}`.
  The exact rule is left to the implementer's discretion, as long as it passes `test_cr001_port80_vs_redirect`.

**Rules of `verify`:**
1. **Syntax:** `bash -n` is run with `runner(["bash","-n"], input=<joined commands>, text=True,
   capture_output=True, shell=False)`. A remediation command is never executed.
2. **CLI:** only with `check_cli=True` and `which("aws")`. For each line that starts with `aws `: runs
   `["aws", service, operation, "help"]` with env `PAGER=cat`, `AWS_PAGER=""`, and verifies that each `--flag`
   on the line appears in the help. Without the CLI: `cli_checked: false`, plus an informational gap.
3. **Hygiene and placeholders:** as in spec §9bis.1.
4. **Destructive without warning:** as in spec §9bis.1.
5. **Conflicts:** per `conflict-rules.json`.
6. **Dependency impact:** if a `FAIL` has a non-empty `depends_on_me` → `REVIEW`, naming
   the tests.
7. **Gaps:** as in spec §9bis.1.
8. **Apply order:** spec §9bis.1. If the `order` pairs form a cycle, they are ignored and a
   gap is added.
9. **Claude claims:** they are combined keeping the most severe status. A claim cannot lower a
   `CONFLICT`.

**Render:** `render_report.py` accepts `--verification FILE` (optional) and `render(findings, template,
verification=None)`. The template shows the badge and the reasons on each card, and the
"Verification" section after the summary. Without `verification`, the HTML looks the same as in Task 14.

- [ ] **Step 1: write the failing tests** in `tests/test_verify.py`:
  - `test_syntax_error_is_conflict`: command `aws s3api put-x --bucket "a` left unclosed;
  - `test_bash_n_never_executes`: the fake `runner` records argv; only `["bash","-n"]` is seen, and the
    command goes via stdin;
  - `test_unresolved_placeholder_is_conflict`;
  - `test_fill_in_counted_and_review`;
  - `test_heredoc_or_set_e_is_conflict`;
  - `test_destructive_without_warning_is_review`;
  - `test_cr001_port80_vs_redirect`;
  - `test_cr003_ssh_without_ssm_orders_ssm_first`: `apply_order` puts CMP-006 before NET-001;
  - `test_dependency_impact_names_tests`;
  - `test_gaps_listed`: the 4 gap kinds;
  - `test_apply_order_by_group_and_severity`;
  - `test_order_cycle_ignored_with_gap`;
  - `test_claude_claim_cannot_downgrade_conflict`;
  - `test_check_cli_flags`: the fake `runner` returns a help without `--foo`, and the command with `--foo` yields
    `invalid_cli`;
  - `test_no_cli_available_gap`;
  - `test_conflict_rules_reference_existing_checks`: via `catalog.validate`;
  - `test_render_with_verification_shows_badges_and_section`;
  - `test_low_risk_copy_excludes_conflicts`;
  - `test_render_without_verification_unchanged`.
- [ ] **Step 2:** run `python3 -m unittest tests.test_verify -v`. Expected: FAIL.
- [ ] **Step 3:** implement.
- [ ] **Step 4:** run the full suite. Expected: OK.
- [ ] **Step 5:** commit with `feat: remediation verification stage`.

---

### Task 16: SKILL.md and references, with skill TDD

**Files:**
- Create: `auditing-infra-compliance/SKILL.md`
- Create: `auditing-infra-compliance/references/vault-reading.md`, `remediation-guidelines.md`,
  `report-format.md`, `drata-vanta.md`
- Create: `tests/skill-scenarios.md` (scenarios and results of the baseline and of the post run)

**Interfaces:**
- **Consumes:** all the CLIs of tasks 2, 4, 12, 13, 14 and 15 (exact names and arguments from
  their Interfaces blocks).

**Required content of `SKILL.md`:**
- **Frontmatter:**
  - `name: auditing-infra-compliance`;
  - `description:` in third person, "Use when…". It is triggered by:
    - requests for an audit or pre-audit of AWS infrastructure against SOC 2 / ISO 27001;
    - "does it pass Drata/Vanta?";
    - reviewing a feature or a resource (ID/ARN) against compliance;
    - in Spanish or in English.
  - Under 1024 characters.
- **Procedural body** (≤ 500 lines), in this order:
  1. **Inputs:** a single grouped question for whatever is missing (section 4 of the spec).
  2. **Preflight and hard rules:**
     - never execute remediation;
     - never read `.env*` or credentials;
     - only `collect.py` talks to AWS. Claude does **not** run `aws` directly, except
       `aws sts get-caller-identity` in the preflight.
  3. **Vault index:** `vault_index.py index`.
     - **Extra evidence folder, if given:** Claude reads as context only `.md`, `.html` and `.pdf`,
       never `.env*` or keys. What that folder claims enters as claims with `vault_note` = the file
       path.
  4. **Resolve the scope:**
     - `feature`: `vault_index.py feature`, show the components and **wait for confirmation**;
     - `resource`: type by prefix and context per §6.4 of the spec;
     - write `scope.json`.
  5. **Collect:** `collect.py`, and read only the stdout summary.
  6. **Claude:**
     - resolve the `PENDING_CLAUDE` entries with EVAL claims;
     - compare the vault against `inventory.json` and `checks-result.json`;
     - write `vault-claims.json`, including the vault recommendations that would break tests.
  7. **Assemble:** `assemble_findings.py`.
  8. **Render:** `render_report.py`.
  9. **Verify:**
     - `verify_remediation.py --run-dir … [--check-cli]`;
     - Claude reviews `REVIEW`/`CONFLICT` and the medium- or high-risk fixes against the vault, and writes
       `verification-claims.json`;
     - `verify_remediation.py --claims …` and `render_report.py --verification …` are run again.
  10. **Reply in the chat:** includes the verification's conflicts and gaps, plus the absolute path of the HTML, the counts, the 3–5 most serious findings and what could not be
     verified.
- **"When to load which reference" table.**
- **Rationalizations table** drawn from the baseline.

**Steps:**
- [ ] **Step 1: baseline (RED).** With one subagent per scenario, **without** the skill, run the
  scenarios from spec §13.4 and record in `tests/skill-scenarios.md` what it does wrong and which
  rationalizations it uses:
  - (a) typed vault, feature "email sending", no credentials;
  - (b) free vault, `full` mode, no credentials;
  - (c) an instance ID with no vault and no credentials;
  - (d) a `.env` in a temporary copy of the free vault, plus the request "and fix it yourself".

  The subagents have no AWS credentials: with `AWS_PROFILE` pointing to a nonexistent profile,
  `collect.py` must exit with 2.
- [ ] **Step 2 (GREEN):** write `SKILL.md` and the 4 references. Each rationalization observed in
  step 1 gets an explicit rule in `SKILL.md`.
  - `report-format.md` documents the `scope.json`, `vault-claims.json` and `findings.json` schemas, and the
    `{resource_id, detail}` convention of the JMESPath expressions.
  - `remediation-guidelines.md` documents:
    - placeholders, variables and the no-`set -e` rule;
    - the 4 kinds;
    - that `--force` and `delete-*` are never used outside the `planned_change` kind.
- [ ] **Step 3:** repeat the 4 scenarios **with** the skill. Expected:
  - (a) asks for confirmation of components, marks `proposed` as pending and produces the HTML;
  - (b) warns "untyped vault" and does not invent components;
  - (c) asks for a source (vault or credentials);
  - (d) does not read the `.env`, reports `critical` for plaintext credentials and refuses to execute
    fixes.

  Record the results. If something fails, close the gap (REFACTOR) and repeat.
- [ ] **Step 4:** run `python3 -m unittest discover -s tests -v` and `validate_catalog.py`. Expected: OK.
- [ ] **Step 5:** commit with `docs: skill instructions and references`.

---

### Task 17: end-to-end test with fake AWS, README and live checklist

**Files:**
- Create: `tests/test_e2e.py`, `tests/fixtures/aws/e2e/` (responses for a complete `FakeRunner` of "Acme
  Notes")
- Modify: `README.md`
- Create: `docs/live-test-checklist.md`

**Interfaces:**
- **Consumes:** `collect.main`, `assemble_findings.assemble`, `render_report.render`,
  `verify_remediation.verify` and `vault_index.build_index`.

- [ ] **Step 1: write the failing test `test_full_pipeline_typed_vault`.** Use the typed vault and the e2e
  `FakeRunner`, with:
  - root without MFA;
  - an SG with 22 open;
  - a bucket without BPA;
  - an alarm with a pending subscription;
  - an `AccessDenied` on `inspector2`.

  Run `collect` → fixed claims (a CMK `DRIFT` and an `UNDOCUMENTED`) → `assemble` → `render` →
  `verify` → `render` with verification.
  Assertions:
  - IAM-001 is `FAIL` `critical`;
  - NET-001 is `FAIL` with the SG ID;
  - DAT-007 is `FAIL` `critical`;
  - MON-001 has a `FAIL` with `detail.missing_part == "confirmed_subscription"`;
  - DET-006 is `NOT_VERIFIED` with `missing` that includes `inspector2:BatchGetAccountStatus`;
  - the HTML exists and contains `F-0001`;
  - `verification.json` exists, the NET-001 fix has a status other than `OK` (the fixture's SG
    is on an instance without SSM: CR-003), and the HTML contains the "Verification" section;
  - no argv recorded by the `FakeRunner` has an operation outside the allowlist.
- [ ] **Step 2: write `test_pipeline_without_aws`.** Only the temporary copy of the free vault plus
  `make_secret_note`:
  - `DOCUMENTED_*` findings;
  - a secret `critical`;
  - a broken-link warning.
- [ ] **Step 3:** run. Expected: FAIL or error until the fixtures are adjusted. Adjust **only fixtures or
  real bugs**, never the assertions.
- [ ] **Step 4: complete `README.md`.**
  - What it does and what it does not do.
  - Installation: `ln -s "$PWD/auditing-infra-compliance" ~/.claude/skills/auditing-infra-compliance`.
  - Recommended IAM policy for the profile: `SecurityAudit` + `ViewOnlyAccess`, plus
    `backup:ListBackupJobs`, `backup:ListRecoveryPointsByResource`,
    `inspector2:BatchGetAccountStatus` and `inspector2:ListFindings` if missing.
  - Example requests for the 3 modes.
  - How to run the tests.
  - Phase 2 (pending).
- [ ] **Step 5: write `docs/live-test-checklist.md`.** Acceptance criterion from spec §13.5, without real
  data:
  - **Security Hub:** each `FAILED` control with an equivalent in the catalog appears as `FAIL`.
  - **Drata:** each green test with an equivalent does not appear as `FAIL`, or the difference is explained.
  - **Vault:** the known differences appear as `DRIFT` or `UNDOCUMENTED`.
  - **Security:**
    - zero write operations in `raw/` and in the log;
    - run time noted.
- [ ] **Step 6:** run the full suite and the validator. Expected: all OK and `OK: 98 checks`.
- [ ] **Step 7: check for own references.** The user supplies the terms to search for and `grep -rIl -i -E "<terms>" .`
  is run by hand; the pattern is not stored in the repo. Expected: no results.
- [ ] **Step 8:** commit with `test: end-to-end pipeline; docs: readme and live checklist`.

---

## After the plan (manual, with the user)

- **Live test** with `docs/live-test-checklist.md` on a real account and a read-only profile
  provided by the user. The reports from that run stay outside the repo.
- **Phase 2,** with a separate plan: live cross-checking with the Drata MCP or the Vanta API and Prowler ingestion.
