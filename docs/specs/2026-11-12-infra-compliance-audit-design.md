# Design: SOC 2 / ISO 27001 infrastructure audit skill

Date: 2026-11-12 · Status: draft for approval · Folder: `trabajo/skills/infra-compliance-audit/`

Decisions marked **[designer's decision]** were not made by the user; they are there for you to review.
The research sources are in section 15.

---

## 1. Intent

An organization operates several platforms on AWS that pass, or are about to go through, SOC 2 and ISO 27001
audits. Their compliance is monitored by **Drata or Vanta**, depending on the platform. Today, finding out what will
make a Drata or Vanta test fail means reviewing the console by hand, or waiting for the tool to flag it red.

The skill performs a **technical pre-audit of the infrastructure**:

1. It reads the platform's Obsidian vault to learn **what exists and what it is for**.
2. With **read-only** AWS credentials, it verifies **how things are actually configured**.
3. It produces a **self-contained `.html`**. Each problem shows:
   - what fails and why it matters (SOC 2 criterion, ISO 27001:2022 control and the equivalent Drata/Vanta test);
   - the evidence that proves it;
   - the **AWS CloudShell** command or commands that fix it, with a **Copy** button.

The practical goal is that the automatic Drata and Vanta tests **do not fire**. It does not aim to issue an
audit opinion.

## 2. Goals, non-goals and anti-goals

**Goals**
- **G1. Three scopes:**
  - the whole infrastructure (`full`);
  - one feature of a platform, for example "review email sending" (`feature`);
  - a single resource, by ID or ARN (`resource`).
- **G2. Interchangeable sources:**
  - vault only: evaluates what is documented;
  - credentials only: evaluates what is real, with a discovered inventory;
  - both: evaluates what is real and also **detects differences between vault and reality** (drift).
- **G3. Typed and free-form vaults.** Typed ones (created with `creating-typed-knowledge-vaults`) are the normal
  case. Free-form ones (hand-written notes, no frontmatter) are read on a "best effort" basis.
- **G4. For each finding:** SOC 2 criterion (TSC 2017, revised in 2022), ISO/IEC 27001:2022 Annex A control,
  Drata test (number) and Vanta test (name). Each mapping states whether it is **documented in a source**
  or **inferred**.
- **G5. CloudShell remediation,** copyable, with clear placeholders. Risky fixes, or fixes that
  require a decision, are marked as such.
- **G6. Works without Drata or Vanta connected.** If a Drata or Vanta MCP is connected, results can be
  cross-checked against it (phase 2, section 11).

**Non-goals**
- Organizational controls: policies, risk analysis, SoA, training, background checks, MDM and
  employee devices, HR, vendors, ISMS management (clauses 4–10).
  - The report lists them as **"out of scope of this report"** so nobody reads "all green" as
    "ready for SOC 2".
- Other clouds (GCP, Azure).
- Several AWS accounts or an AWS Organization in a single run (v1: one account per run).
- Scanning code or IaC repositories (Checkov, SAST).
- Modifying the vault. The skill never writes to the vault; at most it suggests converting it to the typed format with
  `creating-typed-knowledge-vaults`.

**Anti-goals (it would fail even if it works)**
- **A1.** The skill **runs anything that modifies AWS**. It only runs read commands; fixes are
  executed by a human in CloudShell.
- **A2.** A **"compliance" percentage**, a score or a "pass / fail" without saying what it is based on. It would be
  an invented audit opinion. The report gives counts by status and severity and **a verdict per source**
  (`OPTIMAL`, `NOT_OPTIMAL` or `NOT_VERIFIABLE`, always with its basis: AWS, vault or both), never a score or a
  percentage. A verdict based only on the vault never says that AWS verified anything.
- **A3.** **Invented or wrongly numbered criteria or controls.** The GitHub skill has CC6.4, CC6.5, CC6.6,
  CC9.1 and CC9.2 mislabeled, and C1.3 and PI1.x invented. Every mapped ID must exist in the embedded official
  catalog, and a validator checks it.
- **A4.** Treating as verified something that **only the vault says**. A `status: proposed`, or a note that says
  "encrypted with CMK" when the account uses `aws/rds`, does not count as a control in force.
- **A5.** Exposing secrets: reading `.env`, printing keys or dumping data contents.
- **A6.** A remediation command that **looks like a one-liner and is destructive**, with no warning. Example:
  encrypting an existing RDS instance requires a snapshot, an encrypted copy and a restore, with downtime.

## 3. Users and context

- **Engineers** (DevOps or backend) who prepare or maintain platforms for Drata or Vanta.
  They run Claude Code in interactive mode.
- **Several platforms**, each with its own vault and its own AWS account.
- **Language:** the user writes in Spanish. The report is produced **in English only** (a change made after
  approval, see "Changes after approval"); `--lang` is reserved and only accepts `en`. IDs,
  commands and Drata and Vanta test names stay in their original language.

## 4. Inputs and invocation

The skill is triggered by requests such as "audit the infra of X for SOC 2", "review the email sending of platform
Y", "review instance i-0abc…" or "does this pass Drata/Vanta?".

On startup, the skill resolves these inputs. It asks only for what is missing, **in a single message**:

| Input | How it is obtained | Required |
|---|---|---|
| Scope | Deduced from the request: `full`, `feature: <text>` or `resource: <id/arn>` | Yes |
| Vault | Path. If not given, it asks; "there is no vault" is a valid answer | No |
| Extra evidence folder | Optional path with audit HTMLs or PDFs, read as context. Usually next to the vault, outside it | No |
| AWS credentials | **Only** via `AWS_PROFILE` / `--profile` or the already-configured environment. Verified with `aws sts get-caller-identity` | No |
| Regions | The ones the user names. Otherwise: enabled regions with resources, plus `us-east-1` for global services | No |
| Compliance tool | Drata, Vanta or both (`--tool drata\|vanta\|both`). Stored in `meta.tool`, and the HTML preselects that tool in the Drata/Vanta filter; both remain available and by default none is preselected | No |

At least one of the two sources, vault or credentials, is required. The skill **verifies what it is given**: with a vault
it does not insist on credentials, with credentials it does not insist on a vault, and in all three cases it gives a verdict that states
its basis.

## 5. Skill workflow

1. **Preflight**
   - Resolve the inputs.
   - If there are credentials:
     - `sts get-caller-identity`;
     - detect whether the identity has broad write permissions (`AdministratorAccess`, `*:*`) and
       **warn about it** in one line. It does not block; it suggests using a role with `SecurityAudit` + `ViewOnlyAccess`.
   - **Never** read `.env*` files, `credentials` or keys from the vault or the project.
2. **Map the infrastructure**
   - Vault → documented inventory (section 6).
   - Credentials → real inventory per service, with read commands from the catalog.
   - **With credentials, reality rules** **[designer's decision]**. The inventory is built by live
     discovery; the vault contributes **claims** (what each thing is, which feature it belongs to,
     what it says it complies with).
     - A live resource that the vault does not mention → `UNDOCUMENTED` finding, severity `low`. ISO 5.9
       (inventory of assets) requires it, and Vanta requires an owner on everything inventoried.
     - A resource that the vault mentions and that does not exist → `DRIFT`.
3. **Resolve the scope**
   - `full`: the whole inventory plus the account baseline.
   - `feature`: walk the vault to obtain the list of components (section 6.3). **Show the list to the
     user and ask for confirmation before auditing** **[designer's decision]**: a badly resolved feature
     produces a confident and wrong report.
   - `resource`: the resource and its direct dependencies (section 6.4).
4. **Select checks.** From the catalog (section 7), those applicable to the resource types in scope, plus
   the relevant account checks.
5. **Run read checks with a script, not with ad hoc Claude calls**
   **[designer's decision]**. `scripts/collect.py` receives the resolved scope and the list of checks.
   - **Execution:**
     - calls AWS CLI v2 through `subprocess` with an argument list (no shell);
     - runs in parallel per region, with retries on throttling and automatic CLI pagination;
     - saves each raw output in `compliance-reports/<run>/raw/`.
   - **Deterministic evaluation:** applies each check's rule (section 7.1) and writes
     `checks-result.json`.
   - **Errors:**
     - `AccessDenied` → `NOT_VERIFIED`, with the missing permission; never `PASS`;
     - service not subscribed or `OptInRequired` → distinguished from `AccessDenied` and reported as "service
       not enabled". That is often the finding itself; for example, GuardDuty turned off.
   - **Regions:**
     - resource checks: only in regions with resources;
     - "all regions" checks (GuardDuty, Config, EBS by default, Access Analyzer, CloudTrail):
       all enabled regions, as Vanta's CIS tests do.

   Claude does **not** re-judge PASS or FAIL. It only intervenes in checks marked
   `evaluator: "claude"`, which are few and justified in the catalog, and in vault reading, drift
   and feature resolution.
6. **Compare with the vault.** For each documented resource or control, compare what is claimed with what is real →
   `DRIFT` if they differ.
7. **Build `findings.json`** with the schema from section 8.
8. **Render the HTML** with the skill's script: fixed, deterministic, self-contained template.
9. **Verify the fixes** (section 9bis): automatic check of the commands, Claude's review against the
   vault, and a new render of the HTML with the "Verification" section, the per-card stamp and the suggested
   application order. Requested by the user on 2026-11-12.
10. **Reply in the chat:**
   - the absolute path of the HTML;
   - counts by severity;
   - the 3–5 most serious findings, one line each;
   - what could not be verified.

## 6. Reading the vault

**Access:** direct file-system reading: Markdown, YAML frontmatter and wikilinks. It does not depend on
Obsidian being open, nor on Local REST API, nor on MCP, nor on Dataview.

### 6.1 Typed vault (contract of `creating-typed-knowledge-vaults`)

**Detection:** `_meta/relations.md` exists, `_meta/edges.md` exists, or notes have a `type:` frontmatter.

**Elements it uses:**
- **Folders by type:** `systems/`, `constraints/`, `failures/`, `decisions/`, `concepts/`, `MOC/`.
  `systems/` is the main source of components.
- **Frontmatter:**
  - `type`;
  - `status` (`shipped | built-off-by-default | proposed | draft | todo | superseded`);
  - `source`.
- **Edges:** lines `- <relation> → [[Target]]` under `## Structural` and `## Associative`. Incoming
  edges are read from `_meta/edges.md`, which is generated.
- **`status` rules:**
  - `proposed`, `todo` and `draft`: **does not exist**. If it is a control, the finding is "documented as pending".
  - `built-off-by-default`: exists but turned off; verified live if there are credentials.
  - `superseded`: ignored.
- **AWS identifiers:** IDs and ARNs inside notes, by regex (`arn:aws:…`, `i-…`, `sg-…`, `vpc-…`,
  `subnet-…`, `db-…`, bucket names), plus the `source:` field.

### 6.2 Free-form vault (best effort)

Usual patterns in free-form vaults: notes without frontmatter, hub-and-spoke structure.

- **Resource type:** deduced from the file name prefix ("RDS - …", "VPC", "ALB", "IAM"…) and,
  if that is not enough, from the H1 or from keywords.
- **Metadata:** `| Field | Value |` tables and N-column tables.
- **Relations:** `## Connected to` sections, `← [[Hub]]` breadcrumbs and wikilinks.
- **Dates and statuses:** fields with a "verified" date, "RESOLVED" headings and status or severity emojis.
- **Broken links:** tolerated; recorded as a warning in the report.
- **Warning:** the HTML says "untyped vault: the feature map is inferred, less reliable".

### 6.3 Resolving a feature

1. **Find the feature note:**
   - by exact title or alias;
   - otherwise, by text search in titles and H1s;
   - otherwise, in the body.

   If there are several candidates, ask.
2. **Typed:** from that note, walk the outgoing structural edges `depends on`, `requires` and
   `enables`, plus the incoming `is part of` (components that are part of the feature).
   - Maximum depth: 3.
   - Only nodes from `systems/` are collected.
   - The `constraints/` reached are saved as "declared requirements", useful for drift.
3. **Free-form:** outgoing wikilinks of the feature note, with depth 2, filtered to notes that
   describe AWS resources.
4. **Sensitive data:** if the feature or its components mention user data or PII (keywords or
   a privacy `constraint`), confidentiality checks are added: encryption, access logging,
   retention.
5. **If, with credentials, not all resources are found by ID:**
   - search by tags (`Project`, `Feature`, `Name`) and by name;
   - everything found this way is marked **inferred** and goes into the confirmation list of step 3 of the workflow.
6. **Undocumented feature:** this is stated explicitly. With credentials, the tag and name search from item 5
   is offered. Components are never invented.

**"Email sending" example:** the feature resolves, for example, to:
- SES identity;
- configuration set;
- Lambda or sending service;
- SQS queue;
- IAM role;
- SMTP secret;
- log group;
- SPF, DKIM and DMARC DNS records.

DNS is checked with `dig` against public DNS, which is read-only.

### 6.4 Resolving a resource by ID

The prefix or the ARN determines the type. The resource and its immediate context are audited.

| Resource | Audited context |
|---|---|
| EC2 | Security groups, EBS volumes, instance profile and its role, subnet (route to IGW, public IP), VPC flow logs |
| RDS | Subnet group, SGs, KMS key, backups, parameter group (force SSL) |
| S3 bucket | Policies, Block Public Access, encryption, versioning, logging |

Without credentials, this mode can only report what the vault says about that ID.

## 7. Check catalog

### 7.1 Format

One JSON file per domain in `references/checks/<domain>.json`, so that only the domains in
scope are loaded. Each check has:

```json
{
  "id": "IAM-001",
  "title": "MFA enabled on the root account",
  "domain": "iam",
  "scope": "account",
  "resource_types": ["AWS::IAM::Root"],
  "severity": "critical",
  "verify": {
    "calls": [{"service": "iam", "operation": "get-account-summary", "args": [], "region": "global"}],
    "evaluator": "jmespath",
    "offenders": "[?SummaryMap.AccountMFAEnabled != `1`]",
    "pass_when_text": "AccountMFAEnabled == 1",
    "needs": ["iam:GetAccountSummary"]
  },
  "vault_signals": ["root", "MFA"],
  "mappings": {
    "drata": [{"test": "214", "name": "MFA for AWS Root Account", "sourced": true}],
    "vanta": [{"test": "MFA is enabled on the root account", "sourced": true}],
    "tsc":   [{"id": "CC6.1", "sourced": false}],
    "iso27001_2022": [{"id": "A.8.5", "sourced": false}],
    "security_hub": ["IAM.9"],
    "cis_aws": ["1.4"]
  },
  "remediation": {
    "kind": "console_only",
    "risk": "low",
    "downtime": false,
    "steps": ["..."],
    "commands": [],
    "verify_after": "aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'",
    "notes": "Root MFA cannot be enabled through the CLI; console steps."
  },
  "sources": ["https://help.drata.com/en/articles/9828711"]
}
```

**Allowed values:**
- `remediation.kind`: `cli` | `cli_with_decision` | `planned_change` | `console_only`.
  - `cli_with_decision`: there is a value the user decides, such as retention days or the owner's email.
  - `planned_change`: multi-step, destructive or with downtime; it carries **steps and warnings**, not a
    one-liner.
- `remediation.risk`: `low` | `medium` | `high`.
- `severity`: `critical` | `high` | `medium` | `low`. Criterion **[designer's decision]**:

| Severity | When |
|---|---|
| `critical` | Public exposure of data or credentials; root without MFA or with access keys |
| `high` | Fails an automatic Drata or Vanta test that is in the default SOC 2/ISO set |
| `medium` | Fails a relevant Security Hub, CIS or FSBP control, with no direct Drata/Vanta test |
| `low` | Hygiene: tags, descriptions, good practices |

**Evaluation rules (deterministic)** **[designer's decision]**

Each check produces a **list of offenders**: empty → `PASS`; with elements → `FAIL` per offender.
`evaluator` can be:

- **`jmespath`**: JMESPath expression over the JSON output of the call. It is the same language as AWS CLI's
  `--query`; in Python it is evaluated with the JMESPath bundled with the CLI or through `--query`, without depending on `jq`.
  It covers most checks.
- **`python:<name>`**: named function in the `scripts/evaluators/` package (one module per domain) for logic that crosses calls or
  parses CSV. Examples:
  - credential report → keys older than 90 days or credentials unused for more than 45 days;
  - security groups open only in regions with active ENIs;
  - confirmed SNS subscription behind each alarm;
  - root usage in 7 days via `cloudtrail lookup-events`.

  Each function has tests with sample outputs.
- **`claude`**: exception documented in the check, for what requires judgment. For example, whether an IAM
  policy with `*` is acceptable. The report marks "evaluated by Claude".

`pass_when_text` is the human-readable explanation that goes into the HTML.

### 7.2 Initial content

98 checks. The thresholds in the table are **documented** in Drata, Vanta or CIS (sources in
section 15). The full list with mappings goes in the plan; these are the domains and the key checks:

| Domain | Checks (threshold) | Drata | Vanta (CIS) |
|---|---|---|---|
| **IAM / root** | MFA on root; **hardware** MFA on root; root without access keys; root usage (2+ logins in 7 days = fail) | 214, 225, 124 | #1, #2 |
| **IAM / users** | MFA on users with console access; password ≥14 and reuse 24; access keys ≤90 days; credentials unused ≤45 days; ≤1 active key; permissions only through groups (no inline or direct); no `*:*` policies; support role; Access Analyzer in all regions | 88, 215, 216, 232, 229, 217, 230 | #3–#11, #14 |
| **Logging** | Multi-region CloudTrail; file validation; encryption with CMK; S3 data events for read and write; access logging on the CloudTrail bucket; VPC Flow Logs on all VPCs; log retention ≥365 days; EKS audit logs | 205, 222, 226, 221, 224, 111, 310 | #17–#19, #25, #26, #28, #30 |
| **Detection** | GuardDuty in every region with resources (+ S3 Protection); Security Hub enabled; AWS Config in all regions (all types; IAM daily; SNS) | 105 | #27, #31 + Config test |
| **Encryption at rest** | EBS by default in every region used; RDS, EFS, DynamoDB, S3 encrypted; CMK rotation; CMK not scheduled for deletion | 218, 231, 68, 69, 223 | #20, #21, #24, #29 |
| **Encryption in transit** | S3 denies `aws:SecureTransport=false`; ALB redirects HTTP→HTTPS; ALB TLS policy ≥ TLS 1.2 *(no documented Drata/Vanta test: severity `medium`)*; RDS forces SSL | 234, 299 | #15 |
| **Network** | No 0.0.0.0/0 or ::/0 to 22/3389 (SG and NACL); no 0.0.0.0/0 to 80; default SG without rules; no "ALL traffic" rule; RDS neither public nor in a public subnet; WAF associated with public ALB, CloudFront and API GW | 102, 228, 227, 291, 233, 119, 220, 122 | #23, #32–#35 |
| **Compute** | IMDSv2 required (includes ASG launch templates); instances with IAM role; LB in ≥2 AZs; ASG present; Inspector active and no open critical or high findings | 292, 130, 131, 21 | #12, #36 |
| **Data and backups** | RDS: automated backups (retention >0; recommended ≥7 *[designer's decision]*), Multi-AZ in prod, auto minor upgrade, deletion protection; DynamoDB PITR; S3 versioning; Block Public Access per bucket (the account-level one is not enough for Drata 104); AWS Backup: previous day's jobs OK and failure alerts | 107, 30, 219, 301, 108, 104, 132, 133 | #16, #22 |
| **Monitoring** | CloudWatch alarms **with a confirmed SNS subscription** for: RDS CPU, storage and IO; EC2 CPU; ALB 5xx, unhealthy hosts and latency; SQS message age; Lambda errors | 112–118, 206, 290, 293–300 | Alarm tests |
| **Inventory and tags** | `VantaOwner` (email of an active user; Vanta fails if there is no owner); `VantaContainsUserData` on storage and databases; `VantaNonProd` only in non-prod; configurable organizational tags (by default `Project`, `Environment`, `Owner`) | — | "active owners" and "user data" tests |
| **Integration health** | If `DrataAutopilotRole` or `vanta-auditor` exist: they have `SecurityAudit` (+ `VantaAdditionalPermissions` as a managed policy, not inline); the CMK key policies give them access; bucket policies do not block them | Requirement of 223 | Permissions doc |
| **Email feature** (example) | SES: DKIM enabled, domain verified, configuration set with TLS `Require`, event destination or logging; DNS SPF, DKIM and DMARC (`p=quarantine` or `reject`) | — | — |

**Additions from the reference research and from Drata's DCF catalog** (`docs/research/soc2-reference-infrastructures.md`,
`drata-dcf-mapping.json`):

- **CloudTrail:**
  - `IsLogging = true`, because an existing trail may be stopped;
  - log bucket with an `aws:SourceArn` policy, versioning and SSE-KMS;
  - CloudTrail → CloudWatch Logs with the CIS 3.x metric filters (root usage, IAM changes, unauthorized
    calls). CIS v5 removed them, but auditors often ask for them.
- **GuardDuty:** S3 Protection and an EventBridge rule with a target for findings (Drata 105).
- **Retention:** ≥365 days in CloudWatch log groups and in the lifecycle of log buckets (Drata 111,
  Vanta "AWS Server Logs").
- **Edge and detection logs:** ALB access logs; WAF logging; Security Hub with standards
  enabled (FSBP and CIS).
- **Account:** alternate account contacts (security, operations, billing); prefer IAM Identity
  Center over IAM users (`low`, informational).
- **Secrets and operations:** rotation in Secrets Manager; SSM Session Manager and Patch Manager (patch
  associations); Inspector for EC2, ECR and Lambda; AWS Backup plan with frequency and retention; ACM
  certificates close to expiry (≤30 days).
- **Default network objects in all enabled regions:** default VPC, default SG, NACL and
  Flow Logs. Drata evaluates all VPCs in all enabled regions, not just the application's VPC.
- **Integration:**
  - exact name `DrataAutopilotRole`;
  - inline permission `backup:ListRecoveryPointsByResource` for tests 132, 133, 134 and 301;
  - `VantaAdditionalPermissions` as a customer-managed policy;
  - region-restriction SCP aligned with the scope of the connection.
- **Multi-account:**
  - no source requires it for SOC 2; the AWS Startup Security Baseline is single-account;
  - it goes in as an `INFO` note (separate logging account, scope reduction), **never** as `FAIL`.
- **SES:** Drata and Vanta have no SES tests, so those checks are our own. Maximum severity
  `medium`, except missing DMARC on a domain that sends (`high`).

**Truthfulness rule for mappings** (updated with a read-only query to the Drata Control
Framework via API/MCP, 2026-11-12):
- **Drata does not map per test.** It maps test → DCF control → requirements. The DCF controls expose the
  requirements of **SOC 2 (61) and ISO 27001:2022 (123, includes clauses)**.
- **What was extracted is authoritative:** the mapping of 130 tests is in `docs/research/drata-dcf-mapping.json`
  (without statuses or data from any account). For checks with an equivalent Drata test, the
  TSC and ISO columns are taken from there with `sourced: "drata-dcf-2026-11-12"`.
- **Checks without a Drata test** (Config, Security Hub, Access Analyzer, ALB TLS, SES…): the mapping is
  inferred (`sourced: false`), with a visible "inferred" indicator in the HTML.
- **Vanta:** its test names (CIS) are documented; its mapping to TSC and ISO is still inferred.
- **Snapshot and phase 2:**
  - the mapping is embedded in `references/mappings/drata-dcf.json` with a date;
  - a Drata account can customize mappings, and the Vanta one has its own configuration;
  - in phase 2, if an MCP is connected, the live mapping of that account is used.
- **Tests enabled in the account:** it is common for some Drata tests to be `UNUSED` or `DISABLED`
  (for example Inspector, vulnerability scanning or 365-day retention).
  - Only with a live connection (phase 2), when a check fails and its test is unused, the HTML marks it
    **"Drata does not monitor this today; an auditor or Vanta does"**.
  - Without a connection, nothing is claimed about the account's state.
- **Vacuous pass:** when a test would pass only because there are no resources of that type (for example, Drata 130 with no
  EC2 or 105 with no buckets), the status is `N/A`, with the note "passes vacuously". Never `PASS`.

### 7.3 Embedded reference catalogs

- `references/frameworks/iso27001-2022.json`: the **93** controls (5: 37 · 6: 8 · 7: 14 · 8: 34),
  ID and paraphrased name, and responsibility (customer, shared or inherited from AWS).
- `references/frameworks/tsc-2017.json`: the 61 criteria (CC1–CC9, A1, C1, PI1, P1–P8), paraphrased.
- AICPA or ISO text is **not** copied; only IDs and short paraphrased names.
- They serve to:
  - validate that every mapped ID exists;
  - draw the report's coverage table: which controls this report touches, which are
    organizational (out of scope) and which are inherited from AWS (for example, physical 7.x: evidence
    = AWS Artifact).

## 8. Statuses and finding model

**Finding statuses:**

| Status | Meaning |
|---|---|
| `FAIL` | Verified live, does not comply |
| `PASS` | Verified live, complies |
| `DRIFT` | The vault claims something different from reality (may or may not comply; both are shown) |
| `DOCUMENTED_ONLY` | Vault only: the vault says it complies, but it is not verified |
| `DOCUMENTED_GAP` | Vault only: the vault says it is missing or `proposed` |
| `UNDOCUMENTED` | Exists in the account and the vault does not mention it |
| `NOT_VERIFIED` | No credentials or `AccessDenied` (the missing permission is stated) |
| `N/A` | Does not apply; for example, there are no resources of that type |

**`findings.json` schema:**
- run metadata: platform, scope, sources, account (visible ID), identity, regions, date,
  catalog version;
- resolved inventory;
- list of findings. Each one has `check_id`, `resource`, `region`, `status`, `severity`, `evidence`,
  `vault_claim`, `mappings` and the already-instantiated `remediation` (placeholders resolved when known).

**Evidence:** the relevant command output, trimmed. The following are masked:
- access key IDs, in the form `AKIA…WXYZ`;
- tokens and secrets (never requested);
- emails of individuals, except those in owner tags.

## 9. HTML report

- **Single file**, no external dependencies: inline CSS and JS. It opens offline and can be attached as
  evidence.
- **Path:** `./compliance-reports/<platform>-<scope>-<YYYY-MM-DD-HHMM>/report.html` in the working
  directory **[designer's decision]**: one folder per run with `report.html`, `findings.json`, `verification.json` and the
  intermediate files. Never inside the vault.
- **Structure:**
  1. **Header:** platform, scope, sources used (typed or free-form vault, credentials, regions),
     date, account and identity.
  2. **Summary:** **verdict** (`OPTIMAL`, `NOT_OPTIMAL` or `NOT_VERIFIABLE`) with its basis (AWS, vault or AWS and
     vault) next to it, counts by status and severity, affected Drata and Vanta tests, "not
     verified" list. **No percentage or score.**
  3. **Filters:** severity, status, domain, Drata/Vanta, SOC 2/ISO. Text search.
  4. **Finding cards**, sorted by severity. Each one includes:
     - title;
     - resource and region;
     - status and severity;
     - mapping chips (`CC6.1`, `A.8.5`, `Drata 214`, `Vanta: MFA is enabled on the root account`, with an
       "inferred" mark where applicable);
     - evidence;
     - what the vault claims, if there is drift;
     - remediation block.
  5. **Remediation block**, in each card:
     - bash code block for **CloudShell** with a **Copy** button;
     - variables at the top (`REGION=…`, `ACCOUNT_ID=…`);
     - `__FILL_IN_<NAME>__` placeholders highlighted;
     - risk and downtime labels, and a warning if it is `planned_change` (numbered steps, each with its own
       Copy);
     - "verify afterwards" command.
     - **Global Copy:** button "Copy all `low`-risk fixes of this severity" **[designer's
       decision]**, to speed things up without mixing in dangerous changes.
  6. **"Do not touch without review":** resources on which tests that pass today depend, with the tests and controls
     that depend on each one. Each resource card also shows "Tests that depend on this
     resource".
     - Reason: it is common for a vault or a cost guide to suggest savings (turning off Multi-AZ, deleting Flow
       Logs, deleting the destination bucket of the CloudTrail access logs) that would turn tests like 30,
       224 and 221 red.
     - If the vault contains such a recommendation, it is reported as `DRIFT` with severity `high` and the note
       "this vault recommendation would break <test>".
  7. **Standards coverage:** Annex A and TSC table with the controls touched (pass, fail or not verified),
     the organizational ones "out of scope of this report" and those inherited from AWS.
  8. **Run warnings:** broken vault links, missing permissions, skipped regions, free-form
     vault.
  9. **Footer:** "Automated technical pre-audit. It is not an audit opinion and does not cover
     organizational controls."
- **Accessibility and theme:** light and dark mode, clean printing (expands everything, hides buttons).
- **Copy:** `navigator.clipboard.writeText`, with a fallback for `file://` (`document.execCommand('copy')`
  with a hidden textarea).
- **Determinism:** the HTML is generated by `scripts/render_report.py` from `findings.json`, with Python
  stdlib, so that all reports have the same shape. Claude does not write HTML by hand.

## 9bis. Fix verification stage

It runs after the first render and before delivering the report. Its goal is to detect whether the remediation commands
**break anything** or whether **something is missing**. **Nothing is executed in AWS** at this stage.

### 9bis.1 Automatic verification (`scripts/verify_remediation.py`, deterministic)

It reads `findings.json` (plus `inventory.json`) and writes `verification.json`.

| Check | What it does | Result |
|---|---|---|
| Syntax | `bash -n` on each command block (reads without executing) | `CONFLICT` if it fails |
| CLI validity (optional, `--check-cli`) | local `aws <service> <operation> help` with `PAGER=cat`, without calling AWS; each `--flag` of the command must appear in the help | `CONFLICT` if the operation or a flag does not exist; if there is no CLI, a warning |
| Placeholders | `{resource_id}`, `{region}`, `{account_id}` or `{resource_name}` remain unresolved | `CONFLICT` |
| Data to fill in | counts the `__FILL_IN_*__` | `REVIEW` |
| Hygiene | `<<` or `set -e` | `CONFLICT` |
| Destructive without warning | `delete-`, `revoke-`, `terminate-`, `remove-`, `deregister-`, `detach-`, `disable-`, `stop-`, `--force`, or commands that **replace** a policy (`put-bucket-policy`, `put-key-policy`, `update-account-password-policy`) in a fix that is neither `planned_change` nor `cli_with_decision` with `notes` | `REVIEW` |
| Conflicts between fixes | rules in `references/conflict-rules.json` (see 9bis.2) | `CONFLICT` or `REVIEW` |
| Impact on what passes today | the fix modifies a resource with green tests in `dependencies` | `REVIEW`, naming the tests |
| What is missing (`gaps`) | `FAIL` without commands and that is not `console_only`; `NOT_VERIFIED` with its missing permission; inventory resources that no check evaluated; fixes without `verify_after` | list of missing items |

**Suggested application order** (`apply_order`):
1. identity;
2. logging and detection, to have visibility before touching anything;
3. KMS keys;
4. encryption;
5. network;
6. data and backups;
7. monitoring;
8. tags and integration.

Within each group it is sorted by severity, and `planned_change` fixes go last. If a conflict rule
says "apply B before A", that rule wins.

### 9bis.2 Initial conflict rules (`references/conflict-rules.json`)

| ID | Situation | Message | Result |
|---|---|---|---|
| CR-001 | NET-003 or NET-004 on an SG attached to a load balancer's interface (ENI description starting with `ELB `: ALB, NLB or classic) | Closing 80 breaks the HTTP→HTTPS redirect; alternative: 443 only, or exclude in Drata with justification | `CONFLICT` |
| CR-002 | LOG-003 (CloudTrail with CMK) | The key policy must allow `cloudtrail.amazonaws.com` before applying; otherwise the trail stops logging | `REVIEW`, with order: the key before the trail |
| CR-003 | NET-001 or NET-002 (revoke SSH/RDP) on an instance with CMP-006 in `FAIL` (not managed by SSM) | You lose access; enable SSM first | `CONFLICT`, with order: CMP-006 first |
| CR-004 | CMP-001 or CMP-002 (IMDSv2) | Old SDKs or agents that only use IMDSv1 stop obtaining credentials | `REVIEW` |
| CR-005 | IAM-008, IAM-009 or IAM-010 (rotate or deactivate keys) | The app or pipeline that uses that key breaks; rotate first, deactivate afterwards | `REVIEW` |
| CR-006 | TLS-001 (S3 deny without TLS) | Clients that access the bucket over HTTP fail | `REVIEW` |
| CR-007 | ENC-003, ENC-002 or ENC-004 (encrypt an existing resource) | Requires a migration with downtime | `REVIEW` |
| CR-008 | INV-003 (remove `VantaNonProd` from a prod resource) | The resource enters Vanta's scope and may open new tests | `REVIEW` |
| CR-009 | INT-004 (key policy) or any `put-key-policy` | Replacing the key policy can leave the key inaccessible; keep the root account statement | `REVIEW` |
| CR-010 | DAT-002 (Multi-AZ) | Cost and brief failover during the change | `REVIEW` |

The rule catalog is validated with `validate_catalog.py`: the check IDs cited must exist.

### 9bis.3 Claude's review against the vault

For each fix with `REVIEW` or `CONFLICT`, and for every fix with `medium` or `high` risk, Claude
cross-checks the vault and the inventory for what depends on the resource. For example: "key `…MNOP` is used by the
email-sending Lambda according to `systems/Mailer Lambda.md`".

It writes this to `verification-claims.json`:

```
[{"finding_id", "status": "OK|REVIEW|CONFLICT", "message", "vault_note"}]
```

The script combines the two sources; the most severe status wins. Claude never lowers a script `CONFLICT`.

### 9bis.4 In the HTML

- Per-card stamp: **OK**, **REVIEW** or **CONFLICT**, with the reasons.
- "Verification" section, with:
  - conflicts between fixes;
  - what is missing;
  - the suggested application order;
  - the number of pending `__FILL_IN__` placeholders.
- The "Copy low-risk fixes" button **excludes** fixes with `CONFLICT`.

## 10. Skill security rules

1. **Read-only on AWS.** `collect.py` runs **only** `service + operation` pairs that appear in the
   catalog **[designer's decision]**.
   - **Exact allowlist**, not by prefix, enforced in Python before each call.
   - **No shell:** `subprocess` with an argument list, no pipes, `;`, `&&` or `$()`. Filtering is done by the
     evaluator, not by `jq`.
   - **Catalog validation:** `validate_catalog.py` rejects any operation that does not start with
     `describe-`, `list-`, `get-`, `lookup-events` or `generate-credential-report`. The latter is harmless and
     Drata/Vanta use it; it is the only written exception.
   - **Explicit denylist of reads that expose secrets or data**, even if they start with `get-`/`list-`:
     - `secretsmanager get-secret-value`;
     - `ssm get-parameter*` with `--with-decryption`;
     - `lambda get-function` (returns environment variables and the code URL; for configuration,
       `get-function-configuration` is used with a `--query` that excludes `Environment`);
     - `s3api get-object`;
     - `kms decrypt`/`generate-data-key*`;
     - `ecr get-login-password`;
     - `sts get-session-token`;
     - `logs get-log-events`/`filter-log-events`;
     - `rds-data *`;
     - `dynamodb get-item`/`scan`/`query`;
     - `ec2 get-password-data`.
   - **DNS:** queried with `dig +short` (if absent, `nslookup`) for public TXT/CNAME records, with
     the same no-shell argument rule. If neither is available → `NOT_VERIFIED`.
   - Remediation commands are **never** executed; they are only written to the HTML.
2. **Credentials:**
   - only already-configured profiles or environment;
   - never read `.env*`, `~/.aws/credentials` or key files;
   - never ask for keys to be pasted into the chat.
3. **Do not read data contents:** no `s3 cp`, `get-object`, database queries or `logs get-log-events`
   (except CloudTrail's `lookup-events` for root usage).
4. **Masking** according to section 8.
5. **Plain-text credentials:** if the vault or the evidence folder contain plain-text
   credentials (for example, a `.env` with `AKIA`), it is reported as a `critical` finding **without reading or showing the
   values**: only the file name and the pattern detected by `grep -l`.
6. **Identity with broad permissions:** the skill continues, but warns (step 1 of the workflow).

## 11. Phases

- **Phase 1 (MVP):**
  - vault reading, typed and free-form;
  - inventory and live checks with the AWS CLI;
  - catalog of 98 checks in the domains of 7.2;
  - embedded authoritative Drata mapping;
  - "do not touch without review" section;
  - ISO and TSC catalogs;
  - `findings.json`;
  - HTML with Copy;
  - `full`, `feature` and `resource` modes;
  - catalog validator;
  - tests.
- **Phase 2 (optional, if connections are available):**
  - **Drata MCP:** `Drata_searchMonitoringTests` and `Drata_getMonitoringTestFindings` to fetch failing
    tests and cross-check ("matches", "Drata only", "skill only"); `Drata_searchControls` and
    `Drata_listRequirements` for the authoritative mapping. Reads only: no retest, exclude or create.
  - **Vanta:** `GET /tests` API (or its MCP, if one exists; to be confirmed) for the same cross-check.
  - **Prowler:** if installed and the user agrees, `prowler aws --compliance soc2_aws iso27001_2022_aws`
    and ingest the OCSF output as a second opinion. The multi-framework syntax is to be verified with
    `prowler aws -h`.

  When there is no connection, phase 2 does not appear and is not mentioned in the report.

## 12. Skill structure (proposal)

```
infra-compliance-audit/
  README.md
  docs/specs/2026-11-12-infra-compliance-audit-design.md   (this document)
  docs/plans/…                                             (implementation plan)
  auditing-infra-compliance/                               (the skill itself)
    SKILL.md                     lean procedural flow; says which reference to load and when
    references/
      vault-reading.md           typed contract + free-form heuristics + feature/resource resolution
      checks/<domain>.json       catalog (iam, logging, detection, encryption, network, compute,
                                 data, monitoring, inventory, integration, email…)
      frameworks/iso27001-2022.json
      frameworks/tsc-2017.json
      mappings/drata-dcf.json    authoritative mapping Drata test → DCF → SOC 2 / ISO (2026-11-12),
                                 without data from any account
      remediation-guidelines.md  rules for CloudShell commands, placeholders, planned_change
      report-format.md           findings.json schema and statuses
      drata-vanta.md             permissions and roles of the tools, Vanta tags, test behavior
                                 (phase 2: MCP usage)
    scripts/
      collect.py                 runs checks (allowlist + denylist, parallel per region, raw to disk)
      evaluators/                python:<name> evaluators, one module per domain
      render_report.py           findings.json → HTML (stdlib)
      validate_catalog.py        unique IDs, mappings existing in catalogs, required fields,
                                 verify commands in allowlist, non-empty remediation
    assets/report-template.html
  tests/
    fixtures/typed-vault/        synthetic typed vault (fictional platform with an email feature)
    fixtures/free-vault/         synthetic free-form vault (hand-written notes, tables, broken links, drift)
    fixtures/findings-sample.json
    …                            render, validator and allowlist tests
```

**Skill name:** `auditing-infra-compliance` **[designer's decision]**, in gerund form like
`creating-typed-knowledge-vaults`.

**Frontmatter description:** triggered by requests in Spanish or English for an audit or pre-audit
of SOC 2 / ISO 27001 for AWS infrastructure, for "does this pass Drata/Vanta?", or for reviewing a feature or a resource
against compliance.

## 13. Validation and tests

1. **`validate_catalog.py`** runs in the tests:
   - every `tsc` and `iso27001_2022` exists in the embedded catalogs;
   - unique IDs;
   - every `verify` passes the allowlist;
   - every `remediation` has `verify_after`;
   - every `planned_change` has steps and a warning.
2. **Render:** `render_report.py` with a sample `findings.json`:
   - the HTML has no external resources;
   - all blocks have a Copy button;
   - placeholders are highlighted;
   - no sample secrets appear unmasked.
3. **Allowlist:** cases that must pass and cases that must be rejected, such as `aws s3 rm`,
   `aws iam create-*`, `aws ec2 modify-*`, chaining with `;`, `&&` or `|` into another write
   `aws`, and `$(…)`.
4. **Skill scenarios**, in the style of `superpowers:writing-skills`: test the behavior with
   subagents before and after writing SKILL.md:
   - **(a)** synthetic typed vault, "email sending" feature, no credentials;
   - **(b)** synthetic free-form vault (`tests/fixtures/free-vault/`: hand-written notes, tables, broken links,
     one outdated claim), `full` mode, no credentials: it must detect that it is free-form, warn
     and not invent;
   - **(c)** request with an instance ID and no vault or credentials: it must ask for a source;
   - **(d)** temptations: a `.env` in the folder, a request to "fix it yourself". It must refuse to run
     changes and not read the `.env`.
5. **Live test** (manual, with the user): a real AWS account with a known state in Drata and Security
   Hub, with a read-only profile that the user provides. No data from that account is stored in the skill's
   repo. Acceptance criterion **[designer's decision]**; it is not a score, it is explained
   discrepancies:
   - **Security Hub:** every Security Hub control in FAILED that has an equivalent check in the catalog
     (`security_hub` column) appears as `FAIL` in the report;
   - **Drata:** every green Drata test that has an equivalent does not appear as `FAIL`. If it does, the
     difference is explained: scope, threshold or test not enabled in the account;
   - **Vault:** known differences between vault and account appear as `DRIFT` or `UNDOCUMENTED`;
   - **Security:** no write command in `collect.py`'s log.

**Assumed environment** **[designer's decision]**:
- Linux or macOS;
- AWS CLI v2;
- Python ≥ 3.10, stdlib only plus the CLI's JMESPath. If it cannot be imported, evaluation goes through `--query`;
- `dig` or `nslookup` optional;
- Windows is out of scope for v1.

## 14. Research context facts

- **Resources not worth using:**
  - AWS Audit Manager is in maintenance mode (not accepting new customers since 2026-04-30) and its
    ISO framework is 2013;
  - there are no AWS Config conformance packs for SOC 2 or ISO 27001;
  - the public GitHub skill reviewed has wrong SOC 2 and ISO mappings. Only **ideas** are reused from it
    (control matrix schema, gap taxonomy), not data. MIT license.
- **ISO transition:** the ISO 27001:2013 → 2022 transition closed on 2025-10-31. Everything is evaluated against
  2022. Amendment 1:2024 (climate change) only touches clauses 4.1 and 4.2.
- **Vacuous passes and default objects:** Drata passes some tests when there are no resources, and evaluates default
  network objects in all regions. The catalog must reflect both.

## 15. Main sources

The full research reports (with all URLs) are in `docs/research/`. They are the source of
the catalog's test numbers, names and thresholds. A mapping without a source is published marked "inferred";
it is not omitted.
- `vanta-drata-tests.md`: about 45 Drata AWS tests with thresholds and articles, the 36 Vanta CIS tests,
  the Vanta tags, the permissions of both roles;
- `frameworks-aws-mapping.md`: the 93 Annex A controls, the 61 TSC criteria, the CISO
  Assistant crosswalk, Security Hub CIS v5, Prowler, Obsidian;
- `github-skill-review.md`: review of the GitHub skill;
- `drata-dcf-mapping.json`: authoritative mapping of 130 Drata tests (test → DCF → SOC 2 / ISO);
- `soc2_rules.txt`: the 65 AWS Config rules of Audit Manager's SOC 2 framework;
- `soc2-reference-infrastructures.md`: AWS SRA, Startup Security Baseline, LZA, IaC modules, guides;
  catalog gaps.

Key URLs:
- Drata tests: https://help.drata.com/en/collections/2711965-tests
- Drata AWS permissions: https://help.drata.com/en/articles/8852274-aws-resource-permissions
- Vanta CIS: https://help.vanta.com/en/articles/11345518-cis-foundation-benchmarks-available-in-vanta
- Vanta tags: https://help.vanta.com/en/articles/11345627-bulk-tags
- Security Hub CIS: https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html
- Prowler: https://hub.prowler.com/compliance/soc2_aws · https://hub.prowler.com/compliance/iso27001_2022_aws
- No SOC 2/ISO conformance packs: https://docs.aws.amazon.com/config/latest/developerguide/conformancepack-sample-templates.html

---

## 16. Changes after approval

Decisions made during implementation and reviews, after this design was approved. Each one says
why it was changed. Where they contradict the text above, these take precedence.

- **Verdict per source (`summary.verdict`, `summary.verdict_basis`).** The report gives `OPTIMAL`, `NOT_OPTIMAL` or
  `NOT_VERIFIABLE` and states its basis: `aws`, `vault` or `aws+vault`. Previously (A2) there was no global verdict.
  - Reason: the user asked the skill to verify "whatever it is given, not strictly credentials". Without a
    verdict per source, a vault-only run did not answer the question.
  - Kept: no percentages or scores; the `DOCUMENTED_*` statuses do not change (the vault never marks `PASS` or
    `FAIL`); a verdict with `vault` basis does not say that AWS verified anything.
- **Report-only: first and absolute rule.** The skill never writes to AWS and never applies a fix, even if the
  user asks for it, authorizes it or offers an admin profile (that profile is only good for read-only
  collection). Reason: pressure tests showed that an agent yields to "it's just a test" and offers IaC or a PR.
- **`REVIEWED_OPERATIONS` and the naming rule.** `aws_runner.py` only admits `describe-*`, `list-*` and `get-*`
  (plus a few fixed exceptions), rejects operations with sensitive names (credential, password, token, secret…) except for reviewed
  exceptions, and `collect.py` only runs the (service, operation) pairs in `catalog.REVIEWED_OPERATIONS`.
  Reason: so that a new read cannot expose secrets without someone having reviewed what it returns.
- **More cautious remediations.**
  - To `cli_with_decision` (there is a value that a person decides, or the command replaces an existing configuration or
    policy): IAM-009, LOG-009, ENC-005, TLS-002, TLS-003, NET-001, NET-002, NET-004, NET-006, DAT-006,
    DAT-007, INV-003, INT-002 and EML-002.
  - DAT-001 becomes `planned_change`: raising retention from 0 to a higher value interrupts a Single-AZ instance for a few minutes.
  - IAM-006 and IAM-007 are fixed with a single change in three blocks (read the current policy, generate the
    merged values without applying anything, apply after review), because `update-account-password-policy` replaces
    the entire policy and whatever is not passed goes back to the AWS default.
  - Common reason: a command that looks like a one-liner and destroys configuration is anti-goal A6.
- **Evaluators moved from `jq` to Python** in ENC-001, ENC-003, DAT-002, DAT-005, DAT-006, EML-002, EML-003 and EML-006.
  Reason: they need to cross calls, tolerate per-item errors or compare dates, which a declarative
  expression cannot cover safely; in Python they are unit-tested.
- **DAT-008 with a rolling 24 h window** (AWS Backup jobs of the last 24 hours) instead of the calendar
  "previous day". Reason: the result does not depend on the time of day the run happens.
- **Partial runs, progress and call cache.** `collect.py` shows progress on stderr, writes
  `checks-result.json` incrementally (`partial`, `pending_checks`), reuses identical calls and tolerates the
  failure of a region or an item without bringing down the whole check; a partial run is declared as such in the report and
  is never `OPTIMAL`. Reason: in large accounts a long or interrupted run cannot be lost or read as clean.
- **Stricter verification floors.** A high-risk fix or one with downtime never comes out `OK` (the floor is
  `REVIEW`), and the verification is tied to the hash of the findings (an old verification is ignored and a
  warning is shown). Reason: so that the `OK` stamp is not read as permission to apply something risky.
- **Bulk copy only with current verification.** The button to copy low-risk fixes is disabled without a current
  `verification.json` and excludes `REVIEW`, `CONFLICT` and commands with `__FILL_IN_*__`. Reason: pasting
  literal placeholders or unreviewed fixes into CloudShell is unsafe.
- **`awscli.py` becomes `aws_runner.py`.** Reason: it clashed with pip's `awscli` package, present on
  development machines, and a wrong import broke `collect.py`.
- **Language and tool.** The report is English only (`--lang` reserved, only `en`) and the chosen
  tool (`--tool`) is stored in `meta.tool` and preselected in the filter. Reason: there was an input that did
  nothing and a flag that promised a language that does not exist.
