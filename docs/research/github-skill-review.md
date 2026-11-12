# Review: alirezarezvani/claude-skills — SOC 2 and ISO 27001 skills (ra-qm-team)

Source: https://github.com/alirezarezvani/claude-skills (main, fetched 2026-11-12 via GitHub API + raw URLs).
Source reviewed read-only from the public repository (nothing executed).

NOTE on paths: the URL in the brief (ra-qm-team/skills/soc2-compliance) is correct. The repo also mirrors skills into .codex/, .gemini/, .hermes/, .vibe/ and a plugin wrapper dir; the canonical copy is ra-qm-team/skills/*. A second, separate SOC 2 item exists at compliance-os/skills/soc2-audit-prep (a 6 KB "six forcing questions" command, no controls catalog).

---------------------------------------------------------------------
## 1. File tree, frontmatter, structure

### soc2-compliance (ra-qm-team/skills/soc2-compliance)
```
SKILL.md                                  19.1 KB, 423 lines
references/trust_service_criteria.md      17.8 KB
references/evidence_collection_guide.md   11.7 KB
references/type1_vs_type2.md              10.5 KB
references/soc2_audit_playbook.md          9.5 KB
scripts/control_matrix_builder.py         27.4 KB
scripts/evidence_tracker.py                8.0 KB
scripts/gap_analyzer.py                   15.9 KB
```
Frontmatter (only two keys, quoted):
- name: "soc2-compliance"
- description: "Use when the user asks to prepare for SOC 2 audits, map Trust Service Criteria, build control matrices, collect audit evidence, perform gap analysis, or assess SOC 2 Type I vs Type II readiness."
(Good trigger-style description: starts with "Use when", lists concrete trigger phrases.)

SKILL.md sections: Overview (what is SOC 2, Type I vs II table, who needs it, journey diagram) -> Trust Service Criteria (CC1-9, A1, C1, PI1, P1-8 summary tables with "select when" guidance) -> Control Matrix Generation (field schema, ID naming SEC-/AVL-/CON-/PRI-/PRV-NNN, 5-step workflow) -> Gap Analysis Workflow (4 phases, remediation table, priority->weeks) -> Evidence Collection (evidence by control area, automation opportunities, continuous monitoring) -> Audit Readiness Checklist (+ scoring bands, common findings) -> Vendor Management (tiers, carve-out vs inclusive for subservice orgs, CUECs) -> Continuous Compliance (quarterly cycle) -> Anti-Patterns table -> Tools (CLI usage) -> References -> Cross-References. A "More in this skill" footer links the playbook (progressive disclosure, loosely done: the TOC is in SKILL.md but references are all one hop).
Weakness: SKILL.md is long (423 lines) and is mostly a textbook overview rather than instructions for what Claude should DO; much of it duplicates references/trust_service_criteria.md.

### information-security-manager-iso27001 (ra-qm-team/skills/information-security-manager-iso27001)
```
SKILL.md 11.5 KB, 419 lines
references/iso27001-controls.md       9.7 KB  (labelled "ISO 27001:2022 Controls Implementation Guide")
references/risk-assessment-guide.md   8.4 KB
references/incident-response.md      11.3 KB
scripts/compliance_checker.py        16.2 KB
scripts/risk_assessment.py           17.4 KB
```
Frontmatter: name "information-security-manager-iso27001"; description "Use when designing or running an ISO 27001 ISMS in HealthTech or MedTech: risk assessment, control implementation, certification or security incidents. Assesses risk with risk_assessment.py and checks controls with compliance_checker.py." Framed for HealthTech/MedTech/HIPAA/EHR - not generic SaaS.

### isms-audit-expert (ra-qm-team/skills/isms-audit-expert)
```
SKILL.md 7.5 KB, 241 lines  (frontmatter also has metadata.triggers list: ISMS audit, ISO 27001 audit, nonconformity, ...)
references/cloud-security-audit.md          6.3 KB
references/iso27001-audit-methodology.md    6.8 KB
references/iso27001_audit_playbook.md       9.6 KB
references/security-control-testing.md      7.1 KB
scripts/isms_audit_scheduler.py             9.2 KB
```
Description: "Use for ISO 27001 audit work: internal or surveillance audits, Annex A control evidence, Statement of Applicability, nonconformities, Stage 1 and 2 prep. Plans risk-based audits with isms_audit_scheduler.py."

So yes: the same folder has two ISO 27001 skills (ISMS implementation + ISMS audit). Also ra-qm-team/skills/iso42001-specialist (AI management system, out of scope) and gdpr-dsgvo-expert (cross-referenced).

---------------------------------------------------------------------
## 2. What each file / script does

All scripts: Python 3, stdlib only (argparse, csv, json, io, sys, datetime, typing). No network, no subprocess, no third-party deps; they read local JSON/CSV and print to stdout / write an output file. Safe in that sense; I read them but did not run them. They are static/offline "template processors" - none of them touches a live system.

SOC 2 scripts
- control_matrix_builder.py: hard-coded dict of 64 controls (SEC-001.. etc.), one or more per TSC criterion; input = `--categories security,availability,...` + `--format md|json|csv`; output = control matrix with id, TSC ref, description, type (Preventive/Detective/Corrective), frequency, evidence text. Note: the SKILL.md matrix schema lists "Owner" and "Testing Procedure" fields but the generated controls only have id/tsc/description/type/frequency/evidence (owner/test are left to the user).
- evidence_tracker.py: input = JSON matrix (`{"controls":[...]}` or array) with fields like control_id, tsc_criteria, description, evidence_required plus status; output = collection completeness %, overdue items, readiness score. Statuses: collected / pending / overdue / not_started / not_applicable. It only tracks what you type in; nothing is collected.
- gap_analyzer.py: input = JSON of your current controls + `--type type1|type2`; compares against a hard-coded REQUIRED_TSC map (security/availability/confidentiality/processing-integrity/privacy) and reports missing / partial / design gaps / (type2) operating gaps with priorities.
References
- trust_service_criteria.md: per-criterion table (objective / typical controls / evidence), "when to include" guidance, RTO/RPO/SLA metrics, data-classification levels, TSC selection guide by company type, GDPR overlap table, and a cross-framework table (ISO 27001 / NIST CSF / HIPAA / PCI DSS).
- evidence_collection_guide.md: auditor evidence types (inquiry/observation/inspection/re-performance), evidence-quality criteria, Type I vs Type II evidence per control area (access, change, IR, vuln mgmt, encryption, backup/DR, monitoring, governance, vendor), automation tool table (Okta, AWS IAM, AWS Config, Terraform/OPA, Nessus/Qualys/Snyk, GitHub/GitLab/Bitbucket, Datadog, AWS Backup, KnowBe4...), a suggested evidence repository directory tree, and a sampling-size table by control frequency (annual 1; quarterly 2-4; monthly 2-5; weekly 5-15; daily 20-40; per-event 25-60).
- type1_vs_type2.md: comparison table, when to start with Type I vs go straight to Type II, timelines, costs (audit fees $20-50K Type I / $30-100K+ Type II), upgrade path, auditor testing approach.
- soc2_audit_playbook.md: Type II 12-month cycle (pre-observation, observation, field testing, report), report structure (opinion / management assertion / system description / controls+tests), top-10 common exceptions, Type I vs II delta, ISO 27001 reuse (~75% overlap claim), Privacy/GDPR overlap. References a `compliance-os/...` skill and `audit_simulator.py` that are NOT part of this skill (dangling cross-reference; compliance-os is a separate dir in the repo).

ISO 27001 scripts
- compliance_checker.py: `--standard iso27001|iso27002|hipaa`, `--controls-file` CSV, `--gap-analysis`, `--domains`, `--output`. Contains a hard-coded "simplified" Annex A list of only 54 controls (A.5: 10, A.6: 8, A.7: 8, A.8: 28) out of 93, each with a priority. Output: implementation status, % per domain, gap recommendations.
- risk_assessment.py: `--scope`, `--template general|healthcare|cloud`, `--assets` CSV, `--output`, `--format json|csv|markdown`. Built-in threat/vulnerability lists (includes e.g. "HIPAA violation" threat), likelihood x impact 5x5 scoring, treatment recommendation, residual risk.
- isms_audit_scheduler.py: `--year`, `--controls` CSV, `--format`; risk-rated Annex A domains (A.5 37, A.6 8, A.7 14, A.8 34 - correct counts) -> annual audit calendar.
References: iso27001-controls.md (implementation + evidence for ~17 selected controls, SoA guidance, exclusion examples), risk-assessment-guide.md, incident-response.md (procedures/escalation/comms templates), cloud-security-audit.md (shared responsibility, provider cert check, AWS/Azure checklists), iso27001-audit-methodology.md, iso27001_audit_playbook.md, security-control-testing.md (inquiry/observation/inspection/re-performance, sampling table, per-Annex-A test procedures).

---------------------------------------------------------------------
## 3. Control catalog coverage

### SOC 2 TSC coverage (breadth: complete in IDs; depth: shallow; accuracy: partially wrong)
Criteria IDs present everywhere (reference + builder + gap analyzer): CC1.1-1.5, CC2.1-2.3, CC3.1-3.4, CC4.1-4.2, CC5.1-5.3, CC6.1-6.8, CC7.1-7.5, CC8.1, CC9.1-9.2 (all 33 official CC criteria exist); A1.1-1.3; C1.1-1.3; PI1.1-1.4; P1.1, P2.1, P3.1, P4.1, P4.2, P5.1, P5.2, P6.1, P6.2, P7.1, P8.1.
Depth: one row per criterion = {objective, "typical controls" (1-3 phrases), evidence list}; the script has 64 one-line controls (about 1-2 per criterion), with type/frequency/evidence. No points-of-focus (the 2022 revised POFs under each criterion), no concrete implementable control statements, no test procedures, no tech-stack-specific guidance. It is a catalog skeleton.

ACCURACY PROBLEMS versus the real AICPA 2017 TSC (rev. 2022 points of focus), verified from my knowledge of the criteria text:
- CC6.4: skill says "Periodic access reviews". Real CC6.4 = physical access restrictions to facilities and protected information assets. CC6.5 in the skill = "Physical access restrictions"; real CC6.5 = discontinuing logical/physical protections over assets and disposing of them (decommissioning). Real home of periodic access review is CC6.2/CC6.3 (registration/authorization, role-change/removal; reviews appear as points of focus).
- CC6.6: skill = "Encryption of data in transit and at rest". Real CC6.6 = logical access security measures against threats from OUTSIDE system boundaries (firewalls, perimeter, MFA for remote). Encryption is in CC6.1 (point of focus) and CC6.7 (data transmission/movement/removal, with encryption of data in transit).
- CC9.1/CC9.2 are swapped in substance: real CC9.1 = identifies, selects and develops risk mitigation activities for business disruptions (incl. insurance/transfer); real CC9.2 = assesses and manages risks from vendors and business partners. Skill says CC9.1 = vendor mgmt, CC9.2 = insurance.
- C1: real Confidentiality has only C1.1 (identify and maintain confidential information) and C1.2 (dispose of it). Skill invents C1.3 and relabels C1.2 as "protection" - encryption/DLP are NOT criteria under C1.
- PI1: real PI1.1 = definitions of processing specifications / quality info, PI1.2 = inputs complete & accurate, PI1.3 = processing complete/accurate/timely/authorized, PI1.4 = outputs, PI1.5 = stored items. Skill's PI1.1-PI1.4 (accuracy / completeness / timeliness / authorization) is an invented decomposition and omits PI1.5.
- Privacy: real set is P1.1; P2.1; P3.1, P3.2; P4.1, P4.2, P4.3; P5.1, P5.2; P6.1-P6.7; P7.1; P8.1. Skill has P4.2 = "Disposal" (real P4.2 = retention, P4.3 = disposal), P6.2 = "breach notification" (real breach/incident notification are P6.3/P6.6/P6.7; P6.2 = authorized disclosures records), omits P3.2, P4.3, P6.3-P6.7. Also SKILL.md table calls P1-P8 with generic names (OK at family level).
- CC1-CC5, CC7, CC8, A1 descriptions are basically correct at the headline level.
- "Maps to COSO 2013 principles... 17 COSO principles" - correct (COSO 2013, 17 principles).
- Statement "Security ... required; others optional" correct. Playbook mentions "2017 TSC as updated in 2022" - correct. AT-C 205 / description of system - correct.
- Missing: Common criteria "additional criteria" for Availability/Confidentiality beyond IDs; no mention of DC 200 (description criteria), SOC 2+ (HIPAA/ISO overlays), SOC 3, or bridge letters / gap letters, complementary subservice organization controls (CSOCs; only CUECs mentioned), and that the CC criteria are "common" to all categories (the skill says so briefly).

### ISO 27001 coverage
- Uses ISO 27001:2022 consistently (93 controls, 4 themes A.5-A.8 with 37/8/14/34 - correct). No 2013 (A.9-A.18) numbering found anywhere (grep for 2013 hits only COSO 2013). Good.
- But catalog is partial: compliance_checker.py has only 54 of 93 controls ("simplified"); iso27001-controls.md writes up ~17 controls in detail; the 2022 new controls (A.5.7 threat intel is listed; A.5.23 cloud services, A.5.30 ICT readiness for BC, A.7.4 physical monitoring (present), A.8.9 configuration mgmt (present), A.8.10 deletion, A.8.11 masking, A.8.12 DLP, A.8.16 monitoring activities, A.8.23 web filtering, A.8.28 secure coding) are only partly covered - e.g. A.5.23 and A.5.30 absent from the checker's list; verify before reuse.
- Clause 4-10 management-system requirements (scope, SoA, risk treatment plan, internal audit, management review) are covered at a checklist level in SKILL.md; no clause-by-clause reference file.
- The SOC 2 -> ISO mapping table in trust_service_criteria.md is partly wrong with 2022 numbering: CC3 -> "A.8.2 (Risk)" (A.8.2 is Privileged access rights; risk assessment is Clause 6.1.2/8.2, not Annex A); CC4 -> "A.8.34 (Monitoring)" (A.8.34 is protection of info systems during audit testing; monitoring is A.8.16 / Clause 9); CC1/CC2 -> A.5.1 only (too thin: also A.5.2-5.4, A.6.x). Others (A.5.15 access, A.8.8 vulns, A.8.15 logging, A.8.32 change mgmt, A.5.19-5.22 suppliers, A.8.13-14 backup/redundancy, A.5.34 privacy) are right. "~75% overlap" is an unsourced heuristic.
- The ISO skills never cross-walk back to TSC in detail (only a one-line claim in isms-audit-expert playbook).
- ISO skill domain bias: healthcare/HIPAA/EHR examples and a `hipaa` standard flag in the checker; not tailored to SaaS/dev-shop.

---------------------------------------------------------------------
## 4. AWS infra inspection, evidence collection, Vanta/Drata

- Vanta / Drata / Secureframe / compliance platforms: NOT mentioned anywhere in either skill (grep: zero hits for vanta, drata, secureframe; only generic "compliance platforms"/"compliance-as-code tools").
- AWS infra inspection: no scripts call AWS, no CLI/boto3/Config/Prowler/Security Hub/CloudTrail queries. The only AWS content is (a) a tool-name list in evidence_collection_guide.md ("AWS IAM + Jira", "AWS Config", "AWS Backup"), and (b) a static manual AWS checklist in isms-audit-expert/references/cloud-security-audit.md (root MFA, no root keys, least privilege, no 0.0.0.0/0 on mgmt ports, VPC flow logs, no public S3, encryption, versioning, CloudTrail all regions/log-file validation/KMS, CloudWatch alarms). That checklist is a useful starting list but is checkbox-only: no commands, no mapping to TSC/Annex A, no evidence artifact definition. The ISO skill's examples mention "AWS RDS / AWS ECS" only as sample assets.
- Evidence collection: conceptual + tracking only. evidence_collection_guide.md gives per-control Type I vs Type II evidence expectations, the evidence-quality criteria, a recommended folder structure and a 6-step "evidence collection script pattern", but no automation is provided. evidence_tracker.py is a status reporter over a hand-filled JSON file. No concept of evidence freshness/hash/timestamp capture, population lists for sampling, or auditor request lists (PBC).
- No MCP / API integrations of any kind.

---------------------------------------------------------------------
## 5. Quality assessment

### Licensing
Repo LICENSE = MIT, "Copyright (c) 2025 Alireza Rezvani". Reuse of ideas/structure/text is permitted with the MIT notice retained for any copied substantial portions; ideas and the public TSC facts themselves are not copyrightable. (AICPA TSC text is AICPA copyright - do not paste verbatim criteria wording/points of focus; paraphrase and cite the TSC 2017 rev. 2022 document.) ISO 27001 / 27002 control titles are ISO copyright; control IDs + short names are commonly used but do not paste ISO text.

### Strengths (worth reusing as ideas)
1. Description is trigger-oriented ("Use when ...") with concrete task verbs - good for skill routing.
2. Clear separation: SKILL.md (overview/workflow) -> references (catalog, evidence, Type I vs II, playbook) -> scripts. Reference files are one-hop from SKILL.md.
3. Control-matrix schema is well thought out: control ID convention by category, TSC mapping, type (preventive/detective/corrective), owner, frequency, evidence type, testing procedure. Matrix validation rule "every selected criterion has >=1 control".
4. Evidence guide splits Type I (design evidence) vs Type II (operating evidence across the period) per control area - this distinction is the most valuable practical idea. Also the sampling-size-by-frequency table and "population completeness" rule (auditor picks from the full population you provide).
5. Playbook content on the observation window is practical: don't skip a cycle, don't change controls mid-period without change management, capture evidence in real time, top-10 typical Type II exceptions, exception handling.
6. Anti-patterns table, readiness scoring bands, vendor tiering + carve-out vs inclusive + CUEC explanation.
7. Gap taxonomy: missing / partial / design gap / operating gap (Type II only) with priority->remediation weeks.
8. Cross-skill linking (SOC 2 <-> ISO 27001 <-> GDPR <-> audit) and the ISO 2022 theme structure (organizational/people/physical/technological).
9. Stdlib-only scripts, no network - low supply-chain risk (still not run by me).

### Weaknesses / wrong / generic
1. Factual errors in TSC mapping (CC6.4, CC6.5, CC6.6, CC9.1/9.2 swapped, invented C1.3, wrong PI1.x semantics, incomplete P-series) - listed in section 3. These errors propagate into the gap analyzer's REQUIRED_TSC and the builder's control IDs, so the tools' "coverage" outputs would mislead an auditor-facing deliverable. Looks LLM-generated without checking against the AICPA text.
2. Wrong ISO 27001:2022 cross-references in the SOC 2 mapping (A.8.2, A.8.34).
3. Generic, shallow controls: one-liner "typical controls" and evidence lists; no cloud/IaC/CI-CD/DevSecOps specifics; no examples of real policies (the ~15 policies auditors expect: InfoSec, access control, change mgmt, IR, BCP/DR, vendor mgmt, data classification/retention, SDLC, risk mgmt, acceptable use, HR/onboarding/offboarding, encryption, logging, vulnerability mgmt).
4. Scripts are static data dumps: the "gap analyzer" requires you to hand-write a controls JSON; none infers state from real systems. Matrix output omits Owner/Testing fields promised in SKILL.md. No tests.
5. Costs/timelines (audit fees $20-100K, "~75% overlap", 4-8 week gap assessment) are unsourced guesses, US-centric, and date quickly.
6. SKILL.md is textbook-style (423 lines of explanation) rather than procedural instruction for the agent; no decision points like "ask the user which TSC categories/systems/period", no output templates for deliverables beyond the matrix.
7. Dangling references: soc2_audit_playbook.md points to compliance-os/... and audit_simulator.py that are not packaged with the skill; "gdpr-dsgvo-expert" etc. rely on sibling skills.
8. ISO side is healthcare/HIPAA-biased, checker covers only 54/93 controls, and its "worked example" output (Overall Compliance 87%) is illustrative fiction not produced by the script. Clause 4-10 requirements lack a dedicated reference.
9. No handling of: SOC 2 scoping/system description (DC 200 / AT-C 205 is only named), subservice org CSOC mapping to AWS shared responsibility, readiness vs. audit-firm roles (readiness consultants cannot be the auditor - independence), bridge letters, report lifetimes, penetration testing expectations, change-in-scope mid-period, personnel/HR evidence (background checks, onboarding/offboarding SLAs), endpoint/MDM evidence.
10. Two-key frontmatter is fine, but SKILL.md Table of Contents + very long tables load every time the skill triggers (token cost); a lean SKILL.md with the catalog moved into references would load cheaper.

---------------------------------------------------------------------
## 6. Ideas to adopt and pitfalls to avoid for our own skill

### Adopt
1. Trigger-style description ("Use when the user asks to prepare for SOC 2 / ISO 27001, map controls, collect evidence, run gap analysis...") and keep SKILL.md lean; push catalog into references/.
2. Control-matrix schema: control ID, criterion mapping (TSC + ISO Annex A 2022 + optionally NIST/CIS), type (preventive/detective/corrective), owner, frequency, evidence artifact(s), test procedure, automation status (automated / semi / manual), source system. Add two columns they lack: "AWS/Bitbucket resource it lives on" and "Vanta/Drata test ID(s) it maps to".
3. Per-control Type I (design) vs Type II (operating over period) evidence split, plus sampling table by frequency and "provide full population" rule.
4. Gap taxonomy (missing / partial / design / operating) and remediation priority windows.
5. Observation-window discipline checklist (no skipped cycles, change-managed control changes, evidence captured in real time) and the top-10 Type II exception list - turn each into an automatable check (e.g. quarterly access review ticket exists for each quarter; vuln SLA breach count; background check present for each new hire).
6. Cross-framework "one control, many mappings" model: single control catalog with columns for SOC 2 TSC and ISO 27001:2022 Annex A (and a Clauses 4-10 list for ISMS-only items like scope, SoA, internal audit, management review, which SOC 2 doesn't require).
7. Evidence-repository folder layout per audit period and evidence-quality criteria (relevant/reliable/timely/sufficient/complete), reliable = system-generated rather than self-reported.
8. Their AWS config checklist (cloud-security-audit.md) as a seed, but upgrade to concrete read-only commands/queries (aws iam get-account-summary / credential report, s3api get-public-access-block, cloudtrail describe-trails, config rules, GuardDuty/Security Hub, RDS encryption, KMS rotation, backup plans, SG 0.0.0.0/0) each tagged to a control ID and the artifact to store.
9. Anti-patterns table, readiness scoring bands (make thresholds ours, not theirs).
10. Vendor tiering and carve-out vs inclusive; typical SaaS stack: cloud provider, VCS, compliance platform, chat, office suite as subservice orgs/vendors with CUEC/CSOC notes.

### Avoid
1. Do NOT copy their TSC table or the builder/gap_analyzer data: it contains the errors listed in section 3 (CC6.4/6.5/6.6, CC9.1/9.2, C1.3, PI1.x, P-series). Build our catalog from the AICPA 2017 TSC (rev. 2022 POFs) or from the criteria as exposed in Vanta/Drata (`Drata_listRequirements`, `Drata_searchControls`), and mark source + version.
2. Do not map SOC 2 to ISO with unverified Annex A numbers (their A.8.2 and A.8.34 are wrong); validate against ISO/IEC 27001:2022 Annex A (93 controls, 37/8/14/34) and keep a test that every mapped ID exists.
3. Don't ship scripts that only format hand-entered JSON; if scripts are included, make them read-only collectors against real systems (AWS CLI/SDK, Bitbucket API) with documented IAM least-privilege policy, no credentials in code, output hashed + timestamped, and never log PII/secrets (matches the organization rules). Alternatively prefer using Drata/Vanta MCP as the evidence source of truth rather than re-implementing it.
4. Don't invent criteria, scores ("Overall Compliance: 87%") or unsourced cost/time/overlap numbers; state "unknown - confirm with auditor".
5. Don't write a textbook in SKILL.md; make it procedural: ask for scope (systems, TSC categories, Type I/II, observation period, auditor), then run steps, then produce defined deliverables (matrix, gap report, evidence request list, remediation backlog).
6. Avoid dangling cross-references to skills/scripts that are not in the package; keep every file referenced one level deep from SKILL.md.
7. Avoid industry bias (their ISO skill is HIPAA/EHR-oriented); ours is SaaS/dev-shop on AWS.
8. Don't conflate readiness advice with the audit opinion: a consultant/agent output is not an attestation; auditor independence applies.
9. Keep copyright hygiene: paraphrase AICPA TSC and ISO text; if any code/text from this MIT repo is reused verbatim, retain "Copyright (c) 2025 Alireza Rezvani" MIT notice.
10. Include tests/validation for the catalog (unique IDs, every TSC criterion for selected categories covered, every Annex A ID valid) - this repo has none and that is how errors slipped in.

### Suggested structure for our skill (derived)
```
soc2-iso27001-readiness/
  SKILL.md                       (lean workflow, scoping questions, deliverables, when to load which reference)
  references/control-catalog.md  (one catalog, columns: ID | TSC | ISO 27001:2022 Annex A | type | frequency | evidence | AWS/Bitbucket source | Drata/Vanta test)
  references/tsc-criteria.md     (verified criteria IDs only, paraphrased)
  references/iso27001-isms.md    (clauses 4-10 + SoA + Annex A 93 list)
  references/evidence-playbook.md(Type I vs II evidence, sampling, folder layout, observation-window rules, top exceptions)
  references/aws-evidence-queries.md (read-only commands per control)
  references/drata-vanta.md      (how to use the MCP tools: tests, controls, personnel, vendors, evidence upload)
  scripts/ (optional, read-only collectors + catalog validator)
```
