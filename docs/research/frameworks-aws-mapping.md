# SOC 2 + ISO 27001 readiness: reference material for an AWS-in-Obsidian evaluation skill

Research date: 2026-11-12. Legend: **[S]** = sourced from a fetched page/file (URL given); **[K]** = from model background knowledge, not verified in this session (verify before hard-coding); **[I]** = inference/recommendation.

---------------------------------------------------------------------

## 0. Headline corrections to the brief (important for skill design)

1. **There is NO AWS Config conformance pack for SOC 2 or for ISO 27001** [S]. The AWS Config sample-template index and the awslabs GitHub folder (125 files) contain no SOC2/ISO27001/AICPA pack. AWS itself states "AWS Config does not currently offer Conformance Pack templates for ... SOC2 and GDPR", and the Audit Manager->Config mapping table lists "ISO/IEC 27001:2013 Annex A: -- No equivalent --" and "SSAE-18 SOC 2: -- No equivalent --".
   - https://docs.aws.amazon.com/config/latest/developerguide/conformancepack-sample-templates.html
   - https://docs.aws.amazon.com/audit-manager/latest/userguide/audit-manager-availability-change.html
   - https://api.github.com/repos/awslabs/aws-config-rules/contents/aws-config-conformance-packs
   - Substitute (concrete rule list, section 4.2): the 65 Config rule identifiers that Audit Manager's SOC 2 framework uses as data-source mappings (downloadable xlsx from AWS docs).
2. **AWS Audit Manager is in maintenance mode** [S]: "no longer open to new customers"; from 30 April 2026 it cannot be set up in new accounts/regions; no new frameworks or framework versions. Its ISO framework is **ISO/IEC 27001:2013 Annex A only** (per the AWS mapping table). So it is not a good dependency for a new skill. Same URL as above.
3. **AWS Control Tower controls** (Control Catalog) *do* tag controls by framework including **"ISO-IEC-27001:2013-Annex-A"** and **"SSAE-18-SOC-2-Oct-2023"** [S] - https://docs.aws.amazon.com/controltower/latest/controlreference/frameworks-supported.html . Useful as a "which AWS detective control relates to which SOC 2/ISO criterion" lookup (2013 numbering for ISO).
4. **The "31 Oct 2025" date is the ISO 27001:2013 -> 2022 transition deadline, not tied to the 2024 climate amendment** [S] (see 1.5).
5. **AICPA's SOC2<->ISO27001 mapping is member-gated** (AICPA & CIMA members only), dated 4 May 2018, file `trust-services-map-to-iso-27001.xlsx`, edition of ISO not named on the page (inference: ISO 27001:2013, since it predates 2022) [S/I]. Could not download it. A usable open substitute exists (section 3.2).

---------------------------------------------------------------------

## 1. ISO/IEC 27001:2022

### 1.1 Clauses 4-10 (ISMS requirements) [K, consistent with Advisera/TCSA pages below]

| Clause | Sub-clauses | What an assessor looks for |
|---|---|---|
| 4 Context | 4.1 understanding the organization and its context (**Amd 1:2024 adds: determine whether climate change is a relevant issue**); 4.2 needs/expectations of interested parties (Amd 1 adds a note: relevant parties may have climate-related requirements); 4.3 determining ISMS scope; 4.4 ISMS | Documented scope, interfaces/dependencies (here: AWS as a service provider) |
| 5 Leadership | 5.1 leadership & commitment; 5.2 policy; 5.3 organizational roles, responsibilities, authorities | Signed policy, named roles |
| 6 Planning | 6.1.1 general; 6.1.2 information security risk assessment; 6.1.3 risk treatment (incl. **Statement of Applicability**, risk treatment plan); 6.2 security objectives and planning to achieve them; **6.3 planning of changes (new in 2022)** | Risk method (criteria, acceptance), risk register, SoA, treatment plan, objectives |
| 7 Support | 7.1 resources; 7.2 competence; 7.3 awareness; 7.4 communication (2022 now: what/when/with whom/how); 7.5 documented information (7.5.1-7.5.3) | Training records, document control |
| 8 Operation | 8.1 operational planning and control (2022: define criteria for processes, control outsourced processes); 8.2 risk assessment (performed at planned intervals / on change); 8.3 risk treatment | Evidence that planned risk assessments and treatments were executed |
| 9 Performance evaluation | 9.1 monitoring, measurement, analysis, evaluation; 9.2 internal audit (9.2.1 general, 9.2.2 programme); 9.3 management review (9.3.1 general, 9.3.2 inputs, 9.3.3 results) | Audit programme + reports; minutes of management review |
| 10 Improvement | 10.1 continual improvement; 10.2 nonconformity and corrective action (2022 order: 10.1 continual improvement comes first) | Corrective-action log |

Corroborating sources for clause content: https://www.tcsa.in/frameworks/iso-27001/requirements (lists clause topics, no sub-numbers) [S]; sub-numbering above is [K]. Clause 4-10 are all mandatory; exclusion is not allowed (only Annex A controls can be excluded, with justification in the SoA) [K].

### 1.2 Mandatory documented information (source: Advisera) [S]
https://advisera.com/27001academy/knowledgebase/list-of-mandatory-documents-required-by-iso-27001-revision/

Documents ("must be documented"):

| Item | Clause |
|---|---|
| Scope of the ISMS | 4.3 |
| Information security policy | 5.2 |
| Risk assessment and risk treatment process | 6.1.2 |
| **Statement of Applicability (SoA)** | 6.1.3 d) |
| Risk treatment plan | 6.1.3 e), 6.2, 8.3 |
| Information security objectives | 6.2 |
| Risk assessment and treatment report (results) | 8.2, 8.3 |

Records ("must be retained as evidence"):

| Item | Clause |
|---|---|
| Evidence of competence (training, skills, experience, qualifications) | 7.2 |
| Monitoring and measurement results | 9.1 |
| Internal audit programme | 9.2 |
| Internal audit results | 9.2 |
| Management review results | 9.3 |
| Nonconformities and corrective action results | 10.2 |

Annex A-driven documents (Advisera marks these as needed only if risks / interested parties call for them): asset inventory (5.9), acceptable use (5.10), incident response procedure (5.26), legal/regulatory/contractual requirements (5.31), operating procedures (5.37), security roles/responsibilities (6.2, 6.6), security configurations (8.9), secure engineering principles (8.27), logs of user activity/exceptions/security events (8.15).

Notes: Advisera is a vendor blog, not the standard. Other clause-level items that exist in the standard text but are not in Advisera's table [K]: 7.5.1(b) "documented information determined by the organization as necessary"; 8.1 "documented information to the extent necessary to have confidence processes carried out as planned"; 6.1.3 "retain documented information about risk treatment process". Treat the SoA as the single most scrutinised artifact: for each of the 93 controls, included/excluded, justification, implementation status.

### 1.3 Annex A: 93 controls, 4 themes (5=37, 6=8, 7=14, 8=34) [S]
Source: https://www.isms.online/iso-27001/annex-a-controls/ (names there confirmed against the Prowler `iso27001_2022_aws.json` which has 92 of 93 IDs, see 6.1). **NEW = one of the 11 controls introduced in 2022.**

**Theme 5 - Organizational (37)**

| ID | Name | | ID | Name |
|---|---|---|---|---|
| 5.1 | Policies for information security | | 5.20 | Addressing information security within supplier agreements |
| 5.2 | Information security roles and responsibilities | | 5.21 | Managing information security in the ICT supply chain |
| 5.3 | Segregation of duties | | 5.22 | Monitoring, review and change management of supplier services |
| 5.4 | Management responsibilities | | 5.23 | Information security for use of cloud services **NEW** |
| 5.5 | Contact with authorities | | 5.24 | Information security incident management planning and preparation |
| 5.6 | Contact with special interest groups | | 5.25 | Assessment and decision on information security events |
| 5.7 | Threat intelligence **NEW** | | 5.26 | Response to information security incidents |
| 5.8 | Information security in project management | | 5.27 | Learning from information security incidents |
| 5.9 | Inventory of information and other associated assets | | 5.28 | Collection of evidence |
| 5.10 | Acceptable use of information and other associated assets | | 5.29 | Information security during disruption |
| 5.11 | Return of assets | | 5.30 | ICT readiness for business continuity **NEW** |
| 5.12 | Classification of information | | 5.31 | Legal, statutory, regulatory and contractual requirements |
| 5.13 | Labelling of information | | 5.32 | Intellectual property rights |
| 5.14 | Information transfer | | 5.33 | Protection of records |
| 5.15 | Access control | | 5.34 | Privacy and protection of PII |
| 5.16 | Identity management | | 5.35 | Independent review of information security |
| 5.17 | Authentication information | | 5.36 | Compliance with policies, rules and standards for information security |
| 5.18 | Access rights | | 5.37 | Documented operating procedures |
| 5.19 | Information security in supplier relationships | | | |

**Theme 6 - People (8)**: 6.1 Screening; 6.2 Terms and conditions of employment; 6.3 Information security awareness, education and training; 6.4 Disciplinary process; 6.5 Responsibilities after termination or change of employment; 6.6 Confidentiality or non-disclosure agreements; 6.7 Remote working; 6.8 Information security event reporting.

**Theme 7 - Physical (14)**: 7.1 Physical security perimeters; 7.2 Physical entry; 7.3 Securing offices, rooms and facilities; 7.4 Physical security monitoring **NEW**; 7.5 Protecting against physical and environmental threats; 7.6 Working in secure areas; 7.7 Clear desk and clear screen; 7.8 Equipment siting and protection; 7.9 Security of assets off-premises; 7.10 Storage media; 7.11 Supporting utilities; 7.12 Cabling security; 7.13 Equipment maintenance; 7.14 Secure disposal or re-use of equipment.

**Theme 8 - Technological (34)**

| ID | Name | | ID | Name |
|---|---|---|---|---|
| 8.1 | User endpoint devices | | 8.18 | Use of privileged utility programs |
| 8.2 | Privileged access rights | | 8.19 | Installation of software on operational systems |
| 8.3 | Information access restriction | | 8.20 | Networks security |
| 8.4 | Access to source code | | 8.21 | Security of network services |
| 8.5 | Secure authentication | | 8.22 | Segregation of networks |
| 8.6 | Capacity management | | 8.23 | Web filtering **NEW** |
| 8.7 | Protection against malware | | 8.24 | Use of cryptography |
| 8.8 | Management of technical vulnerabilities | | 8.25 | Secure development life cycle |
| 8.9 | Configuration management **NEW** | | 8.26 | Application security requirements |
| 8.10 | Information deletion **NEW** | | 8.27 | Secure system architecture and engineering principles |
| 8.11 | Data masking **NEW** | | 8.28 | Secure coding **NEW** |
| 8.12 | Data leakage prevention **NEW** | | 8.29 | Security testing in development and acceptance |
| 8.13 | Information backup | | 8.30 | Outsourced development |
| 8.14 | Redundancy of information processing facilities | | 8.31 | Separation of development, test and production environments |
| 8.15 | Logging | | 8.32 | Change management |
| 8.16 | Monitoring activities **NEW** | | 8.33 | Test information |
| 8.17 | Clock synchronization | | 8.34 | Protection of information systems during audit testing |

The 11 new controls (confirmed against the isms.online page, 11 flagged): 5.7, 5.23, 5.30, 7.4, 8.9, 8.10, 8.11, 8.12, 8.16, 8.23, 8.28. Count check: 37+8+14+34 = 93 [S].

Structure change [K]: 2013 had 114 controls in 14 domains (A.5-A.18); 2022 has 93 in 4 themes (11 new, the rest carried over, renamed or merged from 2013); ISO/IEC 27002:2022 adds attributes per control (control type, CIA properties, cybersecurity concept, operational capability, security domain) - useful tagging dimensions for the skill [K].

### 1.4 Cloud-relevant new controls (what to look for in an AWS vault) [I]
- 5.23 cloud services: documented process for acquiring/using/exiting cloud; shared-responsibility doc, AWS Artifact reports reviewed.
- 5.30 ICT readiness for BC: RTO/RPO, multi-AZ/region, restore tests.
- 8.9 configuration management: IaC, Config/Security Hub baselines, drift detection.
- 8.10 deletion: S3 lifecycle, RDS/snapshot retention, KMS key deletion policy.
- 8.11 masking / 8.12 DLP: Macie, masked non-prod data, egress controls.
- 8.16 monitoring: GuardDuty, CloudWatch alarms, Security Hub triage.
- 8.23 web filtering: Route 53 Resolver DNS Firewall / Network Firewall / proxy for egress.
- 8.28 secure coding: SAST/dependency scanning in CI (note Prowler's JSON has no A.8.28 entry, see 6.1).
- 7.4 physical monitoring: inherited for AWS DCs; customer-side for offices.
- 5.7 threat intel: GuardDuty feeds, vendor advisories, subscription process.

### 1.5 Transition & amendment
- **Transition deadline: 31 Oct 2025** - 36-month window from 2022 publication (IAF MD 26:2023); new/recert audits had to be to 2022 from 30 Apr 2024; ISO 27001:2013 certificates not transitioned lapse at 31 Oct 2025. The deadline has passed (today 2026-11-12), so **any assessment today should be against 2022 only; 2013 numbering is legacy** [S via certification bodies: https://www.dqsglobal.com/en/explore/blog/hk/transition-requirements-for-iso-27001-2022 ; https://www.brightdefense.com/news/iso-270012022-deadline-puts-legacy-certificates-at-risk/ ; IAF MD 26 itself not opened].
- **ISO/IEC 27001:2022/Amd 1:2024 (published Feb 2024)** - climate action: 4.1 add "the organization shall determine whether climate change is a relevant issue"; 4.2 adds a note that relevant interested parties may have climate-related requirements. No new/changed Annex A controls. Amendment text identical to ISO available via BIS India (https://services.bis.gov.in/tmp/LITD23425400_06092024_1.pdf) [S via search summary]; commentary: https://hightable.io/iso27001-2022-amendment-1-climate-action-changes-executive-briefing/ . No formal cutover date for Amd 1 found; a consultancy says incorporate at next surveillance/recert audit [S, weak]. Skill implication: the vault should have a note in the 4.1/4.2 context docs stating climate relevance [I].

---------------------------------------------------------------------

## 2. SOC 2 - 2017 Trust Services Criteria (revised points of focus 2022)

Official doc: AICPA "TSP Section 100, 2017 Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy (With Revised Points of Focus - 2022)" - https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022 (free, requires AICPA account; download returned HTML in this session) [S]. The 2022 revision changed **points of focus only, not the criteria** (AICPA, quoted by Hyperproof/EY) [S via https://www.barradvisory.com/blog/whats-new-with-soc-2, https://drata.com/learn/soc-2/trust-services-criteria-revised-points]. Points of focus are guidance; an assessment does not require evaluating each one [S via Drata].

Criterion IDs and text below parsed from the open CISO Assistant library of the AICPA doc (61 criteria): https://github.com/intuitem/ciso-assistant-community/blob/main/backend/library/libraries/soc2_2017_with_rev_2022.yaml [S]. One-line titles are my paraphrase.

### 2.1 Common Criteria (Security, always in scope): 33 criteria

| Series (COSO component) | IDs | Paraphrase |
|---|---|---|
| CC1 Control environment | CC1.1 integrity & ethics; CC1.2 board independence/oversight; CC1.3 structures, reporting lines, authorities; CC1.4 attract/develop/retain competent people; CC1.5 accountability | Governance, HR, org chart |
| CC2 Communication & information | CC2.1 quality information for internal control; CC2.2 internal communication (objectives, responsibilities); CC2.3 external communication | Policies communicated, customer commitments, incident reporting channels |
| CC3 Risk assessment | CC3.1 objectives specified; CC3.2 identify/analyze risks; CC3.3 fraud risk; CC3.4 identify/assess changes | Risk register |
| CC4 Monitoring | CC4.1 ongoing/separate evaluations; CC4.2 communicate deficiencies | Internal audits, control testing |
| CC5 Control activities | CC5.1 select controls that mitigate risks; CC5.2 general IT controls; CC5.3 policies and procedures | Policy set |
| **CC6 Logical & physical access** | CC6.1 logical access software/infrastructure/architecture (auth, encryption of data, key mgmt); CC6.2 register/authorize before issuing credentials; CC6.3 authorize/modify/remove access (least privilege, RBAC); CC6.4 physical access restriction; CC6.5 secure disposal/decommission (before reuse) of assets; CC6.6 protection from external threats (firewalls, boundary); CC6.7 restrict transmission/movement/removal of info (encryption in transit); CC6.8 prevent/detect malicious software | The AWS-heavy series |
| **CC7 System operations** | CC7.1 detection & monitoring procedures (config changes, new vulnerabilities); CC7.2 monitor components for anomalies; CC7.3 evaluate security events; CC7.4 incident response program; CC7.5 recovery from incidents | Logging, GuardDuty, IR runbooks |
| CC8 Change management | CC8.1 authorize, design, develop, test, approve, implement changes | CI/CD, PR reviews, change tickets |
| CC9 Risk mitigation | CC9.1 business disruption (incl. insurance); CC9.2 vendor and business partner risk | Vendor mgmt (AWS is a subservice org) |

### 2.2 Additional categories (optional, chosen by scope)

| Category | IDs |
|---|---|
| Availability | A1.1 capacity management; A1.2 environmental protections, backups, recovery infrastructure; A1.3 recovery plan testing |
| Confidentiality | C1.1 identify/maintain confidential info; C1.2 dispose of confidential info |
| Processing Integrity | PI1.1 quality info on processing objectives; PI1.2 inputs; PI1.3 processing; PI1.4 outputs; PI1.5 stored items |
| Privacy | P1.1 notice; P2.1 choice & consent; P3.1 collection, P3.2 explicit consent; P4.1 use, P4.2 retention, P4.3 disposal; P5.1 access by data subjects, P5.2 correction; P6.1 disclosure with consent, P6.2 record of authorized disclosures, P6.3 record of unauthorized disclosures, P6.4 vendor privacy commitments, P6.5 vendor breach notification, P6.6 breach notification to subjects/regulators, P6.7 accounting of disclosures; P7.1 quality of PI; P8.1 inquiry/complaint/dispute process |

Totals: CC 33 + A 3 + C 2 + PI 5 + P 18 = 61 criteria [S, counted from library]. Most startup SOC 2 = Security (CC1-CC9) only, often + Availability/Confidentiality [K].

### 2.3 Type I vs Type II [K - standard AICPA/SSAE 18 definitions; no source fetched; AWS doc confirms SOC 2 reports are issued per SSAE 18]
| | Type I | Type II |
|---|---|---|
| Opinion on | design of controls (suitability) at a **point in time** | design **and operating effectiveness** over a **period** (commonly 3-12 months; 6 or 12 typical) |
| Evidence | Policies, configs, screenshots at date | Samples/population over period: access reviews, tickets, logs |
| Use | First report, quick to market | What most customers ask for |
Skill implication [I]: Type II needs **evidence of recurrence** (dated reviews, ticket exports); a vault documenting only configuration supports Type I-level readiness at best.

---------------------------------------------------------------------

## 3. Crosswalk SOC 2 <-> ISO 27001

### 3.1 AICPA official mapping [S]
- Page: https://www.aicpa-cima.com/resources/download/mapping-2017-trust-services-criteria-to-iso-27001 - "Mapping: 2017 Trust Services Criteria to ISO 27001", dated 4 May 2018, Excel `trust-services-map-to-iso-27001.xlsx` (137.8 KB), **AICPA & CIMA member access only**; TSC content includes March 2020 updates; page does not name the ISO edition (**[I] likely ISO 27001:2013 Annex A**, predating 2022). Could not open it, workbook layout unknown.
- AICPA also publishes mappings to NIST CSF, COBIT 5, NIST 800-53, GDPR (per search summary, [S weak]).
- Vendor "overlap" claims vary widely (~80%, 53-95%); Vanta: "vast majority of SOC 2 and ISO controls overlap" and no definitive figure exists; mapping does not give automatic dual compliance [S weak: https://www.vanta.com/collection/soc-2/iso-27001-vs-soc-2-mapping].

### 3.2 Open machine-readable alternative: CISO Assistant mapping SOC 2 (2017 rev 2022) -> ISO 27001:2022 [S]
https://github.com/intuitem/ciso-assistant-community/blob/main/backend/library/libraries/mapping-soc2-2017-rev-2022-to-iso27001-2022.yaml (1,405 point-of-focus-level mappings, relationship "intersect", published 2025-06-04, community-authored, **not AICPA/ISO endorsed**). I rolled it up to criterion level. Quality caveats [I]: coarse/partial (e.g. CC6.6 maps only to A.8.2, which is clearly incomplete - firewalls/segmentation 8.20-8.22 are missing; CC5.1/CC5.2/CC2.x sparse; one source URN looks like a typo `C6.5` for CC6.5). Use as a **starting lookup, then curate**. Plain numbers = ISO clauses, `A.x.y` = Annex A.

| SOC 2 criterion | ISO 27001:2022 clauses / Annex A controls (rolled-up from CISO Assistant) |
|---|---|
| CC1.1 | 5.1 |
| CC1.2 | 5.1, 5.3, A.5.31 |
| CC1.3 | 4.2, 5.1, 5.2, 5.3, 6.2, 6.3, 7.2-7.5, 8.1, 9.3, A.5.2, A.5.4, A.5.21, A.5.23, A.5.35, A.6.5, A.8.26 |
| CC1.4 | 7.2, A.6.1 |
| CC1.5 | 7.3, A.6.4 |
| CC2.1 | 9.1, 9.3, 10.1, A.5.29 |
| CC2.2 | 5.1, 5.2, 7.2, 7.3, 7.5, A.6.2 |
| CC2.3 | A.6.8 |
| CC3.1 | 5.1, 6.2, 6.3, 7.5.2, 8.1, A.5.35, A.8.6, A.8.26 |
| CC3.2 | 4.1, 6.1.3, 6.2, 8.1-8.3, 9.1, 10.2, A.5.12, A.5.22, A.8.8 |
| CC3.3 / CC3.4 | 4.1, 6.1.3, 6.2, 8.1-8.3, 9.1, 10.2 |
| CC4.1 / CC4.2 | 9.1, 9.3, 10.1, A.5.29 (+A.5.22 for CC4.1) |
| CC5.1 / CC5.2 | (no mappings in source) |
| CC5.3 | 5.1, 5.2, 7.3, 7.5 |
| CC6.1 | A.5.12, A.5.13, A.5.16, A.5.17, A.6.7, A.8.5, A.8.22, A.8.24, A.8.31 |
| CC6.2 / CC6.3 | A.5.9, A.5.15, A.5.18 |
| CC6.4 | A.5.15, A.5.22, A.7.1, A.7.3, A.7.4, A.7.6 |
| CC6.5 | A.5.12, A.7.14, A.8.10 |
| CC6.6 | A.8.2 (incomplete in source) |
| CC6.7 | A.6.7, A.7.1 |
| CC6.8 | A.8.7, A.8.9, A.8.16, A.8.18 |
| CC7.1 | A.5.33, A.8.8, A.8.9, A.8.15, A.8.18 |
| CC7.2 | A.8.6, A.8.16 |
| CC7.3 | A.8.16 |
| CC7.4 | A.5.24-A.5.28 |
| CC7.5 | A.5.3, A.5.24, A.5.27-A.5.29, A.5.33, A.8.13, A.8.14 |
| CC8.1 | A.5.8, A.8.3, A.8.9, A.8.25, A.8.27, A.8.28, A.8.32 |
| CC9.1 | 4.1, 6.1.3, 6.2, 7.1, 8.1-8.3, 9.1, 10.2, A.5.33, A.8.13, A.8.14 |
| CC9.2 | A.5.22, A.6.6 |
| A1.1 | A.8.6 |
| A1.2 | A.5.33, A.7.5, A.7.11, A.7.13, A.8.6, A.8.13, A.8.14 |
| A1.3 | A.5.3, A.8.13 |
| C1.1 | A.5.2, A.5.12, A.5.21, A.5.23, A.5.33, A.6.6, 7.3, A.8.13, A.8.14 |
| C1.2 | A.7.14, A.8.10 |
| PI1.x, P1-P8 | roll-up key not captured for PI (regex issue); PI/P map mostly to A.5.34 and A.8.x, check the YAML directly [I] |

Observation [I]: SOC 2 has no counterpart to ISO clauses 4-10 as such (ISMS cycle: SoA, internal audit, management review). Those need separate ISO-only checks; conversely SOC 2 Type II requires evidence of operation over time which ISO only requires via 9.1/9.2 records.

Other crosswalk sources (vendor): Sprinto https://sprinto.com/blog/soc-2-criteria-mapping-to-iso-27001/ ; Secureframe https://secureframe.com/hub/soc-2/common-criteria ; Grace/Ampcus PDF https://www.ampcuscyber.com/downloads/whitepaper/grace-soc-2-to-iso-27001-crosswalk.pdf (not opened). Also in the same repo: SCF-pivoted mappings `mapping-soc2-2017-rev-2022-and-scf-2025.2.2.yaml`, `mapping-iso27001-2022-and-scf-2025.2.2.yaml` (Secure Controls Framework) [S, listed, not parsed].

---------------------------------------------------------------------

## 4. AWS-native tooling

### 4.1 Overview table
| Tool | SOC 2 | ISO 27001 | Status / note |
|---|---|---|---|
| AWS Audit Manager | prebuilt "SSAE-18 SOC 2" framework: 15 automated + 46 manual controls, 20 control sets | prebuilt **ISO/IEC 27001:2013** Annex A only | **Maintenance mode, closed to new customers** (30 Apr 2026). Automated evidence needs Security Hub standards + specific Config rules enabled. Does not "verify compliance" and does not check procedural controls. https://docs.aws.amazon.com/audit-manager/latest/userguide/SOC2.html |
| AWS Config conformance packs | **none** | **none** | See section 0 and https://docs.aws.amazon.com/config/latest/developerguide/conformancepack-sample-templates.html. Closest general packs: Operational Best Practices for AWS Well-Architected Security Pillar, NIST 800-53 r5, NIST CSF, CIS v1.4 L1/L2, CIS Controls v8 IG1-3, plus per-service Security Best Practice packs. Config packs only cover machine-checkable technical controls; AWS: "there is no Config rule that verifies the organization has documented its security policies" and recommends partners like Vanta/Drata for end-to-end |
| AWS Control Tower controls (Control Catalog) | framework tag "SSAE-18-SOC-2-Oct-2023" | "ISO-IEC-27001:2013-Annex-A" | Controls implemented as Config rules, deployable per OU, no Conformance Pack object. https://docs.aws.amazon.com/controltower/latest/controlreference/frameworks-supported.html |
| Security Hub CSPM standards | none | none | Supported: AWS Foundational Security Best Practices (FSBP), AI Security Best Practices, AWS Resource Tagging, CIS AWS Foundations v5.0.0 / v3.0.0 / v1.4.0 / v1.2.0, NIST SP 800-53 r5, NIST SP 800-171 r2, PCI DSS, CRI Profile v2.2, Control Tower service-managed. https://docs.aws.amazon.com/securityhub/latest/userguide/standards-reference.html |
| AWS Artifact | AWS's own SOC 1/2/3 reports (SOC 2 Security, Availability & Confidentiality; SOC 2 Privacy Type I; SOC 3 public) | AWS ISO/IEC 27001:2022 certificate, plus 27017:2015, 27018:2019 (certificate linked from AWS page) | Self-service portal for audit reports and agreements. https://aws.amazon.com/artifact/ ; https://aws.amazon.com/compliance/iso-27001-faqs/ |

AWS caveat repeated across docs: conformance packs / standards "are not designed to ensure compliance... can neither replace internal efforts nor guarantee passing an assessment" [S].

### 4.2 Concrete machine-checkable list: Config rules in Audit Manager's SOC 2 framework [S]
Source: AWS-published `AuditManager_ConfigDataSourceMappings_SSAE-No.-18-SOC-Report-2.zip` (https://docs.aws.amazon.com/audit-manager/latest/userguide/samples/AuditManager_ConfigDataSourceMappings_SSAE-No.-18-SOC-Report-2.zip), 65 rule identifiers parsed locally (saved as `soc2_rules.txt` next to this report). The xlsx has no SOC 2 criterion column (rule + description only), so rule->criterion mapping is **not** provided by AWS here [S/I].

Grouped by theme (grouping is mine [I]):

- **Encryption in transit / TLS**: ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK, CLOUDFRONT_CUSTOM_SSL_CERTIFICATE, CLOUDFRONT_TRAFFIC_TO_ORIGIN_ENCRYPTED, CLOUDFRONT_VIEWER_POLICY_HTTPS, DAX_TLS_ENDPOINT_ENCRYPTION, DMS_ENDPOINT_SSL_CONFIGURED, DMS_REDIS_TLS_ENABLED, ELASTICACHE_REPL_GRP_ENCRYPTED_IN_TRANSIT, ELASTICSEARCH_NODE_TO_NODE_ENCRYPTION_CHECK, ELB_ACM_CERTIFICATE_REQUIRED, ELB_CUSTOM_SECURITY_POLICY_SSL_CHECK, ELB_PREDEFINED_SECURITY_POLICY_SSL_CHECK, ELB_TLS_HTTPS_LISTENERS_ONLY, MSK_IN_CLUSTER_NODE_REQUIRE_TLS, OPENSEARCH_HTTPS_REQUIRED, OPENSEARCH_NODE_TO_NODE_ENCRYPTION_CHECK, REDSHIFT_REQUIRE_TLS_SSL, S3_BUCKET_SSL_REQUESTS_ONLY
- **Encryption at rest / keys**: BACKUP_RECOVERY_POINT_ENCRYPTED, CMK_BACKING_KEY_ROTATION_ENABLED, DYNAMODB_TABLE_ENCRYPTED_KMS, DYNAMODB_TABLE_ENCRYPTION_ENABLED, EFS_ENCRYPTED_CHECK, KMS_CMK_NOT_SCHEDULED_FOR_DELETION, NEPTUNE_CLUSTER_ENCRYPTED, RDS_CLUSTER_ENCRYPTED_AT_REST, S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED, SAGEMAKER_ENDPOINT_CONFIGURATION_KMS_KEY_CONFIGURED, SAGEMAKER_NOTEBOOK_INSTANCE_KMS_KEY_CONFIGURED, SNS_ENCRYPTED_KMS
- **IAM / MFA / access**: IAM_POLICY_IN_USE, IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS, IAM_POLICY_NO_STATEMENTS_WITH_FULL_ACCESS, IAM_USER_MFA_ENABLED, MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS, ROOT_ACCOUNT_HARDWARE_MFA_ENABLED, ROOT_ACCOUNT_MFA_ENABLED, S3_BUCKET_MFA_DELETE_ENABLED, OPENSEARCH_ACCESS_CONTROL_ENABLED
- **Network / WAF / firewall**: API_GW_ASSOCIATED_WITH_WAF, FMS_WEBACL_RESOURCE_POLICY_CHECK, FMS_WEBACL_RULEGROUP_ASSOCIATION_CHECK, INCOMING_SSH_DISABLED, NETFW_MULTI_AZ_ENABLED, NETFW_POLICY_DEFAULT_ACTION_FRAGMENT_PACKETS, NETFW_POLICY_DEFAULT_ACTION_FULL_PACKETS, NETFW_POLICY_RULE_GROUP_ASSOCIATED, NETFW_STATELESS_RULE_GROUP_NOT_EMPTY, WAF_GLOBAL_RULEGROUP_NOT_EMPTY, WAFV2_RULEGROUP_LOGGING_ENABLED, WAFV2_WEBACL_NOT_EMPTY
- **Logging / monitoring / detection**: CLOUD_TRAIL_ENABLED, CLOUDTRAIL_SECURITY_TRAIL_ENABLED, MULTI_REGION_CLOUD_TRAIL_ENABLED, CLOUDWATCH_ALARM_ACTION_CHECK, CLOUDWATCH_ALARM_SETTINGS_CHECK, GUARDDUTY_ENABLED_CENTRALIZED, SECURITYHUB_ENABLED
- **Backup / lifecycle / hygiene**: BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK, S3_LIFECYCLE_POLICY_CHECK, S3_VERSION_LIFECYCLE_POLICY_CHECK, REQUIRED_TAGS
- **Container / vuln**: ECR_PRIVATE_IMAGE_SCANNING_ENABLED, ECS_CONTAINERS_NONPRIVILEGED, ECS_CONTAINERS_READONLY_ACCESS

Gaps in this list worth knowing [I]: no `S3_BUCKET_PUBLIC_*`, `RDS_INSTANCE_PUBLIC_ACCESS_CHECK`, `ENCRYPTED_VOLUMES`, `ACCESS_KEYS_ROTATED`, `IAM_PASSWORD_POLICY`, `VPC_FLOW_LOGS_ENABLED`, `RESTRICTED_INCOMING_TRAFFIC`, `CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED` - the list is mostly what AWS decided maps to "automated" SOC 2 controls, not a complete hygiene baseline. For baseline hygiene use the Well-Architected Security Pillar pack (~76+ rules: e.g. account-part-of-organizations, mfa-enabled-for-iam-console-access, iam-root-access-key-check, iam-password-policy, access-keys-rotated, s3-bucket-public-read/write-prohibited, rds-instance-public-access-check, ebs-snapshot-public-restorable-check, ec2-imdsv2-check, cloud-trail-cloud-watch-logs-enabled, elb-logging-enabled ...) https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-wa-Security-Pillar.html [S, page truncated at 100k chars; list not exhaustive]. Full templates: https://github.com/awslabs/aws-config-rules/tree/master/aws-config-conformance-packs

For ISO 27001:2013, AWS's Audit Manager Config-rule zip for ISO exists, but the URL I guessed returned 404 and the ISO doc page body did not render through the fetcher; not obtained [S/gap].

### 4.3 Security Hub controls most relevant to both frameworks [S: control IDs from CIS tables; relationship to SOC2/ISO is my inference [I]]
CIS AWS Foundations v5.0.0/v3.0.0 controls (https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html) - AWS recommends v5.0.0. Control IDs with CIS requirement numbers (v5.0.0):

| Area | Security Hub control (CIS v5.0.0 req) | SOC 2 | ISO 27001:2022 [I] |
|---|---|---|---|
| Identity | IAM.4 root key absent (1.3), IAM.9 root MFA (1.4), IAM.6 hardware root MFA (1.5), IAM.5 MFA for console users (1.9), IAM.15 password length >=14 (1.7), IAM.16 reuse (1.8), IAM.3 key rotation 90d (1.13), IAM.22 unused creds 45d (1.11), IAM.2 no user-attached policies (1.14), IAM.28 Access Analyzer (1.19), IAM.18 support role (1.16) | CC6.1-CC6.3 | 5.15-5.18, 8.2, 8.5 |
| Logging | CloudTrail.1 multi-region trail (3.1), CloudTrail.4 log validation (3.2), Config.1 Config on (3.3), CloudTrail.7 S3 access logging (3.4), CloudTrail.2 trail encryption (3.5), KMS.4 key rotation (3.6), EC2.6 VPC flow logs (3.7), S3.22/S3.23 object-level logging | CC7.1-CC7.3 | 8.15, 8.16, 8.17(ntp n/a) |
| Storage | S3.1/S3.8 block public access (2.1.4), S3.5 TLS only (2.1.1), S3.20 MFA delete (2.1.2), EC2.7 EBS default encryption (5.1.1), RDS.3 encryption (2.2.1), RDS.2 no public (2.2.3), RDS.5/15 multi-AZ (2.2.4), RDS.13 auto minor upgrade (2.2.2), EFS.1/EFS.8 encryption (2.3.1) | CC6.1, CC6.7, A1.2 | 8.24, 8.3, 8.14, 8.8 |
| Networking | EC2.2 default SG closed (5.5), EC2.21 NACL admin ports (5.2), EC2.53/54 SG admin ports (5.3/5.4), EC2.8 IMDSv2 (5.7) | CC6.6 | 8.20-8.22 |
| Other | Account.1 security contact (1.2), IAM.26 expired certs, IAM.27 CloudShellFullAccess | CC2.3, CC6.x | 5.5, 8.2 |
CIS v5.0.0 no longer covers CloudWatch metric-filter alarms or CloudTrail->CloudWatch Logs (marked manual / removed); v1.4/1.2 did. FSBP (the broader AWS standard, hundreds of controls) is documented at https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html (not fetched).

### 4.4 AWS Artifact [S/K]
- Provides AWS audit reports (SOC 1/2/3, ISO certificates), plus agreements (e.g. BAA, per account/org); AWS SOC 2 Security/Availability/Confidentiality report is "available to AWS customers from AWS Artifact"; SOC 3 public whitepaper https://d1.awsstatic.com/whitepapers/compliance/AWS_SOC3.pdf [S via Audit Manager SOC2 page]. ISO 27001:2022 cert covered by EY CertifyPoint [S]. Reports under NDA [K].
- Skill use [I]: ask the vault for evidence the org reviewed the AWS SOC 2 report + bridge letter annually (CC9.2, CC3.x, ISO 5.19/5.22/5.23) and mapped Complementary User Entity Controls (CUECs) to their own controls.

---------------------------------------------------------------------

## 5. Shared responsibility: inherited vs customer

AWS model [S: https://aws.amazon.com/compliance/shared-responsibility-model/]: AWS = security **of** the cloud (hardware, software, networking, facilities); customer = security **in** the cloud, depends on service (EC2: guest OS, patches, apps, SGs; S3/DynamoDB: data, encryption, classification, IAM). Control categories: **Inherited** (e.g. physical & environmental), **Shared** (patch management; awareness & training), **Customer-specific**.

Mapping to the frameworks (**[I]**, derived from the model + control semantics; confirm each against AWS's SOC 2 report CUEC section):

| Area | ISO Annex A | SOC 2 | Responsibility |
|---|---|---|---|
| Physical perimeters, entry, offices (data centers), monitoring, environmental threats, utilities, cabling, equipment siting/maintenance, secure disposal of hardware | 7.1, 7.2, 7.3, 7.4, 7.5, 7.8, 7.11, 7.12, 7.13, 7.14 (for AWS-hosted assets) | CC6.4, CC6.5, A1.2 (environmental) | **Inherited from AWS** for cloud assets. Customer evidence = AWS Artifact reports/ISO cert. **Customer still owns** 7.1-7.3, 7.6-7.7, 7.9 for its own offices/endpoints/remote work, 7.10 storage media for own devices |
| Virtualization/hypervisor, hardware capacity, redundancy of AZ infrastructure | 8.6 (infra), 8.14 (infra), 8.34 | A1.1, A1.2 | Inherited at infra layer; customer designs multi-AZ/region architecture and monitors own capacity (shared) |
| Patching, vuln mgmt, malware | 8.7, 8.8 | CC6.8, CC7.1 | Shared (AWS: infra/managed-service internals; customer: guest OS, containers, app deps, RDS minor versions per config) |
| Awareness & training, HR screening | 6.1-6.8 | CC1.4, CC1.5 | Shared (each trains own staff); customer-owned for its people |
| IAM, MFA, privileged access, key management policy, secure authentication | 5.15-5.18, 8.2, 8.3, 8.5, 8.24 | CC6.1-CC6.3 | **Customer** (AWS provides tools) |
| Logging/monitoring/incident response on workloads | 5.24-5.28, 8.15, 8.16 | CC7.1-CC7.5 | **Customer** (AWS does its own for its infra) |
| Network configuration (SGs, NACLs, WAF, VPC) | 8.20-8.23 | CC6.6, CC6.7 | **Customer** |
| Encryption config at rest/in transit, backups, data deletion | 8.24, 8.13, 8.10, 5.33 | CC6.1, CC6.7, A1.2, C1.2 | Customer configures; AWS supplies mechanisms |
| Change management, SDLC, secure coding, source code | 8.25-8.32, 8.4 | CC8.1 | **Customer** |
| ISMS governance (clauses 4-10), risk assessment, SoA, supplier management, legal/regulatory, policies, BC planning | clauses 4-10, 5.1-5.8, 5.19-5.23, 5.29-5.37 | CC1-CC5, CC9 | **Customer** (cannot be inherited; AWS's cert doesn't cover your ISMS) |

Critical certification point [I/K]: an ISO 27001 certificate or SOC 2 report for AWS does not make a customer certified; it is evidence for the supplier-management and inherited-control portions (5.19-5.23, 7.x, CC9.2, CC6.4).

---------------------------------------------------------------------

## 6. Open-source scanners (optional live verification)

### 6.1 Prowler (best fit) [S]
- Repo: https://github.com/prowler-cloud/prowler (Apache-2.0, ~15k stars, pushed 2026-11-12 => very active).
- Commands (docs: https://docs.prowler.com/developer-guide/security-compliance-framework , hub: https://hub.prowler.com/compliance/soc2_aws and https://hub.prowler.com/compliance/iso27001_2022_aws):
  - `prowler aws --list-compliance`
  - `prowler aws --compliance soc2_aws iso27001_2022_aws` (framework key = JSON basename; the brief's syntax is right. A third-party guide shows `--compliance soc2`, but hub/docs use `soc2_aws`. Multiple frameworks in one run are supported per Prowler docs/convention [K for exact multi-arg syntax; verify with `prowler aws -h`])
  - `prowler aws --compliance soc2_aws --list-checks`
  - `prowler aws --compliance soc2_aws --list-compliance-requirements soc2_aws` (as documented)
  - Also `iso27001_2013_aws` exists. Output: CLI table, CSV in `output/compliance/`, OCSF, JSON; read-only AWS creds (SecurityAudit + ViewOnly policies per Prowler docs [K]).
- Framework JSON files (fetched from master, 2026-11-12): `prowler/compliance/aws/soc2_aws.json`, `iso27001_2022_aws.json` (legacy provider-specific schema with `Requirements[].Id/Name/Attributes/Checks`).
  - **soc2_aws**: 27 requirements, 171 unique checks. Covers: CC1.3, CC2.1, CC3.1-3.4, CC4.2, CC5.2, CC6.1, CC6.2, CC6.3, CC6.6 (48 checks), CC6.7, CC6.8, CC7.1-7.5, CC8.1, A1.2 (labelled "cc_a_1_1", 37 checks), C1.1, C1.2, PI1.2-PI1.5. **Absent**: CC1.1, CC1.2, CC1.4, CC1.5, CC2.2, CC2.3, CC4.1, CC5.1, CC5.3, CC6.4 (physical), CC6.5, CC9.1, CC9.2, A1.1, A1.3, PI1.1, all P (privacy). I.e. only technically measurable criteria. (Hub pages' header counts of 134/171/251 checks are inconsistent; 171 unique is from the JSON.)
  - **iso27001_2022_aws**: 92 requirements (**A.8.28 Secure coding is missing**), 333 unique checks; **55 of 92 requirements have zero checks** (all of 6.x people, all of 7.x physical, most of 5.x governance, plus 8.6, 8.8 vulnerability mgmt, 8.17, 8.18, 8.19, 8.25, 8.26, 8.29-8.34). Heavy requirements: A.8.20/8.21/8.22 (~82 each), A.8.15 logging (72), A.8.24 crypto (65), A.8.11 data masking (41), A.8.1 endpoint (32), A.5.15 access control (18). Mapping is "check-shaped" (e.g. 8.11 masking mapped to 41 encryption checks) - treat as indicative, not as a faithful control assessment [I].
  - Prowler marks ISO/SOC 2 "manual" requirements (no checks) so a skill can still list them as "needs vault evidence".
- Role for the skill [I]: **best optional live-verification engine** - run per framework, ingest the JSON/CSV/OCSF, and for each Annex A / TSC id compare "vault says implemented" vs "Prowler FAIL/PASS". Prowler also has a vulnerability-less posture view (no agent); requires AWS read creds so must stay opt-in.

### 6.2 Steampipe + Powerpipe `aws_compliance` mod [S]
- https://github.com/turbot/steampipe-mod-aws-compliance (Apache-2.0). Needs Steampipe + AWS plugin + Powerpipe. Benchmarks in repo (dir listing): `soc_2` (children: cc_1, cc_2, cc_3, cc_4, cc_6, cc_7, cc_8, a_1, c_1 - no CC5, CC9, PI, P), `foundational_security`, CIS v1.2.0-v6.0.0 (cis_v120 ... cis_v600), NIST 800-53 r4/r5, NIST CSF v1/v2, NIST 800-171, PCI v3.2.1/v4.0, HIPAA, FedRAMP low/moderate r4, GDPR, FFIEC, GxP, ACSC E8, CISA CE, RBI, NYDFS, `audit_manager_control_tower`. **No ISO 27001 benchmark.**
- Run: `powerpipe benchmark list`; `powerpipe benchmark run aws_compliance.benchmark.soc_2` (pattern shown in README for `cis_v400`); `steampipe service start`; `powerpipe server` -> localhost:9033. Output formats incl. json/csv/html/snapshot.
- The SOC 2 benchmark description states it is built on Audit Manager's SOC 2 framework mapping, so it is essentially the 65-rule list of 4.2 expressed as SQL [S/I]. Licence note: Powerpipe/Steampipe binaries are under Turbot's commercial terms; mod is Apache-2.0.
- Role [I]: good alternative if the team already runs Steampipe; SOC 2 only; per-account SQL means custom queries against the live account (e.g. "which IAM users lack MFA") are easy.

### 6.3 ScoutSuite [S]
- https://github.com/nccgroup/ScoutSuite (GPL-2.0, ~7.9k stars, last push 2025-09-23). Multi-cloud; AWS/Azure/GCP supported; HTML report of config + findings; **no compliance-framework mapping** mentioned. Role [I]: weak fit for SOC 2/ISO mapping; use only for ad-hoc discovery of misconfigurations; lower activity than Prowler.

### 6.4 Checkov (IaC) [S]
- https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html ; repo https://github.com/bridgecrewio/checkov (Apache-2.0, active). Static scan of Terraform (`--framework terraform`/`terraform_plan`), CloudFormation, Kubernetes, Helm, Dockerfile, CI configs (GitHub Actions, Bitbucket Pipelines), secrets, SCA. `checkov -d <dir> -o json|sarif|junitxml|cli`. **No SOC 2 / ISO 27001 mapping flag.** Role [I]: shift-left evidence for 8.9 config mgmt, 8.25/8.28 SDLC, CC8.1; relevant if the vault points at a Terraform/CDK repo. Maps to compliance only indirectly via check IDs you map yourself (Prowler has no IaC equivalent).

### 6.5 Recommendation [I]
1. Core skill = document-based assessment against the 93 controls / 61 TSC criteria from the vault (works offline, no creds).
2. Optional live verification = Prowler (`soc2_aws`, `iso27001_2022_aws`) because it is the only open tool with both frameworks. Use its per-requirement PASS/FAIL/MANUAL as a cross-check signal for "implemented" claims.
3. Optional: Checkov for IaC repos; Steampipe only if already deployed.
4. Do not rely on Audit Manager (closed to new customers, ISO 2013) or on non-existent Config packs.

---------------------------------------------------------------------

## 7. Obsidian integration options for a Claude skill

### 7.1 Options [S for facts cited; pros/cons mostly [I]]
| Option | How | Pros | Cons |
|---|---|---|---|
| **A. Direct filesystem read** (Read/Grep/Glob on vault folder; parse YAML frontmatter + wikilinks) | No Obsidian needed running | Zero dependencies; works headless/CI; fastest for bulk scans (can Glob all notes, grep `status:`); deterministic; works offline in Claude Code skills; permission model = normal file permissions | No Obsidian-aware resolution (aliases, `[[link]]` -> path resolution, embeds, tags in body) unless the skill implements it; Dataview queries not executable (must emulate); read-only discipline needed to avoid corrupting notes; sync-conflicts if vault on cloud sync |
| **B. Obsidian Local REST API plugin** (coddingtonbear) | HTTPS 127.0.0.1:27124 (HTTP 27123 optional), bearer API key; `/vault/{path}` CRUD, `/search/simple/`, `/search/` (JsonLogic over frontmatter/tags/path/content), `/tags/`, `/commands/`, PATCH by heading/block/frontmatter field, ETag conditional writes, SSE event streams; **now has built-in MCP server at `/mcp/`** (Streamable HTTP, bearer auth) | Structured frontmatter/tag queries; safe targeted edits (patch a heading or frontmatter key); built-in MCP => no extra bridge; auth + signed URLs | Requires Obsidian desktop **running** with plugin enabled; self-signed cert trust or use HTTP; `.obsidian` config blocked by default; 10 failed auths/min throttle; deprecated header-PATCH format removed in v6.0; DQL/Dataview not listed in the page [S]; extra setup friction for each teammate |
| **C. MCP server wrapper `MarkusPfundstein/mcp-obsidian`** | Python 3.11+, wraps Local REST API; 7 tools: list_files_in_vault, list_files_in_dir, get_file_contents, search, patch_content, append_content, delete_file; needs API key env | Standard MCP tool surface for Claude Desktop/Code; popular (~4.5k stars, MIT) | Same Obsidian-running dependency; extra process; `mcp` SDK must be pinned <2.0 (breaks otherwise); tools are file-level (no backlink/graph tool); delete_file is risky in autonomous mode; maintenance cadence unclear (last push 2026-08-31). Alternatives: obsidian-mcp-tools plugin, cyanheads/obsidian-mcp-server, fazer-ai TS server [S via directory listings, unverified] |
| **D. Obsidian official CLI** (Obsidian 1.12+, Feb 2026) | `obsidian` command talking via IPC to running app; enable in Settings > General > Command line interface; works from Claude Code via Bash; Base/frontmatter queries | Obsidian-aware ops (properties, Bases, search) with fewer tool calls; no plugin | App must be running; early-access/licensing statements conflict across sources; syntax may change; multi-vault targeting reported flaky; not usable from Claude Desktop (no shell) [S via https://dev.to/shimo4228/obsidians-official-cli-is-here-no-more-hacking-your-vault-from-the-back-door-3123 and other blogs, weak] |
| **E. Dataview** (plugin) conventions | Frontmatter + inline fields `key:: value`; DQL `TABLE ... FROM #tag WHERE ...` | Humans get live dashboards in-vault; fields double as machine-readable metadata | Dataview is a *render-time* feature inside Obsidian; Claude cannot execute DQL via filesystem; Local REST API page does not list a DQL endpoint [S] (older versions/community forks did, [K]); inline fields are non-standard markdown |

### 7.2 Recommendation for the skill [I]
- **Primary: filesystem read (A)**; it is the only mode that works for every dev, in co-work/headless runs, and in CI. Optionally detect Obsidian CLI/REST only to improve search.
- Treat Obsidian-specific syntax as a parsing contract the skill documents: YAML frontmatter (`type`, `status`, `controls: [A.8.15, CC7.2]`, `owner`, `last_reviewed`, `evidence:`), `[[wikilinks]]` for typed edges, tags `#control/implemented` etc. Keep Dataview inline-field use minimal, mirror anything important in frontmatter, since frontmatter is parsed by every option.
- Existing user skills `creating-typed-knowledge-vaults` / `updating-typed-knowledge-vaults` define typed vault conventions; the evaluator should key off those types/edges rather than invent new ones [I, based on skill list in this environment].
- Safety: read-only by default; if REST/MCP is used, avoid delete_file/patch and never expose the API key (env var only, per company rules).

---------------------------------------------------------------------

## 8. Source index
- ISO Annex A list: https://www.isms.online/iso-27001/annex-a-controls/
- Mandatory docs: https://advisera.com/27001academy/knowledgebase/list-of-mandatory-documents-required-by-iso-27001-revision/ ; https://www.tcsa.in/frameworks/iso-27001/requirements
- ISO transition: https://www.dqsglobal.com/en/explore/blog/hk/transition-requirements-for-iso-27001-2022 ; https://www.brightdefense.com/news/iso-270012022-deadline-puts-legacy-certificates-at-risk/
- Amd 1:2024: https://hightable.io/iso27001-2022-amendment-1-climate-action-changes-executive-briefing/ ; https://services.bis.gov.in/tmp/LITD23425400_06092024_1.pdf
- AICPA TSC 2022 POF: https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022 ; summary https://drata.com/learn/soc-2/trust-services-criteria-revised-points
- AICPA ISO mapping: https://www.aicpa-cima.com/resources/download/mapping-2017-trust-services-criteria-to-iso-27001
- CISO Assistant libraries: https://github.com/intuitem/ciso-assistant-community/tree/main/backend/library/libraries
- AWS Config conformance packs: https://docs.aws.amazon.com/config/latest/developerguide/conformancepack-sample-templates.html ; repo https://github.com/awslabs/aws-config-rules/tree/master/aws-config-conformance-packs
- Audit Manager: https://docs.aws.amazon.com/audit-manager/latest/userguide/SOC2.html ; availability change https://docs.aws.amazon.com/audit-manager/latest/userguide/audit-manager-availability-change.html
- Control Tower frameworks: https://docs.aws.amazon.com/controltower/latest/controlreference/frameworks-supported.html
- Security Hub: https://docs.aws.amazon.com/securityhub/latest/userguide/standards-reference.html ; https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html
- AWS shared responsibility: https://aws.amazon.com/compliance/shared-responsibility-model/ ; Artifact https://aws.amazon.com/artifact/ ; ISO FAQ https://aws.amazon.com/compliance/iso-27001-faqs/
- Prowler: https://hub.prowler.com/compliance/soc2_aws ; https://hub.prowler.com/compliance/iso27001_2022_aws ; https://docs.prowler.com/developer-guide/security-compliance-framework ; JSON https://github.com/prowler-cloud/prowler/tree/master/prowler/compliance/aws
- Steampipe: https://github.com/turbot/steampipe-mod-aws-compliance
- ScoutSuite: https://github.com/nccgroup/ScoutSuite ; Checkov: https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html
- Obsidian: https://github.com/coddingtonbear/obsidian-local-rest-api ; https://github.com/MarkusPfundstein/mcp-obsidian ; Obsidian CLI overview https://dev.to/shimo4228/obsidians-official-cli-is-here-no-more-hacking-your-vault-from-the-back-door-3123

## 9. Open gaps / things not verified
- AICPA SOC2<->ISO spreadsheet contents (member-gated); AICPA TSC PDF not downloaded (used open library).
- Audit Manager ISO 27001 framework page and its Config-rule list (not retrieved).
- IAF MD 26 and ISO Amd 1 primary text not opened; Type I/II definitions and clause sub-numbering are from background knowledge.
- Whether Prowler accepts `--compliance a b` multi-framework syntax in the current version (run `prowler aws -h`).
- FSBP control-to-SOC2/ISO relation (none official); all Security Hub -> SOC2/ISO relations in 4.3 are inference.
