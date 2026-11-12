# Reference AWS infrastructures for SOC 2 / ISO 27001 vs. our check catalog

Research date: 2026-11-12. Method: web search plus page fetches (AWS docs, Drata and Vanta help centers, Cloud Posse docs, practitioner posts).
Compared against: `docs/specs/2026-11-12-infra-compliance-audit-design.md` section 7.2.

Legend: **[S]** = sourced (the page says it, URL given). **[I]** = inferred by me (not stated by any source). **[V]** = vendor/blog content of low reliability.

---

## 0. Executive summary

1. Our catalog (about 70 checks) already covers the core that nearly every source agrees on. The gaps are in four places: (a) GuardDuty details that Drata Test 105 actually checks, (b) CloudTrail protection and integration (CloudWatch Logs, bucket hardening), (c) account-governance items in AWS's own baseline (alternate contacts, Budgets, region restriction, default VPC, Identity Center instead of IAM users, secrets), and (d) integration-permission gotchas (backup permission, region SCP, exact role name).
2. **No official SOC 2 or ISO 27001 AWS Config conformance pack exists.** The AWS sample list has none [S]. Some vendor blogs claim there is one; treat that as wrong [V]. This confirms spec section 14.
3. **Multi-account is not required by any source for SOC 2.** AWS's own Startup Security Baseline is explicitly designed for single-account setups [S]. Multi-account (log archive plus security account) is recommended by AWS SRA and by vendors mainly to shrink audit scope and prevent log tampering. Treat it as informational in the skill, never as a failing check.
4. SES and other SaaS features: neither Drata nor Vanta publishes any SES test [S, from the full Drata test list]. SES checks are our own value-add. Auditor evidence for email is DNS-level (SPF, DKIM, DMARC), and the sources are vendor blogs [V].

---

## 1. AWS official sources

| Source | URL | Date | Key content |
|---|---|---|---|
| AWS Startup Security Baseline (SSB) | https://docs.aws.amazon.com/prescriptive-guidance/latest/aws-startup-security-baseline/welcome.html (PDF fetched; copyright 2026; first published May 2022 per https://aws.amazon.com/blogs/startups/aws-startup-security-baseline-day-one-recommendations-to-secure-your-account-and-workload) | 2026 revision | 17 account controls (ACCT.01-17) and 15 workload controls (WKLD.01-15). **Designed for single-account.** [S] |
| AWS Security Reference Architecture (SRA) checklist | https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/checklist.html | current | MUST/SHOULD list per service. Enterprise, multi-account oriented. Also mentions the SRA Verify tool: https://github.com/awslabs/sra-verify [S] |
| Landing Zone Accelerator Universal Configuration + Compliance Workbook | https://aws.amazon.com/blogs/security/introducing-the-landing-zone-accelerator-on-aws-universal-configuration-and-lza-compliance-workbook | 2025-11-20, updated 2026-04-04 | Multi-account baseline. Workbook maps to NIST 800-53 r5, **SOC 2**, **ISO 27001 Annex A**, HIPAA, C5, CIS v8 and others. Workbook is delivered through AWS Artifact [S] |
| AWS Config conformance pack sample list | https://docs.aws.amazon.com/config/latest/developerguide/conformancepack-sample-templates.html | fetched 2026-11-12 | About 90 packs (CIS v1.4 L1/L2, CIS v8 IG1-3, NIST, FedRAMP, PCI, HIPAA, Well-Architected Security and Reliability pillars, Logging, Monitoring, Encryption, Data Resiliency, etc.). **No SOC 2, no ISO 27001, no AICPA pack.** AWS states the packs do not ensure compliance [S] |
| Audit Manager SOC 2 framework | https://docs.aws.amazon.com/audit-manager/latest/userguide/SOC2.html | fetched 2026-11-12 | 15 automated plus 46 manual controls, 20 control sets. Needs all Security Hub standards and Config rules on. **Audit Manager is no longer open to new customers** [S]. Do not recommend it. |
| ISO/IEC 27001:2022 on AWS Compliance Guide | https://aws.amazon.com/blogs/security/new-compliance-guide-available-iso-iec-270012022-on-aws-compliance-guide (PDF: https://d1.awsstatic.com/onedam/marketing-channels/website/aws/en_US/whitepapers/compliance/ISO27001-2022_on_AWS_Compliance_Guide.pdf) | 2026-03-31 | Annex A to AWS service mapping (see section 6 below) [S] |
| AWS Marketplace partner offers | https://aws.amazon.com/marketplace/pp/prodview-djtzaafyl4rwe (Gruntwork LZA, USD 46k/yr) | n/a | Only marketing mention of SOC 2 support; no technical detail [S/V] |

### 1.1 SSB control list (all IDs) [S]

Account: ACCT.01 alternate contacts to distribution lists; .02 restrict root; .03 console access per user; .04 assign permissions; .05 MFA; .06 password policy; .07 CloudTrail to protected S3 bucket (multi-region, Read+Write, `aws:SourceArn` in bucket policy, MFA delete suggested); .08 S3 public access blocked; .09 delete unused VPCs, subnets, SGs (default VPCs in every region); .10 AWS Budgets; .11 IAM Access Analyzer per region; .12 Trusted Advisor high-risk items; .13 short-lived credentials (Identity Center or IdP); .14 GuardDuty in **all supported regions**; .15 Security Hub (FSBP) with Config enabled; .16 Cost Anomaly Detection; .17 restrict API calls to used regions (`aws:RequestedRegion` deny policy or SCP).

Workload: WKLD.01 IAM roles for compute; .02 resource-based policies; .03 Secrets Manager or SSM Parameter Store; .04 prevent secrets exposure; .05 detect exposed secrets; .06 Systems Manager instead of SSH/RDP; .07 S3 data events for sensitive buckets; .08 EBS encryption; .09 RDS encryption; .10 private resources in private subnets; .11 SG-based network restriction; .12 VPC endpoints; .13 HTTPS for public endpoints with modern TLS policy; .14 edge protection (CloudFront, ALB, WAF); .15 security controls in IaC and CI/CD.

### 1.2 SRA checklist items relevant to a SOC 2 startup [S]

CloudTrail: multi-region, global events, log file validation, **CloudWatch Logs integration**, **CMK on trail and on log bucket**, S3 Object Lock (SHOULD), versioning (SHOULD), bucket policy restricting uploads to the trail ARN.
Security Hub: FSBP **and** CIS standards enabled, Config as prerequisite, cross-region aggregation.
Config: recorder on in all regions, all resource types, aggregator.
GuardDuty: all regions; foundational sources; S3 protection, EBS malware, RDS, Lambda, EKS, runtime monitoring (SHOULD); findings export to S3 encrypted with CMK.
IAM: **IAM users MUST NOT be used** (Identity Center with MFA instead), root credentials removed in member accounts, Access Analyzer external and unused-access analyzers.
KMS: CMKs for sensitive data, **automatic rotation MUST**, key admin separated from key use, `kms:ViaService` conditions.
Secrets Manager: automatic rotation, CMK, CloudTrail monitoring.
WAF: on CloudFront, API Gateway and ALB; **WAF logging MUST be on**.
Inspector: EC2, ECR, Lambda scanning. Macie, Detective, Shield Advanced, Firewall Manager, Network Firewall, Security Lake, Private CA: mostly SHOULD and enterprise-scale.
Systems Manager: SSM agent on all instances, Session Manager instead of SSH, Patch Manager.

---

## 2. Open-source IaC and reference implementations

| Project | URL | What it deploys | Notes |
|---|---|---|---|
| Cloud Posse `vanta` component (docs) | https://docs.cloudposse.com/components/library/aws/vanta/ | IAM role `vanta-auditor` per account: trust with ExternalId, managed `SecurityAudit`, custom `VantaAdditionalPermissions` (always) and `VantaManagementAccountPermissions` (management account only). Defaults: `account_verification_enabled=true`, `management_account_permissions_enabled=false` | [S]. Repo location (`cloudposse-terraform-components/aws-vanta`) was not confirmed. |
| Cloud Posse security and compliance layer | https://docs.cloudposse.com/layers/security-and-compliance/ | 9 components: Config (+ org conformance packs for CMMC L2, CIS, custom), CloudTrail org trail (validation, CloudWatch Logs integration, lifecycle on bucket), GuardDuty, Security Hub (CIS, PCI, FSBP, cross-region aggregation), Macie, Inspector2, Access Analyzer, Shield, Audit Manager. Accounts: `security` and `audit`. Lists SOC2, HIPAA, PCI, CIS as targets | [S]. Retention days **not stated** on the page. No SOC 2-specific mapping. |
| Gruntwork CIS landing zone | https://docs.gruntwork.io/guides/build-it-yourself/achieve-compliance/production-grade-design/logging | CloudTrail (`is_multi_region_trail`, `include_global_service_events`, `enable_log_file_validation`, S3 data events, CloudWatch Logs, KMS), Config in every region (one module call per region), S3 account BPA, KMS `enable_key_rotation`, flow logs on every VPC, `cloud-nuke defaults-aws` for default VPC/SG | [S]. CIS-oriented, not SOC 2. No retention numbers. Closed modules (paid). |
| nozaq `terraform-aws-secure-baseline` | https://github.com/nozaq/terraform-aws-secure-baseline | Submodules: analyzer, cloudtrail, config, ebs, guardduty, iam, s3, securityhub, vpc baselines (CIS and FSBP) | [S] from search result only; I did not read the repo, so retention values unknown. |
| Trussworks `terraform-aws-config` | https://github.com/trussworks/terraform-aws-config | Config recorder plus managed rules | [S] summary only. |
| SquareOps `terraform-aws-security-automations` | via https://awesome.ecosyste.ms/projects/github.com%2Fsquareops%2Fterraform-aws-security-automations | CIS L1, CIS L2, SOC 2 check directories | [S] listing only; very low adoption; I could not open the repo. |
| Coalfire `terraform-aws-organization` | https://github.com/Coalfire-CF/terraform-aws-organization | GuardDuty, Security Hub, Config, CloudTrail at org level | FedRAMP target, not SOC 2. |
| Vanta "Remediating cloud tests with Terraform" | https://help.vanta.com/en/articles/11345520-remediating-cloud-tests-with-terraform | Vanta generates Terraform per failing cloud test (AWS, Azure, GCP, others) via Vanta AI | [S]. This is remediation per test, not a published module. |
| Vanta "engineering at Vanta" (2022-06) | https://www.vanta.com/resources/engineering-at-vanta-how-we-imported-our-aws-environment-into-terraform | Their own AWS is in Terraform with driftctl drift alerts to Slack | [S]. Nothing on SOC 2 settings. |

Not found: a maintained open-source repo literally named `terraform-aws-soc2`, an official `aws-vanta` retention spec, a StrongDM "comply" AWS module, or any Drata-published Terraform for the DrataAutopilot role beyond the one referenced in Drata's connection docs (bulk-creates roles) [S, see section 3.4].

**Convergence across IaC projects [S/I]:** every project deploys CloudTrail (multi-region, validation, KMS, CW Logs), Config (all regions), GuardDuty, Security Hub (CIS and/or FSBP), Access Analyzer, KMS rotation, flow logs, S3 BPA. Macie, Inspector, Shield, Audit Manager appear only in the enterprise-style (Cloud Posse) stack.

---

## 3. What Drata and Vanta actually test on AWS (primary vendor docs)

This is the most reliable evidence for "what turns tests green".

### 3.1 Drata (help.drata.com)

Index: https://help.drata.com/en/collections/2711965-tests. AWS tests released 2024-10-30: https://help.drata.com/en/articles/10034590-october-2024-release-aws-drata-test. **New tests have status "New" and do not run until enabled** [S].

Test numbers and names (all [S]): 105 threat detection (GuardDuty); 205 CloudTrail log validation; 214 root MFA; 215 password min length; 216 password reuse; 217 group-based access; 218 EBS encryption; 219 RDS auto minor upgrade; 220 RDS public access; 221 S3 access logging; 222 CloudTrail logs encrypted (CMK); 223 CMK rotation; 224 VPC flow logs; 225 hardware root MFA; 226 S3 object-level logging; 227 NACL admin ports; 228 SG RDP; 229 unused credentials; 230 least privilege; 231 EFS encrypted; 232 key rotation; 233 default SG restricts all; 234 S3 HTTP denied; 290 DB write IO; 291 SG HTTP; 292 IMDSv1 disabled; 293-298 Classic LB and ALB latency, errors, unhealthy hosts, response time; 299 ALB redirects HTTP to HTTPS; 300 Lambda error rate; 301 DynamoDB PITR; 310 EKS audit logs; 132-134 backup job monitoring.
Provider-agnostic infra tests that hit AWS: 4, 30 (AZs), 68, 69, 88, 95, 98, 102, 104, 106-108, 109, 110, 111, 112-118, 119, 122, 123, 124, 129, 130, 131, 206, 208, 209, 210 [S, titles only for many].

Details confirmed by reading the articles:
- **Test 105** (https://help.drata.com/en/articles/4778757-test-105-threat-detection-in-place): passes automatically if the account has no S3 buckets. Otherwise requires GuardDuty active **in every region where resources exist**, **S3 Protection enabled**, and the how-to also tells you to create an **EventBridge rule for GuardDuty findings with a target (e.g. SNS)** [S]. Failure causes listed: some regions only, detector not retrievable (region or permissions), S3 protection off.
- **Test 111** (https://help.drata.com/en/articles/4778770-test-111-logs-are-retained-for-365-days): logs retained at least 12 months or archived long term. The article does not say which AWS resource is evaluated [S].
- **Test 222**: CloudTrail logs encrypted with KMS **customer-created** keys; the page does not say whether AWS-managed keys pass; each trail evaluated; CMK must be in the same region as the bucket [S].
- **Test 224**: flow logging on in all VPCs; "Reject" filter recommended but not stated as required [S].
- **Tests 132/133/134/301** need the inline permission `backup:ListRecoveryPointsByResource` on `DrataAutopilotRole`; 132 checks for a successful snapshot from the previous day [S] (https://help.drata.com/en/articles/9999495-test-132-daily-backup-job-status-monitored).
- **Test 107**: daily backups per database; Redis never passes and must be excluded [S snippet].
- **Test 30**: multi-AZ; S3 is not checked [S snippet].
- **Test 122**: WAF; fails if no Web ACLs or no rulesets [S snippet].
- **Tests 293-300**: CloudWatch alarm **with SNS topic subscription** per resource; thresholds are yours [S] (https://help.drata.com/en/articles/9828822-test-298-aws-application-load-balancer-unhealthy-hosts-monitored).
- **Test 121** (logs monitored for suspicious activity) is **Datadog-only** [S]; it does not apply to a pure AWS setup, so disable it rather than fix it.
- **Test 109** (logs centrally stored) lists Datadog; AWS applicability not confirmed [S].

### 3.2 Drata permission surface

https://help.drata.com/en/articles/8852274-aws-resource-permissions. Default `SecurityAudit` covers: API Gateway, AppSync, CloudFront, CloudTrail (root events), CloudWatch alarms, DynamoDB, EC2 (SGs, instances), ECS, ElastiCache, ELB classic and v2, Elasticsearch, GuardDuty, IAM users, RDS, S3, SQS. Custom connections add Lambda, Backup, KMS, Config, Secrets Manager, Auto Scaling, Route 53, Trusted Advisor, EKS-adjacent items and more [S].
Gotchas [S] (https://help.drata.com/en/articles/5048935-aws-connection-details): role must be named exactly `DrataAutopilotRole`; SCP region restrictions cause test errors unless the connection scope is set to the allowed regions; Identity Center is read only through SCIM; sub-account resources are skipped if the sub-account toggle was off at connection time; tests show "Unused" if the mapped control or AWS connection is missing.

### 3.3 Vanta

- Role: https://help.vanta.com/en/articles/11345630-connecting-vanta-aws-account : role with `SecurityAudit` **plus** customer-managed (not inline) policy `VantaAdditionalPermissions`; products scanned include IAM Identity Center and Inspector; enabling a new product later requires updating the policy; cannot mix account-level and org-level connections [S].
- 36 AWS CIS tests (https://help.vanta.com/en/articles/11345518-cis-foundation-benchmarks-available-in-vanta): IAM (root keys, root MFA, password length and reuse, console MFA, unused credentials, key count and rotation, group-only permissions, no full-admin policies, support role, instance roles, expired certificates, Access Analyzer), S3 (HTTP denied, BPA, CloudTrail bucket access logging, object-level logging), encryption (EBS, RDS, EFS, CloudTrail KMS, CMK rotation), RDS (auto minor upgrade, no public), logging (CloudTrail all regions, validation, Config, flow logs, Security Hub), network (NACL and SG admin ports IPv4 and IPv6, default SG), IMDSv2. Appear automatically with SOC 2, ISO 27001 or CIS v8; need Professional or Enterprise plan [S].
- **AWS Config test** (https://help.vanta.com/en/articles/11345517-resolve-aws-config-is-enabled-correctly-in-all-regions-internal): per region, recording strategy "all resource types with customizable overrides"; IAM Policy, User, Role, Group set to **daily** recording; S3 delivery bucket; **SNS topic attached** [S]. Already in our catalog.
- Customizable defaults (https://help.vanta.com/en/articles/11345527-customizing-automated-tests): AWS Server Logs retention (unlimited allowed, default not stated), EC2 and **ECS task** ports restricted, key rotation frequency, unused accounts default **90 days**, root unused default **30 days** [S].
- CloudWatch alarm tests (https://help.vanta.com/hc/en-us/articles/12264595240724-Create-AWS-Cloud-Watch-Alarms-to-pass-Vanta-Tests): alarm per flagged resource, same account and region, dimension must match the resource; SNS is **not** mentioned for Vanta [S]. Our catalog demands confirmed SNS, which is stricter than Vanta and matches Drata (acceptable).
- Inventory tests: `VantaOwner` tag read automatically; value must be the email of an **active** Vanta user; connecting user becomes default owner and may be a former employee later (https://developer.vanta.com/docs/guides/add-owners-to-resources and https://help.vanta.com/en/articles/11345884-error-inventory-is-auto-assigning-to-a-former-person) [S].

### 3.4 Gotcha list from vendor docs [S]

1. GuardDuty must be on in every region that has resources, with S3 protection, or Test 105 fails (Drata).
2. Config must be enabled per region, with the IAM daily override and SNS (Vanta).
3. SCP region restrictions break scans unless regions are scoped (Drata).
4. Backup tests error with AccessDenied until the inline backup permission is added (Drata).
5. CMK rotation test needs extra permissions (Drata 223).
6. New Drata AWS tests do not run until enabled.
7. Owner tag must be an active user email (Vanta); default owner can be a leaver.
8. Vanta reviewers report noise from tests outside the SOC 2 scope; filter by framework (AWS Marketplace reviews, https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-5ophamrbfxt44?page=18) [V].

---

## 4. Engineering write-ups ("how we got SOC 2 on AWS")

Honest finding: I found **no first-person engineering blog from a named company** with a concrete list of AWS changes. Results were vendor or anonymous guides. Use them as corroboration only.

| Post | URL | Date | Concrete content | Reliability |
|---|---|---|---|---|
| "I turned 23 Vanta red tests green in 14 days" | https://dev.to/aayostem/i-turned-23-vanta-red-tests-green-in-14-days-here-is-the-exact-command-for-each-one-ihp | undated | IAM key rotation 90d, MFA, IRSA, Cilium policy (EKS), KMS for EKS secrets, RDS re-encrypt via snapshot copy, S3 SSE-KMS, GuardDuty (15-min publishing) plus EKS runtime, flow logs. No retention or alarms. Internally inconsistent (22 vs 23 controls) | [V], low |
| "AWS misconfigurations on almost every SOC 2 audit" | https://dev.to/trailproof/the-aws-misconfigurations-that-show-up-on-almost-every-soc-2-audit-5ed8 | posted Jun 5 (year not shown) | MFA missing, CloudTrail not multi-region or no validation, S3 no default encryption, GuardDuty only in some regions, SGs open to 0.0.0.0/0 on 22/3306/5432/27017 | [V] |
| "AWS SOC 2 Compliance: What Auditors Actually Look For" | https://towardsthecloud.com/blog/aws-soc-2-compliance | 2026-01-25, upd. 2026-05-18 | CloudTrail 1-year minimum retention, 90-day key rotation, Object Lock and MFA delete on log bucket, CMK rotation, TLS 1.2+, Inspector, WAF, flow logs; five common failures: root misuse and key sprawl, CloudTrail gaps, unencrypted data and weak keys, open SGs, no IR plan / GuardDuty off. Claims an "Operational Best Practices for SOC 2" Config pack exists, which is **wrong** per AWS's own list | [V], low on that claim |
| "Why your startup needs an AWS landing zone before SOC 2" | https://towardsthecloud.com/blog/aws-landing-zone-soc-2 | 2026-04-02, upd. 2026-11-09 | Recommends 5 accounts (management, log archive, audit/security, prod, dev); single account puts dev and test in audit scope and "typically produces about 12 predictable findings across CC6, CC7, CC8". Does not say a single account is prohibited | [V], sells the service |
| "SOC 2 on AWS: Config and Security Hub" (AWS Builder Center) | https://builder.aws.com/content/3Kp8N4Mc9K5Lr0Dw4AJLdcVatGm/soc-2-on-aws-automate-compliance-with-config-and-security-hub | 2026-10-19 | Example rules: `iam-policy-no-statements-with-admin-access`, `mfa-enabled-for-iam-console-access`, `s3-bucket-level-public-access-prohibited`, `restricted-ssh`, `rds-storage-encrypted`, `multi-region-cloudtrail-enabled`, `s3-bucket-logging-enabled`, `required-tags`. Says mappings are examples, not official | Community builder; moderate |
| freeCodeCamp SOC 2 Type II handbook | https://www.freecodecamp.org/news/the-complete-soc-2-type-ii-implementation-guide-for-engineers/ | 2026-05-05 | CloudTrail needs explicit `start-logging`; GuardDuty HIGH/CRITICAL to EventBridge; flow logs ALL; EBS default encryption; account-level S3 BPA; Secrets Manager rotation 90d; Object Lock 365d on evidence bucket; quarterly access reviews and RDS restore tests. Several technical errors noted by the fetch (Object Lock at creation, `IsLogging` not checked) | [V], moderate |
| Agency "Vanta AWS integration" | https://blog.getagency.com/articles/vanta-aws-integration-complete-setup-guide | 2026-02-24, upd. 2026-11-01 | Table of tested services (IAM, S3, EC2, RDS, CloudTrail, CloudWatch, KMS, VPC, Config, GuardDuty); partial discovery when policy lacks permissions; unconnected prod account is an evidence gap; role drift breaks integration | [V] |

**Most common failing tests / surprises (convergent across sources):**
1. Root MFA and root access keys (all sources).
2. CloudTrail single-region, no validation, no CMK (all sources; Drata 205 and 222).
3. GuardDuty not in all regions or no S3 protection (Drata 105 and blogs).
4. S3 and EBS and RDS without encryption, especially buckets and volumes created before defaults (Agency, DEV posts).
5. Security groups open to the world on admin or DB ports (all).
6. IAM users without MFA, stale keys, unused credentials (Drata 229/232, Vanta).
7. Missing flow logs on default VPCs in unused regions [I, follows from "all VPCs" in Drata 224].
8. Config not enabled in every region, or missing the IAM daily override and SNS (Vanta).
9. CloudWatch alarms not created or without SNS subscription (Drata 293-300).
10. Owner tags pointing to an inactive user (Vanta).
11. [I] Public ALB with port 80 open conflicts with Drata Test 291 (HTTP restricted) while Test 299 wants an HTTP-to-HTTPS redirect. Expect a justified exclusion rather than a fix. Not documented by Drata; flagged as my inference.

---

## 5. Minimum viable SOC 2 AWS baseline: convergence

| Control | AWS SSB | SRA | Drata/Vanta test | Blogs | Verdict |
|---|---|---|---|---|---|
| Root MFA (hardware), no root keys, root unused | yes | yes | yes | yes | **Universal** |
| IAM MFA, password policy, key rotation, group-based perms | yes | yes (prefers no IAM users) | yes | yes | **Universal** |
| CloudTrail multi-region + validation + KMS | yes | yes | yes | yes | **Universal** |
| CloudTrail to CloudWatch Logs | no | yes | not tested | yes | Common (SRA and blogs, no vendor test) |
| CloudTrail bucket hardening (SourceArn, MFA delete, Object Lock, versioning) | partial | yes | no | yes | Common; Object Lock optional |
| S3 BPA, encryption, HTTPS-only | yes | yes | yes | yes | **Universal** |
| EBS, RDS, EFS encryption | yes | yes | yes | yes | **Universal** |
| KMS CMK rotation | n/a | yes | yes | yes | **Universal** |
| GuardDuty all regions (+S3) | yes | yes | yes | yes | **Universal** |
| Security Hub (FSBP/CIS) | yes | yes | yes (Vanta) | yes | Common |
| Config all regions | yes (as prerequisite) | yes | yes | yes | **Universal** |
| Access Analyzer | yes | yes | yes (Vanta) | yes | Common |
| Flow logs | no (implicit) | yes | yes | yes | **Universal** |
| SG and NACL admin ports | yes | yes | yes | yes | **Universal** |
| Backups (RDS, DynamoDB PITR, AWS Backup) | no | n/a | yes | some | Common (Drata-driven) |
| IMDSv2 | no | no | yes | no | Test-driven only |
| Inspector | no | yes | partial (vuln scan test 21) | yes | Common |
| WAF | yes (edge protection) | yes | yes (122) | yes | Common |
| CloudWatch alarms + SNS | no | no | yes (Drata 112-118, 206, 290-300) | few | **Test-driven only; not in AWS guidance** |
| Alternate contacts, Budgets, Cost Anomaly | yes | alternate contacts | no | no | AWS-baseline only |
| Region restriction (SCP or deny policy) | yes | yes | affects scan scope | no | AWS-baseline only |
| Macie, Detective, Shield Adv., Firewall Manager, Security Lake, Network Firewall, Private CA | no | yes (mostly SHOULD) | no | no | **Optional / enterprise** |

---

## 6. ISO 27001 mapping (AWS's own guide, 2026-03-31) [S]

From the fetched PDF text (`ISO27001-2022_on_AWS_Compliance_Guide.pdf`):
- A.8.2 / A.8.3 privileged access and access restriction: IAM, Access Analyzer, SCPs, S3 bucket policies, Object Lock.
- A.8.8 vulnerabilities: **Inspector**, **Systems Manager Patch Manager**, Config rules.
- A.8.9 configuration management: **AWS Config** (continuous recording, drift, inventory).
- A.8.13 backup: **AWS Backup** (schedules, lifecycle, cross-Region copy) and **RDS automated backups with PITR**.
- A.8.15/A.8.16 logging and monitoring: **CloudTrail incl. data events (S3, DynamoDB)**, **VPC Flow Logs**, **ELB access logs**.
- A.8.20 network: VPC public/private subnets, SGs and NACLs, Transit Gateway, Network Firewall.
- A.8.24 cryptography: TLS 1.2 or later in transit; at-rest encryption.
No ISO-specific AWS Config pack exists in the AWS list (section 1). Claims of an "ISO 27001 conformance pack" in search snippets are [V] and unconfirmed.

---

## 7. Multi-account patterns

- AWS SSB: single-account is the baseline; "controls can be adapted when you move to multi-account" [S].
- AWS SRA: Organizations, Security OU with Security Tooling and Log Archive accounts, delegated admin for GuardDuty, Security Hub, Config, Inspector, Macie, Access Analyzer, org trail to Log Archive bucket; **IAM users MUST NOT be used** [S]. This is an enterprise reference, not a SOC 2 requirement.
- Vendor argument for multi-account: smaller audit scope (only prod in scope), tamper-resistant logs, SCP guardrails (Control Tower mandatory controls: CloudTrail on, validation on, no deletion of Config/GuardDuty) [V] (https://towardsthecloud.com/blog/aws-landing-zone-soc-2).
- **Do auditors or Drata/Vanta expect it?** I found no source saying so [S: none]. Drata and Vanta both connect per account or via an organization; Vanta cannot mix modes; an unconnected production account is an evidence gap [S/V]. Drata sub-account resources are skipped unless the toggle was on [S].
- Recommendation for the skill [I]: detect whether Organizations exists. If single account: do not fail; emit INFO "log bucket lives in the monitored account; confirm it is protected (bucket policy, versioning, Object Lock or equivalent)". If org: check that every member account that runs workloads is in the integration scope and that an org trail exists.

---

## 8. SES and other SaaS features

- Drata and Vanta publish **no SES-specific tests** (not in Drata's full test list, section 3.1) [S].
- SOC 2 does not mandate email technologies; evidence is SPF, DKIM, DMARC DNS records plus DMARC aggregate reports [V] (https://dev.to/rronyecz/soc2-cc66-made-easy-automating-logical-access-evidence-7hn). MTA-STS applies to inbound mail, so it is not evidence for SES outbound [V, my note on the source].
- Palisade: DNS or SES "verified" alone does not prove production mail uses the authenticated path; keep a delivered message's `Authentication-Results` header as evidence [V] (https://www.palisade.email/learning/how-does-the-amazon-ses-palisade-partnership-simplify-bulk-sender-compliance.md).
- AWS SES docs on DMARC alignment: https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dmarc.md [S, for how it works only].
- Our planned SES checks (DKIM on, verified identity, configuration set with TLS `Require`, event destination, DNS SPF/DKIM/DMARC) are reasonable [I]. Suggested additions [I, from my own SES knowledge, not verified in this session]: custom MAIL FROM domain (SPF alignment), DKIM 2048-bit (Easy DKIM), bounce/complaint event destination plus alarm, account-level suppression list, identity policies not granting `ses:SendEmail` to `*`, SMTP credentials as IAM users (ties to IAM-user rules).
- Other feature checks implied by SSB/SRA [S]: S3 static sites need CloudFront with OAC (WKLD.13); Cognito and API Gateway behind WAF (SRA); secrets for SMTP or API keys in Secrets Manager (WKLD.03); EKS needs secrets encryption, audit logs, GuardDuty runtime (SRA, DEV post, Drata 310).

---

## 9. What we are MISSING (gap list vs. spec section 7.2)

Priority: **P1** = directly turns a documented Drata/Vanta test red or is MUST in AWS guidance for a single account; **P2** = AWS baseline or SRA SHOULD, common in audits; **P3** = optional.

### 9.1 Logging and detection

| # | Gap | Source | Prio |
|---|---|---|---|
| 1 | **EventBridge rule for GuardDuty findings with a target** (Drata 105 how-to) | [S] Drata Test 105 | P1 |
| 2 | GuardDuty detector publishing frequency and **SNS or channel notification** for findings | [V] DEV posts; [S] SRA (findings flow to Security Hub) | P2 |
| 3 | GuardDuty extra protection plans: RDS, Lambda, EBS malware, EKS runtime (when those resources exist) | [S] SRA SHOULD | P2 |
| 4 | **CloudTrail `IsLogging = true`** (not just exists) and `start-logging` | [V] freeCodeCamp | P1 |
| 5 | **CloudTrail integrated with CloudWatch Logs** | [S] SRA MUST, Gruntwork | P2 |
| 6 | **CloudTrail S3 bucket protection:** bucket policy with `aws:SourceArn`, versioning, optional MFA delete or Object Lock, no public access, SSE-KMS on bucket | [S] SSB ACCT.07, SRA | P1 |
| 7 | CloudTrail management events Read+Write, global service events included | [S] SSB, Gruntwork | P2 |
| 8 | Security Hub: **standards actually enabled** (FSBP and CIS), cross-region aggregation | [S] SRA; SSB ACCT.15 | P2 |
| 9 | Config **delivery bucket protected** and aggregator (if multi-account) | [S] SRA | P3 |
| 10 | **ELB/ALB access logs** and WAF logging enabled | [S] ISO guide A.8.15; SRA WAF logging MUST | P2 |
| 11 | CloudWatch Logs **log group retention** (not "never expire", not below 365 on security logs) and **S3 lifecycle** on log buckets for Drata 111 / Vanta "AWS Server Logs" | [S] Drata 111 (365d), Vanta customizable; the article does not say which resource is evaluated, so [I] for the specific resources | P1 |
| 12 | Route 53 Resolver query logs, Detective, Macie, Security Lake | [S] SRA SHOULD | P3 |
| 13 | CIS 3.x style metric filters and alarms (root usage, unauthorized API calls, console login without MFA, IAM policy changes, CloudTrail config changes, SG/NACL changes) | [I] CIS (Gruntwork mentions CIS 3.x, but the page does not list the filters) | P2 |

### 9.2 Identity

| # | Gap | Source | Prio |
|---|---|---|---|
| 14 | **IAM users should not exist; IAM Identity Center with MFA** for humans; SSO session duration | [S] SSB ACCT.13, SRA | P2 |
| 15 | **Alternate contacts** (billing, operations, security) set to distribution lists | [S] SSB ACCT.01, SRA | P2 |
| 16 | Unused access analyzer (SRA) in addition to external access analyzer | [S] SRA | P3 |
| 17 | Vanta default thresholds: unused accounts 90d (we use 45d from CIS, fine) and root 30d | [S] Vanta customization | P3 |
| 18 | Expired IAM server certificates and ACM certificate expiry (Vanta CIS list; Drata 72 for websites) | [S] Vanta CIS list; Drata test titles | P2 |
| 19 | **Region restriction** (SCP or deny policy on `aws:RequestedRegion`) and, for Drata, scan scope matching it | [S] SSB ACCT.17; Drata connection docs | P2 |

### 9.3 Encryption, secrets, network

| # | Gap | Source | Prio |
|---|---|---|---|
| 20 | **Secrets Manager / SSM SecureString** used for credentials; rotation enabled; no secrets in Lambda env vars or task definitions | [S] SSB WKLD.03-05, SRA | P2 |
| 21 | Key policy hygiene: separate keys per data class, `kms:ViaService`, not `*` principals | [S] SRA | P3 |
| 22 | **Default VPCs, default SGs and unused SGs** removed or empty in every region | [S] SSB ACCT.09, Gruntwork `cloud-nuke defaults-aws`; Drata 233 | P2 |
| 23 | Private resources in private subnets; **VPC endpoints** for S3, DynamoDB, SSM | [S] SSB WKLD.10, .12 | P3 |
| 24 | **SSM Session Manager** instead of SSH/RDP; SSM agent registered on instances; Patch Manager | [S] SSB WKLD.06; SRA; ISO guide A.8.8 | P2 |
| 25 | ECS task ports restricted (Vanta test) | [S] Vanta customization | P2 |
| 26 | ElastiCache, OpenSearch, SQS, SNS, EKS secrets, Redshift, DocumentDB, MSK encryption at rest and in transit | [I] (Drata scans ElastiCache, SQS, Elasticsearch per permissions list; no named test) | P2 |
| 27 | TLS termination: CloudFront minimum protocol version, ALB TLS policy modern (already planned as `medium`; SSB WKLD.13 recommends current `ELBSecurityPolicy-TLS13-1-2-*`) | [S] SSB | P2 |

### 9.4 Compute, data, backups

| # | Gap | Source | Prio |
|---|---|---|---|
| 28 | Inspector scanning scope: EC2, **ECR**, **Lambda** and the Vanta severity threshold setting | [S] SRA; Vanta connection doc | P2 |
| 29 | AWS Backup vault and plan existence, plan retention, **vault lock / cross-region copy (optional)** | [S] ISO guide A.8.13 | P2 |
| 30 | Backup **restore test evidence** (quarterly) | [V] freeCodeCamp | P3 (process, not config) |
| 31 | RDS backup retention floor, snapshot encryption, **snapshots not public** | [I] (CIS/FSBP style; Drata 107 only needs daily) | P2 |
| 32 | Lambda: runtime supported, not public, DLQ or alarm | [I] Drata 300 covers alarm only | P3 |

### 9.5 Monitoring tests we may not have

Drata tests in the index that I did not see in section 7.2: **112-118 are listed**; **119, 122, 123, 129, 130, 131** partly listed. Not listed: **Test 4** (SSL/TLS on admin page of infrastructure console), **Test 28** (DR plan, process), **Test 106** (backup policy, process), **Test 110** (only authorized users can access log sinks, i.e. log bucket and log group access), **Test 116/117** (NoSQL CPU and storage; DynamoDB or ElastiCache alarms), **Test 129** (capacity and usage monitoring), **Test 209** (external exposure of cloud resources), **Test 208** (excessive privileges, CSPM-driven). [S titles only; detail for 208 from https://help.drata.com/en/articles/8946448-test-208-excessive-privileges-assigned]

### 9.6 Integration health additions

1. `DrataAutopilotRole` exact name; inline `backup:ListRecoveryPointsByResource` for tests 132/133/134/301 [S].
2. `VantaAdditionalPermissions` must be **customer-managed**, not inline (already planned) and must be refreshed when products are enabled (Inspector, Identity Center, CodeCommit) [S].
3. SCP region deny must match the region scope configured in Drata/Vanta [S].
4. Trust policy has ExternalId; role not editable by workload roles (drift breaks the integration) [S/V] (Cloud Posse component and Agency post).
5. Owner tag value belongs to an **active** user [S] (already planned).
6. Every account that hosts in-scope workloads is connected (unconnected prod account = evidence gap) [V].

### 9.7 Governance items the skill can only flag as "manual / INFO" [S/I]

Budgets (ACCT.10), Cost Anomaly Detection (ACCT.16), Trusted Advisor high-risk (ACCT.12; needs Business or Enterprise support for full checks [I]), IaC and CI/CD for controls (WKLD.15), IR plan (Drata test 33), DR plan (28), access review cadence (quarterly per vendor guides [V]).

---

## 10. Items in our catalog that are weakly supported or stricter than the evidence

- "Retention >= 7 days for RDS backups" is a designer decision, not documented (already marked in spec).
- "Confirmed SNS subscription" on CloudWatch alarms: required by Drata (293-300); **Vanta's article does not require it** [S]. Keep, but tag as Drata-driven.
- GuardDuty "only in regions with resources" (spec 5, step 139-142) versus SSB ACCT.14, which says enable in **all supported regions**, even unused ones, because attackers use unmonitored regions [S]. Drata 105 only needs regions with resources. Consider a second, lower-severity check for unused regions [I].
- "Inspector active and no critical/high" maps to Drata Test 21 vulnerability scanning; Vanta says "Sunsetting server vulnerability scanning" in its test index [S title only], so do not over-weight.
- MFA hardware on root (Drata 225): documented but strict; note some auditors accept virtual MFA [I].

---

## 11. Source index (all fetched or surfaced 2026-11-12)

AWS: SSB https://docs.aws.amazon.com/prescriptive-guidance/latest/aws-startup-security-baseline/welcome.html ; SRA checklist https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/checklist.html ; LZA https://aws.amazon.com/blogs/security/introducing-the-landing-zone-accelerator-on-aws-universal-configuration-and-lza-compliance-workbook ; Config packs https://docs.aws.amazon.com/config/latest/developerguide/conformancepack-sample-templates.html ; Audit Manager SOC 2 https://docs.aws.amazon.com/audit-manager/latest/userguide/SOC2.html ; ISO guide https://aws.amazon.com/blogs/security/new-compliance-guide-available-iso-iec-270012022-on-aws-compliance-guide
Drata: https://help.drata.com/en/collections/2711965-tests ; https://help.drata.com/en/articles/10034590-october-2024-release-aws-drata-test ; https://help.drata.com/en/articles/8852274-aws-resource-permissions ; https://help.drata.com/en/articles/5048935-aws-connection-details ; tests 105, 111, 121, 132, 222, 224, 298 (URLs in section 3)
Vanta: https://help.vanta.com/en/articles/11345630-connecting-vanta-aws-account ; https://help.vanta.com/en/articles/11345518-cis-foundation-benchmarks-available-in-vanta ; https://help.vanta.com/en/articles/11345517-resolve-aws-config-is-enabled-correctly-in-all-regions-internal ; https://help.vanta.com/en/articles/11345527-customizing-automated-tests ; https://help.vanta.com/hc/en-us/articles/12264595240724-Create-AWS-Cloud-Watch-Alarms-to-pass-Vanta-Tests ; https://developer.vanta.com/docs/guides/add-owners-to-resources
IaC: https://docs.cloudposse.com/components/library/aws/vanta/ ; https://docs.cloudposse.com/layers/security-and-compliance/ ; https://docs.gruntwork.io/guides/build-it-yourself/achieve-compliance/production-grade-design/logging
Blogs (low reliability): see section 4 table; SES: https://dev.to/rronyecz/soc2-cc66-made-easy-automating-logical-access-evidence-7hn , https://www.palisade.email/learning/how-does-the-amazon-ses-palisade-partnership-simplify-bulk-sender-compliance.md

## 12. Limits of this research

- Drata articles for tests 30, 107, 108, 122, 208 were read only as search snippets; pass criteria beyond what is quoted are not verified.
- I could not find Vanta's per-test pages for AWS tests (help center lists only a Config article under "Resolving tests"), so Vanta details come from the CIS list, customization and alarm articles.
- Retention values for Cloud Posse, Gruntwork and nozaq modules were not published on the pages I read.
- Auditor acceptance of single-account setups was not confirmed by any auditor source (only vendor opinion).
