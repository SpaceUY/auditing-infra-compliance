# Vanta and Drata automated tests against AWS (and adjacent systems) - research report

Research date: 2026-11-12. Method: Drata public help center (help.drata.com) articles fetched one by one; Vanta public help center (help.vanta.com), vanta.com AWS page, and a few third-party pages.

## 0. How to read this report

- **SOURCED** = stated on the cited page (fetched and read).
- **INFERRED** = my judgement (marked "inferred"). All SOC 2 TSC and ISO 27001:2022 columns are INFERRED unless stated otherwise. Neither Drata's nor Vanta's public per-test help articles publish a per-test SOC 2 / ISO mapping. The Drata test pages only cite "CIS AWS Foundations Benchmark" and a DCF control ID. The real mapping of DCF control -> framework requirement lives inside the Drata app ("Frameworks" tab of each control, "Compare to defaults"). Vanta says it supports 35+ frameworks but does not publish a per-test mapping.
- Coverage gap, stated honestly: Drata's test catalogue is public and numbered (high confidence). Vanta's full test catalogue is only visible inside the app (1,200+ tests per Vanta marketing, 100+ for AWS). Public Vanta sources give: the 36 CIS AWS Foundations tests, a handful of named tests, the 44 supported AWS resource types, and the tag scheme. Vanta rows below that are not in the CIS list are marked as example/third-party.
- TSC refs are the 2017 TSC (with 2022 points of focus). ISO refs are ISO/IEC 27001:2022 Annex A.

Primary URLs:
- Drata tests index: https://help.drata.com/en/collections/2711965-tests
- Drata Oct 2024 AWS release (ID -> DCF control -> CIS/custom): https://help.drata.com/en/articles/10034590-october-2024-release-aws-drata-test
- Drata AWS connection: https://help.drata.com/en/articles/4663372-connecting-aws-to-drata
- Drata AWS resource permissions: https://help.drata.com/en/articles/8852274-aws-resource-permissions
- Vanta CIS tests: https://help.vanta.com/en/articles/11345518-cis-foundation-benchmarks-available-in-vanta
- Vanta AWS page: https://www.vanta.com/integrations/aws
- Vanta bulk tags: https://help.vanta.com/en/articles/11345627-bulk-tags
- Vanta tests collection: https://help.vanta.com/en/collections/12575278-tests

---

## 1. Drata - AWS infrastructure tests (SOURCED from each test article)

Base URL pattern is https://help.drata.com/en/articles/<id>. Controls are Drata DCF IDs. "CIS" = article says it aligns with CIS AWS Foundations Benchmark.

| Test | Name | AWS service | Check logic | Threshold | DCF control | Source article ID |
|---|---|---|---|---|---|---|
| 214 | MFA for AWS Root Account | IAM | MFA enabled on root user | binary | DCF-90 Root Infrastructure Account Monitored (CIS) | 9828711 |
| 225 | Hardware MFA for AWS Root Account | IAM | Hardware MFA on root; virtual/software MFA FAILS; orphaned virtual MFA records can cause failures | binary | DCF-90 (CIS) | 9828713 |
| 124 | Root Infrastructure Account Unused | CloudTrail/IAM | Fails on 2+ root login attempts (even failed) in rolling 7 days | 2 attempts / 7 days | "Root Infrastructure Account Unused" | 4777051 |
| 88 | MFA on Infrastructure Console | IAM | Pulls IAM accounts; every IAM user must have MFA | zero exceptions; nightly sync | "MFA on Accounts" | 4777035 |
| 215 | AWS IAM Password Minimum Length | IAM account password policy | min length >= 14 | 14 chars | DCF-346, DCF-68 (CIS) | 9828716 |
| 216 | AWS IAM Password Reuse | IAM password policy | blocks reuse of last 24 passwords | 24 | DCF-350 (CIS) | 9828717 |
| 217 | AWS IAM Group-Based Access Control | IAM | Fails if any IAM user has an inline policy or directly attached policy | per user | DCF-776 (CIS) | 9828704 |
| 230 | AWS IAM Principle of Least Privilege | IAM policies | Fails on policies with wildcard/broad permissions (`*`); AWS-managed AdministratorAccess findings can be excluded per-finding | none | DCF-776 (CIS) | 9828707 |
| 229 | AWS IAM Unused Credentials | IAM credential report | active passwords/keys unused > 45 days fail | 45 days | DCF-335 (CIS) | 9828680 |
| 232 | AWS IAM Access Key Rotation | IAM credential report | any access key age >= 90 days fails (report refreshed up to every 4 h) | 90 days | DCF-783 (CIS) | 9828694 |
| 95 | Infrastructure Accounts Properly Removed | IAM/Identity Center | former personnel still holding infra accounts fail | 1 business day (from System Access Control Policy) | "Terminated Employee Access Revoked Within One Business Day" | 4777040 |
| 98 | Employees have Unique Infrastructure Accounts | IAM | each infra account must map to an IdP identity; service accounts must be marked out of scope in Manage Accounts | none | "Unique Accounts Used" | 4777045 |
| 218 | AWS EBS Volume Encryption | EC2/EBS | default EBS encryption enabled in every region where EC2 instances exist | per region | DCF-54 Encryption at Rest (CIS) | 9828784 |
| 231 | AWS EFS Encrypted at Rest | EFS | all file systems encrypted (KMS) in all regions; cannot be fixed in place | per FS | DCF-54 (CIS) | 9828789 |
| 68 | Customer Data is Encrypted at Rest | DynamoDB (default), OpenSearch, ElastiCache Redis | production DBs encrypted at rest | per DB | "Customer Data is Encrypted at Rest" | 4776970 |
| 69 | Customer Data in Cloud Storage Encrypted at Rest | S3 | S3 encryption (default-on since 2023-01-05) | per bucket | same control | 4776971 |
| 222 | AWS CloudTrail Logs Encrypted | CloudTrail+KMS | each trail uses SSE-KMS with a customer-managed key (CMK); CMK must be in same region as S3 log bucket, key policy must allow CloudTrail | per trail | DCF-54 (CIS) | 9828725 |
| 223 | AWS CMK Rotation | KMS | automatic rotation enabled on customer-created symmetric CMKs; needs kms:ListKeys, DescribeKey, GetKeyRotationStatus in each key policy for DrataAutopilotRole | annual | DCF-779 (CIS) | 9828731 |
| 219 | AWS RDS Auto Minor Version Upgrade | RDS | AutoMinorVersionUpgrade true on every instance | per instance | DCF-152 (CIS) | 9828785 |
| 220 | AWS RDS Public Access Restricted | RDS/VPC | Fails if instance allows 0.0.0.0/0 or sits in a public subnet (route to igw); fix = PubliclyAccessible off | none | DCF-75 (CIS) | 9828787 |
| 107 | Daily Database Backups | RDS/Aurora/DocDB | RDS: automatic backups on, retention > 0 days; Aurora/DocDB pass by default (retention 1) | retention > 0 | "Daily Database Backups" | 4777050 |
| 30 | Availability Zones Used | RDS, ElastiCache, DynamoDB | RDS Multi-AZ with standby; ElastiCache Redis Multi-AZ; DynamoDB passes by default; S3 not checked | per DB | "Multiple Availability Zones" | 4776928 |
| 301 | AWS DynamoDB Point-in-Time Recovery | DynamoDB (+Backup API perm) | PITR enabled on every table | per table | DCF-86 | 9999538 |
| 132 | Daily backup job status monitored | AWS Backup / DB snapshots | successful snapshot for the previous day; needs backup:ListRecoveryPointsByResource | previous day | DCF-99 Backup Monitoring | 9999495 |
| 133 | Failed Backup Alerts Being Sent | AWS Backup | alerts configured for backup failure; needs backup:ListBackupJobs | none | DCF-99 | 4778878 |
| 134 | Failed Backups Addressed in Timely Manner | AWS Backup | failed backup must be restarted within 24h | 24 hours | DCF-99 | 4778882 |
| 108 | Storage Data Versioned or Retained | S3 | bucket versioning enabled | per bucket | "Storage Buckets are Versioned" | 4778759 |
| 104 | Cloud Storage Public Access Disabled | S3 | bucket-level "Block all public access" = On (account-level BPA is NOT evaluated per article) | per bucket | "Threat Detection System" (as named in article) | 4777046 |
| 234 | AWS S3 HTTP Requests Denied | S3 | bucket policy must explicitly Deny `aws:SecureTransport=false` | per bucket | DCF-55 Encryption in Transit (CIS) | 9828783 |
| 221 | AWS S3 Bucket Access Logging | S3 / CloudTrail bucket | server access logging on the CloudTrail S3 bucket | none | DCF-406 Audit Logging (CIS) | 9828721 |
| 226 | AWS S3 Object-Level Logging Read & Write | CloudTrail data events | needs >=1 multi-region trail; S3 data events for read AND write | none | DCF-406 (CIS) | 9828791 |
| 205 | CloudTrail log file integrity validation | CloudTrail | log file validation on all trails | per trail | DCF-478 Change Detection Mechanism (CIS) | 10029049 |
| 224 | AWS VPC Flow Logging | VPC | flow logs enabled in all VPCs (Reject filter recommended, not required) | per VPC | DCF-406 (CIS) | 9828733 |
| 310 | Audit Logs Enabled for EKS Clusters | EKS | cluster `logging.enabled` true in each region (all log types recommended) | per cluster | DCF-406 | 10375560 |
| 109 | Logs are Centrally Stored | (page names Datadog only) | logging enabled and used | - | "Logs Centrally Stored" | 4778760 |
| 110 | Only Authorized Users Access Log Sinks | (Datadog) | logging-system users must be on infra admins list | - | same | 4778762 |
| 111 | Logs are Retained for 365 Days | (page references Datadog; no CloudWatch detail) | retention policy or archive >= 12 months | 365 days / 12 months | "Logs Retained for 12 Months" | 4778770 |
| 121 | Logs Monitored for Suspicious Activity | Datadog Cloud SIEM only | at least one Signal notification rule | - | - | 4797516 |
| 105 | Threat Detection in Place | GuardDuty | no S3 buckets: pass. With S3 buckets: GuardDuty active in EVERY region with resources AND S3 Protection on | all regions | "Logging/Monitoring" | 4778757 |
| 102 | Public SSH Denied | EC2 security groups | SG ingress port 22 from 0.0.0.0/0 or ::/0 fails only in regions with active ENIs; SG-source passes; a specific CIDR does NOT count as "pass" for this test per article | - | "Denial of Public SSH" | 4776976 |
| 228 | AWS Security Groups Restrict Public RDP | EC2 SG | port 3389 from 0.0.0.0/0 or ::/0 | none | DCF-73 Remote Admin Ports Restricted (CIS) | 9828740 |
| 227 | AWS Network ACLs Remote Admin Restricted | VPC NACL | inbound allow from 0.0.0.0/0 (and ::/0) to 22 or 3389 over TCP/UDP/all | none | DCF-73 (CIS) | 9828735 |
| 233 | VPC Default SGs Restrict All Traffic | VPC | each default SG has no inbound/outbound rules | per SG | DCF-85 Network Security Controls (CIS) | 9828741 |
| 291 | AWS SGs HTTP Access Restricted | EC2 SG | port 80 from 0.0.0.0/0 or IPv6 any fails | none | DCF-85 (custom) | 9828797 |
| 119 | Firewall Default Disallows Traffic | EC2 SG | inbound "ALL traffic" type fails; SG source passes; a CIDR source does not pass per article | - | "Firewalls" | 4777002 |
| 292 | EC2 Instances IMDSv1 Disabled | EC2 | HttpTokens=required on all active instances (ASG: launch template + instance refresh) | per instance | DCF-12 Baseline Config & Hardening (custom) | 9828799 |
| 299 | ALB Redirects HTTP to HTTPS | ELBv2 | every ALB listener must redirect HTTP->HTTPS (443, 301/302) | per listener | DCF-55 (custom) | 9828823 |
| 122 | Web Application Firewall in Place | WAFv2 | fails if no Web ACLs; ACL must be associated (CloudFront, ALB, API Gateway, AppSync) | none | "Web Application Firewall" | 4777003 |
| 130 | Load Balancer Used | ELB | LB spanning >= 2 AZs in every region with EC2; no EC2 = pass | 2 AZs | "Load Balancer Used" | 4777006 |
| 131 | Autoscale Server Instances | Auto Scaling | autoscale group config found; centralized scaling plan; all compute regions | - | DCF-97 Autoscaling | 10029045 |
| 112 | Database CPU Monitored | CloudWatch alarm on RDS CPUUtilization + confirmed SNS subscription | alarm exists on instance and cluster; example threshold >10% (illustrative only) | not fixed | "Databases Monitored and Alarmed" | 4776977 |
| 113, 114, 206, 290 | DB Free Storage / Read IO / Freeable Memory / Write IO monitored | CloudWatch alarms | same pattern (alarm + SNS) | not fixed | DCF-86 System Monitoring (206/290 custom) | 4776980 / 4776984 / 10029047 / 9828793 |
| 115, 116, 117 | SQS Message Age, NoSQL CPU, NoSQL storage monitored | CloudWatch alarms | same pattern | not fixed | DCF-86 / monitored-and-alarmed | 4776986 / 10029043 / 4776995 |
| 118 | Infrastructure Instance CPU Monitored | CloudWatch CPUUtilization on EC2/ASG/ECS/EKS | alarm + confirmed SNS subscription | illustrative >10% | "Servers Monitored and Alarmed" | 4776997 |
| 293-298, 300 | Classic/App LB latency, target response time, 5xx errors, unhealthy hosts; Lambda error rate monitored | CloudWatch alarms | alarm per resource (assumed same pattern; each is custom, DCF-86) | not fixed | DCF-86 | 9828801..9828825 |
| 4 | SSL/TLS on Admin Page of Infra Console | aws.amazon.com | cert valid/trusted (trivially passes for AWS) | - | "Require Encryption of Web-Based Admin Access" | 4776882 |
| 208, 209, 210 | Excessive privileges / External exposure / Encryption in transit (CSPM-sourced) | CSPM tool (e.g. Wiz) | any open CSPM issue of that category fails | none | Privileged Access Restricted; Network Security Controls; Encryption of Data in Transit | 8946448 / 8946449 / 8946445 |
| 21, "Critical/High Vulnerabilities Addressed" | Vulnerability Scanning | any connected scanner (page does not name Inspector) | scanner connected; any open critical/high not fixed or excluded fails; SLA days not stated on page | - | "Quarterly Vulnerability Scan" | 4776909 / 9859338 / 9859341 |
| "Backups Checked for Integrity" | DR test evidence | Disaster Recovery Report uploaded in last 12 months | 12 months | "Backup Integrity and Completeness" | 4778883 |
| 123 | Cloud Infrastructure Linked to Drata | connection health | API call must succeed | - | - | 4778777 |
| 8 | Formal Code Review (AWS CodeCommit) | CodeCommit | approval rule template with >= 2 approvals on repos with default branch | 2 approvals (GitHub: PR required, no count) | - | 4776886 |

Important Drata behavior notes (SOURCED, Oct 2024 release page):
- A test runs only if its mapped DCF control exists in the workspace's frameworks AND an AWS connection is active; otherwise status = "Unused".
- New tests released as "New" are not auto-enabled for existing tenants; they must be set to Enabled on the Monitoring page.
- Drata passes some tests by "no resources found" (e.g. Test 130 with no EC2, Test 105 with no S3). Per-region tests (218, 105, 130, 102) depend on regions where resources exist.
- Scoping: Drata AWS connection supports in/out-of-scope condition groups by tag (equal operator only; blank value matches any tag with that key) or by name. Source: https://help.drata.com/en/articles/4663372-connecting-aws-to-drata
- Findings can be excluded per resource in the Findings tab (e.g. AdministratorAccess, service accounts).

Drata IAM requirements (SOURCED, https://help.drata.com/en/articles/4663372-connecting-aws-to-drata and https://help.drata.com/en/articles/8852274-aws-resource-permissions):
- Role name `DrataAutopilotRole` (exact), AWS-managed `SecurityAudit` policy, trusted AWS account (ver la documentación del proveedor), external ID required (tenant-specific), MFA requirement unchecked.
- Extra inline policy only for tests 132/133/134/301: `backup:ListRecoveryPointsByResource`, `backup:ListBackupJobs` on `*`.
- KMS: test 223 needs kms:ListKeys, kms:DescribeKey, kms:GetKeyRotationStatus granted in each CMK key policy to arn:aws:iam::<acct>:role/DrataAutopilotRole.
- SecurityAudit covers: API Gateway, AppSync, CloudFront, CloudTrail root-event lookup, CloudWatch alarms, DynamoDB, EC2 SG/instances, ECS, ElastiCache, ELB v1/v2, Elasticsearch, GuardDuty, IAM users, RDS, S3, SQS.
- Custom-connection resources (extra actions listed, most covered by ReadOnlyAccess): MemoryDB, Lambda, EMR, Backup (ListBackupJobs/Plans/Vaults, DescribeGlobalSettings), CloudTrail (ListTrails), Cognito, Auto Scaling, OpenSearch (+Serverless), CodeBuild, Kinesis, Config, KMS, SageMaker, Secrets Manager, Redshift, Route53, Trusted Advisor, DocumentDB elastic, etc. Not covered by ReadOnlyAccess: memorydb:DescribeAcls, trustedadvisor:*, docdb-elastic:ListClusterSnapshots.
- SCP-restricted regions: select "Specific regions" matching the SCP `aws:RequestedRegion` allow-list, otherwise tests can error. AccessDenied errors in test JSON identify missing permissions.
- Multi-account: role `DrataAutopilotRole` is needed in every monitored account including the management account (https://help.drata.com/en/articles/8981943-aws-org-units-connection-instructions, from search summary).

---

## 2. Vanta - AWS tests

### 2.1 CIS AWS Foundations tests (SOURCED - 36 tests; https://help.vanta.com/en/articles/11345518-cis-foundation-benchmarks-available-in-vanta)

Available on Professional and Enterprise plans; automatically added when using SOC 2, ISO 27001 or CIS v8 frameworks (so these are in play for a SOC 2/ISO customer). Thresholds in test names are as printed.

| # | Vanta test (verbatim from page) | AWS service | Threshold in name | TSC (INFERRED) | ISO 27001:2022 (INFERRED) |
|---|---|---|---|---|---|
| 1 | The root account has no access key | IAM | - | CC6.1, CC6.3 | A.8.2, A.5.15 |
| 2 | MFA is enabled on the root account | IAM | - | CC6.1 | A.8.5, A.8.2 |
| 3 | Password policy requires a minimum length of 14 or more | IAM | 14 | CC6.1 | A.5.17, A.8.5 |
| 4 | Password policy blocks password reuse | IAM | (count not on page; CIS = 24) | CC6.1 | A.5.17 |
| 5 | MFA is enabled for IAM users with console passwords | IAM | - | CC6.1 | A.8.5 |
| 6 | Unused credentials are disabled after 45 days | IAM | 45 days | CC6.2, CC6.3 | A.5.18 |
| 7 | Each IAM user has at most one active access key | IAM | 1 key | CC6.1 | A.5.16, A.5.17 |
| 8 | Access keys are rotated at least every 90 days | IAM | 90 days | CC6.1 | A.5.17 |
| 9 | IAM users get permissions only through groups | IAM | - | CC6.3 | A.5.15, A.5.18 |
| 10 | Full administrative (`*:*`) policies are not attached | IAM | - | CC6.3 | A.8.2 |
| 11 | A support role exists for managing incidents with AWS Support | IAM | - | CC7.3, CC7.4 | A.5.24, A.5.26 |
| 12 | Instances use IAM instance roles for AWS resource access | IAM/EC2 | - | CC6.1 | A.5.17, A.8.2 |
| 13 | Expired SSL/TLS certificates are removed from IAM | IAM | - | CC6.7 | A.8.24 |
| 14 | IAM Access Analyzer is enabled in all regions | Access Analyzer | all regions | CC6.1, CC7.1 | A.8.3, A.8.16 |
| 15 | Bucket policies deny HTTP requests | S3 | - | CC6.7 | A.8.24 |
| 16 | Buckets use Block Public Access settings | S3 | - | CC6.1, CC6.6 | A.8.3, A.8.20 |
| 17 | Object-level logging is enabled for write events | CloudTrail | - | CC7.2 | A.8.15 |
| 18 | Object-level logging is enabled for read events | CloudTrail | - | CC7.2 | A.8.15 |
| 19 | Access logging is enabled on the CloudTrail bucket | S3 | - | CC7.2 | A.8.15 |
| 20 | EBS volume encryption is enabled in all regions | EBS | all regions | CC6.1 | A.8.24 |
| 21 | Encryption at rest is enabled for RDS instances | RDS | - | CC6.1 | A.8.24 |
| 22 | Auto minor version upgrade is enabled for RDS instances | RDS | - | CC7.1 | A.8.8, A.8.9 |
| 23 | RDS instances are not publicly accessible | RDS | - | CC6.1, CC6.6 | A.8.20, A.8.22 |
| 24 | EFS file systems are encrypted | EFS | - | CC6.1 | A.8.24 |
| 25 | CloudTrail is enabled in all regions | CloudTrail | all regions | CC7.2 | A.8.15 |
| 26 | CloudTrail log file validation is enabled | CloudTrail | - | CC7.2 | A.8.15 |
| 27 | AWS Config is enabled in all regions | Config | all regions | CC7.1, CC8.1 | A.8.9, A.8.16 |
| 28 | CloudTrail logs are encrypted with KMS customer-managed keys | CloudTrail/KMS | - | CC6.1 | A.8.24, A.8.15 |
| 29 | Rotation is enabled for customer-created symmetric KMS keys | KMS | - | CC6.1 | A.8.24 |
| 30 | VPC flow logging is enabled in all VPCs | VPC | all VPCs | CC7.2 | A.8.15, A.8.16 |
| 31 | AWS Security Hub is enabled | Security Hub | - | CC7.1, CC7.2 | A.8.16 |
| 32 | No network ACL allows unrestricted ingress (0.0.0.0/0) to remote administration ports | VPC NACL | - | CC6.6 | A.8.20, A.8.22 |
| 33 | No security group allows unrestricted IPv4 ingress to remote administration ports | EC2 SG | - | CC6.6 | A.8.20 |
| 34 | No security group allows unrestricted IPv6 ingress (::/0) to remote administration ports | EC2 SG | - | CC6.6 | A.8.20 |
| 35 | The default security group in every VPC blocks all traffic | VPC | - | CC6.6 | A.8.20, A.8.22 |
| 36 | EC2 instances use only IMDSv2 for the metadata service | EC2 | - | CC6.1, CC7.1 | A.8.9 |

Note: AWS Config recorder and Security Hub enablement appear in Vanta (CIS #27, #31) but have no Drata counterpart in the public catalogue. Access Analyzer (#14) likewise.

### 2.2 Other named Vanta tests (SOURCED where a URL is given)

| Test (as named) | Check logic / threshold | AWS service | TSC / ISO | Source |
|---|---|---|---|---|
| AWS Config is enabled correctly in all regions | Per in-scope region: recording ON; "All resource types with customizable overrides"; IAM global types overridden to DAILY recording; delivery S3 bucket; stream changes to an SNS topic (topic selected) | Config | CC7.1/CC8.1; A.8.9 (inferred) | https://help.vanta.com/en/articles/11345517-resolve-aws-config-is-enabled-correctly-in-all-regions-internal |
| Inventory items have active owners | Fails if owner offboarded, not a person, scoped out of HRIS/IdP, VantaOwner tag email not matching an active Vanta user, owner on leave, or future start date | any inventory item | CC6.1/CC2.1 (inferred); A.5.9 Inventory of assets, A.5.10 (inferred) | https://help.vanta.com/en/articles/11345538-resolve-inventory-items-have-active-owners-test |
| Inventory list tracks resources that contain user data | Passes if >=1 in-scope resource of supported type (buckets, databases, PaaS, queues, data warehouses, custom) is flagged "contains user data" | S3, RDS, DynamoDB, SQS etc. | C1.1/CC6.1 (inferred); A.5.12 Classification of info (inferred) | https://help.vanta.com/en/articles/11345540-resolve-inventory-list-tracks-resources-that-contain-user-data-test |
| AWS CloudWatch alarms tests (e.g. messaging queue message age monitored) | Per flagged resource a CloudWatch alarm on the metric named in the test's "how to fix"; resource name exact; same account+region; no threshold dictated | CloudWatch/SQS/RDS/EC2/ELB | A1.1/CC7.2; A.8.6, A.8.16 (inferred) | https://help.vanta.com/hc/en-us/articles/12264595240724-Create-AWS-Cloud-Watch-Alarms-to-pass-Vanta-Tests |
| IMDSv1 is disabled on EC2 Instances (ASG variant) | launch template metadata set to V2-only | EC2/ASG | see CIS #36 | https://help.vanta.com/en/articles/11345860-how-to-pass-the-imdsv1-is-disabled-on-ec2-instances-test-with-autoscaling-group |
| No root user access keys exist (AWS) | example test on Vanta AWS page | IAM | see CIS #1 | https://www.vanta.com/integrations/aws |
| Public SSH denied (AWS) | example test on Vanta AWS page | EC2 SG | CC6.6 / A.8.20 (inferred) | https://www.vanta.com/integrations/aws |
| AWS accounts deprovisioned when personnel leave (a.k.a. `aws-account-access-removed-on-termination`) | example on AWS page and Vanta API doc; SLA default: Vanta recommends 3 days for offboarding (editable) | IAM / Identity Center | CC6.2 / A.5.18, A.6.5 (inferred) | https://www.vanta.com/integrations/aws ; https://developer.vanta.com/api-reference/tests/list-tests.md ; https://help.vanta.com/en/articles/11345547-test-priorities-and-slas |
| Critical vulnerabilities identified in packages are addressed (AWS Inspector) | example on AWS page; Inspector/ECR findings feed Vulnerabilities page; default SLA days NOT published (set in app: Settings > Features > Assets > Vulnerability remediation SLAs; applied to newly detected vulns; business days available) | Inspector, ECR | CC7.1 / A.8.8 (inferred) | https://www.vanta.com/integrations/aws ; https://help.vanta.com/en/articles/11951321-how-vanta-calculates-vulnerability-slas |
| Kubernetes nodes follow a certificate rotation policy | example on AWS page | EKS | - | https://www.vanta.com/integrations/aws |
| "AWS Server Logs" log retention test | threshold editable in "Customizing Automated Tests": "can change number of days logs have to be retained (can be unlimited)". Default value not on page. Vanta's GCP equivalent is named "Logs retained for 365 days (GCP)" (bucket must be a log sink, retention >= 365d) so default for AWS is very likely 365 (inferred) | CloudWatch Logs / S3 | CC7.2 / A.8.15 (inferred) | https://help.vanta.com/en/articles/11345527-customizing-automated-tests ; https://help.vanta.com/en/articles/11345542-resolve-logs-retained-for-365-days-gcp-test |
| Infra Access Keys Rotated | rotation period editable; default not on page (CIS says 90) | IAM | - | same Customizing page |
| AES (AWS) Ec2 Instances Ports Restricted | list of "public ports" editable | EC2 SG | - | same Customizing page |
| root account last-used window; unused-account window | editable thresholds, defaults not given | IAM | - | same Customizing page |

### 2.3 Third-party descriptions of Vanta AWS tests (UNOFFICIAL, treat as indicative only)

From https://blog.getagency.com/articles/vanta-aws-integration-complete-setup-guide (unverified, author does not cite Vanta docs): MFA enabled for all IAM users; access keys rotated within 90 days; no root access keys; password policy; S3 server-side encryption, public access blocked; SG no 0.0.0.0/0 on sensitive ports; EBS encrypted; RDS encryption at rest, automated backups configured, Multi-AZ (it labels this A1); CloudTrail enabled in all regions with log file validation and delivery to S3; CloudWatch alarms and log groups with retention; KMS rotation; default SGs restrict inbound; VPC flow logs; Config; GuardDuty enabled and findings monitored. Its TSC labels (CC6, CC7, A1) are the author's, not Vanta's.

From https://dev.to/aayostem/i-turned-23-vanta-red-tests-green-in-14-days-here-is-the-exact-command-for-each-one-ihp (personal blog, UNOFFICIAL, names may not match Vanta): MFA for IAM users, 90-day access keys, EKS secrets with CMK, RDS/S3 CMK, GuardDuty (incl. EKS runtime monitoring), VPC flow logs, IRSA for EKS, K8s network policy. Do not use for thresholds.

### 2.4 Supported AWS resource types (SOURCED, 44 types)
https://www.vanta.com/integrations/aws and https://help.vanta.com/en/articles/11345614-which-resources-does-vanta-fetch-from-aws : Access Analyzer, Autoscaling Group, Certificate, CloudTrail, CloudWatch Log Group, CloudWatch Metric Alarm, CodeCommit Repo, Config Recorder, Credential Report, DocumentDB Cluster, DynamoDB Table, EBS Volume, EC2 Instance, ECR Repo, ECR Vulnerability, ECS Cluster/Service/Standalone Task, EFS, EKS Cluster/Node, Flow Log, Group, GuardDuty Detector, IAM Identity Center User, IAM Policy, IAM User, Inspector Vulnerability, KMS Key, Lambda, Load Balancer, Network ACL, Organization Account, Password Policy, RDS Instance, Redshift Cluster, Role, Route Table, S3 Bucket, Security Group, Security Hub, SQS Queue, Subnet, VPC. "Resources not listed above are currently not supported" (can be added as custom inventory items). Practical implication: resources outside this list (e.g. Aurora clusters beyond RDS, ElastiCache, OpenSearch, MSK, Kinesis, API Gateway, CloudFront, WAF) are not auto-tested by Vanta; they would require manual inventory/evidence.

### 2.5 Vanta AWS permissions (SOURCED)
- Role name `vanta-auditor` (docs show "vanta-auditor"; one article text is garbled). Policies: AWS-managed `SecurityAudit` + customer-managed `VantaAdditionalPermissions` (an INLINE policy is not detected). Trust policy snippet comes from Vanta (Cloud Posse docs show trust to Vanta scanner roles in accounts (ver la documentación del proveedor) with external ID; third-party). Sources: https://help.vanta.com/en/articles/11345630-connecting-vanta-aws-accounts ; https://docs.cloudposse.com/components/library/aws/vanta/
- VantaAdditionalPermissions base content = a DENY statement: `datapipeline:EvaluateExpression`, `datapipeline:QueryObjects`, `rds:DownloadDBLogFilePortion` (data-access guard). Optional products add Allow statements: CodeCommit (`codecommit:GetApprovalRuleTemplate, ListPullRequests, GetCommentsForPullRequest, GetPullRequest, GetPullRequestApprovalStates`), IAM Identity Center (`identitystore:Describe*, Get*, IsMemberInGroups, List*`), Inspector (no extra). Source: https://help.vanta.com/en/articles/11345613
- Child accounts of an Organization need the same role with both policies; management account has a separate policy (`VantaManagementAccountPermissions`, inline unsupported). Sources: https://help.vanta.com/en/articles/11345628-connecting-vanta-to-an-aws-organization and https://help.vanta.com/en/articles/11346027-how-to-fix-assume_role-warning-from-aws-organization
- KMS keys with a custom key policy must allow vanta-auditor either via account-root `kms:*` ("Enable IAM User Permissions") or targeted `kms:DescribeKey, GetPublicKey, ListAliases, ListGrants, ListKeyPolicies, ListResourceTags, ListRetirableGrants` in the KEY policy. Source: https://help.vanta.com/en/articles/11345859-understanding-kms-key-policy-permissions-and-access-issues-in-vanta
- S3 buckets with restrictive bucket policies need vanta-auditor read access in the bucket policy. Regions: only selected regions are scanned; resources in removed regions are not pulled.
- Vanta fetches resources roughly hourly (https://help.vanta.com/en/articles/11345619-how-to-troubleshoot-aws-resources-not-appearing-in-inventory and search summaries).

### 2.6 Vanta tagging conventions (SOURCED, https://help.vanta.com/en/articles/11345627-bulk-tags)

| Tag key (exact) | Value | Effect |
|---|---|---|
| `VantaOwner` | email of an ACTIVE Vanta user | sets resource owner; if no matching user, no owner (this feeds the "Inventory items have active owners" test) |
| `VantaNonProd` | `true` | marks non-production AND removes from scope; troubleshooting page says remove tag or set `false` to bring back into scope |
| `VantaDescription` | free text | sets description |
| `VantaContainsUserData` | boolean (article prints "True/0 or False/1" - odd wording; use `true`/`false`) | sets "contains user data" flag (feeds "Inventory list tracks resources that contain user data") |
| `VantaContainsEPHI` | boolean | HIPAA customers only |
| `VantaUserDataStored` | free text | type of user data in resource |
| `VantaNoAlert` | key presence alone (value ignored; reason entered in Vanta) | out of audit scope entirely |

Also: custom tag names can be mapped to Vanta tags once in the UI (e.g. `owner` -> VantaOwner, `environment=development` -> VantaNonProd): https://help.vanta.com/en/articles/11345392-custom-inventory-tags . Vanta only READS tags, never writes them to AWS. Confirmation about "owners and descriptions required": SOURCED for owners (active-owner test exists). Descriptions: the VantaDescription tag exists, but I found NO public test that fails when description is empty (not confirmed).

Quirk: a VantaNonProd=true or VantaNoAlert tag removes the resource from ALL tests, which is useful for scoping dev/test but is audit-visible; auditors see scoping.

### 2.7 Test priorities/SLAs (SOURCED)
Tests show orange (needs attention, not past due) and red (past deadline); auditors/reports only see failing after deadline passes. SLAs are editable under Settings. Only default stated: offboarding "within three days" recommended. Business-day SLAs supported. https://help.vanta.com/en/articles/11345547-test-priorities-and-slas

---

## 3. Thresholds compendium (only values found in sources)

| Item | Value | Tool | Source |
|---|---|---|---|
| Log retention | 365 days / 12 months | Drata Test 111 | help.drata.com/en/articles/4778770 |
| Log retention (Vanta GCP; AWS default not published, editable) | 365 days (GCP) | Vanta | help.vanta.com/en/articles/11345542 ; customizing page |
| Backup retention RDS | > 0 days (automatic backups on); Aurora/DocDB retention 1 passes | Drata Test 107 | help.drata.com/en/articles/4777050 |
| Failed backup restart | 24 hours | Drata Test 134 | help.drata.com/en/articles/4778882 |
| Backup job success | successful snapshot for previous day | Drata Test 132 | 9999495 |
| DR/restore test evidence | uploaded within 12 months | Drata "Backups Checked for Integrity" | 4778883 |
| Policy approval (DRP, Password policy) | within 12 months | Drata Test 28, 89 | 4776923, 4776975 |
| IAM password min length | 14 | Drata 215, Vanta CIS | - |
| IAM password reuse | last 24 | Drata 216 | 9828717 |
| Access key rotation | 90 days | Drata 232, Vanta CIS | - |
| Unused IAM credentials | 45 days | Drata 229, Vanta CIS | - |
| Root account use | 2+ login attempts in 7 days fails | Drata 124 | 4777051 |
| Terminated access removal | 1 business day (Drata, policy-driven); 3 days (Vanta recommended, editable) | both | 4777040 ; 11345547 |
| Multi-AZ LB | >= 2 AZs | Drata 130 | 4777006 |
| Code review approvals | CodeCommit >= 2; Azure DevOps >=1 (self-approve off) or >=2; Bitbucket >=1 | Drata Test 8 | 4776886 |
| Screen lock | idle 15 min, password required within 60 s | Drata 61 | 4778709 |
| Training | annual, all full-time employees | Drata 43 | 4778548 |
| Security patches / disk encryption / antivirus | binary per device; Mac antivirus pass on macOS >= 10.16 (sic) | Drata 64-66 | 4776962 etc. |
| CloudWatch alarm thresholds | NOT fixed (Drata examples ">10%" illustrative; Vanta: admin's discretion) | both | 4776977 ; 12264595240724 |
| Vulnerability SLAs | NOT published by either tool in help center (editable). Third-party benchmark mentions 7/30 or 14/30/60/90 - not tool defaults | - | - |
| TLS versions | Drata Test 71 "SSL/TLS Configuration has No Known Issues" exists (website-level); no minimum-version threshold fetched. AWS-side: Drata 234 (deny non-SecureTransport on S3), 299 (ALB HTTP->HTTPS redirect). ALB TLS policy / minimum TLS 1.2 NOT found as a sourced Drata/Vanta AWS test | - | - |
| Inactive user days (non-AWS) | not found beyond 45 (IAM) | - | - |

Not found / unverified: TLS minimum versions for ALB/CloudFront; Vanta's default log retention for AWS, key rotation and vuln SLAs; Vanta tests for RDS backup retention days; Vanta "Database encrypted / load balancer TLS" named tests (only CIS #21 and #15 confirmed).

---

## 4. Non-infrastructure tests both tools flag (brief)

Drata (SOURCED titles from tests index; logic where fetched):

| Area | Tests |
|---|---|
| Endpoint/MDM (Drata agent or MDM) | 61 screen lock (15 min idle -> password within 60 s); 62/63 password manager required/records; 64 malware detection (agent or MDM; Windows Defender OK); 65 OS security patches auto-applied; 66 hard-disk encryption |
| Identity provider | 86 MFA on IdP (required and registered; Entra order: Security Defaults > Conditional Access > per-user; one non-compliant identity fails user); 96 unique email accounts; 87 MFA on VCS; 97 unique VCS accounts; 94 VCS accounts removed (1 business day) |
| Code repo | 5 VCS used; 6 only authorized access; 7 only authorized users with write access, matched to IdP; 8 formal code review (branch protection, see section 1); 9 production changes restricted |
| HR | 43 security awareness training (annual); 47/50 employee/contractor background checks (before hire, no day window); 45/48/49/55 policy and code-of-conduct acknowledgements; "Policies are Acknowledged"; 58 new hire contracts; 59/60 job descriptions; 46 performance evaluation; "Termination Process and Checklist" (1 business day); 17 org chart |
| Policies | 13, 16, 18, 28, 33 (IRP), 36 (SDLC), 39 (reviewed), 42, 44, 56, 67, 106 (backup), 127, 128, 136-143 etc.; approved within 12 months |
| Security process | 26 security issues prioritized (label, priority, owner), 27 SLA for security bugs; 28 DR plan; "Backups Checked for Integrity" (DR report <=12 months); IRP team/lessons learned; responsible disclosure |
| Vendors/risk/pentest | covered by Drata controls and risk register; not as numbered AWS tests in the fetched index |

Vanta (partially SOURCED): offboarding within recommended 3 days; "Vendors list maintained"; "Employee computers monitored with Vanta Agent" (third-party description); MFA on Google Workspace / Office 365 (help articles exist); version-control tests incl. "Company has a version control system", "Application changes reviewed (GitHub)", security impact in merge requests; inventory owners/user-data tests; risk review annually (editable cadence); version control tool records staleness; people/computers/policies/vendors/risk categories (Vanta API test categories: ACCOUNTS_ACCESS, ACCOUNT_SECURITY, COMPUTERS, DATA_STORAGE, EMPLOYEES, INFRASTRUCTURE, IT, LOGGING, MONITORING_ALERTS, PEOPLE, POLICIES, RISK_ANALYSIS, SECURITY_ALERT_MANAGEMENT, SOFTWARE_DEVELOPMENT, VENDORS, VULNERABILITY_MANAGEMENT; source https://developer.vanta.com/api-reference/tests/list-tests.md). Specific device-test thresholds (disk encryption, screen lock minutes, AV) were not confirmed from Vanta public pages.

---

## 5. SOC 2 TSC and ISO 27001:2022 mapping for Drata AWS tests (ALL INFERRED)

No public per-test mapping exists (Drata maps tests -> DCF controls -> framework requirements inside the app). Inferred by control semantics. Treat as hints for the skill's "why it matters" text, and verify in-app (Drata: control > Frameworks tab; Drata MCP `Drata_searchControls`).

| Drata test(s) | DCF | TSC (inferred) | ISO 27001:2022 (inferred) |
|---|---|---|---|
| 214, 225, 124 root MFA/hardware MFA/unused | DCF-90 | CC6.1, CC6.2 | A.8.2, A.8.5 |
| 88 MFA infra console | MFA on Accounts | CC6.1 | A.8.5 |
| 215, 216 password policy | DCF-346/68/350 | CC6.1 | A.5.17 |
| 217, 230 IAM least privilege | DCF-776 | CC6.3 | A.5.15, A.5.18, A.8.2 |
| 229 unused credentials; 95 terminated access | DCF-335 | CC6.2, CC6.3 | A.5.18, A.6.5 |
| 232 key rotation; 223 CMK rotation | DCF-783 / 779 | CC6.1 | A.5.17 / A.8.24 |
| 218, 231, 222, 68, 69 encryption at rest | DCF-54 | CC6.1, C1.1 | A.8.24 |
| 234, 299, 210 encryption in transit | DCF-55 | CC6.7 | A.8.24, A.5.14 |
| 104, 220, 209 public exposure | DCF-75 | CC6.1, CC6.6 | A.8.3, A.8.20, A.8.22 |
| 102, 227, 228, 233, 291, 119 network/SG | DCF-73 / DCF-85 | CC6.6 | A.8.20, A.8.22 |
| 122 WAF | "Web Application Firewall" | CC6.6, CC6.8 | A.8.20, A.8.23 |
| 105 GuardDuty | - | CC7.2 | A.8.16 |
| 221, 224, 226, 310 logging | DCF-406 | CC7.2 | A.8.15 |
| 205 CloudTrail log validation | DCF-478 | CC7.2, CC6.1 | A.8.15 |
| 111 log retention | - | CC7.2 | A.8.15 |
| 219 auto minor version upgrade | DCF-152 | CC7.1 | A.8.8 |
| 292 IMDSv1 | DCF-12 | CC7.1 | A.8.9 |
| 21, vuln tests | Quarterly Vuln Scan | CC7.1 | A.8.8 |
| 107, 108, 132-134, 301 backups/PITR | DCF-99 / DCF-86 | A1.2 | A.8.13 |
| "Backups Checked for Integrity", 28 DRP | - | A1.3, CC9.1 | A.5.30, A.5.29 |
| 30, 130, 131 availability | - | A1.1, A1.2 | A.8.14 |
| 112-118, 206, 290, 293-300 monitoring alarms | DCF-86 | A1.1, CC7.2 | A.8.6, A.8.16 |
| 8 code review | - | CC8.1 | A.8.32, A.8.28 |
| 43 training / 47 background checks | - | CC1.4 | A.6.3 / A.6.1 |
| 61 screen lock; 66 disk encryption; 64 AV; 65 patches | - | CC6.1, CC6.8 | A.8.1, A.7.7, A.8.7, A.8.8 |
| policies / acknowledgements | - | CC1.1, CC2.2 | A.5.1, A.6.3 |

Counter-note for ISO: ISO 27001 certification audits are on the ISMS and Annex A applicability (SoA); Vanta/Drata tests are evidence for A.8.x technology controls and do not replace the risk assessment/management review (clauses 4-10), which both tools flag via policy and risk tests.

---

## 6. Gaps in what Drata/Vanta check that a skill should still pre-check (INFERRED, not tool tests)
Only note for scoping: items that commonly trip these tools but are weak or absent in public catalogues: ALB/CloudFront TLS policy minimum, KMS key policy admin separation, SNS subscription confirmation for alarm tests (Drata explicitly requires confirmed subscription), AWS Config + Security Hub + Access Analyzer (Vanta CIS tests), tag hygiene (Vanta), SCP region restrictions breaking scanners, KMS key policies blocking the auditor role, S3 bucket policies blocking the auditor role.

## 7. Using the Drata MCP to cross-check (do NOT call here; design note for the skill)
Drata exposes an MCP server. A skill could, when connected to a Drata account:
- `Drata_searchMonitoringTests` (filter by AWS / failing status) to pull the live list of enabled tests and their statuses, instead of trusting this static report; tenant catalogue can differ (tests are "Unused" if the control is not in the workspace framework; new tests need Enabled).
- `Drata_getMonitoringTestFindings` per failing test to get the exact failing resource IDs/regions and the raw result (shows AccessDenied for missing IAM permissions).
- `Drata_searchControls` / `Drata_listRequirements` to get the authoritative DCF -> SOC 2 criterion / ISO 27001 Annex A requirement mapping and replace the inferred columns in section 5.
- `Drata_retestMonitoringTest` after remediation; `Drata_excludeMonitoringTestResources` for legitimate exceptions (service accounts, AdministratorAccess), `Drata_listDevices`/`searchDeviceCompliance`/`searchPersonnelCompliance` for endpoint/HR findings. Writes (exclude, retest, create) should be user-confirmed.
For Vanta there is a REST API (https://developer.vanta.com/api-reference/tests/list-tests.md: GET /tests with filters by integration "aws", status, category, framework) that serves the same cross-check role; test IDs look like `aws-account-access-removed-on-termination`.

## 8. Suggested "pre-flight" checklist for the skill, derived from sourced facts
Highest-leverage items that fail the most tests in both tools (all sourced above): root MFA (hardware for Drata 225) and no root keys; IAM password policy min 14 + reuse 24; MFA for all console IAM users; no inline/direct IAM policies, no `*:*`; keys <=90 d, unused creds <=45 d, <=1 active key; CloudTrail multi-region with log validation, KMS CMK encryption, S3 data events read+write, CloudTrail bucket access logging; VPC flow logs on all VPCs; EBS default encryption in every used region; RDS/EFS encrypted, not public, auto-minor-upgrade, backups retention >0 (use >=7 as a practical choice: INFERRED), Multi-AZ for prod; S3 Block Public Access on each bucket + deny non-TLS policy (+ versioning for Drata 108); no 0.0.0.0/0 or ::/0 on 22/3389 (and 80 for Drata 291); default SGs empty; IMDSv2 required; ALB HTTP->HTTPS redirect; GuardDuty in every active region with S3 protection; AWS Config (all regions, IAM daily) + Security Hub + Access Analyzer (Vanta); CMK rotation; log retention >= 365 days; CloudWatch alarms with confirmed SNS subscriptions on RDS CPU/storage/IO, EC2 CPU, ALB 5xx/unhealthy/latency, SQS age, Lambda errors; AWS Backup job failure alerting; WAF on public ALB/CloudFront/API GW; EKS control-plane logging; DynamoDB PITR; tags `VantaOwner`, `VantaDescription`, `VantaContainsUserData`, `VantaNonProd` (for non-prod only); IAM roles `DrataAutopilotRole` / `vanta-auditor` with SecurityAudit (+ extras) and KMS key-policy access.
