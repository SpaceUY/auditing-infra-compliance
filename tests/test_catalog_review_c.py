"""Final review C and review 2 area C: catalog content (Vanta names, Drata names, remediation blocks and their safety)."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import SKILL_DIR

import aws_runner
import catalog
import inventory
import verify_remediation
from test_verify import RULES, doc

REFS = SKILL_DIR / "references"
CHECKS = {c["id"]: c for c in catalog.load_checks(REFS / "checks")}
HAS_BASH = shutil.which("bash") is not None
HAS_JQ = shutil.which("jq") is not None
INVENTORY = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))


def commands(check_id):
    return CHECKS[check_id]["remediation"]["commands"]


def instantiate(text):
    text = re.sub(r"\{detail_json:[^}]+\}", "'[]'", text)
    for key, value in (("resource_id", "res-1"), ("region", "us-east-1"), ("account_id", "111122223333"),
                       ("resource_name", "n"), ("resource_arn", "arn:aws:s3:::x")):
        text = text.replace("{" + key + "}", value)
    return text


class VantaNameTests(unittest.TestCase):
    # Test names that the public Vanta articles do not give: the mapping is dropped ("sin test equivalente").
    NO_PUBLIC_NAME = [f"MON-00{n}" for n in range(1, 10)] + ["INT-003", "INT-004", "INV-003", "TLS-005"]

    def test_checks_without_a_public_vanta_test_name_have_no_vanta_mapping(self):
        for check_id in self.NO_PUBLIC_NAME:
            self.assertEqual(CHECKS[check_id]["mappings"]["vanta"], [], check_id)

    def test_every_vanta_name_is_in_the_research_report(self):
        research = (SKILL_DIR.parent / "docs" / "research" / "vanta-drata-tests.md").read_text(encoding="utf-8")
        for check_id, check in CHECKS.items():
            for mapping in check["mappings"]["vanta"]:
                self.assertIn(mapping["test"], research, f"{check_id}: {mapping['test']}")

    def test_vanta_names_are_not_spanish_descriptions(self):
        for check_id, check in CHECKS.items():
            for mapping in check["mappings"]["vanta"]:
                self.assertNotRegex(mapping["test"], r"[áéíóúñ¿¡]|rol vanta-auditor|\(scoping\)", check_id)


class DrataNameTests(unittest.TestCase):
    def test_catalog_names_equal_the_dcf_file(self):
        names = {t["test_id"]: t["test_name"] for t in json.loads((REFS / "mappings" / "drata-dcf.json").read_text(encoding="utf-8"))["tests"]}
        for check_id, check in CHECKS.items():
            for mapping in check["mappings"]["drata"]:
                if mapping["test"] in names:
                    self.assertEqual(mapping["name"], names[mapping["test"]], check_id)


class RemediationBlockTests(unittest.TestCase):
    def test_log_006_never_pastes_a_fixed_policy_and_keeps_existing_statements(self):
        rem = CHECKS["LOG-006"]["remediation"]
        text = "\n".join(rem["commands"])
        self.assertIn("get-bucket-policy", rem["commands"][1])
        self.assertNotIn("POLICY='", text)
        self.assertEqual(sum("put-bucket-policy" in c for c in rem["commands"]), 1)
        apply_block = rem["commands"][3]
        self.assertIn('file://policy-$BUCKET-new.json', apply_block)
        merge = rem["commands"][2]
        self.assertIn('TRAIL_PREFIX="__COMPLETAR_PREFIJO_TRAIL__"', merge)
        self.assertIn('p["Statement"]=s', merge)  # the statement list is extended, never replaced
        self.assertNotIn("put-bucket-policy", merge)

    def test_log_006_merge_script_respects_prefix_and_keeps_other_statements(self):
        if not HAS_BASH:
            self.skipTest("bash is not available")
        merge = instantiate(CHECKS["LOG-006"]["remediation"]["commands"][2])
        existing = {"Version": "2012-10-17", "Statement": [
            {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::res-1/*",
             "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
            {"Sid": "AWSCloudTrailAclCheck", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:GetBucketAcl", "Resource": "arn:aws:s3:::res-1"}]}
        arn = "arn:aws:cloudtrail:us-east-1:111122223333:trail/acme-notes"
        for prefix, expected in (("", "arn:aws:s3:::res-1/AWSLogs/111122223333/*"), ("logs/ct", "arn:aws:s3:::res-1/logs/ct/AWSLogs/111122223333/*")):
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "policy-res-1.json").write_text(json.dumps(existing), encoding="utf-8")
                script = merge.replace('"__COMPLETAR_TRAIL_ARN__"', f'"{arn}"').replace('"__COMPLETAR_PREFIJO_TRAIL__"', f'"{prefix}"')
                done = subprocess.run(["bash", "-c", script], cwd=tmp, capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, done.stderr)
                merged = json.loads((Path(tmp) / "policy-res-1-new.json").read_text(encoding="utf-8"))
            sids = [s["Sid"] for s in merged["Statement"]]
            self.assertEqual(sids, ["DenyInsecureTransport", "AWSCloudTrailAclCheck", "AWSCloudTrailWrite"])
            acl = merged["Statement"][1]
            self.assertEqual(acl["Condition"]["StringEquals"]["aws:SourceArn"], arn)  # existing CloudTrail statement gains the condition
            self.assertEqual(merged["Statement"][2]["Resource"], expected)

    def test_log_006_without_a_bucket_policy_merge_starts_from_an_empty_policy(self):
        if not HAS_BASH:
            self.skipTest("bash is not available")
        commands_ = CHECKS["LOG-006"]["remediation"]["commands"]
        fetch, merge = instantiate(commands_[1]), instantiate(commands_[2])
        merge = merge.replace('"__COMPLETAR_TRAIL_ARN__"', '"arn:aws:cloudtrail:us-east-1:111122223333:trail/acme-notes"')
        merge = merge.replace('"__COMPLETAR_PREFIJO_TRAIL__"', '""')
        # stub: never the real aws CLI. get-bucket-policy fails like NoSuchBucketPolicy
        stub = 'aws() { echo "An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation" >&2; return 254; }\n'
        with tempfile.TemporaryDirectory() as tmp:
            done = subprocess.run(["bash", "-c", stub + fetch + "\n" + merge], cwd=tmp, capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            merged = json.loads((Path(tmp) / "policy-res-1-new.json").read_text(encoding="utf-8"))
        self.assertEqual([s["Sid"] for s in merged["Statement"]], ["AWSCloudTrailAclCheck", "AWSCloudTrailWrite"])

    def test_log_006_other_read_errors_stop_and_produce_no_merged_policy(self):
        if not HAS_BASH:
            self.skipTest("bash is not available")
        commands_ = CHECKS["LOG-006"]["remediation"]["commands"]
        fetch, merge = instantiate(commands_[1]), instantiate(commands_[2])
        merge = merge.replace('"__COMPLETAR_TRAIL_ARN__"', '"arn:aws:cloudtrail:us-east-1:111122223333:trail/acme-notes"')
        merge = merge.replace('"__COMPLETAR_PREFIJO_TRAIL__"', '""')
        # stub: never the real aws CLI. get-bucket-policy is denied, so an existing policy may be hidden
        stub = 'aws() { echo "An error occurred (AccessDenied) when calling the GetBucketPolicy operation" >&2; return 254; }\n'
        with tempfile.TemporaryDirectory() as tmp:
            done = subprocess.run(["bash", "-c", stub + fetch + "\n" + merge], cwd=tmp, capture_output=True, text=True)
            self.assertIn("DETENIDO", done.stdout)
            self.assertFalse((Path(tmp) / "policy-res-1-new.json").exists())

    def test_log_006_notes_warn_that_the_merge_is_scoped_to_one_trail(self):
        notes = CHECKS["LOG-006"]["remediation"]["notes"]
        self.assertIn("ESTE trail", notes)
        self.assertIn("varios trails", notes)

    def test_log_006_merge_refuses_unfilled_placeholders(self):
        if not HAS_BASH:
            self.skipTest("bash is not available")
        merge = instantiate(CHECKS["LOG-006"]["remediation"]["commands"][2])
        with tempfile.TemporaryDirectory() as tmp:
            done = subprocess.run(["bash", "-c", merge], cwd=tmp, capture_output=True, text=True)
            self.assertNotEqual(done.returncode, 0)
            self.assertFalse((Path(tmp) / "policy-res-1-new.json").exists())

    def test_net_001_002_004_are_cli_with_decision(self):
        for check_id in ("NET-001", "NET-002", "NET-004"):
            self.assertEqual(CHECKS[check_id]["remediation"]["kind"], "cli_with_decision", check_id)

    def test_enc_003_cluster_block_sets_subnet_group_and_security_group(self):
        block = commands("ENC-003")[1]
        self.assertIn('SUBNET_GROUP="__COMPLETAR_DB_SUBNET_GROUP__"', block)
        self.assertIn('SG_ID="__COMPLETAR_SECURITY_GROUP_ID__"', block)
        self.assertRegex(block, r'restore-db-cluster-from-snapshot [^\n]*--db-subnet-group-name "\$SUBNET_GROUP" --vpc-security-group-ids "\$SG_ID"')

    def test_enc_002_reads_the_source_volume_instead_of_hardcoding_gp3(self):
        rem = CHECKS["ENC-002"]["remediation"]
        block = rem["commands"][1]
        self.assertNotIn("--volume-type gp3", block)
        self.assertIn('describe-volumes --volume-ids "$VOLUME_ID"', block)
        for query in ("Volumes[0].VolumeType", "Volumes[0].Iops", "Volumes[0].Throughput"):
            self.assertIn(query, block)
        self.assertRegex(block, r'create-volume [^\n]*--volume-type "\$VOL_TYPE" \$IOPS_ARG \$THR_ARG')
        self.assertIn("instance store", rem["notes"])

    def test_eml_001_first_block_says_when_to_use_it(self):
        self.assertIn("solo si la identidad usa BYODKIM o no tiene Easy DKIM", commands("EML-001")[0])

    def test_dat_003_is_medium_risk_so_it_leaves_the_low_risk_bulk_copy(self):
        self.assertEqual(CHECKS["DAT-003"]["remediation"]["risk"], "medium")

    def test_eml_005_notes_mention_inheritance_from_the_organizational_domain(self):
        notes = CHECKS["EML-005"]["remediation"]["notes"]
        self.assertIn("RFC 7489", notes)
        self.assertRegex(notes, r"(?i)dominio padre")


def fix_findings(check_ids=None):
    """One FAIL finding per catalog check that has commands, with the catalog placeholders filled in."""
    findings = []
    for number, (check_id, check) in enumerate(CHECKS.items()):
        rem = check["remediation"]
        if (check_ids and check_id not in check_ids) or not rem or not rem.get("commands"):
            continue
        findings.append({
            "id": f"F-{number:04d}", "check_id": check_id, "title": check["title"], "domain": "x", "status": "FAIL",
            "severity": check["severity"], "resource": {"type": "x", "id": "res-1", "region": "us-east-1", "name": "n"},
            "remediation": {"kind": rem["kind"], "risk": rem["risk"], "downtime": rem["downtime"],
                            "steps": [instantiate(s) for s in rem["steps"]], "notes": instantiate(rem["notes"]),
                            "verify_after": instantiate(rem["verify_after"]), "commands": [instantiate(c) for c in rem["commands"]]},
            "evidence": {}, "depends_on_me": [], "missing": []})
    return findings


@unittest.skipUnless(HAS_BASH, "bash is not available")
class CatalogWideSweepTests(unittest.TestCase):
    """Review 2 C, I6: the verifier runs over EVERY catalog fix. Nothing is allowlisted: a new fix that replaces or deletes
    without a warning, or that has a syntax or hygiene problem, fails here before a user sees REVISAR."""

    @classmethod
    def setUpClass(cls):
        cls.findings = fix_findings()
        cls.result = verify_remediation.verify(doc(*cls.findings), [], RULES, runner=subprocess.run)

    def test_the_sweep_covers_every_check_that_has_commands(self):
        with_commands = [c for c in CHECKS.values() if c["remediation"] and c["remediation"].get("commands")]
        self.assertEqual(len(self.findings), len(with_commands))
        self.assertGreaterEqual(len(self.findings), 80)

    def test_no_fix_has_syntax_hygiene_unresolved_placeholder_or_unwarned_destructive_issues(self):
        bad = {"syntax", "higiene", "placeholder_sin_resolver", "destructivo_sin_aviso"}
        for finding in self.findings:
            kinds = {i["kind"] for i in self.result["per_finding"][finding["id"]]["issues"]}
            self.assertFalse(kinds & bad, (finding["check_id"], finding["remediation"]["kind"], kinds & bad))

    def test_a_destructive_or_replacing_command_is_never_a_plain_cli_fix(self):
        for finding in self.findings:
            rem = finding["remediation"]
            ops = verify_remediation._destructive_operations(rem["commands"])
            if ops:
                self.assertIn(rem["kind"], ("planned_change", "cli_with_decision"), (finding["check_id"], ops))
                self.assertTrue(verify_remediation._has_warning(rem), (finding["check_id"], ops, "las notas no advierten"))

    def test_downtime_is_never_a_plain_cli_fix(self):
        for check_id, check in CHECKS.items():
            rem = check["remediation"]
            if rem and rem["downtime"]:
                self.assertNotEqual(rem["kind"], "cli", check_id)

    def test_a_cli_fix_with_several_blocks_has_no_alternative_blocks(self):
        # "Copiar todo" pastes every block of a cli card: blocks that are alternatives of each other must be one conditional block
        alternative = re.compile(r"#\s*(solo (si|para)|instancia que no|miembro de un cluster|alternativ)", re.I)
        for check_id, check in CHECKS.items():
            rem = check["remediation"]
            if rem and rem["kind"] == "cli" and len(rem.get("commands") or []) > 1:
                for command in rem["commands"]:
                    self.assertIsNone(alternative.search(command), (check_id, command[:120]))

    def test_every_command_and_verify_after_is_valid_bash_after_substitution(self):
        for check_id, check in CHECKS.items():
            rem = check["remediation"]
            if not rem:
                continue
            for text in [*(rem.get("commands") or []), rem.get("verify_after") or ""]:
                done = subprocess.run(["bash", "-n"], input=instantiate(text), capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, f"{check_id}: {done.stderr}")

    def test_every_check_with_a_fix_declares_the_kind_its_commands_need(self):
        for check_id, check in CHECKS.items():
            rem = check["remediation"]
            if rem and rem["kind"] == "console_only":
                self.assertFalse(rem.get("commands"), check_id)
            if rem and rem["kind"] == "planned_change":
                self.assertGreaterEqual(len(rem["steps"]), 2, check_id)


class PlaceholderResolvabilityTests(unittest.TestCase):
    """Review 2 C, I5/I6: every {placeholder} a fix uses is resolvable for every resource type of its check."""

    def test_resource_arn_exists_for_every_type_of_a_check_that_uses_it(self):
        for check_id, check in CHECKS.items():
            rem = check["remediation"]
            if not rem or "{resource_arn}" not in json.dumps(rem):
                continue
            for resource_type in check["resource_types"]:
                has_arn = bool(INVENTORY[resource_type]["arn_path"]) or resource_type in inventory.ARN_FORMATS
                self.assertTrue(has_arn, f"{check_id}: el tipo {resource_type} no tiene ARN en el inventario")

    def test_only_known_placeholders_are_used(self):
        known = re.compile(r"\{(resource_id|region|account_id|resource_name|resource_arn|detail_json:[A-Za-z0-9_]+)\}")
        for check_id, check in CHECKS.items():
            rem = check["remediation"]
            text = json.dumps(rem or {}, ensure_ascii=False)
            leftover = re.sub(known, "", text)
            # a remaining {word} would be a typo of a placeholder (JSON, JMESPath and bash braces are not words alone)
            self.assertIsNone(re.search(r"\{[a-z_]+\}", leftover), check_id)


class InventoryArnTests(unittest.TestCase):
    """Review 2 C, I5: the inventory builds the ARN of the types whose listing carries none."""

    def listing(self, region="us-east-1", partition_region=None):
        shown = partition_region or region
        data = {
            ("ec2", "describe-instances"): {"Reservations": [{"Instances": [{"InstanceId": "i-0123456789abcdef0"}]}]},
            ("ec2", "describe-volumes"): {"Volumes": [{"VolumeId": "vol-0123456789abcdef0"}]},
            ("s3api", "list-buckets"): {"Buckets": [{"Name": "acme-notes-uploads"}]},
            ("dynamodb", "list-tables"): {"TableNames": ["acme-notes-sessions"]},
            ("sqs", "list-queues"): {"QueueUrls": [f"https://sqs.{shown}.amazonaws.com/111122223333/acme-notes-mail-queue"]},
            ("eks", "list-clusters"): {"clusters": ["acme-notes-eks"]},
        }

        def call(service, operation, args, called_region):
            payload = data.get((service, operation))
            return aws_runner.CallResult(payload is not None, payload, None, None, ("aws", service, operation))

        specs = {t: INVENTORY[t] for t in ("ec2_instance", "ebs_volume", "s3_bucket", "dynamodb_table", "sqs_queue", "eks_cluster")}
        items, _ = inventory.build_inventory(call, specs, [region], account_id="111122223333")
        return {i["type"]: i for i in items}

    def test_arns_are_built_from_partition_region_account_and_id(self):
        items = self.listing()
        self.assertEqual(items["ec2_instance"]["arn"], "arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0")
        self.assertEqual(items["ebs_volume"]["arn"], "arn:aws:ec2:us-east-1:111122223333:volume/vol-0123456789abcdef0")
        self.assertEqual(items["s3_bucket"]["arn"], "arn:aws:s3:::acme-notes-uploads")
        self.assertEqual(items["dynamodb_table"]["arn"], "arn:aws:dynamodb:us-east-1:111122223333:table/acme-notes-sessions")
        self.assertEqual(items["sqs_queue"]["arn"], "arn:aws:sqs:us-east-1:111122223333:acme-notes-mail-queue")
        self.assertEqual(items["eks_cluster"]["arn"], "arn:aws:eks:us-east-1:111122223333:cluster/acme-notes-eks")

    def test_the_partition_follows_the_region(self):
        items = self.listing(region="cn-north-1")
        self.assertEqual(items["ec2_instance"]["arn"], "arn:aws-cn:ec2:cn-north-1:111122223333:instance/i-0123456789abcdef0")
        items = self.listing(region="us-gov-west-1")
        self.assertTrue(items["eks_cluster"]["arn"].startswith("arn:aws-us-gov:eks:us-gov-west-1:"))

    def test_without_an_account_the_arn_stays_empty_instead_of_being_wrong(self):
        specs = {"ec2_instance": INVENTORY["ec2_instance"], "s3_bucket": INVENTORY["s3_bucket"]}
        data = {("ec2", "describe-instances"): {"Reservations": [{"Instances": [{"InstanceId": "i-0123456789abcdef0"}]}]},
                ("s3api", "list-buckets"): {"Buckets": [{"Name": "b"}]}}
        call = lambda s, o, a, r: aws_runner.CallResult(True, data[(s, o)], None, None, ("aws", s, o))  # noqa: E731
        items, _ = inventory.build_inventory(call, specs, ["us-east-1"])
        by_type = {i["type"]: i["arn"] for i in items}
        self.assertEqual(by_type["ec2_instance"], "")  # needs the account
        self.assertEqual(by_type["s3_bucket"], "arn:aws:s3:::b")  # needs nothing

    def test_a_listed_arn_is_never_replaced_by_a_built_one(self):
        specs = {"rds_instance": INVENTORY["rds_instance"]}
        data = {("rds", "describe-db-instances"): {"DBInstances": [{"DBInstanceIdentifier": "db1", "DBInstanceArn": "arn:aws:rds:us-east-1:111122223333:db:db1"}]}}
        call = lambda s, o, a, r: aws_runner.CallResult(True, data[(s, o)], None, None, ("aws", s, o))  # noqa: E731
        items, _ = inventory.build_inventory(call, specs, ["us-east-1"], account_id="999999999999")
        self.assertEqual(items[0]["arn"], "arn:aws:rds:us-east-1:111122223333:db:db1")

    def test_collect_passes_the_account_to_the_inventory(self):
        text = (SKILL_DIR / "scripts" / "collect.py").read_text(encoding="utf-8")
        self.assertIn("build_inventory(list_inventory, specs, inventory_regions, account_id=account_id)", text)


def run_blocks(blocks, stub_body, files=None):
    """Run catalog command strings one after the other, each in its own bash (files persist, shell variables do not, like
    separate pastes in CloudShell), inside a temp dir and with a stub `aws` shell function: the real CLI is never run.
    The stub logs every call to calls.log. Returns ([(returncode, stdout)], calls, files after)."""
    stub = 'aws() { echo "$*" >> calls.log; ' + stub_body + "; }\n"
    with tempfile.TemporaryDirectory() as tmp:
        for name, text in (files or {}).items():
            (Path(tmp) / name).write_text(text, encoding="utf-8")
        outcomes = []
        for block in blocks:
            done = subprocess.run(["bash", "-c", stub + block], cwd=tmp, capture_output=True, text=True)
            outcomes.append((done.returncode, done.stdout + done.stderr))
        calls = (Path(tmp) / "calls.log").read_text(encoding="utf-8").splitlines() if (Path(tmp) / "calls.log").exists() else []
        after = {p.name: p.read_text(encoding="utf-8") for p in Path(tmp).iterdir() if p.is_file() and p.name != "calls.log"}
    return outcomes, calls, after


def catalog_blocks(check_id, *indexes):
    commands_ = commands(check_id)
    return [instantiate(commands_[i]) for i in (indexes or range(len(commands_)))]


def aws_calls(calls, verb):
    return [c for c in calls if f" {verb}" in f" {c}"]


@unittest.skipUnless(HAS_BASH, "bash is not available")
class PasswordPolicyFixTests(unittest.TestCase):
    """Review 2 C, I1: IAM-006/007 read the current policy first and merge; nothing is silently reset."""

    CURRENT = {"MinimumPasswordLength": 8, "PasswordReusePrevention": 5, "MaxPasswordAge": 90, "HardExpiry": True,
               "RequireSymbols": False, "AllowUsersToChangePassword": False}

    def stub(self, policy=None, error=None):
        if error:
            return f'if [ "$2" = get-account-password-policy ]; then echo "{error}" >&2; return 254; fi'
        return f"if [ \"$2\" = get-account-password-policy ]; then echo '{json.dumps(policy)}'; fi"

    def test_both_checks_are_cli_with_decision_with_a_real_warning_and_read_first(self):
        for check_id in ("IAM-006", "IAM-007"):
            rem = CHECKS[check_id]["remediation"]
            self.assertEqual(rem["kind"], "cli_with_decision", check_id)
            self.assertTrue(verify_remediation.WARNING_WORDS.search(rem["notes"]), check_id)
            self.assertIn("get-account-password-policy", rem["commands"][0])
            self.assertEqual("\n".join(rem["commands"]).count("then aws iam update-account-password-policy"), 1)
            self.assertNotIn("update-account-password-policy --minimum", "\n".join(rem["commands"]))  # no fixed one-liner

    def test_the_merge_keeps_expiry_hard_expiry_and_the_change_permission_and_only_raises_length_and_reuse(self):
        for check_id in ("IAM-006", "IAM-007"):
            outcomes, calls, files = run_blocks(catalog_blocks(check_id), self.stub(self.CURRENT))
            self.assertEqual([o[0] for o in outcomes], [0, 0, 0], outcomes)
            args = files["password-policy-nuevo.args"].split()
            self.assertEqual(args[args.index("--max-password-age") + 1], "90")
            self.assertIn("--hard-expiry", args)
            self.assertIn("--no-allow-users-to-change-password", args)
            self.assertEqual(args[args.index("--minimum-password-length") + 1], "14")
            self.assertEqual(args[args.index("--password-reuse-prevention") + 1], "24")
            for flag in ("--require-symbols", "--require-numbers", "--require-uppercase-characters", "--require-lowercase-characters"):
                self.assertIn(flag, args)
            (applied,) = aws_calls(calls, "iam update-account-password-policy")
            self.assertEqual(applied.split(), ["iam", "update-account-password-policy", *args])

    def test_a_stronger_current_length_and_reuse_are_never_lowered(self):
        outcomes, calls, files = run_blocks(catalog_blocks("IAM-006"), self.stub({"MinimumPasswordLength": 20, "PasswordReusePrevention": 30}))
        args = files["password-policy-nuevo.args"].split()
        self.assertEqual(args[args.index("--minimum-password-length") + 1], "20")
        self.assertEqual(args[args.index("--password-reuse-prevention") + 1], "30")
        self.assertEqual(args[args.index("--max-password-age") + 1], "0")  # no expiry stays no expiry
        self.assertIn("--no-hard-expiry", args)
        self.assertIn("--allow-users-to-change-password", args)

    def test_an_account_without_a_policy_starts_from_an_empty_one(self):
        error = "An error occurred (NoSuchEntity) when calling the GetAccountPasswordPolicy operation"
        outcomes, calls, files = run_blocks(catalog_blocks("IAM-006"), self.stub(error=error))
        self.assertEqual([o[0] for o in outcomes], [0, 0, 0], outcomes)
        self.assertIn("--minimum-password-length 14", files["password-policy-nuevo.args"])
        self.assertEqual(len(aws_calls(calls, "iam update-account-password-policy")), 1)

    def test_a_read_error_stops_everything_and_nothing_is_applied(self):
        error = "An error occurred (AccessDenied) when calling the GetAccountPasswordPolicy operation"
        outcomes, calls, files = run_blocks(catalog_blocks("IAM-006"), self.stub(error=error))
        self.assertIn("DETENIDO", outcomes[0][1])
        self.assertIn("DETENIDO", outcomes[1][1])
        self.assertIn("DETENIDO", outcomes[2][1])
        self.assertNotIn("password-policy-nuevo.args", files)
        self.assertEqual(aws_calls(calls, "iam update-account-password-policy"), [])

    def test_a_stale_args_file_from_an_earlier_run_is_never_applied_after_a_failed_read(self):
        error = "An error occurred (AccessDenied) when calling the GetAccountPasswordPolicy operation"
        blocks = catalog_blocks("IAM-006")
        outcomes, calls, files = run_blocks([blocks[0], blocks[2]], self.stub(error=error), files={"password-policy-nuevo.args": "--minimum-password-length 5\n"})
        self.assertEqual(aws_calls(calls, "iam update-account-password-policy"), [])
        self.assertIn("DETENIDO", outcomes[1][1])

    def test_the_apply_block_alone_refuses_without_the_reviewed_file(self):
        outcomes, calls, _ = run_blocks([catalog_blocks("IAM-006")[2]], self.stub(self.CURRENT))
        self.assertIn("DETENIDO", outcomes[0][1])
        self.assertEqual(calls, [])


@unittest.skipUnless(HAS_BASH, "bash is not available")
class KindsFollowTheGuidelinesTests(unittest.TestCase):
    """Review 2 C, I1 and fix B M11: the kind says what the card is. Alternative blocks are never one-click copied."""

    def test_replacing_or_downtime_fixes_have_the_kind_the_guidelines_define(self):
        expected = {"IAM-006": "cli_with_decision", "IAM-007": "cli_with_decision", "IAM-009": "cli_with_decision",
                    "DAT-001": "planned_change", "EML-002": "cli_with_decision", "ENC-005": "cli_with_decision",
                    "DAT-006": "cli_with_decision", "TLS-002": "cli_with_decision", "TLS-003": "cli_with_decision",
                    "INT-002": "cli_with_decision", "LOG-009": "cli_with_decision", "LOG-012": "cli_with_decision"}
        for check_id, kind in expected.items():
            self.assertEqual(CHECKS[check_id]["remediation"]["kind"], kind, check_id)

    def test_fixes_that_had_alternative_blocks_are_one_conditional_block_or_not_cli(self):
        for check_id in ("DAT-004", "DET-001", "DET-004"):
            rem = CHECKS[check_id]["remediation"]
            self.assertEqual(rem["kind"], "cli", check_id)
            self.assertEqual(len(rem["commands"]), 1, check_id)
        for check_id in ("DAT-001", "EML-002"):
            self.assertNotEqual(CHECKS[check_id]["remediation"]["kind"], "cli", check_id)

    def test_dat_004_applies_to_the_cluster_when_there_is_one_and_to_the_instance_otherwise(self):
        block = catalog_blocks("DAT-004")[0]
        for cluster, expected, other in (("aurora-1", "modify-db-cluster", "modify-db-instance"), ("None", "modify-db-instance", "modify-db-cluster")):
            _, calls, _ = run_blocks([block], f'if [ "$2" = describe-db-instances ]; then echo "{cluster}"; fi')
            self.assertEqual(len(aws_calls(calls, "rds " + expected)), 1, calls)
            self.assertEqual(aws_calls(calls, "rds " + other), [], calls)

    def test_det_001_creates_a_detector_only_when_none_exists_and_otherwise_reenables_it(self):
        block = catalog_blocks("DET-001")[0]
        _, calls, _ = run_blocks([block], 'if [ "$2" = list-detectors ]; then echo None; fi')
        self.assertEqual((len(aws_calls(calls, "guardduty create-detector")), len(aws_calls(calls, "guardduty update-detector"))), (1, 0))
        _, calls, _ = run_blocks([block], 'if [ "$2" = list-detectors ]; then echo abc123def456; fi')
        self.assertEqual((len(aws_calls(calls, "guardduty create-detector")), len(aws_calls(calls, "guardduty update-detector"))), (0, 1))
        self.assertIn("--detector-id abc123def456", aws_calls(calls, "guardduty update-detector")[0])

    def test_det_004_enables_the_hub_only_when_missing_and_the_standard_only_after_that_succeeded(self):
        block = catalog_blocks("DET-004")[0]
        _, calls, _ = run_blocks([block], 'if [ "$2" = describe-hub ]; then return 0; fi')
        self.assertEqual((len(aws_calls(calls, "securityhub enable-security-hub")), len(aws_calls(calls, "securityhub batch-enable-standards"))), (0, 1))
        _, calls, _ = run_blocks([block], 'if [ "$2" = describe-hub ]; then return 254; fi')
        self.assertEqual((len(aws_calls(calls, "securityhub enable-security-hub")), len(aws_calls(calls, "securityhub batch-enable-standards"))), (1, 1))
        _, calls, _ = run_blocks([block], 'if [ "$2" = describe-hub ] || [ "$2" = enable-security-hub ]; then return 254; fi')
        self.assertEqual(aws_calls(calls, "securityhub batch-enable-standards"), [])


@unittest.skipUnless(HAS_BASH, "bash is not available")
class Tls002GuardTests(unittest.TestCase):
    """Review 2 C, I4: the redirect only runs when an HTTPS:443 listener exists."""

    def stub(self, https_443):
        return ('case "$2" in describe-load-balancers) echo arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/x/1;;'
                f' describe-listeners) case "$*" in *"length("*) echo {https_443};; *) echo arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/app/x/1/2;; esac;; esac')

    def test_with_an_https_443_listener_every_http_listener_is_redirected(self):
        outcomes, calls, _ = run_blocks(catalog_blocks("TLS-002"), self.stub(1))
        self.assertEqual(len(aws_calls(calls, "elbv2 modify-listener")), 1)
        self.assertNotIn("DETENIDO", outcomes[0][1])

    def test_without_one_it_stops_and_changes_nothing(self):
        for count in ("0", "None", ""):
            outcomes, calls, _ = run_blocks(catalog_blocks("TLS-002"), self.stub(count))
            self.assertEqual(aws_calls(calls, "elbv2 modify-listener"), [], count)
            self.assertIn("DETENIDO", outcomes[0][1], count)

    def test_the_guard_asks_for_protocol_https_and_port_443_exactly(self):
        text = commands("TLS-002")[0]
        self.assertIn("Protocol==`HTTPS` && Port==`443`", text)
        self.assertLess(text.index("DETENIDO"), text.index("modify-listener"))

    def test_the_card_warns_and_is_not_a_plain_cli_fix(self):
        rem = CHECKS["TLS-002"]["remediation"]
        self.assertEqual(rem["kind"], "cli_with_decision")
        self.assertIn("DETENIDO", rem["notes"])


@unittest.skipUnless(HAS_BASH, "bash is not available")
class Tls001MergeTests(unittest.TestCase):
    """Review 2 C, M1: TLS-001 never overwrites an existing bucket policy."""

    EXISTING = {"Version": "2012-10-17", "Statement": [{"Sid": "AllowCloudFront", "Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
                                                         "Action": "s3:GetObject", "Resource": "arn:aws:s3:::res-1/*"}]}

    def test_an_existing_policy_keeps_its_statements_and_gains_the_deny(self):
        stub = f"if [ \"$2\" = get-bucket-policy ]; then echo '{json.dumps(self.EXISTING)}'; fi"
        outcomes, calls, files = run_blocks(catalog_blocks("TLS-001"), stub)
        self.assertEqual([o[0] for o in outcomes], [0, 0, 0], outcomes)
        merged = json.loads(files["policy-res-1-new.json"])
        self.assertEqual([s["Sid"] for s in merged["Statement"]], ["AllowCloudFront", "DenyInsecureTransport"])
        self.assertEqual(len(aws_calls(calls, "s3api put-bucket-policy")), 1)

    def test_a_bucket_without_policy_starts_from_an_empty_one(self):
        stub = 'if [ "$2" = get-bucket-policy ]; then echo "An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation" >&2; return 254; fi'
        outcomes, _, files = run_blocks(catalog_blocks("TLS-001"), stub)
        self.assertEqual([s["Sid"] for s in json.loads(files["policy-res-1-new.json"])["Statement"]], ["DenyInsecureTransport"])

    def test_a_read_error_leaves_no_file_to_apply_and_applies_nothing(self):
        stub = 'if [ "$2" = get-bucket-policy ]; then echo "An error occurred (AccessDenied) when calling the GetBucketPolicy operation" >&2; return 254; fi'
        outcomes, calls, files = run_blocks(catalog_blocks("TLS-001"), stub, files={"policy-res-1-new.json": "{}"})
        self.assertTrue(all("DETENIDO" in o[1] for o in outcomes), outcomes)
        self.assertEqual(aws_calls(calls, "s3api put-bucket-policy"), [])
        self.assertNotIn("policy-res-1-new.json", files)

    def test_no_block_writes_a_policy_from_scratch_over_an_existing_one(self):
        self.assertNotIn("echo '{", "\n".join(commands("TLS-001")[1:]))


@unittest.skipUnless(HAS_BASH, "bash is not available")
class Enc002OrderTests(unittest.TestCase):
    """Review 2 C, I2: the instance is stopped BEFORE the snapshot, so no write is lost."""

    def stub(self, instance_state, attached=True):
        attachments = "i-0123456789abcdef0" if attached else "None"
        return ('case "$2" in describe-volumes) case "$*" in *Attachments*) echo ' + attachments + ';; *VolumeType*) echo gp3;; *) echo None;; esac;;'
                f' describe-instances) echo {instance_state};; create-snapshot) echo snap-1;; copy-snapshot) echo snap-2;; create-volume) echo vol-new;; esac')

    def blocks(self):
        return [b.replace("__COMPLETAR_INSTANCE_ID__", "i-0123456789abcdef0").replace("__COMPLETAR_KMS_KEY_ID__", "alias/aws/ebs")
                 .replace("__COMPLETAR_ZONA_DISPONIBILIDAD__", "us-east-1a").replace("__COMPLETAR_VOLUME_ID_CIFRADO__", "vol-new")
                 .replace("__COMPLETAR_DISPOSITIVO__", "/dev/xvda") for b in catalog_blocks("ENC-002")]

    def test_the_stop_is_the_first_block_and_the_snapshot_comes_later(self):
        first, second, third = commands("ENC-002")
        self.assertIn("stop-instances", first)
        self.assertNotIn("create-snapshot", first)
        self.assertIn("create-snapshot", second)
        self.assertNotIn("stop-instances", second + third)
        self.assertIn("detach-volume", third)

    def test_in_order_the_calls_stop_then_snapshot_then_swap(self):
        _, calls, _ = run_blocks(self.blocks(), self.stub("stopped"))
        verbs = [c.split()[1] for c in calls if c.startswith("ec2")]
        self.assertLess(verbs.index("stop-instances"), verbs.index("create-snapshot"))
        self.assertLess(verbs.index("create-snapshot"), verbs.index("detach-volume"))
        self.assertLess(verbs.index("detach-volume"), verbs.index("attach-volume"))
        self.assertLess(verbs.index("attach-volume"), verbs.index("start-instances"))

    def test_the_snapshot_block_refuses_while_the_instance_is_running(self):
        outcomes, calls, _ = run_blocks([self.blocks()[1]], self.stub("running"))
        self.assertIn("DETENIDO", outcomes[0][1])
        self.assertEqual(aws_calls(calls, "ec2 create-snapshot"), [])

    def test_an_unattached_volume_needs_no_stop(self):
        outcomes, calls, _ = run_blocks([self.blocks()[1]], self.stub("running", attached=False))
        self.assertNotIn("DETENIDO", outcomes[0][1])
        self.assertEqual(len(aws_calls(calls, "ec2 create-snapshot")), 1)

    def test_notes_say_the_old_volume_keeps_the_latest_data(self):
        notes = CHECKS["ENC-002"]["remediation"]["notes"]
        self.assertIn("ANTES del snapshot", notes)
        self.assertIn("datos más recientes", notes)
        self.assertEqual(CHECKS["ENC-002"]["remediation"]["kind"], "planned_change")


class Enc003ExposureTests(unittest.TestCase):
    """Review 2 C, I3 and fix B leftover: the replacement database is never more exposed than the original."""

    def test_both_restore_paths_pass_no_publicly_accessible(self):
        instance_block, cluster_block = commands("ENC-003")
        self.assertRegex(instance_block, r"restore-db-instance-from-db-snapshot [^\n]*--no-publicly-accessible")
        self.assertRegex(cluster_block, r"create-db-instance [^\n]*--no-publicly-accessible")

    def test_the_notes_list_what_the_restore_does_not_inherit_including_exposure_settings(self):
        notes = CHECKS["ENC-003"]["remediation"]["notes"]
        for word in ("acceso público", "protección contra borrado", "versiones menores", "exportación de logs", "ventana de mantenimiento", "Multi-AZ"):
            self.assertIn(word, notes)

    def test_verify_after_is_scoped_to_the_resource_not_region_wide(self):
        verify = CHECKS["ENC-003"]["remediation"]["verify_after"]
        self.assertIn("{resource_id}", verify)
        self.assertIn("StorageEncrypted", verify)
        self.assertNotIn("StorageEncrypted==`false`", verify)

    @unittest.skipUnless(HAS_BASH, "bash is not available")
    def test_the_instance_restore_runs_in_order_with_the_flag(self):
        blocks = [b.replace("__COMPLETAR_ID_BASE_NUEVA__", "res-1-nueva").replace("__COMPLETAR_KMS_KEY_ID__", "alias/aws/rds")
                   .replace("__COMPLETAR_DB_SUBNET_GROUP__", "sg-db").replace("__COMPLETAR_SECURITY_GROUP_ID__", "sg-0123")
                   .replace("__COMPLETAR_PARAMETER_GROUP__", "default.postgres16") for b in catalog_blocks("ENC-003", 0)]
        _, calls, _ = run_blocks(blocks, "return 0")
        restore = aws_calls(calls, "rds restore-db-instance-from-db-snapshot")
        self.assertEqual(len(restore), 1)
        self.assertIn("--no-publicly-accessible", restore[0])
        verbs = [c.split()[1] for c in calls if c.startswith("rds")]
        self.assertLess(verbs.index("create-db-snapshot"), verbs.index("copy-db-snapshot"))


@unittest.skipUnless(HAS_BASH, "bash is not available")
class SmallCatalogFixTests(unittest.TestCase):
    """Review 2 C minors: INT-004 file names, DET-005 delivery channel guard, notes for CMP-002 / NET-005."""

    @unittest.skipUnless(HAS_JQ, "jq is not available")
    def test_int_004_files_carry_the_key_id_whether_the_id_is_a_uuid_or_an_arn(self):
        uuid = "1234abcd-12ab-34cd-56ef-1234567890ab"
        policy = {"Version": "2012-10-17", "Statement": [{"Sid": "Root", "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                                                          "Action": "kms:*", "Resource": "*"}]}
        stub = f"if [ \"$2\" = get-key-policy ]; then echo '{json.dumps(policy)}'; fi"
        for key in (uuid, f"arn:aws:kms:us-east-1:111122223333:key/{uuid}"):
            blocks = [instantiate(c.replace("{resource_id}", key)) for c in commands("INT-004")]
            outcomes, calls, files = run_blocks(blocks, stub)
            self.assertEqual(sorted(files), [f"key-policy-{uuid}-nuevo.json", f"key-policy-{uuid}.json"], key)
            statements = json.loads(files[f"key-policy-{uuid}-nuevo.json"])["Statement"]
            self.assertEqual([s["Sid"] for s in statements], ["Root", "AllowAuditorRead"])
            self.assertEqual(len(aws_calls(calls, "kms put-key-policy")), 1)

    def test_int_004_does_not_apply_a_file_left_by_another_key(self):
        _, calls, _ = run_blocks([instantiate(commands("INT-004")[2])], "return 0", files={"key-policy-nuevo.json": "{}", "key-policy-otra-clave-nuevo.json": "{}"})
        self.assertEqual(aws_calls(calls, "kms put-key-policy"), [])

    def test_det_005_stops_when_the_region_already_has_a_delivery_channel(self):
        blocks = [b.replace("__COMPLETAR_BUCKET_CONFIG__", "acme-notes-config") for b in catalog_blocks("DET-005", 1)]
        outcomes, calls, _ = run_blocks(blocks, 'if [ "$2" = describe-delivery-channels ]; then echo 1; fi')
        self.assertIn("DETENIDO", outcomes[0][1])
        self.assertEqual(aws_calls(calls, "configservice put-"), [])
        _, calls, _ = run_blocks(blocks, 'if [ "$2" = describe-delivery-channels ]; then echo 0; fi')
        self.assertEqual(len(aws_calls(calls, "configservice put-delivery-channel")), 1)

    def test_cmp_002_and_net_005_notes_mention_the_side_effects(self):
        self.assertIn("TODOS los que lo usan", CHECKS["CMP-002"]["remediation"]["notes"])
        notes = CHECKS["NET-005"]["remediation"]["notes"]
        for word in ("ESP", "GRE"):
            self.assertIn(word, notes)

    def test_eml_006_mapping_is_not_a_stretch_to_cryptography(self):
        self.assertEqual(CHECKS["EML-006"]["mappings"]["iso_inferred"], ["A.5.14"])

    def test_enc_005_and_log_009_say_what_they_replace(self):
        for check_id in ("ENC-005", "DAT-006", "LOG-009", "LOG-012"):
            self.assertTrue(verify_remediation.WARNING_WORDS.search(CHECKS[check_id]["remediation"]["notes"]), check_id)


if __name__ == "__main__":
    unittest.main()
