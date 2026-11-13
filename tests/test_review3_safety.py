"""Review 3, safety and pipeline findings: ReDoS (headings, policy wildcards), secret detection gaps, abbreviation guard, index paths,
sensitive file names, non-UTF-8 note names, scope.json validation, inventory warnings outside the scope.

Fake secrets are built at runtime from fragments, never written as literals."""
import contextlib
import builtins
import io
import json
import os
import random
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import helpers  # noqa: F401  (puts the scripts on sys.path)

import aws_runner
import collect
import redact
import vault_index
from evaluators import encryption, integration
from evaluators.policy_glob import glob_match
from test_collect_review_a import INSTANCES_DENIED, ONE_INSTANCE, ReviewCase
from test_collect import err, ok

PASSWORD = "Hunter2" + "-Zq9xK2m"


def seconds(function, *args):
    start = time.perf_counter()
    function(*args)
    return time.perf_counter() - start


# ---------------------------------------------------------------- A I-1: heading regex

class HeadingRegexTests(unittest.TestCase):
    def test_a_long_whitespace_run_inside_a_heading_is_linear(self):
        text = "# a" + " " * 50_000 + "b\n"
        self.assertLess(seconds(vault_index.HEADING.findall, text), 1.0)  # 4 s with the lazy `\s*$` version

    def test_a_heading_of_only_whitespace_after_the_hashes_is_linear(self):
        text = ("#" + " " * 30_000 + "\n") * 3
        self.assertLess(seconds(vault_index.HEADING.findall, text), 1.0)

    def test_headings_are_unchanged_for_normal_notes(self):
        body = "# Title  \n\ntext\n## Sub heading\t\n###### Six\n####### Seven\n#NoSpace\n"
        found = [f"{m.group(1)} {m.group(2).strip()}" for m in vault_index.HEADING.finditer(body)]
        self.assertEqual(found, ["# Title", "## Sub heading", "###### Six"])

    def test_the_whitespace_after_the_hashes_does_not_cross_a_line(self):
        self.assertEqual(vault_index.HEADING.findall("#\n   text\n"), [])

    def test_a_note_with_such_a_heading_indexes_quickly(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp)
            (vault / "n.md").write_text("# a" + " " * 50_000 + "b\n", encoding="utf-8")
            start = time.perf_counter()
            index = vault_index.build_index(vault)
            self.assertLess(time.perf_counter() - start, 1.5)
        self.assertEqual(len(index["notes"][0]["headings"]), 1)
        self.assertTrue(index["notes"][0]["headings"][0].startswith("# a") and index["notes"][0]["headings"][0].endswith("b"))


# ---------------------------------------------------------------- A I-2: policy wildcards

def reference_match(pattern, text, ignore_case=False):
    regex = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(regex, text, re.I | re.S if ignore_case else re.S) is not None


class GlobMatchTests(unittest.TestCase):
    def test_matches_the_regex_translation_on_random_small_alphabets(self):
        rng = random.Random(7)
        for _ in range(4000):
            pattern = "".join(rng.choice("ab*?A") for _ in range(rng.randint(0, 7)))
            text = "".join(rng.choice("abA") for _ in range(rng.randint(0, 8)))
            for ignore_case in (False, True):
                self.assertEqual(glob_match(pattern, text, ignore_case=ignore_case), reference_match(pattern, text, ignore_case),
                                 (pattern, text, ignore_case))

    def test_special_characters_other_than_star_and_question_mark_are_literal(self):
        self.assertTrue(glob_match("a[b]c.d", "a[b]c.d"))
        self.assertFalse(glob_match("a[b]c.d", "abcxd"))
        self.assertFalse(glob_match("a.c", "abc"))

    def test_hostile_patterns_are_fast(self):
        for pattern, text in (("*a" * 40 + "Z", "a" * 200), ("a*" * 40 + "?" * 40 + "Z", "a" * 200), ("*" * 5000 + "x", "y" * 2000),
                              ("?*" * 500 + "Z", "a" * 2000)):
            self.assertLess(seconds(glob_match, pattern, text), 1.0, pattern[:12])
            self.assertFalse(glob_match(pattern, text))


class PolicyWildcardTests(unittest.TestCase):
    def test_a_hostile_bucket_policy_resource_does_not_hang_the_tls_check(self):
        pattern = "arn:aws:s3:::" + "*a" * 9 + "Z"  # 9 stars took about 5 s as a regex, 12 never returned
        self.assertLess(seconds(encryption._resource_matches, pattern, "arn:aws:s3:::" + "a" * 40 + "/object"), 1.0)
        self.assertFalse(encryption._resource_matches(pattern, "arn:aws:s3:::" + "a" * 40 + "/object"))

    def test_a_hostile_action_pattern_does_not_hang_the_integration_checks(self):
        statement = {"Effect": "Allow", "Action": ["s3:" + "*a" * 9 + "Z"]}
        self.assertLess(seconds(integration._action_matches, statement, "s3:" + "a" * 40), 1.0)
        self.assertFalse(integration._action_matches(statement, "s3:" + "a" * 40))

    def test_the_tls_check_end_to_end_with_a_hostile_policy(self):
        policy = {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::" + "*a" * 9 + "Z",
                                 "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
        self.assertLess(seconds(encryption._denies_insecure_transport, policy, "a" * 40), 1.0)
        self.assertFalse(encryption._denies_insecure_transport(policy, "a" * 40))

    def test_resource_matching_keeps_its_rules(self):
        match = encryption._resource_matches
        self.assertTrue(match("arn:aws:s3:::b*", "arn:aws:s3:::b/object"))
        self.assertTrue(match("arn:aws-cn:s3:::b/*", "arn:aws:s3:::b/object"))  # the partition of the pattern is ignored
        self.assertTrue(match("arn:aws:s3:::?", "arn:aws:s3:::b"))
        self.assertFalse(match("arn:aws:s3:::b?", "arn:aws:s3:::b"))
        self.assertFalse(match("arn:aws:s3:::B/*", "arn:aws:s3:::b/object"))  # resources are case sensitive

    def test_action_matching_is_case_insensitive(self):
        statement = {"Action": ["S3:Get*"]}
        self.assertTrue(integration._action_matches(statement, "s3:getobject"))
        self.assertFalse(integration._action_matches({"Action": ["s3:Put*"]}, "s3:getobject"))
        self.assertTrue(integration._action_matches({"Action": "*"}, "kms:Decrypt"))


# ---------------------------------------------------------------- A I-3 / M-4: secrets

def fake(*parts):
    return "".join(parts)


TOKENS = {
    "github_token": [fake("gh", "p_", "a" * 36), fake("github", "_pat_", "B" * 50)],
    "slack_token": [fake("xo", "xb-", "1234567890-abcdefghij")],
    "stripe_key": [fake("sk", "_live_", "c" * 20)],
    "google_api_key": [fake("AI", "za", "d" * 35)],
    "jwt": [fake("eyJ", "h" * 10, ".eyJ", "p" * 10, ".", "s" * 12)],
    "aws_session_token": [fake("FwoG", "ZXIvYXdz", "A" * 90), fake("IQoJ", "b3JpZ2lu", "z9/+" * 25)],
    "slack_webhook": [fake("https://hooks.slack.com/services/", "T0000000/B0000000/", "x" * 24)],
}


class TokenShapeTests(unittest.TestCase):
    def test_every_shape_is_masked_and_detected_without_a_label(self):
        for name, samples in TOKENS.items():
            for sample in samples:
                line = f"see {sample} for details"
                masked = redact.mask(line)
                self.assertIn(redact.REDACTED, masked, name)
                self.assertNotIn(sample[-20:], masked, name)
                self.assertEqual(redact.detect(line), [name], name)
                self.assertEqual(redact.mask(masked), masked, name)  # idempotent

    def test_the_slack_webhook_keeps_its_host(self):
        sample = TOKENS["slack_webhook"][0]
        self.assertTrue(redact.mask(sample).startswith("https://hooks.slack.com/services/" + redact.REDACTED))

    def test_a_note_with_a_token_is_reported_by_the_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp)
            (vault / "ci.md").write_text(f"# CI\n\nthe runner uses {TOKENS['github_token'][0]}\n", encoding="utf-8")
            index = vault_index.build_index(vault)
        self.assertEqual(index["secrets_detected"], [{"path": "ci.md", "pattern": "github_token"}])
        self.assertNotIn("a" * 36, json.dumps(index))

    def test_ordinary_text_that_looks_a_little_like_a_token_is_left_alone(self):
        for line in ("ghp_ is the prefix GitHub uses", "xoxb-short", "sk_live_short", "the eyJ prefix of a JWT", "AIza is a prefix",
                     "task_live_" + "x" * 30, "hooks.slack.com/services/ is the webhook path", "eyJ" + "a" * 20 + ".notajwt"):
            self.assertEqual(redact.mask(line), line, line)
            self.assertEqual(redact.detect(line), [], line)

    def test_shape_scans_are_linear(self):
        units = ("eyJ-", "eyJaaaaaaaaaa.eyJbbbbbbbbbb.", "ghp_" + "a" * 35 + "_", "github_pat_" + "a" * 49 + "-", "xoxb-" + "a" * 9 + " ",
                 "FwoGZXIvYXdz" + "A" * 79 + "-", "hooks.slack.com/services/", "AIza" + "a" * 34 + " ", "sk_live_" + "a" * 15 + " ")
        for unit in units:
            text = unit * (200_000 // len(unit))
            self.assertLess(seconds(lambda t: (redact.mask(t), redact.detect(t)), text), 2.0, unit)


class LabelTests(unittest.TestCase):
    def assert_masked(self, line, value=PASSWORD):
        masked = redact.mask(line)
        self.assertNotIn(value, masked, line)
        self.assertIn(redact.REDACTED, masked, line)
        self.assertEqual(redact.mask(masked), masked, line)
        self.assertNotEqual(redact.detect(line), [], line)

    def assert_untouched(self, line):
        self.assertEqual(redact.mask(line), line, line)
        self.assertEqual(redact.detect(line), [], line)

    def test_more_password_labels(self):
        for label in ("DB_PASS=", "db_pass: ", "pass: ", "PASS = ", "passphrase: ", "contraseña de root: ", "Contraseña del usuario admin: ",
                      "password for root: ", "pwd for the db: "):
            self.assert_masked(label + PASSWORD)

    def test_key_like_labels(self):
        value = "Zq9xK2mPw7Ab3Cd5Ef8Gh1Jk"
        for label in ("private_key: ", "PRIVATE-KEY=", "psk: ", "auth_key: ", "AuthKey=", "clave: ", "clave secreta: ", "Clave secreta = "):
            self.assert_masked(label + value, value)

    def test_the_aws_secret_key_separated_by_a_space(self):
        key = fake("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY")
        for line in (f"export AWS_SECRET_ACCESS_KEY {key}", f"secret_key {key}"):
            self.assert_masked(line, key)
            self.assertEqual(redact.detect(line), ["aws_secret_access_key"])
        self.assert_untouched("AWS_SECRET_ACCESS_KEY stored in Secrets Manager")
        self.assert_untouched("secret key rotation is enabled every ninety days")

    def test_command_line_credentials(self):
        for line in (f"curl -u admin:{PASSWORD} https://api.example.test", f"curl -sS --user=admin:{PASSWORD} https://api.example.test",
                     f"mysql -h db -u root -p{PASSWORD} acme", f"sshpass -p {PASSWORD} ssh deploy@host",
                     f"sshpass -p '{PASSWORD}' ssh deploy@host", f"mysql -u root -p'{PASSWORD}'"):
            self.assert_masked(line)

    def test_basic_authorization_headers(self):
        value = "dXNlcjpwYXNzd29yZDEyMw=="
        self.assert_masked(f"curl -H 'Authorization: Basic {value}' https://x.example.test", value)
        self.assertEqual(redact.detect(f"Authorization: Basic {value}"), ["basic_auth"])

    def test_references_and_ordinary_text_are_not_secrets(self):
        for line in ("DB_PASS: stored in Secrets Manager", "DB_PASS=${DB_PASS}", "pass: true", "pass: 12", "| test | pass |",
                     "contraseña de root: almacenada en Secrets Manager", "password for root: see 1Password", "passphrase: in Vault",
                     "clave: simplicidad", "private_key: /etc/ssl/private/app.key", "psk: N/A", "bypass: abcdefghijkl", "passed: yes",
                     "pass_rate: 99%", "password in the vault: foo", "curl -u user:password https://x", "curl -u $USER:$PASS https://x",
                     "mysql -u root -p", "mysql -P 3306 -h db", "ssh -p 22 host", 'sshpass -p "$PASS" ssh h', "sshpass -e ssh h",
                     "docker run -p8080:80 nginx", "Authorization: Basic $TOKEN", "private_key_file: ~/.ssh/key"):
            self.assert_untouched(line)

    def test_every_new_label_is_linear_with_references(self):
        for label in ("DB_PASS", "pass", "passphrase", "private_key", "psk", "auth_key", "clave", "clave secreta", "contraseña de root"):
            for prefix in ("/", "$", "${", "<", "arn:", "stored in", "true", "N/A", "-"):
                unit = f"{label}: {prefix} "
                self.assertLess(seconds(lambda t: (redact.mask(t), redact.detect(t)), unit * (20_000 // len(unit))), 0.5, unit)

    def test_the_connector_scan_is_linear_on_long_runs(self):
        for text in ("contraseña de " + "a " * 100_000, "password for" + " " * 100_000 + "x", "password " + "de a " * 50_000):
            self.assertLess(seconds(lambda t: (redact.mask(t), redact.detect(t)), text), 1.0)

    def test_labels_are_part_of_the_recognised_forms(self):
        for label in ("DB_PASS", "private_key", "clave secreta", "contraseña de root"):
            self.assertIn(label, redact.LABEL_FORMS)  # the timing matrix of test_redact runs every listed label


class MaskObjShapeTests(unittest.TestCase):
    def test_name_value_pairs_of_other_aws_shapes(self):
        for obj in ({"name": "DB_PASSWORD", "value": PASSWORD}, {"Name": "DBPassword", "Value": PASSWORD},
                    {"ParameterKey": "DBPassword", "ParameterValue": PASSWORD}, {"OptionName": "DB_PASSWORD", "Value": PASSWORD},
                    {"Variable": "db_password", "Value": PASSWORD}, {"Key": "DBPassword", "Value": PASSWORD}):
            self.assertNotIn(PASSWORD, json.dumps(redact.mask_obj(obj)), obj)

    def test_pairs_that_are_not_secret_are_kept(self):
        obj = {"Name": "LOG_LEVEL", "Value": "debug-level-9"}
        self.assertEqual(redact.mask_obj(obj), obj)
        obj = {"name": "PasswordPolicy", "value": "length 14"}
        self.assertEqual(redact.mask_obj(obj), obj)

    def test_containers_under_a_secret_key_are_redacted(self):
        masked = redact.mask_obj({"password": {"v": PASSWORD}, "token": [PASSWORD], "DBPassword": {"a": {"b": PASSWORD}}})
        self.assertNotIn(PASSWORD, json.dumps(masked))
        self.assertEqual(masked, {"password": redact.REDACTED, "token": redact.REDACTED, "DBPassword": redact.REDACTED})

    def test_a_container_under_a_secret_pair_value_is_redacted(self):
        masked = redact.mask_obj({"Name": "DBPassword", "Value": {"x": PASSWORD}})
        self.assertEqual(masked, {"Name": "DBPassword", "Value": redact.REDACTED})

    def test_other_values_are_untouched(self):
        obj = {"PasswordReusePrevention": 24, "HasPassword": True, "Tags": [{"Key": "Env", "Value": "prod"}], "n": None}
        self.assertEqual(redact.mask_obj(obj), obj)


# ---------------------------------------------------------------- A M-1: abbreviations

class AbbreviationGuardTests(unittest.TestCase):
    def test_abbreviations_of_the_value_revealing_flags_are_rejected(self):
        for flag in ("--with-d", "--with-de", "--with-decr", "--include-v", "--include-va", "--include-value", "--include-values",
                     "--with-decryption", "--with-d=true", "--include-v=true"):
            with self.subTest(flag=flag), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only("ec2", "describe-instances", [flag])

    def test_ordinary_flags_are_still_accepted(self):
        for flag in ("--instance-ids", "--max-items", "--filters", "--no-paginate"):
            aws_runner.assert_read_only("ec2", "describe-instances", [flag])

    def test_the_timeout_message_is_english(self):
        def runner(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 120)

        result = aws_runner.run_aws("ec2", "describe-instances", [], region=None, profile=None, runner=runner)
        self.assertEqual(result.error_message, f"timeout after {aws_runner.TIMEOUT_SECONDS}s")
        dns = aws_runner.run_dns("example.test", "TXT", runner=runner, which=lambda name: "/usr/bin/dig")
        self.assertEqual(dns.error_message, f"timeout after {aws_runner.TIMEOUT_SECONDS}s")


# ---------------------------------------------------------------- A M-2, M-5 / B I-3: the vault index

class VaultCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.vault = self.tmp / "vault"
        self.vault.mkdir()

    def run_index(self, output=None, *, patch_index=None):
        output = output or self.tmp / "out" / "vault-index.json"
        output.parent.mkdir(exist_ok=True)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = vault_index.main(["index", str(self.vault), "-o", str(output)])
        return code, stdout.getvalue(), stderr.getvalue(), output


class IndexPathTests(VaultCase):
    def test_note_paths_with_a_key_are_masked_everywhere_in_the_index(self):
        key = fake("AKIA", "TESTKEYABCDEMNOP")
        folder = self.vault / "sub"
        folder.mkdir()
        name = f"{key} notes.md"
        (folder / name).write_text(f"# Rotation runbook\n\nunique-phrase-zeta\n\naws_access_key_id = {key}\n\n- [[Missing note]]\n", encoding="utf-8")
        code, _, _, output = self.run_index()
        self.assertEqual(code, 0)
        text = output.read_text(encoding="utf-8")
        self.assertNotIn(key, text)
        index = json.loads(text)
        masked = "sub/AKIA…MNOP notes.md"
        self.assertEqual(index["notes"][0]["path"], masked)
        self.assertEqual(index["secrets_detected"], [{"path": masked, "pattern": "aws_access_key_id"}])
        self.assertEqual(index["broken_links"][0]["from"], masked)

    def test_the_real_file_is_still_read_through_the_masked_path(self):
        key = fake("AKIA", "TESTKEYABCDEMNOP")
        (self.vault / f"{key} notes.md").write_text("# Rotation runbook\n\nunique-phrase-zeta\n", encoding="utf-8")
        index = vault_index.build_index(self.vault)
        result = vault_index.resolve_feature(index, "unique-phrase-zeta")  # level 3: the body is read
        self.assertEqual(result["chosen"], index["notes"][0]["path"])

    def test_truncated_notes_use_the_masked_path(self):
        key = fake("AKIA", "TESTKEYABCDEMNOP")
        (self.vault / f"{key}.md").write_text("# Big\n" + "x" * 50, encoding="utf-8")
        with mock.patch.object(vault_index, "MAX_NOTE_BYTES", 10):
            index = vault_index.build_index(self.vault)
        self.assertEqual(index["truncated_notes"], ["AKIA…MNOP.md"])


class SensitiveNameTests(VaultCase):
    NAMES = {
        ".env": ".env file", ".envrc": ".env file", ".env-prod": ".env file", ".env_local": ".env file", "prod.env": ".env file",
        "a.pem": "private key file (.pem/.key)", "a.KEY": "private key file (.pem/.key)",
        "a.pfx": "certificate or key store (.pfx/.p12/.jks/.keystore)", "a.p12": "certificate or key store (.pfx/.p12/.jks/.keystore)",
        "k.jks": "certificate or key store (.pfx/.p12/.jks/.keystore)", "k.keystore": "certificate or key store (.pfx/.p12/.jks/.keystore)",
        "prod.tfvars": "Terraform variables file (.tfvars)", "terraform.tfstate": "Terraform state file (terraform.tfstate*)",
        "terraform.tfstate.backup": "Terraform state file (terraform.tfstate*)",
        "id_rsa": "SSH private key (id_rsa, id_ed25519, id_ecdsa)", "id_ed25519": "SSH private key (id_rsa, id_ed25519, id_ecdsa)",
        "id_ecdsa": "SSH private key (id_rsa, id_ed25519, id_ecdsa)",
        "aws-credentials.txt": "name containing 'credentials'", "secrets.yaml": "name containing 'secret'",
        "my-Secret.json": "name containing 'secret'",
    }

    def test_every_documented_name_is_listed_and_never_opened(self):
        for name in self.NAMES:
            (self.vault / name).write_text("hunter2\n", encoding="utf-8")
        (self.vault / "notes.txt").write_text("hunter2\n", encoding="utf-8")
        (self.vault / "id_rsa.pub").write_text("public\n", encoding="utf-8")
        real_open = builtins.open
        opened = []

        def guarded(file, *args, **kwargs):
            opened.append(Path(str(file)).name)
            return real_open(file, *args, **kwargs)

        with mock.patch.object(builtins, "open", guarded):
            index = vault_index.build_index(self.vault)
        self.assertEqual({i["path"]: i["reason"] for i in index["sensitive_files"]}, self.NAMES)
        self.assertEqual([n for n in opened if n in self.NAMES], [])
        self.assertNotIn("hunter2", json.dumps(index))

    def test_a_note_about_a_secrets_service_is_a_note_not_a_sensitive_file(self):
        (self.vault / "AWS Secrets Manager.md").write_text("# AWS Secrets Manager\n\nrotation every 30 days\n", encoding="utf-8")
        index = vault_index.build_index(self.vault)
        self.assertEqual(index["sensitive_files"], [])
        self.assertEqual([n["title"] for n in index["notes"]], ["AWS Secrets Manager"])

    def test_one_constant_drives_the_note_filter_and_the_listing(self):
        self.assertEqual(vault_index._sensitive_reason("x.pfx"), "certificate or key store (.pfx/.p12/.jks/.keystore)")
        self.assertIsNone(vault_index._sensitive_reason("x.md"))
        self.assertEqual(vault_index._sensitive_reason("Credentials.md"), "name containing 'credentials'")
        self.assertIsNone(vault_index._sensitive_reason("environment.txt"))


class NonUtf8NameTests(VaultCase):
    def make_latin1_note(self):
        name = os.fsdecode(b"Configuraci\xf3n RDS.md")
        try:
            (self.vault / name).write_text("# Configuracion\n\nunique-phrase-eta\n", encoding="utf-8")
        except OSError:
            self.skipTest("the file system refuses names that are not UTF-8")
        (self.vault / "ok.md").write_text("# OK\n", encoding="utf-8")

    def test_the_index_is_written_with_a_normalised_name(self):
        self.make_latin1_note()
        code, stdout, stderr, output = self.run_index()
        self.assertEqual((code, stderr), (0, ""))
        index = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(sorted(n["path"] for n in index["notes"]), ["Configuraci\ufffdn RDS.md", "ok.md"])
        self.assertIn("2 notes", stdout)

    def test_the_note_is_still_read_by_its_normalised_path(self):
        self.make_latin1_note()
        index = vault_index.build_index(self.vault)
        self.assertEqual(vault_index.resolve_feature(index, "unique-phrase-eta")["chosen"], "Configuraci\ufffdn RDS.md")

    def test_a_sensitive_file_name_that_is_not_utf8_is_listed_cleanly(self):
        try:
            (self.vault / os.fsdecode(b"credentials-\xe9.txt")).write_text("x\n", encoding="utf-8")
        except OSError:
            self.skipTest("the file system refuses names that are not UTF-8")
        index = vault_index.build_index(self.vault)
        json.dumps(index, ensure_ascii=False).encode("utf-8")  # must not raise
        self.assertEqual(index["sensitive_files"][0]["path"], "credentials-\ufffd.txt")


class AtomicIndexTests(VaultCase):
    def test_a_failed_write_exits_2_with_an_error_and_leaves_no_partial_file(self):
        (self.vault / "a.md").write_text("# A\n", encoding="utf-8")
        output = self.tmp / "out" / "vault-index.json"
        output.parent.mkdir()
        bad = {"kind": "free", "root": "/x", "notes": [{"path": "a\udcf3.md"}], "broken_links": [], "secrets_detected": [],
               "sensitive_files": [], "obsidian_plugins": [], "truncated_notes": []}
        with mock.patch.object(vault_index, "build_index", return_value=bad):
            code, stdout, stderr, _ = self.run_index(output)
        self.assertEqual(code, 2)
        self.assertTrue(stderr.startswith("error: could not write the index"), stderr)
        self.assertEqual(os.listdir(output.parent), [], "no index and no temporary file may remain")

    def test_a_failed_write_keeps_the_previous_index(self):
        output = self.tmp / "out" / "vault-index.json"
        output.parent.mkdir()
        output.write_text("previous", encoding="utf-8")
        bad = {"x": "\udcf3"}
        with mock.patch.object(vault_index, "build_index", return_value=bad):
            code, _, _, _ = self.run_index(output)
        self.assertEqual((code, output.read_text(encoding="utf-8")), (2, "previous"))

    def test_an_unwritable_output_is_an_error_not_a_traceback(self):
        (self.vault / "a.md").write_text("# A\n", encoding="utf-8")
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            code = vault_index.main(["index", str(self.vault), "-o", str(self.tmp / "missing-dir" / "i.json")])
        self.assertEqual(code, 2)
        self.assertTrue(stderr.getvalue().startswith("error: could not write the index"))

    def test_a_good_write_leaves_only_the_index(self):
        (self.vault / "a.md").write_text("# A\n", encoding="utf-8")
        code, _, _, output = self.run_index()
        self.assertEqual((code, os.listdir(output.parent)), (0, ["vault-index.json"]))


# ---------------------------------------------------------------- B M-1, M-5 / A M-7: collect.py

INVENTORY_WARNING = "incomplete inventory"
BUCKETS = {"Buckets": [{"Name": "acme-notes-logs"}]}


class OutOfScopeInventoryWarningTests(ReviewCase):
    def responses(self, us, eu=None):
        from test_collect import base_responses
        responses = base_responses()
        responses[("ec2", "describe-instances", "us-east-1")] = us
        responses[("ec2", "describe-instances", "eu-west-1")] = eu or ok({"Reservations": []})
        responses[("ec2", "describe-volumes", "us-east-1")] = ok({"Volumes": []})
        return responses

    def inventory_warnings(self):
        return [w for w in self.result["warnings"] if w.startswith(INVENTORY_WARNING)]

    def test_a_failed_type_outside_a_resource_scope_does_not_mark_the_run_incomplete(self):
        scope = self.scope_file("scope-resource.json")  # one s3 bucket
        self.run_collect(self.responses(err(INSTANCES_DENIED)), scope=scope)
        self.assertEqual(self.code, 0)
        self.assertEqual(self.inventory_warnings(), [])

    def test_a_failed_region_outside_the_scoped_resources_is_not_warned(self):
        scope = self.scope_file(regions=["us-east-1", "eu-west-1"], mode="resource", target="i-0acme00000000001", resources=[
            {"type": "ec2_instance", "id": "i-0acme00000000001", "region": "us-east-1"}])
        self.run_collect(self.responses(ok(ONE_INSTANCE), err(INSTANCES_DENIED)), scope=scope)
        self.assertEqual(self.inventory_warnings(), [])

    def test_a_failure_that_touches_the_scoped_resources_is_still_warned(self):
        scope = self.scope_file(regions=["us-east-1", "eu-west-1"], mode="resource", target="i-0acme00000000001", resources=[
            {"type": "ec2_instance", "id": "i-0acme00000000001", "region": "us-east-1"}])
        self.run_collect(self.responses(err(INSTANCES_DENIED), ok(ONE_INSTANCE)), scope=scope)
        self.assertEqual(self.inventory_warnings(), ["incomplete inventory: ec2_instance ACCESS_DENIED in us-east-1"])

    def test_full_mode_warns_about_every_failure(self):
        self.run_collect(self.responses(err(INSTANCES_DENIED)))
        self.assertEqual(self.inventory_warnings(), ["incomplete inventory: ec2_instance ACCESS_DENIED in us-east-1"])


class ScopeFileTests(ReviewCase):
    def assert_scope_error(self, scope_path, needle):
        self.run_collect(scope=scope_path)
        self.assertEqual(self.code, 2)
        self.assertTrue(self.stdout.startswith("error: "), self.stdout)
        self.assertIn(needle, self.stdout)
        self.assertEqual(self.runner.calls, [])
        self.assertFalse((self.out / "checks-result.json").exists() if hasattr(self, "out") else False)

    def test_a_missing_scope_is_an_error_not_a_traceback(self):
        self.assert_scope_error(self.tmp / "nope.json", "scope.json could not be read")

    def test_invalid_json_is_an_error_not_a_traceback(self):
        path = self.tmp / "bad.json"
        path.write_text('{"mode": "full",', encoding="utf-8")
        self.assert_scope_error(path, "scope.json could not be read")

    def test_a_scope_that_is_not_utf8_is_an_error(self):
        path = self.tmp / "latin.json"
        path.write_bytes(b'{"mode": "full", "target": "Configuraci\xf3n"}')
        self.assert_scope_error(path, "scope.json could not be read")

    def test_a_byte_order_mark_is_accepted(self):
        path = self.tmp / "bom.json"
        path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"mode": "full", "regions": ["us-east-1"], "target": None}).encode("utf-8"))
        self.run_collect(scope=path)
        self.assertEqual(self.code, 0)

    def test_every_scope_failure_starts_with_error(self):
        self.run_collect(scope=self.scope_file(mode="nonsense"))
        self.assertEqual(self.code, 2)
        self.assertTrue(self.stdout.startswith("error: scope.mode must be one of"), self.stdout)


class ScopeProfileTests(ReviewCase):
    def test_a_profile_that_is_not_a_name_is_rejected_before_any_aws_call(self):
        for profile in (5, ["a"], {"a": 1}, True, "", "-x", "--endpoint-url=http://evil", "a b", "a\nb", "x" * 129, "p;rm", "$(id)"):
            with self.subTest(profile=profile):
                self.run_collect(scope=self.scope_file(profile=profile))
                self.assertEqual(self.code, 2)
                self.assertIn("scope.profile", self.stdout)
                self.assertEqual(self.runner.calls, [])

    def test_profile_names_are_accepted(self):
        for profile in (None, "default", "acme-prod", "acme.prod", "sso_admin@acme", "a+b=c,d"):
            with self.subTest(profile=profile):
                self.assertIsNone(collect._scope_problem({"mode": "full", "profile": profile}, collect.catalog.load_checks(
                    helpers.SKILL_DIR / "references" / "checks")))

    def test_a_valid_profile_is_passed_to_the_cli(self):
        self.run_collect(scope=self.scope_file(profile="acme-prod"))
        self.assertEqual(self.code, 0)
        self.assertTrue(all(c[c.index("--profile") + 1] == "acme-prod" for c in self.runner.calls if "--profile" in c))
        self.assertTrue(any("--profile" in c for c in self.runner.calls))


if __name__ == "__main__":
    unittest.main()
