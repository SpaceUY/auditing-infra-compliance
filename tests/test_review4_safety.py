"""Review 4, safety findings: the `secret` file-name rule (text-like files only), glued password labels, empty-user URLs, CLI secret flags,
PGP private keys, prose and ARN false positives, unique public note paths, the scope.json account_id guard.

Fake secrets are built at runtime from fragments, never written as literals."""
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

import helpers  # noqa: F401  (puts the scripts on sys.path)

import collect
import redact
import vault_index
from test_collect import base_responses, err, ok
from test_review3_safety import ReviewCase

VALUE = "Zq9x" + "K2mP" + "7vLw"
ACCESS_KEY_TAIL = "MPLE"


def seconds(function, *args):
    start = time.perf_counter()
    function(*args)
    return time.perf_counter() - start


# ---------------------------------------------------------------- N-1 / M-4: secret file names

class SecretFileNameTests(unittest.TestCase):
    def test_attachments_with_secret_in_the_name_are_not_sensitive(self):
        for name in ("secrets-manager-flow.png", "AWS Secrets Manager.pdf", "Secretary-contact.docx", "secrets-rotation.canvas",
                     "Secret santa.jpg", "secrets.svg", "Secrets Manager architecture.drawio", "secret-handling.pptx", "secrets.xlsx",
                     "Credentials rotation flow.pdf", "credentials-diagram.png"):
            with self.subTest(name=name):
                self.assertIsNone(vault_index._sensitive_reason(name))

    def test_files_that_can_hold_a_secret_are_still_sensitive(self):
        for name in ("secrets", "secret", "secrets.txt", "secrets.json", "prod-secrets.yaml", "secrets.yml", "app.secret.ini", "secrets.cfg",
                     "secret.conf", "secrets.toml", "secrets.properties", "secrets.xml", "secrets.sh", "secrets.ps1", "Secrets.CSV",
                     "my.secret", "credentials", "credentials.csv", "credentials.json"):
            with self.subTest(name=name):
                self.assertIn("secret" if "secret" in name.lower() else "credentials", vault_index._sensitive_reason(name))

    def test_notes_are_still_excluded_from_the_secret_rule_and_not_from_credentials(self):
        self.assertIsNone(vault_index._sensitive_reason("AWS Secrets Manager.md"))
        self.assertIsNotNone(vault_index._sensitive_reason("Credentials.md"))

    def test_the_other_rules_are_not_limited_to_text_files(self):
        for name in ("a.pem", "a.key", "k.jks", "id_rsa", "terraform.tfstate.backup", "prod.tfvars", ".env"):
            with self.subTest(name=name):
                self.assertIsNotNone(vault_index._sensitive_reason(name))

    def test_a_vault_with_a_diagram_about_secrets_lists_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp)
            (vault / "Overview.md").write_text("# Overview\n", encoding="utf-8")
            (vault / "secrets-manager-flow.png").write_bytes(b"\x89PNG")
            (vault / "secrets.json").write_text("{}", encoding="utf-8")
            index = vault_index.build_index(vault)
        self.assertEqual([f["path"] for f in index["sensitive_files"]], ["secrets.json"])


# ---------------------------------------------------------------- N-2: masked and detected forms

class SecretFormTests(unittest.TestCase):
    def assert_masked(self, text, pattern=None):
        masked = redact.mask(text)
        self.assertNotIn(VALUE, masked, text)
        self.assertIn(redact.REDACTED, masked, text)
        found = redact.detect(text)
        self.assertTrue(found if pattern is None else pattern in found, (text, found))

    def assert_untouched(self, text):
        self.assertEqual(redact.mask_secrets(text), text)
        self.assertEqual(redact.detect(text), [], text)

    def test_glued_password_labels(self):
        for text in (f"PGPASSWORD={VALUE}", f"export PGPASSWORD='{VALUE}'", f"DBPASSWORD={VALUE}", f"DBPASS={VALUE}", f"dbpass: {VALUE}",
                     f"dbpassword: {VALUE}", f"MYSQL_PWD={VALUE}", f"MYSQLPASSWORD={VALUE}", f"rootpassword: {VALUE}",
                     f"ADMINPASSWORD: {VALUE}", f"adminpwd: {VALUE}", f"userpassword: {VALUE}", f"rootpass: {VALUE}"):
            with self.subTest(text=text):
                self.assert_masked(text, "password")

    def test_glued_labels_with_a_reference_are_left_alone(self):
        for text in ("PGPASSWORD=${DB_PASSWORD}", "PGPASSWORD=$DB_PASSWORD", "DBPASS=<password>", "dbpassword: stored in Secrets Manager",
                     "dbpassword: file://secret.txt"):
            with self.subTest(text=text):
                self.assert_untouched(text)

    def test_a_word_that_only_ends_in_pass_is_not_a_label(self):
        self.assert_untouched(f"bypass: {VALUE}")
        self.assert_untouched(f"compass: {VALUE}")

    def test_a_url_password_with_an_empty_user(self):
        self.assert_masked(f"redis://:{VALUE}@cache.internal:6379/0", "url_credentials")
        self.assertEqual(redact.mask(f"redis://:{VALUE}@cache.internal:6379/0"), "redis://:[REDACTED]@cache.internal:6379/0")
        self.assert_untouched("redis://:password@cache.internal:6379")
        self.assert_untouched("redis://cache.internal:6379/0")
        self.assert_untouched("https://example.com:8080/path")

    def test_cli_flags_with_a_space_separated_value(self):
        patterns = {"--secret-string": "password", "--client-secret": "client_secret", "--api-key": "api_key", "--token": "token",
                    "--access-token": "token", "--auth-token": "token", "--passphrase": "password", "--password": "password",
                    "--private-key": "private_key"}
        for flag, pattern in patterns.items():
            for quote in ("", "'", '"'):
                with self.subTest(flag=flag, quote=quote):
                    text = f"aws something --name x {flag} {quote}{VALUE}{quote} --region us-east-1"
                    self.assert_masked(text, pattern)
                    self.assertIn("--region us-east-1", redact.mask(text))

    def test_a_json_secret_string_is_masked_whole(self):
        text = "aws secretsmanager create-secret --name n --secret-string '{\"user\":\"u\",\"pw\":\"" + VALUE + "\"}'"
        self.assertEqual(redact.mask(text), "aws secretsmanager create-secret --name n --secret-string '[REDACTED]'")

    def test_cli_flags_with_references_are_left_alone(self):
        for text in ("--token $TOKEN", "--token ${GITHUB_TOKEN}", "--secret-string file://secret.json", "--password '<password>'",
                     "--api-key $(cat key.txt)", "--client-secret fileb://cs.bin", "--token-file token.txt", "--token to authenticate",
                     "use --api-key for the gateway", "--token"):
            with self.subTest(text=text):
                self.assert_untouched(text)

    def test_pgp_private_key_blocks(self):
        block = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + "lQdGBF" + VALUE + "\n=abcd\n-----END PGP PRIVATE KEY BLOCK-----"
        text = "before\n" + block + "\nafter"
        self.assertEqual(redact.mask(text), "before\n[REDACTED]\nafter")
        self.assertIn("private_key", redact.detect(text))
        unterminated = "x\n-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + VALUE
        self.assertNotIn(VALUE, redact.mask(unterminated))
        self.assertIn("private_key", redact.detect(unterminated))
        self.assertEqual(redact.detect("-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----"), [])

    def test_mask_is_idempotent_for_the_new_forms(self):
        for text in (f"PGPASSWORD={VALUE}", f"redis://:{VALUE}@h:1", f"--token {VALUE}", f"--secret-string '{VALUE}'"):
            once = redact.mask(text)
            self.assertEqual(redact.mask(once), once)

    def test_mask_obj_redacts_glued_keys(self):
        masked = redact.mask_obj({"PGPASSWORD": VALUE, "DBPASS": VALUE})
        self.assertEqual(masked, {"PGPASSWORD": redact.REDACTED, "DBPASS": redact.REDACTED})

    def test_the_new_patterns_are_linear(self):
        for unit in ("PGPASSWORD" * 3000, "--token " * 5000, "--secret-string '" * 3000, "redis://" + ":" * 30000, "pass " * 8000,
                     "-----BEGIN PGP PRIVATE KEY BLOCK-----" * 2000, "arn:aws:lambda:x:" * 3000 + "token: a", "dbpass:" * 6000):
            with self.subTest(unit=unit[:20]):
                self.assertLess(seconds(redact.mask, unit), 2.0)
                self.assertLess(seconds(redact.detect, unit), 2.0)


# ---------------------------------------------------------------- N-3: false positives

class FalsePositiveTests(unittest.TestCase):
    def assert_untouched(self, text):
        self.assertEqual(redact.mask(text), text)
        self.assertEqual(redact.detect(text), [], text)

    def test_the_weak_pass_label_ignores_prose(self):
        for text in ("Pipelines must pass: lint, test, build and deploy", "tests pass: yes", "Quality gate pass: coverage above 80 percent",
                     "Pass: Cumple con la politica de retencion", "Boarding pass: see attachment", "**Vacuous pass:** the check has no resources",
                     "pass: Cumplimiento", "pass: all-green-ci", "pass: 12"):
            with self.subTest(text=text):
                self.assert_untouched(text)

    def test_the_weak_pass_label_still_masks_a_password_looking_value(self):
        for text in (f"pass: {VALUE}", f"pass={VALUE}", f"Pass: '{VALUE}'", "pass: Hunter2-" + VALUE):
            with self.subTest(text=text):
                self.assertNotIn(VALUE, redact.mask(text))
                self.assertIn("password", redact.detect(text))

    def test_token_labels_do_not_mangle_arns_or_names(self):
        for text in ("arn:aws:lambda:us-east-1:111122223333:function:refresh-token:live-alias",
                     "arn:aws:lambda:us-east-1:111122223333:function:refresh-token:20240101x",
                     "arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/api-token:log-stream:2024-01-01-abcdef12",
                     "Token: refresh-token-rotation", "API key: managed-by-apigateway-usage-plans", "private_key: stored-in-kms-hsm",
                     "PSK: generated-by-aws-vpn", "Clave: rotacion-anual", "see (arn:aws:lambda:us-east-1:111122223333:function:x-token:v2024)"):
            with self.subTest(text=text):
                self.assert_untouched(text)

    def test_token_labels_still_mask_real_values(self):
        for text in (f"token: {VALUE}", f"API key: {VALUE}", "token: ghp_abcdef", f"client_secret = {VALUE}",
                     f"arn:aws:iam::111122223333:role/r token: {VALUE}"):
            with self.subTest(text=text):
                self.assertNotIn(VALUE, redact.mask(text))
                self.assertTrue(redact.detect(text))


# ---------------------------------------------------------------- N-5 / M-5: public note paths

class PublicPathTests(unittest.TestCase):
    def setUp(self):
        self.vault = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.vault, ignore_errors=True)

    def key_named(self, middle):
        return "AK" + "IA" + middle + ACCESS_KEY_TAIL + ".md"

    def note(self, name, text):
        (self.vault / name).write_text(text, encoding="utf-8")

    def test_notes_whose_masked_paths_collide_are_all_kept_and_readable(self):
        self.note(self.key_named("A" * 12), "# First\n\nonly-in-the-first-note\n")
        self.note(self.key_named("B" * 12), "# Second\n\nonly-in-the-second-note\n")
        self.note(self.key_named("C" * 12), "# Third\n\nonly-in-the-third-note\n")
        index = vault_index.build_index(self.vault)
        paths = [n["path"] for n in index["notes"]]
        self.assertEqual(paths, ["AKIA…MPLE.md", "AKIA…MPLE (2).md", "AKIA…MPLE (3).md"])
        for phrase, title in (("only-in-the-first-note", "First"), ("only-in-the-second-note", "Second"), ("only-in-the-third-note", "Third")):
            with self.subTest(phrase=phrase):
                result = vault_index.resolve_feature(index, phrase)
                self.assertEqual(len(result["candidates"]), 1, result)
                chosen = next(n for n in index["notes"] if n["path"] == result["chosen"])
                self.assertEqual(chosen["headings"], [f"# {title}"])

    def test_the_disambiguated_path_is_also_used_by_secrets_and_links(self):
        self.note(self.key_named("A" * 12), "# One\n\n[[Missing one]]\n")
        self.note(self.key_named("B" * 12), "# Two\n\n[[Missing two]]\n\npassword: " + VALUE + "\n")
        index = vault_index.build_index(self.vault)
        self.assertEqual([s["path"] for s in index["secrets_detected"]], ["AKIA…MPLE (2).md"])
        self.assertEqual({b["from"]: b["target"] for b in index["broken_links"]},
                         {"AKIA…MPLE.md": "Missing one", "AKIA…MPLE (2).md": "Missing two"})

    def test_an_existing_note_with_the_disambiguated_name_keeps_its_name(self):
        self.note(self.key_named("A" * 12), "# A\n")
        self.note(self.key_named("B" * 12), "# B\n")
        self.note("AKIA…MPLE (2).md", "# Own\n")
        paths = {n["headings"][0]: n["path"] for n in vault_index.build_index(self.vault)["notes"]}
        self.assertEqual(paths["# Own"], "AKIA…MPLE (2).md")
        self.assertEqual(len(set(paths.values())), 3)

    def test_the_result_is_deterministic(self):
        for middle in "ABCD":
            self.note(self.key_named(middle * 12), f"# {middle}\n")
        first = [n["path"] for n in vault_index.build_index(self.vault)["notes"]]
        self.assertEqual(first, [n["path"] for n in vault_index.build_index(self.vault)["notes"]])

    def test_non_utf8_names_that_collide_are_both_found(self):
        try:
            (self.vault / os.fsdecode(b"Configuraci\xf3n.md")).write_text("# One\n\nphrase-one-only\n", encoding="utf-8")
            (self.vault / os.fsdecode(b"Configuraci\xe9n.md")).write_text("# Two\n\nphrase-two-only\n", encoding="utf-8")
        except OSError:
            self.skipTest("the file system refuses names that are not UTF-8")
        index = vault_index.build_index(self.vault)
        self.assertEqual(len({n["path"] for n in index["notes"]}), 2)
        self.assertEqual(len(vault_index.resolve_feature(index, "phrase-two-only")["candidates"]), 1)

    def test_the_real_path_map_is_built_once_per_feature_call(self):
        for number in range(60):
            self.note(f"Note {number}.md", f"# Note {number}\n\nbody {number}\n")
        index = vault_index.build_index(self.vault)
        calls = []
        original = vault_index._note_files
        vault_index._note_files = lambda root: calls.append(root) or original(root)
        try:
            vault_index.resolve_feature(index, "zzzz unmatched phrase")
        finally:
            vault_index._note_files = original
        self.assertEqual(len(calls), 1)

    def test_a_vault_of_masked_names_resolves_quickly(self):
        for number in range(300):
            (self.vault / f"Descripci\xf3n {number}.md").write_text(f"# D {number}\n\ntext {number}\n", encoding="utf-8")
        index = vault_index.build_index(self.vault)
        self.assertLess(seconds(vault_index.resolve_feature, index, "zzzz unmatched phrase"), 2.0)


# ---------------------------------------------------------------- scope.account_id guard

class AccountGuardTests(ReviewCase):
    def assert_rejected_before_any_call(self, account_id):
        self.run_collect(scope=self.scope_file(account_id=account_id))
        self.assertEqual(self.code, 2, account_id)
        self.assertEqual(self.stdout.strip(), "error: scope.account_id must be null or a 12-digit AWS account id; received "
                         f"{json.dumps(account_id, ensure_ascii=False)}. Fix scope.json and retry.")
        self.assertEqual(self.runner.calls, [])

    def test_a_malformed_account_id_is_a_scope_error(self):
        for bad in ("1234", "12345678901", "1234567890123", "11112222333a", "", " 111122223333", 111122223333, ["111122223333"], True,
                    "１１１１２２２２３３３３"):
            with self.subTest(account_id=bad):
                self.assert_rejected_before_any_call(bad)

    def test_null_and_a_missing_key_are_accepted(self):
        for scope in (self.scope_file(account_id=None), self.scope_file()):
            self.run_collect(scope=scope)
            self.assertEqual(self.code, 0)

    def test_the_matching_account_runs_normally(self):
        self.run_collect(scope=self.scope_file(account_id="111122223333"))
        self.assertEqual(self.code, 0)
        self.assertGreater(len(self.runner.calls), 1)

    def test_another_account_stops_after_the_identity_call_and_writes_nothing(self):
        self.run_collect(scope=self.scope_file(account_id="999988887777"))
        self.assertEqual(self.code, 2)
        self.assertEqual(self.stdout.strip(), "error: the credentials belong to account 111122223333, not the account confirmed in "
                         "scope.json (999988887777). Fix the profile or scope.json and retry.")
        self.assertEqual([c[1:3] for c in self.runner.calls], [["sts", "get-caller-identity"]])
        self.assertFalse(self.out.exists(), "nothing may be written")
        self.assertIsNone(self.result)

    def test_an_identity_without_an_account_does_not_pass_the_guard(self):
        responses = base_responses()
        responses[("sts", "get-caller-identity", "us-east-1")] = ok({"Arn": "arn:aws:iam::111122223333:user/x"})
        self.run_collect(responses, scope=self.scope_file(account_id="111122223333"))
        self.assertEqual(self.code, 2)
        self.assertIn("not the account confirmed in scope.json (111122223333)", self.stdout)
        self.assertEqual(len(self.runner.calls), 1)

    def test_no_credentials_still_reports_that_error_first(self):
        responses = base_responses()
        responses[("sts", "get-caller-identity", "us-east-1")] = err("An error occurred (ExpiredToken) when calling GetCallerIdentity")
        self.run_collect(responses, scope=self.scope_file(account_id="999988887777"))
        self.assertEqual(self.code, 2)
        self.assertIn("no valid AWS credentials", self.stdout)


# ---------------------------------------------------------------- English-only messages

class EnglishMessageTests(unittest.TestCase):
    def test_no_spanish_error_messages_in_the_engine_and_the_catalog_validator(self):
        scripts = Path(helpers.SCRIPTS_DIR)
        for name in ("collect.py", "catalog.py"):
            text = (scripts / name).read_text(encoding="utf-8")
            for word in ("no registrado", "llamada '"):
                with self.subTest(file=name, word=word):
                    self.assertNotIn(word, text)

    def test_the_unregistered_evaluator_message_is_english(self):
        with self.assertRaises(LookupError) as raised:
            collect._python_offenders(None, {}, "no-such-evaluator", {"responses": {}, "values": {}}, [])
        self.assertEqual(str(raised.exception), "python evaluator 'no-such-evaluator' is not registered")


if __name__ == "__main__":
    unittest.main()
