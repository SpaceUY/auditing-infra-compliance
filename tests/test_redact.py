import unittest

import helpers  # noqa: F401  (sets up sys.path)

import redact

KEY = "AKIA" + "TESTKEYABCDEMNOP"
SESSION_KEY = "ASIA" + "TESTKEYABCDEWXYZ"
SECRET_VALUE = "wJalr" + "XUtnFEMI/K7MDENG/bPxRfiCY" + "TESTVALUE"
SECRET_LABEL = "aws_secret" + "_access_key"


def pem(label="PRIVATE", body="MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nKcwggSjAgEAAoIBAQC7", end=True):
    """PEM block built at runtime (a hook blocks private-key literals in files)."""
    block = "-----BEG" + "IN " + label + " KEY-----\n" + body + "\n"
    return block + ("-----E" + "ND " + label + " KEY-----" if end else "")


class MaskTests(unittest.TestCase):
    def test_mask_access_key(self):
        self.assertEqual(redact.mask(f"clave {KEY} en uso"), "clave AKIA…MNOP en uso")
        self.assertEqual(redact.mask(SESSION_KEY), "ASIA…WXYZ")

    def test_mask_secret_assignment(self):
        masked = redact.mask(f"{SECRET_LABEL} = {SECRET_VALUE}")
        self.assertIn(redact.REDACTED, masked)
        self.assertNotIn("wJalr", masked)
        self.assertNotIn("TESTVALUE", redact.mask("aws_session" + "_token: abcdTESTVALUE123"))

    def test_mask_email_except_kept(self):
        text = "dueño owner@acme-notes.example, contacto jane@acme-notes.example"
        masked = redact.mask(text, keep_emails=frozenset({"Owner@acme-notes.example"}))
        self.assertIn("owner@acme-notes.example", masked)
        self.assertIn("j***@acme-notes.example", masked)
        self.assertNotIn("jane@", masked)

    def test_mask_obj_recursive(self):
        obj = {"a": [KEY, {"b": "jane@acme-notes.example"}], "n": 3, "t": (KEY,), "SecretAccessKey": SECRET_VALUE}
        masked = redact.mask_obj(obj)
        self.assertEqual(masked["a"][0], "AKIA…MNOP")
        self.assertEqual(masked["a"][1]["b"], "j***@acme-notes.example")
        self.assertEqual(masked["n"], 3)
        self.assertEqual(masked["t"], ["AKIA…MNOP"])
        self.assertEqual(masked["SecretAccessKey"], redact.REDACTED)

    def test_mask_is_idempotent(self):
        once = redact.mask(f"{KEY} jane@acme-notes.example")
        self.assertEqual(redact.mask(once), once)

    def test_mask_obj_passes_keep_emails(self):
        keep = frozenset({"owner@acme-notes.example"})
        self.assertEqual(redact.mask_obj({"o": "owner@acme-notes.example"}, keep_emails=keep)["o"],
                         "owner@acme-notes.example")

    def test_mask_obj_masks_dict_keys(self):
        masked = redact.mask_obj({"ana@acme-notes.example": 1, KEY: {"x": 2}})
        self.assertEqual(masked, {"a***@acme-notes.example": 1, "AKIA…MNOP": {"x": 2}})


class LayoutTests(unittest.TestCase):
    """Secret layouts that a plain `label: value` rule misses (final review B, I2 and minor 8)."""

    def assert_masked(self, line):
        masked = redact.mask(line)
        self.assertNotIn(SECRET_VALUE, masked, line)
        self.assertIn(redact.REDACTED, masked, line)
        self.assertEqual(redact.mask(masked), masked, line)
        self.assertIn(redact.REDACTED, redact.mask_secrets(line))

    def test_bare_secret_label_in_tables_and_key_value_lines(self):
        for line in (f"| Secret | {SECRET_VALUE} |", f"Secret: {SECRET_VALUE}", f"**Secret**: {SECRET_VALUE}",
                     f"| Secret Key (prod) | {SECRET_VALUE} |", f"secret = {SECRET_VALUE}"):
            self.assert_masked(line)
        self.assertEqual(redact.mask(f"| Secret | {SECRET_VALUE} |"), "| Secret | [REDACTED] |")

    def test_access_key_and_secret_on_one_line(self):
        masked = redact.mask(f"access key: {KEY} secret: {SECRET_VALUE}")
        self.assertEqual(masked, "access key: AKIA…MNOP secret: [REDACTED]")

    def test_aws_configure_set(self):
        for line in (f"aws configure set {SECRET_LABEL} {SECRET_VALUE}",
                     f"aws configure set {SECRET_LABEL} {SECRET_VALUE} --profile acme",
                     f"aws configure set --profile acme {SECRET_LABEL} {SECRET_VALUE}",
                     "aws configure set aws_session" + f"_token {SECRET_VALUE}"):
            self.assert_masked(line)
        self.assertEqual(redact.mask(f"aws configure set {SECRET_LABEL} {SECRET_VALUE} --profile acme"),
                         f"aws configure set {SECRET_LABEL} [REDACTED] --profile acme")

    def test_password_labels(self):
        for line in ("password=hunter2", "Password: hunter2", "db_password = hunter2", '"password": "hunter2"',
                     "PASSWD=hunter2", "pwd: hunter2", "| password: hunter2 |"):
            masked = redact.mask(line)
            self.assertNotIn("hunter2", masked, line)
            self.assertIn(redact.REDACTED, masked, line)
            self.assertEqual(redact.mask(masked), masked, line)

    def test_bare_secret_scan_is_linear_on_repeated_labels(self):
        import time
        for text in ("secret=" * 15000, "secret=a/" * 11000):
            start = time.perf_counter()
            redact.mask(text)
            redact.detect(text)
            self.assertLess(time.perf_counter() - start, 1.0, text[:12])

    def test_secrets_manager_arn_is_neither_masked_nor_flagged(self):
        arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/MyApp2/dbpasswordXY-AbCdEf"
        for text in (arn, f"| Secreto | {arn} |", f'"SecretArn": "{arn}"', f"secret: {arn}"):
            self.assertIn(arn, redact.mask(text), text)
        for text in (arn, f"| Secreto | {arn} |", f'"SecretArn": "{arn}"'):
            self.assertEqual(redact.detect(text), [], text)

    def test_password_policy_settings_are_not_secrets(self):
        for text in ("password_policy: enabled", "PasswordPolicy: {MinimumPasswordLength: 14}", "password_reuse_prevention: 24",
                     "minimum_password_length: 14", "max_password_age: 90", "password_length=14", "password_policy=strong"):
            self.assertEqual(redact.mask(text), text, text)
            self.assertEqual(redact.detect(text), [], text)

    def test_password_with_short_qualifier_is_still_a_secret(self):
        for line in ("db_password: hunter2", "password_db=hunter2", "ADMIN_PASSWORD=hunter2", "--password=hunter2"):
            self.assertNotIn("hunter2", redact.mask(line), line)
            self.assertEqual(redact.detect(line), ["password"], line)

    def test_pem_private_key_block(self):
        for kind in ("", "RSA ", "OPENSSH ", "EC "):
            text = "antes\n" + pem(kind + "PRIVATE") + "\ndespues"
            masked = redact.mask(text)
            self.assertEqual(masked, "antes\n[REDACTED]\ndespues", kind)
            self.assertEqual(redact.mask(masked), masked)
        unterminated = redact.mask("x\n" + pem(end=False))
        self.assertNotIn("MIIEv", unterminated)
        certificate = "-----BEG" + "IN CERTIFICATE-----\nabc\n-----E" + "ND CERTIFICATE-----"
        self.assertEqual(redact.mask(certificate), certificate)

    def test_false_positives_stay_low(self):
        for text in ("La password se rota cada 90 días", "Password policy: mínimo 14", "AWS Secrets Manager guarda la clave",
                     "Secret | Rotación |", "secret: /acme/prod/db-credentials", "| Secret | acme-notes-db |",
                     "token: abc", "el secreto de producción", "password"):
            self.assertEqual(redact.mask(text), text, text)

    def test_detect_reports_patterns(self):
        self.assertEqual(redact.detect(f"| Secret | {SECRET_VALUE} |"), ["aws_secret_access_key"])
        self.assertEqual(redact.detect(f"aws configure set {SECRET_LABEL} {SECRET_VALUE}"), ["aws_secret_access_key"])
        self.assertEqual(redact.detect("password=hunter2"), ["password"])
        self.assertEqual(redact.detect(pem()), ["private_key"])
        self.assertEqual(redact.detect(f"{KEY} y {SECRET_LABEL}={SECRET_VALUE}"), ["aws_access_key_id", "aws_secret_access_key"])
        self.assertEqual(redact.detect("nada que ver"), [])

    def test_masking_stays_linear_on_new_patterns(self):
        import time
        for text in (pem("PRIVATE", "", end=False) * 5000, "password" * 20000, "secret|" * 20000, "aws configure set " * 5000,
                     "secret: " + "A1b" * 50000, "pwd=" * 30000):
            start = time.perf_counter()
            redact.mask(text)
            redact.detect(text)
            self.assertLess(time.perf_counter() - start, 1.0, text[:20])


def url(scheme, rest):
    """URL built at runtime (a hook blocks literal database URLs that carry credentials)."""
    return scheme + "://" + rest


class CredentialFormatTests(unittest.TestCase):
    """Review 2, C1/I1/I2/I3: the credential formats a vault really uses, and the references that are not secrets."""

    def assert_secret(self, line, pattern="password", value="hunter2"):
        masked = redact.mask(line)
        self.assertNotIn(value, masked, line)
        self.assertIn(redact.REDACTED, masked, line)
        self.assertEqual(redact.mask(masked), masked, line)
        self.assertIn(pattern, redact.detect(line), line)

    def assert_untouched(self, line):
        self.assertEqual(redact.mask(line), line, line)
        self.assertEqual(redact.detect(line), [], line)

    def test_password_in_table_cells(self):
        for line in ("| Password | hunter2 |", "| db_password | hunter2 |", "| Admin password | hunter2 |",
                     "| DBPassword | hunter2 | nota |", "| Contraseña | hunter2 |"):
            self.assert_secret(line)
        self.assertEqual(redact.mask("| Password | hunter2 | nota |"), "| Password | [REDACTED] | nota |")

    def test_compound_and_camel_case_labels(self):
        for line in ("MasterUserPassword: hunter2", "DBPassword: hunter2", "AdminPassword = hunter2", "db_password=hunter2",
                     "RDS_MASTER_PASSWORD=hunter2", "x-db-password: hunter2", "--master-user-password hunter2",
                     "--master-user-password 'hunter2'"):
            self.assert_secret(line)

    def test_values_with_spaces_and_quotes_are_fully_masked(self):
        cases = {"password: P@ss;w0rd123": "password: [REDACTED]", "password=Ab,Cd*12|x": "password=[REDACTED]",
                 'PASSWORD="pa ss"': 'PASSWORD="[REDACTED]"', "password: 'two words here'": "password: '[REDACTED]'",
                 "Password: correct horse battery staple": "Password: [REDACTED]",
                 '"password": "a b; c"': '"password": "[REDACTED]"',
                 '{\\"password\\": \\"sp ace\\"}': '{\\"password\\": \\"[REDACTED]\\"}',
                 "| Password | pa ss word | nota |": "| Password | [REDACTED] | nota |"}
        for text, expected in cases.items():
            self.assertEqual(redact.mask(text), expected, text)
            self.assertEqual(redact.mask(expected), expected)
            self.assertEqual(redact.detect(text), ["password"], text)

    def test_unterminated_quote_masks_to_end_of_line(self):
        self.assertEqual(redact.mask('password: "abc def'), 'password: "[REDACTED]')

    def test_references_are_not_secrets(self):
        for line in ("Password: in Secrets Manager", "Password: en Secrets Manager", "- Password: ver Secrets Manager (prod/db)",
                     "DB_PASSWORD=${DB_PASSWORD}", "password: {{ vault_db_password }}", "password: <db-password>",
                     "- Password: N/A", "| Password | - |", "| Password |  |", "Password:", "password: *****", "password: [REDACTED]",
                     "PASSWORD_ARN=arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-AbCdEf",
                     "password: arn:aws:ssm:us-east-1:111122223333:parameter/prod/db",
                     "password: ssm:/acme/prod/db-password", "password: /acme/prod/db-password",
                     "password_file: /run/secrets/db", "db_password_path: /run/secrets/db", "admin_password_file=/x/y",
                     "password: rotated every 90 days", "password: stored in 1Password", "Contraseña: en Secrets Manager",
                     "IAM password policy: enforced", "password_policy: strong", "RequireUppercaseCharacters: true",
                     "MinimumPasswordLength: 14", "PasswordReusePrevention: 24", "MaxPasswordAge: 90",
                     "AllowUsersToChangePassword: true", "password_last_used: 2026-01-01"):
            self.assert_untouched(line)

    def test_table_header_with_password_column_is_not_a_secret(self):
        text = "| Password | Rotación | Owner |\n|---|---|---|\n| Password | hunter2 | ops |\n"
        masked = redact.mask(text)
        self.assertIn("| Password | Rotación | Owner |", masked)
        self.assertNotIn("hunter2", masked)
        self.assertEqual(redact.detect("| Password | Rotación | Owner |\n|---|---|---|\n"), [])

    def test_hr_after_a_password_line_does_not_hide_it(self):
        self.assertNotIn("hunter2", redact.mask("password: hunter2\n---\n"))

    def test_api_keys_tokens_and_client_secrets(self):
        cases = (("api_key: sk-123456789", "api_key"), ("apikey=abcDEF123456", "api_key"), ("X-Api-Key: abcDEF123456", "api_key"),
                 ("API key | abcDEF123456 |", "api_key"), ("token: ghp_abcdef", "token"), ("access_token=abcDEF123456", "token"),
                 ("auth_token: abcDEF123456", "token"), ("x-amz-security-token: FwoGZXIvYXdz12345", "token"),
                 ("client_secret=abcDEF123456", "client_secret"), ('"client_secret": "abcDEF123456"', "client_secret"),
                 ("Authorization: Bearer eyJhbGciOi.abc123.def456", "bearer_token"), ("curl -H 'Bearer abcDEF123456'", "bearer_token"))
        for line, pattern in cases:
            masked = redact.mask(line)
            self.assertIn(redact.REDACTED, masked, line)
            self.assertEqual(redact.mask(masked), masked, line)
            self.assertIn(pattern, redact.detect(line), line)
        for secret in ("sk-123456789", "ghp_abcdef", "abcDEF123456", "FwoGZXIvYXdz12345", "eyJhbGciOi.abc123.def456"):
            for line, _ in cases:
                self.assertNotIn(secret, redact.mask(line), line)

    def test_token_and_key_labels_that_are_not_secrets(self):
        for line in ("token: abc", "token: placeholder", "tokens: 5", "token_ttl: 3600", "api_key: <your-key>",
                     "access_token: ${TOKEN}", "api_key: in Secrets Manager", "Authorization: required", "bearer authentication",
                     "api_key_id: AbCdEf123456", "| Token | Expiración |\n|---|---|", "client_secret: ver Secrets Manager"):
            self.assert_untouched(line)

    def test_url_userinfo_password(self):
        for text in (url("postgres", "admin:s3cr3t@db.acme-notes.example:5432/app"), url("https", "bob:s3cr3t@host.acme-notes.example/x")):
            masked = redact.mask(text)
            self.assertNotIn("s3cr3t", masked)
            self.assertIn(":[REDACTED]@", masked)
            self.assertNotIn("***", masked)
            self.assertEqual(redact.mask(masked), masked)
            self.assertEqual(redact.detect(text), ["url_credentials"])
        for text in (url("postgres", "admin:${DB_PASS}@db.acme-notes.example/app"),
                     url("postgres", "admin:<password>@db.acme-notes.example/app"),
                     url("https", "acme-notes.example/path"), url("postgres", "admin@db.acme-notes.example/app"),
                     "mailto:jo@acme-notes.example"):
            self.assertEqual(redact.detect(text), [], text)

    def test_arn_with_secret_key_segment_is_not_an_assignment(self):
        arn = "arn:aws:lambda:us-east-1:111122223333:function:secret_key_rotator:PROD"
        self.assertEqual(redact.mask(arn), arn)
        self.assertEqual(redact.detect(arn), [])

    def test_mask_obj_keeps_colliding_keys_and_masks_tag_lists(self):
        masked = redact.mask_obj({"ab@x.example": 1, "ac@x.example": 2})
        self.assertEqual(sorted(masked.values()), [1, 2])
        tags = redact.mask_obj([{"Key": "DBPassword", "Value": "hunter2"}, {"Key": "Owner", "Value": "ana"}])
        self.assertEqual(tags, [{"Key": "DBPassword", "Value": redact.REDACTED}, {"Key": "Owner", "Value": "ana"}])
        self.assertEqual(redact.mask_obj({"api_key": "x", "PasswordPolicy": {"MinimumPasswordLength": 14}, "Token": "abc"}),
                         {"api_key": redact.REDACTED, "PasswordPolicy": {"MinimumPasswordLength": 14}, "Token": redact.REDACTED})

    def test_hostile_lines_stay_linear(self):
        import time
        texts = ("password=" * 25000, "password_policy=" * 12000, "| password |" * 20000, '"password": "' * 15000,
                 "x" * 200000 + "password=y", "a" * 100000 + "token=" + "b" * 100000, "token: " + "A1b" * 70000,
                 "://a:" * 40000, "api_key " * 30000, "bearer " * 30000, "--password " * 20000, "Password" * 25000 + ": x",
                 url("p", "u" * 200000 + ":" + "p" * 200000 + "@h"), "| password |\n|---|\n" * 10000,
                 "a|\n|" + " " * 50000 + "|" + " " * 50000 + "--x", "a|\n" + "| -- " * 50000 + "|x", "password:" + " " * 200000 + "x",
                 'password: "' + '\\"' * 100000, "password: '" + "a'" * 100000)
        for text in texts:
            start = time.perf_counter()
            redact.mask(text)
            redact.detect(text)
            self.assertLess(time.perf_counter() - start, 1.0, text[:24])


class FinalCleanupBTests(unittest.TestCase):
    """Final cleanup B: linear masking for every label x reference prefix (N1), configuration flags and references that are not
    secrets (I2), column-layout tables and `/hunter2` (N3), reference words followed by punctuation (N5)."""

    def assert_untouched(self, line):
        self.assertEqual(redact.mask(line), line, line)
        self.assertEqual(redact.detect(line), [], line)

    def assert_masked(self, line, value="hunter2"):
        masked = redact.mask(line)
        self.assertNotIn(value, masked, line)
        self.assertIn(redact.REDACTED, masked, line)
        self.assertEqual(redact.mask(masked), masked, line)
        self.assertNotEqual(redact.detect(line), [], line)

    def test_every_recognised_label_is_listed_and_detected(self):
        for label in redact.LABEL_FORMS:
            self.assertNotEqual(redact.detect(label + "=" + "Zq9" + "xK2mPw7Ab3Cd5Ef8Gh1Jk"), [], label)

    @staticmethod
    def _repeated(number, label, prefix, size):
        unit = label + (": ", "=", " | ")[number % 3] + prefix + " "
        return unit, unit * (size // len(unit))

    @staticmethod
    def _seconds(text):
        import time
        start = time.perf_counter()
        redact.mask(text)
        redact.detect(text)
        return time.perf_counter() - start

    def test_masking_is_linear_for_every_label_and_reference_prefix(self):
        """The full matrix at 20 KB: a quadratic scan is already obvious there (200 KB took 15 s before the fix)."""
        for number, label in enumerate(redact.LABEL_FORMS):
            for prefix in redact.REFERENCE_PREFIXES:
                unit, text = self._repeated(number, label, prefix, 20_000)
                self.assertLess(self._seconds(text), 0.2, repr(unit))

    def test_representative_label_and_prefix_pairs_stay_linear_at_200_kb(self):
        labels, prefixes = redact.LABEL_FORMS, redact.REFERENCE_PREFIXES
        picks = [(0, 0), (len(labels) - 1, len(prefixes) - 1), (len(labels) // 2, len(prefixes) // 2),
                 (3, len(prefixes) - 1), (len(labels) - 2, 1)]
        for number, index in picks:
            unit, text = self._repeated(number, labels[number], prefixes[index], 200_000)
            self.assertLess(self._seconds(text), 1.0, repr(unit))

    def test_unspaced_repetitions_stay_linear(self):
        import time
        for unit in ("pwd=/", "token=/", "password: arn:aws:", "secret=$", "api_key=<", "password=${", "password|{{"):
            text = unit * (200_000 // len(unit))
            start = time.perf_counter()
            redact.mask(text)
            redact.detect(text)
            self.assertLess(time.perf_counter() - start, 1.0, unit)

    def test_configuration_flags_and_booleans_are_not_passwords(self):
        for line in ("ManageMasterUserPassword: true", "manage_master_user_password = true", "| ManageMasterUserPassword | true |",
                     "PasswordAuthentication: disabled", "PasswordAuthentication: no", "password: yes", "Password: enabled",
                     "password: False", "| Contraseña | sí |", "password: habilitada", "Password: N/D", "| Password | N/D |"):
            self.assert_untouched(line)

    def test_iac_references_are_not_passwords(self):
        for line in ("MasterUserPassword: !Ref DBSecret", "MasterUserPassword: !GetAtt DBSecret.Password", "password = var.db_password",
                     "password = data.aws_secretsmanager_secret_version.db.secret_string", "password: module.db.password",
                     "password: aws_secretsmanager_secret.db.arn", "password: !Sub ${Prefix}-db", "DB_PASSWORD=${DB_PASSWORD}",
                     "password: {{resolve:secretsmanager:prod/db:SecretString:password}}", "password = local.db_pass",
                     "api_key: !Ref ApiKeyParam", "token: var.github_token_value", "client_secret: data.aws_ssm_parameter.cs.value"):
            self.assert_untouched(line)

    def test_wiki_links_are_not_passwords(self):
        for line in ("| Password | [[Secrets Manager]] |", "| Password | [Secrets Manager](https://acme-notes.example/a) |",
                     "Password: [[Secrets Manager]]"):
            self.assert_untouched(line)

    def test_stored_in_phrases_are_not_passwords(self):
        for line in ("Password: almacenada en Secrets Manager", "| Contraseña | Se guarda en Secrets Manager |",
                     "Contraseña: guardada en 1Password", "Password: (en Secrets Manager)", "Password: Parameter Store",
                     "Password: Vault", "Password: 1Password", "Password: not stored", "Password: stored in AWS Secrets Manager (prod/db)",
                     "Password: se guarda en Secrets Manager y rota cada 90 días", "password: stored in Vault", "Password: en Parameter Store",
                     "- **Password**: en Secrets Manager", "password: gestionada por AWS Secrets Manager", "Password: no se guarda",
                     "password: rotated every 90 days", "password: ver Secrets Manager (cuenta prod)", "Password: en el gestor de secretos"):
            self.assert_untouched(line)

    def test_reference_word_followed_by_punctuation_is_still_a_password(self):
        for value in ("Secret-Admin-2024!", "In-Prod-2024", "no-more-secrets1", "Yes!Sir2024", "kms-key-passw0rd", "Vault-2024!",
                      "en-Secrets-9", "true-Blue99"):
            self.assert_masked("password: " + value, value)
            self.assert_masked("| Password | " + value + " |", value)

    def test_leading_slash_is_a_path_only_for_known_reference_forms(self):
        self.assert_masked("password: /hunter2")
        self.assert_masked("db_password=/hunter2")
        for line in ("password: /acme/prod/db-password", "password: ssm:/acme/prod/db", "password: /run/secrets/db"):
            self.assert_untouched(line)

    def test_column_layout_tables_mask_the_credential_column(self):
        tables = (("| Usuario | Password |", "|---|---|", "| bob | hunter2 |", "| ana | hunter3x9 |"),
                  ("| Usuario | Contraseña |", "|---|---|", "| bob | hunter2 |", "| ana | hunter3x9 |"),
                  ("| Usuario | Clave |", "|---|---|", "| bob | hunter2 |", "| ana | hunter3x9 |"),
                  ("| User | Secret |", "|---|---|", "| bob | hunter2 |", "| ana | hunter3x9 |"),
                  ("| User | Token |", "|---|---|", "| bob | hunter2abc |", "| ana | hunter3x9abc |"),
                  ("| User | API key |", "|---|---|", "| bob | hunter2abc |", "| ana | hunter3x9abc |"),
                  ("| User | Password | Notes |", "|---|---|---|", "| bob | hunter2 | ops |", "| ana | hunter3x9 | dev |"),
                  ("| **User** | **Password** |", "| --- | --- |", "| bob | `hunter2` |", "| ana | **hunter3x9** |"),
                  ("Usuario | Password", "---|---", "bob | hunter2", "ana | hunter3x9"))
        for header, sep, row, row2 in tables:
            text = "\n".join((header, sep, row, row2)) + "\n"
            masked = redact.mask(text)
            self.assertNotIn("hunter", masked, header)
            self.assertIn("bob", masked, header)
            self.assertEqual(redact.mask(masked), masked, header)
            self.assertNotEqual(redact.detect(text), [], header)
            self.assertEqual(masked.splitlines()[:2], [header, sep])

    def test_column_layout_keeps_the_other_columns_and_the_table_end(self):
        text = "| Usuario | Password | Rotación |\n|---|---|---|\n| bob | hunter2 | 90 días |\n\nfuera | hunter2 | texto\n"
        self.assertEqual(redact.mask(text), "| Usuario | Password | Rotación |\n|---|---|---|\n| bob | [REDACTED] | 90 días |\n\nfuera | hunter2 | texto\n")

    def test_column_layout_ignores_references_and_empty_cells(self):
        text = ("| Usuario | Password |\n|---|---|\n| a | en Secrets Manager |\n| b | [[Secrets Manager]] |\n| c |  |\n| d | - |\n"
                "| e | ${DB_PASS} |\n| f | N/A |\n")
        self.assertEqual(redact.mask(text), text)
        self.assertEqual(redact.detect(text), [])

    def test_key_value_tables_with_a_clave_column_are_not_credentials(self):
        text = "| Clave | Valor |\n|---|---|\n| region | us-east-1 |\n| owner | ana |\n"
        self.assertEqual(redact.mask(text), text)
        self.assertEqual(redact.detect(text), [])

    def test_secret_name_columns_keep_plain_identifiers(self):
        text = "| Secret | Rotación |\n|---|---|\n| acme-notes-db | 90 |\n"
        self.assertEqual(redact.mask(text), text)
        masked = redact.mask("| User | Secret |\n|---|---|\n| bob | hunter2 |\n| ana | Hunter |\n| cy | two words |\n")
        self.assertNotIn("hunter2", masked)
        self.assertNotIn("Hunter", masked)
        self.assertNotIn("two words", masked)

    def test_token_and_api_key_columns_use_the_word_rule(self):
        text = "| User | Token | Expira |\n|---|---|---|\n| bob | abcDEF123456 | 15 min |\n| ana | JWT, 15 min | 1 h |\n"
        masked = redact.mask(text)
        self.assertNotIn("abcDEF123456", masked)
        self.assertIn("JWT, 15 min", masked)

    def test_tables_with_policy_columns_are_untouched(self):
        text = "| Password policy | Valor |\n|---|---|\n| MinimumPasswordLength | 14 |\n| MaxPasswordAge | 90 |\n"
        self.assertEqual(redact.mask(text), text)

    def test_column_scan_is_linear(self):
        import time
        header = "| Usuario | Password |\n|---|---|\n"
        for text in (header + "| bob | hunter2 |\n" * 20000, header + "|" * 200000, header + "| a " * 60000 + "|\n",
                     "| Password |" * 20000 + "\n|---|\n" + "| x |" * 30000, header + ("| " + "a|" * 100) * 3000):
            start = time.perf_counter()
            redact.mask(text)
            redact.detect(text)
            self.assertLess(time.perf_counter() - start, 1.0, text[:24])


if __name__ == "__main__":
    unittest.main()
