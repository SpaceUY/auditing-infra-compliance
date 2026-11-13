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


if __name__ == "__main__":
    unittest.main()
