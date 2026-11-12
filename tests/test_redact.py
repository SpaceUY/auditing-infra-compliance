import unittest

import helpers  # noqa: F401  (sets up sys.path)

import redact

KEY = "AKIA" + "TESTKEYABCDEMNOP"
SESSION_KEY = "ASIA" + "TESTKEYABCDEWXYZ"
SECRET_VALUE = "wJalr" + "XUtnFEMI/K7MDENG/bPxRfiCY" + "TESTVALUE"
SECRET_LABEL = "aws_secret" + "_access_key"


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


if __name__ == "__main__":
    unittest.main()
