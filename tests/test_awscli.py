import json
import subprocess
import unittest

from tests.helpers import FakeRunner  # also puts scripts/ on sys.path

import awscli  # noqa: E402

OK = {"stdout": json.dumps({"Reservations": []}), "stderr": "", "returncode": 0}
THROTTLED = {"stdout": "", "stderr": "An error occurred (Throttling) when calling: Rate exceeded", "returncode": 254}
DENIED = {"stdout": "", "stderr": "An error occurred (AccessDenied) when calling the X operation", "returncode": 254}


def run(responses, service="ec2", operation="describe-instances", args=(), **kw):
    runner = FakeRunner(responses)
    sleeps = []
    kw.setdefault("region", "us-east-1")
    kw.setdefault("profile", None)
    result = awscli.run_aws(service, operation, list(args), runner=runner, sleep=sleeps.append, **kw)
    return result, runner, sleeps


class AssertReadOnlyTest(unittest.TestCase):
    def test_allows_describe_list_get(self):
        for service, op in (
            ("ec2", "describe-instances"),
            ("iam", "list-users"),
            ("iam", "get-account-summary"),
        ):
            with self.subTest(op=op):
                awscli.assert_read_only(service, op, [])

    def test_allows_exact_exceptions(self):
        awscli.assert_read_only("cloudtrail", "lookup-events", [])
        awscli.assert_read_only("iam", "generate-credential-report", [])

    def test_rejects_write_ops(self):
        for service, op in (
            ("ec2", "modify-instance-metadata-options"),
            ("iam", "create-user"),
            ("s3api", "put-bucket-policy"),
            ("iam", "delete-access-key"),
            ("cloudtrail", "start-logging"),
        ):
            with self.subTest(op=op), self.assertRaises(awscli.ReadOnlyViolation):
                awscli.assert_read_only(service, op, [])

    def test_rejects_denylist(self):
        for service, op in awscli.DENYLIST:
            op = "execute-statement" if op == "*" and service == "rds-data" else op
            op = "ls" if op == "*" and service == "s3" else op
            with self.subTest(service=service, op=op), self.assertRaises(awscli.ReadOnlyViolation):
                awscli.assert_read_only(service, op, [])

    def test_wildcard_entries_cover_whole_service(self):
        with self.assertRaises(awscli.ReadOnlyViolation):
            awscli.assert_read_only("rds-data", "execute-statement", [])
        with self.assertRaises(awscli.ReadOnlyViolation):
            awscli.assert_read_only("s3", "ls", [])

    def test_rejects_with_decryption(self):
        with self.assertRaises(awscli.ReadOnlyViolation):
            awscli.assert_read_only("ssm", "describe-parameters", ["--with-decryption"])
        with self.assertRaises(awscli.ReadOnlyViolation):
            awscli.assert_read_only("ssm", "describe-parameters", ["--with-decryption=true"])

    def test_rejects_malformed_names(self):
        for service, op in (("ec2", "describe-instances; rm"), ("--profile", "list-x"), ("", "list-x")):
            with self.subTest(service=service, op=op), self.assertRaises(awscli.ReadOnlyViolation):
                awscli.assert_read_only(service, op, [])


class RunAwsTest(unittest.TestCase):
    def test_never_uses_shell(self):
        result, runner, _ = run({("ec2", "describe-instances", "us-east-1"): OK})
        self.assertTrue(result.ok)
        self.assertIsInstance(runner.calls[0], list)
        self.assertFalse(runner.kwargs[0].get("shell", False))
        self.assertEqual(runner.kwargs[0]["timeout"], 120)

    def test_write_op_never_reaches_runner(self):
        runner = FakeRunner({})
        with self.assertRaises(awscli.ReadOnlyViolation):
            awscli.run_aws("iam", "create-user", [], region=None, profile=None, runner=runner)
        self.assertEqual(runner.calls, [])

    def test_query_and_region_in_argv(self):
        result, runner, _ = run(
            {("ec2", "describe-instances", "us-east-1"): OK},
            args=["--instance-ids", "i-1"],
            profile="acme",
            query="Reservations[].Instances[]",
        )
        self.assertEqual(
            runner.calls[0],
            [
                "aws", "ec2", "describe-instances", "--instance-ids", "i-1", "--output", "json",
                "--region", "us-east-1", "--profile", "acme", "--query", "Reservations[].Instances[]",
            ],
        )
        self.assertEqual(result.argv, tuple(runner.calls[0]))
        self.assertEqual(result.data, {"Reservations": []})

    def test_no_region_no_profile_no_query(self):
        _, runner, _ = run({("iam", "list-users", None): OK}, "iam", "list-users", region=None)
        self.assertEqual(runner.calls[0], ["aws", "iam", "list-users", "--output", "json"])

    def test_throttling_retries_then_succeeds(self):
        result, runner, sleeps = run({("ec2", "describe-instances", "us-east-1"): [THROTTLED, THROTTLED, OK]})
        self.assertTrue(result.ok)
        self.assertEqual(len(runner.calls), 3)
        self.assertEqual(sleeps, [1, 2])

    def test_throttling_gives_up_after_four_retries(self):
        result, runner, sleeps = run({("ec2", "describe-instances", "us-east-1"): THROTTLED})
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "THROTTLED")
        self.assertEqual(len(runner.calls), 5)
        self.assertEqual(sleeps, [1, 2, 4, 8])

    def test_access_denied_not_retried(self):
        result, runner, sleeps = run({("ec2", "describe-instances", "us-east-1"): DENIED})
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "ACCESS_DENIED")
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(sleeps, [])
        self.assertIn("AccessDenied", result.error_message)

    def test_invalid_json_is_error(self):
        result, _, _ = run({("ec2", "describe-instances", "us-east-1"): {"stdout": "not json", "returncode": 0}})
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "ERROR")

    def test_empty_stdout_is_ok_with_no_data(self):
        result, _, _ = run({("ec2", "describe-instances", "us-east-1"): {"stdout": "", "returncode": 0}})
        self.assertTrue(result.ok)
        self.assertIsNone(result.data)

    def test_timeout_is_error(self):
        def runner(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 120)

        result = awscli.run_aws("ec2", "describe-instances", [], region=None, profile=None, runner=runner)
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "ERROR")

    def test_missing_aws_binary_is_error(self):
        def runner(argv, **kwargs):
            raise FileNotFoundError("aws")

        result = awscli.run_aws("ec2", "describe-instances", [], region=None, profile=None, runner=runner)
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "ERROR")


class ClassifyErrorTest(unittest.TestCase):
    def test_classify_error_table(self):
        table = {
            "ACCESS_DENIED": [
                "An error occurred (AccessDenied) when calling",
                "An error occurred (UnauthorizedOperation) when calling",
                "An error occurred (AccessDeniedException) when calling",
                "User: arn:aws:iam::111122223333:user/x is not authorized to perform: iam:ListUsers",
            ],
            "NOT_ENABLED": [
                "An error occurred (OptInRequired) when calling",
                "An error occurred (SubscriptionRequiredException) when calling",
                "An error occurred (InvalidAccessException) when calling: Account is not subscribed to AWS Security Hub",
                "Account 111122223333 is not subscribed to AWS Security Hub",
                "An error occurred (NoSuchConfigurationRecorderException) when calling",
                "An error occurred (BadRequestException) when calling: The detector is not enabled",
            ],
            "NO_CREDENTIALS": [
                "Unable to locate credentials. You can configure credentials by running",
                "An error occurred (ExpiredToken) when calling",
                "An error occurred (InvalidClientTokenId) when calling",
                "The config profile (acme) could not be found",
            ],
            "THROTTLED": [
                "An error occurred (Throttling) when calling",
                "An error occurred (ThrottlingException): Rate exceeded",
                "An error occurred (TooManyRequestsException) when calling",
            ],
            "ERROR": ["An error occurred (ValidationError) when calling", "", "boom"],
        }
        for expected, samples in table.items():
            for stderr in samples:
                with self.subTest(expected=expected, stderr=stderr):
                    self.assertEqual(awscli.classify_error(stderr), expected)

    def test_bad_request_without_not_enabled_is_error(self):
        self.assertEqual(awscli.classify_error("An error occurred (BadRequestException) when calling"), "ERROR")


class RunDnsTest(unittest.TestCase):
    def test_dig_preferred(self):
        runner = FakeRunner({("dig", None, None): {"stdout": '"v=spf1 -all"\n\n', "returncode": 0}})
        result = awscli.run_dns(
            "acme-notes.example", "TXT", runner=runner, which=lambda t: f"/usr/bin/{t}"
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.data, ['"v=spf1 -all"'])
        self.assertEqual(runner.calls[0], ["dig", "+short", "TXT", "acme-notes.example"])
        self.assertFalse(runner.kwargs[0].get("shell", False))

    def test_dns_falls_back_to_nslookup(self):
        runner = FakeRunner({("nslookup", None, None): {"stdout": "Server: x\ntext = \"v=spf1 -all\"\n", "returncode": 0}})
        which = lambda t: "/usr/bin/nslookup" if t == "nslookup" else None  # noqa: E731
        result = awscli.run_dns("acme-notes.example", "TXT", runner=runner, which=which)
        self.assertTrue(result.ok)
        self.assertEqual(runner.calls[0], ["nslookup", "-type=TXT", "acme-notes.example"])
        self.assertIn('text = "v=spf1 -all"', result.data)

    def test_dns_missing_tools(self):
        runner = FakeRunner({})
        result = awscli.run_dns("acme-notes.example", "TXT", runner=runner, which=lambda t: None)
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "ERROR")
        self.assertEqual(result.error_message, "dig/nslookup no disponibles")
        self.assertEqual(runner.calls, [])

    def test_dns_command_failure_is_error(self):
        runner = FakeRunner({("dig", None, None): {"stderr": "timed out", "returncode": 9}})
        result = awscli.run_dns("acme-notes.example", "TXT", runner=runner, which=lambda t: "/x")
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "ERROR")


if __name__ == "__main__":
    unittest.main()
