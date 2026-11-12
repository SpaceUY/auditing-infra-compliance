import json
import subprocess
import unittest

from tests.helpers import FakeRunner  # also puts scripts/ on sys.path

import aws_runner  # noqa: E402

OK = {"stdout": json.dumps({"Reservations": []}), "stderr": "", "returncode": 0}
THROTTLED = {"stdout": "", "stderr": "An error occurred (Throttling) when calling: Rate exceeded", "returncode": 254}
DENIED = {"stdout": "", "stderr": "An error occurred (AccessDenied) when calling the X operation", "returncode": 254}


def run(responses, service="ec2", operation="describe-instances", args=(), **kw):
    runner = FakeRunner(responses)
    sleeps = []
    kw.setdefault("region", "us-east-1")
    kw.setdefault("profile", None)
    result = aws_runner.run_aws(service, operation, list(args), runner=runner, sleep=sleeps.append, **kw)
    return result, runner, sleeps


class AssertReadOnlyTest(unittest.TestCase):
    def test_allows_describe_list_get(self):
        for service, op in (
            ("ec2", "describe-instances"),
            ("iam", "list-users"),
            ("iam", "get-account-summary"),
        ):
            with self.subTest(op=op):
                aws_runner.assert_read_only(service, op, [])

    def test_allows_exact_exceptions(self):
        aws_runner.assert_read_only("cloudtrail", "lookup-events", [])
        aws_runner.assert_read_only("iam", "generate-credential-report", [])
        aws_runner.assert_read_only("inspector2", "batch-get-account-status", [])

    def test_other_batch_get_operations_stay_rejected(self):
        for service, op in (("secretsmanager", "batch-get-secret-value"), ("dynamodb", "batch-get-item")):
            with self.subTest(op=op), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only(service, op, [])

    def test_rejects_write_ops(self):
        for service, op in (
            ("ec2", "modify-instance-metadata-options"),
            ("iam", "create-user"),
            ("s3api", "put-bucket-policy"),
            ("iam", "delete-access-key"),
            ("cloudtrail", "start-logging"),
        ):
            with self.subTest(op=op), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only(service, op, [])

    def test_rejects_denylist(self):
        for service, op in aws_runner.DENYLIST:
            op = "execute-statement" if op == "*" and service == "rds-data" else op
            op = "ls" if op == "*" and service == "s3" else op
            with self.subTest(service=service, op=op), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only(service, op, [])

    def test_wildcard_entries_cover_whole_service(self):
        with self.assertRaises(aws_runner.ReadOnlyViolation):
            aws_runner.assert_read_only("rds-data", "execute-statement", [])
        with self.assertRaises(aws_runner.ReadOnlyViolation):
            aws_runner.assert_read_only("s3", "ls", [])

    def test_rejects_with_decryption(self):
        with self.assertRaises(aws_runner.ReadOnlyViolation):
            aws_runner.assert_read_only("ssm", "describe-parameters", ["--with-decryption"])
        with self.assertRaises(aws_runner.ReadOnlyViolation):
            aws_runner.assert_read_only("ssm", "describe-parameters", ["--with-decryption=true"])

    def test_rejects_malformed_names(self):
        for service, op in (("ec2", "describe-instances; rm"), ("--profile", "list-x"), ("", "list-x")):
            with self.subTest(service=service, op=op), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only(service, op, [])


class ArgHardeningTest(unittest.TestCase):
    def test_rejects_trailing_newline_and_spaces_in_names(self):
        for service, op in (
            ("secretsmanager", "get-secret-value\n"),
            ("s3\n", "list-buckets"),
            (" s3", "list-buckets"),
            ("s3 ", "list-buckets"),
            ("iam", "list-users\n"),
        ):
            with self.subTest(service=service, op=op), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only(service, op, [])

    def test_rejects_with_decryption_abbreviations(self):
        for arg in ("--with-decrypt", "--with-decryp=true", "--with-dec", "--with-decryption ", " --with-decryption"):
            with self.subTest(arg=arg), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only("ssm", "describe-parameters", [arg])

    def test_rejects_forbidden_flags_exact_eq_and_prefix(self):
        flags = (
            "--endpoint-url", "--debug", "--cli-input-json", "--cli-input-yaml", "--no-verify-ssl",
            "--ca-bundle", "--profile", "--region", "--query", "--output",
        )
        for flag in flags:
            variants = [flag, flag + "=x"]
            variants += [flag[:n] for n in range(3, len(flag))]
            variants += [flag[:n] + "=x" for n in range(3, len(flag))]
            for arg in variants:
                with self.subTest(arg=arg), self.assertRaises(aws_runner.ReadOnlyViolation):
                    aws_runner.assert_read_only("ec2", "describe-instances", [arg])

    def test_rejects_short_abbreviations(self):
        for arg in ("--e", "--end", "--end=http://evil.example", "--pro", "--que", "--out", "--reg", "--ca-", "--deb", "--cli-i"):
            with self.subTest(arg=arg), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only("ec2", "describe-instances", [arg])

    def test_allows_legit_lookalike_flags(self):
        for arg in ("--region-name", "--query-string", "--output-location", "--endpoint-type", "--profile-name", "--debug-mode"):
            with self.subTest(arg=arg):
                aws_runner.assert_read_only("ec2", "describe-instances", [arg, "x"])

    def test_rejects_file_urls(self):
        for arg in ("file:///etc/passwd", "fileb://x", "--filters=file://x", "Name=a,Values=file://x"):
            with self.subTest(arg=arg), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only("ec2", "describe-instances", [arg])

    def test_rejects_non_string_args(self):
        for arg in (1, None, b"--x", ["a"]):
            with self.subTest(arg=arg), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only("ec2", "describe-instances", [arg])

    def test_allows_normal_args(self):
        aws_runner.assert_read_only(
            "ec2", "describe-instances", ["--instance-ids", "i-1", "--filters", "Name=tag:a,Values=b", "--max-items", "5"]
        )

    def test_new_denylist_entries(self):
        for pair in (
            ("sso", "get-role-credentials"), ("cognito-identity", "get-credentials-for-identity"),
            ("cognito-identity", "get-open-id-token"), ("cognito-identity", "get-open-id-token-for-developer-identity"),
            ("codeartifact", "get-authorization-token"), ("ecr-public", "get-authorization-token"),
            ("ecr", "get-login"), ("redshift", "get-cluster-credentials"),
            ("redshift", "get-cluster-credentials-with-iam"), ("redshift-serverless", "get-credentials"),
            ("ssm", "get-parameter-history"), ("logs", "get-query-results"), ("logs", "get-log-record"),
            ("logs", "get-log-object"), ("athena", "get-query-results"), ("ec2", "get-console-output"),
            ("ec2", "get-console-screenshot"), ("codecommit", "get-file"), ("codecommit", "get-blob"),
            ("codecommit", "get-folder"),
        ):
            self.assertIn(pair, aws_runner.DENYLIST)
            with self.subTest(pair=pair), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only(*pair, [])


class RunAwsTest(unittest.TestCase):
    def test_never_uses_shell(self):
        result, runner, _ = run({("ec2", "describe-instances", "us-east-1"): OK})
        self.assertTrue(result.ok)
        self.assertIsInstance(runner.calls[0], list)
        self.assertFalse(runner.kwargs[0].get("shell", False))
        self.assertEqual(runner.kwargs[0]["timeout"], 120)

    def test_write_op_never_reaches_runner(self):
        runner = FakeRunner({})
        with self.assertRaises(aws_runner.ReadOnlyViolation):
            aws_runner.run_aws("iam", "create-user", [], region=None, profile=None, runner=runner)
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

    def test_credential_report_in_progress_is_retried(self):
        in_progress = {"stdout": "", "returncode": 254, "stderr": "An error occurred (ReportInProgress) when calling the GetCredentialReport operation: not ready"}
        result, runner, sleeps = run({("iam", "get-credential-report", "us-east-1"): [in_progress, OK]}, "iam", "get-credential-report")
        self.assertTrue(result.ok)
        self.assertEqual(sleeps, [1])

    def test_access_denied_not_retried(self):
        result, runner, sleeps = run({("ec2", "describe-instances", "us-east-1"): DENIED})
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "ACCESS_DENIED")
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(sleeps, [])
        self.assertIn("AccessDenied", result.error_message)

    def test_scrubs_secret_bearing_keys_recursively(self):
        payload = {
            "Functions": [{"FunctionName": "f", "Environment": {"Variables": {"K": "v"}}, "Nested": [{"Environment": 1}]}]
        }
        result, _, _ = run(
            {("lambda", "list-functions", "us-east-1"): {"stdout": json.dumps(payload), "returncode": 0}},
            "lambda", "list-functions",
        )
        self.assertEqual(result.data, {"Functions": [{"FunctionName": "f", "Nested": [{}]}]})

    def test_scrubs_ecs_task_definition(self):
        payload = {"taskDefinition": {"containerDefinitions": [{"name": "c", "environment": [1], "secrets": [2]}]}}
        result, _, _ = run(
            {("ecs", "describe-task-definition", "us-east-1"): {"stdout": json.dumps(payload), "returncode": 0}},
            "ecs", "describe-task-definition",
        )
        self.assertEqual(result.data, {"taskDefinition": {"containerDefinitions": [{"name": "c"}]}})

    def test_no_scrub_for_other_operations(self):
        payload = {"Environment": "keep"}
        result, _, _ = run(
            {("ec2", "describe-instances", "us-east-1"): {"stdout": json.dumps(payload), "returncode": 0}}
        )
        self.assertEqual(result.data, payload)

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

        result = aws_runner.run_aws("ec2", "describe-instances", [], region=None, profile=None, runner=runner)
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "ERROR")

    def test_missing_aws_binary_is_error(self):
        def runner(argv, **kwargs):
            raise FileNotFoundError("aws")

        result = aws_runner.run_aws("ec2", "describe-instances", [], region=None, profile=None, runner=runner)
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
                "An error occurred (ReportInProgress) when calling the GetCredentialReport operation: Report generation in progress",
                "An error occurred (ReportNotPresent) when calling the GetCredentialReport operation: Report not present",
            ],
            "ERROR": ["An error occurred (ValidationError) when calling", "", "boom"],
        }
        for expected, samples in table.items():
            for stderr in samples:
                with self.subTest(expected=expected, stderr=stderr):
                    self.assertEqual(aws_runner.classify_error(stderr), expected)

    def test_resource_not_found_is_error_not_no_credentials(self):
        self.assertEqual(aws_runner.classify_error("Resource X could not be found"), "ERROR")

    def test_bad_request_without_not_enabled_is_error(self):
        self.assertEqual(aws_runner.classify_error("An error occurred (BadRequestException) when calling"), "ERROR")


class RunDnsTest(unittest.TestCase):
    def test_dig_preferred(self):
        runner = FakeRunner({("dig", None, None): {"stdout": '"v=spf1 -all"\n\n', "returncode": 0}})
        result = aws_runner.run_dns(
            "acme-notes.example", "TXT", runner=runner, which=lambda t: f"/usr/bin/{t}"
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.data, ['"v=spf1 -all"'])
        self.assertEqual(runner.calls[0], ["dig", "+short", "TXT", "acme-notes.example"])
        self.assertFalse(runner.kwargs[0].get("shell", False))

    def test_dns_falls_back_to_nslookup(self):
        runner = FakeRunner({("nslookup", None, None): {"stdout": "Server: x\ntext = \"v=spf1 -all\"\n", "returncode": 0}})
        which = lambda t: "/usr/bin/nslookup" if t == "nslookup" else None  # noqa: E731
        result = aws_runner.run_dns("acme-notes.example", "TXT", runner=runner, which=which)
        self.assertTrue(result.ok)
        self.assertEqual(runner.calls[0], ["nslookup", "-type=TXT", "acme-notes.example"])
        self.assertIn('text = "v=spf1 -all"', result.data)

    def test_dns_missing_tools(self):
        runner = FakeRunner({})
        result = aws_runner.run_dns("acme-notes.example", "TXT", runner=runner, which=lambda t: None)
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "ERROR")
        self.assertEqual(result.error_message, "dig/nslookup no disponibles")
        self.assertEqual(runner.calls, [])

    def test_dns_command_failure_is_error(self):
        runner = FakeRunner({("dig", None, None): {"stderr": "timed out", "returncode": 9}})
        result = aws_runner.run_dns("acme-notes.example", "TXT", runner=runner, which=lambda t: "/x")
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "ERROR")


if __name__ == "__main__":
    unittest.main()
