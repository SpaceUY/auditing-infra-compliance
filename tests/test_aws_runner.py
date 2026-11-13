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
        for service, op in (("secretsmanager", "batch-get-secret-value"), ("dynamodb", "batch-get-item"),
                            ("ec2", "batch-get-account-status"), ("secretsmanager", "batch-get-account-status")):
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

    def test_rejects_http_urls_the_cli_would_fetch(self):
        for arg in ("https://example.com/x", "http://169.254.169.254/latest/meta-data", "HTTPS://x", "--filters=https://example.com/x"):
            with self.subTest(arg=arg), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only("ec2", "describe-instances", ["--filters", arg])

    def test_allows_arguments_that_merely_contain_a_url(self):
        aws_runner.assert_read_only("ec2", "describe-instances", ["--filters", "Name=tag:u,Values=https://x"])

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


class ReviewTwoReadOnlyTests(unittest.TestCase):
    NEW_DENIED = (
        ("kinesis", "get-records"), ("kinesis", "get-shard-iterator"), ("dynamodbstreams", "get-records"),
        ("dynamodbstreams", "get-shard-iterator"), ("ebs", "get-snapshot-block"),
        ("lightsail", "get-instance-access-details"), ("lightsail", "get-relational-database-master-user-password"),
        ("glue", "get-connection"), ("glue", "get-connections"), ("connect", "get-federation-token"),
        ("ecr", "get-download-url-for-layer"), ("lambda", "get-layer-version-by-arn"), ("lambda", "get-layer-version"),
        ("quicksight", "get-dashboard-embed-url"), ("quicksight", "get-session-embed-url"),
        ("appconfig", "get-configuration"), ("appconfigdata", "get-latest-configuration"),
        ("redshift-data", "get-statement-result"), ("redshift-data", "get-statement-result-v2"),
        ("stepfunctions", "get-activity-task"), ("ec2", "get-launch-template-data"),
        ("cloudformation", "get-template"), ("apigateway", "get-export"), ("apigateway", "get-sdk"),
        ("codecommit", "get-commit"), ("codecommit", "get-differences"),
    )

    def test_review_two_denylist_additions(self):
        for service, op in self.NEW_DENIED:
            with self.subTest(op=f"{service} {op}"), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only(service, op, [])

    def test_operations_that_look_like_they_return_secrets_are_refused_without_being_listed(self):
        for service, op in (("newsvc", "get-signing-credentials"), ("newsvc", "describe-admin-password"),
                            ("newsvc", "get-auth-token"), ("newsvc", "list-secret-values"),
                            ("newsvc", "get-private-key"), ("newsvc", "get-signed-download-url")):
            with self.subTest(op=op), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only(service, op, [])

    def test_named_exceptions_to_the_sensitive_name_rule_still_run(self):
        for service, op in (("iam", "get-credential-report"), ("iam", "generate-credential-report"),
                            ("iam", "get-account-password-policy"), ("secretsmanager", "list-secrets"),
                            ("secretsmanager", "describe-secret")):
            with self.subTest(op=op):
                aws_runner.assert_read_only(service, op, [])

    def test_flags_that_make_a_listing_return_secret_values_are_refused(self):
        for arg in ("--include-values", "--include-value", "--include-value=true", "--include-val"):
            with self.subTest(arg=arg), self.assertRaises(aws_runner.ReadOnlyViolation):
                aws_runner.assert_read_only("apigateway", "get-api-keys", [arg])

    def test_denylist_and_allowlist_do_not_overlap(self):
        for service, op in aws_runner.DENYLIST:
            self.assertNotIn((service, op), aws_runner.ALLOWED_PAIRS)
            self.assertNotIn((service, op), aws_runner.SENSITIVE_NAME_EXCEPTIONS)


class ReviewTwoRunTests(unittest.TestCase):
    def test_a_cancelled_run_does_not_retry_a_throttled_call(self):
        runner = FakeRunner({("ec2", "describe-instances", "us-east-1"): THROTTLED})
        sleeps = []
        result = aws_runner.run_aws("ec2", "describe-instances", [], region="us-east-1", profile=None, runner=runner,
                                    sleep=sleeps.append, cancelled=lambda: True)
        self.assertEqual((result.ok, result.error_kind, len(runner.calls), sleeps), (False, "ERROR", 1, []))
        self.assertIn("cancelled", result.error_message)

    def test_credential_report_expired_is_retried(self):
        expired = {"stdout": "", "returncode": 254, "stderr": "An error occurred (ReportExpired) when calling the GetCredentialReport operation: expired"}
        result, _, sleeps = run({("iam", "get-credential-report", "us-east-1"): [expired, OK]}, "iam", "get-credential-report")
        self.assertTrue(result.ok)
        self.assertEqual(sleeps, [1])

    def test_new_error_spellings_are_classified(self):
        table = {
            "NO_CREDENTIALS": ["An error occurred (UnrecognizedClientException) when calling the ListFunctions operation: The security token included in the request is invalid",
                               "An error occurred (SignatureDoesNotMatch) when calling the ListUsers operation"],
            "THROTTLED": ["An error occurred (ThrottledException) when calling the X operation",
                          "An error occurred (RequestLimitExceeded) when calling the DescribeInstances operation"],
        }
        for expected, samples in table.items():
            for stderr in samples:
                with self.subTest(stderr=stderr):
                    self.assertEqual(aws_runner.classify_error(stderr), expected)


class RunAwsTest(unittest.TestCase):
    def test_never_uses_shell(self):
        result, runner, _ = run({("ec2", "describe-instances", "us-east-1"): OK})
        self.assertTrue(result.ok)
        self.assertIsInstance(runner.calls[0], list)
        self.assertFalse(runner.kwargs[0].get("shell", False))
        self.assertEqual(runner.kwargs[0]["timeout"], 120)

    def test_stdin_is_closed_so_prompts_fail_fast(self):
        _, runner, _ = run({("ec2", "describe-instances", "us-east-1"): OK})
        self.assertEqual(runner.kwargs[0]["stdin"], subprocess.DEVNULL)

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

    def test_scrubs_api_gateway_stage_variables(self):
        rest = {"item": [{"stageName": "prod", "variables": {"DB_URL": "x"}, "methodSettings": {}}]}
        result, _, _ = run(
            {("apigateway", "get-stages", "us-east-1"): {"stdout": json.dumps(rest), "returncode": 0}},
            "apigateway", "get-stages",
        )
        self.assertEqual(result.data, {"item": [{"stageName": "prod", "methodSettings": {}}]})
        http = {"Items": [{"StageName": "$default", "StageVariables": {"TOKEN": "x"}, "AutoDeploy": True}]}
        result, _, _ = run(
            {("apigatewayv2", "get-stages", "us-east-1"): {"stdout": json.dumps(http), "returncode": 0}},
            "apigatewayv2", "get-stages",
        )
        self.assertEqual(result.data, {"Items": [{"StageName": "$default", "AutoDeploy": True}]})

    def test_scrubs_sns_subscriber_endpoints(self):
        payload = {"Subscriptions": [{"SubscriptionArn": "PendingConfirmation", "Protocol": "email", "Endpoint": "oncall@acme-notes.example"}]}
        result, _, _ = run(
            {("sns", "list-subscriptions-by-topic", "us-east-1"): {"stdout": json.dumps(payload), "returncode": 0}},
            "sns", "list-subscriptions-by-topic",
        )
        self.assertEqual(result.data, {"Subscriptions": [{"SubscriptionArn": "PendingConfirmation", "Protocol": "email"}]})

    def test_masks_launch_template_user_data_but_keeps_its_presence(self):
        secret = "IyEvYmluL2Jhc2gKZXhwb3J0IERCX1BBU1M9aHVudGVyMg=="
        payload = {"LaunchTemplateVersions": [{"LaunchTemplateData": {"UserData": secret, "MetadataOptions": {"HttpTokens": "required"}}}]}
        result, runner, _ = run(
            {("ec2", "describe-launch-template-versions", "us-east-1"): {"stdout": json.dumps(payload), "returncode": 0}},
            "ec2", "describe-launch-template-versions",
        )
        data = result.data["LaunchTemplateVersions"][0]["LaunchTemplateData"]
        self.assertEqual(data["UserData"], "[REDACTED]")
        self.assertEqual(data["MetadataOptions"], {"HttpTokens": "required"})
        self.assertNotIn(secret, json.dumps(result.data))

    def test_masks_cloudfront_origin_custom_header_values(self):
        secret = "shared-origin-secret-value"
        origin = {"Id": "o", "DomainName": "alb.acme-notes.example",
                  "CustomHeaders": {"Quantity": 1, "Items": [{"HeaderName": "X-Origin-Verify", "HeaderValue": secret}]}}
        payload = {"DistributionList": {"Items": [{"Id": "E1", "Origins": {"Items": [origin]}, "WebACLId": "acl", "Enabled": True}]}}
        for operation in ("list-distributions", "get-distribution-config"):
            with self.subTest(operation=operation):
                result, _, _ = run(
                    {("cloudfront", operation, "us-east-1"): {"stdout": json.dumps(payload), "returncode": 0}},
                    "cloudfront", operation,
                )
                self.assertNotIn(secret, json.dumps(result.data))
                item = result.data["DistributionList"]["Items"][0]
                self.assertEqual((item["WebACLId"], item["Enabled"]), ("acl", True))
                headers = item["Origins"]["Items"][0]["CustomHeaders"]["Items"][0]
                self.assertEqual(headers, {"HeaderName": "X-Origin-Verify", "HeaderValue": "[REDACTED]"})

    def test_masks_eventbridge_target_payloads(self):
        secret = "webhook-token-123"
        targets = [{"Id": "t1", "Arn": "arn:aws:sns:us-east-1:111122223333:alerts", "Input": json.dumps({"token": secret}),
                    "InputTransformer": {"InputTemplate": secret}, "HttpParameters": {"HeaderParameters": {"Authorization": secret}}}]
        result, _, _ = run(
            {("events", "list-targets-by-rule", "us-east-1"): {"stdout": json.dumps({"Targets": targets}), "returncode": 0}},
            "events", "list-targets-by-rule",
        )
        self.assertNotIn(secret, json.dumps(result.data))
        (target,) = result.data["Targets"]
        self.assertEqual((target["Id"], target["Arn"]), ("t1", "arn:aws:sns:us-east-1:111122223333:alerts"))
        self.assertEqual((target["Input"], target["InputTransformer"], target["HttpParameters"]), ("[REDACTED]",) * 3)

    def test_masked_payload_keys_are_absent_when_absent(self):
        payload = {"Targets": [{"Id": "t1", "Arn": "arn"}]}
        result, _, _ = run(
            {("events", "list-targets-by-rule", "us-east-1"): {"stdout": json.dumps(payload), "returncode": 0}},
            "events", "list-targets-by-rule",
        )
        self.assertEqual(result.data, payload)

    def test_no_scrub_for_other_operations(self):
        payload = {"Environment": "keep"}
        result, _, _ = run(
            {("ec2", "describe-instances", "us-east-1"): {"stdout": json.dumps(payload), "returncode": 0}}
        )
        self.assertEqual(result.data, payload)

    def truncated(self, payload, args=(), operation="list-web-acls", service="wafv2"):
        return run({(service, operation, "us-east-1"): {"stdout": json.dumps(payload), "returncode": 0}},
                   service, operation, args=args)[0]

    def test_truncated_response_without_max_items_is_an_error(self):
        for payload in ({"WebACLs": [], "NextMarker": "abc"}, {"Rules": [], "NextToken": "t"}, {"Users": [], "Marker": "m"},
                        {"Users": [], "IsTruncated": True}):
            with self.subTest(payload=payload):
                result = self.truncated(payload)
                self.assertFalse(result.ok)
                self.assertEqual(result.error_kind, "ERROR")
                self.assertIn("truncated response", result.error_message)

    def test_complete_responses_are_not_flagged(self):
        for payload in ({"WebACLs": [], "NextMarker": None}, {"WebACLs": [], "NextMarker": ""}, {"Users": [], "IsTruncated": False},
                        {"Nested": {"NextToken": "x"}}, [{"NextToken": "x"}]):
            with self.subTest(payload=payload):
                self.assertTrue(self.truncated(payload).ok)

    def test_truncation_is_expected_when_max_items_is_passed(self):
        self.assertTrue(self.truncated({"findings": [], "NextToken": "t"}, args=["--max-items", "100"]).ok)
        self.assertTrue(self.truncated({"findings": [], "NextToken": "t"}, args=["--max-items=100"]).ok)

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
        self.assertEqual(result.error_message, "dig/nslookup not available")
        self.assertEqual(runner.calls, [])

    def test_dns_command_failure_is_error(self):
        runner = FakeRunner({("dig", None, None): {"stderr": "timed out", "returncode": 9}})
        result = aws_runner.run_dns("acme-notes.example", "TXT", runner=runner, which=lambda t: "/x")
        self.assertFalse(result.ok)
        self.assertEqual(result.error_kind, "ERROR")


if __name__ == "__main__":
    unittest.main()
