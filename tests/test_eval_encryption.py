import contextlib
import copy
import io
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import helpers
from helpers import SKILL_DIR, load_fixture

import aws_runner
import catalog
import collect
import evaluators
from test_eval_iam import RuleRunner, err, ok

try:
    import jmespath
except ImportError:  # the skill itself is stdlib-only; the JMESPath expressions are only verified when it is installed
    jmespath = None

ENCRYPTION_JSON = SKILL_DIR / "references" / "checks" / "encryption.json"
REFS = SKILL_DIR / "references"
REGION = "us-east-1"
OTHER = "eu-west-1"
NOW = "2026-11-12T12:00:00+00:00"
I1, I2, I3 = "i-0a1b2c3d4e5f60718", "i-0b2c3d4e5f6071829", "i-0c3d4e5f60718293a"
K_CUSTOMER = "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d"
K_AWS = "2b3c4d5e-6f7a-4b1c-9d2e-4f5a6b7c8d9e"
K_ASYM = "3c4d5e6f-7a8b-4c1d-8e2f-5a6b7c8d9e0f"
K_DISABLED = "4d5e6f7a-8b9c-4d1e-9f2a-6b7c8d9e0f1a"
K_EXTERNAL = "5e6f7a8b-9c0d-4e1f-8a2b-7c8d9e0f1a2b"
K_PENDING = "6f7a8b9c-0d1e-4f1a-9b2c-8d9e0f1a2b3c"
ALB_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/acme-notes-alb/50dc6c495c0c9188"
NLB_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/acme-notes-nlb/6d0ecf831eec9f09"
CERT_ISSUED = "arn:aws:acm:us-east-1:111122223333:certificate/7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d"
CERT_EXPIRED = "arn:aws:acm:us-east-1:111122223333:certificate/8b9c0d1e-2f3a-4b4c-9d5e-6f7a8b9c0d1e"
CERT_PENDING = "arn:aws:acm:us-east-1:111122223333:certificate/9c0d1e2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f"


def fx(name):
    return load_fixture(f"aws/encryption/{name}.json")


def evaluate(name, responses, params=None):
    return evaluators.EVALUATORS[name](responses, params or {})


def catalog_check(check_id):
    data = json.loads(ENCRYPTION_JSON.read_text(encoding="utf-8"))
    return next(c for c in data["checks"] if c["id"] == check_id)


def item(type_, id_, region=REGION, arn=""):
    return {"type": type_, "id": id_, "arn": arn, "name": id_, "region": region, "tags": []}


def instance(id_, region=REGION):
    return item("ec2_instance", id_, region)


def ids(offenders):
    return [o["resource_id"] for o in offenders]


def real(offenders):
    return [o for o in offenders if not o.get("not_applicable")]


def flags(offenders):
    return [(o["resource_id"], "not_applicable" if o.get("not_applicable") else "unverified" if o.get("unverified") else "offender")
            for o in offenders]


def for_each(call, pairs):
    """(responses entry, for_each entry) of a call answered once per (value, data)."""
    return {call: [(REGION, data) for _, data in pairs], "__for_each__": {call: [value for value, _ in pairs]}}


def merge(*parts):
    out = {"__for_each__": {}}
    for part in parts:
        part = dict(part)
        out["__for_each__"].update(part.pop("__for_each__", {}))
        out.update(part)
    return out


def deny_http_policy(bucket):
    statement = {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                 "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                 "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
    return {"Policy": json.dumps({"Version": "2012-10-17", "Statement": [statement]})}


class JmespathChecksTests(unittest.TestCase):
    def search(self, check_id, document):
        return jmespath.search(catalog_check(check_id)["verify"]["offenders"], document)

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_enc_002_reports_unencrypted_volumes(self):
        self.assertEqual(self.search("ENC-002", fx("ec2-describe-volumes-raw")), fx("ec2-describe-volumes-offenders"))
        self.assertEqual(self.search("ENC-002", {"Volumes": []}), [])

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_enc_002_a_missing_encrypted_field_is_not_encrypted(self):
        found = self.search("ENC-002", {"Volumes": [{"VolumeId": "vol-1", "State": "in-use", "Attachments": []}]})
        self.assertEqual([o["resource_id"] for o in found], ["vol-1"])

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_enc_004_reports_unencrypted_file_systems(self):
        self.assertEqual(self.search("ENC-004", fx("efs-describe-file-systems-raw")), fx("efs-describe-file-systems-offenders"))
        self.assertEqual(self.search("ENC-004", {"FileSystems": []}), [])

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_enc_008_reports_secrets_without_rotation(self):
        self.assertEqual(self.search("ENC-008", fx("secretsmanager-list-secrets-raw")), fx("secretsmanager-list-secrets-offenders"))
        self.assertEqual(self.search("ENC-008", {"SecretList": []}), [])

    @unittest.skipIf(jmespath is None, "jmespath not installed")
    def test_enc_008_rotation_enabled_false_is_reported(self):
        document = {"SecretList": [{"Name": "acme-notes/x", "RotationEnabled": False}]}
        self.assertEqual([o["resource_id"] for o in self.search("ENC-008", document)], ["acme-notes/x"])


class EbsDefaultEncryptionTests(unittest.TestCase):
    def responses(self, fixture, *items, region=REGION):
        return {"status": [(region, fx(f"ec2-get-ebs-encryption-by-default-{fixture}"))],
                "__inventory__": list(items) or [instance(I1), instance(I2)]}

    def test_ebs_default_encryption_pass(self):
        self.assertEqual(evaluate("ebs_default_encryption", self.responses("on")), [])

    def test_ebs_default_encryption_fail_reports_offenders(self):
        offenders = evaluate("ebs_default_encryption", self.responses("off"))
        self.assertEqual([(o["resource_id"], o["region"]) for o in offenders], [(I1, REGION), (I2, REGION)])
        self.assertEqual(offenders[0]["detail"]["reason"], "el cifrado de EBS por defecto está desactivado en la región")

    def test_only_the_instances_of_regions_without_default_encryption_fail(self):
        responses = self.responses("on", instance(I1), instance(I3, OTHER))
        responses["status"].append((OTHER, fx("ec2-get-ebs-encryption-by-default-off")))
        self.assertEqual([(o["resource_id"], o["region"]) for o in evaluate("ebs_default_encryption", responses)], [(I3, OTHER)])

    def test_region_without_an_answer_is_unverified_instead_of_passing(self):
        offenders = evaluate("ebs_default_encryption", self.responses("on", instance(I3, OTHER)))
        self.assertEqual(flags(offenders), [(I3, "unverified")])

    def test_other_resource_types_are_ignored(self):
        self.assertEqual(evaluate("ebs_default_encryption", self.responses("off", item("vpc", "vpc-1"))), [])


class RdsEncryptedTests(unittest.TestCase):
    def responses(self, instances=None, clusters=None):
        return {"instances": [(REGION, instances or fx("rds-describe-db-instances-raw"))],
                "clusters": [(REGION, clusters or fx("rds-describe-db-clusters-raw"))]}

    @staticmethod
    def all_encrypted(data, key):
        data = copy.deepcopy(data)
        for entry in data[key]:
            entry["StorageEncrypted"] = True
        return data

    def test_rds_encrypted_pass(self):
        responses = self.responses(self.all_encrypted(fx("rds-describe-db-instances-raw"), "DBInstances"),
                                   self.all_encrypted(fx("rds-describe-db-clusters-raw"), "DBClusters"))
        self.assertEqual([o for o in evaluate("rds_encrypted", responses) if not o.get("not_applicable")], [])

    def test_rds_encrypted_fail_reports_offenders(self):
        offenders = [o for o in evaluate("rds_encrypted", self.responses()) if not o.get("not_applicable")]
        self.assertEqual(ids(offenders), ["acme-notes-legacy", "acme-notes-aurora"])
        self.assertEqual((offenders[0]["detail"]["kind"], offenders[0]["detail"]["engine"]), ("instance", "mysql"))
        self.assertEqual(offenders[1]["detail"]["kind"], "cluster")

    def test_cluster_members_are_judged_through_their_cluster(self):
        found = evaluate("rds_encrypted", self.responses())
        self.assertEqual([(o["resource_id"], o.get("not_applicable")) for o in found if o.get("not_applicable")],
                         [("acme-notes-aurora-1", True)])

    def test_an_encrypted_cluster_passes_even_if_a_member_reports_otherwise(self):
        clusters = self.all_encrypted(fx("rds-describe-db-clusters-raw"), "DBClusters")
        found = evaluate("rds_encrypted", self.responses(clusters=clusters))
        self.assertEqual(ids([o for o in found if not o.get("not_applicable")]), ["acme-notes-legacy"])

    def test_instance_whose_cluster_was_not_listed_is_judged_on_its_own(self):
        found = evaluate("rds_encrypted", self.responses(clusters=fx("rds-describe-db-clusters-none")))
        self.assertEqual(ids(found), ["acme-notes-legacy", "acme-notes-aurora-1"])

    def test_missing_storage_encrypted_is_not_encrypted(self):
        data = {"DBInstances": [{"DBInstanceIdentifier": "acme-notes-x", "Engine": "mysql"}]}
        self.assertEqual(ids(evaluate("rds_encrypted", self.responses(data, fx("rds-describe-db-clusters-none")))), ["acme-notes-x"])


class S3DefaultEncryptionTests(unittest.TestCase):
    def responses(self, **buckets):
        return for_each("encryption", list(buckets.items()))

    def test_s3_default_encryption_pass(self):
        responses = self.responses(**{"acme-notes-data": fx("s3api-get-bucket-encryption-sse-s3"),
                                      "acme-notes-assets": fx("s3api-get-bucket-encryption-kms")})
        self.assertEqual(evaluate("s3_default_encryption", responses), [])

    def test_s3_default_encryption_fail_reports_offenders(self):
        responses = self.responses(**{"acme-notes-data": fx("s3api-get-bucket-encryption-sse-s3"),
                                      "acme-notes-uploads": {"__error__": "ServerSideEncryptionConfigurationNotFoundError"}})
        (offender,) = evaluate("s3_default_encryption", responses)
        self.assertEqual((offender["resource_id"], offender["region"]), ("acme-notes-uploads", REGION))
        self.assertEqual(offender["detail"]["reason"], "sin cifrado por defecto configurado")

    def test_deleted_bucket_is_not_applicable(self):
        (entry,) = evaluate("s3_default_encryption", self.responses(gone={"__error__": "NoSuchBucket"}))
        self.assertEqual(flags([entry]), [("gone", "not_applicable")])

    def test_unreadable_bucket_is_unverified_not_a_fail(self):
        responses = self.responses(denied={"__error__": "ACCESS_DENIED"}, broken={"__error__": "ERROR"},
                                   ok=fx("s3api-get-bucket-encryption-sse-s3"))
        found = evaluate("s3_default_encryption", responses)
        self.assertEqual(flags(found), [("denied", "unverified"), ("broken", "unverified")])
        self.assertEqual([o["detail"]["error_code"] for o in found], ["ACCESS_DENIED", "ERROR"])

    def test_algorithm_names_are_compared_ignoring_case(self):
        data = {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aes256"}}]}}
        self.assertEqual(evaluate("s3_default_encryption", self.responses(b=data)), [])

    def test_dual_layer_kms_passes(self):
        data = {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms:dsse"}}]}}
        self.assertEqual(evaluate("s3_default_encryption", self.responses(b=data)), [])

    def test_empty_rules_or_unknown_algorithm_fail(self):
        empty = {"ServerSideEncryptionConfiguration": {"Rules": []}}
        unknown = {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "none"}}]}}
        offenders = evaluate("s3_default_encryption", self.responses(a=empty, b=unknown))
        self.assertEqual(ids(offenders), ["a", "b"])


class KmsRotationTests(unittest.TestCase):
    def responses(self, *keys):
        """keys: (key id, describe fixture or {"__error__"}, rotation fixture or {"__error__"} or None)."""
        describe = [(k, d) for k, d, _ in keys]
        rotation = [(k, r) for k, _, r in keys if r is not None]
        return merge(for_each("describe", describe), for_each("rotation", rotation))

    def key(self, key_id, kind, rotation, **meta):
        data = fx(f"kms-describe-key-{kind}")
        data["KeyMetadata"].update(KeyId=key_id, **meta)
        return key_id, data, fx(f"kms-get-key-rotation-status-{rotation}") if isinstance(rotation, str) else rotation

    def test_kms_rotation_pass(self):
        self.assertEqual(evaluate("kms_rotation", self.responses(self.key(K_CUSTOMER, "customer", "on"))), [])

    def test_kms_rotation_fail_reports_offenders(self):
        (offender,) = evaluate("kms_rotation", self.responses(self.key(K_CUSTOMER, "customer", "off")))
        self.assertEqual((offender["resource_id"], offender["region"]), (K_CUSTOMER, REGION))
        self.assertEqual(offender["detail"]["reason"], "rotación automática deshabilitada")

    def test_aws_managed_keys_are_not_applicable_even_when_rotation_is_off(self):
        found = evaluate("kms_rotation", self.responses(self.key(K_AWS, "aws-managed", "off")))
        self.assertEqual(flags(found), [(K_AWS, "not_applicable")])

    def test_keys_outside_the_rotation_scope_are_not_applicable(self):
        unsupported = {"__error__": "UnsupportedOperationException"}
        found = evaluate("kms_rotation", self.responses(
            self.key(K_ASYM, "asymmetric", unsupported), self.key(K_DISABLED, "disabled", "off"),
            self.key(K_EXTERNAL, "external", unsupported), self.key(K_PENDING, "pending-deletion", "off")))
        self.assertEqual({flag for _, flag in flags(found)}, {"not_applicable"})
        self.assertEqual(len(found), 4)

    def test_only_the_offending_key_is_reported_among_several(self):
        found = evaluate("kms_rotation", self.responses(
            self.key(K_CUSTOMER, "customer", "on"), self.key(K_AWS, "aws-managed", "on"),
            self.key("7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0e", "customer", "off")))
        self.assertEqual(flags(found), [(K_AWS, "not_applicable"), ("7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0e", "offender")])

    def test_key_deleted_between_listing_and_describe_is_not_applicable(self):
        found = evaluate("kms_rotation", self.responses((K_CUSTOMER, {"__error__": "NotFoundException"}, None)))
        self.assertEqual(flags(found), [(K_CUSTOMER, "not_applicable")])

    def test_key_that_cannot_report_rotation_is_not_applicable(self):
        found = evaluate("kms_rotation", self.responses(self.key(K_CUSTOMER, "customer", {"__error__": "UnsupportedOperationException"})))
        self.assertEqual(flags(found), [(K_CUSTOMER, "not_applicable")])

    def test_key_policy_that_blocks_the_auditor_is_unverified_not_a_pass_or_a_fail(self):
        denied = {"__error__": "ACCESS_DENIED"}
        found = evaluate("kms_rotation", self.responses(
            self.key(K_CUSTOMER, "customer", "on"), (K_ASYM, denied, None), self.key(K_DISABLED, "customer", denied)))
        self.assertEqual(flags(found), [(K_ASYM, "unverified"), (K_DISABLED, "unverified")])
        self.assertTrue(all(o["detail"]["error_code"] == "ACCESS_DENIED" for o in found))

    def test_a_blocked_key_does_not_stop_the_other_keys_from_being_evaluated(self):
        found = evaluate("kms_rotation", self.responses((K_ASYM, {"__error__": "ACCESS_DENIED"}, None),
                                                         self.key(K_CUSTOMER, "customer", "off")))
        self.assertEqual(flags(found), [(K_ASYM, "unverified"), (K_CUSTOMER, "offender")])

    def test_unexpected_call_errors_are_unverified_not_not_applicable(self):
        for code in ("ERROR", "THROTTLED"):
            found = evaluate("kms_rotation", self.responses((K_CUSTOMER, {"__error__": code}, None),
                                                             self.key(K_DISABLED, "customer", {"__error__": code})))
            self.assertEqual(flags(found), [(K_CUSTOMER, "unverified"), (K_DISABLED, "unverified")], code)
            self.assertEqual(found[0]["detail"]["error_code"], code)

    def test_key_without_a_rotation_answer_is_unverified(self):
        found = evaluate("kms_rotation", self.responses((K_CUSTOMER, fx("kms-describe-key-customer"), None)))
        self.assertEqual(flags(found), [(K_CUSTOMER, "unverified")])

    def test_key_manager_is_compared_ignoring_case(self):
        found = evaluate("kms_rotation", self.responses(self.key(K_CUSTOMER, "customer", "off", KeyManager="customer")))
        self.assertEqual(ids(found), [K_CUSTOMER])


class KmsPendingDeletionTests(unittest.TestCase):
    def responses(self, **keys):
        return for_each("describe", [(k, d) for k, d in keys.items()])

    def test_kms_pending_deletion_pass(self):
        responses = self.responses(**{K_CUSTOMER: fx("kms-describe-key-customer"), K_AWS: fx("kms-describe-key-aws-managed"),
                                      K_DISABLED: fx("kms-describe-key-disabled")})
        self.assertEqual(evaluate("kms_pending_deletion", responses), [])

    def test_kms_pending_deletion_fail_reports_offenders(self):
        (offender,) = evaluate("kms_pending_deletion", self.responses(**{K_CUSTOMER: fx("kms-describe-key-customer"),
                                                                        K_PENDING: fx("kms-describe-key-pending-deletion")}))
        self.assertEqual((offender["resource_id"], offender["region"]), (K_PENDING, REGION))
        self.assertEqual((offender["detail"]["key_state"], offender["detail"]["deletion_date"]), ("PendingDeletion", "2026-11-30T12:00:00+00:00"))

    def test_replica_keys_scheduled_for_deletion_are_reported_too(self):
        data = {"KeyMetadata": {"KeyId": "k-1", "KeyState": "PendingReplicaDeletion"}}
        self.assertEqual(ids(evaluate("kms_pending_deletion", self.responses(**{"k-1": data}))), ["k-1"])

    def test_key_deleted_meanwhile_is_not_applicable_and_a_blocked_key_is_unverified(self):
        found = evaluate("kms_pending_deletion", self.responses(**{
            K_CUSTOMER: {"__error__": "NotFoundException"}, K_AWS: {"__error__": "ACCESS_DENIED"}, K_PENDING: fx("kms-describe-key-pending-deletion")}))
        self.assertEqual(flags(found), [(K_CUSTOMER, "not_applicable"), (K_AWS, "unverified"), (K_PENDING, "offender")])
        self.assertEqual(found[1]["detail"]["error_code"], "ACCESS_DENIED")


class S3TlsOnlyTests(unittest.TestCase):
    BUCKET = "acme-notes-assets"

    @staticmethod
    def policy(*statements):
        return {"Policy": json.dumps({"Version": "2012-10-17", "Statement": list(statements)})}

    def deny(self, **changes):
        statement = {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                     "Resource": [f"arn:aws:s3:::{self.BUCKET}", f"arn:aws:s3:::{self.BUCKET}/*"],
                     "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
        statement.update(changes)
        return {k: v for k, v in statement.items() if v is not None}

    def evaluate(self, data, bucket=None):
        return evaluate("s3_tls_only", for_each("policy", [(bucket or self.BUCKET, data)]))

    def test_s3_tls_only_pass(self):
        self.assertEqual(self.evaluate(fx("s3api-get-bucket-policy-tls-only")), [])

    def test_s3_tls_only_fail_reports_offenders(self):
        responses = for_each("policy", [("acme-notes-assets", fx("s3api-get-bucket-policy-tls-only")),
                                        ("acme-notes-uploads", fx("s3api-get-bucket-policy-no-tls-statement")),
                                        ("acme-notes-exports", {"__error__": "NoSuchBucketPolicy"})])
        offenders = evaluate("s3_tls_only", responses)
        self.assertEqual([(o["resource_id"], o["region"]) for o in offenders],
                         [("acme-notes-uploads", REGION), ("acme-notes-exports", REGION)])
        self.assertEqual(offenders[1]["detail"]["reason"], "sin bucket policy")
        self.assertEqual(offenders[0]["detail"]["reason"], "ninguna statement niega aws:SecureTransport=false sobre el bucket y sus objetos")

    def test_deleted_bucket_is_not_applicable(self):
        self.assertEqual(flags(self.evaluate({"__error__": "NoSuchBucket"})), [(self.BUCKET, "not_applicable")])

    def test_unreadable_policy_is_unverified_not_a_fail(self):
        for code in ("ACCESS_DENIED", "ERROR", "THROTTLED"):
            found = self.evaluate({"__error__": code})
            self.assertEqual(flags(found), [(self.BUCKET, "unverified")], code)
            self.assertEqual(found[0]["detail"]["error_code"], code)

    def test_deny_must_cover_the_bucket_and_its_objects(self):
        for resource in (f"arn:aws:s3:::{self.BUCKET}", f"arn:aws:s3:::{self.BUCKET}/*", f"arn:aws:s3:::{self.BUCKET}/private/*",
                         "arn:aws:s3:::acme-notes-other", ["arn:aws:s3:::acme-notes-other", "arn:aws:s3:::acme-notes-other/*"]):
            self.assertEqual(ids(self.evaluate(self.policy(self.deny(Resource=resource)))), [self.BUCKET], resource)

    def test_wildcard_resources_that_cover_both_pass(self):
        for resource in ("*", f"arn:aws:s3:::{self.BUCKET}*", "arn:aws:s3:::acme-notes-*", ["arn:aws:s3:::acme-notes-?ssets*"]):
            self.assertEqual(self.evaluate(self.policy(self.deny(Resource=resource))), [], resource)

    def test_two_statements_can_split_bucket_and_objects(self):
        policy = self.policy(self.deny(Resource=f"arn:aws:s3:::{self.BUCKET}"), self.deny(Resource=f"arn:aws:s3:::{self.BUCKET}/*"))
        self.assertEqual(self.evaluate(policy), [])

    def test_partition_of_the_arn_does_not_matter(self):
        resources = [f"arn:aws-us-gov:s3:::{self.BUCKET}", f"arn:aws-us-gov:s3:::{self.BUCKET}/*"]
        self.assertEqual(self.evaluate(self.policy(self.deny(Resource=resources))), [])

    def test_action_must_cover_every_s3_action(self):
        self.assertEqual(self.evaluate(self.policy(self.deny(Action="*"))), [])
        self.assertEqual(self.evaluate(self.policy(self.deny(Action=["s3:GetObject", "S3:*"]))), [])
        for action in ("s3:GetObject", ["s3:GetObject", "s3:PutObject"]):
            self.assertEqual(ids(self.evaluate(self.policy(self.deny(Action=action)))), [self.BUCKET], action)

    def test_effect_must_be_deny(self):
        self.assertEqual(ids(self.evaluate(self.policy(self.deny(Effect="Allow")))), [self.BUCKET])

    def test_condition_must_be_exactly_secure_transport_false(self):
        bad = ({"Bool": {"aws:SecureTransport": "true"}}, {"StringEquals": {"aws:SecureTransport": "false"}},
               {"Bool": {"aws:SecureTransport": "false", "aws:ViaAWSService": "false"}},
               {"Bool": {"aws:SecureTransport": "false"}, "StringNotEquals": {"aws:PrincipalOrgID": "o-acme"}},
               {"Bool": {"aws:MultiFactorAuthPresent": "false"}}, None)
        for condition in bad:
            self.assertEqual(ids(self.evaluate(self.policy(self.deny(Condition=condition)))), [self.BUCKET], condition)

    def test_equivalent_spellings_of_the_condition_pass(self):
        for condition in ({"Bool": {"aws:SecureTransport": False}}, {"Bool": {"aws:SecureTransport": ["false"]}},
                          {"BoolIfExists": {"aws:SecureTransport": "false"}}, {"Bool": {"aws:SecureTransport": "False"}}):
            self.assertEqual(self.evaluate(self.policy(self.deny(Condition=condition))), [], condition)

    def test_principal_must_be_everyone(self):
        for principal in ("*", {"AWS": "*"}, {"AWS": ["*"]}):
            self.assertEqual(self.evaluate(self.policy(self.deny(Principal=principal))), [], principal)
        for principal in ({"AWS": "arn:aws:iam::111122223333:root"}, {"Service": "cloudfront.amazonaws.com"}, None):
            self.assertEqual(ids(self.evaluate(self.policy(self.deny(Principal=principal)))), [self.BUCKET], principal)

    def test_negated_elements_are_not_counted(self):
        self.assertEqual(ids(self.evaluate(self.policy(self.deny(Resource=None, NotResource="arn:aws:s3:::other")))), [self.BUCKET])
        self.assertEqual(ids(self.evaluate(self.policy(self.deny(Action=None, NotAction="s3:GetObject")))), [self.BUCKET])
        self.assertEqual(ids(self.evaluate(self.policy(self.deny(Principal=None, NotPrincipal={"AWS": "x"})))), [self.BUCKET])

    def test_a_single_statement_object_is_accepted(self):
        data = {"Policy": json.dumps({"Version": "2012-10-17", "Statement": self.deny()})}
        self.assertEqual(self.evaluate(data), [])

    def test_unreadable_policy_fails(self):
        self.assertEqual(ids(self.evaluate({"Policy": "not json"})), [self.BUCKET])
        self.assertEqual(ids(self.evaluate({})), [self.BUCKET])


class AlbListenerTests(unittest.TestCase):
    def responses(self, *fixtures, arn=ALB_ARN, items=None):
        data = [(arn, fx(f"elbv2-describe-listeners-{name}") if isinstance(name, str) else name) for name in fixtures]
        return merge(for_each("listeners", data),
                     {"__inventory__": items or [item("elbv2", "acme-notes-alb", arn=ALB_ARN), item("elbv2", "acme-notes-nlb", arn=NLB_ARN)]})

    @staticmethod
    def listeners(*entries):
        return {"Listeners": list(entries)}

    @staticmethod
    def http(actions, port=80):
        return {"ListenerArn": f"arn:l/{port}", "Port": port, "Protocol": "HTTP", "DefaultActions": actions}

    @staticmethod
    def redirect(**changes):
        config = {"Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301"}
        config.update(changes)
        return [{"Type": "redirect", "RedirectConfig": config}]

    def redirects(self, actions):
        return evaluate("alb_http_redirect", self.responses(self.listeners(self.http(actions))))

    def test_alb_http_redirect_pass(self):
        self.assertEqual([o for o in evaluate("alb_http_redirect", self.responses("redirect-and-modern")) if not o.get("not_applicable")], [])

    def test_alb_http_redirect_fail_reports_offenders(self):
        (offender,) = real(evaluate("alb_http_redirect", self.responses("http-forward-and-legacy")))
        self.assertEqual((offender["resource_id"], offender["region"]), ("acme-notes-alb", REGION))
        self.assertEqual(offender["detail"]["listeners"], [{"port": 80, "reason": "la acción por defecto no redirige a HTTPS:443 con 301 o 302"}])
        self.assertEqual(offender["detail"]["arn"], ALB_ARN)

    def test_network_load_balancers_are_not_applicable(self):
        found = evaluate("alb_http_redirect", self.responses("redirect-and-modern"))
        self.assertEqual(flags(found), [("acme-notes-nlb", "not_applicable")])

    def test_status_codes_301_and_302_pass_and_others_fail(self):
        self.assertEqual([o for o in self.redirects(self.redirect(StatusCode="HTTP_302")) if not o.get("not_applicable")], [])
        self.assertEqual(ids([o for o in self.redirects(self.redirect(StatusCode="HTTP_307")) if not o.get("not_applicable")]), ["acme-notes-alb"])

    def test_redirect_must_target_https_on_443(self):
        for change in ({"Protocol": "HTTP"}, {"Port": "8443"}, {"Port": "#{port}"}):
            found = [o for o in self.redirects(self.redirect(**change)) if not o.get("not_applicable")]
            self.assertEqual(ids(found), ["acme-notes-alb"], change)

    def test_protocol_comparison_ignores_case(self):
        self.assertEqual([o for o in self.redirects(self.redirect(Protocol="https")) if not o.get("not_applicable")], [])

    def test_fixed_response_on_http_fails(self):
        found = [o for o in self.redirects([{"Type": "fixed-response"}]) if not o.get("not_applicable")]
        self.assertEqual(ids(found), ["acme-notes-alb"])

    def test_balancer_without_http_listeners_passes(self):
        found = evaluate("alb_http_redirect", self.responses(self.listeners()))
        self.assertEqual([o for o in found if not o.get("not_applicable")], [])

    def test_every_failing_http_listener_is_listed(self):
        data = self.listeners(self.http([{"Type": "forward"}], 80), self.http(self.redirect(), 8080), self.http([{"Type": "forward"}], 81))
        (offender,) = real(evaluate("alb_http_redirect", self.responses(data)))
        self.assertEqual([entry["port"] for entry in offender["detail"]["listeners"]], [80, 81])


class AlbTlsPolicyTests(unittest.TestCase):
    ACCEPTED = ("ELBSecurityPolicy-TLS13-1-2-2021-06", "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
                "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06", "ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04",
                "ELBSecurityPolicy-TLS13-1-3-2021-06", "ELBSecurityPolicy-FS-1-2-2019-08",
                "ELBSecurityPolicy-FS-1-2-Res-2019-08", "ELBSecurityPolicy-FS-1-2-Res-2020-10",
                "ELBSecurityPolicy-TLS-1-2-2017-01", "ELBSecurityPolicy-TLS-1-2-Ext-2018-06")
    REJECTED = ("ELBSecurityPolicy-TLS13-1-1-2021-06", "ELBSecurityPolicy-TLS13-1-0-2021-06",
                "ELBSecurityPolicy-TLS13-1-1-FIPS-2023-04", "ELBSecurityPolicy-FS-1-1-2019-08", "ELBSecurityPolicy-FS-2018-06",
                "ELBSecurityPolicy-TLS-1-1-2017-01", "ELBSecurityPolicy-TLS-1-0-2015-04", "ELBSecurityPolicy-2016-08",
                "ELBSecurityPolicy-2015-05", "ELBSample-OpenSSLDefaultCipherPolicy", "custom-policy", "")

    @staticmethod
    def responses(*listeners):
        data = {"Listeners": list(listeners)}
        return merge(for_each("listeners", [(ALB_ARN, data)]), {"__inventory__": [item("elbv2", "acme-notes-alb", arn=ALB_ARN)]})

    @staticmethod
    def https(policy, port=443, protocol="HTTPS"):
        listener = {"ListenerArn": f"arn:l/{port}", "Port": port, "Protocol": protocol, "DefaultActions": []}
        if policy is not None:
            listener["SslPolicy"] = policy
        return listener

    def test_alb_tls_policy_pass(self):
        self.assertEqual(evaluate("alb_tls_policy", self.responses(self.https("ELBSecurityPolicy-TLS13-1-2-2021-06"))), [])
        modern = merge(for_each("listeners", [(ALB_ARN, fx("elbv2-describe-listeners-redirect-and-modern"))]),
                       {"__inventory__": [item("elbv2", "acme-notes-alb", arn=ALB_ARN)]})
        self.assertEqual(evaluate("alb_tls_policy", modern), [])

    def test_alb_tls_policy_fail_reports_offenders(self):
        responses = merge(for_each("listeners", [(ALB_ARN, fx("elbv2-describe-listeners-http-forward-and-legacy"))]),
                          {"__inventory__": [item("elbv2", "acme-notes-alb", arn=ALB_ARN)]})
        (offender,) = evaluate("alb_tls_policy", responses)
        self.assertEqual((offender["resource_id"], offender["region"]), ("acme-notes-alb", REGION))
        self.assertEqual(offender["detail"]["listeners"], [{"port": 443, "ssl_policy": "ELBSecurityPolicy-2016-08"}])

    def test_accepted_policies_pass(self):
        for policy in self.ACCEPTED:
            self.assertEqual(evaluate("alb_tls_policy", self.responses(self.https(policy))), [], policy)

    def test_policies_that_allow_tls_1_0_or_1_1_fail_at_the_boundary(self):
        for policy in self.REJECTED:
            self.assertEqual(ids(evaluate("alb_tls_policy", self.responses(self.https(policy)))), ["acme-notes-alb"], policy)

    def test_listener_without_a_policy_fails(self):
        (offender,) = evaluate("alb_tls_policy", self.responses(self.https(None)))
        self.assertEqual(offender["detail"]["listeners"], [{"port": 443, "ssl_policy": None}])

    def test_http_listeners_are_not_judged(self):
        self.assertEqual(evaluate("alb_tls_policy", self.responses({"Port": 80, "Protocol": "HTTP", "DefaultActions": []})), [])

    def test_tls_listeners_of_an_alb_are_judged_by_protocol_ignoring_case(self):
        self.assertEqual(ids(evaluate("alb_tls_policy", self.responses(self.https("ELBSecurityPolicy-2016-08", protocol="https")))), ["acme-notes-alb"])

    def test_network_load_balancers_are_not_applicable(self):
        data = {"Listeners": [self.https("ELBSecurityPolicy-2016-08", protocol="TLS")]}
        responses = merge(for_each("listeners", [(NLB_ARN, data)]), {"__inventory__": [item("elbv2", "acme-notes-nlb", arn=NLB_ARN)]})
        self.assertEqual(flags(evaluate("alb_tls_policy", responses)), [("acme-notes-nlb", "not_applicable")])

    def test_every_failing_listener_is_listed(self):
        found = evaluate("alb_tls_policy", self.responses(self.https("ELBSecurityPolicy-2016-08", 443), self.https("ELBSecurityPolicy-TLS13-1-2-2021-06", 8443),
                                                          self.https("ELBSecurityPolicy-TLS-1-1-2017-01", 9443)))
        self.assertEqual([entry["port"] for entry in found[0]["detail"]["listeners"]], [443, 9443])


class RdsForceSslTests(unittest.TestCase):
    def responses(self, instances=None, clusters=None, params=(), cluster_params=()):
        """params / cluster_params: (group name, parameters fixture or {"__error__"})."""
        return merge({"instances": [(REGION, instances or fx("rds-describe-db-instances-raw"))],
                      "clusters": [(REGION, clusters or fx("rds-describe-db-clusters-raw"))]},
                     for_each("params", list(params)), for_each("cparams", list(cluster_params)))

    def full(self, **overrides):
        params = {"acme-notes-postgres-ssl": "postgres-ssl-on", "default.mysql8.0": "mysql-ssl-on"}
        params.update(overrides)
        return self.responses(params=[(g, fx(f"rds-describe-db-parameters-{f}")) for g, f in params.items()],
                              cluster_params=[("default.aurora-postgresql15", fx("rds-describe-db-cluster-parameters-postgres-ssl-on"))])

    @staticmethod
    def offenders(found):
        return [o for o in found if not o.get("not_applicable")]

    def test_rds_force_ssl_pass(self):
        self.assertEqual(self.offenders(evaluate("rds_force_ssl", self.full())), [])

    def test_rds_force_ssl_fail_reports_offenders(self):
        responses = self.responses(params=[("acme-notes-postgres-ssl", fx("rds-describe-db-parameters-postgres-ssl-off")),
                                           ("default.mysql8.0", fx("rds-describe-db-parameters-mysql-ssl-off"))],
                                   cluster_params=[("default.aurora-postgresql15", fx("rds-describe-db-cluster-parameters-postgres-ssl-off"))])
        offenders = self.offenders(evaluate("rds_force_ssl", responses))
        self.assertEqual([(o["resource_id"], o["region"]) for o in offenders],
                         [("acme-notes-db", REGION), ("acme-notes-legacy", REGION), ("acme-notes-aurora", REGION)])
        self.assertEqual(offenders[0]["detail"], {"kind": "instance", "engine": "postgres", "parameter_group": "acme-notes-postgres-ssl",
                                                  "parameter": "rds.force_ssl", "value": "0"})
        self.assertEqual((offenders[1]["detail"]["parameter"], offenders[1]["detail"]["value"]), ("require_secure_transport", "OFF"))
        self.assertEqual(offenders[2]["detail"]["kind"], "cluster")

    def test_cluster_members_are_judged_through_their_cluster(self):
        found = evaluate("rds_force_ssl", self.full())
        self.assertEqual([o["resource_id"] for o in found if o.get("not_applicable")], ["acme-notes-aurora-1"])

    def test_mysql_value_spellings(self):
        for value, expected in (("ON", []), ("on", []), ("1", []), ("OFF", ["acme-notes-legacy"]), ("0", ["acme-notes-legacy"])):
            data = {"Parameters": [{"ParameterName": "require_secure_transport", "ParameterValue": value}]}
            responses = self.full()
            responses["params"][1] = (REGION, data)
            self.assertEqual(ids(self.offenders(evaluate("rds_force_ssl", responses))), expected, value)

    def test_postgres_only_accepts_force_ssl_equal_to_1(self):
        for value, expected in (("1", []), ("0", ["acme-notes-db"]), ("2", ["acme-notes-db"]), (None, ["acme-notes-db"])):
            entry = {"ParameterName": "rds.force_ssl"}
            if value is not None:
                entry["ParameterValue"] = value
            responses = self.full()
            responses["params"][0] = (REGION, {"Parameters": [entry]})
            self.assertEqual(ids(self.offenders(evaluate("rds_force_ssl", responses))), expected, value)

    def test_parameter_missing_from_the_group_fails(self):
        responses = self.full()
        responses["params"][0] = (REGION, {"Parameters": [{"ParameterName": "max_connections", "ParameterValue": "100"}]})
        (offender,) = self.offenders(evaluate("rds_force_ssl", responses))
        self.assertEqual((offender["resource_id"], offender["detail"]["value"]), ("acme-notes-db", None))

    def test_engines_without_a_force_ssl_parameter_are_not_applicable(self):
        data = {"DBInstances": [{"DBInstanceIdentifier": "acme-notes-ora", "Engine": "oracle-ee",
                                 "DBParameterGroups": [{"DBParameterGroupName": "default.oracle-ee-19"}]}]}
        found = evaluate("rds_force_ssl", self.responses(data, fx("rds-describe-db-clusters-none")))
        self.assertEqual(flags(found), [("acme-notes-ora", "not_applicable")])

    def test_sql_server_uses_rds_force_ssl(self):
        data = {"DBInstances": [{"DBInstanceIdentifier": "acme-notes-mssql", "Engine": "sqlserver-se",
                                 "DBParameterGroups": [{"DBParameterGroupName": "acme-notes-mssql"}]}]}
        responses = self.responses(data, fx("rds-describe-db-clusters-none"), params=[("acme-notes-mssql", fx("rds-describe-db-parameters-postgres-ssl-off"))])
        self.assertEqual(ids(evaluate("rds_force_ssl", responses)), ["acme-notes-mssql"])

    def test_parameter_group_that_could_not_be_read_is_unverified(self):
        responses = self.full()
        responses["params"][0] = (REGION, {"__error__": "DBParameterGroupNotFound"})
        found = evaluate("rds_force_ssl", responses)
        self.assertEqual([f for f in flags(found) if f[1] != "not_applicable"], [("acme-notes-db", "unverified")])

    def test_group_names_do_not_leak_between_regions(self):
        responses = self.full()
        responses["params"] = [(OTHER, data) for _, data in responses["params"]]
        found = evaluate("rds_force_ssl", responses)
        self.assertEqual({f for _, f in flags(self.offenders(found))}, {"unverified"})


class AcmExpiryTests(unittest.TestCase):
    PARAMS = {"min_days": 30, "now": NOW}

    @staticmethod
    def certificate(arn, **changes):
        data = fx("acm-describe-certificate-issued")
        data["Certificate"].update(CertificateArn=arn, **changes)
        return arn, data

    def responses(self, *certificates):
        inventory = [item("acm_certificate", arn, arn=arn) for arn, _ in certificates]
        return merge(for_each("certificate", list(certificates)), {"__inventory__": inventory})

    def expiring_in(self, delta, **changes):
        not_after = (datetime.fromisoformat(NOW) + delta).isoformat()
        return evaluate("acm_expiry", self.responses(self.certificate(CERT_ISSUED, NotAfter=not_after, **changes)), self.PARAMS)

    def test_acm_expiry_pass(self):
        self.assertEqual(evaluate("acm_expiry", self.responses(self.certificate(CERT_ISSUED)), self.PARAMS), [])

    def test_acm_expiry_fail_reports_offenders(self):
        responses = self.responses((CERT_ISSUED, fx("acm-describe-certificate-issued")), (CERT_EXPIRED, fx("acm-describe-certificate-expired")))
        (offender,) = evaluate("acm_expiry", responses, self.PARAMS)
        self.assertEqual((offender["resource_id"], offender["region"]), (CERT_EXPIRED, REGION))
        self.assertEqual({k: offender["detail"][k] for k in ("domain", "type", "status", "not_after", "in_use")},
                         {"domain": "app.acme-notes.example", "type": "IMPORTED", "status": "ISSUED",
                          "not_after": "2020-01-01T00:00:00+00:00", "in_use": True})

    def test_more_than_30_days_left_passes_by_a_single_second(self):
        self.assertEqual(self.expiring_in(timedelta(days=30, seconds=1)), [])

    def test_exactly_30_days_left_fails(self):
        (offender,) = self.expiring_in(timedelta(days=30))
        self.assertEqual(offender["detail"]["days_left"], 30)

    def test_just_under_30_days_left_fails(self):
        self.assertEqual(ids(self.expiring_in(timedelta(days=30) - timedelta(seconds=1))), [CERT_ISSUED])

    def test_expired_certificates_fail(self):
        self.assertEqual(ids(self.expiring_in(timedelta(days=-1))), [CERT_ISSUED])

    def test_threshold_comes_from_the_params(self):
        responses = self.responses(self.certificate(CERT_ISSUED, NotAfter="2026-12-20T12:00:00+00:00"))
        self.assertEqual(ids(evaluate("acm_expiry", responses, {"min_days": 45, "now": NOW})), [CERT_ISSUED])
        self.assertEqual(evaluate("acm_expiry", responses, {"min_days": 30, "now": NOW}), [])

    def test_certificates_that_were_never_issued_are_not_applicable(self):
        responses = self.responses((CERT_PENDING, fx("acm-describe-certificate-pending")),
                                   self.certificate(CERT_ISSUED, Status="FAILED"), self.certificate(CERT_EXPIRED, Status="VALIDATION_TIMED_OUT"))
        self.assertEqual({flag for _, flag in flags(evaluate("acm_expiry", responses, self.PARAMS))}, {"not_applicable"})

    def test_certificate_removed_between_listing_and_describe_is_not_applicable(self):
        responses = self.responses((CERT_ISSUED, {"__error__": "ResourceNotFoundException"}))
        self.assertEqual(flags(evaluate("acm_expiry", responses, self.PARAMS)), [(CERT_ISSUED, "not_applicable")])

    def test_timestamps_without_an_offset_are_read_as_utc(self):
        self.assertEqual(ids(evaluate("acm_expiry", self.responses(self.certificate(CERT_ISSUED, NotAfter="2026-11-20T00:00:00")), self.PARAMS)),
                         [CERT_ISSUED])


class EncryptionCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks = json.loads(ENCRYPTION_JSON.read_text(encoding="utf-8"))["checks"]

    def test_encryption_catalog_valid(self):
        data = json.loads(ENCRYPTION_JSON.read_text(encoding="utf-8"))
        for check in data["checks"]:
            check.setdefault("domain", data["domain"])
        tsc_ids, iso_ids = catalog.load_frameworks(REFS / "frameworks")
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        self.assertEqual(catalog.validate(data["checks"], tsc_ids, iso_ids, drata), [])
        self.assertEqual([c["id"] for c in data["checks"]], [f"ENC-{n:03d}" for n in range(1, 9)] + [f"TLS-{n:03d}" for n in range(1, 6)])
        self.assertEqual(data["domain"], "encryption")

    def test_every_python_evaluator_is_registered(self):
        for check in self.checks:
            kind, _, name = check["verify"]["evaluator"].partition(":")
            if kind == "python":
                self.assertIn(name, evaluators.EVALUATORS, check["id"])

    def test_evaluator_kinds(self):
        expected = {"ENC-001": "python:ebs_default_encryption", "ENC-002": "jmespath", "ENC-003": "python:rds_encrypted",
                    "ENC-004": "jmespath", "ENC-005": "python:s3_default_encryption", "ENC-006": "python:kms_rotation",
                    "ENC-007": "python:kms_pending_deletion", "ENC-008": "jmespath", "TLS-001": "python:s3_tls_only",
                    "TLS-002": "python:alb_http_redirect", "TLS-003": "python:alb_tls_policy", "TLS-004": "python:rds_force_ssl",
                    "TLS-005": "python:acm_expiry"}
        self.assertEqual({c["id"]: c["verify"]["evaluator"] for c in self.checks}, expected)

    def test_severities_follow_the_brief(self):
        expected = {"ENC-001": "high", "ENC-002": "high", "ENC-003": "high", "ENC-004": "high", "ENC-005": "high", "ENC-006": "high",
                    "ENC-007": "medium", "ENC-008": "medium", "TLS-001": "high", "TLS-002": "high", "TLS-003": "medium",
                    "TLS-004": "medium", "TLS-005": "medium"}
        self.assertEqual({c["id"]: c["severity"] for c in self.checks}, expected)

    def test_remediation_kinds_follow_the_brief(self):
        expected = {"ENC-001": "cli", "ENC-002": "planned_change", "ENC-003": "planned_change", "ENC-004": "planned_change",
                    "ENC-005": "cli_with_decision", "ENC-006": "cli", "ENC-007": "cli_with_decision", "ENC-008": "cli_with_decision",
                    "TLS-001": "cli_with_decision", "TLS-002": "cli_with_decision", "TLS-003": "cli_with_decision", "TLS-004": "planned_change",
                    "TLS-005": "planned_change"}
        self.assertEqual({c["id"]: c["remediation"]["kind"] for c in self.checks}, expected)

    def test_scopes_resource_types_and_regions(self):
        expected = {"ENC-001": ["ec2_instance"], "ENC-002": ["ebs_volume"], "ENC-003": ["rds_instance", "rds_cluster"],
                    "ENC-004": ["efs"], "ENC-005": ["s3_bucket"], "ENC-006": ["kms_key"], "ENC-007": ["kms_key"],
                    "ENC-008": ["secret"], "TLS-001": ["s3_bucket"], "TLS-002": ["elbv2"], "TLS-003": ["elbv2"],
                    "TLS-004": ["rds_instance", "rds_cluster"], "TLS-005": ["acm_certificate"]}
        self.assertEqual({c["id"]: c["resource_types"] for c in self.checks}, expected)
        self.assertTrue(all(c["scope"] == "resource" and c["all_regions"] is False for c in self.checks))

    def test_steps_are_not_numbered_by_hand(self):
        for check in self.checks:
            for step in check["remediation"]["steps"]:
                self.assertNotRegex(step, r"^\d+\.\s", check["id"])

    def test_remediation_commands_follow_cloudshell_rules(self):
        for check in self.checks:
            rem = check["remediation"]
            self.assertTrue(rem["commands"], check["id"])
            for command in rem["commands"]:
                self.assertTrue(command.startswith('REGION="{region}"\nACCOUNT_ID="{account_id}"\n'), check["id"])
                self.assertNotIn("set -e", command, check["id"])
                self.assertNotIn("<<", command, check["id"])
            self.assertTrue(rem["verify_after"].startswith("aws "), check["id"])

    def test_planned_changes_warn_in_notes(self):
        for check in self.checks:
            if check["remediation"]["kind"] == "planned_change":
                self.assertGreaterEqual(len(check["remediation"]["steps"]), 2, check["id"])
                self.assertTrue(check["remediation"]["notes"].strip(), check["id"])

    def test_drata_mapped_checks_resolve_from_the_dcf_file(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        expected = {"ENC-001": 218, "ENC-002": 218, "ENC-003": 68, "ENC-004": 231, "ENC-005": 69, "ENC-006": 223,
                    "TLS-001": 234, "TLS-002": 299}
        for check_id, test in expected.items():
            resolved = catalog.resolve_mappings(catalog_check(check_id), drata)
            self.assertEqual([m["test"] for m in resolved["drata"]], [test], check_id)
            self.assertTrue(resolved["tsc"] and all(t["sourced"] == catalog.DCF_SOURCE for t in resolved["tsc"]), check_id)

    def test_checks_without_a_resolvable_drata_test_carry_inferred_mappings(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        for check_id in ("ENC-007", "ENC-008", "TLS-003", "TLS-004", "TLS-005"):
            resolved = catalog.resolve_mappings(catalog_check(check_id), drata)
            self.assertTrue(resolved["tsc"] and resolved["iso27001_2022"], check_id)
            self.assertTrue(all(m["sourced"] is False for m in resolved["tsc"] + resolved["iso27001_2022"]), check_id)

    def test_tls_004_has_no_security_hub_control(self):
        mappings = catalog_check("TLS-004")["mappings"]
        self.assertEqual((mappings["security_hub"], mappings["tsc_inferred"], mappings["iso_inferred"]), ([], ["CC6.7"], ["A.8.24"]))

    def test_vanta_tests_follow_the_cis_table(self):
        expected = {"ENC-001": "EBS volume encryption is enabled in all regions", "ENC-003": "Encryption at rest is enabled for RDS instances",
                    "ENC-004": "EFS file systems are encrypted", "ENC-006": "Rotation is enabled for customer-created symmetric KMS keys",
                    "TLS-001": "Bucket policies deny HTTP requests"}
        for check_id, name in expected.items():
            self.assertEqual([m["test"] for m in catalog_check(check_id)["mappings"]["vanta"]], [name], check_id)

    def test_tls_005_has_no_vanta_mapping_because_it_does_not_evaluate_iam_certificates(self):
        self.assertEqual(catalog_check("TLS-005")["mappings"]["vanta"], [])

    def test_security_hub_and_cis_controls_follow_the_brief(self):
        expected = {"ENC-001": ("EC2.7", "5.1.1"), "ENC-002": ("EC2.3", None), "ENC-003": ("RDS.3", "2.2.1"), "ENC-004": ("EFS.1", None),
                    "ENC-006": ("KMS.4", "3.6"), "ENC-007": ("KMS.3", None), "ENC-008": ("SecretsManager.1", None),
                    "TLS-001": ("S3.5", "2.1.1"), "TLS-002": ("ELB.1", None), "TLS-003": ("ELB.17", None), "TLS-005": ("ACM.1", None)}
        for check_id, (control, cis) in expected.items():
            mappings = catalog_check(check_id)["mappings"]
            self.assertIn(control, mappings["security_hub"], check_id)
            if cis:
                self.assertIn(cis, mappings["cis_aws"], check_id)

    def test_s3_calls_declare_the_errors_that_mean_not_configured(self):
        encryption = catalog_check("ENC-005")["verify"]["calls"][0]
        self.assertEqual((encryption["operation"], encryption["region"]), ("get-bucket-encryption", "global"))
        self.assertEqual(encryption["ok_errors"], ["ServerSideEncryptionConfigurationNotFoundError", "NoSuchBucket"])
        policy = catalog_check("TLS-001")["verify"]["calls"][0]
        self.assertEqual((policy["operation"], policy["for_each"]), ("get-bucket-policy", {"from": "__inventory__", "path": "id", "arg": "--bucket"}))
        self.assertEqual(policy["ok_errors"], ["NoSuchBucketPolicy", "NoSuchBucket"])

    def test_kms_calls_tolerate_keys_that_do_not_support_rotation(self):
        calls = {c["name"]: c for c in catalog_check("ENC-006")["verify"]["calls"]}
        self.assertEqual(set(calls), {"describe", "rotation"})
        self.assertEqual(calls["describe"]["ok_errors"], ["NotFoundException"])
        self.assertIn("UnsupportedOperationException", calls["rotation"]["ok_errors"])
        self.assertEqual(calls["rotation"]["operation"], "get-key-rotation-status")
        for call in calls.values():
            self.assertEqual(call["for_each"], {"from": "__inventory__", "path": "id", "arg": "--key-id"})
            self.assertEqual(call["item_errors"], "evaluator")

    def test_enc_007_reads_each_key_and_lets_the_evaluator_handle_failures(self):
        (call,) = catalog_check("ENC-007")["verify"]["calls"]
        self.assertEqual((call["operation"], call["ok_errors"], call["item_errors"]), ("describe-key", ["NotFoundException"], "evaluator"))
        self.assertEqual(call["for_each"], {"from": "__inventory__", "path": "id", "arg": "--key-id"})

    def test_acm_threshold_is_a_param(self):
        self.assertEqual(catalog_check("TLS-005")["verify"]["params"], {"min_days": 30})

    def test_enc_003_replaces_the_instance_through_a_snapshot_with_downtime(self):
        rem = catalog_check("ENC-003")["remediation"]
        self.assertTrue(rem["downtime"])
        text = "\n".join(rem["commands"])
        self.assertRegex(text, r"create-db-snapshot [^\n]*&&[^\n]*wait db-snapshot-available[^\n]*&&[^\n]*copy-db-snapshot [^\n]*--kms-key-id[^\n]*&&[^\n]*wait db-snapshot-available[^\n]*&&[^\n]*restore-db-instance-from-db-snapshot")
        self.assertRegex(text, r"create-db-cluster-snapshot [^\n]*&&[^\n]*copy-db-cluster-snapshot [^\n]*--kms-key-id[^\n]*&&[^\n]*restore-db-cluster-from-snapshot")
        self.assertRegex(" ".join(rem["steps"]), r"(?i)endpoint")

    def test_enc_002_encrypts_a_copy_of_the_snapshot_before_replacing_the_volume(self):
        rem = catalog_check("ENC-002")["remediation"]
        self.assertTrue(rem["downtime"])
        command = "\n".join(rem["commands"])
        self.assertRegex(command, r"create-snapshot [^\n]*&&[^\n]*wait snapshot-completed[^\n]*&&[^\n]*copy-snapshot [^\n]*--encrypted[^\n]*&&[^\n]*wait snapshot-completed[^\n]*&&[^\n]*create-volume ")
        self.assertNotRegex(command, r"detach-volume[^\n]*\n[^\n]*create-snapshot")

    def test_enc_004_cannot_be_fixed_in_place(self):
        rem = catalog_check("ENC-004")["remediation"]
        self.assertTrue(rem["downtime"])
        self.assertRegex(rem["notes"], r"(?i)no se puede")
        self.assertIn("create-file-system", "\n".join(rem["commands"]))
        self.assertIn("--encrypted", "\n".join(rem["commands"]))

    def test_tls_001_merges_the_deny_statement_with_python3_and_applies_it_in_a_separate_command(self):
        rem = catalog_check("TLS-001")["remediation"]
        self.assertEqual(rem["kind"], "cli_with_decision")
        prepare = next(c for c in rem["commands"] if "python3 -c" in c)
        read = next(c for c in rem["commands"] if "get-bucket-policy" in c)
        self.assertRegex(read, r'get-bucket-policy [^\n]*>\s*"policy-\$BUCKET\.json"')  # review 2 C: read first, in its own block
        self.assertIn('[ ! -s "policy-$BUCKET.json" ]', prepare)  # the merge refuses to run without what the read block saved
        self.assertIn("aws:SecureTransport", prepare)
        self.assertNotIn("put-bucket-policy", prepare)
        self.assertTrue(any("put-bucket-policy" in c and "python3" not in c for c in rem["commands"]))

    def test_tls_001_temp_files_are_per_bucket_so_a_stale_file_cannot_be_applied(self):
        commands = catalog_check("TLS-001")["remediation"]["commands"]
        for command in commands:
            self.assertNotRegex(command, r"policy(-new)?\.json", command)
        apply = next(c for c in commands if "put-bucket-policy" in c)
        self.assertIn('--policy "file://policy-$BUCKET-new.json"', apply)
        self.assertIn('BUCKET="{resource_id}"', apply)

    def run_prepare_snippet(self, tmp, existing, bucket="acme-notes-assets"):
        import subprocess
        prepare = next(c for c in catalog_check("TLS-001")["remediation"]["commands"] if "python3 -c" in c)
        snippet = prepare.split("python3 -c '", 1)[1].split("' ", 1)[0]
        Path(tmp, f"policy-{bucket}.json").write_text(json.dumps(existing), encoding="utf-8")
        subprocess.run(["python3", "-c", snippet, bucket], cwd=tmp, check=True)
        return json.loads(Path(tmp, f"policy-{bucket}-new.json").read_text(encoding="utf-8"))

    EXISTING = {"Version": "2012-10-17", "Statement": [{"Sid": "Existing", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                                         "Resource": "arn:aws:s3:::acme-notes-assets/*"}]}

    def test_tls_001_prepared_policy_is_valid_and_keeps_the_existing_statements(self):
        with tempfile.TemporaryDirectory() as tmp:
            merged = self.run_prepare_snippet(tmp, self.EXISTING)
        self.assertEqual([s["Sid"] for s in merged["Statement"]], ["Existing", "DenyInsecureTransport"])
        self.assertEqual(self.evaluate_policy(merged, "acme-notes-assets"), [])

    def test_tls_001_prepared_policy_does_not_repeat_an_existing_deny_statement(self):
        with tempfile.TemporaryDirectory() as tmp:
            once = self.run_prepare_snippet(tmp, self.EXISTING)
            twice = self.run_prepare_snippet(tmp, once)
        self.assertEqual(once, twice)
        self.assertEqual([s["Sid"] for s in twice["Statement"]].count("DenyInsecureTransport"), 1)

    def test_tls_001_a_single_statement_object_is_converted_to_a_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            merged = self.run_prepare_snippet(tmp, {"Version": "2012-10-17", "Statement": self.EXISTING["Statement"][0]})
        self.assertEqual([s["Sid"] for s in merged["Statement"]], ["Existing", "DenyInsecureTransport"])

    def test_tls_001_prepare_snippet_uses_the_files_of_its_own_bucket(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "policy-acme-notes-other.json").write_text(json.dumps({"Statement": []}), encoding="utf-8")
            merged = self.run_prepare_snippet(tmp, self.EXISTING)
            self.assertTrue(Path(tmp, "policy-acme-notes-assets-new.json").exists())
            self.assertFalse(Path(tmp, "policy-acme-notes-other-new.json").exists())
        self.assertEqual(len(merged["Statement"]), 2)

    @staticmethod
    def evaluate_policy(document, bucket):
        responses = for_each("policy", [(bucket, {"Policy": json.dumps(document)})])
        return evaluate("s3_tls_only", responses)

    def test_tls_002_redirects_every_http_listener_to_https(self):
        command = catalog_check("TLS-002")["remediation"]["commands"][0]
        self.assertRegex(command, r"describe-load-balancers [^\n]*\n[^\n]*Protocol==`HTTPS` && Port==`443`[\s\S]*for [^\n]*describe-listeners [^\n]*Protocol==`HTTP`")
        self.assertIn("Type=redirect,RedirectConfig={Protocol=HTTPS,Port=443,StatusCode=HTTP_301}", command)
        self.assertRegex(catalog_check("TLS-002")["remediation"]["notes"], r"(?i)listener HTTPS")

    def test_tls_002_says_that_only_the_default_action_is_evaluated(self):
        check = catalog_check("TLS-002")
        self.assertRegex(check["verify"]["pass_when_text"], r"acción por defecto del listener; las reglas del listener no")
        self.assertRegex(check["remediation"]["notes"], r"reglas del listener no se tocan ni se revisan")

    def test_tls_003_recommends_the_tls_1_3_policy_and_warns_about_old_clients(self):
        rem = catalog_check("TLS-003")["remediation"]
        self.assertIn("ELBSecurityPolicy-TLS13-1-2-2021-06", rem["commands"][0])
        self.assertIn("--ssl-policy", rem["commands"][0])
        self.assertRegex(rem["notes"], r"(?i)clientes")

    def test_tls_004_creates_a_parameter_group_and_reboots_in_a_separate_command(self):
        rem = catalog_check("TLS-004")["remediation"]
        self.assertTrue(rem["downtime"])
        first = rem["commands"][0]
        self.assertRegex(first, r"create-db-parameter-group [^\n]*&&[^\n]*modify-db-parameter-group [^\n]*&&[^\n]*modify-db-instance ")
        self.assertTrue(any("reboot-db-instance" in c and "create-db-parameter-group" not in c for c in rem["commands"]))
        self.assertTrue(any("modify-db-cluster-parameter-group" in c for c in rem["commands"]))

    def test_tls_005_checks_the_renewal_status_before_replacing_the_certificate(self):
        commands = "\n".join(catalog_check("TLS-005")["remediation"]["commands"])
        self.assertIn("describe-certificate", commands)
        self.assertIn("import-certificate", commands)
        self.assertIn("request-certificate", commands)

    def test_enc_006_enables_rotation_and_enc_007_enables_the_key_again_after_cancelling(self):
        self.assertIn("enable-key-rotation", catalog_check("ENC-006")["remediation"]["commands"][0])
        self.assertRegex(catalog_check("ENC-007")["remediation"]["commands"][-1], r"cancel-key-deletion [^\n]*&&\s*aws kms enable-key ")

    def test_enc_008_needs_a_rotation_function(self):
        rem = catalog_check("ENC-008")["remediation"]
        self.assertIn("__COMPLETAR_ARN_LAMBDA_ROTACION__", rem["commands"][0])
        self.assertIn("AutomaticallyAfterDays=90", rem["commands"][0])

    def test_no_key_shaped_literals(self):
        text = ENCRYPTION_JSON.read_text(encoding="utf-8")
        self.assertNotRegex(text, r"A[SK]IA[0-9A-Z]{8,}")


class EncryptionCollectTests(unittest.TestCase):
    """The whole encryption catalog through collect.main with a fake AWS: wiring of calls, for_each, ok_errors and args."""

    TYPES = ("ec2_instance", "ebs_volume", "rds_instance", "rds_cluster", "s3_bucket", "efs", "elbv2", "kms_key", "secret",
             "acm_certificate")
    BUCKETS = ("acme-notes-data", "acme-notes-logs")
    K_DENIED = "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0e"
    KEYS = (K_CUSTOMER, K_AWS, K_ASYM, K_PENDING, K_DENIED)

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        (cls.tmp / "checks").mkdir()
        shutil.copy(ENCRYPTION_JSON, cls.tmp / "checks" / "encryption.json")
        specs = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))
        (cls.tmp / "inventory.json").write_text(json.dumps({t: specs[t] for t in cls.TYPES}), encoding="utf-8")
        scope = {"platform": "Acme Notes", "mode": "full", "target": None, "regions": [REGION], "profile": None,
                 "resources": [], "domains": None}
        (cls.tmp / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
        cls.runner = RuleRunner(cls.rules())
        out = cls.tmp / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            cls.code = collect.main(
                ["--scope", str(cls.tmp / "scope.json"), "--out", str(out), "--checks-dir", str(cls.tmp / "checks"),
                 "--inventory", str(cls.tmp / "inventory.json"), "--quiet"],
                runner=cls.runner, sleep=lambda s: None, which=lambda name: None)
        cls.result = json.loads((out / "checks-result.json").read_text(encoding="utf-8"))

    @classmethod
    def rules(cls):
        core = lambda name: ok(load_fixture(f"aws/core/{name}.json"))
        enc = lambda name: ok(fx(name))
        no_policy = err("An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation: The bucket policy does not exist")
        no_encryption = err("An error occurred (ServerSideEncryptionConfigurationNotFoundError) when calling the GetBucketEncryption "
                            "operation: The server side encryption configuration was not found")
        denied = err("An error occurred (AccessDeniedException) when calling the DescribeKey operation: User: arn:aws:iam::111122223333:user/auditor "
                     "is not authorized to perform: kms:DescribeKey on resource: key because no resource-based policy allows the kms:DescribeKey action")
        invalid_state = err("An error occurred (KMSInvalidStateException) when calling the GetKeyRotationStatus operation: key is pending deletion")
        unsupported = err("An error occurred (UnsupportedOperationException) when calling the GetKeyRotationStatus operation: "
                          "You cannot perform this operation on an asymmetric KMS key")
        listing = {"Keys": [{"KeyId": k, "KeyArn": f"arn:aws:kms:us-east-1:111122223333:key/{k}"} for k in cls.KEYS]}
        loadbalancers = {"LoadBalancers": [{"LoadBalancerName": "acme-notes-alb", "LoadBalancerArn": ALB_ARN, "Type": "application"},
                                           {"LoadBalancerName": "acme-notes-nlb", "LoadBalancerArn": NLB_ARN, "Type": "network"}]}
        certificates = {"CertificateSummaryList": [{"CertificateArn": CERT_ISSUED, "DomainName": "app.acme-notes.example"},
                                                   {"CertificateArn": CERT_EXPIRED, "DomainName": "app.acme-notes.example"}]}
        instances = {"Reservations": [{"Instances": [{"InstanceId": i, "State": {"Name": "running"}} for i in (I1, I2)]}]}
        return [
            ("sts", "get-caller-identity", None, "", core("sts-get-caller-identity")),
            ("ec2", "describe-regions", None, "", core("ec2-describe-regions")),
            ("iam", "list-attached-user-policies", None, "", ok({"AttachedPolicies": []})),
            # inventory listings (no --query) next to the checks that use --query
            ("ec2", "describe-instances", None, "", ok(instances)),
            ("ec2", "describe-volumes", None, "Volumes[?", enc("ec2-describe-volumes-offenders")),
            ("ec2", "describe-volumes", None, "", enc("ec2-describe-volumes-raw")),
            ("efs", "describe-file-systems", None, "Encrypted", enc("efs-describe-file-systems-offenders")),
            ("efs", "describe-file-systems", None, "", enc("efs-describe-file-systems-raw")),
            ("secretsmanager", "list-secrets", None, "RotationEnabled", enc("secretsmanager-list-secrets-offenders")),
            ("secretsmanager", "list-secrets", None, "", enc("secretsmanager-list-secrets-raw")),
            ("rds", "describe-db-instances", None, "", enc("rds-describe-db-instances-raw")),
            ("rds", "describe-db-clusters", None, "", enc("rds-describe-db-clusters-raw")),
            ("s3api", "list-buckets", None, "", core("s3api-list-buckets")),
            ("elbv2", "describe-load-balancers", None, "", ok(loadbalancers)),
            ("kms", "list-keys", None, "", ok(listing)),
            ("acm", "list-certificates", None, "keyTypes=", ok(certificates)),
            # checks
            ("ec2", "get-ebs-encryption-by-default", None, "", enc("ec2-get-ebs-encryption-by-default-off")),
            ("s3api", "get-bucket-encryption", None, "acme-notes-data", enc("s3api-get-bucket-encryption-sse-s3")),
            ("s3api", "get-bucket-encryption", None, "acme-notes-logs", no_encryption),
            ("s3api", "get-bucket-policy", None, "acme-notes-data", no_policy),
            ("s3api", "get-bucket-policy", None, "acme-notes-logs", ok(deny_http_policy("acme-notes-logs"))),
            ("kms", "describe-key", None, K_CUSTOMER, enc("kms-describe-key-customer")),
            ("kms", "describe-key", None, K_AWS, enc("kms-describe-key-aws-managed")),
            ("kms", "describe-key", None, K_ASYM, enc("kms-describe-key-asymmetric")),
            ("kms", "describe-key", None, K_PENDING, enc("kms-describe-key-pending-deletion")),
            ("kms", "describe-key", None, cls.K_DENIED, denied),
            ("kms", "get-key-rotation-status", None, K_PENDING, invalid_state),
            ("kms", "get-key-rotation-status", None, cls.K_DENIED, denied),
            ("kms", "get-key-rotation-status", None, K_CUSTOMER, enc("kms-get-key-rotation-status-off")),
            ("kms", "get-key-rotation-status", None, K_AWS, enc("kms-get-key-rotation-status-on")),
            ("kms", "get-key-rotation-status", None, K_ASYM, unsupported),
            ("elbv2", "describe-listeners", None, ALB_ARN, enc("elbv2-describe-listeners-http-forward-and-legacy")),
            ("elbv2", "describe-listeners", None, NLB_ARN, enc("elbv2-describe-listeners-none")),
            ("rds", "describe-db-parameter-groups", None, "", enc("rds-describe-db-parameter-groups")),
            ("rds", "describe-db-cluster-parameter-groups", None, "", enc("rds-describe-db-cluster-parameter-groups")),
            ("rds", "describe-db-parameters", None, "acme-notes-postgres-ssl", enc("rds-describe-db-parameters-postgres-ssl-on")),
            ("rds", "describe-db-parameters", None, "default.mysql8.0", enc("rds-describe-db-parameters-mysql-ssl-off")),
            ("rds", "describe-db-cluster-parameters", None, "default.aurora-postgresql15", enc("rds-describe-db-cluster-parameters-postgres-ssl-off")),
            ("acm", "describe-certificate", None, CERT_ISSUED, enc("acm-describe-certificate-issued")),
            ("acm", "describe-certificate", None, CERT_EXPIRED, enc("acm-describe-certificate-expired")),
        ]

    def rows(self, check_id):
        return [(r["status"], r["resource_id"], r["region"]) for r in self.result["results"] if r["check_id"] == check_id]

    def test_run_succeeds_and_only_the_blocked_key_is_unverified(self):
        self.assertEqual(self.code, 0)
        unverified = [(r["check_id"], r["resource_id"]) for r in self.result["results"] if r["status"] == "NO_VERIFICADO"]
        self.assertEqual(unverified, [("ENC-006", self.K_DENIED), ("ENC-007", self.K_DENIED)])

    def test_ebs_outcomes(self):
        self.assertEqual(self.rows("ENC-001"), [("FAIL", I1, REGION), ("FAIL", I2, REGION)])
        self.assertEqual(self.rows("ENC-002"), [("PASS", "vol-0a1b2c3d4e5f60718", REGION), ("FAIL", "vol-0b2c3d4e5f6071829", REGION),
                                                ("FAIL", "vol-0c3d4e5f60718293a", REGION)])

    def test_data_store_outcomes(self):
        self.assertEqual(self.rows("ENC-003"), [("FAIL", "acme-notes-aurora", REGION), ("PASS", "acme-notes-db", REGION),
                                                ("FAIL", "acme-notes-legacy", REGION)])
        self.assertEqual(self.rows("ENC-004"), [("PASS", "fs-0a1b2c3d4e5f60718", REGION), ("FAIL", "fs-0b2c3d4e5f6071829", REGION)])
        self.assertEqual(self.rows("ENC-005"), [("PASS", "acme-notes-data", REGION), ("FAIL", "acme-notes-logs", REGION)])

    def test_kms_secrets_outcomes(self):
        self.assertEqual(self.rows("ENC-006"), [("FAIL", K_CUSTOMER, REGION), ("NO_VERIFICADO", self.K_DENIED, REGION)])
        self.assertEqual(self.rows("ENC-007"), [("PASS", K_CUSTOMER, REGION), ("PASS", K_AWS, REGION), ("PASS", K_ASYM, REGION),
                                                ("FAIL", K_PENDING, REGION), ("NO_VERIFICADO", self.K_DENIED, REGION)])
        self.assertEqual(self.rows("ENC-008"), [("FAIL", "acme-notes/api-token", REGION), ("PASS", "acme-notes/db-password", REGION)])

    def test_transit_outcomes(self):
        self.assertEqual(self.rows("TLS-001"), [("FAIL", "acme-notes-data", REGION), ("PASS", "acme-notes-logs", REGION)])
        self.assertEqual(self.rows("TLS-002"), [("FAIL", "acme-notes-alb", REGION)])
        self.assertEqual(self.rows("TLS-003"), [("FAIL", "acme-notes-alb", REGION)])
        self.assertEqual(self.rows("TLS-004"), [("FAIL", "acme-notes-aurora", REGION), ("PASS", "acme-notes-db", REGION),
                                                ("FAIL", "acme-notes-legacy", REGION)])
        self.assertEqual(self.rows("TLS-005"), [("PASS", CERT_ISSUED, REGION), ("FAIL", CERT_EXPIRED, REGION)])

    def test_a_blocked_key_names_the_missing_permissions_and_does_not_hide_the_others(self):
        for check_id in ("ENC-006", "ENC-007"):
            (row,) = [r for r in self.result["results"] if r["check_id"] == check_id and r["resource_id"] == self.K_DENIED]
            self.assertEqual(row["status"], "NO_VERIFICADO")
            self.assertEqual(row["detail"]["error_code"], "ACCESS_DENIED")
            self.assertEqual(row["missing"], catalog_check(check_id)["verify"]["needs"])

    def test_the_acm_inventory_listing_includes_every_key_type(self):
        (argv,) = [a for a in self.runner.calls if a[2] == "list-certificates"]
        value = argv[argv.index("--includes") + 1]
        self.assertEqual(value, "keyTypes=RSA_1024,RSA_2048,RSA_3072,RSA_4096,EC_prime256v1,EC_secp384r1,EC_secp521r1")

    def test_every_listed_key_is_described(self):
        asked = [a[a.index("--key-id") + 1] for a in self.runner.calls if a[2] == "describe-key"]
        self.assertEqual(sorted(set(asked)), sorted(self.KEYS))

    def test_parameters_are_requested_once_per_parameter_group(self):
        asked = [a[a.index("--db-parameter-group-name") + 1] for a in self.runner.calls if a[2] == "describe-db-parameters"]
        self.assertEqual(sorted(set(asked)), ["acme-notes-postgres-ssl", "default.mysql8.0"])
        cluster = [a[a.index("--db-cluster-parameter-group-name") + 1] for a in self.runner.calls if a[2] == "describe-db-cluster-parameters"]
        self.assertEqual(sorted(set(cluster)), ["default.aurora-postgresql15"])

    def test_only_read_only_calls_were_made(self):
        for argv in self.runner.calls:
            aws_runner.assert_read_only(argv[1], argv[2], [])


if __name__ == "__main__":
    unittest.main()
