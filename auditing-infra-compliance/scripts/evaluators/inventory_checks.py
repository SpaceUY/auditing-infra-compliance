"""Inventory evaluators: Vanta tags (owner, user data, non-prod) and organisational tags on the inventoried resources.

The tags of a resource are the ones the inventory listing already carries (EC2, RDS, EFS...) plus the ones the Resource
Groups Tagging API returns for it (call "tags", one answer per region): S3, DynamoDB, SQS, Lambda, KMS and others are listed
without their tags. A resource absent from the tagging answers has no tags. AWS-managed KMS keys (alias/aws/..., call "aliases")
cannot be tagged and are not applicable. One offender per resource, except the user-data check's single account offender.
"""

import re

from evaluators import DEFAULT_REGION, _not_applicable, _offender, register

EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PATTERNS = {"email": lambda value: bool(EMAIL.match(value))}
DEFAULT_KEYS = ("Project", "Environment", "Owner")
ENVIRONMENT_KEY, NON_PROD_KEY = "Environment", "VantaNonProd"
PROD_VALUES = frozenset({"prod", "production"})
# Resource id prefix inside the ARN of the types whose inventory item carries no ARN.
_ARN_RESOURCE = {"ec2_instance": ("ec2", "instance/"), "ebs_volume": ("ec2", "volume/"), "dynamodb_table": ("dynamodb", "table/"),
                 "eks_cluster": ("eks", "cluster/")}


def _arn_key(arn: str) -> tuple[str, str, str] | None:
    """(service, region, resource) of an ARN; S3 ARNs have no region and log group ARNs end in ':*'."""
    parts = arn.split(":", 5)
    if len(parts) < 6 or parts[0] != "arn":
        return None
    resource = parts[5][:-2] if parts[5].endswith(":*") else parts[5]
    return parts[2], "" if parts[2] == "s3" else parts[3], resource


def _item_key(item: dict) -> tuple[str, str, str] | None:
    if item["arn"]:
        return _arn_key(item["arn"])
    if item["type"] == "s3_bucket":
        return "s3", "", item["id"]
    if item["type"] == "sqs_queue":
        return "sqs", item["region"], item["id"].rstrip("/").rsplit("/", 1)[-1]
    if item["type"] in _ARN_RESOURCE:
        service, prefix = _ARN_RESOURCE[item["type"]]
        return service, item["region"], prefix + item["id"]
    return None


def _tagging_index(responses: dict) -> dict[tuple[str, str, str], dict[str, str]]:
    index: dict[tuple[str, str, str], dict[str, str]] = {}
    for _, data in responses.get("tags", []):
        for mapping in (data or {}).get("ResourceTagMappingList") or []:
            key = _arn_key(mapping.get("ResourceARN") or "")
            if key:
                index.setdefault(key, {}).update({t["Key"]: t.get("Value", "") for t in mapping.get("Tags") or [] if "Key" in t})
    return index


def _aws_managed_keys(responses: dict) -> set[tuple[str, str]]:
    """{(region, key id)} of the keys behind an 'alias/aws/...' alias: AWS-managed keys cannot be tagged by the customer."""
    return {(region, alias["TargetKeyId"]) for region, data in responses.get("aliases", [])
            for alias in (data or {}).get("Aliases") or [] if str(alias.get("AliasName", "")).startswith("alias/aws/") and alias.get("TargetKeyId")}


def _tagged_items(responses: dict, params: dict) -> tuple[list[tuple[dict, dict[str, str]]], list[dict]]:
    """([(inventory item, its tags)], not applicable entries) for the items of params["inventory_types"]. AWS-managed KMS keys are
    not applicable (a key without alias information is evaluated)."""
    types, index, managed = set(params["inventory_types"]), _tagging_index(responses), _aws_managed_keys(responses)
    items = [i for i in responses.get("__inventory__", []) if i["type"] in types]
    skipped = [_not_applicable(i["id"], i["region"]) for i in items if i["type"] == "kms_key" and (i["region"], i["id"]) in managed]
    applicable = [(i, {**index.get(_item_key(i), {}), **(i.get("tags") or {})}) for i in items if not (i["type"] == "kms_key" and (i["region"], i["id"]) in managed)]
    return applicable, skipped


@register("tag_present")
def tag_present(responses: dict, params: dict) -> list[dict]:
    """params.key (exact match) must be present; params.pattern ('email') also constrains its value."""
    key, pattern = params["key"], params.get("pattern")
    applicable, offenders = _tagged_items(responses, params)
    for item, tags in applicable:
        if key not in tags:
            offenders.append(_offender(item["id"], item["region"], tag=key, reason=f"falta el tag {key}"))
        elif pattern and not PATTERNS[pattern](tags[key]):
            offenders.append(_offender(item["id"], item["region"], tag=key, value=tags[key],
                                       reason=f"el valor del tag {key} no tiene formato {pattern}"))
    return offenders


@register("user_data_flag")
def user_data_flag(responses: dict, params: dict) -> list[dict]:
    """Vanta "Inventory list tracks resources that contain user data": at least one data store flagged params.key=true. Without
    one, a single account offender (the test fails); stores without a true/false value are reported at low severity."""
    key = params["key"]
    applicable, offenders = _tagged_items(responses, params)
    unclassified, flagged = [], False
    for item, tags in applicable:
        value = tags.get(key, "").strip().lower()
        flagged = flagged or value == "true"
        if value not in ("true", "false"):
            unclassified.append(_offender(item["id"], item["region"], tag=key, value=tags.get(key), severity_override="low",
                                          reason=f"sin clasificar: falta {key} con valor true o false"))
    if applicable and not flagged:
        offenders.append(_offender("account", DEFAULT_REGION, tag=key, data_stores=len(applicable),
                                   reason=f"ningún almacén de datos tiene {key}=true"))
    return offenders + unclassified


@register("nonprod_on_prod")
def nonprod_on_prod(responses: dict, params: dict) -> list[dict]:
    """VantaNonProd=true takes a resource out of every Vanta test: on a production resource that hides it from the audit."""
    applicable, offenders = _tagged_items(responses, params)
    for item, tags in applicable:
        environment, flag = tags.get(ENVIRONMENT_KEY, ""), tags.get(NON_PROD_KEY, "")
        if environment.strip().lower() in PROD_VALUES and flag.strip().lower() == "true":
            offenders.append(_offender(item["id"], item["region"], environment=environment, vanta_non_prod=flag,
                                       reason="VantaNonProd=true en un recurso con Environment de producción"))
    return offenders


@register("tags_present")
def tags_present(responses: dict, params: dict) -> list[dict]:
    """Organisational tags (params.keys, default Project/Environment/Owner); an empty value counts as missing."""
    keys = list(params.get("keys") or DEFAULT_KEYS)
    applicable, offenders = _tagged_items(responses, params)
    for item, tags in applicable:
        missing = [k for k in keys if not tags.get(k, "").strip()]
        if missing:
            offenders.append(_offender(item["id"], item["region"], missing=missing, reason="faltan tags organizacionales"))
    return offenders
