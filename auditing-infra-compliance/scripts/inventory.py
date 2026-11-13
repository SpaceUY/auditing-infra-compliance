"""Inventory listing: resource-type specs (references/inventory.json) -> normalised items.

`call(service, operation, args, region)` must return an aws_runner.CallResult.
"""

from concurrent.futures import ThreadPoolExecutor

import paths

DEFAULT_REGION = "us-east-1"
WORKERS = 8

# ARN of the types whose listing carries none (inventory.json has an empty arn_path). AWS builds these ARNs deterministically from
# partition, region, account and id; {name} is the last path segment of the id (an SQS queue is listed by its URL). Without the
# account an ARN that needs it stays empty (the report then asks to complete it) instead of being wrong.
ARN_FORMATS = {
    "ec2_instance": "arn:{partition}:ec2:{region}:{account}:instance/{id}",
    "ebs_volume": "arn:{partition}:ec2:{region}:{account}:volume/{id}",
    "s3_bucket": "arn:{partition}:s3:::{id}",
    "dynamodb_table": "arn:{partition}:dynamodb:{region}:{account}:table/{id}",
    "sqs_queue": "arn:{partition}:sqs:{region}:{account}:{name}",
    "eks_cluster": "arn:{partition}:eks:{region}:{account}:cluster/{id}",
}


def _tags(nodes):
    tags = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        key = node.get("Key", node.get("key"))
        if key is not None:
            tags[str(key)] = str(node.get("Value", node.get("value", "")))
        else:
            tags.update({str(k): str(v) for k, v in node.items()})
    return tags


def _first(item, path):
    values = paths.extract(item, path)
    return str(values[0]) if values else ""


def _partition(region):
    if region.startswith("cn-"):
        return "aws-cn"
    return "aws-us-gov" if region.startswith("us-gov-") else "aws"


def _built_arn(type_, item_id, region, account_id, partition=None):
    """The deterministic ARN of an item the listing gave no ARN for; "" when the type has no format or the account is unknown."""
    pattern = ARN_FORMATS.get(type_)
    if not pattern:
        return ""
    name = item_id.rstrip("/").rsplit("/", 1)[-1]
    account = account_id
    if type_ == "sqs_queue":  # the queue URL is https://sqs.<region>.amazonaws.com/<account>/<name>
        parts = item_id.rstrip("/").split("/")
        account = parts[-2] if len(parts) >= 2 and parts[-2].isdigit() else account_id
    if "{account}" in pattern and not account:
        return ""
    return pattern.format(partition=partition or _partition(region), region=region, account=account, id=item_id, name=name)


def _to_item(type_, spec, raw, region, account_id=None, partition=None):
    item_id = _first(raw, spec["id_path"])
    if not item_id:
        return None
    tags = _tags(paths.extract(raw, spec["tags_path"]))
    name = _first(raw, spec["name_path"]) or tags.get("Name") or item_id
    arn = _first(raw, spec["arn_path"]) or _built_arn(type_, item_id, region, account_id, partition)
    arn = arn.removesuffix(":*")  # describe-log-groups returns "...:log-group:NAME:*"; the tagging API takes the ARN without the suffix
    return {"type": type_, "id": item_id, "arn": arn, "name": name, "region": region, "tags": tags}


def _list_type(call, type_, spec, region, account_id=None, partition=None):
    res = call(spec["service"], spec["operation"], spec["args"], region)
    if not res.ok:
        return [], res.error_kind
    items = (_to_item(type_, spec, raw, region, account_id, partition) for raw in paths.extract(res.data, spec["items_path"]))
    return [i for i in items if i], None


def build_inventory(call, specs, regions, account_id=None, partition=None):
    """One job per region (ThreadPoolExecutor); global types run once in us-east-1.

    `account_id` and `partition` (both from the sts get-caller-identity ARN) complete the ARN of the types listed without one
    (ARN_FORMATS); without a partition it follows the region of the item (a global type is listed in us-east-1, so it would
    always be "aws" in a China or GovCloud account).
    Returns (items sorted by type/region/id, [(type, region, error_kind)]).
    """
    jobs = {r: [t for t, s in specs.items() if s["region"] == "each"] for r in regions}
    jobs.setdefault(DEFAULT_REGION, [])
    jobs[DEFAULT_REGION] = jobs[DEFAULT_REGION] + [t for t, s in specs.items() if s["region"] == "global"]

    def run(region):
        found, errors = [], []
        for type_ in jobs[region]:
            items, error = _list_type(call, type_, specs[type_], region, account_id, partition)
            found += items
            if error:
                errors.append((type_, region, error))
        return found, errors

    pool = ThreadPoolExecutor(max_workers=WORKERS)
    try:
        results = list(pool.map(run, sorted(jobs)))
    except BaseException:  # Ctrl-C or a worker failure: do not wait for the queued regions
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    pool.shutdown()
    items = sorted((i for found, _ in results for i in found), key=lambda i: (i["type"], i["region"], i["id"]))
    return items, [e for _, errors in results for e in errors]
