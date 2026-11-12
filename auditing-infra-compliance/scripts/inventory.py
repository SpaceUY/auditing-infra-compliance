"""Inventory listing: resource-type specs (references/inventory.json) -> normalised items.

`call(service, operation, args, region)` must return an aws_runner.CallResult.
"""

from concurrent.futures import ThreadPoolExecutor

import paths

DEFAULT_REGION = "us-east-1"
WORKERS = 8


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


def _to_item(type_, spec, raw, region):
    item_id = _first(raw, spec["id_path"])
    if not item_id:
        return None
    tags = _tags(paths.extract(raw, spec["tags_path"]))
    name = _first(raw, spec["name_path"]) or tags.get("Name") or item_id
    return {"type": type_, "id": item_id, "arn": _first(raw, spec["arn_path"]), "name": name,
            "region": region, "tags": tags}


def _list_type(call, type_, spec, region):
    res = call(spec["service"], spec["operation"], spec["args"], region)
    if not res.ok:
        return [], res.error_kind
    items = (_to_item(type_, spec, raw, region) for raw in paths.extract(res.data, spec["items_path"]))
    return [i for i in items if i], None


def build_inventory(call, specs, regions):
    """One job per region (ThreadPoolExecutor); global types run once in us-east-1.

    Returns (items sorted by type/region/id, [(type, region, error_kind)]).
    """
    jobs = {r: [t for t, s in specs.items() if s["region"] == "each"] for r in regions}
    jobs.setdefault(DEFAULT_REGION, [])
    jobs[DEFAULT_REGION] = jobs[DEFAULT_REGION] + [t for t, s in specs.items() if s["region"] == "global"]

    def run(region):
        found, errors = [], []
        for type_ in jobs[region]:
            items, error = _list_type(call, type_, specs[type_], region)
            found += items
            if error:
                errors.append((type_, region, error))
        return found, errors

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(run, sorted(jobs)))
    items = sorted((i for found, _ in results for i in found), key=lambda i: (i["type"], i["region"], i["id"]))
    return items, [e for _, errors in results for e in errors]
