"""Monitoring evaluators: every resource has a CloudWatch alarm on the named metric, wired to an SNS topic that has a
confirmed subscription (Drata 112-118, 206, 290, 293-300; Vanta CloudWatch alarm tests)."""

import re

from evaluators import _for_each_pairs, _not_applicable, _offender, _unverified, register

# Resource type each CloudWatch namespace is evaluated for.
NAMESPACE_TYPES = {
    "AWS/RDS": "rds_instance", "AWS/EC2": "ec2_instance", "AWS/ApplicationELB": "elbv2", "AWS/SQS": "sqs_queue",
    "AWS/Lambda": "lambda_function", "AWS/ElastiCache": "elasticache_group",
}
_UNCONFIRMED = frozenset({"pendingconfirmation", "deleted"})
_ASG_TAG = "aws:autoscaling:groupName"
_ALB_ARN = re.compile(r":loadbalancer/(app/[^/]+/[^/]+)$")


def _spec(params: dict) -> dict:
    """{type, namespace, dimension, metrics} from params {namespace, metric (name or list), resource_dimension}."""
    metric = params["metric"]
    return {"type": NAMESPACE_TYPES[params["namespace"]], "namespace": params["namespace"], "dimension": params["resource_dimension"],
            "metrics": [metric] if isinstance(metric, str) else list(metric)}


def _dimension_value(item: dict) -> str | None:
    """The value CloudWatch uses for the resource in its dimension; None when the resource has no such metric."""
    if item["type"] == "elbv2":
        match = _ALB_ARN.search(item["arn"] or "")
        return match.group(1) if match else None
    if item["type"] == "sqs_queue":
        return item["id"].rstrip("/").rsplit("/", 1)[-1]
    return item["id"]


def _covers(item: dict, dimension: str, value: str, dims: dict[str, str], members: set[str]) -> bool:
    """The alarm dimensions name the resource (extra dimensions are fine), or the group/nodes that contain it."""
    if dims.get(dimension) == value:
        return True
    if item["type"] == "ec2_instance":
        group = (item.get("tags") or {}).get(_ASG_TAG)
        return bool(group) and dims.get("AutoScalingGroupName") == group
    if item["type"] == "elasticache_group":
        return dims.get("CacheClusterId") in members
    return False


def _dimensions(raw: object) -> dict[str, str]:
    return {d["Name"]: d["Value"] for d in raw or [] if "Name" in d and "Value" in d}


def _watched_metrics(alarm: dict) -> list[tuple[str | None, str | None, dict[str, str]]]:
    """(namespace, metric, dimensions) an alarm watches: its own metric, or each metric query of a metric-math alarm."""
    if alarm.get("MetricName"):
        return [(alarm.get("Namespace"), alarm["MetricName"], _dimensions(alarm.get("Dimensions")))]
    queries = [(q.get("MetricStat") or {}).get("Metric") for q in alarm.get("Metrics") or []]
    return [(m.get("Namespace"), m.get("MetricName"), _dimensions(m.get("Dimensions"))) for m in queries if m]


def _alarms_by_region(responses: dict) -> dict[str, list[tuple[dict, str | None, str | None, dict[str, str]]]]:
    found: dict[str, list] = {}
    for region, data in responses.get("alarms", []):
        for alarm in (data or {}).get("MetricAlarms", []):
            found.setdefault(region, []).extend((alarm, ns, metric, dims) for ns, metric, dims in _watched_metrics(alarm))
    return found


def _is_sns_topic(arn: object) -> bool:
    parts = arn.split(":") if isinstance(arn, str) else []
    return len(parts) == 6 and parts[0] == "arn" and parts[2] == "sns"


def _account_of(arn: object) -> str | None:
    parts = arn.split(":") if isinstance(arn, str) else []
    return parts[4] if len(parts) > 4 and parts[4] else None


def _topic_state(topic: str, region: str, account: str | None, subscriptions: dict) -> tuple[str, dict]:
    """('confirmed' | 'unconfirmed' | 'unverified', detail) of one topic. A topic of another account or region is not
    read by the audit (its call runs in the alarm's region), so it cannot be judged."""
    _, _, _, topic_region, topic_account, _ = topic.split(":")
    if (topic_region, topic_account) != (region, account or topic_account):
        return "unverified", {"topic": topic, "reason": "el topic SNS está en otra cuenta o región: no se puede verificar su suscripción"}
    if (region, topic) not in subscriptions:
        return "unverified", {"topic": topic, "reason": "no se leyeron las suscripciones del topic SNS"}
    data = subscriptions[(region, topic)] or {}
    error = data.get("__error__")
    if error == "NotFound":
        return "unconfirmed", {}
    if error:
        return "unverified", {"topic": topic, "error_code": error, "reason": "no se pudieron leer las suscripciones del topic SNS"}
    confirmed = any(str(s.get("SubscriptionArn") or "").lower() not in _UNCONFIRMED | {""}
                    for s in data.get("Subscriptions") or [])
    return ("confirmed" if confirmed else "unconfirmed"), {}


def _judge(item: dict, metric: str, spec: dict, value: str, alarms: list, subscriptions: dict, members: set[str]) -> dict | None:
    """None when covered; else an offender (detail.missing_part) or an unverified entry for this resource and metric."""
    region = item["region"]
    base = {"namespace": spec["namespace"], "metric": metric, "dimension": {"name": spec["dimension"], "value": value}}
    matching = [alarm for alarm, ns, name, dims in alarms
                if ns == spec["namespace"] and name == metric and _covers(item, spec["dimension"], value, dims, members)]
    if not matching:
        return _offender(item["id"], region, missing_part="alarm", **base,
                         reason=f"no hay una alarma de CloudWatch sobre {spec['namespace']} {metric} con {spec['dimension']}={value}")
    names = sorted({a.get("AlarmName") for a in matching})
    wired = [(a, topic) for a in matching if a.get("ActionsEnabled", True) for topic in a.get("AlarmActions") or [] if _is_sns_topic(topic)]
    if not wired:
        return _offender(item["id"], region, missing_part="action", alarms=names, **base,
                         reason="la alarma existe pero no notifica a un topic SNS (sin acción SNS, o con las acciones deshabilitadas)")
    topics = list(dict.fromkeys(topic for _, topic in wired))
    states = [(topic, *_topic_state(topic, region, _account_of(a.get("AlarmArn")), subscriptions)) for a, topic in wired]
    if any(state == "confirmed" for _, state, _ in states):
        return None
    undecided = [detail for _, state, detail in states if state == "unverified"]
    if undecided:
        return _unverified(item["id"], region, alarms=names, **base, **undecided[0])
    return _offender(item["id"], region, missing_part="confirmed_subscription", alarms=names, topics=topics, **base,
                     reason="el topic SNS de la alarma no tiene ninguna suscripción confirmada (todas están en PendingConfirmation, o no hay ninguna)")


def _engines(responses: dict) -> dict[tuple[str, str], str]:
    """{(region, id): lower-case Engine} of the db instances read by the check's `instances` call."""
    return {(region, db["DBInstanceIdentifier"]): str(db.get("Engine") or "").lower()
            for region, data in responses.get("instances", []) for db in (data or {}).get("DBInstances", [])}


def _states(responses: dict) -> dict[tuple[str, str], str]:
    """{(region, instance id): state name} of the EC2 instances read by the check's `instances` call."""
    return {(region, i["InstanceId"]): (i.get("State") or {}).get("Name")
            for region, data in responses.get("instances", []) for r in (data or {}).get("Reservations", []) for i in r.get("Instances", [])}


def _members(responses: dict) -> dict[tuple[str, str], set[str]]:
    """{(region, replication group): its member cache cluster ids} from the check's `groups` call."""
    return {(region, g["ReplicationGroupId"]): set(g.get("MemberClusters") or [])
            for region, data in responses.get("groups", []) for g in (data or {}).get("ReplicationGroups", [])}


def _out_of_scope(item: dict, params: dict, engines: dict, states: dict) -> bool:
    """Engines named in params.not_applicable_engines (prefix match) and EC2 instances that are not running are not evaluated;
    when the engine or state is unknown the resource is evaluated."""
    key = (item["region"], item["id"])
    if item["type"] == "rds_instance":
        engine = engines.get(key)
        return engine is not None and engine.startswith(tuple(params.get("not_applicable_engines") or ()))
    return item["type"] == "ec2_instance" and states.get(key, "running") != "running"


@register("alarm_coverage")
def alarm_coverage(responses: dict, params: dict) -> list[dict]:
    """Per resource and metric: an alarm in the resource's region on the namespace+metric with the resource's dimension,
    an enabled SNS action, and a topic with at least one confirmed subscription. Topics are read per topic (`subs`,
    for_each over the alarm actions); one that cannot be read leaves only the resources that depend on it unverified.
    Optional calls: `instances` (RDS engine / EC2 state) and `groups` (ElastiCache member nodes)."""
    spec, alarms = _spec(params), _alarms_by_region(responses)
    engines, states, members = _engines(responses), _states(responses), _members(responses)
    subscriptions = {}
    for topic, region, data in _for_each_pairs(responses, "subs"):
        subscriptions.setdefault((region, topic), data)
    results = []
    for item in responses.get("__inventory__", []):
        if item["type"] != spec["type"]:
            continue
        value = _dimension_value(item)
        if value is None or _out_of_scope(item, params, engines, states):
            results.append(_not_applicable(item["id"], item["region"]))
            continue
        nodes = members.get((item["region"], item["id"]), set())
        for metric in spec["metrics"]:
            verdict = _judge(item, metric, spec, value, alarms.get(item["region"], []), subscriptions, nodes)
            if verdict:
                results.append(verdict)
    return results
