"""Compute evaluators: launch templates, availability, patching."""

from evaluators import _for_each_pairs, _not_applicable, _offender, register


# ---------------------------------------------------------------- Compute: launch templates

def _template_spec(group: dict) -> dict | None:
    mixed = ((group.get("MixedInstancesPolicy") or {}).get("LaunchTemplate") or {}).get("LaunchTemplateSpecification")
    return group.get("LaunchTemplate") or mixed


def _resolve_version(versions: list[dict], spec_version: str | None) -> dict | None:
    """'$Latest' = highest number, '$Default' (also when omitted) = the default version, a number = that version."""
    wanted = spec_version or "$Default"
    if wanted == "$Latest":
        return max(versions, key=lambda v: v["VersionNumber"], default=None)
    if wanted == "$Default":
        return next((v for v in versions if v.get("DefaultVersion")), None)
    return next((v for v in versions if str(v["VersionNumber"]) == wanted), None)


def _versions_by_template(responses: dict) -> dict[tuple[str, str], dict]:
    found: dict[tuple[str, str], dict] = {}
    for call in ("versions", "mixed_versions"):
        for template_id, region, data in _for_each_pairs(responses, call):
            found.setdefault((region, template_id), data or {})
    return found


def _group_imds_problem(group: dict, region: str, templates: dict[tuple[str, str], dict]) -> dict | None:
    spec = _template_spec(group)
    if spec is None:
        return {"reason": "the group uses a launch configuration (obsolete): migrate to a launch template with IMDSv2 required",
                "launch_configuration": group.get("LaunchConfigurationName")}
    data = templates.get((region, spec["LaunchTemplateId"]), {})
    if "__error__" in data or "LaunchTemplateVersions" not in data:
        return {"reason": "launch template does not exist or is not accessible", "launch_template": spec["LaunchTemplateId"]}
    version = _resolve_version(data["LaunchTemplateVersions"], spec.get("Version"))
    base = {"launch_template": spec["LaunchTemplateId"], "version_spec": spec.get("Version") or "$Default"}
    if version is None:
        return {**base, "reason": "the launch template version used by the group was not found"}
    tokens = ((version.get("LaunchTemplateData") or {}).get("MetadataOptions") or {}).get("HttpTokens")
    if tokens == "required":
        return None
    return {**base, "reason": "the launch template version does not require IMDSv2", "version": version["VersionNumber"], "http_tokens": tokens}


@register("lt_imdsv2")
def lt_imdsv2(responses: dict, params: dict) -> list[dict]:
    """Drata 292 / Vanta ASG variant: the launch template version each ASG uses has HttpTokens=required."""
    templates = _versions_by_template(responses)
    found = [(region, group, _group_imds_problem(group, region, templates))
             for region, data in responses.get("asgs", []) for group in (data or {}).get("AutoScalingGroups", [])]
    return [_offender(group["AutoScalingGroupName"], region, **problem) for region, group, problem in found if problem]


# ---------------------------------------------------------------- Compute: availability and patching

def _instances(responses: dict) -> list[dict]:
    """EC2 instances of the inventory. The region-level tests below (Drata 130 / 131) report every instance of a
    failing region, so that the instances of the other regions still get their own PASS row."""
    return [i for i in responses.get("__inventory__", []) if i["type"] == "ec2_instance"]


def _balancer_zones(responses: dict) -> dict[str, list[dict]]:
    """{region: [{"name", "zones"}]} of application/network and classic load balancers."""
    found: dict[str, list[dict]] = {}
    for region, data in responses.get("alb", []):
        found.setdefault(region, []).extend({"name": lb["LoadBalancerName"], "zones": len(lb.get("AvailabilityZones") or [])}
                                            for lb in (data or {}).get("LoadBalancers", []))
    for region, data in responses.get("clb", []):
        found.setdefault(region, []).extend({"name": lb["LoadBalancerName"], "zones": len(lb.get("AvailabilityZones") or [])}
                                            for lb in (data or {}).get("LoadBalancerDescriptions", []))
    return found


@register("lb_multi_az")
def lb_multi_az(responses: dict, params: dict) -> list[dict]:
    """Drata 130: every region with EC2 has a load balancer spanning 2 or more AZs (no EC2 = nothing to report)."""
    balancers = _balancer_zones(responses)
    reason = "the region has no load balancer spanning 2 or more availability zones"
    return [_offender(i["id"], i["region"], reason=reason, load_balancers=balancers.get(i["region"], []))
            for i in _instances(responses) if not any(lb["zones"] >= 2 for lb in balancers.get(i["region"], []))]


@register("asg_present")
def asg_present(responses: dict, params: dict) -> list[dict]:
    """Drata 131: every region with EC2 has at least one Auto Scaling group."""
    with_groups = {region for region, data in responses.get("asgs", []) if (data or {}).get("AutoScalingGroups")}
    return [_offender(i["id"], i["region"], reason="the region has EC2 instances and no Auto Scaling group")
            for i in _instances(responses) if i["region"] not in with_groups]


@register("ssm_managed")
def ssm_managed(responses: dict, params: dict) -> list[dict]:
    """Running instances registered in Systems Manager with a live agent and a Patch Manager patch state.
    Instances in any other state (stopped...) cannot run the agent and are not applicable.
    detail.ssm_unreachable is true when the instance is not registered or its agent is not online (a missing patch state
    alone leaves it false)."""
    states = {(region, i["InstanceId"]): (i.get("State") or {}).get("Name")
              for region, data in responses.get("instances", []) for r in (data or {}).get("Reservations", []) for i in r.get("Instances", [])}
    managed = {(region, i["InstanceId"]): i for region, data in responses.get("info", [])
               for i in (data or {}).get("InstanceInformationList", [])}
    patched = {(region, s["InstanceId"]) for _, region, data in _for_each_pairs(responses, "patches")
               for s in (data or {}).get("InstancePatchStates", [])}
    offenders = []
    for instance in _instances(responses):
        key = (instance["region"], instance["id"])
        if states.get(key, "running") != "running":
            offenders.append(_not_applicable(instance["id"], instance["region"]))
            continue
        info = managed.get(key)
        if info is None:
            problems = ["not registered in Systems Manager"]
        else:
            problems = ([] if info.get("PingStatus") == "Online" else [f"the SSM agent is not online ({info.get('PingStatus')})"])
            problems += [] if key in patched else ["no patch association (Patch Manager)"]
        if problems:
            # ssm_unreachable (stable key): not registered or agent offline, i.e. no Session Manager access today
            unreachable = info is None or info.get("PingStatus") != "Online"
            offenders.append(_offender(instance["id"], instance["region"], problems=problems, ssm_unreachable=unreachable))
    return offenders
