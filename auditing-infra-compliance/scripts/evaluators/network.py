"""Network evaluators: security groups, network ACLs, default security groups, public RDS and WAF."""

import ipaddress

from evaluators import _for_each_pairs, _not_applicable, _offender, _unverified, register

ADMIN_PORTS = (22, 3389)
TCP = frozenset({"tcp", "6"})
NACL_PROTOCOLS = frozenset({"-1", "tcp", "6", "udp", "17"})


def _is_any_address(cidr: object) -> bool:
    """0.0.0.0/0 or ::/0 (any spelling of a zero-length prefix)."""
    try:
        return ipaddress.ip_network(str(cidr), strict=False).prefixlen == 0
    except ValueError:
        return False


# ---------------------------------------------------------------- Security groups

def _cidr_ranges(permission: dict, only_any_address: bool) -> tuple[list[dict], list[dict]]:
    v4 = [{"CidrIp": r["CidrIp"]} for r in permission.get("IpRanges") or [] if r.get("CidrIp") and (not only_any_address or _is_any_address(r["CidrIp"]))]
    v6 = [{"CidrIpv6": r["CidrIpv6"]} for r in permission.get("Ipv6Ranges") or []
          if r.get("CidrIpv6") and (not only_any_address or _is_any_address(r["CidrIpv6"]))]
    return v4, v6


def _exact_permission(permission: dict, only_any_address: bool) -> dict | None:
    """The IpPermission to revoke: the protocol and ports of the rule with only the offending CIDR ranges (None if it has none)."""
    v4, v6 = _cidr_ranges(permission, only_any_address)
    if not (v4 or v6):
        return None
    exact = {key: permission[key] for key in ("IpProtocol", "FromPort", "ToPort") if key in permission}
    if v4:
        exact["IpRanges"] = v4
    if v6:
        exact["Ipv6Ranges"] = v6
    return exact


def _covers_port(permission: dict, port: int) -> bool:
    protocol = str(permission.get("IpProtocol", "")).lower()
    if protocol == "-1":
        return True
    first, last = permission.get("FromPort"), permission.get("ToPort")
    return protocol in TCP and isinstance(first, int) and isinstance(last, int) and first <= port <= last


def _is_all_traffic(permission: dict) -> bool:
    return str(permission.get("IpProtocol")) == "-1"


def _eni_regions(responses: dict) -> tuple[set[str], set[str]]:
    """({regions with at least one in-use network interface}, {regions with an answer})."""
    active, answered = set(), set()
    for region, data in responses.get("enis", []):
        answered.add(region)
        if any(str(eni.get("Status", "in-use")).lower() == "in-use" for eni in (data or {}).get("NetworkInterfaces", [])):
            active.add(region)
    return active, answered


def _attachments(responses: dict) -> dict[tuple[str, str], list[dict]]:
    """(region, group id) -> the in-use network interfaces that use the group, as {eni_id, instance_id, description,
    requester_id}. instance_id is Attachment.InstanceId (None for ENIs not attached to an instance, such as ELB ones)."""
    found: dict[tuple[str, str], list[dict]] = {}
    for region, data in responses.get("enis", []):
        for eni in (data or {}).get("NetworkInterfaces", []):
            if str(eni.get("Status", "in-use")).lower() != "in-use":
                continue
            entry = {"eni_id": eni.get("NetworkInterfaceId"), "instance_id": (eni.get("Attachment") or {}).get("InstanceId"),
                     "description": eni.get("Description"), "requester_id": eni.get("RequesterId")}
            for group in eni.get("Groups") or []:
                found.setdefault((region, group.get("GroupId")), []).append(entry)
    return found


def _group_findings(responses: dict, matches, only_any_address: bool, **extra) -> list[dict]:
    """One entry per security group, attached or not (like Drata, which evaluates every group of a region with active ENIs):
    offender (a matching rule open to a CIDR), not applicable (the region has no in-use interface) or unverified (the
    region's interfaces could not be read)."""
    active, answered = _eni_regions(responses)
    attachments = _attachments(responses)
    found = []
    for region, data in responses.get("groups", []):
        for sg in (data or {}).get("SecurityGroups", []):
            gid = sg["GroupId"]
            if region not in answered:
                found.append(_unverified(gid, region, reason="sin respuesta de describe-network-interfaces"))
                continue
            if region not in active:
                found.append(_not_applicable(gid, region))
                continue
            exposed = [e for p in sg.get("IpPermissions") or [] if matches(p) and (e := _exact_permission(p, only_any_address))]
            if exposed:
                sources = sorted({r.get("CidrIp") or r["CidrIpv6"] for e in exposed for r in (e.get("IpRanges") or []) + (e.get("Ipv6Ranges") or [])})
                found.append(_offender(gid, region, group_name=sg.get("GroupName"), vpc_id=sg.get("VpcId"), ip_permissions=exposed,
                                       sources=sources, attachments=attachments.get((region, gid), []), **extra))
    return found


@register("sg_open_port")
def sg_open_port(responses: dict, params: dict) -> list[dict]:
    """Drata 102 / 228 / 291 and Vanta #33-#34: no ingress rule from 0.0.0.0/0 or ::/0 whose protocol is tcp or all (-1) and
    whose port range contains params["port"], in any security group of a region with in-use ENIs. Source security groups,
    specific CIDRs and prefix lists pass. detail.ip_permissions is the exact JSON of the offending rules (stable key);
    detail.attachments lists the in-use ENIs using the group (stable key, read by the fix verification stage)."""
    port = int(params["port"])
    return _group_findings(responses, lambda p: _covers_port(p, port), True, port=port)


@register("sg_all_traffic")
def sg_all_traffic(responses: dict, params: dict) -> list[dict]:
    """Drata 119: no ingress rule of type ALL traffic (protocol -1) from a CIDR source (any CIDR; security group sources pass).
    detail.ip_permissions is the exact JSON of the offending rules (stable key)."""
    return _group_findings(responses, _is_all_traffic, False)


# ---------------------------------------------------------------- Network ACLs

def _entry_ports(entry: dict) -> list[int]:
    """Admin ports an inbound entry covers (every port when the protocol is all or the port range is missing)."""
    if str(entry.get("Protocol")) == "-1" or not entry.get("PortRange"):
        return list(ADMIN_PORTS)
    first, last = entry["PortRange"].get("From"), entry["PortRange"].get("To")
    if not (isinstance(first, int) and isinstance(last, int)):
        return list(ADMIN_PORTS)
    return [port for port in ADMIN_PORTS if first <= port <= last]


def _open_entry(entry: dict) -> dict | None:
    source = next((c for c in (entry.get("CidrBlock"), entry.get("Ipv6CidrBlock")) if c and _is_any_address(c)), None)
    allows = not entry.get("Egress") and str(entry.get("RuleAction", "")).lower() == "allow"
    if not (allows and source and str(entry.get("Protocol", "")).lower() in NACL_PROTOCOLS):
        return None
    ports = _entry_ports(entry)
    return {"rule_number": entry.get("RuleNumber"), "protocol": str(entry["Protocol"]), "ports": ports, "source": source} if ports else None


@register("nacl_admin_ports")
def nacl_admin_ports(responses: dict, params: dict) -> list[dict]:
    """Drata 227 / Vanta #32: no inbound allow entry from 0.0.0.0/0 or ::/0 to 22 or 3389 over TCP, UDP or all protocols.
    Rule order is not modelled: like the CIS control, any such allow entry is reported."""
    offenders = []
    for region, data in responses.get("nacls", []):
        for nacl in (data or {}).get("NetworkAcls", []):
            entries = [e for raw in nacl.get("Entries") or [] if (e := _open_entry(raw))]
            if entries:
                offenders.append(_offender(nacl["NetworkAclId"], region, default=bool(nacl.get("IsDefault")), entries=entries))
    return offenders


# ---------------------------------------------------------------- Default security groups

@register("default_sg_empty")
def default_sg_empty(responses: dict, params: dict) -> list[dict]:
    """Drata 233 / Vanta #35: the default security group of every VPC has no inbound and no outbound rules."""
    defaults = {(region, sg["VpcId"]): sg for region, data in responses.get("groups", []) for sg in (data or {}).get("SecurityGroups", [])
                if str(sg.get("GroupName", "")).lower() == "default" and sg.get("VpcId")}
    offenders = []
    for vpc in (i for i in responses.get("__inventory__", []) if i["type"] == "vpc"):
        sg = defaults.get((vpc["region"], vpc["id"]))
        if sg is None:
            offenders.append(_unverified(vpc["id"], vpc["region"], reason="no se encontró el security group por defecto de la VPC"))
            continue
        inbound, outbound = len(sg.get("IpPermissions") or []), len(sg.get("IpPermissionsEgress") or [])
        if inbound or outbound:
            offenders.append(_offender(vpc["id"], vpc["region"], group_id=sg["GroupId"], inbound_rules=inbound, outbound_rules=outbound))
    return offenders


# ---------------------------------------------------------------- Public RDS

def _routes_to_igw(table: dict) -> bool:
    return any(str(route.get("GatewayId", "")).startswith("igw-") and str(route.get("State", "active")).lower() == "active"
               and any(_is_any_address(route.get(key)) for key in ("DestinationCidrBlock", "DestinationIpv6CidrBlock"))
               for route in table.get("Routes") or [])


def _subnet_table(region: str, vpc_id: str, subnet_id: str, tables: list[tuple[str, dict]]) -> dict | None:
    """The route table of a subnet: its explicit association, else the main table of its VPC."""
    scoped = [t for r, t in tables if r == region]
    explicit = next((t for t in scoped for a in t.get("Associations") or [] if a.get("SubnetId") == subnet_id), None)
    return explicit or next((t for t in scoped if t.get("VpcId") == vpc_id and any(a.get("Main") for a in t.get("Associations") or [])), None)


@register("rds_not_public")
def rds_not_public(responses: dict, params: dict) -> list[dict]:
    """Drata 220 / Vanta #23: PubliclyAccessible is false and no subnet of the DB subnet group has a route to an internet gateway."""
    tables = [(region, t) for region, data in responses.get("routes", []) for t in (data or {}).get("RouteTables", [])]
    offenders = []
    for region, data in responses.get("instances", []):
        for db in (data or {}).get("DBInstances", []):
            group = db.get("DBSubnetGroup") or {}
            public_subnets, unknown = [], []
            for subnet in group.get("Subnets") or []:
                table = _subnet_table(region, group.get("VpcId"), subnet["SubnetIdentifier"], tables)
                if table is None:
                    unknown.append(subnet["SubnetIdentifier"])
                elif _routes_to_igw(table):
                    public_subnets.append(subnet["SubnetIdentifier"])
            flagged = bool(db.get("PubliclyAccessible"))
            reasons = (["PubliclyAccessible=true"] if flagged else []) + [
                f"la subnet {s} tiene una ruta hacia un internet gateway" for s in public_subnets]
            if reasons:
                offenders.append(_offender(db["DBInstanceIdentifier"], region, publicly_accessible=flagged, public_subnets=public_subnets, reasons=reasons))
            elif unknown:
                offenders.append(_unverified(db["DBInstanceIdentifier"], region, reason="sin route table para las subnets", subnets=unknown))
    return offenders


# ---------------------------------------------------------------- WAF

def _associated(responses: dict, call: str) -> set[tuple[str, str]]:
    return {(region, arn) for _, region, data in _for_each_pairs(responses, call) for arn in (data or {}).get("ResourceArns", [])}


def _alb_findings(responses: dict, associated: set[tuple[str, str]]) -> list[dict]:
    found = []
    for region, data in responses.get("albs", []):
        for lb in (data or {}).get("LoadBalancers", []):
            name, arn = lb["LoadBalancerName"], lb["LoadBalancerArn"]
            public_alb = str(lb.get("Type", "")).lower() == "application" and str(lb.get("Scheme", "")).lower() == "internet-facing"
            if not public_alb:
                found.append(_not_applicable(name, region))
            elif (region, arn) not in associated:
                found.append(_offender(name, region, kind="alb", arn=arn, reason="el ALB público no tiene un web ACL de WAF asociado"))
    return found


def _api_findings(responses: dict, associated: set[tuple[str, str]]) -> list[dict]:
    """REST APIs: one entry per API. Private APIs and APIs without a deployed stage are not applicable; an API fails when any of
    its stages has no web ACL."""
    stages = {(region, api_id): data for api_id, region, data in _for_each_pairs(responses, "stages")}
    found = []
    for region, data in responses.get("apis", []):
        for api in (data or {}).get("items", []):
            api_id = api["id"]
            answer = stages.get((region, api_id))
            if answer is None:
                found.append(_unverified(api_id, region, reason="sin respuesta de get-stages"))
                continue
            names = [stage["stageName"] for stage in answer.get("item") or []]
            private = "PRIVATE" in [str(t).upper() for t in (api.get("endpointConfiguration") or {}).get("types") or []]
            if private or "__error__" in answer or not names:
                found.append(_not_applicable(api_id, region))
                continue
            bare = [n for n in names if (region, f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{n}") not in associated]
            if bare:
                found.append(_offender(api_id, region, kind="api_gateway", api=api.get("name", api_id), stages=bare,
                                       reason="el API público tiene stages sin un web ACL de WAF asociado"))
    return found


def _distribution_findings(responses: dict) -> list[dict]:
    available = sorted({acl["Name"] for _, data in responses.get("cf_acls", []) for acl in (data or {}).get("WebACLs", [])})
    found = []
    for region, data in responses.get("distributions", []):
        for dist in ((data or {}).get("DistributionList") or {}).get("Items") or []:
            if not dist.get("Enabled", True):
                found.append(_not_applicable(dist["Id"], region))
            elif not dist.get("WebACLId"):
                found.append(_offender(dist["Id"], region, kind="cloudfront", domain=dist.get("DomainName"), available_web_acls=available,
                                       reason="la distribución no tiene un web ACL de WAF asociado"))
    return found


@register("waf_associated")
def waf_associated(responses: dict, params: dict) -> list[dict]:
    """Drata 122: public ALBs, REST APIs (every stage) and enabled CloudFront distributions have a WAF web ACL associated.
    Internal ALBs, NLBs, private APIs, APIs without stages and disabled distributions are not applicable. HTTP APIs are not
    evaluated: WAF cannot be associated with them."""
    return (_alb_findings(responses, _associated(responses, "acl_albs")) + _api_findings(responses, _associated(responses, "acl_apis"))
            + _distribution_findings(responses))
