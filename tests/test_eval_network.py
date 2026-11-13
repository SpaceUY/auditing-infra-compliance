import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import helpers
from helpers import SKILL_DIR, load_fixture

import catalog
import collect
import evaluators
from test_eval_encryption import flags, for_each, ids, item, merge
from test_eval_iam import RuleRunner, ok

try:
    import jmespath
except ImportError:  # the skill itself is stdlib-only; the JMESPath expressions are only verified when it is installed
    jmespath = None

NETWORK_JSON = SKILL_DIR / "references" / "checks" / "network.json"
REFS = SKILL_DIR / "references"
REGION = "us-east-1"
OTHER = "eu-west-1"
VPC_A, VPC_B = "vpc-0a1b2c3d4e5f60718", "vpc-0b2c3d4e5f6071829"
S_BASTION, S_WEB, S_DB, S_RDP, S_WIDE, S_SPARE = ("sg-0a1b2c3d4e5f60718", "sg-0b2c3d4e5f6071829", "sg-0c3d4e5f60718293a",
                                                  "sg-0d4e5f60718293a4b", "sg-0e5f60718293a4b5c", "sg-0f60718293a4b5c6d")
S_RANGE, S_CIDR, S_UDP, S_PREFIX = "sg-0a1b2c3d4e5f607a1", "sg-0b2c3d4e5f607182b", "sg-0c3d4e5f60718293c", "sg-0d4e5f60718293a4d"
NACL_OK, NACL_SSH, NACL_DEFAULT, NACL_V6, NACL_UDP, NACL_RANGE, NACL_NARROW = (
    "acl-0a1b2c3d4e5f60718", "acl-0b2c3d4e5f6071829", "acl-0c3d4e5f60718293a", "acl-0d4e5f60718293a4b",
    "acl-0e5f60718293a4b5c", "acl-0f60718293a4b5c6d", "acl-0a1b2c3d4e5f607a1")
SUB_PUB, SUB_PRIV, SUB_NAT = "subnet-0a1b2c3d4e5f60718", "subnet-0b2c3d4e5f6071829", "subnet-0c3d4e5f60718293a"
ALB_PUB = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/acme-notes-alb/50dc6c495c0c9188"
ALB_BARE = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/acme-notes-open/6d0ecf831eec9f09"
ALB_INT = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/acme-notes-internal/7e1fd0942ffd0a1a"
NLB = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/acme-notes-nlb/8f2ae1a53a0e1b2b"
ACL_ARN = "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/acme-notes-acl/0a1b2c3d-4e5f-4a1b-8c2d-3e4f5a6b7c8d"
STAGE_PROD = "arn:aws:apigateway:us-east-1::/restapis/a1b2c3d4e5/stages/prod"
STAGE_DEV = "arn:aws:apigateway:us-east-1::/restapis/a1b2c3d4e5/stages/dev"
STAGE_EDGE = "arn:aws:apigateway:us-east-1::/restapis/b2c3d4e5f6/stages/prod"


def fx(name):
    return load_fixture(f"aws/network/{name}.json")


def evaluate(name, responses, params=None):
    return evaluators.EVALUATORS[name](responses, params or {})


def catalog_check(check_id):
    data = json.loads(NETWORK_JSON.read_text(encoding="utf-8"))
    return next(c for c in data["checks"] if c["id"] == check_id)


def real(offenders):
    return [o for o in offenders if not o.get("not_applicable")]


def sg_responses(groups=None, enis="in-use", region=REGION):
    groups = fx("ec2-describe-security-groups-mixed") if groups is None else groups
    return {"groups": [(region, groups)], "enis": [(region, fx(f"ec2-describe-network-interfaces-{enis}"))]}


def group(gid, *permissions, name="acme-notes-x"):
    return {"GroupId": gid, "GroupName": name, "VpcId": VPC_A, "IpPermissions": list(permissions), "IpPermissionsEgress": []}


def tcp(lo, hi, cidr="0.0.0.0/0", protocol="tcp"):
    return {"IpProtocol": protocol, "FromPort": lo, "ToPort": hi, "IpRanges": [{"CidrIp": cidr}], "Ipv6Ranges": [], "UserIdGroupPairs": []}


def attached(*gids, region=REGION):
    return {"enis": [(region, {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "Status": "in-use", "Groups": [{"GroupId": g} for g in gids]}]})]}


class SgOpenPortTests(unittest.TestCase):
    def test_sg_open_port_pass(self):
        groups = {"SecurityGroups": [g for g in fx("ec2-describe-security-groups-mixed")["SecurityGroups"] if g["GroupId"] in (S_WEB, S_DB)]}
        found = evaluate("sg_open_port", sg_responses(groups), {"port": 22})
        self.assertEqual(found, [])

    def test_sg_open_port_fail_reports_offenders(self):
        found = evaluate("sg_open_port", sg_responses(), {"port": 22})
        self.assertEqual(flags(found), [(S_BASTION, "offender"), (S_WIDE, "offender"), (S_SPARE, "offender"), (S_RANGE, "offender")])
        bastion = found[0]
        self.assertEqual(bastion["region"], REGION)
        self.assertEqual(bastion["detail"]["ip_permissions"], [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                                                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
        self.assertEqual((bastion["detail"]["sources"], bastion["detail"]["port"], bastion["detail"]["group_name"]),
                         (["0.0.0.0/0", "::/0"], 22, "acme-notes-bastion"))

    def test_sg_open_port_rdp_and_http_use_the_same_logic(self):
        self.assertEqual(ids(real(evaluate("sg_open_port", sg_responses(), {"port": 3389}))), [S_RDP, S_WIDE, S_SPARE, S_RANGE])
        self.assertEqual(ids(real(evaluate("sg_open_port", sg_responses(), {"port": 80}))), [S_WEB, S_WIDE, S_SPARE, S_RANGE])

    def test_all_protocols_rule_reports_the_exact_permission(self):
        wide = next(o for o in evaluate("sg_open_port", sg_responses(), {"port": 22}) if o["resource_id"] == S_WIDE)
        self.assertEqual(wide["detail"]["ip_permissions"], [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])

    def test_port_range_boundaries(self):
        def exposed(lo, hi, port=22):
            responses = {**{"groups": [(REGION, {"SecurityGroups": [group("sg-1", tcp(lo, hi))]})]}, **attached("sg-1")}
            return bool(real(evaluate("sg_open_port", responses, {"port": port})))
        self.assertTrue(exposed(22, 22))
        self.assertTrue(exposed(20, 22))
        self.assertTrue(exposed(22, 25))
        self.assertTrue(exposed(0, 65535))
        self.assertFalse(exposed(23, 25))
        self.assertFalse(exposed(20, 21))
        self.assertFalse(exposed(21, 21))
        self.assertTrue(exposed(3389, 3389, 3389))
        self.assertFalse(exposed(3390, 3390, 3389))

    def test_only_tcp_and_all_protocols_count(self):
        for protocol, expected in (("tcp", True), ("6", True), ("TCP", True), ("udp", False), ("17", False), ("icmp", False)):
            responses = {**{"groups": [(REGION, {"SecurityGroups": [group("sg-1", tcp(22, 22, protocol=protocol))]})]}, **attached("sg-1")}
            self.assertEqual(bool(real(evaluate("sg_open_port", responses, {"port": 22}))), expected, protocol)

    def test_sources_other_than_the_whole_internet_pass(self):
        found = evaluate("sg_open_port", sg_responses(), {"port": 22})
        self.assertNotIn(S_DB, ids(found))
        self.assertNotIn(S_WEB, ids(found))
        self.assertNotIn(S_CIDR, ids(found))
        self.assertNotIn(S_PREFIX, ids(found))
        responses = {**{"groups": [(REGION, {"SecurityGroups": [group("sg-1", tcp(22, 22, "0.0.0.0/1"))]})]}, **attached("sg-1")}
        self.assertEqual(evaluate("sg_open_port", responses, {"port": 22}), [])

    def test_an_unattached_open_group_in_a_region_with_active_interfaces_fails(self):
        found = evaluate("sg_open_port", sg_responses(), {"port": 22})
        spare = next(o for o in found if o["resource_id"] == S_SPARE)
        self.assertNotIn("not_applicable", spare)
        self.assertEqual(spare["detail"]["sources"], ["0.0.0.0/0"])

    def test_groups_of_a_region_without_in_use_interfaces_are_not_applicable(self):
        groups = {"SecurityGroups": [group("sg-1", tcp(22, 22))]}
        self.assertEqual(flags(evaluate("sg_open_port", sg_responses(groups, "none"), {"port": 22})), [("sg-1", "not_applicable")])
        available = {"groups": [(REGION, groups)],
                     "enis": [(REGION, {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "Status": "available", "Groups": [{"GroupId": "sg-1"}]}]})]}
        self.assertEqual(flags(evaluate("sg_open_port", available, {"port": 22})), [("sg-1", "not_applicable")])

    def test_region_without_interface_answer_is_unverified_instead_of_passing(self):
        responses = {"groups": [(OTHER, {"SecurityGroups": [group("sg-1", tcp(22, 22))]})], "enis": [(REGION, {"NetworkInterfaces": []})]}
        self.assertEqual(flags(evaluate("sg_open_port", responses, {"port": 22})), [("sg-1", "unverified")])

    def test_the_same_group_id_in_two_regions_is_judged_per_region(self):
        responses = {"groups": [(REGION, {"SecurityGroups": [group("sg-1", tcp(22, 22))]}), (OTHER, {"SecurityGroups": [group("sg-1", tcp(22, 22))]})],
                     "enis": [(REGION, {"NetworkInterfaces": []}), (OTHER, {"NetworkInterfaces": [{"Status": "in-use", "Groups": [{"GroupId": "sg-1"}]}]})]}
        self.assertEqual([(o["resource_id"], o["region"], bool(o.get("not_applicable"))) for o in evaluate("sg_open_port", responses, {"port": 22})],
                         [("sg-1", REGION, True), ("sg-1", OTHER, False)])


class SgAttachmentsTests(unittest.TestCase):
    ALB_ENI = {"NetworkInterfaceId": "eni-alb", "Status": "in-use", "Description": "ELB app/acme-notes-alb/50dc6c495c0c9188",
               "RequesterId": "amazon-elb", "Attachment": {"InstanceOwnerId": "amazon-elb"}, "Groups": [{"GroupId": "sg-web"}]}
    EC2_ENI = {"NetworkInterfaceId": "eni-ec2", "Status": "in-use", "Description": "", "RequesterId": None,
               "Attachment": {"InstanceId": "i-0123456789abcdef0"}, "Groups": [{"GroupId": "sg-web"}, {"GroupId": "sg-ssh"}]}
    IDLE_ENI = {"NetworkInterfaceId": "eni-idle", "Status": "available", "Groups": [{"GroupId": "sg-ssh"}]}

    def responses(self, *enis):
        groups = {"SecurityGroups": [group("sg-web", tcp(80, 80)), group("sg-ssh", tcp(22, 22)), group("sg-none", tcp(22, 22))]}
        return {"groups": [(REGION, groups)], "enis": [(REGION, {"NetworkInterfaces": list(enis)})]}

    def detail(self, found, gid):
        return next(o for o in found if o["resource_id"] == gid)["detail"]

    def test_offenders_list_the_in_use_enis_that_use_the_group(self):
        found = evaluate("sg_open_port", self.responses(self.ALB_ENI, self.EC2_ENI, self.IDLE_ENI), {"port": 80})
        self.assertEqual(self.detail(found, "sg-web")["attachments"], [
            {"eni_id": "eni-alb", "instance_id": None, "description": "ELB app/acme-notes-alb/50dc6c495c0c9188", "requester_id": "amazon-elb"},
            {"eni_id": "eni-ec2", "instance_id": "i-0123456789abcdef0", "description": "", "requester_id": None}])
        ssh = evaluate("sg_open_port", self.responses(self.ALB_ENI, self.EC2_ENI, self.IDLE_ENI), {"port": 22})
        self.assertEqual([a["eni_id"] for a in self.detail(ssh, "sg-ssh")["attachments"]], ["eni-ec2"])
        self.assertEqual(self.detail(ssh, "sg-none")["attachments"], [])

    def test_existing_detail_keys_are_kept_and_all_traffic_has_attachments_too(self):
        found = evaluate("sg_open_port", self.responses(self.EC2_ENI), {"port": 22})
        self.assertTrue({"group_name", "vpc_id", "ip_permissions", "sources", "port"} <= set(self.detail(found, "sg-ssh")))
        groups = {"SecurityGroups": [group("sg-web", {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]})]}
        responses = {"groups": [(REGION, groups)], "enis": [(REGION, {"NetworkInterfaces": [self.EC2_ENI]})]}
        self.assertEqual(self.detail(evaluate("sg_all_traffic", responses), "sg-web")["attachments"][0]["instance_id"], "i-0123456789abcdef0")

    def test_the_same_group_id_in_another_region_does_not_share_attachments(self):
        responses = self.responses(self.EC2_ENI)
        responses["groups"].append((OTHER, {"SecurityGroups": [group("sg-ssh", tcp(22, 22))]}))
        responses["enis"].append((OTHER, {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-eu", "Status": "in-use", "Groups": []}]}))
        eu = [o for o in evaluate("sg_open_port", responses, {"port": 22}) if o["region"] == OTHER]
        self.assertEqual(eu[0]["detail"]["attachments"], [])


class SgAllTrafficTests(unittest.TestCase):
    def test_sg_all_traffic_pass(self):
        groups = {"SecurityGroups": [g for g in fx("ec2-describe-security-groups-mixed")["SecurityGroups"] if g["GroupId"] in (S_WEB, S_DB, S_RDP)]}
        self.assertEqual(evaluate("sg_all_traffic", sg_responses(groups)), [])

    def test_sg_all_traffic_fail_reports_offenders(self):
        found = evaluate("sg_all_traffic", sg_responses())
        self.assertEqual(flags(found), [(S_WIDE, "offender"), (S_SPARE, "offender"), (S_CIDR, "offender")])
        self.assertEqual(found[0]["detail"]["sources"], ["0.0.0.0/0"])
        self.assertEqual(found[0]["detail"]["ip_permissions"], [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        self.assertEqual(found[1]["detail"]["ip_permissions"], [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])

    def test_any_cidr_source_counts_not_only_the_whole_internet(self):
        office = next(o for o in evaluate("sg_all_traffic", sg_responses()) if o["resource_id"] == S_CIDR)
        self.assertEqual(office["detail"]["sources"], ["198.51.100.0/24"])

    def test_all_traffic_from_a_security_group_passes(self):
        perm = {"IpProtocol": "-1", "IpRanges": [], "Ipv6Ranges": [], "UserIdGroupPairs": [{"GroupId": "sg-2"}]}
        responses = {**{"groups": [(REGION, {"SecurityGroups": [group("sg-1", perm)]})]}, **attached("sg-1")}
        self.assertEqual(evaluate("sg_all_traffic", responses), [])

    def test_ipv6_source_counts(self):
        perm = {"IpProtocol": "-1", "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32"}]}
        responses = {**{"groups": [(REGION, {"SecurityGroups": [group("sg-1", perm)]})]}, **attached("sg-1")}
        (offender,) = evaluate("sg_all_traffic", responses)
        self.assertEqual(offender["detail"]["sources"], ["2001:db8::/32"])

    def test_specific_ports_from_a_cidr_are_not_all_traffic(self):
        responses = {**{"groups": [(REGION, {"SecurityGroups": [group("sg-1", tcp(0, 65535, "10.0.0.0/8"))]})]}, **attached("sg-1")}
        self.assertEqual(evaluate("sg_all_traffic", responses), [])

    def test_regions_without_in_use_interfaces_are_not_applicable_and_a_missing_answer_is_unverified(self):
        groups = {"SecurityGroups": [group("sg-1", {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]})]}
        self.assertEqual(flags(evaluate("sg_all_traffic", sg_responses(groups, "none"))), [("sg-1", "not_applicable")])
        responses = {"groups": [(OTHER, {"SecurityGroups": [group("sg-1", tcp(22, 22))]})], "enis": []}
        self.assertEqual(flags(evaluate("sg_all_traffic", responses)), [("sg-1", "unverified")])


class NaclAdminPortsTests(unittest.TestCase):
    def responses(self, *nacls):
        data = fx("ec2-describe-network-acls-mixed")
        if nacls:
            data = {"NetworkAcls": [n for n in data["NetworkAcls"] if n["NetworkAclId"] in nacls]}
        return {"nacls": [(REGION, data)]}

    def test_nacl_admin_ports_pass(self):
        self.assertEqual(evaluate("nacl_admin_ports", self.responses(NACL_OK, NACL_RANGE, NACL_NARROW)), [])

    def test_nacl_admin_ports_fail_reports_offenders(self):
        found = evaluate("nacl_admin_ports", self.responses())
        self.assertEqual([(o["resource_id"], o["region"]) for o in found], [(NACL_SSH, REGION), (NACL_DEFAULT, REGION), (NACL_V6, REGION), (NACL_UDP, REGION)])
        self.assertEqual(found[0]["detail"]["entries"], [{"rule_number": 100, "protocol": "6", "ports": [22], "source": "0.0.0.0/0"},
                                                          {"rule_number": 110, "protocol": "6", "ports": [3389], "source": "0.0.0.0/0"}])
        self.assertFalse(found[0]["detail"]["default"])

    def test_the_default_nacl_allows_everything_inbound_and_is_flagged_for_ipv4_and_ipv6(self):
        default = next(o for o in evaluate("nacl_admin_ports", self.responses()) if o["resource_id"] == NACL_DEFAULT)
        self.assertTrue(default["detail"]["default"])
        self.assertEqual([(e["rule_number"], e["protocol"], e["ports"], e["source"]) for e in default["detail"]["entries"]],
                         [(100, "-1", [22, 3389], "0.0.0.0/0"), (101, "-1", [22, 3389], "::/0")])

    def test_udp_rules_and_all_protocols_count_but_icmp_and_deny_do_not(self):
        udp = next(o for o in evaluate("nacl_admin_ports", self.responses()) if o["resource_id"] == NACL_UDP)
        self.assertEqual(udp["detail"]["entries"][0]["ports"], [22])

    def test_egress_entries_are_ignored(self):
        self.assertEqual(evaluate("nacl_admin_ports", self.responses(NACL_RANGE)), [])

    def test_port_range_boundaries(self):
        def exposed(lo, hi):
            nacl = {"NetworkAclId": "acl-1", "Entries": [{"RuleNumber": 100, "Protocol": "6", "RuleAction": "allow", "Egress": False,
                                                          "CidrBlock": "0.0.0.0/0", "PortRange": {"From": lo, "To": hi}}]}
            found = evaluate("nacl_admin_ports", {"nacls": [(REGION, {"NetworkAcls": [nacl]})]})
            return found[0]["detail"]["entries"][0]["ports"] if found else []
        self.assertEqual(exposed(22, 22), [22])
        self.assertEqual(exposed(3389, 3389), [3389])
        self.assertEqual(exposed(1, 65535), [22, 3389])
        self.assertEqual(exposed(23, 3388), [])
        self.assertEqual(exposed(1, 21), [])
        self.assertEqual(exposed(3390, 65535), [])
        self.assertEqual(exposed(22, 3389), [22, 3389])

    def test_a_tcp_entry_without_port_range_covers_every_port(self):
        nacl = {"NetworkAclId": "acl-1", "Entries": [{"RuleNumber": 100, "Protocol": "6", "RuleAction": "ALLOW", "Egress": False, "CidrBlock": "0.0.0.0/0"}]}
        (offender,) = evaluate("nacl_admin_ports", {"nacls": [(REGION, {"NetworkAcls": [nacl]})]})
        self.assertEqual(offender["detail"]["entries"][0]["ports"], [22, 3389])


class DefaultSgEmptyTests(unittest.TestCase):
    @staticmethod
    def vpcs(*specs):
        return [item("vpc", vpc, region) for vpc, region in specs]

    def test_default_sg_empty_pass(self):
        responses = {"groups": [(REGION, fx("ec2-describe-security-groups-default-empty"))],
                     "__inventory__": self.vpcs((VPC_A, REGION), (VPC_B, REGION))}
        self.assertEqual(evaluate("default_sg_empty", responses), [])

    def test_default_sg_empty_fail_reports_offenders(self):
        responses = {"groups": [(REGION, fx("ec2-describe-security-groups-default"))], "__inventory__": self.vpcs((VPC_A, REGION), (VPC_B, REGION))}
        (offender,) = evaluate("default_sg_empty", responses)
        self.assertEqual((offender["resource_id"], offender["region"]), (VPC_A, REGION))
        self.assertEqual(offender["detail"], {"group_id": "sg-0a1b2c3d4e5f6a001", "inbound_rules": 1, "outbound_rules": 1})

    def test_only_egress_rules_also_fail(self):
        data = {"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "default", "VpcId": VPC_A, "IpPermissions": [], "IpPermissionsEgress": [{"IpProtocol": "-1"}]}]}
        (offender,) = evaluate("default_sg_empty", {"groups": [(REGION, data)], "__inventory__": self.vpcs((VPC_A, REGION))})
        self.assertEqual((offender["detail"]["inbound_rules"], offender["detail"]["outbound_rules"]), (0, 1))

    def test_every_region_is_judged_with_its_own_default_groups(self):
        responses = {"groups": [(REGION, fx("ec2-describe-security-groups-default-empty")), (OTHER, fx("ec2-describe-security-groups-default-eu"))],
                     "__inventory__": self.vpcs((VPC_A, REGION), ("vpc-0c3d4e5f60718293a", OTHER))}
        self.assertEqual([(o["resource_id"], o["region"]) for o in evaluate("default_sg_empty", responses)], [("vpc-0c3d4e5f60718293a", OTHER)])

    def test_vpc_without_a_default_group_in_the_answer_is_unverified(self):
        responses = {"groups": [(REGION, {"SecurityGroups": []})], "__inventory__": self.vpcs((VPC_A, REGION))}
        self.assertEqual(flags(evaluate("default_sg_empty", responses)), [(VPC_A, "unverified")])

    def test_other_inventory_types_are_ignored(self):
        responses = {"groups": [(REGION, fx("ec2-describe-security-groups-default"))], "__inventory__": [item("subnet", "subnet-1")]}
        self.assertEqual(evaluate("default_sg_empty", responses), [])


class RdsNotPublicTests(unittest.TestCase):
    def responses(self, routes="ec2-describe-route-tables", instances=None):
        return {"instances": [(REGION, instances or fx("rds-describe-db-instances-exposure"))], "routes": [(REGION, fx(routes))]}

    def test_rds_not_public_pass(self):
        data = fx("rds-describe-db-instances-exposure")
        data["DBInstances"] = data["DBInstances"][:1]
        self.assertEqual(evaluate("rds_not_public", self.responses(instances=data)), [])

    def test_rds_not_public_fail_reports_offenders(self):
        found = evaluate("rds_not_public", self.responses())
        self.assertEqual([(o["resource_id"], o["region"]) for o in found],
                         [("acme-notes-flagged", REGION), ("acme-notes-public-subnet", REGION), ("acme-notes-both", REGION), ("acme-notes-main-igw", REGION)])
        flagged, subnet, both, main = (o["detail"] for o in found)
        self.assertEqual((flagged["publicly_accessible"], flagged["public_subnets"]), (True, []))
        self.assertEqual((subnet["publicly_accessible"], subnet["public_subnets"]), (False, [SUB_PUB]))
        self.assertEqual((both["publicly_accessible"], both["public_subnets"]), (True, [SUB_PUB]))
        self.assertEqual(subnet["reasons"], ["subnet subnet-0a1b2c3d4e5f60718 has a route to an internet gateway"])
        self.assertEqual(flagged["reasons"], ["PubliclyAccessible=true"])
        self.assertEqual(main["public_subnets"], ["subnet-0d4e5f60718293a4b"])

    def test_subnet_without_an_explicit_association_uses_the_main_route_table_of_its_vpc(self):
        found = evaluate("rds_not_public", self.responses())
        self.assertIn("acme-notes-main-igw", ids(found))
        self.assertNotIn("acme-notes-db", ids(found))

    def test_ipv6_default_route_to_an_igw_counts(self):
        main = next(o for o in evaluate("rds_not_public", self.responses()) if o["resource_id"] == "acme-notes-main-igw")
        self.assertEqual(len(main["detail"]["public_subnets"]), 1)

    def test_blackhole_route_to_an_igw_does_not_count(self):
        data = {"DBInstances": [{"DBInstanceIdentifier": "acme-notes-x", "PubliclyAccessible": False,
                                 "DBSubnetGroup": {"VpcId": VPC_A, "Subnets": [{"SubnetIdentifier": SUB_PRIV}]}}]}
        self.assertEqual(evaluate("rds_not_public", self.responses("ec2-describe-route-tables-blackhole", data)), [])

    def test_nat_gateway_route_is_not_public(self):
        data = {"DBInstances": [{"DBInstanceIdentifier": "acme-notes-x", "PubliclyAccessible": False,
                                 "DBSubnetGroup": {"VpcId": VPC_A, "Subnets": [{"SubnetIdentifier": SUB_NAT}]}}]}
        self.assertEqual(evaluate("rds_not_public", self.responses(instances=data)), [])

    def test_missing_publicly_accessible_is_not_public_but_subnets_are_still_checked(self):
        data = {"DBInstances": [{"DBInstanceIdentifier": "acme-notes-x", "DBSubnetGroup": {"VpcId": VPC_A, "Subnets": [{"SubnetIdentifier": SUB_PUB}]}}]}
        (offender,) = evaluate("rds_not_public", self.responses(instances=data))
        self.assertEqual(offender["detail"]["publicly_accessible"], False)

    def test_subnet_whose_route_table_cannot_be_found_is_unverified_unless_already_public(self):
        data = {"DBInstances": [{"DBInstanceIdentifier": "acme-notes-x", "PubliclyAccessible": False,
                                 "DBSubnetGroup": {"VpcId": "vpc-0e5f60718293a4b5c", "Subnets": [{"SubnetIdentifier": "subnet-1"}]}}]}
        self.assertEqual(flags(evaluate("rds_not_public", self.responses(instances=data))), [("acme-notes-x", "unverified")])
        data["DBInstances"][0]["PubliclyAccessible"] = True
        self.assertEqual(flags(evaluate("rds_not_public", self.responses(instances=data))), [("acme-notes-x", "offender")])

    def test_instance_without_a_subnet_group_is_judged_on_the_flag_only(self):
        data = {"DBInstances": [{"DBInstanceIdentifier": "acme-notes-x", "PubliclyAccessible": False}]}
        self.assertEqual(evaluate("rds_not_public", self.responses(instances=data)), [])


class WafAssociatedTests(unittest.TestCase):
    def responses(self, albs="elbv2-describe-load-balancers-mixed", acls="wafv2-list-web-acls-one", associated="wafv2-list-resources-for-web-acl-alb",
                  apis=None, stages=None, associated_apis="wafv2-list-resources-for-web-acl-empty", distributions="cloudfront-list-distributions-none"):
        with_acls = bool(fx(acls)["WebACLs"])
        parts = [{"albs": [(REGION, fx(albs))], "acls": [(REGION, fx(acls))], "apis": [(REGION, apis if apis is not None else {"items": []})],
                  "distributions": [(REGION, fx(distributions))], "cf_acls": [(REGION, fx("wafv2-list-web-acls-cloudfront"))]},
                 for_each("acl_albs", [(ACL_ARN, fx(associated))] if with_acls else []),
                 for_each("acl_apis", [(ACL_ARN, fx(associated_apis))] if with_acls else []),
                 for_each("stages", list((stages or {}).items()))]
        return merge(*parts)

    def apis_case(self, **kwargs):
        stages = {"a1b2c3d4e5": fx("apigateway-get-stages-prod-dev"), "b2c3d4e5f6": fx("apigateway-get-stages-prod"),
                  "c3d4e5f6a7": fx("apigateway-get-stages-prod")}
        return self.responses(apis=fx("apigateway-get-rest-apis-mixed"), stages=stages, **kwargs)

    def test_waf_associated_pass(self):
        data = {"LoadBalancers": [lb for lb in fx("elbv2-describe-load-balancers-mixed")["LoadBalancers"] if lb["LoadBalancerName"] == "acme-notes-alb"]}
        responses = self.responses()
        responses["albs"] = [(REGION, data)]
        self.assertEqual(evaluate("waf_associated", responses), [])

    def test_waf_associated_fail_reports_offenders(self):
        found = evaluate("waf_associated", self.responses())
        self.assertEqual(flags(found), [("acme-notes-open", "offender"), ("acme-notes-internal", "not_applicable"), ("acme-notes-nlb", "not_applicable")])
        offender = found[0]
        self.assertEqual((offender["resource_id"], offender["region"]), ("acme-notes-open", REGION))
        self.assertEqual(offender["detail"], {"kind": "alb", "arn": ALB_BARE, "reason": "the public ALB has no WAF web ACL associated"})

    def test_region_without_web_acls_fails_every_public_alb(self):
        found = evaluate("waf_associated", self.responses(acls="wafv2-list-web-acls-none"))
        self.assertEqual(ids(real(found)), ["acme-notes-alb", "acme-notes-open"])

    def test_a_rest_api_fails_when_any_stage_has_no_web_acl(self):
        found = evaluate("waf_associated", self.apis_case(associated_apis="wafv2-list-resources-for-web-acl-api"))
        apis = [o for o in found if o["resource_id"] in ("a1b2c3d4e5", "b2c3d4e5f6", "c3d4e5f6a7")]
        self.assertEqual(flags(apis), [("a1b2c3d4e5", "offender"), ("b2c3d4e5f6", "offender"), ("c3d4e5f6a7", "not_applicable")])
        self.assertEqual(apis[0]["detail"], {"kind": "api_gateway", "api": "acme-notes-api", "stages": ["dev"],
                                             "reason": "the public API has stages without an associated WAF web ACL"})
        self.assertEqual(apis[1]["detail"]["stages"], ["prod"])

    def test_a_rest_api_with_every_stage_associated_passes(self):
        stages = {"a1b2c3d4e5": fx("apigateway-get-stages-prod")}
        apis = {"items": [fx("apigateway-get-rest-apis-mixed")["items"][0]]}
        found = evaluate("waf_associated", self.responses(apis=apis, stages=stages, associated_apis="wafv2-list-resources-for-web-acl-api"))
        self.assertEqual([o for o in found if o["resource_id"] == "a1b2c3d4e5"], [])

    def test_private_apis_apis_without_stages_and_deleted_apis_are_not_applicable(self):
        stages = {"a1b2c3d4e5": fx("apigateway-get-stages-none"), "b2c3d4e5f6": {"__error__": "NotFoundException"}, "c3d4e5f6a7": fx("apigateway-get-stages-prod")}
        found = evaluate("waf_associated", self.responses(apis=fx("apigateway-get-rest-apis-mixed"), stages=stages))
        self.assertEqual([(o["resource_id"], bool(o.get("not_applicable"))) for o in found if o["resource_id"] in stages],
                         [("a1b2c3d4e5", True), ("b2c3d4e5f6", True), ("c3d4e5f6a7", True)])

    def test_an_api_without_a_stages_answer_is_unverified(self):
        found = evaluate("waf_associated", self.responses(apis=fx("apigateway-get-rest-apis-mixed")))
        self.assertEqual([flag for rid, flag in flags(found) if rid == "a1b2c3d4e5"], ["unverified"])

    def test_cloudfront_distributions_need_a_web_acl_and_disabled_ones_are_not_applicable(self):
        found = evaluate("waf_associated", self.responses(distributions="cloudfront-list-distributions-mixed"))
        distributions = [(o["resource_id"], "not_applicable" if o.get("not_applicable") else "offender") for o in found if o["resource_id"].startswith("E")]
        self.assertEqual(distributions, [("E2B3C4D5E6F7A8", "offender"), ("E3C4D5E6F7A8B9", "not_applicable")])
        cloudfront = next(o for o in found if o["resource_id"] == "E2B3C4D5E6F7A8")
        self.assertEqual((cloudfront["region"], cloudfront["detail"]["domain"], cloudfront["detail"]["available_web_acls"]),
                         (REGION, "d2b3c4d5e6f7a8.cloudfront.net", ["acme-notes-edge-acl"]))
        self.assertEqual(cloudfront["detail"]["kind"], "cloudfront")

    def test_missing_distribution_list_items_is_no_distributions(self):
        found = evaluate("waf_associated", self.responses())
        self.assertEqual([o for o in found if o["resource_id"].startswith("E")], [])


class NetworkCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks = json.loads(NETWORK_JSON.read_text(encoding="utf-8"))["checks"]

    def test_network_catalog_valid(self):
        data = json.loads(NETWORK_JSON.read_text(encoding="utf-8"))
        for check in data["checks"]:
            check.setdefault("domain", data["domain"])
        tsc_ids, iso_ids = catalog.load_frameworks(REFS / "frameworks")
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        self.assertEqual(catalog.validate(data["checks"], tsc_ids, iso_ids, drata), [])
        self.assertEqual([c["id"] for c in data["checks"]], [f"NET-{n:03d}" for n in range(1, 9)])
        self.assertEqual(data["domain"], "network")

    def test_every_python_evaluator_is_registered(self):
        for check in self.checks:
            kind, _, name = check["verify"]["evaluator"].partition(":")
            self.assertEqual(kind, "python", check["id"])
            self.assertIn(name, evaluators.EVALUATORS, check["id"])

    def test_evaluators_params_and_severities_follow_the_brief(self):
        expected = {"NET-001": ("python:sg_open_port", {"port": 22}, "high"), "NET-002": ("python:sg_open_port", {"port": 3389}, "high"),
                    "NET-003": ("python:sg_open_port", {"port": 80}, "high"), "NET-004": ("python:sg_all_traffic", None, "high"),
                    "NET-005": ("python:nacl_admin_ports", None, "high"), "NET-006": ("python:default_sg_empty", None, "high"),
                    "NET-007": ("python:rds_not_public", None, "critical"), "NET-008": ("python:waf_associated", None, "high")}
        self.assertEqual({c["id"]: (c["verify"]["evaluator"], c["verify"].get("params"), c["severity"]) for c in self.checks}, expected)

    def test_remediation_kinds_follow_the_brief(self):
        expected = {"NET-001": "cli_with_decision", "NET-002": "cli_with_decision", "NET-003": "cli_with_decision",
                    "NET-004": "cli_with_decision", "NET-005": "cli_with_decision", "NET-006": "cli_with_decision", "NET-007": "planned_change", "NET-008": "cli_with_decision"}
        self.assertEqual({c["id"]: c["remediation"]["kind"] for c in self.checks}, expected)

    def test_scopes_resource_types_and_regions(self):
        expected = {"NET-001": ["security_group"], "NET-002": ["security_group"], "NET-003": ["security_group"], "NET-004": ["security_group"],
                    "NET-005": ["nacl"], "NET-006": ["vpc"], "NET-007": ["rds_instance"], "NET-008": ["elbv2", "apigw_rest_api", "cloudfront_distribution"]}
        self.assertEqual({c["id"]: c["resource_types"] for c in self.checks}, expected)
        self.assertTrue(all(c["scope"] == "resource" for c in self.checks))
        self.assertEqual({c["id"] for c in self.checks if c["all_regions"]}, {"NET-006"})

    def test_security_group_checks_read_groups_and_active_interfaces(self):
        for check_id in ("NET-001", "NET-002", "NET-003", "NET-004"):
            calls = {c["name"]: c for c in catalog_check(check_id)["verify"]["calls"]}
            self.assertEqual({n: (c["service"], c["operation"]) for n, c in calls.items()},
                             {"groups": ("ec2", "describe-security-groups"), "enis": ("ec2", "describe-network-interfaces")}, check_id)
            self.assertEqual(calls["enis"]["args"], ["--filters", "Name=status,Values=in-use"], check_id)

    def test_default_sg_check_reads_only_default_groups_in_every_region(self):
        check = catalog_check("NET-006")
        (call,) = check["verify"]["calls"]
        self.assertEqual((call["operation"], call["args"]), ("describe-security-groups", ["--filters", "Name=group-name,Values=default"]))
        self.assertTrue(check["all_regions"])

    def test_rds_public_check_reads_instances_and_route_tables(self):
        calls = {c["name"]: (c["service"], c["operation"]) for c in catalog_check("NET-007")["verify"]["calls"]}
        self.assertEqual(calls, {"instances": ("rds", "describe-db-instances"), "routes": ("ec2", "describe-route-tables")})

    def test_waf_check_reads_acl_associations_per_resource_type(self):
        calls = {c["name"]: c for c in catalog_check("NET-008")["verify"]["calls"]}
        self.assertEqual(calls["acl_albs"]["args"], ["--resource-type", "APPLICATION_LOAD_BALANCER"])
        self.assertEqual(calls["acl_apis"]["args"], ["--resource-type", "API_GATEWAY"])
        for name in ("acl_albs", "acl_apis"):
            self.assertEqual((calls[name]["operation"], calls[name]["for_each"]),
                             ("list-resources-for-web-acl", {"from": "acls", "path": "WebACLs[].ARN", "arg": "--web-acl-arn"}))
        self.assertEqual(calls["stages"]["for_each"], {"from": "apis", "path": "items[].id", "arg": "--rest-api-id"})
        self.assertEqual(calls["distributions"]["region"], "global")
        self.assertEqual((calls["cf_acls"]["operation"], calls["cf_acls"]["args"], calls["cf_acls"]["region"]),
                         ("list-web-acls", ["--scope", "CLOUDFRONT"], "global"))

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

    @unittest.skipUnless(shutil.which("bash"), "bash not installed")
    def test_remediation_commands_and_verification_parse_as_bash(self):
        for check in self.checks:
            rem = check["remediation"]
            for text in [*rem["commands"], rem["verify_after"]]:
                script = text.replace("{region}", "us-east-1").replace("{account_id}", "111122223333").replace("{resource_id}", "acme-notes-x").replace("{detail_json:ip_permissions}", "'[]'")
                done = subprocess.run(["bash", "-n"], input=script, capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, f"{check['id']}: {done.stderr}\n{script}")

    def test_planned_changes_warn_in_notes(self):
        for check in self.checks:
            if check["remediation"]["kind"] == "planned_change":
                self.assertGreaterEqual(len(check["remediation"]["steps"]), 2, check["id"])
                self.assertTrue(check["remediation"]["notes"].strip(), check["id"])

    def test_drata_mapped_checks_resolve_from_the_dcf_file(self):
        drata = catalog.load_drata_map(REFS / "mappings" / "drata-dcf.json")
        expected = {"NET-001": 102, "NET-002": 228, "NET-003": 291, "NET-004": 119, "NET-005": 227, "NET-006": 233, "NET-007": 220, "NET-008": 122}
        for check_id, test in expected.items():
            resolved = catalog.resolve_mappings(catalog_check(check_id), drata)
            self.assertEqual([m["test"] for m in resolved["drata"]], [test], check_id)
            self.assertTrue(resolved["tsc"] and all(t["sourced"] == catalog.DCF_SOURCE for t in resolved["tsc"]), check_id)

    def test_vanta_tests_follow_the_cis_table(self):
        n33 = "No security group allows unrestricted IPv4 ingress to remote administration ports"
        n34 = "No security group allows unrestricted IPv6 ingress (::/0) to remote administration ports"
        expected = {"NET-001": [n33, n34], "NET-002": [n33, n34], "NET-003": [], "NET-004": [],
                    "NET-005": ["No network ACL allows unrestricted ingress (0.0.0.0/0) to remote administration ports"],
                    "NET-006": ["The default security group in every VPC blocks all traffic"], "NET-007": ["RDS instances are not publicly accessible"],
                    "NET-008": []}
        self.assertEqual({c["id"]: [m["test"] for m in c["mappings"]["vanta"]] for c in self.checks}, expected)

    def test_security_hub_and_cis_controls_follow_the_brief(self):
        expected = {"NET-001": (["EC2.53", "EC2.54"], ["5.3", "5.4"]), "NET-002": (["EC2.53", "EC2.54"], ["5.3", "5.4"]), "NET-003": ([], []),
                    "NET-004": ([], []), "NET-005": (["EC2.21"], ["5.2"]), "NET-006": (["EC2.2"], ["5.5"]), "NET-007": (["RDS.2"], ["2.2.3"]),
                    "NET-008": ([], [])}
        self.assertEqual({c["id"]: (c["mappings"]["security_hub"], c["mappings"]["cis_aws"]) for c in self.checks}, expected)

    def test_security_group_revokes_use_the_exact_rules_of_the_finding_and_never_revoke_everything(self):
        for check_id in ("NET-001", "NET-002", "NET-003", "NET-004"):
            rem = catalog_check(check_id)["remediation"]
            self.assertEqual(len(rem["commands"]), 1, check_id)
            (command,) = rem["commands"]
            self.assertIn("revoke-security-group-ingress", command, check_id)
            self.assertIn("--ip-permissions {detail_json:ip_permissions}", command, check_id)
            self.assertNotIn("__FILL_IN_IP_PERMISSIONS__", command, check_id)
            self.assertNotIn("--protocol", command, check_id)
            self.assertNotIn("--cidr", command, check_id)
            self.assertIn("detail.ip_permissions", rem["notes"], check_id)

    def test_security_group_checks_follow_drata_and_evaluate_every_group_of_a_region_with_active_enis(self):
        for check_id in ("NET-001", "NET-002", "NET-003", "NET-004"):
            text = catalog_check(check_id)["verify"]["pass_when_text"]
            self.assertRegex(text, r"(?i)whether or not the group is attached", check_id)
            self.assertRegex(text, r"(?i)region", check_id)

    def test_net_003_notes_say_that_an_alb_redirect_still_fails_drata_291(self):
        rem = catalog_check("NET-003")["remediation"]
        self.assertRegex(rem["notes"], r"(?i)redirect")
        self.assertIn("291", rem["notes"])
        self.assertRegex(rem["notes"], r"(?i)exclude the resource in Drata")
        self.assertRegex(" ".join(rem["steps"]), r"(?i)only 443|443")

    def test_default_sg_remediation_revokes_only_the_rules_of_the_default_group_it_just_read(self):
        text = "\n".join(catalog_check("NET-006")["remediation"]["commands"])
        self.assertIn("revoke-security-group-ingress", text)
        self.assertIn("revoke-security-group-egress", text)
        self.assertIn('"Name=group-name,Values=default"', text)
        self.assertIn("--ip-permissions \"$", text)

    def test_net_007_is_a_planned_change_with_downtime_and_moves_subnets(self):
        rem = catalog_check("NET-007")["remediation"]
        self.assertTrue(rem["downtime"])
        text = "\n".join(rem["commands"])
        self.assertIn("--no-publicly-accessible", text)
        self.assertRegex(text, r"create-db-subnet-group [^\n]*&&[^\n]*modify-db-instance [^\n]*--db-subnet-group-name")

    def test_net_005_split_keeps_udp_and_icmp_so_return_traffic_survives(self):
        commands = catalog_check("NET-005")["remediation"]["commands"]
        splits = [c for c in commands if "replace-network-acl-entry" in c and "$EXTRA_6" in c]
        self.assertEqual(len(splits), 2)  # IPv4 and IPv6
        for command in splits:
            self.assertNotIn("--protocol -1", command)
            self.assertNotRegex(command, r"--protocol (-1|all)\b")
            for proto in ("tcp", "udp"):
                for ports in ("From=23,To=3388", "From=3390,To=65535"):
                    self.assertRegex(command, rf"create-network-acl-entry [^\n&]*--protocol {proto} --port-range {ports}")
            self.assertRegex(command, r"create-network-acl-entry [^\n&]*--protocol udp --port-range From=1,To=21")
            self.assertRegex(command, r"create-network-acl-entry [^\n&]*--icmp-type-code Type=-1,Code=-1")
            self.assertTrue(command.rindex("replace-network-acl-entry") > command.rindex("create-network-acl-entry"))
            self.assertRegex(command, r"replace-network-acl-entry [^\n&]*--protocol tcp --port-range From=1,To=21")
            self.assertIn("&&", command)
        self.assertIn("--protocol 1 ", splits[0])
        self.assertIn("--protocol 58 ", splits[1])
        self.assertEqual(sum("--ipv6-cidr-block ::/0" in c for c in splits), 1)
        self.assertRegex(commands[1], r"(?i)WARNING")

    def test_net_006_blocks_stop_when_network_interfaces_use_the_default_group(self):
        rem = catalog_check("NET-006")["remediation"]
        self.assertEqual(rem["kind"], "cli_with_decision")
        self.assertEqual(rem["risk"], "high")
        for command in rem["commands"][1:3]:
            self.assertRegex(command, r"describe-network-interfaces --filters \"Name=group-id,Values=\$SG_ID\"")
            self.assertIn("length(NetworkInterfaces)", command)
            self.assertIn('[ "$ENIS" != "0" ]', command)
            self.assertIn("STOPPED", command)
            # the revoke only runs in the branch reached when no interface uses the group
            self.assertGreater(command.index("revoke-security-group-"), command.index('"$ENIS" != "0"'))

    def test_net_005_notes_warn_about_the_default_nacl_and_statelessness(self):
        notes = catalog_check("NET-005")["remediation"]["notes"]
        self.assertRegex(notes, r"(?i)default")
        self.assertRegex(notes, r"(?i)stateless")

    def test_net_008_associates_the_acl_with_the_resource(self):
        text = "\n".join(catalog_check("NET-008")["remediation"]["commands"])
        self.assertIn("create-web-acl", text)
        self.assertIn("associate-web-acl", text)
        self.assertIn("/restapis/{resource_id}/stages/$STAGE", text)


class NetworkCollectTests(unittest.TestCase):
    """The whole network catalog through collect.main with a fake AWS: wiring of calls, for_each and args."""

    TYPES = ("security_group", "nacl", "vpc", "rds_instance", "elbv2", "apigw_rest_api", "cloudfront_distribution")

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        (cls.tmp / "checks").mkdir()
        shutil.copy(NETWORK_JSON, cls.tmp / "checks" / "network.json")
        specs = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))
        (cls.tmp / "inventory.json").write_text(json.dumps({t: specs[t] for t in cls.TYPES}), encoding="utf-8")
        scope = {"platform": "Acme Notes", "mode": "full", "target": None, "regions": [REGION], "profile": None, "resources": [], "domains": None}
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
        net = lambda name: ok(fx(name))
        vpcs = {"Vpcs": [{"VpcId": VPC_A}, {"VpcId": VPC_B}]}
        return [
            ("sts", "get-caller-identity", None, "", core("sts-get-caller-identity")),
            ("ec2", "describe-regions", None, "", core("ec2-describe-regions")),
            ("iam", "list-attached-user-policies", None, "", ok({"AttachedPolicies": []})),
            # inventory listings and checks share the operation: the check calls carry --filters
            ("ec2", "describe-security-groups", None, "Name=group-name", net("ec2-describe-security-groups-default")),
            ("ec2", "describe-security-groups", None, "", net("ec2-describe-security-groups-mixed")),
            ("ec2", "describe-network-interfaces", None, "", net("ec2-describe-network-interfaces-in-use")),
            ("ec2", "describe-network-acls", None, "", net("ec2-describe-network-acls-mixed")),
            ("ec2", "describe-vpcs", None, "", ok(vpcs)),
            ("ec2", "describe-route-tables", None, "", net("ec2-describe-route-tables")),
            ("rds", "describe-db-instances", None, "", net("rds-describe-db-instances-exposure")),
            ("elbv2", "describe-load-balancers", None, "", net("elbv2-describe-load-balancers-mixed")),
            ("wafv2", "list-web-acls", None, "CLOUDFRONT", net("wafv2-list-web-acls-cloudfront")),
            ("wafv2", "list-web-acls", None, "", net("wafv2-list-web-acls-one")),
            ("wafv2", "list-resources-for-web-acl", None, "APPLICATION_LOAD_BALANCER", net("wafv2-list-resources-for-web-acl-alb")),
            ("wafv2", "list-resources-for-web-acl", None, "API_GATEWAY", net("wafv2-list-resources-for-web-acl-api")),
            ("apigateway", "get-rest-apis", None, "", net("apigateway-get-rest-apis-mixed")),
            ("apigateway", "get-stages", None, "a1b2c3d4e5", net("apigateway-get-stages-prod-dev")),
            ("apigateway", "get-stages", None, "b2c3d4e5f6", net("apigateway-get-stages-prod")),
            ("apigateway", "get-stages", None, "c3d4e5f6a7", net("apigateway-get-stages-prod")),
            ("cloudfront", "list-distributions", None, "", net("cloudfront-list-distributions-mixed")),
        ]

    def rows(self, check_id):
        return [(r["status"], r["resource_id"], r["region"]) for r in self.result["results"] if r["check_id"] == check_id]

    def test_run_succeeds_and_nothing_is_unverified(self):
        self.assertEqual(self.code, 0)
        self.assertEqual([(r["check_id"], r["detail"]) for r in self.result["results"] if r["status"] == "NOT_VERIFIED"], [])

    def test_security_group_outcomes(self):
        ssh = self.rows("NET-001")
        self.assertEqual([r for r in ssh if r[0] == "FAIL"], [("FAIL", S_BASTION, REGION), ("FAIL", S_RANGE, REGION), ("FAIL", S_WIDE, REGION), ("FAIL", S_SPARE, REGION)])
        self.assertEqual(sorted(r[1] for r in ssh if r[0] == "PASS"), sorted([S_WEB, S_DB, S_RDP, S_CIDR, S_UDP, S_PREFIX]))
        self.assertEqual([r[1] for r in self.rows("NET-002") if r[0] == "FAIL"], [S_RANGE, S_RDP, S_WIDE, S_SPARE])
        self.assertEqual([r[1] for r in self.rows("NET-003") if r[0] == "FAIL"], [S_RANGE, S_WEB, S_WIDE, S_SPARE])
        self.assertEqual([r[1] for r in self.rows("NET-004") if r[0] == "FAIL"], [S_CIDR, S_WIDE, S_SPARE])

    def test_nacl_outcomes(self):
        self.assertEqual([r for r in self.rows("NET-005") if r[0] == "FAIL"],
                         [("FAIL", NACL_SSH, REGION), ("FAIL", NACL_DEFAULT, REGION), ("FAIL", NACL_V6, REGION), ("FAIL", NACL_UDP, REGION)])
        self.assertEqual(sorted(r[1] for r in self.rows("NET-005") if r[0] == "PASS"), sorted([NACL_OK, NACL_RANGE, NACL_NARROW]))

    def test_default_security_groups_are_read_in_every_enabled_region(self):
        asked = sorted(c[c.index("--region") + 1] for c in self.runner.calls if c[2] == "describe-security-groups" and "Name=group-name,Values=default" in c)
        self.assertEqual(asked, sorted([REGION, OTHER]))
        self.assertEqual(self.rows("NET-006"), [("FAIL", VPC_A, REGION), ("PASS", VPC_B, REGION)])

    def test_rds_outcomes(self):
        found = self.rows("NET-007")
        self.assertEqual([r[1] for r in found if r[0] == "FAIL"], ["acme-notes-both", "acme-notes-flagged", "acme-notes-main-igw", "acme-notes-public-subnet"])
        self.assertEqual([r[1] for r in found if r[0] == "PASS"], ["acme-notes-db"])

    def test_waf_outcomes(self):
        self.assertEqual(self.rows("NET-008"), [("PASS", "E1A2B3C4D5E6F7", REGION), ("FAIL", "E2B3C4D5E6F7A8", REGION), ("FAIL", "a1b2c3d4e5", REGION),
                                                ("PASS", "acme-notes-alb", REGION), ("FAIL", "acme-notes-open", REGION), ("FAIL", "b2c3d4e5f6", REGION)])

    def test_waf_associations_are_asked_once_per_web_acl_and_resource_type(self):
        asked = [c for c in self.runner.calls if c[2] == "list-resources-for-web-acl"]
        self.assertEqual(sorted(c[c.index("--resource-type") + 1] for c in asked), ["API_GATEWAY", "APPLICATION_LOAD_BALANCER"])
        self.assertTrue(all(ACL_ARN in c for c in asked))

    def test_cloudfront_web_acls_are_read_in_us_east_1_with_their_scope(self):
        (argv,) = [c for c in self.runner.calls if c[2] == "list-web-acls" and "CLOUDFRONT" in c]
        self.assertEqual(argv[argv.index("--region") + 1], "us-east-1")


class WafWithoutBalancersTests(unittest.TestCase):
    """An account with only CloudFront (no ALB) still gets a verdict per distribution."""

    def test_cloudfront_only_account_gets_pass_and_fail_rows_and_nothing_is_na(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "checks").mkdir()
        shutil.copy(NETWORK_JSON, tmp / "checks" / "network.json")
        specs = json.loads((REFS / "inventory.json").read_text(encoding="utf-8"))
        (tmp / "inventory.json").write_text(json.dumps({t: specs[t] for t in ("cloudfront_distribution",)}), encoding="utf-8")
        scope = {"platform": "Acme Notes", "mode": "full", "target": None, "regions": [REGION], "profile": None, "resources": [], "domains": None}
        (tmp / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
        core = lambda name: ok(load_fixture(f"aws/core/{name}.json"))
        runner = RuleRunner([
            ("sts", "get-caller-identity", None, "", core("sts-get-caller-identity")), ("ec2", "describe-regions", None, "", core("ec2-describe-regions")),
            ("iam", "list-attached-user-policies", None, "", ok({"AttachedPolicies": []})),
            ("cloudfront", "list-distributions", None, "", ok(fx("cloudfront-list-distributions-mixed"))),
            ("wafv2", "list-web-acls", None, "CLOUDFRONT", ok(fx("wafv2-list-web-acls-cloudfront"))),
            ("wafv2", "list-web-acls", None, "", ok(fx("wafv2-list-web-acls-none"))),
            ("elbv2", "describe-load-balancers", None, "", ok({"LoadBalancers": []})), ("apigateway", "get-rest-apis", None, "", ok({"items": []}))])
        with contextlib.redirect_stdout(io.StringIO()):
            collect.main(["--scope", str(tmp / "scope.json"), "--out", str(tmp / "out"), "--checks-dir", str(tmp / "checks"),
                          "--inventory", str(tmp / "inventory.json"), "--quiet"], runner=runner, sleep=lambda s: None, which=lambda name: None)
        results = json.loads((tmp / "out" / "checks-result.json").read_text(encoding="utf-8"))["results"]
        self.assertEqual([(r["status"], r["resource_id"]) for r in results if r["check_id"] == "NET-008"],
                         [("PASS", "E1A2B3C4D5E6F7"), ("FAIL", "E2B3C4D5E6F7A8")])


if __name__ == "__main__":
    unittest.main()
