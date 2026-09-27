"""EC2 / network checks — CIS AWS Foundations Benchmark v5.0.0, sections 5.1.1 and 5.3-5.5."""

from .models import Finding, Severity, Status

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}


def _rule_covers_port(rule, port):
    """True if an ingress rule opens `port`. Protocol "-1" means all traffic."""
    if rule.get("IpProtocol") == "-1":
        return True
    if rule.get("IpProtocol") not in ("tcp", "6"):
        return False
    return rule.get("FromPort", 0) <= port <= rule.get("ToPort", 65535)


def _open_to_world(rule):
    """Return which 'whole internet' ranges the rule allows: IPv4 and/or IPv6."""
    ranges = []
    if any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])):
        ranges.append("0.0.0.0/0")
    if any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", [])):
        ranges.append("::/0")
    return ranges


def check_security_groups(ec2, region):
    findings = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            sg_id, sg_name = sg["GroupId"], sg["GroupName"]
            resource = f"{region}/{sg_id} ({sg_name})"

            # CIS 5.3 / 5.4: no admin ports open to the whole internet.
            exposed = set()
            for rule in sg.get("IpPermissions", []):
                for cidr in _open_to_world(rule):
                    for port, proto in ADMIN_PORTS.items():
                        if _rule_covers_port(rule, port):
                            exposed.add(f"{proto}/{port} from {cidr}")
            if exposed:
                findings.append(Finding(
                    "EC2-01", "5.3/5.4", "No admin ports open to the internet", Severity.HIGH,
                    Status.FAIL, resource, f"Exposed: {', '.join(sorted(exposed))}.",
                    "Restrict SSH/RDP to known IP ranges or use SSM Session Manager instead.",
                ))

            # CIS 5.5: the default SG must allow nothing, so it cannot be used by accident.
            if sg_name == "default":
                has_rules = bool(sg.get("IpPermissions")) or bool(sg.get("IpPermissionsEgress"))
                findings.append(Finding(
                    "EC2-02", "5.5", "Default security group restricts all traffic", Severity.LOW,
                    Status.FAIL if has_rules else Status.PASS, resource,
                    "Default SG has inbound/outbound rules." if has_rules else "Default SG has no rules.",
                    "Remove all rules from the default security group.",
                ))
    return findings


def check_ebs_default_encryption(ec2, region):
    """CIS 5.1.1: every new EBS volume encrypted automatically."""
    on = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    return [Finding(
        "EC2-03", "5.1.1", "EBS encryption by default enabled", Severity.MEDIUM,
        Status.PASS if on else Status.FAIL, f"{region}/account",
        "New EBS volumes are encrypted by default." if on
        else "New EBS volumes are created unencrypted unless someone remembers to tick the box.",
        "Enable EBS encryption by default in every region you use.",
    )]


def run(session, regions):
    findings = []
    for region in regions:
        ec2 = session.client("ec2", region_name=region)
        findings += check_security_groups(ec2, region)
        findings += check_ebs_default_encryption(ec2, region)
    return findings
