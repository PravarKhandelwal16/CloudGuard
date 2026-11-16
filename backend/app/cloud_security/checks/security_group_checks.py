"""
Security Group Security Checks for CloudGuard Cloud Security Auditor.

Evaluates:
- SSH (port 22) exposed to 0.0.0.0/0 or ::/0
- RDP (port 3389) exposed to 0.0.0.0/0 or ::/0
- Inbound access to all ports (Protocol -1 or port range 0-65535)
- Database ports exposed to public internet
"""

import uuid
import logging
from typing import Dict, Any, List, Tuple
from botocore.exceptions import ClientError
from ..severity_engine import Severity, CheckStatus
from ..remediation import get_remediation_info

logger = logging.getLogger(__name__)


def run_security_group_checks(ec2_client, default_region: str = "ap-south-1") -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """
    Executes Security Group checks using EC2 describe_security_groups.
    """
    findings = []
    permission_denied_services = []
    total_groups = 0
    passed_groups = 0
    failed_groups = 0
    warned_groups = 0
    not_assessed_groups = 0

    try:
        response = ec2_client.describe_security_groups()
        security_groups = response.get("SecurityGroups", [])
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code in ("AccessDenied", "UnauthorizedOperation"):
            permission_denied_services.append("EC2 (DescribeSecurityGroups)")
            findings.append({
                "finding_id": f"sg-denied-{uuid.uuid4().hex[:8]}",
                "service": "SecurityGroup",
                "resource_id": "arn:aws:ec2:*:*:security-group/*",
                "title": "Security Group Assessment Incomplete: Missing ec2:DescribeSecurityGroups",
                "description": "CloudGuard could not describe security groups due to IAM permission denial.",
                "severity": Severity.INFORMATIONAL,
                "status": CheckStatus.NOT_ASSESSED,
                "evidence": f"AWS API returned {error_code}.",
                "remediation": "Add ec2:DescribeSecurityGroups permission to the CloudGuard audit role.",
                "region": default_region
            })
            return findings, {"total": 0, "passed": 0, "failed": 0, "warned": 0, "not_assessed": 1}, permission_denied_services
        raise

    total_groups = len(security_groups)

    for sg in security_groups:
        sg_id = sg.get("GroupId", "unknown-sg")
        sg_name = sg.get("GroupName", "unnamed")
        ip_permissions = sg.get("IpPermissions", [])
        sg_findings = []

        for rule in ip_permissions:
            proto = str(rule.get("IpProtocol", "")).lower()
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")

            # Collect CIDRs
            open_cidrs = []
            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp")
                if cidr in ("0.0.0.0/0",):
                    open_cidrs.append(cidr)
            for ipv6_range in rule.get("Ipv6Ranges", []):
                cidr = ipv6_range.get("CidrIpv6")
                if cidr in ("::/0",):
                    open_cidrs.append(cidr)

            if not open_cidrs:
                continue

            cidr_str = ", ".join(open_cidrs)

            # 1. Catch-all: All ports & all protocols open
            if proto == "-1" or (from_port == 0 and to_port == 65535):
                rem = get_remediation_info("SG_ALL_PORTS_OPEN", sg_id, default_region)
                sg_findings.append({
                    "finding_id": f"sg-all-ports-open-{sg_id}",
                    "service": "SecurityGroup",
                    "resource_id": sg_id,
                    "title": f"Security Group Allows Unrestricted Inbound Traffic on All Ports ({sg_name})",
                    "description": (
                        f"Security group '{sg_id}' ({sg_name}) allows inbound traffic on all ports and protocols "
                        f"from the public internet ({cidr_str})."
                    ),
                    "severity": Severity.CRITICAL,
                    "status": CheckStatus.FAILED,
                    "evidence": f"Protocol={proto}, Ports={from_port}-{to_port}, SourceCIDRs={cidr_str}",
                    "remediation": rem["summary"],
                    "remediation_details": rem,
                    "region": default_region
                })
                continue

            # Check specific sensitive ports
            if from_port is not None and to_port is not None:
                # 2. SSH (Port 22)
                if from_port <= 22 <= to_port:
                    rem = get_remediation_info("SG_SSH_OPEN", sg_id, default_region)
                    sg_findings.append({
                        "finding_id": f"sg-ssh-open-{sg_id}",
                        "service": "SecurityGroup",
                        "resource_id": sg_id,
                        "title": f"Security Group Exposes SSH (Port 22) to the Internet ({sg_name})",
                        "description": (
                            f"Security group '{sg_id}' ({sg_name}) permits unrestricted inbound SSH (port 22) "
                            f"from {cidr_str}."
                        ),
                        "severity": Severity.HIGH,
                        "status": CheckStatus.FAILED,
                        "evidence": f"Protocol={proto}, Port=22, SourceCIDRs={cidr_str}",
                        "remediation": rem["summary"],
                        "remediation_details": rem,
                        "region": default_region
                    })

                # 3. RDP (Port 3389)
                if from_port <= 3389 <= to_port:
                    rem = get_remediation_info("SG_RDP_OPEN", sg_id, default_region)
                    sg_findings.append({
                        "finding_id": f"sg-rdp-open-{sg_id}",
                        "service": "SecurityGroup",
                        "resource_id": sg_id,
                        "title": f"Security Group Exposes RDP (Port 3389) to the Internet ({sg_name})",
                        "description": (
                            f"Security group '{sg_id}' ({sg_name}) permits unrestricted inbound RDP (port 3389) "
                            f"from {cidr_str}."
                        ),
                        "severity": Severity.HIGH,
                        "status": CheckStatus.FAILED,
                        "evidence": f"Protocol={proto}, Port=3389, SourceCIDRs={cidr_str}",
                        "remediation": rem["summary"],
                        "remediation_details": rem,
                        "region": default_region
                    })

                # 4. Database ports (3306, 5432, 27017, 1433, 6379)
                db_ports = [
                    (3306, "MySQL/Aurora"),
                    (5432, "PostgreSQL"),
                    (27017, "MongoDB"),
                    (1433, "MSSQL"),
                    (6379, "Redis")
                ]
                for p_num, p_name in db_ports:
                    if from_port <= p_num <= to_port:
                        sg_findings.append({
                            "finding_id": f"sg-db-open-{sg_id}-{p_num}",
                            "service": "SecurityGroup",
                            "resource_id": sg_id,
                            "title": f"Security Group Exposes {p_name} (Port {p_num}) to the Internet ({sg_name})",
                            "description": (
                                f"Security group '{sg_id}' ({sg_name}) permits direct internet access to database port "
                                f"{p_num} ({p_name}) from {cidr_str}."
                            ),
                            "severity": Severity.HIGH,
                            "status": CheckStatus.FAILED,
                            "evidence": f"Protocol={proto}, Port={p_num}, SourceCIDRs={cidr_str}",
                            "remediation": f"Revoke inbound rule for port {p_num} from 0.0.0.0/0. Database tiers should never be directly accessible from the public internet.",
                            "region": default_region
                        })

        if sg_findings:
            failed_groups += 1
            findings.extend(sg_findings)
        else:
            passed_groups += 1
            findings.append({
                "finding_id": f"sg-compliant-{sg_id}",
                "service": "SecurityGroup",
                "resource_id": sg_id,
                "title": f"Security Group Perimeter Ingress Baseline Met ({sg_name})",
                "description": f"Security group '{sg_id}' ({sg_name}) does not expose management or database ports to 0.0.0.0/0.",
                "severity": Severity.INFORMATIONAL,
                "status": CheckStatus.PASSED,
                "evidence": "Inbound rules restrict administrative and database ports to authorized IP ranges.",
                "remediation": "Regularly review and remove unused inbound rules.",
                "region": default_region
            })

    summary = {
        "service": "SecurityGroup",
        "resource_type": "Security Group",
        "total": total_groups,
        "passed": passed_groups,
        "failed": failed_groups,
        "warned": warned_groups,
        "not_assessed": not_assessed_groups
    }
    return findings, summary, permission_denied_services
