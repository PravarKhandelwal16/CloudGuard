"""
Storage Encryption Checks for CloudGuard Cloud Security Auditor.

Evaluates:
- Unencrypted EBS volumes (EC2 describe_volumes)
- Unencrypted RDS database storage (RDS describe_db_instances)
"""

import uuid
import logging
from typing import Dict, Any, List, Tuple
from botocore.exceptions import ClientError
from ..severity_engine import Severity, CheckStatus
from ..remediation import get_remediation_info

logger = logging.getLogger(__name__)


def run_encryption_checks(
    ec2_client,
    rds_client,
    default_region: str = "ap-south-1"
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """
    Executes EBS and RDS storage encryption checks.
    """
    findings = []
    permission_denied_services = []
    total_resources = 0
    passed_resources = 0
    failed_resources = 0
    warned_resources = 0
    not_assessed_resources = 0

    # 1. EBS Volume Encryption Check
    volumes = []
    try:
        vol_resp = ec2_client.describe_volumes()
        volumes = vol_resp.get("Volumes", [])
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code in ("AccessDenied", "UnauthorizedOperation"):
            permission_denied_services.append("EC2 (DescribeVolumes)")
            findings.append({
                "finding_id": f"ebs-denied-{uuid.uuid4().hex[:8]}",
                "service": "EBS",
                "resource_id": "arn:aws:ec2:*:*:volume/*",
                "title": "EBS Encryption Assessment Incomplete: Missing ec2:DescribeVolumes",
                "description": "CloudGuard could not inspect EBS volumes due to IAM permission denial.",
                "severity": Severity.INFORMATIONAL,
                "status": CheckStatus.NOT_ASSESSED,
                "evidence": f"AWS API returned {error_code}.",
                "remediation": "Add ec2:DescribeVolumes permission to the CloudGuard audit role.",
                "region": default_region
            })
            not_assessed_resources += 1
        elif error_code != "EndpointConnectionError":
            logger.warning("Error describing EBS volumes: %s", str(e))

    for vol in volumes:
        total_resources += 1
        vol_id = vol.get("VolumeId", "unknown-vol")
        is_encrypted = vol.get("Encrypted", False)
        size_gb = vol.get("Size", 0)
        state = vol.get("State", "available")

        if not is_encrypted:
            failed_resources += 1
            rem = get_remediation_info("EBS_UNENCRYPTED", vol_id, default_region)
            findings.append({
                "finding_id": f"ebs-unencrypted-{vol_id}",
                "service": "EBS",
                "resource_id": vol_id,
                "title": f"Unencrypted EBS Volume ({vol_id})",
                "description": f"EBS volume '{vol_id}' (Size: {size_gb}GB, State: {state}) is not encrypted at rest.",
                "severity": Severity.MEDIUM,
                "status": CheckStatus.FAILED,
                "evidence": f"Encrypted=False, VolumeType={vol.get('VolumeType')}, Size={size_gb}GB",
                "remediation": rem["summary"],
                "remediation_details": rem,
                "region": default_region
            })
        else:
            passed_resources += 1
            findings.append({
                "finding_id": f"ebs-encrypted-{vol_id}",
                "service": "EBS",
                "resource_id": vol_id,
                "title": f"EBS Volume Encryption Baseline Met ({vol_id})",
                "description": f"EBS volume '{vol_id}' is encrypted at rest using KMS or AWS-managed key.",
                "severity": Severity.INFORMATIONAL,
                "status": CheckStatus.PASSED,
                "evidence": f"Encrypted=True, KmsKeyId={vol.get('KmsKeyId', 'default')}",
                "remediation": "Maintain default encryption settings.",
                "region": default_region
            })

    # 2. RDS Storage Encryption Check
    db_instances = []
    try:
        rds_resp = rds_client.describe_db_instances()
        db_instances = rds_resp.get("DBInstances", [])
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code in ("AccessDenied", "UnauthorizedOperation"):
            permission_denied_services.append("RDS (DescribeDBInstances)")
            findings.append({
                "finding_id": f"rds-denied-{uuid.uuid4().hex[:8]}",
                "service": "RDS",
                "resource_id": "arn:aws:rds:*:*:db:*",
                "title": "RDS Encryption Assessment Incomplete: Missing rds:DescribeDBInstances",
                "description": "CloudGuard could not inspect RDS instances due to IAM permission denial.",
                "severity": Severity.INFORMATIONAL,
                "status": CheckStatus.NOT_ASSESSED,
                "evidence": f"AWS API returned {error_code}.",
                "remediation": "Add rds:DescribeDBInstances permission to the CloudGuard audit role.",
                "region": default_region
            })
            not_assessed_resources += 1
        elif error_code != "EndpointConnectionError":
            logger.warning("Error describing RDS instances: %s", str(e))

    for db in db_instances:
        total_resources += 1
        db_id = db.get("DBInstanceIdentifier", "unknown-db")
        engine = db.get("Engine", "unknown")
        is_encrypted = db.get("StorageEncrypted", False)

        if not is_encrypted:
            failed_resources += 1
            rem = get_remediation_info("RDS_UNENCRYPTED", db_id, default_region)
            findings.append({
                "finding_id": f"rds-unencrypted-{db_id}",
                "service": "RDS",
                "resource_id": db_id,
                "title": f"Unencrypted RDS Database Storage ({db_id})",
                "description": f"RDS database '{db_id}' (Engine: {engine}) does not have storage encryption enabled.",
                "severity": Severity.MEDIUM,
                "status": CheckStatus.FAILED,
                "evidence": f"StorageEncrypted=False, Engine={engine}, AllocatedStorage={db.get('AllocatedStorage')}GB",
                "remediation": rem["summary"],
                "remediation_details": rem,
                "region": default_region
            })
        else:
            passed_resources += 1
            findings.append({
                "finding_id": f"rds-encrypted-{db_id}",
                "service": "RDS",
                "resource_id": db_id,
                "title": f"RDS Database Storage Encryption Baseline Met ({db_id})",
                "description": f"RDS database '{db_id}' has storage encryption enabled.",
                "severity": Severity.INFORMATIONAL,
                "status": CheckStatus.PASSED,
                "evidence": f"StorageEncrypted=True, KmsKeyId={db.get('KmsKeyId', 'default')}",
                "remediation": "Maintain current database KMS encryption settings.",
                "region": default_region
            })

    summary = {
        "service": "StorageEncryption",
        "resource_type": "Storage Volumes & Databases",
        "total": total_resources,
        "passed": passed_resources,
        "failed": failed_resources,
        "warned": warned_resources,
        "not_assessed": not_assessed_resources
    }
    return findings, summary, permission_denied_services
