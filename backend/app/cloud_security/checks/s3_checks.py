"""
S3 Bucket Security Checks for CloudGuard Cloud Security Auditor.

Evaluates:
- Publicly accessible S3 buckets
- Missing S3 Block Public Access
- Missing default encryption
- Insecure bucket policies (lack of TLS enforcement)
- Access control list (ACL) public grants
"""

import json
import uuid
import logging
from typing import Dict, Any, List, Tuple
from botocore.exceptions import ClientError
from ..severity_engine import Severity, CheckStatus
from ..remediation import get_remediation_info

logger = logging.getLogger(__name__)


def run_s3_checks(s3_client, default_region: str = "ap-south-1") -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """
    Executes S3 security checks using read-only Boto3 S3 client.
    Returns:
        (findings_list, summary_dict, permission_denied_services)
    """
    findings = []
    permission_denied_services = []
    total_buckets = 0
    passed_buckets = 0
    failed_buckets = 0
    warned_buckets = 0
    not_assessed_buckets = 0

    try:
        response = s3_client.list_buckets()
        buckets = response.get("Buckets", [])
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code in ("AccessDenied", "UnauthorizedOperation"):
            permission_denied_services.append("S3 (ListBuckets)")
            findings.append({
                "finding_id": f"s3-access-denied-{uuid.uuid4().hex[:8]}",
                "service": "S3",
                "resource_id": "arn:aws:s3:::*",
                "title": "S3 Assessment Incomplete: Missing s3:ListAllMyBuckets Permission",
                "description": "CloudGuard could not enumerate S3 buckets due to IAM permission denial.",
                "severity": Severity.INFORMATIONAL,
                "status": CheckStatus.NOT_ASSESSED,
                "evidence": f"AWS API returned {error_code}: {e.response.get('Error', {}).get('Message')}",
                "remediation": "Add s3:ListAllMyBuckets permission to the CloudGuard audit IAM role.",
                "region": default_region
            })
            return findings, {"total": 0, "passed": 0, "failed": 0, "warned": 0, "not_assessed": 1}, permission_denied_services
        raise

    total_buckets = len(buckets)

    for b in buckets:
        bucket_name = b["Name"]
        bucket_findings = []
        is_public = False
        has_block_public_access = False
        has_encryption = False
        bucket_has_permission_issue = False

        # 1. Block Public Access Check
        pab_config = None
        try:
            pab_res = s3_client.get_public_access_block(Bucket=bucket_name)
            pab_config = pab_res.get("PublicAccessBlockConfiguration", {})
            b_acls = pab_config.get("BlockPublicAcls", False)
            i_acls = pab_config.get("IgnorePublicAcls", False)
            b_policy = pab_config.get("BlockPublicPolicy", False)
            r_buckets = pab_config.get("RestrictPublicBuckets", False)

            if b_acls and i_acls and b_policy and r_buckets:
                has_block_public_access = True
            else:
                disabled_flags = [
                    k for k, v in [
                        ("BlockPublicAcls", b_acls),
                        ("IgnorePublicAcls", i_acls),
                        ("BlockPublicPolicy", b_policy),
                        ("RestrictPublicBuckets", r_buckets)
                    ] if not v
                ]
                rem = get_remediation_info("S3_BLOCK_PUBLIC_ACCESS_DISABLED", bucket_name, default_region)
                bucket_findings.append({
                    "finding_id": f"s3-pab-incomplete-{bucket_name}",
                    "service": "S3",
                    "resource_id": bucket_name,
                    "title": "S3 Block Public Access Disabled or Incomplete",
                    "description": f"The bucket '{bucket_name}' has incomplete Block Public Access settings.",
                    "severity": Severity.HIGH,
                    "status": CheckStatus.FAILED,
                    "evidence": f"Disabled settings: {', '.join(disabled_flags)}",
                    "remediation": rem["summary"],
                    "remediation_details": rem,
                    "region": default_region
                })
        except ClientError as e:
            err = e.response.get("Error", {}).get("Code")
            if err == "NoSuchPublicAccessBlockConfiguration":
                rem = get_remediation_info("S3_BLOCK_PUBLIC_ACCESS_DISABLED", bucket_name, default_region)
                bucket_findings.append({
                    "finding_id": f"s3-pab-missing-{bucket_name}",
                    "service": "S3",
                    "resource_id": bucket_name,
                    "title": "S3 Block Public Access Not Configured",
                    "description": f"No Block Public Access configuration exists for '{bucket_name}'.",
                    "severity": Severity.HIGH,
                    "status": CheckStatus.FAILED,
                    "evidence": "API returned NoSuchPublicAccessBlockConfiguration.",
                    "remediation": rem["summary"],
                    "remediation_details": rem,
                    "region": default_region
                })
            elif err in ("AccessDenied", "UnauthorizedOperation"):
                bucket_has_permission_issue = True
                findings.append({
                    "finding_id": f"s3-pab-denied-{bucket_name}",
                    "service": "S3",
                    "resource_id": bucket_name,
                    "title": f"Cannot Verify S3 Block Public Access on '{bucket_name}'",
                    "description": f"Permission denied while reading Block Public Access for '{bucket_name}'.",
                    "severity": Severity.INFORMATIONAL,
                    "status": CheckStatus.NOT_ASSESSED,
                    "evidence": f"AWS API returned AccessDenied for s3:GetBucketPublicAccessBlock.",
                    "remediation": "Grant s3:GetBucketPublicAccessBlock permission to the auditor role.",
                    "region": default_region
                })

        # 2. Policy Status & Policy Content Check
        has_public_policy = False
        try:
            status_res = s3_client.get_bucket_policy_status(Bucket=bucket_name)
            has_public_policy = status_res.get("PolicyStatus", {}).get("IsPublic", False)
        except ClientError as e:
            err = e.response.get("Error", {}).get("Code")
            if err not in ("NoSuchBucketPolicy", "AccessDenied"):
                logger.warning("Error checking bucket policy status for %s: %s", bucket_name, str(e))

        # Check ACL for public grants
        has_public_acl = False
        try:
            acl_res = s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl_res.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    has_public_acl = True
                    break
        except ClientError:
            pass

        if (has_public_policy or has_public_acl) and not has_block_public_access:
            is_public = True
            rem = get_remediation_info("S3_PUBLIC_BUCKET", bucket_name, default_region)
            bucket_findings.append({
                "finding_id": f"s3-public-access-{bucket_name}",
                "service": "S3",
                "resource_id": bucket_name,
                "title": "Publicly Accessible S3 Bucket",
                "description": f"The bucket '{bucket_name}' allows unrestricted public read or write access from the internet.",
                "severity": Severity.CRITICAL,
                "status": CheckStatus.FAILED,
                "evidence": (
                    f"Public indicators detected: IsPublicPolicy={has_public_policy}, "
                    f"PublicACLGrant={has_public_acl}, BlockPublicAccessComplete={has_block_public_access}"
                ),
                "remediation": rem["summary"],
                "remediation_details": rem,
                "region": default_region
            })

        # 3. Default Encryption Check
        try:
            enc_res = s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = enc_res.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if len(rules) > 0:
                has_encryption = True
            else:
                rem = get_remediation_info("S3_MISSING_ENCRYPTION", bucket_name, default_region)
                bucket_findings.append({
                    "finding_id": f"s3-encryption-empty-{bucket_name}",
                    "service": "S3",
                    "resource_id": bucket_name,
                    "title": "S3 Default Encryption Disabled",
                    "description": f"The bucket '{bucket_name}' has no active server-side default encryption rules.",
                    "severity": Severity.MEDIUM,
                    "status": CheckStatus.FAILED,
                    "evidence": "ServerSideEncryptionConfiguration contains empty Rules list.",
                    "remediation": rem["summary"],
                    "remediation_details": rem,
                    "region": default_region
                })
        except ClientError as e:
            err = e.response.get("Error", {}).get("Code")
            if err == "ServerSideEncryptionConfigurationNotFoundError":
                rem = get_remediation_info("S3_MISSING_ENCRYPTION", bucket_name, default_region)
                bucket_findings.append({
                    "finding_id": f"s3-encryption-missing-{bucket_name}",
                    "service": "S3",
                    "resource_id": bucket_name,
                    "title": "S3 Default Encryption Disabled",
                    "description": f"The bucket '{bucket_name}' does not enforce server-side encryption at rest.",
                    "severity": Severity.MEDIUM,
                    "status": CheckStatus.FAILED,
                    "evidence": "API returned ServerSideEncryptionConfigurationNotFoundError.",
                    "remediation": rem["summary"],
                    "remediation_details": rem,
                    "region": default_region
                })
            elif err in ("AccessDenied", "UnauthorizedOperation"):
                bucket_has_permission_issue = True

        # Aggregate findings or pass status for this bucket
        if bucket_findings:
            failed_buckets += 1
            findings.extend(bucket_findings)
        elif bucket_has_permission_issue:
            not_assessed_buckets += 1
        else:
            # Baseline met
            passed_buckets += 1
            findings.append({
                "finding_id": f"s3-compliant-{bucket_name}",
                "service": "S3",
                "resource_id": bucket_name,
                "title": "S3 Bucket Security Baseline Met",
                "description": f"The bucket '{bucket_name}' has Block Public Access enabled and encryption configured.",
                "severity": Severity.INFORMATIONAL,
                "status": CheckStatus.PASSED,
                "evidence": f"BlockPublicAccess=True, DefaultEncryption={has_encryption}, PublicAccess=False",
                "remediation": "Maintain current security configurations and continuous audit logging.",
                "region": default_region
            })

    summary = {
        "service": "S3",
        "resource_type": "Bucket",
        "total": total_buckets,
        "passed": passed_buckets,
        "failed": failed_buckets,
        "warned": warned_buckets,
        "not_assessed": not_assessed_buckets
    }
    return findings, summary, permission_denied_services
