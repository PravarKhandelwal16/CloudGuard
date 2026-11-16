"""
CloudTrail Security Checks for CloudGuard Cloud Security Auditor.

Evaluates:
- Presence of at least one multi-region trail
- Active logging state of trails
- Log file integrity validation
- KMS encryption configuration
"""

import uuid
import logging
from typing import Dict, Any, List, Tuple
from botocore.exceptions import ClientError
from ..severity_engine import Severity, CheckStatus
from ..remediation import get_remediation_info

logger = logging.getLogger(__name__)


def run_cloudtrail_checks(cloudtrail_client, default_region: str = "ap-south-1") -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """
    Executes CloudTrail checks using describe_trails and get_trail_status.
    """
    findings = []
    permission_denied_services = []
    total_trails = 0
    passed_trails = 0
    failed_trails = 0
    warned_trails = 0
    not_assessed_trails = 0

    try:
        response = cloudtrail_client.describe_trails()
        trails = response.get("trailList", [])
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code in ("AccessDenied", "UnauthorizedOperation"):
            permission_denied_services.append("CloudTrail (DescribeTrails)")
            findings.append({
                "finding_id": f"cloudtrail-denied-{uuid.uuid4().hex[:8]}",
                "service": "CloudTrail",
                "resource_id": "arn:aws:cloudtrail:*:*:trail/*",
                "title": "CloudTrail Assessment Incomplete: Missing cloudtrail:DescribeTrails",
                "description": "CloudGuard could not inspect CloudTrail trails due to IAM permission denial.",
                "severity": Severity.INFORMATIONAL,
                "status": CheckStatus.NOT_ASSESSED,
                "evidence": f"AWS API returned {error_code}.",
                "remediation": "Add cloudtrail:DescribeTrails and cloudtrail:GetTrailStatus to the CloudGuard audit role.",
                "region": default_region
            })
            return findings, {"total": 0, "passed": 0, "failed": 0, "warned": 0, "not_assessed": 1}, permission_denied_services
        raise

    total_trails = len(trails)

    # 1. Check if any trail exists at all
    if total_trails == 0:
        rem = get_remediation_info("CLOUDTRAIL_NO_MULTI_REGION", "default-trail", default_region)
        findings.append({
            "finding_id": f"cloudtrail-none-configured-{default_region}",
            "service": "CloudTrail",
            "resource_id": f"account-{default_region}",
            "title": "No CloudTrail Trails Configured in AWS Account",
            "description": "No CloudTrail trails were found. Audit logging is completely disabled across the account.",
            "severity": Severity.HIGH,
            "status": CheckStatus.FAILED,
            "evidence": "describe_trails returned empty trailList.",
            "remediation": rem["summary"],
            "remediation_details": rem,
            "region": default_region
        })
        return findings, {"total": 1, "passed": 0, "failed": 1, "warned": 0, "not_assessed": 0}, permission_denied_services

    # 2. Check for at least one active multi-region trail
    has_multi_region_trail = any(t.get("IsMultiRegionTrail", False) for t in trails)
    if not has_multi_region_trail:
        rem = get_remediation_info("CLOUDTRAIL_NO_MULTI_REGION", trails[0].get("Name", "trail"), default_region)
        findings.append({
            "finding_id": f"cloudtrail-no-multi-region-{default_region}",
            "service": "CloudTrail",
            "resource_id": trails[0].get("Name", "trail"),
            "title": "No Multi-Region CloudTrail Trail Configured",
            "description": "None of the configured trails are multi-region. API activity outside primary region will not be recorded.",
            "severity": Severity.HIGH,
            "status": CheckStatus.FAILED,
            "evidence": f"Total trails: {len(trails)}, but none have IsMultiRegionTrail=True.",
            "remediation": rem["summary"],
            "remediation_details": rem,
            "region": default_region
        })

    # 3. Check individual trails for logging status and validation
    for trail in trails:
        trail_name = trail.get("Name", "unknown-trail")
        trail_arn = trail.get("TrailARN", trail_name)
        trail_findings = []

        is_logging = True
        try:
            status_resp = cloudtrail_client.get_trail_status(Name=trail_name)
            is_logging = status_resp.get("IsLogging", False)
            if not is_logging:
                rem = get_remediation_info("CLOUDTRAIL_NOT_LOGGING", trail_name, default_region)
                trail_findings.append({
                    "finding_id": f"cloudtrail-not-logging-{trail_name}",
                    "service": "CloudTrail",
                    "resource_id": trail_arn,
                    "title": f"CloudTrail Trail Is Not Actively Logging ({trail_name})",
                    "description": f"Logging is disabled for CloudTrail trail '{trail_name}'. API events are not being captured.",
                    "severity": Severity.HIGH,
                    "status": CheckStatus.FAILED,
                    "evidence": f"get_trail_status returned IsLogging=False. StopLoggingTime: {status_resp.get('StopLoggingTime')}",
                    "remediation": rem["summary"],
                    "remediation_details": rem,
                    "region": default_region
                })
        except ClientError as e:
            err = e.response.get("Error", {}).get("Code")
            if err in ("AccessDenied", "UnauthorizedOperation"):
                findings.append({
                    "finding_id": f"cloudtrail-status-denied-{trail_name}",
                    "service": "CloudTrail",
                    "resource_id": trail_arn,
                    "title": f"Cannot Verify Logging Status for Trail '{trail_name}'",
                    "description": f"Permission denied while calling get_trail_status on '{trail_name}'.",
                    "severity": Severity.INFORMATIONAL,
                    "status": CheckStatus.NOT_ASSESSED,
                    "evidence": f"AWS API returned AccessDenied.",
                    "remediation": "Add cloudtrail:GetTrailStatus to the audit role.",
                    "region": default_region
                })

        # Log file validation
        val_enabled = trail.get("LogFileValidationEnabled", False)
        if not val_enabled:
            rem = get_remediation_info("CLOUDTRAIL_VALIDATION_DISABLED", trail_name, default_region)
            trail_findings.append({
                "finding_id": f"cloudtrail-log-val-disabled-{trail_name}",
                "service": "CloudTrail",
                "resource_id": trail_arn,
                "title": f"CloudTrail Log File Validation Disabled ({trail_name})",
                "description": (
                    f"Trail '{trail_name}' does not have log file validation enabled. "
                    f"Modifications or deletions of delivered log files cannot be cryptographically detected."
                ),
                "severity": Severity.LOW,
                "status": CheckStatus.FAILED,
                "evidence": "LogFileValidationEnabled is False.",
                "remediation": rem["summary"],
                "remediation_details": rem,
                "region": default_region
            })

        # KMS Encryption
        kms_key = trail.get("KmsKeyId")
        if not kms_key:
            trail_findings.append({
                "finding_id": f"cloudtrail-kms-missing-{trail_name}",
                "service": "CloudTrail",
                "resource_id": trail_arn,
                "title": f"CloudTrail Trail Not Encrypted with Customer KMS Key ({trail_name})",
                "description": f"Trail '{trail_name}' uses default S3 SSE rather than a customer-managed KMS key.",
                "severity": Severity.LOW,
                "status": CheckStatus.WARNING,
                "evidence": "KmsKeyId is null/empty in trail configuration.",
                "remediation": "Configure a KMS key on the CloudTrail trail for enhanced audit encryption.",
                "region": default_region
            })

        if any(f["status"] == CheckStatus.FAILED for f in trail_findings):
            failed_trails += 1
            findings.extend(trail_findings)
        elif any(f["status"] == CheckStatus.WARNING for f in trail_findings):
            warned_trails += 1
            findings.extend(trail_findings)
        else:
            passed_trails += 1
            findings.append({
                "finding_id": f"cloudtrail-compliant-{trail_name}",
                "service": "CloudTrail",
                "resource_id": trail_arn,
                "title": f"CloudTrail Audit Logging Baseline Met ({trail_name})",
                "description": f"Trail '{trail_name}' is actively logging with validation enabled.",
                "severity": Severity.INFORMATIONAL,
                "status": CheckStatus.PASSED,
                "evidence": f"IsLogging=True, LogFileValidationEnabled=True, MultiRegion={trail.get('IsMultiRegionTrail')}",
                "remediation": "Maintain current CloudTrail logging configuration and monitor via CloudWatch alarms.",
                "region": default_region
            })

    summary = {
        "service": "CloudTrail",
        "resource_type": "Audit Trail",
        "total": total_trails,
        "passed": passed_trails,
        "failed": failed_trails,
        "warned": warned_trails,
        "not_assessed": not_assessed_trails
    }
    return findings, summary, permission_denied_services
