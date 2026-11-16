"""
Cloud Security Auditor for CloudGuard.

Orchestrates all cloud security checks across S3, IAM, Security Groups,
CloudTrail, and Storage Encryption.
Supports both live AWS STS AssumeRole sessions and local simulation mode
using the exact same security checks and scoring logic.
"""

import time
import logging
from typing import Dict, Any, Optional, List
from .aws_connector import AWSConnector, AWSCloudSecurityException, AWSAuthenticationError
from .simulation_provider import SimulatedAWSClientProvider
from .security_scorer import SecurityScorer
from .checks import (
    run_s3_checks,
    run_iam_checks,
    run_security_group_checks,
    run_cloudtrail_checks,
    run_encryption_checks
)

logger = logging.getLogger(__name__)


class CloudSecurityAuditor:
    """Core auditor engine for AWS cloud infrastructure security assessment."""

    def __init__(
        self,
        account_id: str,
        role_arn: Optional[str] = None,
        region: str = "ap-south-1",
        external_id: Optional[str] = None,
        is_simulation: bool = False,
        simulation_fixture_path: Optional[str] = None
    ):
        self.account_id = account_id
        self.role_arn = role_arn
        self.region = region
        self.external_id = external_id
        self.is_simulation = is_simulation
        self.simulation_fixture_path = simulation_fixture_path
        self.connector: Optional[AWSConnector] = None
        self.client_provider = None

    def _setup_clients(self):
        """Initializes either simulated client provider or live AWS connector."""
        if self.is_simulation:
            logger.info("Initializing CloudGuard Auditor in LOCAL SIMULATION MODE.")
            self.client_provider = SimulatedAWSClientProvider(self.simulation_fixture_path)
        else:
            if not self.role_arn:
                raise AWSCloudSecurityException("Role ARN is required for live AWS account assessment.")
            logger.info("Initializing live AWS connection with STS AssumeRole for account: %s", self.account_id)
            self.connector = AWSConnector(
                role_arn=self.role_arn,
                account_id=self.account_id,
                region=self.region,
                external_id=self.external_id
            )
            # Pre-validate AssumeRole
            self.connector.assume_role()
            self.client_provider = self.connector

    def run_audit(self) -> Dict[str, Any]:
        """
        Executes complete cloud security assessment across all 5 categories.
        Returns full assessment results with findings, coverage metrics, and score.
        """
        start_time = time.perf_counter()
        self._setup_clients()

        all_findings: List[Dict[str, Any]] = []
        resource_summaries: List[Dict[str, Any]] = []
        all_denied_services: List[str] = []
        total_resources = 0

        # 1. S3 Bucket Security Checks
        try:
            s3_client = self.client_provider.get_client("s3", region=self.region)
            s3_findings, s3_summary, s3_denied = run_s3_checks(s3_client, default_region=self.region)
            all_findings.extend(s3_findings)
            resource_summaries.append(s3_summary)
            all_denied_services.extend(s3_denied)
            total_resources += s3_summary["total"]
        except Exception as e:
            logger.error("Error during S3 checks: %s", str(e), exc_info=True)
            all_denied_services.append("S3 (Unexpected error)")

        # 2. IAM Security Checks (IAM is global, typically evaluated with us-east-1 or default)
        try:
            iam_client = self.client_provider.get_client("iam", region="us-east-1" if not self.is_simulation else self.region)
            iam_findings, iam_summary, iam_denied = run_iam_checks(iam_client, default_region=self.region)
            all_findings.extend(iam_findings)
            resource_summaries.append(iam_summary)
            all_denied_services.extend(iam_denied)
            total_resources += iam_summary["total"]
        except Exception as e:
            logger.error("Error during IAM checks: %s", str(e), exc_info=True)
            all_denied_services.append("IAM (Unexpected error)")

        # 3. Security Group Checks
        try:
            ec2_client = self.client_provider.get_client("ec2", region=self.region)
            sg_findings, sg_summary, sg_denied = run_security_group_checks(ec2_client, default_region=self.region)
            all_findings.extend(sg_findings)
            resource_summaries.append(sg_summary)
            all_denied_services.extend(sg_denied)
            total_resources += sg_summary["total"]
        except Exception as e:
            logger.error("Error during Security Group checks: %s", str(e), exc_info=True)
            all_denied_services.append("EC2 (Security Groups unexpected error)")

        # 4. CloudTrail Security Checks
        try:
            ct_client = self.client_provider.get_client("cloudtrail", region=self.region)
            ct_findings, ct_summary, ct_denied = run_cloudtrail_checks(ct_client, default_region=self.region)
            all_findings.extend(ct_findings)
            resource_summaries.append(ct_summary)
            all_denied_services.extend(ct_denied)
            total_resources += ct_summary["total"]
        except Exception as e:
            logger.error("Error during CloudTrail checks: %s", str(e), exc_info=True)
            all_denied_services.append("CloudTrail (Unexpected error)")

        # 5. Storage Encryption Checks (EBS & RDS)
        try:
            ec2_client = self.client_provider.get_client("ec2", region=self.region)
            rds_client = self.client_provider.get_client("rds", region=self.region)
            enc_findings, enc_summary, enc_denied = run_encryption_checks(ec2_client, rds_client, default_region=self.region)
            all_findings.extend(enc_findings)
            resource_summaries.append(enc_summary)
            all_denied_services.extend(enc_denied)
            total_resources += enc_summary["total"]
        except Exception as e:
            logger.error("Error during Storage Encryption checks: %s", str(e), exc_info=True)
            all_denied_services.append("Storage (Unexpected error)")

        duration_ms = int((time.perf_counter() - start_time) * 1000)

        # Calculate score and coverage
        scoring_result = SecurityScorer.calculate_score(
            findings=all_findings,
            total_resources_assessed=total_resources,
            permission_denied_services=all_denied_services
        )

        overall_status = "completed"
        if not scoring_result["is_complete"]:
            overall_status = "partial" if total_resources > 0 else "incomplete"

        return {
            "account_id": self.account_id,
            "region": self.region,
            "role_arn": self.role_arn or ("SimulatedRole" if self.is_simulation else None),
            "is_simulation": self.is_simulation,
            "simulation_label": "DEMO / SIMULATED DATA — NOT LIVE AWS FINDINGS" if self.is_simulation else None,
            "status": overall_status,
            "coverage_status": scoring_result["coverage_status"],
            "coverage_notes": scoring_result["coverage_notes"],
            "security_score": scoring_result["score"],
            "total_resources_assessed": scoring_result["total_resources_assessed"],
            "checks_passed": scoring_result["checks_passed"],
            "checks_failed": scoring_result["checks_failed"],
            "checks_warned": scoring_result["checks_warned"],
            "checks_not_assessed": scoring_result["checks_not_assessed"],
            "critical_count": scoring_result["critical_count"],
            "high_count": scoring_result["high_count"],
            "medium_count": scoring_result["medium_count"],
            "low_count": scoring_result["low_count"],
            "info_count": scoring_result["info_count"],
            "scan_duration_ms": duration_ms,
            "findings": all_findings,
            "resource_summaries": resource_summaries
        }
