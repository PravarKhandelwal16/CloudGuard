"""
CloudGuard Cloud Security Auditor module.
"""

from .aws_connector import (
    AWSConnector,
    validate_account_id,
    validate_role_arn,
    AWSCloudSecurityException,
    AWSAuthenticationError,
    AWSPermissionError,
    AWSValidationError
)
from .sts_manager import STSManager
from .severity_engine import Severity, CheckStatus, SeverityEngine
from .security_scorer import SecurityScorer
from .remediation import get_remediation_info, REMEDIATION_CATALOG
from .auditor import CloudSecurityAuditor
from .simulation_provider import SimulatedAWSClientProvider

__all__ = [
    "AWSConnector",
    "STSManager",
    "Severity",
    "CheckStatus",
    "SeverityEngine",
    "SecurityScorer",
    "get_remediation_info",
    "REMEDIATION_CATALOG",
    "CloudSecurityAuditor",
    "SimulatedAWSClientProvider",
    "validate_account_id",
    "validate_role_arn",
    "AWSCloudSecurityException",
    "AWSAuthenticationError",
    "AWSPermissionError",
    "AWSValidationError",
]
