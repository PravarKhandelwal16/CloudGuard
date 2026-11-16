"""
Severity classification engine for CloudGuard Cloud Security Auditor.

Evaluates security findings within their actual configuration context rather
than assigning a static severity across every occurrence.
"""

from typing import Dict, Any, Optional


class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    ALL = (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)


class CheckStatus:
    FAILED = "FAILED"
    PASSED = "PASSED"
    WARNING = "WARNING"
    NOT_ASSESSED = "NOT ASSESSED"

    ALL = (FAILED, PASSED, WARNING, NOT_ASSESSED)


class SeverityEngine:
    """Contextual severity determination logic."""

    @staticmethod
    def classify_s3_finding(
        issue_type: str,
        is_public: bool = False,
        has_sensitive_name: bool = False,
        encryption_missing: bool = False
    ) -> str:
        """
        Determines severity for S3 misconfigurations based on exposure context.
        """
        if issue_type == "PUBLIC_BUCKET":
            # Direct public access is critical
            return Severity.CRITICAL
        elif issue_type == "BLOCK_PUBLIC_ACCESS_DISABLED":
            # If public block is off and bucket has public policy
            if is_public:
                return Severity.CRITICAL
            return Severity.HIGH
        elif issue_type == "MISSING_DEFAULT_ENCRYPTION":
            return Severity.MEDIUM
        elif issue_type == "INSECURE_POLICY_HTTP":
            return Severity.MEDIUM
        elif issue_type == "PERMISSION_DENIED":
            return Severity.INFORMATIONAL
        return Severity.LOW

    @staticmethod
    def classify_iam_finding(
        issue_type: str,
        actions: Optional[list] = None,
        resources: Optional[list] = None,
        entity_type: str = "role"
    ) -> str:
        """
        Distinguishes potentially dangerous wildcard policies from confirmed
        broad administrative privileges.
        """
        actions = actions or []
        resources = resources or []

        has_star_action = "*" in actions
        has_star_resource = "*" in resources

        if issue_type == "FULL_ADMIN_WILDCARD":
            if has_star_action and has_star_resource:
                # Direct user attachment of full admin is critical/high
                if entity_type == "user":
                    return Severity.HIGH
                return Severity.HIGH
            return Severity.MEDIUM

        elif issue_type == "SERVICE_WILDCARD":
            # Check if sensitive service like iam:* or sts:*
            sensitive_wildcards = {"iam:*", "sts:*", "kms:*"}
            if any(a.lower() in sensitive_wildcards for a in actions):
                return Severity.HIGH
            return Severity.MEDIUM

        elif issue_type == "DIRECT_ADMIN_POLICY":
            return Severity.HIGH

        return Severity.LOW

    @staticmethod
    def classify_security_group_finding(
        port_from: Optional[int],
        port_to: Optional[int],
        protocol: str,
        cidr: str
    ) -> str:
        """
        Evaluates exposure severity based on open ports and protocol.
        """
        is_open_to_all = cidr in ("0.0.0.0/0", "::/0")

        # Catch-all unrestricted inbound
        if protocol == "-1" or (port_from == 0 and port_to == 65535):
            return Severity.CRITICAL if is_open_to_all else Severity.HIGH

        # Specific sensitive management ports
        if port_from is not None and port_to is not None:
            # SSH
            if port_from <= 22 <= port_to and is_open_to_all:
                return Severity.HIGH
            # RDP
            if port_from <= 3389 <= port_to and is_open_to_all:
                return Severity.HIGH
            # Database ports (MySQL, PostgreSQL, MongoDB, MSSQL, Redis)
            db_ports = {3306, 5432, 27017, 1433, 6379, 9200}
            if any(port_from <= p <= port_to for p in db_ports) and is_open_to_all:
                return Severity.HIGH

        return Severity.MEDIUM if is_open_to_all else Severity.LOW

    @staticmethod
    def classify_cloudtrail_finding(issue_type: str) -> str:
        if issue_type == "NO_TRAIL" or issue_type == "TRAIL_NOT_LOGGING":
            return Severity.HIGH
        elif issue_type == "NO_MULTI_REGION":
            return Severity.HIGH
        elif issue_type == "LOG_VALIDATION_DISABLED":
            return Severity.LOW
        elif issue_type == "MISSING_KMS_ENCRYPTION":
            return Severity.LOW
        return Severity.INFORMATIONAL

    @staticmethod
    def classify_storage_finding(resource_type: str, issue_type: str) -> str:
        if issue_type == "UNENCRYPTED_VOLUME":
            return Severity.MEDIUM
        elif issue_type == "UNENCRYPTED_RDS":
            return Severity.MEDIUM
        return Severity.LOW
