"""
STS Manager for CloudGuard Cloud Security Auditor.

Validates IAM role cross-account trust relationships and tests connectivity
without exposing sensitive temporary credentials.
"""

import logging
from typing import Dict, Any, Optional
from .aws_connector import (
    AWSConnector,
    validate_account_id,
    validate_role_arn,
    AWSAuthenticationError,
    AWSValidationError
)

logger = logging.getLogger(__name__)


class STSManager:
    """Manages role assumption verification and AWS connection testing."""

    @staticmethod
    def test_connection(
        account_id: str,
        role_arn: str,
        region: str = "ap-south-1",
        external_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Tests whether CloudGuard can assume the specified IAM role.
        Calls STS AssumeRole and GetCallerIdentity, verifying read access.
        """
        validate_account_id(account_id)
        validate_role_arn(role_arn, account_id)

        connector = AWSConnector(
            role_arn=role_arn,
            account_id=account_id,
            region=region,
            external_id=external_id,
            session_duration_seconds=900
        )

        try:
            assume_result = connector.assume_role()
            session = connector.get_session()
            sts_client = session.client("sts")
            caller_identity = sts_client.get_caller_identity()

            return {
                "success": True,
                "account_id": caller_identity.get("Account"),
                "arn": caller_identity.get("Arn"),
                "user_id": caller_identity.get("UserId"),
                "region": region,
                "expiration": assume_result.get("expiration"),
                "message": "Successfully assumed IAM role and validated AWS STS connectivity."
            }
        except AWSAuthenticationError as e:
            return {
                "success": False,
                "error": str(e),
                "message": f"Connection test failed: {str(e)}"
            }
        except Exception as e:
            logger.error("Unexpected error testing STS connection: %s", str(e), exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "message": f"Unexpected error testing AWS connection: {str(e)}"
            }
