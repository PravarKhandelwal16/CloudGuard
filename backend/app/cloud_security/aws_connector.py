"""
AWS Connector module for CloudGuard Cloud Security Auditor.

Handles secure communication with AWS services using Boto3, least-privilege
read-only client sessions, robust error translation, and strict credential hygiene.
"""

import re
import logging
from typing import Optional, Dict, Any
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError, BotoCoreError, CredentialRetrievalError

logger = logging.getLogger(__name__)

# Strict validation patterns
AWS_ACCOUNT_ID_REGEX = re.compile(r"^\d{12}$")
IAM_ROLE_ARN_REGEX = re.compile(r"^arn:aws[a-zA-Z-]*:iam::\d{12}:role/[\w+=,.@\-_/]+$")


class AWSCloudSecurityException(Exception):
    """Base exception for CloudGuard cloud security audit operations."""
    pass


class AWSAuthenticationError(AWSCloudSecurityException):
    """Raised when STS AssumeRole fails or credentials are invalid/expired."""
    pass


class AWSPermissionError(AWSCloudSecurityException):
    """Raised when an AWS API call fails with AccessDenied."""
    pass


class AWSValidationError(AWSCloudSecurityException):
    """Raised when user input for account connection fails validation."""
    pass


def validate_account_id(account_id: str) -> str:
    """Validate 12-digit AWS Account ID."""
    if not account_id or not AWS_ACCOUNT_ID_REGEX.match(account_id.strip()):
        raise AWSValidationError("Invalid AWS Account ID. Account ID must be exactly 12 numeric digits.")
    return account_id.strip()


def validate_role_arn(role_arn: str, expected_account_id: Optional[str] = None) -> str:
    """Validate IAM Role ARN format and optional matching account ID."""
    if not role_arn or not IAM_ROLE_ARN_REGEX.match(role_arn.strip()):
        raise AWSValidationError(
            "Invalid IAM Role ARN format. Expected format: arn:aws:iam::<12-digit-account-id>:role/<role-name>"
        )
    clean_arn = role_arn.strip()
    if expected_account_id:
        arn_account_match = re.search(r":iam::(\d{12}):role/", clean_arn)
        if arn_account_match and arn_account_match.group(1) != expected_account_id:
            raise AWSValidationError(
                f"Role ARN account ID ({arn_account_match.group(1)}) does not match provided account ID ({expected_account_id})."
            )
    return clean_arn


class AWSConnector:
    """
    Manages STS AssumeRole and creation of read-only Boto3 clients.
    Temporary credentials are held strictly in-memory and never logged or exposed.
    """

    def __init__(
        self,
        role_arn: str,
        account_id: str,
        region: str = "ap-south-1",
        external_id: Optional[str] = None,
        session_duration_seconds: int = 900
    ):
        self.account_id = validate_account_id(account_id)
        self.role_arn = validate_role_arn(role_arn, self.account_id)
        self.region = region.strip() if region else "ap-south-1"
        self.external_id = external_id.strip() if external_id else None
        self.session_duration_seconds = max(900, min(session_duration_seconds, 3600))

        # Standard client config with retries and timeout
        self.boto_config = BotoConfig(
            region_name=self.region,
            retries={"max_attempts": 3, "mode": "standard"},
            connect_timeout=5,
            read_timeout=10
        )
        self._temp_credentials = None
        self._session = None

    def assume_role(self) -> Dict[str, Any]:
        """
        Assumes the specified IAM role using AWS STS to obtain temporary credentials.
        Never logs sensitive credentials.
        """
        try:
            sts_client = boto3.client("sts", config=self.boto_config)
            assume_params = {
                "RoleArn": self.role_arn,
                "RoleSessionName": "CloudGuardSecurityAuditorSession",
                "DurationSeconds": self.session_duration_seconds,
            }
            if self.external_id:
                assume_params["ExternalId"] = self.external_id

            logger.info("Requesting temporary credentials via STS AssumeRole for account: %s", self.account_id)
            response = sts_client.assume_role(**assume_params)

            credentials = response.get("Credentials", {})
            if not credentials or "AccessKeyId" not in credentials:
                raise AWSAuthenticationError("STS AssumeRole succeeded but did not return temporary credentials.")

            self._temp_credentials = credentials
            self._session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=self.region
            )

            # Return non-sensitive metadata only
            return {
                "assumed_role_id": response.get("AssumedRoleUser", {}).get("AssumedRoleId"),
                "arn": response.get("AssumedRoleUser", {}).get("Arn"),
                "expiration": credentials.get("Expiration").isoformat() if credentials.get("Expiration") else None,
                "region": self.region,
                "account_id": self.account_id,
            }

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            logger.error("STS AssumeRole failed with error code %s: %s", error_code, error_msg)

            if error_code in ("AccessDenied", "InvalidClientTokenId", "ExpiredToken"):
                raise AWSAuthenticationError(
                    f"AWS STS authentication failed ({error_code}): {error_msg}. "
                    f"Please verify IAM role trust policy and external ID."
                ) from e
            raise AWSAuthenticationError(f"AWS STS error ({error_code}): {error_msg}") from e

        except (BotoCoreError, CredentialRetrievalError) as e:
            logger.error("BotoCore error during AssumeRole: %s", str(e))
            raise AWSAuthenticationError(f"Could not connect to AWS STS service: {str(e)}") from e

    def get_session(self) -> boto3.Session:
        """Returns the authenticated temporary Boto3 Session."""
        if not self._session:
            self.assume_role()
        return self._session

    def get_client(self, service_name: str, region: Optional[str] = None):
        """Returns a configured Boto3 client for the requested service."""
        session = self.get_session()
        target_region = region or self.region
        return session.client(service_name, region_name=target_region, config=self.boto_config)
