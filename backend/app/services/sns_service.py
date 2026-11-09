import os
import logging
from flask import current_app

logger = logging.getLogger(__name__)


class SNSService:
    """Optional notification service to send alerts when Critical findings are detected."""

    def __init__(self):
        self.enabled = current_app.config.get("ENABLE_SNS", False)
        self.topic_arn = current_app.config.get("SNS_TOPIC_ARN", "")
        self.region = current_app.config.get("AWS_REGION", "ap-south-1")

    def notify_critical_findings(self, scan_id: str, project_name: str, critical_count: int, score: int):
        if not self.enabled or not self.topic_arn:
            logger.debug("SNS notifications disabled or SNS_TOPIC_ARN not set.")
            return

        import boto3
        from botocore.exceptions import ClientError

        subject = f"[CloudGuard Alert] Critical Secrets Detected in {project_name}"
        # Security: Never include secret values or source content in notifications!
        message = (
            f"CloudGuard Security Alert\n\n"
            f"Project: {project_name}\n"
            f"Scan ID: {scan_id}\n"
            f"Security Score: {score}/100\n"
            f"Critical Findings: {critical_count}\n\n"
            f"Action Required: Log in to your CloudGuard dashboard to review masked findings "
            f"and follow the recommended remediation steps immediately.\n"
        )

        try:
            sns_client = boto3.client("sns", region_name=self.region)
            sns_client.publish(
                TopicArn=self.topic_arn,
                Subject=subject[:100],
                Message=message
            )
            logger.info("Published critical alert for scan %s to SNS topic %s", scan_id, self.topic_arn)
        except ClientError as e:
            logger.error("Failed to publish SNS notification: %s", str(e))
        except Exception as e:
            logger.error("Unexpected error publishing to SNS: %s", str(e))

