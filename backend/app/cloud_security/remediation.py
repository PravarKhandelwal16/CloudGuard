"""
Remediation playbooks and actionable step-by-step security recommendations
for CloudGuard Cloud Security Auditor findings.
"""

from typing import Dict, Any


REMEDIATION_CATALOG = {
    "S3_PUBLIC_BUCKET": {
        "title": "Remediate Publicly Accessible S3 Bucket",
        "risk_explanation": (
            "Publicly accessible S3 buckets allow unauthorized anonymous users on the internet to read, "
            "download, or potentially alter sensitive company data, leading to severe data breaches and regulatory non-compliance."
        ),
        "console_steps": [
            "1. Open the Amazon S3 console at https://console.aws.amazon.com/s3/.",
            "2. In the Buckets list, choose the name of the bucket flagged.",
            "3. Choose the 'Permissions' tab.",
            "4. Under 'Block public access (bucket settings)', click 'Edit'.",
            "5. Select 'Block all public access', then click 'Save changes'. Type 'confirm' in the field and click 'Confirm'.",
            "6. Under 'Bucket Policy', review and delete or restrict any statements that grant 'Principal: *' or Allow actions without Conditions.",
            "7. Under 'Access control list (ACL)', ensure no public read/write grants exist for 'Everyone (public access)'."
        ],
        "cli_command": (
            "aws s3api put-public-access-block --bucket {resource_id} "
            "--public-access-block-configuration "
            "\"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\""
        ),
        "best_practice": "Enable Account-level S3 Block Public Access to prevent any bucket in the AWS account from ever becoming public."
    },

    "S3_BLOCK_PUBLIC_ACCESS_DISABLED": {
        "title": "Enable S3 Block Public Access",
        "risk_explanation": (
            "When S3 Block Public Access is disabled, a misplaced bucket policy or ACL modification can immediately expose "
            "private objects to the public internet."
        ),
        "console_steps": [
            "1. Open the Amazon S3 console at https://console.aws.amazon.com/s3/.",
            "2. Select the bucket and open the 'Permissions' tab.",
            "3. Under 'Block public access (bucket settings)', click 'Edit'.",
            "4. Check 'Block all public access' and click 'Save changes'.",
            "5. Confirm the action in the prompt."
        ],
        "cli_command": (
            "aws s3api put-public-access-block --bucket {resource_id} "
            "--public-access-block-configuration "
            "\"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\""
        ),
        "best_practice": "Always enforce S3 Block Public Access across all buckets and AWS accounts."
    },

    "S3_MISSING_ENCRYPTION": {
        "title": "Enable S3 Server-Side Default Encryption",
        "risk_explanation": (
            "Unencrypted data at rest in S3 increases exposure if storage media is compromised and fails standard regulatory compliance "
            "(HIPAA, PCI-DSS, SOC 2, ISO 27001)."
        ),
        "console_steps": [
            "1. Open the Amazon S3 console at https://console.aws.amazon.com/s3/.",
            "2. Select the bucket and choose the 'Properties' tab.",
            "3. Scroll to 'Default encryption' and choose 'Edit'.",
            "4. Select 'Server-side encryption with Amazon S3 managed keys (SSE-S3)' or 'AWS Key Management Service keys (SSE-KMS)'.",
            "5. Choose 'Save changes'."
        ],
        "cli_command": (
            "aws s3api put-bucket-encryption --bucket {resource_id} "
            "--server-side-encryption-configuration '{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\": {\"SSEAlgorithm\": \"AES256\"}}]}'"
        ),
        "best_practice": "Use AWS KMS with customer managed keys (CMKs) and key rotation for sensitive data."
    },

    "IAM_ADMIN_WILDCARD": {
        "title": "Remove Wildcard Administrator Privileges",
        "risk_explanation": (
            "Granting Action: '*' on Resource: '*' gives unbounded administrative power. If credentials are leaked or compromised, "
            "an attacker gains total control over all AWS account resources, data, and IAM permissions."
        ),
        "console_steps": [
            "1. Open the IAM console at https://console.aws.amazon.com/iam/.",
            "2. In the navigation pane, choose 'Policies' (or 'Users' / 'Roles' if attached inline).",
            "3. Select the flagged policy and choose 'Edit policy'.",
            "4. Replace wildcard '*' actions with only the specific API actions required by the application.",
            "5. Replace wildcard '*' resources with specific resource ARNs.",
            "6. Review and save changes."
        ],
        "cli_command": (
            "# Review attached policies:\n"
            "aws iam list-attached-user-policies --user-name {resource_id}\n"
            "# Detach AdministratorAccess if attached directly:\n"
            "aws iam detach-user-policy --user-name {resource_id} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        ),
        "best_practice": "Apply the principle of least privilege. Use AWS IAM Access Analyzer to generate fine-grained policies based on actual access activity."
    },

    "IAM_SERVICE_WILDCARD": {
        "title": "Restrict Wildcard Service Permissions",
        "risk_explanation": (
            "Broad service wildcards (e.g. iam:* or s3:*) allow privilege escalation, unauthorized data exfiltration, or infrastructure destruction."
        ),
        "console_steps": [
            "1. Open the IAM console at https://console.aws.amazon.com/iam/.",
            "2. Select the policy or entity.",
            "3. Update permissions to specify explicit actions (e.g., s3:GetObject, s3:PutObject) rather than s3:*.",
            "4. Restrict resource ARNs to specific buckets or prefixes."
        ],
        "cli_command": (
            "# Inspect the policy document:\n"
            "aws iam get-policy-version --policy-arn {resource_id} --version-id v1"
        ),
        "best_practice": "Never use service-level wildcards like iam:* or s3:* without strict resource ARN constraints."
    },

    "SG_SSH_OPEN": {
        "title": "Restrict Inbound SSH Access (Port 22)",
        "risk_explanation": (
            "Exposing SSH (TCP port 22) to 0.0.0.0/0 invites continuous brute-force attacks, credential stuffing, and exploitation "
            "of potential OpenSSH vulnerabilities from anywhere in the world."
        ),
        "console_steps": [
            "1. Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/.",
            "2. In the navigation pane, choose 'Security Groups'.",
            "3. Select security group '{resource_id}'.",
            "4. Choose the 'Inbound rules' tab, then choose 'Edit inbound rules'.",
            "5. Find the rule allowing port 22 from 0.0.0.0/0 or ::/0.",
            "6. Either delete the rule or restrict the Source to your organization's specific static IP or corporate CIDR.",
            "7. Choose 'Save rules'."
        ],
        "cli_command": (
            "aws ec2 revoke-security-group-ingress --group-id {resource_id} "
            "--protocol tcp --port 22 --cidr 0.0.0.0/0"
        ),
        "best_practice": "Eliminate open SSH ports entirely by using AWS Systems Manager Session Manager for secure, audited, agent-based instance shell access without open inbound ports."
    },

    "SG_RDP_OPEN": {
        "title": "Restrict Inbound RDP Access (Port 3389)",
        "risk_explanation": (
            "Exposing Windows Remote Desktop (port 3389) directly to 0.0.0.0/0 invites ransomware attacks, automated brute-force attempts, "
            "and remote code execution vulnerabilities (such as BlueKeep)."
        ),
        "console_steps": [
            "1. Open the Amazon EC2 console at https://console.aws.amazon.com/ec2/.",
            "2. In the navigation pane, choose 'Security Groups' and select '{resource_id}'.",
            "3. Under 'Inbound rules', click 'Edit inbound rules'.",
            "4. Remove the rule permitting port 3389 from 0.0.0.0/0 or ::/0.",
            "5. Save rules."
        ],
        "cli_command": (
            "aws ec2 revoke-security-group-ingress --group-id {resource_id} "
            "--protocol tcp --port 3389 --cidr 0.0.0.0/0"
        ),
        "best_practice": "Connect to Windows instances via AWS Systems Manager Fleet Manager Remote Desktop or through a secured Client VPN."
    },

    "SG_ALL_PORTS_OPEN": {
        "title": "Remove Unrestricted Inbound Traffic Rule",
        "risk_explanation": (
            "Allowing all traffic (protocol -1 or ports 0-65535) from 0.0.0.0/0 completely bypasses network perimeter defense, "
            "exposing every service running on the attached instances directly to internet adversaries."
        ),
        "console_steps": [
            "1. In the Amazon EC2 console, select Security Groups.",
            "2. Select '{resource_id}' and choose 'Inbound rules' -> 'Edit inbound rules'.",
            "3. Delete the rule with Type 'All traffic' and Source '0.0.0.0/0' (and '::/0').",
            "4. Add only specific required ports (e.g. HTTPS port 443).",
            "5. Save rules."
        ],
        "cli_command": (
            "aws ec2 revoke-security-group-ingress --group-id {resource_id} "
            "--protocol -1 --cidr 0.0.0.0/0"
        ),
        "best_practice": "Never create 0.0.0.0/0 ingress rules without restricting the specific port and protocol."
    },

    "CLOUDTRAIL_NOT_LOGGING": {
        "title": "Start CloudTrail Logging",
        "risk_explanation": (
            "If CloudTrail logging is stopped, AWS API activity is not recorded. Incident response teams cannot detect unauthorized "
            "access, account compromises, or track forensic history."
        ),
        "console_steps": [
            "1. Open the CloudTrail console at https://console.aws.amazon.com/cloudtrail/.",
            "2. Choose 'Trails' and click '{resource_id}'.",
            "3. If logging is stopped, click 'Start logging'.",
            "4. Confirm that the status changes to 'Logging'."
        ],
        "cli_command": (
            "aws cloudtrail start-logging --name {resource_id}"
        ),
        "best_practice": "Configure AWS Config rules to automatically monitor and re-enable CloudTrail logging if it is ever stopped."
    },

    "CLOUDTRAIL_NO_MULTI_REGION": {
        "title": "Enable Multi-Region Logging in CloudTrail",
        "risk_explanation": (
            "Adversaries frequently operate in unused AWS regions to evade detection. Single-region trails fail to log malicious actions "
            "occurring outside the primary region."
        ),
        "console_steps": [
            "1. Open the CloudTrail console at https://console.aws.amazon.com/cloudtrail/.",
            "2. Select '{resource_id}' and choose 'Edit'.",
            "3. Under 'General details', ensure 'Multi-region trail' is set to 'Yes'.",
            "4. Save changes."
        ],
        "cli_command": (
            "aws cloudtrail update-trail --name {resource_id} --is-multi-region-trail"
        ),
        "best_practice": "Ensure at least one multi-region trail exists in every AWS account."
    },

    "CLOUDTRAIL_VALIDATION_DISABLED": {
        "title": "Enable CloudTrail Log File Integrity Validation",
        "risk_explanation": (
            "Log file validation creates cryptographically signed digest files. Without validation, an attacker who gains access to "
            "the log S3 bucket can modify or delete logs undetected."
        ),
        "console_steps": [
            "1. Open the CloudTrail console.",
            "2. Select '{resource_id}' and choose 'Edit'.",
            "3. Enable 'Log file validation'.",
            "4. Save changes."
        ],
        "cli_command": (
            "aws cloudtrail update-trail --name {resource_id} --enable-log-file-validation"
        ),
        "best_practice": "Enable log validation and store log files in an S3 bucket with Object Lock or MFA Delete."
    },

    "EBS_UNENCRYPTED": {
        "title": "Encrypt EBS Volumes at Rest",
        "risk_explanation": (
            "Unencrypted EBS volumes leave file systems, application data, and caches exposed if physical storage or snapshots are improperly shared."
        ),
        "console_steps": [
            "1. In the EC2 console, go to 'Settings' (under Account Attributes) and enable 'Always encrypt new EBS volumes'.",
            "2. For existing volume '{resource_id}':",
            "   a. Stop the attached EC2 instance.",
            "   b. Create a snapshot of the volume.",
            "   c. Copy the snapshot, selecting the 'Encrypt this snapshot' checkbox.",
            "   d. Create a new encrypted EBS volume from the copied snapshot.",
            "   e. Attach the new encrypted volume to the instance and restart."
        ],
        "cli_command": (
            "# Enable EBS encryption by default for the region:\n"
            "aws ec2 enable-ebs-encryption-by-default --region {region}"
        ),
        "best_practice": "Enable EBS encryption by default account-wide in every region."
    },

    "RDS_UNENCRYPTED": {
        "title": "Enable RDS Storage Encryption",
        "risk_explanation": (
            "Unencrypted database storage leaves relational databases and their automated backups vulnerable to data exposure."
        ),
        "console_steps": [
            "1. Open the Amazon RDS console at https://console.aws.amazon.com/rds/.",
            "2. Take a manual snapshot of DB instance '{resource_id}'.",
            "3. Select the snapshot and choose 'Copy Snapshot'.",
            "4. In the Copy Snapshot settings, enable 'Encryption' and choose an AWS KMS key.",
            "5. Restore a new DB instance from the encrypted snapshot.",
            "6. Point your application to the new encrypted DB endpoint."
        ],
        "cli_command": (
            "aws rds copy-db-snapshot --source-db-snapshot-identifier {resource_id}-snap "
            "--target-db-snapshot-identifier {resource_id}-encrypted-snap "
            "--kms-key-id default"
        ),
        "best_practice": "Always specify StorageEncrypted=true when provisioning new RDS databases."
    }
}


def _safe_substitute(text: str, resource_id: str, region: str) -> str:
    """Safely replace template placeholders without conflicting with JSON braces."""
    return text.replace("{resource_id}", resource_id).replace("{region}", region)


def get_remediation_info(check_key: str, resource_id: str = "", region: str = "ap-south-1") -> Dict[str, Any]:
    """Retrieve formatted remediation details with resource context."""
    template = REMEDIATION_CATALOG.get(check_key)
    if not template:
        return {
            "title": "Remediate Security Issue",
            "risk_explanation": "Security misconfiguration detected. Follow AWS security best practices to resolve.",
            "console_steps": ["Review AWS documentation and restrict access in the AWS Management Console."],
            "cli_command": f"# Review resource configuration\naws resource-explorer2 get-resource --arn {resource_id}",
            "best_practice": "Apply least-privilege security controls and enforce encryption.",
            "summary": "Follow the principle of least privilege and enforce secure defaults."
        }

    return {
        "title": template["title"],
        "risk_explanation": template["risk_explanation"],
        "console_steps": [_safe_substitute(step, resource_id, region) for step in template["console_steps"]],
        "cli_command": _safe_substitute(template["cli_command"], resource_id, region),
        "best_practice": template["best_practice"],
        "summary": template["console_steps"][0] if template["console_steps"] else template["best_practice"]
    }
