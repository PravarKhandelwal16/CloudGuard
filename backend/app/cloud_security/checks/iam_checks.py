"""
IAM Security Checks for CloudGuard Cloud Security Auditor.

Evaluates:
- Policies containing Action: "*" and Resource: "*" (Full Admin Privileges)
- Overly permissive administrative policies attached directly to users
- Roles with broad wildcard permissions (e.g., iam:*, s3:*)
- Managed and inline policy inspection
"""

import uuid
import logging
from typing import Dict, Any, List, Tuple, Optional
from botocore.exceptions import ClientError
from ..severity_engine import Severity, CheckStatus
from ..remediation import get_remediation_info

logger = logging.getLogger(__name__)


def _inspect_policy_statement(
    statement: Dict[str, Any],
    entity_name: str,
    entity_type: str,
    policy_name: str,
    default_region: str = "ap-south-1"
) -> List[Dict[str, Any]]:
    findings = []
    effect = statement.get("Effect", "")
    if effect != "Allow":
        return findings

    action = statement.get("Action", [])
    if isinstance(action, str):
        actions = [action]
    elif isinstance(action, list):
        actions = action
    else:
        actions = []

    resource = statement.get("Resource", [])
    if isinstance(resource, str):
        resources = [resource]
    elif isinstance(resource, list):
        resources = resource
    else:
        resources = []

    has_star_action = "*" in actions
    has_star_resource = "*" in resources

    # 1. Full Administrator Wildcard: Action: "*", Resource: "*"
    if has_star_action and has_star_resource:
        rem = get_remediation_info("IAM_ADMIN_WILDCARD", entity_name, default_region)
        findings.append({
            "finding_id": f"iam-full-admin-{entity_type}-{entity_name}-{policy_name}".replace(" ", "_"),
            "service": "IAM",
            "resource_id": f"arn:aws:iam::{entity_type}/{entity_name}",
            "title": f"IAM Policy with Full Administrative Privileges (Action: *, Resource: *)",
            "description": (
                f"The {entity_type} '{entity_name}' has policy '{policy_name}' granting unrestricted "
                f"access (Action: *, Resource: *) across all AWS services."
            ),
            "severity": Severity.HIGH,
            "status": CheckStatus.FAILED,
            "evidence": f"Policy Statement: Effect=Allow, Action=['*'], Resource=['*'] in policy '{policy_name}'.",
            "remediation": rem["summary"],
            "remediation_details": rem,
            "region": default_region
        })
        return findings

    # 2. Sensitive Wildcard Permissions on Resource: "*"
    sensitive_wildcard_prefixes = ["iam:*", "kms:*", "sts:*"]
    for act in actions:
        if act in sensitive_wildcard_prefixes and has_star_resource:
            rem = get_remediation_info("IAM_SERVICE_WILDCARD", entity_name, default_region)
            findings.append({
                "finding_id": f"iam-sensitive-wildcard-{entity_name}-{act}".replace(":", "_").replace("*", "all"),
                "service": "IAM",
                "resource_id": f"arn:aws:iam::{entity_type}/{entity_name}",
                "title": f"Overly Permissive Service Wildcard '{act}' on All Resources",
                "description": (
                    f"The {entity_type} '{entity_name}' policy '{policy_name}' permits wildcard action '{act}' "
                    f"on Resource: '*', allowing potential privilege escalation or data tampering."
                ),
                "severity": Severity.HIGH if act == "iam:*" else Severity.MEDIUM,
                "status": CheckStatus.FAILED,
                "evidence": f"Action '{act}' permitted on Resource: '*'.",
                "remediation": rem["summary"],
                "remediation_details": rem,
                "region": default_region
            })

    # 3. Broad Service Wildcard (e.g. s3:*, ec2:*) on Resource: "*"
    broad_wildcard_prefixes = ["s3:*", "ec2:*", "dynamodb:*", "rds:*"]
    for act in actions:
        if act in broad_wildcard_prefixes and has_star_resource:
            rem = get_remediation_info("IAM_SERVICE_WILDCARD", entity_name, default_region)
            findings.append({
                "finding_id": f"iam-broad-wildcard-{entity_name}-{act}".replace(":", "_").replace("*", "all"),
                "service": "IAM",
                "resource_id": f"arn:aws:iam::{entity_type}/{entity_name}",
                "title": f"Broad Service Wildcard '{act}' Granted on All Resources",
                "description": (
                    f"The {entity_type} '{entity_name}' policy '{policy_name}' grants '{act}' across all resources."
                ),
                "severity": Severity.MEDIUM,
                "status": CheckStatus.FAILED,
                "evidence": f"Action '{act}' granted on Resource: '*'.",
                "remediation": rem["summary"],
                "remediation_details": rem,
                "region": default_region
            })

    return findings


def run_iam_checks(iam_client, default_region: str = "ap-south-1") -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """
    Executes IAM security checks across users, roles, managed and inline policies.
    """
    findings = []
    permission_denied_services = []
    total_entities = 0
    passed_entities = 0
    failed_entities = 0
    warned_entities = 0
    not_assessed_entities = 0

    # 1. Inspect IAM Users
    users = []
    try:
        users_resp = iam_client.list_users()
        users = users_resp.get("Users", [])
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code in ("AccessDenied", "UnauthorizedOperation"):
            permission_denied_services.append("IAM (ListUsers)")
            findings.append({
                "finding_id": f"iam-users-denied-{uuid.uuid4().hex[:8]}",
                "service": "IAM",
                "resource_id": "arn:aws:iam::user/*",
                "title": "IAM User Assessment Incomplete: Missing iam:ListUsers Permission",
                "description": "CloudGuard could not enumerate IAM users due to IAM permission denial.",
                "severity": Severity.INFORMATIONAL,
                "status": CheckStatus.NOT_ASSESSED,
                "evidence": f"AWS API returned {error_code}.",
                "remediation": "Add iam:ListUsers and iam:GetPolicy permissions to the CloudGuard audit role.",
                "region": default_region
            })
            not_assessed_entities += 1

    for u in users:
        total_entities += 1
        username = u["UserName"]
        user_findings = []

        # Check attached managed policies
        try:
            att = iam_client.list_attached_user_policies(UserName=username)
            for pol in att.get("AttachedPolicies", []):
                pol_name = pol.get("PolicyName", "")
                pol_arn = pol.get("PolicyArn", "")
                # Flag direct AdministratorAccess on IAM user
                if "AdministratorAccess" in pol_name:
                    rem = get_remediation_info("IAM_ADMIN_WILDCARD", username, default_region)
                    user_findings.append({
                        "finding_id": f"iam-user-admin-attached-{username}",
                        "service": "IAM",
                        "resource_id": f"arn:aws:iam::user/{username}",
                        "title": f"Direct AdministratorAccess Attached to IAM User '{username}'",
                        "description": (
                            f"IAM user '{username}' has AWS-managed policy 'AdministratorAccess' directly attached. "
                            f"Users should assume scoped roles via IAM Identity Center rather than holding direct full admin."
                        ),
                        "severity": Severity.HIGH,
                        "status": CheckStatus.FAILED,
                        "evidence": f"AttachedPolicyArn: {pol_arn}",
                        "remediation": rem["summary"],
                        "remediation_details": rem,
                        "region": default_region
                    })
        except ClientError:
            pass

        # Check inline policies
        try:
            inline = iam_client.list_user_policies(UserName=username)
            for pol_name in inline.get("PolicyNames", []):
                doc_resp = iam_client.get_user_policy(UserName=username, PolicyName=pol_name)
                doc = doc_resp.get("PolicyDocument", {})
                stmts = doc.get("Statement", [])
                if isinstance(stmts, dict):
                    stmts = [stmts]
                for stmt in stmts:
                    user_findings.extend(
                        _inspect_policy_statement(stmt, username, "user", pol_name, default_region)
                    )
        except ClientError:
            pass

        if user_findings:
            failed_entities += 1
            findings.extend(user_findings)
        else:
            passed_entities += 1
            findings.append({
                "finding_id": f"iam-user-compliant-{username}",
                "service": "IAM",
                "resource_id": f"arn:aws:iam::user/{username}",
                "title": f"IAM User Least Privilege Baseline Met",
                "description": f"User '{username}' does not hold direct full administrative wildcard privileges.",
                "severity": Severity.INFORMATIONAL,
                "status": CheckStatus.PASSED,
                "evidence": "No direct AdministratorAccess or wildcard statements detected.",
                "remediation": "Continue regular access reviews and enforce MFA.",
                "region": default_region
            })

    # 2. Inspect IAM Roles
    roles = []
    try:
        roles_resp = iam_client.list_roles()
        # Filter out AWS service-linked roles
        roles = [
            r for r in roles_resp.get("Roles", [])
            if not r.get("Path", "").startswith("/aws-service-role/")
        ]
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code in ("AccessDenied", "UnauthorizedOperation"):
            permission_denied_services.append("IAM (ListRoles)")

    for r in roles:
        total_entities += 1
        role_name = r["RoleName"]
        role_findings = []

        # Check inline policies
        try:
            inline = iam_client.list_role_policies(RoleName=role_name)
            for pol_name in inline.get("PolicyNames", []):
                doc_resp = iam_client.get_role_policy(RoleName=role_name, PolicyName=pol_name)
                doc = doc_resp.get("PolicyDocument", {})
                stmts = doc.get("Statement", [])
                if isinstance(stmts, dict):
                    stmts = [stmts]
                for stmt in stmts:
                    role_findings.extend(
                        _inspect_policy_statement(stmt, role_name, "role", pol_name, default_region)
                    )
        except ClientError:
            pass

        if role_findings:
            failed_entities += 1
            findings.extend(role_findings)
        else:
            passed_entities += 1
            findings.append({
                "finding_id": f"iam-role-compliant-{role_name}",
                "service": "IAM",
                "resource_id": f"arn:aws:iam::role/{role_name}",
                "title": f"IAM Role Least Privilege Baseline Met",
                "description": f"Role '{role_name}' does not contain unconstrained wildcard permissions.",
                "severity": Severity.INFORMATIONAL,
                "status": CheckStatus.PASSED,
                "evidence": "Inline and attached policies conform to least-privilege checks.",
                "remediation": "Regularly audit role trust policies and condition keys.",
                "region": default_region
            })

    summary = {
        "service": "IAM",
        "resource_type": "IAM Entity (Users & Roles)",
        "total": total_entities,
        "passed": passed_entities,
        "failed": failed_entities,
        "warned": warned_entities,
        "not_assessed": not_assessed_entities
    }
    return findings, summary, permission_denied_services
