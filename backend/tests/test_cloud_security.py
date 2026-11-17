"""
Automated test suite for CloudGuard Cloud Security Auditor.

Covers:
- S3 public access & Block Public Access detection
- S3 encryption detection
- IAM wildcard action & resource detection
- Security Group SSH, RDP, and unrestricted port exposure detection
- CloudTrail logging and validation detection
- Storage (EBS & RDS) encryption detection
- Severity classification logic
- Security score calculation and deductions
- Incomplete assessment and permission denial handling
- Expired STS credentials and authentication failures
- Simulation mode execution without AWS credentials
- REST API authentication, authorization, and workflows
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from backend.app import create_app
from backend.app.config import TestConfig
from backend.app.extensions import db
from backend.app.cloud_security import (
    CloudSecurityAuditor,
    SecurityScorer,
    Severity,
    CheckStatus,
    SeverityEngine,
    AWSConnector,
    STSManager,
    AWSAuthenticationError,
    AWSValidationError
)
from backend.app.cloud_security.checks.s3_checks import run_s3_checks
from backend.app.cloud_security.checks.iam_checks import run_iam_checks
from backend.app.cloud_security.checks.security_group_checks import run_security_group_checks
from backend.app.cloud_security.checks.cloudtrail_checks import run_cloudtrail_checks
from backend.app.cloud_security.checks.encryption_checks import run_encryption_checks


@pytest.fixture
def client():
    app = create_app(TestConfig)
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()


def register_user(client, email="auditor@test.com"):
    res = client.post("/api/auth/register", json={
        "name": "Cloud Auditor",
        "email": email,
        "password": "Password123!"
    })
    return res.get_json()["data"]["token"]


# =====================================================================
# 1. Unit Tests: Security Checks
# =====================================================================

def test_s3_public_access_and_encryption_detection():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {
        "Buckets": [{"Name": "public-unencrypted-bucket"}, {"Name": "secure-bucket"}]
    }

    def get_public_block(Bucket):
        if Bucket == "public-unencrypted-bucket":
            return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}}
        return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}

    def get_policy_status(Bucket):
        if Bucket == "public-unencrypted-bucket":
            return {"PolicyStatus": {"IsPublic": True}}
        raise ClientError({"Error": {"Code": "NoSuchBucketPolicy", "Message": "None"}}, "GetBucketPolicyStatus")

    def get_encryption(Bucket):
        if Bucket == "public-unencrypted-bucket":
            raise ClientError({"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "None"}}, "GetBucketEncryption")
        return {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}

    mock_s3.get_public_access_block.side_effect = get_public_block
    mock_s3.get_bucket_policy_status.side_effect = get_policy_status
    mock_s3.get_bucket_acl.return_value = {"Grants": []}
    mock_s3.get_bucket_encryption.side_effect = get_encryption

    findings, summary, denied = run_s3_checks(mock_s3, default_region="ap-south-1")

    assert summary["total"] == 2
    assert summary["failed"] == 1
    assert summary["passed"] == 1
    assert len(denied) == 0

    public_finding = next((f for f in findings if f["finding_id"].startswith("s3-public-access")), None)
    assert public_finding is not None
    assert public_finding["severity"] == Severity.CRITICAL
    assert public_finding["status"] == CheckStatus.FAILED

    enc_finding = next((f for f in findings if f["finding_id"].startswith("s3-encryption-missing")), None)
    assert enc_finding is not None
    assert enc_finding["severity"] == Severity.MEDIUM


def test_iam_wildcard_detection():
    mock_iam = MagicMock()
    mock_iam.list_users.return_value = {
        "Users": [{"UserName": "admin-user", "UserId": "A1", "Arn": "arn:aws:iam::123456789012:user/admin-user"}]
    }
    mock_iam.list_roles.return_value = {
        "Roles": [{"RoleName": "deployer-role", "Path": "/"}]
    }
    mock_iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
    }
    mock_iam.list_user_policies.return_value = {"PolicyNames": []}
    mock_iam.list_role_policies.return_value = {"PolicyNames": ["DeployInline"]}
    mock_iam.get_role_policy.return_value = {
        "PolicyDocument": {
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }
    }

    findings, summary, denied = run_iam_checks(mock_iam, default_region="ap-south-1")

    assert summary["failed"] >= 1
    admin_attached = next((f for f in findings if "admin-attached" in f["finding_id"]), None)
    assert admin_attached is not None
    assert admin_attached["severity"] == Severity.HIGH

    role_wildcard = next((f for f in findings if "iam-full-admin" in f["finding_id"]), None)
    assert role_wildcard is not None
    assert role_wildcard["severity"] == Severity.HIGH


def test_security_group_ssh_and_rdp_exposure():
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-open-ssh-rdp",
                "GroupName": "bad-sg",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ]
            },
            {
                "GroupId": "sg-secure",
                "GroupName": "good-sg",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}
                ]
            }
        ]
    }

    findings, summary, denied = run_security_group_checks(mock_ec2, default_region="ap-south-1")

    assert summary["total"] == 2
    assert summary["failed"] == 1
    assert summary["passed"] == 1

    ssh_finding = next((f for f in findings if "sg-ssh-open" in f["finding_id"]), None)
    assert ssh_finding is not None
    assert ssh_finding["severity"] == Severity.HIGH

    rdp_finding = next((f for f in findings if "sg-rdp-open" in f["finding_id"]), None)
    assert rdp_finding is not None
    assert rdp_finding["severity"] == Severity.HIGH

    all_open = next((f for f in findings if "sg-all-ports-open" in f["finding_id"]), None)
    assert all_open is not None
    assert all_open["severity"] == Severity.CRITICAL


def test_cloudtrail_logging_detection():
    mock_ct = MagicMock()
    mock_ct.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "test-trail",
                "TrailARN": "arn:aws:cloudtrail:ap-south-1:123456789012:trail/test-trail",
                "IsMultiRegionTrail": False,
                "LogFileValidationEnabled": False
            }
        ]
    }
    mock_ct.get_trail_status.return_value = {"IsLogging": False}

    findings, summary, denied = run_cloudtrail_checks(mock_ct, default_region="ap-south-1")

    assert summary["failed"] >= 1
    no_multi = next((f for f in findings if "no-multi-region" in f["finding_id"]), None)
    assert no_multi is not None
    assert no_multi["severity"] == Severity.HIGH

    not_logging = next((f for f in findings if "not-logging" in f["finding_id"]), None)
    assert not_logging is not None
    assert not_logging["severity"] == Severity.HIGH

    val_disabled = next((f for f in findings if "log-val-disabled" in f["finding_id"]), None)
    assert val_disabled is not None


def test_ebs_and_rds_encryption_detection():
    mock_ec2 = MagicMock()
    mock_rds = MagicMock()

    mock_ec2.describe_volumes.return_value = {
        "Volumes": [
            {"VolumeId": "vol-unenc", "Encrypted": False, "Size": 100},
            {"VolumeId": "vol-enc", "Encrypted": True, "Size": 50}
        ]
    }
    mock_rds.describe_db_instances.return_value = {
        "DBInstances": [
            {"DBInstanceIdentifier": "rds-unenc", "StorageEncrypted": False, "Engine": "mysql"},
            {"DBInstanceIdentifier": "rds-enc", "StorageEncrypted": True, "Engine": "postgres"}
        ]
    }

    findings, summary, denied = run_encryption_checks(mock_ec2, mock_rds, default_region="ap-south-1")

    assert summary["total"] == 4
    assert summary["failed"] == 2
    assert summary["passed"] == 2

    ebs_finding = next((f for f in findings if "ebs-unencrypted-vol-unenc" in f["finding_id"]), None)
    assert ebs_finding is not None
    assert ebs_finding["severity"] == Severity.MEDIUM

    rds_finding = next((f for f in findings if "rds-unencrypted-rds-unenc" in f["finding_id"]), None)
    assert rds_finding is not None
    assert rds_finding["severity"] == Severity.MEDIUM


# =====================================================================
# 2. Scoring, Coverage & Incomplete Assessment Tests
# =====================================================================

def test_score_calculation_deductions():
    findings = [
        {"severity": Severity.CRITICAL, "status": CheckStatus.FAILED}, # -30
        {"severity": Severity.HIGH, "status": CheckStatus.FAILED},     # -15
        {"severity": Severity.MEDIUM, "status": CheckStatus.FAILED},   # -7
        {"severity": Severity.LOW, "status": CheckStatus.FAILED},      # -2
        {"severity": Severity.INFORMATIONAL, "status": CheckStatus.PASSED} # 0
    ]

    result = SecurityScorer.calculate_score(findings, total_resources_assessed=5)
    # 100 - (30 + 15 + 7 + 2) = 46
    assert result["score"] == 46
    assert result["is_complete"] is True
    assert result["coverage_status"] == "complete"
    assert result["critical_count"] == 1
    assert result["high_count"] == 1
    assert result["medium_count"] == 1
    assert result["low_count"] == 1


def test_score_never_below_zero():
    findings = [
        {"severity": Severity.CRITICAL, "status": CheckStatus.FAILED} for _ in range(5)
    ]
    result = SecurityScorer.calculate_score(findings, total_resources_assessed=5)
    assert result["score"] == 0


def test_incomplete_assessment_on_permission_denial():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
        "ListBuckets"
    )

    findings, summary, denied = run_s3_checks(mock_s3, default_region="ap-south-1")
    assert "S3 (ListBuckets)" in denied
    assert summary["not_assessed"] == 1

    score_result = SecurityScorer.calculate_score(
        findings=findings,
        total_resources_assessed=0,
        permission_denied_services=denied
    )
    assert score_result["is_complete"] is False
    assert score_result["coverage_status"] == "incomplete"
    assert "AccessDenied" in findings[0]["evidence"] or "AccessDenied" in findings[0]["finding_id"]


# =====================================================================
# 3. AWS Connector, STS & Credential Tests
# =====================================================================

def test_aws_connector_validation():
    # Valid account and role
    conn = AWSConnector(
        role_arn="arn:aws:iam::123456789012:role/AuditRole",
        account_id="123456789012"
    )
    assert conn.account_id == "123456789012"

    # Mismatched account ID
    with pytest.raises(AWSValidationError):
        AWSConnector(
            role_arn="arn:aws:iam::999999999999:role/AuditRole",
            account_id="123456789012"
        )

    # Invalid account ID format
    with pytest.raises(AWSValidationError):
        AWSConnector(
            role_arn="arn:aws:iam::123456789012:role/AuditRole",
            account_id="not-a-number"
        )


def test_sts_expired_or_invalid_credentials_handling():
    with patch("boto3.client") as mock_boto:
        mock_sts = MagicMock()
        mock_sts.assume_role.side_effect = ClientError(
            {"Error": {"Code": "ExpiredToken", "Message": "The security token included in the request is expired"}},
            "AssumeRole"
        )
        mock_boto.return_value = mock_sts

        res = STSManager.test_connection(
            account_id="123456789012",
            role_arn="arn:aws:iam::123456789012:role/AuditRole"
        )
        assert res["success"] is False
        assert "expired" in res["error"].lower()


# =====================================================================
# 4. Simulation Mode Tests
# =====================================================================

def test_simulation_mode_executes_same_rules():
    auditor = CloudSecurityAuditor(
        account_id="123456789012",
        role_arn="arn:aws:iam::123456789012:role/CloudGuardAuditorRole",
        is_simulation=True
    )
    result = auditor.run_audit()

    assert result["is_simulation"] is True
    assert result["simulation_label"] == "DEMO / SIMULATED DATA — NOT LIVE AWS FINDINGS"
    assert result["total_resources_assessed"] > 0
    assert len(result["findings"]) > 0
    assert result["checks_passed"] > 0
    assert result["checks_failed"] > 0
    assert result["coverage_status"] == "complete"

    # Verify findings contain expected scenarios
    titles = [f["title"] for f in result["findings"]]
    assert any("Publicly Accessible S3 Bucket" in t for t in titles)
    assert any("SSH" in t for t in titles)
    assert any("RDP" in t for t in titles)
    assert any("Administrative Privileges" in t or "Administrator" in t for t in titles)
    assert any("Unencrypted EBS Volume" in t for t in titles)


def test_hardened_and_compliant_simulation_scenarios():
    from pathlib import Path
    fixtures_dir = Path(__file__).resolve().parent.parent / "app" / "cloud_security" / "fixtures"

    # 1. Hardened scenario: score ~91
    hardened_auditor = CloudSecurityAuditor(
        account_id="987654321098",
        role_arn="arn:aws:iam::987654321098:role/CloudGuardAuditorRole",
        is_simulation=True,
        simulation_fixture_path=str(fixtures_dir / "hardened_aws_data.json")
    )
    hardened_res = hardened_auditor.run_audit()
    assert hardened_res["security_score"] == 91
    assert hardened_res["critical_count"] == 0
    assert hardened_res["high_count"] == 0
    assert hardened_res["checks_passed"] > 10

    # 2. Compliant scenario: score 100
    compliant_auditor = CloudSecurityAuditor(
        account_id="112233445566",
        role_arn="arn:aws:iam::112233445566:role/CloudGuardAuditorRole",
        is_simulation=True,
        simulation_fixture_path=str(fixtures_dir / "compliant_aws_data.json")
    )
    compliant_res = compliant_auditor.run_audit()
    assert compliant_res["security_score"] == 100
    assert compliant_res["critical_count"] == 0
    assert compliant_res["checks_failed"] == 0


# =====================================================================
# 5. REST API Integration & Security Tests
# =====================================================================

def test_api_cloud_security_workflow(client):
    token = register_user(client, "user1@example.com")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Test connect account
    res = client.post("/api/cloud-security/connect", json={
        "account_id": "123456789012",
        "role_arn": "arn:aws:iam::123456789012:role/CloudGuardAuditorRole",
        "region": "ap-south-1",
        "alias": "Production AWS"
    }, headers=headers)
    assert res.status_code == 200
    conn_data = res.get_json()["data"]
    assert conn_data["account_id"] == "123456789012"
    conn_id = conn_data["id"]

    # 2. Test demo scan
    demo_res = client.post("/api/cloud-security/demo-scan", json={"region": "ap-south-1"}, headers=headers)
    assert demo_res.status_code == 201
    scan_data = demo_res.get_json()["data"]
    assert scan_data["is_simulation"] is True
    assert scan_data["simulation_label"] == "DEMO / SIMULATED DATA — NOT LIVE AWS FINDINGS"
    scan_id = scan_data["id"]
    assert len(scan_data["findings"]) > 0

    # 3. Test get scan by id
    get_res = client.get(f"/api/cloud-security/scan/{scan_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.get_json()["data"]["id"] == scan_id

    # 4. Test history endpoint
    hist_res = client.get("/api/cloud-security/history", headers=headers)
    assert hist_res.status_code == 200
    history = hist_res.get_json()["data"]
    assert len(history) >= 1
    assert history[0]["id"] == scan_id

    # 5. Test summary endpoint
    summary_res = client.get("/api/cloud-security/summary", headers=headers)
    assert summary_res.status_code == 200
    summary = summary_res.get_json()["data"]
    assert summary["has_assessments"] is True
    assert summary["connected_accounts_count"] == 1

    # 6. Test finding detail endpoint
    first_finding = scan_data["findings"][0]
    finding_id = first_finding["id"]
    f_res = client.get(f"/api/cloud-security/findings/{finding_id}", headers=headers)
    assert f_res.status_code == 200
    f_data = f_res.get_json()["data"]
    assert f_data["id"] == finding_id
    assert "remediation" in f_data

    # 7. Authorization test: Second user cannot access first user's scan
    token2 = register_user(client, "user2@example.com")
    headers2 = {"Authorization": f"Bearer {token2}"}
    unauthorized_res = client.get(f"/api/cloud-security/scan/{scan_id}", headers=headers2)
    assert unauthorized_res.status_code == 403
