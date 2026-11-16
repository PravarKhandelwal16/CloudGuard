"""
Simulated AWS Client Provider for CloudGuard Cloud Security Auditor.

Implements mock Boto3 clients backed by realistic JSON fixtures.
Runs through the EXACT same rules engine and security checks as live AWS scans.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError


class SimulatedClientError(ClientError):
    def __init__(self, code: str, message: str, operation_name: str = "SimulatedOperation"):
        error_response = {
            "Error": {
                "Code": code,
                "Message": message
            }
        }
        super().__init__(error_response, operation_name)


class SimulatedS3Client:
    def __init__(self, data: Dict[str, Any]):
        self.buckets = {b["Name"]: b for b in data.get("buckets", [])}

    def list_buckets(self):
        return {
            "Buckets": [
                {"Name": b["Name"], "CreationDate": b.get("CreationDate")}
                for b in self.buckets.values()
            ]
        }

    def get_public_access_block(self, Bucket: str):
        bucket = self.buckets.get(Bucket)
        if not bucket or bucket.get("PublicAccessBlock") is None:
            raise SimulatedClientError(
                "NoSuchPublicAccessBlockConfiguration",
                "The public access block configuration was not found",
                "GetPublicAccessBlock"
            )
        return {
            "PublicAccessBlockConfiguration": bucket["PublicAccessBlock"]
        }

    def get_bucket_policy_status(self, Bucket: str):
        bucket = self.buckets.get(Bucket)
        if not bucket or bucket.get("PolicyStatus") is None:
            raise SimulatedClientError(
                "NoSuchBucketPolicy",
                "The bucket policy does not exist",
                "GetBucketPolicyStatus"
            )
        return {"PolicyStatus": bucket["PolicyStatus"]}

    def get_bucket_policy(self, Bucket: str):
        bucket = self.buckets.get(Bucket)
        if not bucket or not bucket.get("Policy"):
            raise SimulatedClientError(
                "NoSuchBucketPolicy",
                "The bucket policy does not exist",
                "GetBucketPolicy"
            )
        return {"Policy": json.dumps(bucket["Policy"])}

    def get_bucket_encryption(self, Bucket: str):
        bucket = self.buckets.get(Bucket)
        if not bucket or not bucket.get("Encryption"):
            raise SimulatedClientError(
                "ServerSideEncryptionConfigurationNotFoundError",
                "The server side encryption configuration was not found",
                "GetBucketEncryption"
            )
        return bucket["Encryption"]

    def get_bucket_acl(self, Bucket: str):
        bucket = self.buckets.get(Bucket)
        if not bucket or not bucket.get("Acl"):
            return {"Grants": []}
        return bucket["Acl"]


class SimulatedIAMClient:
    def __init__(self, data: Dict[str, Any]):
        self.users = {u["UserName"]: u for u in data.get("users", [])}
        self.roles = {r["RoleName"]: r for r in data.get("roles", [])}
        self.policies = {p["PolicyArn"]: p for p in data.get("policies", [])}

    def list_users(self):
        return {
            "Users": [
                {"UserName": u["UserName"], "UserId": u.get("UserId"), "Arn": u.get("Arn")}
                for u in self.users.values()
            ]
        }

    def list_roles(self):
        return {
            "Roles": [
                {"RoleName": r["RoleName"], "RoleId": r.get("RoleId"), "Arn": r.get("Arn")}
                for r in self.roles.values()
            ]
        }

    def list_policies(self, Scope: str = "Local"):
        return {
            "Policies": [
                {"PolicyName": p["PolicyName"], "PolicyArn": p["PolicyArn"], "DefaultVersionId": "v1"}
                for p in self.policies.values()
            ]
        }

    def get_policy(self, PolicyArn: str):
        pol = self.policies.get(PolicyArn)
        if not pol:
            # Check AWS managed policies like AdministratorAccess
            if "AdministratorAccess" in PolicyArn:
                return {
                    "Policy": {
                        "PolicyName": "AdministratorAccess",
                        "PolicyArn": PolicyArn,
                        "DefaultVersionId": "v1"
                    }
                }
            raise SimulatedClientError("NoSuchEntity", "Policy does not exist", "GetPolicy")
        return {
            "Policy": {
                "PolicyName": pol["PolicyName"],
                "PolicyArn": pol["PolicyArn"],
                "DefaultVersionId": "v1"
            }
        }

    def get_policy_version(self, PolicyArn: str, VersionId: str):
        pol = self.policies.get(PolicyArn)
        if not pol:
            if "AdministratorAccess" in PolicyArn:
                return {
                    "PolicyVersion": {
                        "Document": {
                            "Version": "2012-10-17",
                            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                        }
                    }
                }
            raise SimulatedClientError("NoSuchEntity", "Policy version does not exist", "GetPolicyVersion")
        return {
            "PolicyVersion": {
                "Document": pol.get("PolicyDocument", {})
            }
        }

    def list_attached_user_policies(self, UserName: str):
        user = self.users.get(UserName, {})
        return {"AttachedPolicies": user.get("AttachedPolicies", [])}

    def list_attached_role_policies(self, RoleName: str):
        role = self.roles.get(RoleName, {})
        return {"AttachedPolicies": role.get("AttachedPolicies", [])}

    def list_user_policies(self, UserName: str):
        user = self.users.get(UserName, {})
        inline = user.get("InlinePolicies", [])
        return {"PolicyNames": [p["PolicyName"] for p in inline]}

    def get_user_policy(self, UserName: str, PolicyName: str):
        user = self.users.get(UserName, {})
        for p in user.get("InlinePolicies", []):
            if p["PolicyName"] == PolicyName:
                return {"PolicyDocument": p.get("PolicyDocument", {})}
        raise SimulatedClientError("NoSuchEntity", "Inline policy not found", "GetUserPolicy")

    def list_role_policies(self, RoleName: str):
        role = self.roles.get(RoleName, {})
        inline = role.get("InlinePolicies", [])
        return {"PolicyNames": [p["PolicyName"] for p in inline]}

    def get_role_policy(self, RoleName: str, PolicyName: str):
        role = self.roles.get(RoleName, {})
        for p in role.get("InlinePolicies", []):
            if p["PolicyName"] == PolicyName:
                return {"PolicyDocument": p.get("PolicyDocument", {})}
        raise SimulatedClientError("NoSuchEntity", "Inline policy not found", "GetRolePolicy")


class SimulatedEC2Client:
    def __init__(self, data: Dict[str, Any]):
        self.security_groups = data.get("security_groups", [])
        self.volumes = data.get("volumes", [])

    def describe_security_groups(self):
        return {"SecurityGroups": self.security_groups}

    def describe_volumes(self):
        return {"Volumes": self.volumes}


class SimulatedCloudTrailClient:
    def __init__(self, data: Dict[str, Any]):
        self.trails = data.get("trails", [])

    def describe_trails(self):
        return {"trailList": self.trails}

    def get_trail_status(self, Name: str):
        for t in self.trails:
            if t["Name"] == Name or t.get("TrailARN") == Name:
                return t.get("Status", {"IsLogging": False})
        raise SimulatedClientError("TrailNotFoundException", f"Trail {Name} not found", "GetTrailStatus")


class SimulatedRDSClient:
    def __init__(self, data: Dict[str, Any]):
        self.instances = data.get("db_instances", [])

    def describe_db_instances(self):
        return {"DBInstances": self.instances}


class SimulatedSTSClient:
    def __init__(self, metadata: Dict[str, Any]):
        self.metadata = metadata

    def get_caller_identity(self):
        return {
            "Account": self.metadata.get("account_id", "123456789012"),
            "Arn": self.metadata.get("role_arn", "arn:aws:iam::123456789012:role/CloudGuardAuditorRole"),
            "UserId": "AROA123456789SIMULATED"
        }


class SimulatedAWSClientProvider:
    """Provides simulated Boto3 clients that read from JSON fixtures."""

    def __init__(self, fixture_path: Optional[str] = None):
        if not fixture_path:
            fixture_path = str(Path(__file__).parent / "fixtures" / "sample_aws_data.json")

        with open(fixture_path, "r", encoding="utf-8") as f:
            self.data = json.load(f)

        self.metadata = self.data.get("scenario_metadata", {})
        self._s3 = SimulatedS3Client(self.data.get("s3", {}))
        self._iam = SimulatedIAMClient(self.data.get("iam", {}))
        self._ec2 = SimulatedEC2Client(self.data.get("ec2", {}))
        self._cloudtrail = SimulatedCloudTrailClient(self.data.get("cloudtrail", {}))
        self._rds = SimulatedRDSClient(self.data.get("rds", {}))
        self._sts = SimulatedSTSClient(self.metadata)

    def get_client(self, service_name: str, region: Optional[str] = None):
        service = service_name.lower()
        if service == "s3":
            return self._s3
        elif service == "iam":
            return self._iam
        elif service == "ec2":
            return self._ec2
        elif service == "cloudtrail":
            return self._cloudtrail
        elif service == "rds":
            return self._rds
        elif service == "sts":
            return self._sts
        raise ValueError(f"Unsupported simulated service: {service_name}")
