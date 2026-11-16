"""
Database models for CloudGuard Cloud Security Auditor.

Tracks:
- Saved AWS Account Connections (strictly without secret keys)
- Cloud Security Assessments (both live and simulation audits)
- Security Findings with remediation details
- Assessed Resource Summaries per service
"""

import uuid
import json
from datetime import datetime, timezone
from ..extensions import db


class CloudAccountConnection(db.Model):
    __tablename__ = "cloud_account_connections"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    account_id = db.Column(db.String(32), nullable=False)
    role_arn = db.Column(db.String(255), nullable=False)
    external_id = db.Column(db.String(128), nullable=True)
    region = db.Column(db.String(64), default="ap-south-1", nullable=False)
    alias = db.Column(db.String(128), nullable=True)
    status = db.Column(db.String(32), default="configured", nullable=False)  # configured, verified, invalid
    last_tested_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    assessments = db.relationship("CloudAssessment", backref="connection", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "account_id": self.account_id,
            "role_arn": self.role_arn,
            "external_id_configured": bool(self.external_id),
            "region": self.region,
            "alias": self.alias,
            "status": self.status,
            "last_tested_at": self.last_tested_at.isoformat() if self.last_tested_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class CloudAssessment(db.Model):
    __tablename__ = "cloud_assessments"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    connection_id = db.Column(db.Integer, db.ForeignKey("cloud_account_connections.id"), nullable=True)
    account_id = db.Column(db.String(32), nullable=False)
    role_arn = db.Column(db.String(255), nullable=True)
    region = db.Column(db.String(64), default="ap-south-1", nullable=False)
    is_simulation = db.Column(db.Boolean, default=False, nullable=False)
    simulation_scenario = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(32), default="completed", nullable=False)  # completed, partial, failed
    coverage_status = db.Column(db.String(32), default="complete", nullable=False)  # complete, incomplete, error
    security_score = db.Column(db.Integer, nullable=True)
    total_resources_assessed = db.Column(db.Integer, default=0, nullable=False)
    checks_passed = db.Column(db.Integer, default=0, nullable=False)
    checks_failed = db.Column(db.Integer, default=0, nullable=False)
    checks_warned = db.Column(db.Integer, default=0, nullable=False)
    checks_not_assessed = db.Column(db.Integer, default=0, nullable=False)
    critical_count = db.Column(db.Integer, default=0, nullable=False)
    high_count = db.Column(db.Integer, default=0, nullable=False)
    medium_count = db.Column(db.Integer, default=0, nullable=False)
    low_count = db.Column(db.Integer, default=0, nullable=False)
    info_count = db.Column(db.Integer, default=0, nullable=False)
    scan_duration_ms = db.Column(db.Integer, default=0, nullable=False)
    error_message = db.Column(db.String(512), nullable=True)
    coverage_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    findings = db.relationship(
        "CloudFinding",
        backref="assessment",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="CloudFinding.id"
    )
    resource_summaries = db.relationship(
        "CloudResourceSummary",
        backref="assessment",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="CloudResourceSummary.id"
    )

    def to_dict(self, include_findings=False):
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "connection_id": self.connection_id,
            "account_id": self.account_id,
            "role_arn": self.role_arn,
            "region": self.region,
            "is_simulation": self.is_simulation,
            "simulation_scenario": self.simulation_scenario,
            "simulation_label": "DEMO / SIMULATED DATA — NOT LIVE AWS FINDINGS" if self.is_simulation else None,
            "status": self.status,
            "coverage_status": self.coverage_status,
            "coverage_notes": self.coverage_notes,
            "security_score": self.security_score,
            "total_resources_assessed": self.total_resources_assessed,
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
            "checks_warned": self.checks_warned,
            "checks_not_assessed": self.checks_not_assessed,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "scan_duration_ms": self.scan_duration_ms,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "resource_summaries": [s.to_dict() for s in self.resource_summaries],
        }
        if include_findings:
            data["findings"] = [f.to_dict() for f in self.findings]
        return data


class CloudFinding(db.Model):
    __tablename__ = "cloud_findings"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.String(36), db.ForeignKey("cloud_assessments.id"), nullable=False, index=True)
    finding_id = db.Column(db.String(128), nullable=False, index=True)
    service = db.Column(db.String(64), nullable=False)
    resource_id = db.Column(db.String(255), nullable=False)
    resource_arn = db.Column(db.String(512), nullable=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(32), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    status = db.Column(db.String(32), nullable=False)    # FAILED, PASSED, WARNING, NOT ASSESSED
    evidence = db.Column(db.Text, nullable=True)
    remediation = db.Column(db.Text, nullable=False)
    region = db.Column(db.String(64), nullable=True)
    remediation_details_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        details = {}
        if self.remediation_details_json:
            try:
                details = json.loads(self.remediation_details_json)
            except Exception:
                pass

        return {
            "id": self.id,
            "assessment_id": self.assessment_id,
            "finding_id": self.finding_id,
            "service": self.service,
            "resource_id": self.resource_id,
            "resource_arn": self.resource_arn,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "region": self.region,
            "remediation_details": details,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class CloudResourceSummary(db.Model):
    __tablename__ = "cloud_resource_summaries"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.String(36), db.ForeignKey("cloud_assessments.id"), nullable=False, index=True)
    service = db.Column(db.String(64), nullable=False)
    resource_type = db.Column(db.String(64), nullable=False)
    total_count = db.Column(db.Integer, default=0, nullable=False)
    passed_count = db.Column(db.Integer, default=0, nullable=False)
    failed_count = db.Column(db.Integer, default=0, nullable=False)
    warned_count = db.Column(db.Integer, default=0, nullable=False)
    not_assessed_count = db.Column(db.Integer, default=0, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "assessment_id": self.assessment_id,
            "service": self.service,
            "resource_type": self.resource_type,
            "total": self.total_count,
            "passed": self.passed_count,
            "failed": self.failed_count,
            "warned": self.warned_count,
            "not_assessed": self.not_assessed_count
        }
