"""
API routes for CloudGuard Cloud Security Auditor.

Endpoints:
- POST /api/cloud-security/connect
- POST /api/cloud-security/test-connection
- POST /api/cloud-security/scan
- GET  /api/cloud-security/scan/<scan_id>
- GET  /api/cloud-security/history
- GET  /api/cloud-security/findings/<finding_id>
- POST /api/cloud-security/demo-scan
- GET  /api/cloud-security/summary
"""

import json
import logging
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from ..extensions import db
from ..utils.auth import login_required
from ..models.cloud_security import (
    CloudAccountConnection,
    CloudAssessment,
    CloudFinding,
    CloudResourceSummary
)
from ..cloud_security import (
    CloudSecurityAuditor,
    STSManager,
    validate_account_id,
    validate_role_arn,
    AWSValidationError,
    AWSAuthenticationError
)

logger = logging.getLogger(__name__)
cloud_security_bp = Blueprint("cloud_security", __name__, url_prefix="/api/cloud-security")


def _persist_audit_result(user_id: int, audit_result: dict, connection_id=None) -> CloudAssessment:
    """Helper to persist audit result and associated findings into database."""
    assessment = CloudAssessment(
        user_id=user_id,
        connection_id=connection_id,
        account_id=audit_result.get("account_id", "Unknown"),
        role_arn=audit_result.get("role_arn"),
        region=audit_result.get("region", "ap-south-1"),
        is_simulation=audit_result.get("is_simulation", False),
        simulation_scenario=audit_result.get("simulation_scenario") if audit_result.get("is_simulation") else None,
        status=audit_result.get("status", "completed"),
        coverage_status=audit_result.get("coverage_status", "complete"),
        coverage_notes=audit_result.get("coverage_notes"),
        security_score=audit_result.get("security_score"),
        total_resources_assessed=audit_result.get("total_resources_assessed", 0),
        checks_passed=audit_result.get("checks_passed", 0),
        checks_failed=audit_result.get("checks_failed", 0),
        checks_warned=audit_result.get("checks_warned", 0),
        checks_not_assessed=audit_result.get("checks_not_assessed", 0),
        critical_count=audit_result.get("critical_count", 0),
        high_count=audit_result.get("high_count", 0),
        medium_count=audit_result.get("medium_count", 0),
        low_count=audit_result.get("low_count", 0),
        info_count=audit_result.get("info_count", 0),
        scan_duration_ms=audit_result.get("scan_duration_ms", 0)
    )
    db.session.add(assessment)
    db.session.flush()

    # Save findings
    for f in audit_result.get("findings", []):
        rem_details = f.get("remediation_details")
        finding_record = CloudFinding(
            assessment_id=assessment.id,
            finding_id=f.get("finding_id", "finding-id"),
            service=f.get("service", "General"),
            resource_id=f.get("resource_id", "resource"),
            resource_arn=f.get("resource_arn"),
            title=f.get("title", "Security Finding"),
            description=f.get("description", ""),
            severity=f.get("severity", "LOW"),
            status=f.get("status", "FAILED"),
            evidence=f.get("evidence"),
            remediation=f.get("remediation", ""),
            region=f.get("region", assessment.region),
            remediation_details_json=json.dumps(rem_details) if rem_details else None
        )
        db.session.add(finding_record)

    # Save resource summaries
    for s in audit_result.get("resource_summaries", []):
        summary_record = CloudResourceSummary(
            assessment_id=assessment.id,
            service=s.get("service", "General"),
            resource_type=s.get("resource_type", "Resource"),
            total_count=s.get("total", 0),
            passed_count=s.get("passed", 0),
            failed_count=s.get("failed", 0),
            warned_count=s.get("warned", 0),
            not_assessed_count=s.get("not_assessed", 0)
        )
        db.session.add(summary_record)

    db.session.commit()
    return assessment


@cloud_security_bp.route("/connect", methods=["POST"])
@login_required
def connect_account():
    """Register or update an AWS account connection for cross-account audit."""
    data = request.get_json() or {}
    account_id = data.get("account_id", "").strip()
    role_arn = data.get("role_arn", "").strip()
    external_id = data.get("external_id", "").strip() or None
    region = data.get("region", "ap-south-1").strip()
    alias = data.get("alias", "").strip() or None

    try:
        clean_account_id = validate_account_id(account_id)
        clean_role_arn = validate_role_arn(role_arn, clean_account_id)
    except AWSValidationError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    # Check if connection already exists for this user and account
    conn = CloudAccountConnection.query.filter_by(
        user_id=g.current_user.id,
        account_id=clean_account_id
    ).first()

    if not conn:
        conn = CloudAccountConnection(
            user_id=g.current_user.id,
            account_id=clean_account_id,
            role_arn=clean_role_arn,
            external_id=external_id,
            region=region,
            alias=alias,
            status="configured"
        )
        db.session.add(conn)
    else:
        conn.role_arn = clean_role_arn
        conn.external_id = external_id
        conn.region = region
        if alias:
            conn.alias = alias
        conn.updated_at = datetime.now(timezone.utc)

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "AWS account connection saved successfully.",
        "data": conn.to_dict()
    }), 200


@cloud_security_bp.route("/test-connection", methods=["POST"])
@login_required
def test_connection():
    """Test STS AssumeRole connectivity with provided or stored credentials."""
    data = request.get_json() or {}
    account_id = data.get("account_id", "").strip()
    role_arn = data.get("role_arn", "").strip()
    external_id = data.get("external_id", "").strip() or None
    region = data.get("region", "ap-south-1").strip()

    # Allow passing connection_id instead of raw details
    conn_id = data.get("connection_id")
    conn = None
    if conn_id:
        conn = db.session.get(CloudAccountConnection, conn_id)
        if conn and conn.user_id == g.current_user.id:
            account_id = conn.account_id
            role_arn = conn.role_arn
            external_id = conn.external_id
            region = conn.region

    try:
        result = STSManager.test_connection(
            account_id=account_id,
            role_arn=role_arn,
            region=region,
            external_id=external_id
        )

        if conn:
            conn.last_tested_at = datetime.now(timezone.utc)
            conn.status = "verified" if result.get("success") else "invalid"
            db.session.commit()

        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code

    except AWSValidationError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        logger.error("Error during connection test: %s", str(e), exc_info=True)
        return jsonify({"success": False, "message": f"Connection test failed: {str(e)}"}), 500


@cloud_security_bp.route("/scan", methods=["POST"])
@login_required
def run_scan():
    """Execute live AWS cloud infrastructure security assessment."""
    data = request.get_json() or {}
    account_id = data.get("account_id", "").strip()
    role_arn = data.get("role_arn", "").strip()
    external_id = data.get("external_id", "").strip() or None
    region = data.get("region", "ap-south-1").strip()
    connection_id = data.get("connection_id")

    if connection_id:
        conn = db.session.get(CloudAccountConnection, connection_id)
        if not conn or conn.user_id != g.current_user.id:
            return jsonify({"success": False, "message": "Saved connection not found or unauthorized."}), 404
        account_id = conn.account_id
        role_arn = conn.role_arn
        external_id = conn.external_id
        region = conn.region

    try:
        clean_account_id = validate_account_id(account_id)
        clean_role_arn = validate_role_arn(role_arn, clean_account_id)
    except AWSValidationError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    auditor = CloudSecurityAuditor(
        account_id=clean_account_id,
        role_arn=clean_role_arn,
        region=region,
        external_id=external_id,
        is_simulation=False
    )

    try:
        audit_result = auditor.run_audit()
        assessment = _persist_audit_result(g.current_user.id, audit_result, connection_id=connection_id)

        return jsonify({
            "success": True,
            "message": "Cloud security assessment completed.",
            "data": assessment.to_dict(include_findings=True)
        }), 201

    except AWSAuthenticationError as e:
        return jsonify({
            "success": False,
            "message": f"AWS STS Authentication failed: {str(e)}"
        }), 401
    except Exception as e:
        logger.error("Live cloud security audit failed: %s", str(e), exc_info=True)
        return jsonify({
            "success": False,
            "message": f"Assessment execution failed: {str(e)}"
        }), 500


@cloud_security_bp.route("/demo-scan", methods=["POST"])
@login_required
def run_demo_scan():
    """
    Execute simulation assessment using realistic JSON fixtures.
    Runs the exact same rules engine without requiring AWS credentials.
    Supports multiple scenarios: 'high_risk' (score ~0), 'hardened' (score ~91), 'compliant' (score 100).
    """
    from pathlib import Path
    data = request.get_json() or {}
    region = data.get("region", "ap-south-1").strip()
    scenario = data.get("scenario", "high_risk").lower().strip()

    fixtures_dir = Path(__file__).resolve().parent.parent / "cloud_security" / "fixtures"

    if scenario in ("hardened", "secure", "good"):
        fixture_path = str(fixtures_dir / "hardened_aws_data.json")
        account_id = "987654321098"
        scenario_title = "Hardened Production AWS Environment"
    elif scenario in ("compliant", "perfect", "clean"):
        fixture_path = str(fixtures_dir / "compliant_aws_data.json")
        account_id = "112233445566"
        scenario_title = "CIS Benchmark Compliant Baseline"
    else:
        fixture_path = str(fixtures_dir / "sample_aws_data.json")
        account_id = "123456789012"
        scenario_title = "Enterprise Multi-Service (High-Risk Demo)"

    auditor = CloudSecurityAuditor(
        account_id=account_id,
        role_arn=f"arn:aws:iam::{account_id}:role/CloudGuardAuditorRole",
        region=region,
        is_simulation=True,
        simulation_fixture_path=fixture_path
    )

    try:
        audit_result = auditor.run_audit()
        audit_result["simulation_scenario"] = scenario_title

        assessment = _persist_audit_result(g.current_user.id, audit_result)

        return jsonify({
            "success": True,
            "message": f"Simulation assessment completed ({scenario_title}).",
            "simulation_label": "DEMO / SIMULATED DATA — NOT LIVE AWS FINDINGS",
            "data": assessment.to_dict(include_findings=True)
        }), 201

    except Exception as e:
        logger.error("Demo scan failed: %s", str(e), exc_info=True)
        return jsonify({
            "success": False,
            "message": f"Simulation assessment failed: {str(e)}"
        }), 500


@cloud_security_bp.route("/scan/<scan_id>", methods=["GET"])
@login_required
def get_scan(scan_id):
    """Retrieve full details and findings for a specific assessment."""
    assessment = CloudAssessment.query.filter_by(id=scan_id).first()
    if not assessment:
        return jsonify({"success": False, "message": "Assessment not found."}), 404

    if assessment.user_id != g.current_user.id:
        return jsonify({"success": False, "message": "Access denied."}), 403

    return jsonify({
        "success": True,
        "data": assessment.to_dict(include_findings=True)
    }), 200


@cloud_security_bp.route("/history", methods=["GET"])
@login_required
def list_history():
    """List historical cloud security assessments for the authenticated user."""
    assessments = (
        CloudAssessment.query.filter_by(user_id=g.current_user.id)
        .order_by(CloudAssessment.created_at.desc())
        .limit(100)
        .all()
    )
    return jsonify({
        "success": True,
        "data": [a.to_dict(include_findings=False) for a in assessments]
    }), 200


@cloud_security_bp.route("/findings/<int:finding_id>", methods=["GET"])
@login_required
def get_finding(finding_id):
    """Retrieve single finding with remediation steps and risk explanation."""
    finding = db.session.get(CloudFinding, finding_id)
    if not finding:
        return jsonify({"success": False, "message": "Finding not found."}), 404

    assessment = finding.assessment
    if assessment.user_id != g.current_user.id:
        return jsonify({"success": False, "message": "Access denied."}), 403

    return jsonify({
        "success": True,
        "data": finding.to_dict()
    }), 200


@cloud_security_bp.route("/summary", methods=["GET"])
@login_required
def get_summary():
    """Get high-level summary of cloud posture, latest score, and connected accounts."""
    latest_assessment = (
        CloudAssessment.query.filter_by(user_id=g.current_user.id)
        .order_by(CloudAssessment.created_at.desc())
        .first()
    )

    connections = CloudAccountConnection.query.filter_by(user_id=g.current_user.id).all()
    total_assessments = CloudAssessment.query.filter_by(user_id=g.current_user.id).count()

    summary_data = {
        "has_assessments": latest_assessment is not None,
        "latest_assessment": latest_assessment.to_dict(include_findings=False) if latest_assessment else None,
        "total_assessments": total_assessments,
        "connected_accounts_count": len(connections),
        "connections": [c.to_dict() for c in connections]
    }

    return jsonify({
        "success": True,
        "data": summary_data
    }), 200
