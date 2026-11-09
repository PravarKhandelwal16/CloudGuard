from flask import Blueprint, jsonify, g
from sqlalchemy import func
from ..extensions import db
from ..models.scan import Scan
from ..models.finding import Finding
from ..utils.auth import login_required

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


@dashboard_bp.route("/summary", methods=["GET"])
@login_required
def get_dashboard_summary():
    user_id = g.current_user.id

    user_scans = (
        Scan.query.filter_by(user_id=user_id)
        .order_by(Scan.created_at.desc())
        .all()
    )

    total_scans = len(user_scans)
    total_findings = sum(s.total_findings for s in user_scans)
    critical_findings = sum(s.critical_count for s in user_scans)

    latest_completed = next((s for s in user_scans if s.status == "completed"), None)
    latest_score = latest_completed.security_score if latest_completed else None

    # Up to 5 recent scans
    recent_scans = [s.to_dict(include_findings=False) for s in user_scans[:5]]

    # Up to 5 recent high-risk findings (Critical or High)
    recent_high_risk = []
    if user_scans:
        scan_ids = [s.id for s in user_scans]
        high_risk_findings = (
            Finding.query.filter(
                Finding.scan_id.in_(scan_ids),
                Finding.severity.in_(["Critical", "High"])
            )
            .order_by(Finding.created_at.desc())
            .limit(5)
            .all()
        )
        recent_high_risk = [f.to_dict() for f in high_risk_findings]

    return jsonify({
        "success": True,
        "data": {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "critical_findings": critical_findings,
            "latest_security_score": latest_score,
            "recent_scans": recent_scans,
            "recent_high_risk_findings": recent_high_risk
        }
    }), 200
