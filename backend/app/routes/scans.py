import logging
from flask import Blueprint, request, jsonify, g
from ..extensions import db
from ..models.scan import Scan
from ..utils.auth import login_required
from ..services.scan_service import ScanService, ArchiveValidationError

logger = logging.getLogger(__name__)
scans_bp = Blueprint("scans", __name__, url_prefix="/api/scans")


@scans_bp.route("", methods=["POST"])
@login_required
def create_scan():
    if "file" not in request.files:
        return jsonify({"success": False, "message": "No ZIP file uploaded in request."}), 400

    uploaded_file = request.files["file"]
    if not uploaded_file.filename:
        return jsonify({"success": False, "message": "Uploaded file is empty or missing a filename."}), 400

    scan_service = ScanService()
    try:
        scan = scan_service.execute_scan(uploaded_file, g.current_user.id)
        return jsonify({
            "success": True,
            "message": "Scan completed successfully.",
            "data": scan.to_dict(include_findings=True)
        }), 201

    except ArchiveValidationError as e:
        return jsonify({
            "success": False,
            "message": f"Archive validation error: {str(e)}"
        }), 400
    except Exception as e:
        logger.error("Scan processing failed: %s", str(e), exc_info=True)
        return jsonify({
            "success": False,
            "message": "Scan processing failed. Please check that your archive is a valid, unencrypted ZIP."
        }), 500


@scans_bp.route("", methods=["GET"])
@login_required
def list_scans():
    scans = (
        Scan.query.filter_by(user_id=g.current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(100)
        .all()
    )
    return jsonify({
        "success": True,
        "data": [s.to_dict(include_findings=False) for s in scans]
    }), 200


@scans_bp.route("/<scan_id>", methods=["GET"])
@login_required
def get_scan(scan_id):
    scan = Scan.query.filter_by(id=scan_id).first()
    if not scan:
        return jsonify({"success": False, "message": "Scan not found."}), 404

    # Ownership check
    if scan.user_id != g.current_user.id:
        return jsonify({"success": False, "message": "Access denied: you do not have permission to view this scan."}), 403

    return jsonify({
        "success": True,
        "data": scan.to_dict(include_findings=True)
    }), 200
