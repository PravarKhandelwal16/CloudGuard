from flask import Blueprint, jsonify

health_bp = Blueprint("health", __name__)


@health_bp.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint that returns operational status without leaking config or secrets."""
    return jsonify({
        "success": True,
        "status": "healthy",
        "service": "cloudguard-api",
        "version": "1.0.0"
    }), 200

