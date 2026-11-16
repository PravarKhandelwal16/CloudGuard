import os
from flask import Flask, jsonify
from flask_cors import CORS
from .config import Config
from .extensions import db


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Enable CORS for frontend development
    CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

    # Initialize extensions
    db.init_app(app)

    # Register blueprints
    from .routes.health import health_bp
    app.register_blueprint(health_bp)

    from .routes.auth import auth_bp
    app.register_blueprint(auth_bp)

    from .routes.scans import scans_bp
    app.register_blueprint(scans_bp)

    from .routes.dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp)

    from .routes.cloud_security import cloud_security_bp
    app.register_blueprint(cloud_security_bp)

    # Error handlers
    @app.errorhandler(413)
    def request_entity_too_large(error):
        return jsonify({
            "success": False,
            "message": f"Upload exceeds maximum allowed size ({app.config['UPLOAD_MAX_MB']} MB)."
        }), 413

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "success": False,
            "message": "Resource not found."
        }), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        return jsonify({
            "success": False,
            "message": "An internal server error occurred."
        }), 500

    # Ensure local upload directories exist
    os.makedirs(app.config.get("LOCAL_UPLOAD_DIR", "temp_scans"), exist_ok=True)

    # Serve built frontend if available
    dist_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "frontend", "dist")
    if os.path.exists(dist_dir):
        from flask import send_from_directory

        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def serve_frontend(path):
            if path and not path.startswith("api") and os.path.exists(os.path.join(dist_dir, path)):
                return send_from_directory(dist_dir, path)
            if not path.startswith("api"):
                return send_from_directory(dist_dir, "index.html")
            return jsonify({"success": False, "message": "Resource not found."}), 404

    with app.app_context():
        db.create_all()

    return app
