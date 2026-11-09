import re
from flask import Blueprint, request, jsonify, g, make_response
from ..extensions import db
from ..models.user import User
from ..utils.auth import generate_token, login_required

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not name:
        return jsonify({"success": False, "message": "Name is required."}), 400
    if not email or not EMAIL_REGEX.match(email):
        return jsonify({"success": False, "message": "Valid email address is required."}), 400
    if len(password) < 8:
        return jsonify({"success": False, "message": "Password must be at least 8 characters long."}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"success": False, "message": "An account with this email already exists."}), 409

    user = User(name=name, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    token = generate_token(user.id)
    response = make_response(jsonify({
        "success": True,
        "message": "User registered successfully.",
        "data": {
            "user": user.to_dict(),
            "token": token
        }
    }), 201)

    # Set secure HTTP-only cookie
    response.set_cookie(
        "cloudguard_token",
        token,
        httponly=True,
        samesite="Lax",
        secure=False  # Allow in local dev; EC2/prod can set secure if HTTPS
    )
    return response


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"success": False, "message": "Invalid email or password."}), 401

    token = generate_token(user.id)
    response = make_response(jsonify({
        "success": True,
        "message": "Logged in successfully.",
        "data": {
            "user": user.to_dict(),
            "token": token
        }
    }), 200)

    response.set_cookie(
        "cloudguard_token",
        token,
        httponly=True,
        samesite="Lax",
        secure=False
    )
    return response


@auth_bp.route("/logout", methods=["POST"])
def logout():
    response = make_response(jsonify({
        "success": True,
        "message": "Logged out successfully."
    }), 200)
    response.delete_cookie("cloudguard_token")
    return response


@auth_bp.route("/me", methods=["GET"])
@login_required
def get_me():
    return jsonify({
        "success": True,
        "data": {
            "user": g.current_user.to_dict()
        }
    }), 200

