from functools import wraps
from datetime import datetime, timedelta, timezone
from flask import current_app, request, jsonify, g
import jwt
from ..extensions import db
from ..models.user import User


def generate_token(user_id: int) -> str:
    """Generate a JWT token for the user."""
    payload = {
        "sub": str(user_id),
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(days=7)
    }
    secret = current_app.config.get("JWT_SECRET_KEY", "fallback-secret")
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(token: str):
    """Decode and validate a JWT token."""
    secret = current_app.config.get("JWT_SECRET_KEY", "fallback-secret")
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        sub = payload.get("sub")
        return int(sub) if sub is not None else None
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, ValueError, TypeError):
        return None


def get_current_user_from_request():
    """Extract token from Authorization header or cookie and find user."""
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    elif "cloudguard_token" in request.cookies:
        token = request.cookies.get("cloudguard_token")

    if not token:
        return None

    user_id = decode_token(token)
    if not user_id:
        return None

    return db.session.get(User, user_id)


def login_required(f):
    """Decorator to require authenticated user for endpoint."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user_from_request()
        if not user:
            return jsonify({
                "success": False,
                "message": "Authentication required. Please log in."
            }), 401
        g.current_user = user
        return f(*args, **kwargs)
    return decorated_function
