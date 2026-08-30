"""
Minimal JWT auth: encode/decode helpers + a @require_auth decorator that
protects a route (or an entire blueprint via before_request).

Tokens carry {sub: user_id, role, exp}. No refresh-token flow here on
purpose — keep it simple; the frontend just re-logs-in when a token expires.
"""
from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import current_app, request, jsonify, g

from app.models import User


class AuthError(Exception):
    def __init__(self, message, status_code=401):
        self.message = message
        self.status_code = status_code


def encode_token(user: User) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": user.id,
        "email": user.email,
        "role": user.role,
        "iat": now,
        "exp": now + timedelta(hours=current_app.config["JWT_EXPIRATION_HOURS"]),
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET_KEY"], algorithm="HS256")


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, current_app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired.")
    except jwt.InvalidTokenError:
        raise AuthError("Invalid token.")


def _extract_token():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    return header.split(" ", 1)[1].strip()


def user_from_token(token: str) -> User:
    """Decode `token` and return the live User it names, or raise AuthError.
    Shared by the REST auth path (get_current_user, below) and the
    WebSocket connect handler (app/ws/handlers.py) so both enforce the exact
    same checks -- token validity, user existence, and enabled status --
    from one place."""
    if not token:
        raise AuthError("Missing token.")
    payload = decode_token(token)
    user = User.query.get(payload["sub"])
    if not user:
        raise AuthError("User no longer exists.")
    if not user.is_active:
        raise AuthError("Account disabled.", 403)
    return user


def get_current_user():
    """Decode the request's token and return the User, or raise AuthError."""
    token = _extract_token()
    if not token:
        raise AuthError("Missing Authorization header.")
    return user_from_token(token)


def require_auth(f):
    """Decorator for protecting an individual route."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            g.current_user = get_current_user()
        except AuthError as e:
            return jsonify({"error": e.message}), e.status_code
        return f(*args, **kwargs)
    return wrapper


def require_auth_before_request():
    """Same check, meant to be registered as a blueprint's before_request."""
    try:
        g.current_user = get_current_user()
    except AuthError as e:
        return jsonify({"error": e.message}), e.status_code
