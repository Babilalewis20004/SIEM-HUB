"""
JWT auth: encode/decode helpers + a @require_auth decorator that protects a
route (or an entire blueprint via before_request), backed by a server-side
refresh-token session (app/models/refresh_token.py).

Access tokens carry {sub: user_id, email, role, iat, exp} and are short-lived
(ACCESS_TOKEN_EXPIRATION_MINUTES). Refresh tokens are opaque random strings,
handed to the client only as an HttpOnly cookie (see app/routes/auth.py) and
stored server-side as a SHA-256 hash so the raw value is never persisted.
Each refresh rotates the token (single-use); replaying an already-rotated
token revokes every other active session for that user (see
rotate_refresh_token) since that can only happen via a copied/replayed token.
"""
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import current_app, request, jsonify, g

from app import db
from app.models import User
from app.models.refresh_token import RefreshToken


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
        "exp": now + timedelta(minutes=current_app.config["ACCESS_TOKEN_EXPIRATION_MINUTES"]),
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET_KEY"], algorithm="HS256")


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, current_app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired.")
    except jwt.InvalidTokenError:
        raise AuthError("Invalid token.")


def _hash_refresh_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def issue_refresh_token(user: User) -> str:
    """Create a new refresh-token session for `user` and return the raw
    (unhashed) token -- the only time it ever exists outside the client's
    cookie. Only its hash is persisted."""
    raw_token = secrets.token_urlsafe(64)
    now = datetime.utcnow()
    row = RefreshToken(
        user_id=user.id,
        token_hash=_hash_refresh_token(raw_token),
        created_at=now,
        expires_at=now + timedelta(days=current_app.config["REFRESH_TOKEN_EXPIRATION_DAYS"]),
    )
    db.session.add(row)
    db.session.commit()
    return raw_token


def revoke_all_refresh_tokens_for_user(user_id: str):
    now = datetime.utcnow()
    (
        RefreshToken.query
        .filter_by(user_id=user_id, revoked_at=None)
        .update({"revoked_at": now})
    )
    db.session.commit()


def revoke_refresh_token(raw_token: str):
    """Revoke the session named by `raw_token`, if it exists. Used by logout;
    a missing/already-revoked token is not an error -- logout should always
    succeed from the client's point of view."""
    if not raw_token:
        return
    row = RefreshToken.query.filter_by(token_hash=_hash_refresh_token(raw_token)).first()
    if row and row.revoked_at is None:
        row.revoked_at = datetime.utcnow()
        db.session.commit()


def rotate_refresh_token(raw_token: str) -> tuple[str, User]:
    """Validate `raw_token`, rotate it (revoke it, issue+return a
    replacement), and return (new_raw_token, user). Raises AuthError if the
    token is missing, unknown, expired, or already-rotated.

    Reuse detection: a token that's already revoked can only be presented
    again if it was copied by an attacker (rotation makes every token
    single-use), so that case revokes every other active session for the
    user rather than just rejecting the one request.
    """
    if not raw_token:
        raise AuthError("Missing refresh token.")

    row = RefreshToken.query.filter_by(token_hash=_hash_refresh_token(raw_token)).first()
    if not row:
        raise AuthError("Invalid refresh token.")

    if row.revoked_at is not None:
        revoke_all_refresh_tokens_for_user(row.user_id)
        raise AuthError("Refresh token reuse detected; all sessions revoked.")

    if row.expires_at <= datetime.utcnow():
        raise AuthError("Refresh token expired.")

    user = User.query.get(row.user_id)
    if not user or not user.is_active:
        raise AuthError("Account disabled.", 403)

    new_raw_token = issue_refresh_token(user)
    new_row = RefreshToken.query.filter_by(token_hash=_hash_refresh_token(new_raw_token)).first()
    row.revoked_at = datetime.utcnow()
    row.replaced_by_id = new_row.id
    db.session.commit()

    return new_raw_token, user


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
