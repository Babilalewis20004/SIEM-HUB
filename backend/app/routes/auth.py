import re

from flask import Blueprint, current_app, request, jsonify, make_response

from app import db, limiter
from app.models import User
from app.services.audit import log_action
from app.utils.auth import (
    encode_token,
    require_auth,
    get_current_user,
    issue_refresh_token,
    rotate_refresh_token,
    revoke_refresh_token,
    AuthError,
)

auth_bp = Blueprint("auth", __name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# Scoped to /api/auth (not the narrower /api/auth/refresh) because cookie
# path-matching is prefix-only against the *browser's request path*, not
# against sibling routes -- a cookie scoped to /api/auth/refresh is never
# sent to /api/auth/logout, which would silently break logout's revoke.
REFRESH_COOKIE_PATH = "/api/auth"


def _set_refresh_cookie(response, raw_refresh_token):
    response.set_cookie(
        current_app.config["REFRESH_COOKIE_NAME"],
        raw_refresh_token,
        httponly=True,
        secure=current_app.config["REFRESH_COOKIE_SECURE"],
        samesite="Strict",
        path=REFRESH_COOKIE_PATH,
        max_age=current_app.config["REFRESH_TOKEN_EXPIRATION_DAYS"] * 86400,
    )


def _clear_refresh_cookie(response):
    response.delete_cookie(
        current_app.config["REFRESH_COOKIE_NAME"],
        path=REFRESH_COOKIE_PATH,
    )


def _get_refresh_cookie():
    return request.cookies.get(current_app.config["REFRESH_COOKIE_NAME"])


@auth_bp.route("/register", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_REGISTER"])
def register():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not EMAIL_RE.match(email):
        return jsonify({"error": "Provide a valid email address."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "An account with that email already exists."}), 409

    # First user to register becomes admin (bootstrapping the system); every
    # subsequent self-registration is a viewer (least privilege) — an admin
    # promotes trusted accounts to analyst via PATCH /api/users/<id>/role.
    # `role` is never accepted from the request body (mass-assignment guard).
    role = "admin" if User.query.count() == 0 else "viewer"

    user = User(email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    token = encode_token(user)
    refresh_token = issue_refresh_token(user)
    response = jsonify({"token": token, "user": user.to_dict()})
    _set_refresh_cookie(response, refresh_token)
    return response, 201


@auth_bp.route("/login", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_LOGIN"])
def login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid email or password."}), 401
    if not user.is_active:
        return jsonify({"error": "This account has been disabled."}), 403

    token = encode_token(user)
    refresh_token = issue_refresh_token(user)
    response = jsonify({"token": token, "user": user.to_dict()})
    _set_refresh_cookie(response, refresh_token)
    return response


@auth_bp.route("/refresh", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_REFRESH"])
def refresh():
    try:
        new_refresh_token, user = rotate_refresh_token(_get_refresh_cookie())
    except AuthError as e:
        response = jsonify({"error": e.message})
        _clear_refresh_cookie(response)
        return response, e.status_code

    log_action(user, action="token_refresh", target_type="user", target_id=user.id)
    token = encode_token(user)
    response = jsonify({"token": token})
    _set_refresh_cookie(response, new_refresh_token)
    return response


@auth_bp.route("/logout", methods=["POST"])
def logout():
    raw_refresh_token = _get_refresh_cookie()
    try:
        actor = get_current_user()
    except AuthError:
        actor = None
    revoke_refresh_token(raw_refresh_token)
    if actor:
        log_action(actor, action="logout", target_type="user", target_id=actor.id)
    response = make_response("", 204)
    _clear_refresh_cookie(response)
    return response


@auth_bp.route("/me", methods=["GET"])
@require_auth
def me():
    from flask import g
    return jsonify(g.current_user.to_dict())
