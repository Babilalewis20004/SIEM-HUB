from flask import Blueprint, request, jsonify, g

from app import db
from app.models import User
from app.auth.permissions import ROLES, USERS_READ, USERS_MANAGE
from app.auth.authorization import require_permission
from app.events import bus
from app.services.audit import log_action

users_bp = Blueprint("users", __name__)


def _active_admin_count(exclude_id=None):
    q = User.query.filter_by(role="admin", is_active=True)
    if exclude_id:
        q = q.filter(User.id != exclude_id)
    return q.count()


@users_bp.route("", methods=["GET"])
@require_permission(USERS_READ)
def list_users():
    users = User.query.order_by(User.created_at.asc()).all()
    return jsonify([u.to_dict() for u in users])


@users_bp.route("/<user_id>", methods=["GET"])
@require_permission(USERS_READ)
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())


@users_bp.route("/<user_id>", methods=["PATCH"])
@require_permission(USERS_MANAGE)
def update_user(user_id):
    """Non-security metadata only. Role and active-status changes go through
    their own dedicated, more carefully guarded endpoints below."""
    user = User.query.get_or_404(user_id)
    data = request.get_json() or {}

    if "email" in data:
        email = (data["email"] or "").strip().lower()
        if not email:
            return jsonify({"error": "email cannot be empty."}), 400
        if User.query.filter(User.email == email, User.id != user.id).first():
            return jsonify({"error": "An account with that email already exists."}), 409
        user.email = email

    log_action(g.current_user, "user.updated", "user", user.id, {"fields": list(data.keys())})
    db.session.commit()
    return jsonify(user.to_dict())


@users_bp.route("/<user_id>/role", methods=["PATCH"])
@require_permission(USERS_MANAGE)
def update_role(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json() or {}
    new_role = data.get("role")

    if new_role not in ROLES:
        return jsonify({"error": f"role must be one of {ROLES}"}), 400
    if user.id == g.current_user.id:
        return jsonify({"error": "You cannot change your own role."}), 403
    if user.role == "admin" and new_role != "admin" and _active_admin_count(exclude_id=user.id) < 1:
        return jsonify({"error": "Cannot remove the last active administrator."}), 409

    old_role = user.role
    user.role = new_role
    log_action(g.current_user, "user.role_changed", "user", user.id,
               {"from": old_role, "to": new_role})
    db.session.commit()
    bus.publish("user.role_changed", {"user_id": user.id, "from": old_role, "to": new_role})
    return jsonify(user.to_dict())


@users_bp.route("/<user_id>/status", methods=["PATCH"])
@require_permission(USERS_MANAGE)
def update_status(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json() or {}

    if "is_active" not in data or not isinstance(data["is_active"], bool):
        return jsonify({"error": "is_active (boolean) is required."}), 400
    new_status = data["is_active"]

    if user.id == g.current_user.id and not new_status:
        return jsonify({"error": "You cannot disable your own account."}), 403
    if user.role == "admin" and not new_status and _active_admin_count(exclude_id=user.id) < 1:
        return jsonify({"error": "Cannot disable the last active administrator."}), 409

    user.is_active = new_status
    log_action(g.current_user, "user.status_changed", "user", user.id, {"is_active": new_status})
    db.session.commit()
    if not new_status:
        bus.publish("user.disabled", {"user_id": user.id})
    return jsonify(user.to_dict())
