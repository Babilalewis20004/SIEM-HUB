from flask import Blueprint, request, jsonify

from app.models import AuditLog
from app.auth.authorization import require_permission
from app.auth.permissions import AUDIT_READ
from app.utils.pagination import paginate

audit_bp = Blueprint("audit", __name__)


@audit_bp.route("", methods=["GET"])
@require_permission(AUDIT_READ)
def list_audit_log():
    q = AuditLog.query

    actor_id = request.args.get("actor_id")
    target_type = request.args.get("target_type")
    action = request.args.get("action")

    if actor_id:
        q = q.filter(AuditLog.actor_id == actor_id)
    if target_type:
        q = q.filter(AuditLog.target_type == target_type)
    if action:
        q = q.filter(AuditLog.action == action)

    q = q.order_by(AuditLog.created_at.desc())

    return jsonify(paginate(q, lambda a: a.to_dict()))
