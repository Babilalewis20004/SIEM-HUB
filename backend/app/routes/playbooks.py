"""
Playbook + playbook-execution REST API. Two blueprints because the URL
convention splits them (/api/playbooks vs /api/playbook-executions, see
docs/ARCHITECTURE.md) even though they share one module -- both are
protected the same way as every other blueprint (app/__init__.py's
protected_blueprints + per-route @require_permission).

Approval separation-of-duties (Part J.27) is enforced here, not just by
RBAC: PLAYBOOKS_APPROVE lets a user approve *someone else's* high-risk
request, but never their own -- see approve_execution below.
"""
from datetime import datetime

from flask import Blueprint, request, jsonify, g, current_app

from app import db
from app.models import Incident, Alert
from app.playbooks.models import Playbook, PlaybookExecution, PlaybookApproval
from app.playbooks.validators import validate_playbook_definition
from app.playbooks.registry import list_actions
from app.playbooks import engine
from app.events import bus
from app.services.audit import log_action
from app.auth.authorization import require_permission
from app.auth.permissions import (
    PLAYBOOKS_READ, PLAYBOOKS_MANAGE, PLAYBOOKS_EXECUTE, PLAYBOOKS_APPROVE,
)
from app.utils.pagination import paginate

playbooks_bp = Blueprint("playbooks", __name__)
playbook_executions_bp = Blueprint("playbook_executions", __name__)

_DEFINITION_FIELDS = ("name", "description", "trigger_type", "trigger_condition", "steps", "enabled")


@playbooks_bp.route("", methods=["GET"])
@require_permission(PLAYBOOKS_READ)
def list_playbooks():
    return jsonify([p.to_dict() for p in Playbook.query.order_by(Playbook.name).all()])


@playbooks_bp.route("/actions", methods=["GET"])
@require_permission(PLAYBOOKS_READ)
def list_registered_actions():
    return jsonify(list_actions())


@playbooks_bp.route("/<playbook_id>", methods=["GET"])
@require_permission(PLAYBOOKS_READ)
def get_playbook(playbook_id):
    return jsonify(Playbook.query.get_or_404(playbook_id).to_dict())


@playbooks_bp.route("", methods=["POST"])
@require_permission(PLAYBOOKS_MANAGE)
def create_playbook():
    data = request.get_json() or {}
    errors = validate_playbook_definition(data)
    if errors:
        return jsonify({"error": "Invalid playbook definition.", "details": errors}), 400
    if Playbook.query.filter_by(name=data["name"].strip()).first():
        return jsonify({"error": "A playbook with this name already exists."}), 409

    playbook = Playbook(
        name=data["name"].strip(),
        description=data.get("description"),
        trigger_type=data.get("trigger_type", "manual"),
        trigger_condition=data.get("trigger_condition") or {},
        steps=data["steps"],
        enabled=bool(data.get("enabled", True)),
        created_by=g.current_user.id,
    )
    db.session.add(playbook)
    db.session.flush()
    log_action(g.current_user, "playbook.created", "playbook", playbook.id, {"name": playbook.name})
    db.session.commit()
    return jsonify(playbook.to_dict()), 201


@playbooks_bp.route("/<playbook_id>", methods=["PATCH"])
@require_permission(PLAYBOOKS_MANAGE)
def update_playbook(playbook_id):
    playbook = Playbook.query.get_or_404(playbook_id)
    data = request.get_json() or {}

    merged = playbook.to_dict()
    merged.update({k: v for k, v in data.items() if k in _DEFINITION_FIELDS})
    errors = validate_playbook_definition(merged)
    if errors:
        return jsonify({"error": "Invalid playbook definition.", "details": errors}), 400

    for field in _DEFINITION_FIELDS:
        if field in data:
            setattr(playbook, field, data[field])
    playbook.version += 1

    log_action(g.current_user, "playbook.updated", "playbook", playbook.id, {"fields": list(data.keys())})
    db.session.commit()
    return jsonify(playbook.to_dict())


@playbooks_bp.route("/<playbook_id>", methods=["DELETE"])
@require_permission(PLAYBOOKS_MANAGE)
def delete_playbook(playbook_id):
    playbook = Playbook.query.get_or_404(playbook_id)
    if PlaybookExecution.query.filter_by(playbook_id=playbook.id).first():
        return jsonify({
            "error": "This playbook has execution history and cannot be deleted (it would destroy "
                     "audit/investigation evidence). Disable it instead."
        }), 409
    log_action(g.current_user, "playbook.deleted", "playbook", playbook.id, {"name": playbook.name})
    db.session.delete(playbook)
    db.session.commit()
    return "", 204


@playbooks_bp.route("/<playbook_id>/execute", methods=["POST"])
@require_permission(PLAYBOOKS_EXECUTE)
def execute_playbook(playbook_id):
    playbook = Playbook.query.get_or_404(playbook_id)
    if not playbook.enabled:
        return jsonify({"error": "This playbook is disabled."}), 409

    data = request.get_json() or {}
    mode = data.get("mode", "manual")
    if mode not in ("manual", "dry_run"):
        return jsonify({"error": "mode must be 'manual' or 'dry_run'."}), 400

    incident = None
    if data.get("incident_id"):
        incident = Incident.query.get(data["incident_id"])
        if incident is None:
            return jsonify({"error": "No such incident."}), 400
    alert = None
    if data.get("alert_id"):
        alert = Alert.query.get(data["alert_id"])
        if alert is None:
            return jsonify({"error": "No such alert."}), 400

    execution = PlaybookExecution(
        playbook_id=playbook.id, incident_id=incident.id if incident else None,
        alert_id=alert.id if alert else None, triggered_by=g.current_user.id,
        status="pending", mode=mode,
    )
    db.session.add(execution)
    db.session.flush()
    log_action(g.current_user, "playbook.executed", "playbook_execution", execution.id,
               {"playbook_id": playbook.id, "mode": mode})
    db.session.commit()

    engine.start_execution_async(current_app._get_current_object(), execution.id)
    return jsonify(execution.to_dict()), 202


# ---- /api/playbook-executions ----------------------------------------------

@playbook_executions_bp.route("", methods=["GET"])
@require_permission(PLAYBOOKS_READ)
def list_executions():
    q = PlaybookExecution.query

    for field, column in (("status", PlaybookExecution.status), ("playbook_id", PlaybookExecution.playbook_id),
                           ("incident_id", PlaybookExecution.incident_id), ("alert_id", PlaybookExecution.alert_id)):
        value = request.args.get(field)
        if value:
            q = q.filter(column == value)

    q = q.order_by(PlaybookExecution.started_at.desc())

    return jsonify(paginate(q, lambda e: e.to_dict(include_logs=False)))


@playbook_executions_bp.route("/<execution_id>", methods=["GET"])
@require_permission(PLAYBOOKS_READ)
def get_execution(execution_id):
    return jsonify(PlaybookExecution.query.get_or_404(execution_id).to_dict())


def _pending_approval_or_404(execution):
    approval = PlaybookApproval.query.filter_by(execution_id=execution.id, status="pending").first()
    if approval is None:
        return None, (jsonify({"error": "No pending approval for this execution."}), 409)
    return approval, None


@playbook_executions_bp.route("/<execution_id>/approve", methods=["POST"])
@require_permission(PLAYBOOKS_APPROVE)
def approve_execution(execution_id):
    execution = PlaybookExecution.query.get_or_404(execution_id)
    approval, error_response = _pending_approval_or_404(execution)
    if error_response:
        return error_response

    # Separation of duties: a person can never approve their own request.
    # An automatic trigger has no requester (triggered_by is None), so
    # there's nothing to conflict with.
    if execution.triggered_by and execution.triggered_by == g.current_user.id:
        return jsonify({"error": "You cannot approve a playbook execution you requested yourself."}), 403

    approval.status = "approved"
    approval.approved_at = datetime.utcnow()
    approval.approved_by = g.current_user.id
    execution.status = "running"
    log_action(g.current_user, "playbook.approved", "playbook_execution", execution.id,
               {"approval_id": approval.id, "action": approval.action})
    db.session.commit()

    engine.start_execution_async(current_app._get_current_object(), execution.id)
    return jsonify(execution.to_dict())


@playbook_executions_bp.route("/<execution_id>/reject", methods=["POST"])
@require_permission(PLAYBOOKS_APPROVE)
def reject_execution(execution_id):
    execution = PlaybookExecution.query.get_or_404(execution_id)
    approval, error_response = _pending_approval_or_404(execution)
    if error_response:
        return error_response

    if execution.triggered_by and execution.triggered_by == g.current_user.id:
        return jsonify({"error": "You cannot reject a playbook execution you requested yourself."}), 403

    data = request.get_json() or {}
    approval.status = "rejected"
    approval.rejected_at = datetime.utcnow()
    approval.rejected_by = g.current_user.id
    approval.reason = data.get("reason")
    log_action(g.current_user, "playbook.rejected", "playbook_execution", execution.id,
               {"approval_id": approval.id, "action": approval.action, "reason": approval.reason})
    db.session.commit()

    engine.start_execution_async(current_app._get_current_object(), execution.id)
    return jsonify(execution.to_dict())


@playbook_executions_bp.route("/<execution_id>/cancel", methods=["POST"])
@require_permission(PLAYBOOKS_EXECUTE)
def cancel_execution(execution_id):
    execution = PlaybookExecution.query.get_or_404(execution_id)

    if g.current_user.role != "admin" and execution.triggered_by != g.current_user.id:
        return jsonify({"error": "You may only cancel playbook executions you triggered yourself."}), 403
    if execution.status not in ("pending", "awaiting_approval"):
        return jsonify({"error": f"Cannot cancel an execution that is already {execution.status}."}), 409

    execution.status = "cancelled"
    execution.completed_at = datetime.utcnow()
    log_action(g.current_user, "playbook.cancelled", "playbook_execution", execution.id)
    db.session.commit()

    bus.publish("playbook.cancelled", {
        "execution_id": execution.id, "playbook_id": execution.playbook_id,
    })
    return jsonify(execution.to_dict())
