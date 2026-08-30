from datetime import datetime

from flask import Blueprint, request, jsonify, g

from app import db
from app.models import Incident, IncidentNote, Alert, Event, User
from app.services.incidents import transition_status, InvalidTransition
from app.services.audit import log_action
from app.auth.authorization import require_permission
from app.auth.permissions import (
    INCIDENTS_READ, INCIDENTS_UPDATE, INCIDENTS_ASSIGN, INCIDENTS_RESOLVE, role_has_permission,
)

incidents_bp = Blueprint("incidents", __name__)

_WRITABLE_FIELDS = ["title", "description", "severity", "priority"]


@incidents_bp.route("", methods=["GET"])
@require_permission(INCIDENTS_READ)
def list_incidents():
    q = Incident.query

    status = request.args.get("status")
    severity = request.args.get("severity")
    priority = request.args.get("priority")
    assigned_to = request.args.get("assigned_to")
    source_ip = request.args.get("source_ip")
    hostname = request.args.get("hostname")
    created_after = request.args.get("created_after")
    updated_after = request.args.get("updated_after")

    if status:
        q = q.filter(Incident.status == status)
    if severity:
        q = q.filter(Incident.severity == severity)
    if priority:
        q = q.filter(Incident.priority == priority)
    if assigned_to:
        q = q.filter(Incident.assigned_to == assigned_to)
    if created_after:
        try:
            q = q.filter(Incident.created_at >= datetime.fromisoformat(created_after))
        except ValueError:
            return jsonify({"error": f"invalid created_after timestamp: {created_after!r}"}), 400
    if updated_after:
        try:
            q = q.filter(Incident.updated_at >= datetime.fromisoformat(updated_after))
        except ValueError:
            return jsonify({"error": f"invalid updated_after timestamp: {updated_after!r}"}), 400
    if source_ip or hostname:
        q = q.join(Alert, Alert.incident_id == Incident.id).join(Event, Alert.event_id == Event.id)
        if source_ip:
            q = q.filter(Event.source_ip == source_ip)
        if hostname:
            q = q.filter(Event.hostname == hostname)
        q = q.distinct()

    q = q.order_by(Incident.last_seen_at.desc().nullslast(), Incident.created_at.desc())

    page = max(int(request.args.get("page", 1)), 1)
    per_page = min(max(int(request.args.get("per_page", 50)), 1), 200)
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [i.to_dict(include_alerts=False) for i in items],
    })


@incidents_bp.route("/<incident_id>", methods=["GET"])
@require_permission(INCIDENTS_READ)
def get_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    return jsonify(incident.to_dict(include_alerts=True, include_notes=True))


@incidents_bp.route("", methods=["POST"])
@require_permission(INCIDENTS_UPDATE)
def create_incident():
    data = request.get_json() or {}
    if not data.get("title"):
        return jsonify({"error": "title is required."}), 400

    incident = Incident(
        title=data["title"],
        description=data.get("description"),
        severity=data.get("severity", "medium"),
        priority=data.get("priority", "medium"),
        status="open",
        created_by=g.current_user.id,
        first_seen_at=datetime.utcnow(),
        last_seen_at=datetime.utcnow(),
    )
    db.session.add(incident)
    db.session.flush()
    log_action(g.current_user, "incident.created", "incident", incident.id, {"title": incident.title})
    db.session.commit()
    return jsonify(incident.to_dict()), 201


@incidents_bp.route("/<incident_id>", methods=["PATCH"])
@require_permission(INCIDENTS_UPDATE)
def update_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    data = request.get_json() or {}

    for field in _WRITABLE_FIELDS:
        if field in data:
            setattr(incident, field, data[field])

    log_action(g.current_user, "incident.updated", "incident", incident.id, {"fields": list(data.keys())})
    db.session.commit()
    return jsonify(incident.to_dict())


@incidents_bp.route("/<incident_id>/assign", methods=["POST"])
@require_permission(INCIDENTS_ASSIGN)
def assign_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    data = request.get_json() or {}
    assignee_id = data.get("assigned_to")

    if assignee_id:
        assignee = User.query.get(assignee_id)
        if not assignee:
            return jsonify({"error": "No such user."}), 400
        if not assignee.is_active:
            return jsonify({"error": "Cannot assign an incident to a disabled user."}), 400

    incident.assigned_to = assignee_id or None
    log_action(g.current_user, "incident.assigned", "incident", incident.id, {"assigned_to": assignee_id})
    db.session.commit()
    return jsonify(incident.to_dict())


@incidents_bp.route("/<incident_id>/status", methods=["POST"])
@require_permission(INCIDENTS_UPDATE, INCIDENTS_RESOLVE)
def set_incident_status(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    data = request.get_json() or {}
    new_status = data.get("status")
    reopen = bool(data.get("reopen"))

    if not new_status:
        return jsonify({"error": "status is required."}), 400
    if new_status == "resolved" and not role_has_permission(g.current_user.role, INCIDENTS_RESOLVE):
        return jsonify({"error": "Forbidden: insufficient permissions."}), 403
    if new_status != "resolved" and not role_has_permission(g.current_user.role, INCIDENTS_UPDATE):
        return jsonify({"error": "Forbidden: insufficient permissions."}), 403

    try:
        transition_status(incident, new_status, reopen=reopen, actor=g.current_user)
    except InvalidTransition as e:
        return jsonify({"error": str(e)}), 400

    log_action(g.current_user, "incident.status_changed", "incident", incident.id,
               {"to": new_status, "reopen": reopen})
    db.session.commit()
    return jsonify(incident.to_dict())


@incidents_bp.route("/<incident_id>/notes", methods=["POST"])
@require_permission(INCIDENTS_UPDATE)
def add_note(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    data = request.get_json() or {}
    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"error": "content is required."}), 400

    note = IncidentNote(incident_id=incident.id, author_id=g.current_user.id, content=content)
    db.session.add(note)
    log_action(g.current_user, "incident.note_added", "incident", incident.id)
    db.session.commit()
    return jsonify(note.to_dict()), 201
