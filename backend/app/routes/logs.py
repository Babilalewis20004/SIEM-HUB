from datetime import datetime

from flask import Blueprint, request, jsonify

from app import db
from app.models import Event
from app.services.normalization import normalize_line
from app.services.validation import validate_event_data, EventValidationError
from app.auth.authorization import require_permission
from app.auth.permissions import EVENTS_READ, LOGS_UPLOAD

logs_bp = Blueprint("logs", __name__)

# A single upload shouldn't be able to hang the request indefinitely; MAX_CONTENT_LENGTH
# already caps request size, this caps line count for JSON-body uploads too.
MAX_LINES_PER_UPLOAD = 50_000


@logs_bp.route("/upload", methods=["POST"])
@require_permission(LOGS_UPLOAD)
def upload_logs():
    """
    Ingestion pipeline: upload -> detect format -> parse -> normalise ->
    validate -> store Event. One malformed line never fails the whole batch.

    Accepts either:
    - multipart file upload (field name 'file'), one log line per row
    - JSON body: {"source": "nginx", "host": "web01", "lines": ["...", "..."]}
    """
    source_hint = request.form.get("source") or request.args.get("source", "generic")
    host = request.form.get("host") or request.args.get("host")

    if "file" in request.files:
        f = request.files["file"]
        content = f.read().decode("utf-8", errors="ignore")
        lines = content.splitlines()
    elif request.is_json:
        payload = request.get_json() or {}
        lines = payload.get("lines", [])
        if not isinstance(lines, list):
            return jsonify({"error": "'lines' must be a list of strings"}), 400
        source_hint = payload.get("source", source_hint)
        host = payload.get("host", host)
    else:
        return jsonify({"error": "Provide a 'file' upload or JSON body with 'lines'"}), 400

    lines = lines[:MAX_LINES_PER_UPLOAD]

    stats = {"total_lines": 0, "parsed": 0, "normalised": 0, "failed": 0, "stored": 0}
    events = []

    for raw_line in lines:
        raw_line = "" if raw_line is None else str(raw_line)
        if not raw_line.strip():
            continue
        stats["total_lines"] += 1

        try:
            normalized = normalize_line(raw_line, source_hint=source_hint, host=host)
        except ValueError:
            stats["failed"] += 1
            continue

        if normalized is None:
            continue
        stats["parsed"] += 1

        try:
            validated = validate_event_data(normalized)
        except EventValidationError:
            stats["failed"] += 1
            continue
        stats["normalised"] += 1

        events.append(Event(**validated))

    db.session.add_all(events)
    db.session.commit()
    stats["stored"] = len(events)

    return jsonify({**stats, "ingested": stats["stored"]}), 201


@logs_bp.route("", methods=["GET"])
@require_permission(EVENTS_READ)
def list_logs():
    q = Event.query

    source_type = request.args.get("source_type") or request.args.get("source")
    event_type = request.args.get("event_type")
    category = request.args.get("category")
    severity = request.args.get("severity")
    source_ip = request.args.get("source_ip")
    destination_ip = request.args.get("destination_ip")
    hostname = request.args.get("hostname") or request.args.get("host")
    username = request.args.get("username")
    outcome = request.args.get("outcome")
    start = request.args.get("start")
    end = request.args.get("end")
    search = request.args.get("q")

    if source_type:
        q = q.filter(Event.source_type == source_type)
    if event_type:
        q = q.filter(Event.event_type == event_type)
    if category:
        q = q.filter(Event.category == category)
    if severity:
        q = q.filter(Event.severity == severity)
    if source_ip:
        q = q.filter(Event.source_ip == source_ip)
    if destination_ip:
        q = q.filter(Event.destination_ip == destination_ip)
    if hostname:
        q = q.filter(Event.hostname == hostname)
    if username:
        q = q.filter(Event.username == username)
    if outcome:
        q = q.filter(Event.outcome == outcome)
    if start:
        try:
            q = q.filter(Event.timestamp >= datetime.fromisoformat(start))
        except ValueError:
            return jsonify({"error": f"invalid start timestamp: {start!r}"}), 400
    if end:
        try:
            q = q.filter(Event.timestamp <= datetime.fromisoformat(end))
        except ValueError:
            return jsonify({"error": f"invalid end timestamp: {end!r}"}), 400
    if search:
        q = q.filter(Event.raw_message.ilike(f"%{search}%"))

    page = max(int(request.args.get("page", 1)), 1)
    per_page = min(max(int(request.args.get("per_page", 50)), 1), 200)

    q = q.order_by(Event.timestamp.desc())
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [event.to_dict() for event in items],
    })


@logs_bp.route("/<event_id>", methods=["GET"])
@require_permission(EVENTS_READ)
def get_log(event_id):
    event = Event.query.get_or_404(event_id)
    return jsonify(event.to_dict())
