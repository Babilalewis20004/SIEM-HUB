from datetime import datetime

from flask import Blueprint, request, jsonify

from app import db
from app.models import Log
from app.utils.parsers import parse_line

logs_bp = Blueprint("logs", __name__)


@logs_bp.route("/upload", methods=["POST"])
def upload_logs():
    """
    Accepts either:
    - multipart file upload (field name 'file'), one log line per row
    - JSON body: {"source": "nginx", "host": "web01", "lines": ["...", "..."]}
    """
    source_hint = request.form.get("source") or request.args.get("source", "generic")
    host = request.form.get("host") or request.args.get("host")

    lines = []

    if "file" in request.files:
        f = request.files["file"]
        content = f.read().decode("utf-8", errors="ignore")
        lines = content.splitlines()
    elif request.is_json:
        payload = request.get_json()
        lines = payload.get("lines", [])
        source_hint = payload.get("source", source_hint)
        host = payload.get("host", host)
    else:
        return jsonify({"error": "Provide a 'file' upload or JSON body with 'lines'"}), 400

    created = 0
    for raw_line in lines:
        parsed = parse_line(raw_line, source_hint=source_hint, host=host)
        if not parsed:
            continue
        log = Log(**parsed)
        db.session.add(log)
        created += 1

    db.session.commit()
    return jsonify({"ingested": created}), 201


@logs_bp.route("", methods=["GET"])
def list_logs():
    q = Log.query

    source = request.args.get("source")
    severity = request.args.get("severity")
    event_type = request.args.get("event_type")
    start = request.args.get("start")
    end = request.args.get("end")
    search = request.args.get("q")

    if source:
        q = q.filter(Log.source == source)
    if severity:
        q = q.filter(Log.severity == severity)
    if event_type:
        q = q.filter(Log.event_type == event_type)
    if start:
        q = q.filter(Log.timestamp >= datetime.fromisoformat(start))
    if end:
        q = q.filter(Log.timestamp <= datetime.fromisoformat(end))
    if search:
        q = q.filter(Log.raw_message.ilike(f"%{search}%"))

    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 200)

    q = q.order_by(Log.timestamp.desc())
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [log.to_dict() for log in items],
    })


@logs_bp.route("/<log_id>", methods=["GET"])
def get_log(log_id):
    log = Log.query.get_or_404(log_id)
    return jsonify(log.to_dict())
