from datetime import datetime

from flask import Blueprint, current_app, request, jsonify
from sqlalchemy import case, func

from app import db, limiter
from app.models import Event
from app.models.event import SEVERITY_LEVELS
from app.services.normalization import normalize_line
from app.services.validation import validate_event_data, EventValidationError
from app.auth.authorization import require_permission
from app.auth.permissions import EVENTS_READ, LOGS_UPLOAD
from app.utils.pagination import get_pagination_params, paginate

logs_bp = Blueprint("logs", __name__)

# A single upload shouldn't be able to hang the request indefinitely; MAX_CONTENT_LENGTH
# already caps request size, this caps line count for JSON-body uploads too.
MAX_LINES_PER_UPLOAD = 50_000


@logs_bp.route("/upload", methods=["POST"])
@require_permission(LOGS_UPLOAD)
@limiter.limit(lambda: current_app.config["RATELIMIT_UPLOAD"])
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


# Whitelisted, not read off Event dynamically -- keeps ?sort=/?group_by= from
# ever turning into arbitrary attribute access on the model.
SORTABLE_FIELDS = (
    "timestamp", "severity", "event_type", "category", "source_type",
    "source_ip", "destination_ip", "hostname", "username", "outcome",
)
GROUPABLE_FIELDS = (
    "source_type", "event_type", "category", "severity",
    "source_ip", "destination_ip", "hostname", "username", "outcome",
)

# severity is a free-text column ("critical"/"high"/...), so an ORDER BY or
# MAX() on it directly sorts alphabetically ("critical" < "high" < ...) --
# meaningless for severity. This CASE maps it to a rank int first.
_SEVERITY_RANK = case(
    *[(Event.severity == level, rank) for rank, level in enumerate(SEVERITY_LEVELS)],
    else_=0,
)
_RANK_TO_SEVERITY = dict(enumerate(SEVERITY_LEVELS))


def _apply_filters(q):
    """Shared by list_logs and grouped_logs so the two never drift apart."""
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
        q = q.filter(Event.timestamp >= datetime.fromisoformat(start))
    if end:
        q = q.filter(Event.timestamp <= datetime.fromisoformat(end))
    if search:
        q = q.filter(Event.raw_message.ilike(f"%{search}%"))

    return q


@logs_bp.route("", methods=["GET"])
@require_permission(EVENTS_READ)
def list_logs():
    try:
        q = _apply_filters(Event.query)
    except ValueError as exc:
        return jsonify({"error": f"invalid start/end timestamp: {exc}"}), 400

    sort_by = request.args.get("sort", "timestamp")
    order = request.args.get("order", "desc")
    if sort_by not in SORTABLE_FIELDS:
        return jsonify({"error": f"invalid sort field: {sort_by!r}"}), 400
    if order not in ("asc", "desc"):
        return jsonify({"error": f"invalid order: {order!r} (must be 'asc' or 'desc')"}), 400

    sort_col = _SEVERITY_RANK if sort_by == "severity" else getattr(Event, sort_by)
    q = q.order_by(sort_col.asc() if order == "asc" else sort_col.desc())

    result = paginate(q, lambda event: event.to_dict())
    result["sort"] = sort_by
    result["order"] = order
    return jsonify(result)


@logs_bp.route("/grouped", methods=["GET"])
@require_permission(EVENTS_READ)
def grouped_logs():
    """
    Aggregate the same filtered event set list_logs would return into counts
    per distinct value of `group_by` -- e.g. "which source IPs are showing up
    the most", filtered the same way the raw table is. Registered before
    /<event_id> so Werkzeug's routing doesn't need "grouped" to look like an id
    (static rules are matched before variable ones regardless of order, but
    keeping it adjacent to list_logs above reads better).
    """
    group_by = request.args.get("group_by", "source_ip")
    if group_by not in GROUPABLE_FIELDS:
        return jsonify({"error": f"invalid group_by field: {group_by!r}"}), 400

    try:
        q = _apply_filters(Event.query)
    except ValueError as exc:
        return jsonify({"error": f"invalid start/end timestamp: {exc}"}), 400

    group_col = getattr(Event, group_by)
    rows = (
        q.with_entities(
            group_col,
            func.count(Event.id),
            func.max(Event.timestamp),
            func.max(_SEVERITY_RANK),
        )
        .group_by(group_col)
        .order_by(func.count(Event.id).desc())
        .all()
    )

    page, per_page = get_pagination_params()
    total = len(rows)
    page_rows = rows[(page - 1) * per_page: (page - 1) * per_page + per_page]

    return jsonify({
        "group_by": group_by,
        "total": total,
        "page": page,
        "per_page": per_page,
        "groups": [
            {
                "key": key,
                "count": count,
                "last_seen": last_seen.isoformat() if last_seen else None,
                "max_severity": _RANK_TO_SEVERITY.get(max_rank, "info"),
            }
            for key, count, last_seen, max_rank in page_rows
        ],
    })


@logs_bp.route("/<event_id>", methods=["GET"])
@require_permission(EVENTS_READ)
def get_log(event_id):
    event = Event.query.get_or_404(event_id)
    return jsonify(event.to_dict())
