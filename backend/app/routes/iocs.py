import csv
import io
from datetime import datetime

from flask import Blueprint, request, jsonify, g

from app import db
from app.models.ioc import IOC, IOCMatch, INDICATOR_TYPES, THREAT_LEVELS
from app.services.ioc_normalization import validate_indicator, sanitize_text
from app.services.audit import log_action
from app.auth.authorization import require_permission
from app.auth.permissions import IOCS_READ, IOCS_MANAGE

iocs_bp = Blueprint("iocs", __name__)

# Mirrors MAX_LINES_PER_UPLOAD in app/routes/logs.py -- one import shouldn't
# be able to hang the request indefinitely.
MAX_IOCS_PER_IMPORT = 5000

_WRITABLE_FIELDS = ["threat_level", "confidence", "source", "description", "expires_at", "enabled"]


def _coerce_bool(value):
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes")
    return bool(value)


def _parse_expires_at(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)


@iocs_bp.route("", methods=["GET"])
@require_permission(IOCS_READ)
def list_iocs():
    q = IOC.query

    indicator_type = request.args.get("type")
    threat_level = request.args.get("threat_level")
    source = request.args.get("source")
    indicator = request.args.get("indicator")
    enabled = request.args.get("enabled")

    if indicator_type:
        q = q.filter(IOC.indicator_type == indicator_type)
    if threat_level:
        q = q.filter(IOC.threat_level == threat_level)
    if source:
        q = q.filter(IOC.source == source)
    if indicator:
        q = q.filter(IOC.normalized_indicator.ilike(f"%{indicator.lower()}%"))
    if enabled is not None:
        q = q.filter(IOC.enabled.is_(enabled.lower() in ("1", "true", "yes")))

    q = q.order_by(IOC.created_at.desc())

    page = max(int(request.args.get("page", 1)), 1)
    per_page = min(max(int(request.args.get("per_page", 50)), 1), 200)
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [i.to_dict() for i in items],
    })


@iocs_bp.route("/<ioc_id>", methods=["GET"])
@require_permission(IOCS_READ)
def get_ioc(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)
    return jsonify(ioc.to_dict())


@iocs_bp.route("/<ioc_id>/matches", methods=["GET"])
@require_permission(IOCS_READ)
def get_ioc_matches(ioc_id):
    IOC.query.get_or_404(ioc_id)
    matches = (
        IOCMatch.query.filter_by(ioc_id=ioc_id).order_by(IOCMatch.created_at.desc()).limit(200).all()
    )
    return jsonify([m.to_dict(include_ioc=False) for m in matches])


def _build_ioc_from_payload(data, existing=None):
    """Validate + normalise one IOC payload. Returns (ioc_or_None, error_or_None)."""
    indicator_type = (data.get("indicator_type") or "").strip().lower()
    indicator = data.get("indicator")
    if not indicator or indicator_type not in INDICATOR_TYPES:
        return None, f"indicator and a valid indicator_type ({', '.join(INDICATOR_TYPES)}) are required"

    ok, normalized_or_error = validate_indicator(indicator_type, indicator)
    if not ok:
        return None, normalized_or_error

    threat_level = (data.get("threat_level") or "unknown").strip().lower()
    if threat_level not in THREAT_LEVELS:
        return None, f"invalid threat_level: {threat_level!r}"

    try:
        confidence = int(data.get("confidence", 50))
    except (TypeError, ValueError):
        return None, f"invalid confidence: {data.get('confidence')!r}"
    confidence = max(0, min(100, confidence))

    try:
        expires_at = _parse_expires_at(data.get("expires_at"))
    except ValueError:
        return None, f"invalid expires_at: {data.get('expires_at')!r}"

    ioc = existing or IOC()
    ioc.indicator = str(indicator).strip()
    ioc.indicator_type = indicator_type
    ioc.normalized_indicator = normalized_or_error
    ioc.threat_level = threat_level
    ioc.confidence = confidence
    ioc.source = sanitize_text(data.get("source"))
    ioc.description = sanitize_text(data.get("description"))
    ioc.expires_at = expires_at
    ioc.enabled = _coerce_bool(data.get("enabled", True))
    ioc.last_seen_at = datetime.utcnow()
    return ioc, None


@iocs_bp.route("", methods=["POST"])
@require_permission(IOCS_MANAGE)
def create_ioc():
    data = request.get_json() or {}
    ioc, error = _build_ioc_from_payload(data)
    if error:
        return jsonify({"error": error}), 400

    existing = IOC.query.filter_by(
        indicator_type=ioc.indicator_type, normalized_indicator=ioc.normalized_indicator
    ).first()
    if existing:
        return jsonify({"error": "An IOC with this indicator already exists.", "id": existing.id}), 409

    db.session.add(ioc)
    db.session.flush()
    log_action(g.current_user, "ioc.created", "ioc", ioc.id, {"indicator": ioc.indicator})
    db.session.commit()
    return jsonify(ioc.to_dict()), 201


@iocs_bp.route("/<ioc_id>", methods=["PATCH"])
@require_permission(IOCS_MANAGE)
def update_ioc(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)
    data = request.get_json() or {}

    if "threat_level" in data and data["threat_level"] not in THREAT_LEVELS:
        return jsonify({"error": f"invalid threat_level: {data['threat_level']!r}"}), 400
    if "confidence" in data:
        try:
            data["confidence"] = max(0, min(100, int(data["confidence"])))
        except (TypeError, ValueError):
            return jsonify({"error": f"invalid confidence: {data['confidence']!r}"}), 400
    if "expires_at" in data:
        try:
            data["expires_at"] = _parse_expires_at(data["expires_at"])
        except ValueError:
            return jsonify({"error": f"invalid expires_at: {data['expires_at']!r}"}), 400
    if "source" in data:
        data["source"] = sanitize_text(data["source"])
    if "description" in data:
        data["description"] = sanitize_text(data["description"])

    for field in _WRITABLE_FIELDS:
        if field in data:
            setattr(ioc, field, data[field])

    log_action(g.current_user, "ioc.updated", "ioc", ioc.id, {"fields": list(data.keys())})
    db.session.commit()
    return jsonify(ioc.to_dict())


@iocs_bp.route("/<ioc_id>", methods=["DELETE"])
@require_permission(IOCS_MANAGE)
def delete_ioc(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)
    if IOCMatch.query.filter_by(ioc_id=ioc.id).first():
        return jsonify({
            "error": "This IOC has match history and cannot be deleted (it would destroy "
                     "investigation evidence). Disable it instead."
        }), 409
    log_action(g.current_user, "ioc.deleted", "ioc", ioc.id, {"indicator": ioc.indicator})
    db.session.delete(ioc)
    db.session.commit()
    return "", 204


@iocs_bp.route("/<ioc_id>/enable", methods=["POST"])
@require_permission(IOCS_MANAGE)
def enable_ioc(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)
    ioc.enabled = True
    log_action(g.current_user, "ioc.enabled", "ioc", ioc.id)
    db.session.commit()
    return jsonify(ioc.to_dict())


@iocs_bp.route("/<ioc_id>/disable", methods=["POST"])
@require_permission(IOCS_MANAGE)
def disable_ioc(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)
    ioc.enabled = False
    log_action(g.current_user, "ioc.disabled", "ioc", ioc.id)
    db.session.commit()
    return jsonify(ioc.to_dict())


def _rows_from_request():
    """Returns (rows: list[dict], error_response_or_None)."""
    if "file" in request.files:
        content = request.files["file"].read().decode("utf-8", errors="ignore")
        return list(csv.DictReader(io.StringIO(content))), None

    if request.content_type and "csv" in request.content_type:
        content = request.get_data(as_text=True)
        return list(csv.DictReader(io.StringIO(content))), None

    if request.is_json:
        payload = request.get_json() or {}
        rows = payload.get("iocs", payload if isinstance(payload, list) else [])
        if not isinstance(rows, list):
            return None, (jsonify({"error": "'iocs' must be a list"}), 400)
        return rows, None

    return None, (jsonify({"error": "Provide a JSON body ({'iocs': [...]}), a CSV file upload, or raw CSV text."}), 400)


@iocs_bp.route("/import", methods=["POST"])
@require_permission(IOCS_MANAGE)
def import_iocs():
    rows, error_response = _rows_from_request()
    if error_response:
        return error_response

    rows = rows[:MAX_IOCS_PER_IMPORT]
    result = {"total": len(rows), "imported": 0, "updated": 0, "skipped": 0, "errors": 0}
    error_details = []

    for row in rows:
        if not isinstance(row, dict):
            result["skipped"] += 1
            result["errors"] += 1
            continue

        indicator_type = (row.get("indicator_type") or "").strip().lower()
        indicator = row.get("indicator")
        ok = False
        normalized = None
        if indicator and indicator_type in INDICATOR_TYPES:
            ok, normalized = validate_indicator(indicator_type, indicator)

        if not ok:
            result["skipped"] += 1
            result["errors"] += 1
            if len(error_details) < 20:
                error_details.append({"row": row.get("indicator"), "error": normalized or "invalid row"})
            continue

        existing = IOC.query.filter_by(indicator_type=indicator_type, normalized_indicator=normalized).first()
        ioc, build_error = _build_ioc_from_payload(row, existing=existing)
        if build_error:
            result["skipped"] += 1
            result["errors"] += 1
            if len(error_details) < 20:
                error_details.append({"row": row.get("indicator"), "error": build_error})
            continue

        db.session.add(ioc)
        if existing:
            result["updated"] += 1
        else:
            result["imported"] += 1

    db.session.flush()
    log_action(g.current_user, "ioc.imported", "ioc", None, {
        "total": result["total"], "imported": result["imported"], "updated": result["updated"],
    })
    db.session.commit()

    if error_details:
        result["error_details"] = error_details
    return jsonify(result), 200
