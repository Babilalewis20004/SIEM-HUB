from datetime import datetime

from flask import Blueprint, request, jsonify, g

from app import db
from app.models import Alert
from app.services.detection import run_detection_job
from app.services import ml_detection
from app.services.audit import log_action
from app.auth.authorization import require_permission
from app.auth.permissions import (
    ALERTS_READ, ALERTS_ACKNOWLEDGE, ALERTS_RESOLVE, ML_TRAIN, DETECTION_RUN, role_has_permission,
)

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("", methods=["GET"])
@require_permission(ALERTS_READ)
def list_alerts():
    q = Alert.query

    status = request.args.get("status")
    severity = request.args.get("severity")

    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)

    q = q.order_by(Alert.created_at.desc())

    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 200)
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [a.to_dict() for a in items],
    })


@alerts_bp.route("/<alert_id>", methods=["PATCH"])
@require_permission(ALERTS_ACKNOWLEDGE, ALERTS_RESOLVE)
def update_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    data = request.get_json() or {}

    new_status = data.get("status")
    if new_status == "acknowledged":
        if not role_has_permission(g.current_user.role, ALERTS_ACKNOWLEDGE):
            return jsonify({"error": "Forbidden: insufficient permissions."}), 403
        alert.status = "acknowledged"
        alert.acknowledged_at = datetime.utcnow()
        alert.acknowledged_by_id = g.current_user.id
        log_action(g.current_user, "alert.acknowledged", "alert", alert.id)
    elif new_status == "resolved":
        if not role_has_permission(g.current_user.role, ALERTS_RESOLVE):
            return jsonify({"error": "Forbidden: insufficient permissions."}), 403
        alert.status = "resolved"
        alert.resolved_at = datetime.utcnow()
        alert.resolved_by_id = g.current_user.id
        log_action(g.current_user, "alert.resolved", "alert", alert.id)
    elif new_status:
        alert.status = new_status

    db.session.commit()
    return jsonify(alert.to_dict())


@alerts_bp.route("/run-detection", methods=["POST"])
@require_permission(DETECTION_RUN)
def trigger_detection():
    """Manually trigger a full detection pass: rule-based + ML scoring (if a model exists)."""
    run_detection_job()
    ml_result = ml_detection.run_ml_detection_job()
    log_action(g.current_user, "detection.run", "system")
    db.session.commit()
    return jsonify({"status": "ok", "ml": ml_result})


@alerts_bp.route("/ml-status", methods=["GET"])
@require_permission(ALERTS_READ)
def ml_status():
    return jsonify(ml_detection.get_model_status())


@alerts_bp.route("/train-model", methods=["POST"])
@require_permission(ML_TRAIN)
def train_model():
    """Train (or retrain) the Isolation Forest on historical log data."""
    lookback_hours = request.get_json(silent=True) or {}
    result = ml_detection.train_model(lookback_hours=lookback_hours.get("lookback_hours"))
    log_action(g.current_user, "ml.train", "system", metadata=result)
    db.session.commit()
    status_code = 200 if result.get("trained") else 422
    return jsonify(result), status_code
