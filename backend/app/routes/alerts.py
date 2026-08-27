from datetime import datetime

from flask import Blueprint, request, jsonify

from app import db
from app.models import Alert
from app.services.detection import run_detection_job
from app.services import ml_detection

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("", methods=["GET"])
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
def update_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    data = request.get_json() or {}

    if "status" in data:
        alert.status = data["status"]
        if data["status"] == "resolved":
            alert.resolved_at = datetime.utcnow()

    db.session.commit()
    return jsonify(alert.to_dict())


@alerts_bp.route("/run-detection", methods=["POST"])
def trigger_detection():
    """Manually trigger a full detection pass: rule-based + ML scoring (if a model exists)."""
    run_detection_job()
    ml_result = ml_detection.run_ml_detection_job()
    return jsonify({"status": "ok", "ml": ml_result})


@alerts_bp.route("/ml-status", methods=["GET"])
def ml_status():
    return jsonify(ml_detection.get_model_status())


@alerts_bp.route("/train-model", methods=["POST"])
def train_model():
    """Train (or retrain) the Isolation Forest on historical log data."""
    lookback_hours = request.get_json(silent=True) or {}
    result = ml_detection.train_model(lookback_hours=lookback_hours.get("lookback_hours"))
    status_code = 200 if result.get("trained") else 422
    return jsonify(result), status_code
