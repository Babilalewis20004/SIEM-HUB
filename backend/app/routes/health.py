from flask import Blueprint, jsonify
from sqlalchemy import text

from app import db

health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def liveness():
    """Process is up and can handle a request. No dependency check, so a
    slow/unreachable DB doesn't false-fail a liveness probe -- that's what
    /health/ready is for."""
    return jsonify({"status": "ok"})


@health_bp.route("/health/ready", methods=["GET"])
def readiness():
    """Checks the one hard dependency this app has. What a load balancer or
    orchestrator should gate routing traffic on, not liveness."""
    try:
        db.session.execute(text("SELECT 1"))
    except Exception:
        return jsonify({"status": "error", "database": "unreachable"}), 503
    return jsonify({"status": "ok", "database": "ok"})
