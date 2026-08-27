from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify
from sqlalchemy import func

from app import db
from app.models import Log, Alert

stats_bp = Blueprint("stats", __name__)


@stats_bp.route("/summary", methods=["GET"])
def summary():
    total_logs = Log.query.count()
    open_alerts = Alert.query.filter_by(status="open").count()

    severity_counts = dict(
        db.session.query(Log.severity, func.count(Log.id)).group_by(Log.severity).all()
    )
    alert_severity_counts = dict(
        db.session.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.status == "open")
        .group_by(Alert.severity)
        .all()
    )
    top_sources = db.session.query(
        Log.source_ip, func.count(Log.id).label("count")
    ).filter(Log.source_ip.isnot(None)).group_by(Log.source_ip).order_by(
        func.count(Log.id).desc()
    ).limit(5).all()

    return jsonify({
        "total_logs": total_logs,
        "open_alerts": open_alerts,
        "log_severity_counts": severity_counts,
        "alert_severity_counts": alert_severity_counts,
        "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_sources],
    })


@stats_bp.route("/timeseries", methods=["GET"])
def timeseries():
    """Bucketed event counts for charting. Default: last 24h, hourly buckets."""
    hours = int(request.args.get("hours", 24))
    since = datetime.utcnow() - timedelta(hours=hours)

    logs = Log.query.filter(Log.timestamp >= since).all()

    buckets = {}
    for log in logs:
        bucket_key = log.timestamp.strftime("%Y-%m-%dT%H:00:00")
        buckets.setdefault(bucket_key, {"total": 0, "warning": 0, "critical": 0})
        buckets[bucket_key]["total"] += 1
        if log.severity in ("warning", "critical"):
            buckets[bucket_key][log.severity] += 1

    series = [
        {"bucket": k, **v} for k, v in sorted(buckets.items())
    ]
    return jsonify({"hours": hours, "series": series})
