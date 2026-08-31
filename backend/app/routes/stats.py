from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify
from sqlalchemy import func

from app import db
from app.models import Event, Alert, Incident
from app.models.ioc import IOC, IOCMatch
from app.models.mitre import MitreTechnique, alert_mitre_techniques
from app.playbooks.models import PlaybookExecution
from app.services.correlation import CORRELATABLE_STATUSES
from app.auth.authorization import require_permission
from app.auth.permissions import EVENTS_READ

stats_bp = Blueprint("stats", __name__)


@stats_bp.route("/summary", methods=["GET"])
@require_permission(EVENTS_READ)
def summary():
    total_events = Event.query.count()
    open_alerts = Alert.query.filter_by(status="open").count()

    # Live SOC dashboard tiles (Part 15) -- the REST snapshot a page load
    # starts from; WebSocket events keep these fresh without a refetch.
    active_incidents = Incident.query.filter(Incident.status.in_(CORRELATABLE_STATUSES)).count()
    critical_alerts = Alert.query.filter_by(status="open", severity="critical").count()
    events_last_minute = Event.query.filter(
        Event.timestamp >= datetime.utcnow() - timedelta(minutes=1)
    ).count()
    high_risk_ioc_matches = (
        IOCMatch.query.join(IOC, IOCMatch.ioc_id == IOC.id)
        .filter(IOC.threat_level.in_(["high", "critical"]))
        .count()
    )
    playbooks_running = PlaybookExecution.query.filter(
        PlaybookExecution.status.in_(["running", "awaiting_approval"])
    ).count()

    severity_counts = dict(
        db.session.query(Event.severity, func.count(Event.id)).group_by(Event.severity).all()
    )
    category_counts = dict(
        db.session.query(Event.category, func.count(Event.id)).group_by(Event.category).all()
    )
    event_type_counts = dict(
        db.session.query(Event.event_type, func.count(Event.id)).group_by(Event.event_type).all()
    )
    source_type_counts = dict(
        db.session.query(Event.source_type, func.count(Event.id)).group_by(Event.source_type).all()
    )
    outcome_counts = dict(
        db.session.query(Event.outcome, func.count(Event.id)).group_by(Event.outcome).all()
    )
    alert_severity_counts = dict(
        db.session.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.status == "open")
        .group_by(Alert.severity)
        .all()
    )
    top_sources = db.session.query(
        Event.source_ip, func.count(Event.id).label("count")
    ).filter(Event.source_ip.isnot(None)).group_by(Event.source_ip).order_by(
        func.count(Event.id).desc()
    ).limit(5).all()

    mitre_counts = (
        db.session.query(
            MitreTechnique.technique_id,
            MitreTechnique.name,
            MitreTechnique.tactic,
            func.count(alert_mitre_techniques.c.alert_id).label("count"),
        )
        .join(alert_mitre_techniques, MitreTechnique.id == alert_mitre_techniques.c.technique_id)
        .group_by(MitreTechnique.id)
        .order_by(func.count(alert_mitre_techniques.c.alert_id).desc())
        .all()
    )

    return jsonify({
        # deprecated aliases kept for the pre-Event dashboard
        "total_logs": total_events,
        "log_severity_counts": severity_counts,

        "total_events": total_events,
        "open_alerts": open_alerts,
        "events_by_severity": severity_counts,
        "events_by_category": category_counts,
        "events_by_type": event_type_counts,
        "events_by_source_type": source_type_counts,
        "events_by_outcome": outcome_counts,
        "alert_severity_counts": alert_severity_counts,
        "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_sources],
        "mitre_technique_counts": [
            {"technique_id": tid, "name": name, "tactic": tactic, "count": c}
            for tid, name, tactic, c in mitre_counts
        ],

        "active_incidents": active_incidents,
        "critical_alerts": critical_alerts,
        "events_per_minute": events_last_minute,
        "high_risk_ioc_matches": high_risk_ioc_matches,
        "playbooks_running": playbooks_running,
    })


@stats_bp.route("/timeseries", methods=["GET"])
@require_permission(EVENTS_READ)
def timeseries():
    """Bucketed event counts for charting. Default: last 24h, hourly buckets."""
    hours = int(request.args.get("hours", 24))
    since = datetime.utcnow() - timedelta(hours=hours)

    events = Event.query.filter(Event.timestamp >= since).all()

    buckets = {}
    for event in events:
        bucket_key = event.timestamp.strftime("%Y-%m-%dT%H:00:00")
        b = buckets.setdefault(
            bucket_key,
            {"total": 0, "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
        )
        b["total"] += 1
        if event.severity in b:
            b[event.severity] += 1

    series = [
        {"bucket": k, **v} for k, v in sorted(buckets.items())
    ]
    return jsonify({"hours": hours, "series": series})


@stats_bp.route("/ioc-timeseries", methods=["GET"])
@require_permission(EVENTS_READ)
def ioc_timeseries():
    """Bucketed IOC match counts for charting. Default: last 24h, hourly buckets."""
    hours = int(request.args.get("hours", 24))
    since = datetime.utcnow() - timedelta(hours=hours)

    matches = IOCMatch.query.filter(IOCMatch.created_at >= since).all()

    buckets = {}
    for match in matches:
        bucket_key = match.created_at.strftime("%Y-%m-%dT%H:00:00")
        buckets[bucket_key] = buckets.get(bucket_key, 0) + 1

    series = [{"bucket": k, "count": v} for k, v in sorted(buckets.items())]
    return jsonify({"hours": hours, "series": series})
