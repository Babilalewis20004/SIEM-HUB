"""
Anomaly detection engine.

Two layers:
1. Threshold rules pulled from the `rules` table (user-configurable)
2. Built-in heuristics (off-hours access) as a fallback / example

Run via APScheduler on an interval, or trigger manually via POST /api/alerts/run-detection
"""
from datetime import datetime, timedelta
from collections import defaultdict

from app import db
from app.models import Log, Alert, Rule


def run_detection_job():
    _run_threshold_rules()
    _run_offhours_heuristic()
    db.session.commit()


def _run_threshold_rules():
    rules = Rule.query.filter_by(enabled=True, rule_type="threshold").all()
    for rule in rules:
        cond = rule.condition or {}
        event_type = cond.get("event_type")
        count_needed = cond.get("count", 5)
        window_seconds = cond.get("window_seconds", 60)
        group_by = cond.get("group_by", "source_ip")

        since = datetime.utcnow() - timedelta(seconds=window_seconds)

        query = Log.query.filter(Log.timestamp >= since)
        if event_type:
            query = query.filter(Log.event_type == event_type)

        logs = query.all()
        buckets = defaultdict(list)
        for log in logs:
            key = getattr(log, group_by, None)
            if key:
                buckets[key].append(log)

        for key, group_logs in buckets.items():
            if len(group_logs) >= count_needed:
                # Avoid duplicate alerts for the same rule+key within the window
                existing = Alert.query.filter(
                    Alert.rule_name == rule.name,
                    Alert.created_at >= since,
                    Alert.context["group_key"].as_string() == str(key),
                ).first()
                if existing:
                    continue

                alert = Alert(
                    log_id=group_logs[-1].id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    description=f"{rule.name}: {len(group_logs)} matching events from '{key}' "
                                 f"in {window_seconds}s (threshold {count_needed})",
                    context={"group_key": str(key), "count": len(group_logs), "group_by": group_by},
                )
                db.session.add(alert)


def _run_offhours_heuristic(start_hour=0, end_hour=5):
    """Flag login_failed / login_success events that occur in off-hours as a simple
    statistical baseline example. Extend with real baselining (per-host averages) later."""
    since = datetime.utcnow() - timedelta(minutes=5)
    logs = Log.query.filter(
        Log.timestamp >= since,
        Log.event_type.in_(["login_failed", "login_success"]),
    ).all()

    for log in logs:
        hour = log.timestamp.hour
        if start_hour <= hour < end_hour:
            existing = Alert.query.filter_by(rule_name="off_hours_login", log_id=log.id).first()
            if existing:
                continue
            db.session.add(
                Alert(
                    log_id=log.id,
                    rule_name="off_hours_login",
                    severity="info",
                    description=f"Login activity from {log.source_ip or 'unknown IP'} during off-hours "
                                 f"({log.timestamp.strftime('%H:%M')})",
                    context={"source_ip": log.source_ip, "hour": hour},
                )
            )
