"""
Anomaly detection engine.

Two layers:
1. Threshold rules pulled from the `rules` table (user-configurable)
2. Built-in heuristics (off-hours access) as a fallback / example

Both operate on normalised `Event` records — a rule never needs to know
whether an event came from the SSH or Nginx parser, only its Event fields
(source_ip, event_type, category, outcome, timestamp, ...).

Run via APScheduler on an interval, or trigger manually via POST /api/alerts/run-detection
"""
from datetime import datetime, timedelta
from collections import defaultdict

from app import db
from app.models import Event, Alert, Rule


def run_detection_job():
    _run_threshold_rules()
    _run_offhours_heuristic()
    db.session.commit()


def _run_threshold_rules():
    rules = Rule.query.filter_by(enabled=True, rule_type="threshold").all()
    for rule in rules:
        cond = rule.condition or {}
        event_type = cond.get("event_type")
        category = cond.get("category")
        count_needed = cond.get("count", 5)
        window_seconds = cond.get("window_seconds", 60)
        group_by = cond.get("group_by", "source_ip")

        since = datetime.utcnow() - timedelta(seconds=window_seconds)

        query = Event.query.filter(Event.timestamp >= since)
        if event_type:
            query = query.filter(Event.event_type == event_type)
        if category:
            query = query.filter(Event.category == category)

        events = query.all()
        buckets = defaultdict(list)
        for event in events:
            key = getattr(event, group_by, None)
            if key:
                buckets[key].append(event)

        for key, group_events in buckets.items():
            if len(group_events) >= count_needed:
                # Avoid duplicate alerts for the same rule+key within the window
                existing = Alert.query.filter(
                    Alert.rule_name == rule.name,
                    Alert.created_at >= since,
                    Alert.context["group_key"].as_string() == str(key),
                ).first()
                if existing:
                    continue

                alert = Alert(
                    event_id=group_events[-1].id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    description=f"{rule.name}: {len(group_events)} matching events from '{key}' "
                                 f"in {window_seconds}s (threshold {count_needed})",
                    context={"group_key": str(key), "count": len(group_events), "group_by": group_by},
                )
                db.session.add(alert)


def _run_offhours_heuristic(start_hour=0, end_hour=5):
    """Flag authentication events that occur in off-hours as a simple
    statistical baseline example. Extend with real baselining (per-host averages) later."""
    since = datetime.utcnow() - timedelta(minutes=5)
    events = Event.query.filter(
        Event.timestamp >= since,
        Event.event_type.in_(["authentication_failure", "authentication_success"]),
    ).all()

    for event in events:
        hour = event.timestamp.hour
        if start_hour <= hour < end_hour:
            existing = Alert.query.filter_by(rule_name="off_hours_login", event_id=event.id).first()
            if existing:
                continue
            db.session.add(
                Alert(
                    event_id=event.id,
                    rule_name="off_hours_login",
                    severity="info",
                    description=f"Login activity from {event.source_ip or 'unknown IP'} during off-hours "
                                 f"({event.timestamp.strftime('%H:%M')})",
                    context={"source_ip": event.source_ip, "hour": hour},
                )
            )
