"""
Deterministic, explainable alert-correlation engine.

Detection engines (app/services/detection.py, app/services/ml_detection.py)
create Alerts; this module decides whether a freshly created Alert belongs to
an existing Incident or needs a new one. It never creates Alerts itself and
is never called from a route directly — only from the same integration
points where an Alert is added to the session, right after it's flushed.

Correlation is scored, not machine-learned: same source IP / destination
host / username / category / time-window each contribute a fixed number of
points (see the SCORE_* constants), and an Incident is reused once the score
against its best-matching existing alert clears CORRELATION_SCORE_THRESHOLD.
The reasoning is stored on the alert (alert.context["correlation"]) so a SOC
analyst can see exactly why two alerts were grouped.
"""
from datetime import timedelta

from flask import current_app

from app import db
from app.models import Incident
from app.models.ioc import IOCMatch
from app.services.incidents import severity_for_alert, priority_for_severity

SCORE_SOURCE_IP = 40
SCORE_DEST_HOST = 30
SCORE_USERNAME = 20
SCORE_CATEGORY = 10
SCORE_TIME_WINDOW = 20
SCORE_SHARED_IOC = 35

# Incidents past these statuses are considered closed investigations and are
# never auto-correlated into (a resolved brute-force incident shouldn't
# silently reopen just because one more matching alert trickles in).
CORRELATABLE_STATUSES = ("open", "investigating", "contained")


def _window(config):
    return timedelta(minutes=config.get("CORRELATION_TIME_WINDOW_MINUTES", 15))


def _threshold(config):
    return config.get("CORRELATION_SCORE_THRESHOLD", 50)


def _score(new_event, candidate_event, window: timedelta):
    """Return (score, [human-readable reasons]) comparing two Events."""
    if new_event is None or candidate_event is None:
        return 0, []

    score = 0
    reasons = []

    if new_event.source_ip and new_event.source_ip == candidate_event.source_ip:
        score += SCORE_SOURCE_IP
        reasons.append(f"same source IP ({new_event.source_ip})")
    if new_event.hostname and new_event.hostname == candidate_event.hostname:
        score += SCORE_DEST_HOST
        reasons.append(f"same destination host ({new_event.hostname})")
    if new_event.username and new_event.username == candidate_event.username:
        score += SCORE_USERNAME
        reasons.append(f"same username ({new_event.username})")
    if new_event.category and new_event.category == candidate_event.category:
        score += SCORE_CATEGORY
        reasons.append(f"same category ({new_event.category})")

    if new_event.timestamp and candidate_event.timestamp:
        delta = abs((new_event.timestamp - candidate_event.timestamp).total_seconds())
        if delta <= window.total_seconds():
            minutes = int(window.total_seconds() // 60)
            reasons.append(f"occurred within {minutes} minutes")
            score += SCORE_TIME_WINDOW

    return score, reasons


def _ioc_ids(alert):
    """{ioc_id: indicator} for the IOCs matched on this alert (see
    app/services/ioc_matching.py). A missing/failed IOC enrichment just
    yields an empty dict, so this signal degrades gracefully."""
    return {m.ioc_id: (m.ioc.indicator if m.ioc else m.matched_value) for m in (alert.ioc_matches or [])}


def _ioc_signal(new_ioc_ids, candidate_alert):
    if not new_ioc_ids:
        return 0, []
    shared = new_ioc_ids.keys() & _ioc_ids(candidate_alert).keys()
    if not shared:
        return 0, []
    indicator = new_ioc_ids[next(iter(shared))]
    return SCORE_SHARED_IOC, [f"shared threat intel indicator ({indicator})"]


def correlate_alert(alert):
    """Attach `alert` to the best-matching open/investigating/contained
    Incident, or create a new one. Must be called after the alert has been
    flushed (alert.id populated) and its event relationship is loadable.
    Returns the Incident the alert ended up in."""
    config = current_app.config
    window = _window(config)
    threshold = _threshold(config)

    new_event = alert.event
    if new_event is None or new_event.timestamp is None:
        return _create_incident(alert)

    # Coarse gate to bound the candidate query: only look at incidents whose
    # activity window could plausibly overlap this alert's event.
    gate_since = new_event.timestamp - window * 2
    gate_until = new_event.timestamp + window * 2

    candidates = Incident.query.filter(
        Incident.status.in_(CORRELATABLE_STATUSES),
        Incident.last_seen_at >= gate_since,
        Incident.first_seen_at <= gate_until,
    ).all()

    best_incident = None
    best_score = 0
    best_reasons = []

    new_ioc_ids = _ioc_ids(alert)

    for incident in candidates:
        for candidate_alert in incident.alerts:
            if candidate_alert.id == alert.id:
                continue
            score, reasons = _score(new_event, candidate_alert.event, window)
            ioc_score, ioc_reasons = _ioc_signal(new_ioc_ids, candidate_alert)
            score += ioc_score
            reasons = reasons + ioc_reasons
            if score > best_score:
                best_score, best_incident, best_reasons = score, incident, reasons

    if best_incident is not None and best_score >= threshold:
        _attach(alert, best_incident, best_score, best_reasons, new_event)
        return best_incident

    return _create_incident(alert)


def _attach(alert, incident, score, reasons, event):
    alert.incident_id = incident.id
    if incident.last_seen_at is None or event.timestamp > incident.last_seen_at:
        incident.last_seen_at = event.timestamp
    if incident.first_seen_at is None or event.timestamp < incident.first_seen_at:
        incident.first_seen_at = event.timestamp

    ctx = dict(alert.context or {})
    ctx["correlation"] = {"incident_id": incident.id, "score": score, "reasons": reasons}
    alert.context = ctx

    db.session.add(incident)
    db.session.add(alert)


def _create_incident(alert):
    severity = severity_for_alert(alert.severity)
    when = alert.event.timestamp if alert.event else alert.created_at

    incident = Incident(
        title=alert.title or alert.rule_name,
        description=alert.description,
        severity=severity,
        priority=priority_for_severity(severity),
        status="open",
        first_seen_at=when,
        last_seen_at=when,
    )
    db.session.add(incident)
    db.session.flush()

    ctx = dict(alert.context or {})
    ctx["correlation"] = {"incident_id": incident.id, "score": 0, "reasons": ["new incident"]}
    alert.context = ctx
    alert.incident_id = incident.id
    db.session.add(alert)

    return incident
