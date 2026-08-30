from datetime import datetime, timedelta

from app import db as _db
from app.models import Event, Alert, Incident
from app.services import correlation


def _make_alert(when, **event_overrides):
    defaults = dict(
        timestamp=when,
        event_type="authentication_failure",
        category="authentication",
        source_type="ssh",
        source_ip="203.0.113.5",
        username="root",
        hostname="server01",
        action="login",
        outcome="failure",
        severity="medium",
        raw_message="test event",
    )
    defaults.update(event_overrides)
    event = Event(**defaults)
    _db.session.add(event)
    _db.session.flush()

    alert = Alert(
        event_id=event.id,
        rule_name="test_rule",
        severity="critical",
        description="test alert",
    )
    _db.session.add(alert)
    _db.session.flush()

    correlation.correlate_alert(alert)
    _db.session.commit()
    return alert


def test_same_source_ip_within_window_correlates(app, db):
    with app.app_context():
        now = datetime.utcnow()
        a1 = _make_alert(now, source_ip="203.0.113.5")
        a2 = _make_alert(now + timedelta(minutes=2), source_ip="203.0.113.5", hostname="other-host",
                          username="alice")

        assert a1.incident_id is not None
        assert a1.incident_id == a2.incident_id
        assert Incident.query.count() == 1


def test_same_host_correlates(app, db):
    with app.app_context():
        now = datetime.utcnow()
        a1 = _make_alert(now, source_ip="10.0.0.1", hostname="web01")
        a2 = _make_alert(now + timedelta(minutes=1), source_ip="10.0.0.2", hostname="web01")

        assert a1.incident_id == a2.incident_id


def test_same_username_correlates(app, db):
    with app.app_context():
        now = datetime.utcnow()
        a1 = _make_alert(now, source_ip="10.0.0.1", hostname="a", username="bob")
        a2 = _make_alert(now + timedelta(minutes=1), source_ip="10.0.0.2", hostname="b", username="bob")

        assert a1.incident_id == a2.incident_id


def test_outside_time_window_does_not_correlate(app, db):
    with app.app_context():
        app.config["CORRELATION_TIME_WINDOW_MINUTES"] = 15
        now = datetime.utcnow()
        a1 = _make_alert(now, source_ip="203.0.113.5")
        a2 = _make_alert(now + timedelta(hours=2), source_ip="203.0.113.5")

        assert a1.incident_id != a2.incident_id
        assert Incident.query.count() == 2


def test_unrelated_alerts_stay_separate(app, db):
    with app.app_context():
        now = datetime.utcnow()
        a1 = _make_alert(now, source_ip="192.168.1.10", hostname="host-a", username="alice",
                          category="authentication")
        a2 = _make_alert(now, source_ip="10.0.0.25", hostname="host-b", username="bob",
                          category="web")

        assert a1.incident_id != a2.incident_id
        assert Incident.query.count() == 2


def test_alert_storm_collapses_into_one_incident(app, db):
    with app.app_context():
        now = datetime.utcnow()
        alerts = [
            _make_alert(now + timedelta(seconds=i * 5), source_ip="203.0.113.99", hostname="server01",
                        username="root")
            for i in range(50)
        ]

        incident_ids = {a.incident_id for a in alerts}
        assert len(incident_ids) == 1
        assert Incident.query.count() == 1
        assert len(Incident.query.first().alerts) == 50
