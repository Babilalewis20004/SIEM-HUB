from datetime import datetime, timedelta

from app.models import Event, Alert, Rule
from app.services.detection import run_detection_job


def _auth_event(db, source_ip, offset_seconds=0, outcome="failure", when=None):
    ts = (when or datetime.utcnow()) - timedelta(seconds=offset_seconds)
    event = Event(
        timestamp=ts,
        event_type="authentication_failure" if outcome == "failure" else "authentication_success",
        category="authentication",
        source_type="ssh",
        source_ip=source_ip,
        username="root",
        hostname="server",
        action="login",
        outcome=outcome,
        severity="medium" if outcome == "failure" else "info",
        raw_message=f"Failed password for root from {source_ip} port 1000 ssh2",
    )
    db.session.add(event)
    return event


def _brute_force_rule():
    return Rule(
        name="brute_force_ssh",
        rule_type="threshold",
        condition={
            "event_type": "authentication_failure",
            "count": 5,
            "window_seconds": 60,
            "group_by": "source_ip",
        },
        severity="critical",
    )


def test_brute_force_detection_triggers_alert(app, db):
    with app.app_context():
        db.session.add(_brute_force_rule())
        for i in range(6):
            _auth_event(db, "203.0.113.5", offset_seconds=i * 5)
        db.session.commit()

        run_detection_job()

        alerts = Alert.query.filter_by(rule_name="brute_force_ssh").all()
        assert len(alerts) == 1
        assert alerts[0].context["group_key"] == "203.0.113.5"
        assert alerts[0].context["count"] == 6


def test_brute_force_below_threshold_no_alert(app, db):
    with app.app_context():
        db.session.add(_brute_force_rule())
        for i in range(3):
            _auth_event(db, "203.0.113.5", offset_seconds=i * 5)
        db.session.commit()

        run_detection_job()

        assert Alert.query.filter_by(rule_name="brute_force_ssh").count() == 0


def test_brute_force_dedup_within_window(app, db):
    with app.app_context():
        db.session.add(_brute_force_rule())
        for i in range(6):
            _auth_event(db, "203.0.113.5", offset_seconds=i * 5)
        db.session.commit()

        run_detection_job()
        run_detection_job()  # second pass shouldn't create a duplicate alert

        assert Alert.query.filter_by(rule_name="brute_force_ssh").count() == 1


def test_normal_successful_logins_dont_trigger_brute_force(app, db):
    with app.app_context():
        db.session.add(_brute_force_rule())
        for i in range(6):
            _auth_event(db, "203.0.113.5", offset_seconds=i * 5, outcome="success")
        db.session.commit()

        run_detection_job()

        assert Alert.query.filter_by(rule_name="brute_force_ssh").count() == 0


class _FrozenDatetime(datetime):
    """Lets off-hours tests control 'now' independently of wall-clock time,
    since the heuristic both windows on recency (last 5 min) and checks the
    hour-of-day of the event timestamp."""
    _frozen = datetime(2026, 8, 28, 2, 0, 0)

    @classmethod
    def utcnow(cls):
        return cls._frozen


def test_off_hours_heuristic_flags_login_at_night(app, db, monkeypatch):
    with app.app_context():
        monkeypatch.setattr("app.services.detection.datetime", _FrozenDatetime)
        _auth_event(db, "10.0.0.9", when=_FrozenDatetime.utcnow())
        db.session.commit()

        run_detection_job()

        alerts = Alert.query.filter_by(rule_name="off_hours_login").all()
        assert len(alerts) == 1
        assert alerts[0].context["source_ip"] == "10.0.0.9"


def test_off_hours_heuristic_ignores_daytime_login(app, db, monkeypatch):
    with app.app_context():
        daytime = datetime(2026, 8, 28, 14, 0, 0)

        class _DaytimeFrozen(_FrozenDatetime):
            _frozen = daytime

        monkeypatch.setattr("app.services.detection.datetime", _DaytimeFrozen)
        _auth_event(db, "10.0.0.9", when=daytime)
        db.session.commit()

        run_detection_job()

        assert Alert.query.filter_by(rule_name="off_hours_login").count() == 0
