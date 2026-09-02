from datetime import datetime

import pytest
from sqlalchemy.exc import IntegrityError

from app.models import Event, Alert


def _make_event(**overrides):
    defaults = dict(
        timestamp=datetime(2026, 8, 28, 10, 0, 0),
        event_type="authentication_failure",
        category="authentication",
        source_type="ssh",
        source_ip="192.168.1.50",
        username="root",
        hostname="server",
        action="login",
        outcome="failure",
        severity="medium",
        raw_message="Failed password for root from 192.168.1.50 port 52344 ssh2",
    )
    defaults.update(overrides)
    return Event(**defaults)


def test_event_creation_round_trips_fields(app, db):
    with app.app_context():
        event = _make_event(parsed_fields={"pid": "1234"})
        db.session.add(event)
        db.session.commit()

        fetched = Event.query.get(event.id)
        assert fetched.event_type == "authentication_failure"
        assert fetched.source_ip == "192.168.1.50"
        assert fetched.parsed_fields == {"pid": "1234"}
        assert fetched.created_at is not None


def test_event_nullable_fields_default_sensibly(app, db):
    with app.app_context():
        event = Event(
            timestamp=datetime.utcnow(),
            event_type="unparsed",
            category="application",
            source_type="generic",
            raw_message="some unrecognised line",
        )
        db.session.add(event)
        db.session.commit()

        fetched = Event.query.get(event.id)
        assert fetched.source_ip is None
        assert fetched.username is None
        assert fetched.severity == "info"  # column default
        assert fetched.parsed_fields == {}


def test_event_requires_raw_message(app, db):
    with app.app_context():
        event = Event(
            timestamp=datetime.utcnow(),
            event_type="unparsed",
            category="application",
            source_type="generic",
        )
        db.session.add(event)
        with pytest.raises(IntegrityError):
            db.session.commit()


def test_event_to_dict_source_geo(app, db):
    with app.app_context():
        public_event = _make_event(source_ip="8.8.8.8")
        private_event = _make_event(source_ip="192.168.1.50")
        db.session.add_all([public_event, private_event])
        db.session.commit()

        assert public_event.to_dict()["source_geo"] == {
            "country_code": "US", "country_name": "United States",
        }
        assert private_event.to_dict()["source_geo"] is None


def test_alert_event_id_and_to_dict(app, db):
    with app.app_context():
        event = _make_event()
        db.session.add(event)
        db.session.commit()

        alert = Alert(
            event_id=event.id,
            rule_name="brute_force_ssh",
            severity="critical",
            description="test alert",
        )
        db.session.add(alert)
        db.session.commit()

        d = alert.to_dict()
        assert d["event_id"] == event.id
        assert d["event"]["id"] == event.id
