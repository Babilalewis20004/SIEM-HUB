from datetime import datetime, timedelta

from app.models import Event, Alert
from app.models.ioc import IOC, IOCMatch
from app.services import ioc_matching


def _event(source_ip="185.10.10.10", **overrides):
    defaults = dict(
        timestamp=datetime.utcnow(),
        event_type="authentication_failure",
        category="authentication",
        source_type="ssh",
        source_ip=source_ip,
        username="root",
        hostname="server01",
        action="login",
        outcome="failure",
        severity="medium",
        raw_message=f"Failed password for root from {source_ip} port 1000 ssh2",
    )
    defaults.update(overrides)
    return Event(**defaults)


def _ioc(indicator="185.10.10.10", indicator_type="ip", **overrides):
    defaults = dict(
        indicator=indicator,
        indicator_type=indicator_type,
        normalized_indicator=indicator,
        threat_level="high",
        confidence=92,
        source="internal",
        enabled=True,
    )
    defaults.update(overrides)
    return IOC(**defaults)


def test_exact_ip_match(app, db):
    with app.app_context():
        db.session.add(_ioc())
        event = _event()
        db.session.add(event)
        db.session.commit()

        matched = ioc_matching.match_indicators(ioc_matching.extract_indicators(event).keys())
        assert ("ip", "185.10.10.10") in matched


def test_no_match_for_unrelated_ip(app, db):
    with app.app_context():
        db.session.add(_ioc())
        event = _event(source_ip="10.0.0.99")
        db.session.add(event)
        db.session.commit()

        matched = ioc_matching.match_indicators(ioc_matching.extract_indicators(event).keys())
        assert matched == {}


def test_disabled_ioc_does_not_match(app, db):
    with app.app_context():
        db.session.add(_ioc(enabled=False))
        event = _event()
        db.session.add(event)
        db.session.commit()

        matched = ioc_matching.match_indicators(ioc_matching.extract_indicators(event).keys())
        assert matched == {}


def test_expired_ioc_does_not_match(app, db):
    with app.app_context():
        db.session.add(_ioc(expires_at=datetime.utcnow() - timedelta(days=1)))
        event = _event()
        db.session.add(event)
        db.session.commit()

        matched = ioc_matching.match_indicators(ioc_matching.extract_indicators(event).keys())
        assert matched == {}


def test_not_yet_expired_ioc_matches(app, db):
    with app.app_context():
        db.session.add(_ioc(expires_at=datetime.utcnow() + timedelta(days=1)))
        event = _event()
        db.session.add(event)
        db.session.commit()

        matched = ioc_matching.match_indicators(ioc_matching.extract_indicators(event).keys())
        assert ("ip", "185.10.10.10") in matched


def test_enrich_alert_iocs_creates_match_row(app, db):
    with app.app_context():
        db.session.add(_ioc())
        event = _event()
        db.session.add(event)
        db.session.flush()
        alert = Alert(event_id=event.id, rule_name="test_rule", severity="critical", description="x")
        db.session.add(alert)
        db.session.flush()

        created = ioc_matching.enrich_alert_iocs(alert)
        db.session.commit()

        assert len(created) == 1
        assert created[0].matched_field == "source_ip"
        assert created[0].alert_id == alert.id
        assert created[0].event_id == event.id


def test_ioc_disabled_after_match_keeps_historical_match(app, db):
    with app.app_context():
        ioc = _ioc()
        db.session.add(ioc)
        event = _event()
        db.session.add(event)
        db.session.flush()
        alert = Alert(event_id=event.id, rule_name="test_rule", severity="critical", description="x")
        db.session.add(alert)
        db.session.flush()

        ioc_matching.enrich_alert_iocs(alert)
        db.session.commit()

        ioc.enabled = False
        db.session.commit()

        assert IOCMatch.query.filter_by(alert_id=alert.id).count() == 1


def test_batch_match_events_dedupes_and_matches_all(app, db):
    with app.app_context():
        db.session.add(_ioc())
        events = [_event() for _ in range(5)]
        db.session.add_all(events)
        db.session.commit()

        results = ioc_matching.match_events(events)
        assert all(("ip", "185.10.10.10") in matches for matches in results.values())
