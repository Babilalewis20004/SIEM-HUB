"""
End-to-end enrichment scenario: seed an IOC, ingest a brute-force burst +
successful login from the matching IP, run detection, and verify the full
Event -> Alert -> MITRE -> IOC -> Correlation -> Incident pipeline. Also
covers the negative case (no detection, no IOC, no incident) and the
enrichment-failure-must-not-lose-the-alert requirement.
"""
from datetime import datetime, timedelta

from app.models import Event, Alert, Rule, Incident
from app.models.mitre import MitreTechnique
from app.models.ioc import IOC
from app.services.detection import run_detection_job
from app.services import enrichment


def _seed_brute_force_rule_with_mitre():
    technique = MitreTechnique(technique_id="T1110", name="Brute Force", tactic="Credential Access")
    rule = Rule(
        name="brute_force_ssh", rule_type="threshold",
        condition={"event_type": "authentication_failure", "count": 5, "window_seconds": 60,
                   "group_by": "source_ip"},
        severity="critical", mitre_techniques=[technique],
    )
    return technique, rule


def _auth_events(source_ip, count=7, outcome="failure"):
    now = datetime.utcnow()
    return [
        Event(
            timestamp=now - timedelta(seconds=i * 5),
            event_type="authentication_failure" if outcome == "failure" else "authentication_success",
            category="authentication", source_type="ssh", source_ip=source_ip,
            username="admin", hostname="web01", action="login", outcome=outcome,
            severity="medium" if outcome == "failure" else "info",
            raw_message=f"sshd: {outcome} for admin from {source_ip} ssh2",
        )
        for i in range(count)
    ]


def test_full_enrichment_pipeline_seeded_ioc_to_incident(app, db):
    with app.app_context():
        technique, rule = _seed_brute_force_rule_with_mitre()
        db.session.add_all([technique, rule])
        db.session.add(IOC(
            indicator="185.10.10.10", indicator_type="ip", normalized_indicator="185.10.10.10",
            threat_level="high", confidence=92, source="Internal Threat Feed",
        ))
        db.session.add_all(_auth_events("185.10.10.10", count=7, outcome="failure"))
        db.session.add_all(_auth_events("185.10.10.10", count=1, outcome="success"))
        db.session.commit()

        run_detection_job()

        alert = Alert.query.filter_by(rule_name="brute_force_ssh").first()
        assert alert is not None, "brute-force alert should have been created"
        assert alert.incident_id is not None

        # MITRE enrichment
        assert [t.technique_id for t in alert.mitre_techniques] == ["T1110"]

        # IOC enrichment
        assert len(alert.ioc_matches) == 1
        assert alert.ioc_matches[0].ioc.indicator == "185.10.10.10"
        assert alert.ioc_matches[0].ioc.threat_level == "high"

        # Risk: severity (critical) + IOC threat level (high) -> overall_risk should not be "low"
        risk = alert.to_dict()["risk"]
        assert risk["detection_severity"] == "critical"
        assert risk["ioc_threat_level"] == "high"
        assert risk["overall_risk"] in ("high", "critical")

        # Correlated into an incident whose enrichment summary reflects both
        incident = Incident.query.get(alert.incident_id)
        summary = incident.enrichment_summary()
        assert {t["technique_id"] for t in summary["mitre_techniques"]} == {"T1110"}
        assert {i["indicator"] for i in summary["ioc_matches"]} == {"185.10.10.10"}


def test_negative_case_unrelated_ip_no_detection_no_incident(app, db, monkeypatch):
    with app.app_context():
        # Pin "now" to daytime so the off-hours heuristic can't spuriously
        # fire depending on when this test happens to run (see test_rbac.py
        # / test_detection.py's own frozen-time off-hours tests).
        daytime = datetime(2026, 8, 28, 14, 0, 0)

        class _Frozen(datetime):
            @classmethod
            def utcnow(cls):
                return daytime

        monkeypatch.setattr("app.services.detection.datetime", _Frozen)

        technique, rule = _seed_brute_force_rule_with_mitre()
        db.session.add_all([technique, rule])
        db.session.add(IOC(
            indicator="185.10.10.10", indicator_type="ip", normalized_indicator="185.10.10.10",
            threat_level="high", confidence=92, source="internal",
        ))
        # A single normal login from an unrelated, unlisted IP.
        db.session.add(Event(
            timestamp=daytime, event_type="authentication_success", category="authentication",
            source_type="ssh", source_ip="10.0.0.50", username="alice", hostname="web01",
            action="login", outcome="success", severity="info", raw_message="normal login",
        ))
        db.session.commit()

        run_detection_job()

        assert Alert.query.count() == 0
        assert Incident.query.count() == 0


def test_ioc_enrichment_failure_does_not_lose_the_alert(app, db, monkeypatch):
    """If IOC matching blows up, the underlying detection alert must still
    be created and correlated -- enrichment is a dependency, not a single
    point of failure."""
    with app.app_context():
        db.session.add(Rule(
            name="brute_force_ssh", rule_type="threshold",
            condition={"event_type": "authentication_failure", "count": 5, "window_seconds": 60,
                       "group_by": "source_ip"},
            severity="critical",
        ))
        db.session.add_all(_auth_events("203.0.113.9", count=6, outcome="failure"))
        db.session.commit()

        def _boom(alert):
            raise RuntimeError("threat intel provider unavailable")

        monkeypatch.setattr("app.services.enrichment.ioc_matching.enrich_alert_iocs", _boom)

        run_detection_job()

        alert = Alert.query.filter_by(rule_name="brute_force_ssh").first()
        assert alert is not None, "alert must survive an IOC enrichment failure"
        assert alert.incident_id is not None, "correlation must still run after enrichment fails"
        assert alert.ioc_matches == []


def test_mitre_enrichment_failure_does_not_lose_the_alert(app, db, monkeypatch):
    with app.app_context():
        db.session.add(Rule(
            name="brute_force_ssh", rule_type="threshold",
            condition={"event_type": "authentication_failure", "count": 5, "window_seconds": 60,
                       "group_by": "source_ip"},
            severity="critical",
        ))
        db.session.add_all(_auth_events("203.0.113.10", count=6, outcome="failure"))
        db.session.commit()

        def _boom(alert):
            raise RuntimeError("mitre catalogue lookup failed")

        monkeypatch.setattr("app.services.enrichment.mitre_enrichment.enrich_alert", _boom)

        run_detection_job()

        alert = Alert.query.filter_by(rule_name="brute_force_ssh").first()
        assert alert is not None
        assert alert.incident_id is not None
        assert alert.mitre_techniques == []
