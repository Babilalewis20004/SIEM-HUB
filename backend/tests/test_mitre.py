from datetime import datetime

from app.models import Event, Alert, Rule
from app.models.mitre import MitreTechnique
from app.services import mitre_enrichment
from app.services.detection import run_detection_job


def _technique(technique_id="T1110", name="Brute Force", tactic="Credential Access"):
    return MitreTechnique(technique_id=technique_id, name=name, tactic=tactic)


def test_rule_maps_to_multiple_techniques(app, db):
    with app.app_context():
        t1 = _technique("T1110", "Brute Force", "Credential Access")
        t2 = _technique("T1110.001", "Password Guessing", "Credential Access")
        db.session.add_all([t1, t2])
        rule = Rule(name="r", rule_type="threshold", condition={}, mitre_techniques=[t1, t2])
        db.session.add(rule)
        db.session.commit()

        assert {t.technique_id for t in rule.mitre_techniques} == {"T1110", "T1110.001"}
        assert {t["technique_id"] for t in rule.to_dict()["mitre"]} == {"T1110", "T1110.001"}


def test_alert_enrichment_copies_rule_techniques(app, db):
    with app.app_context():
        technique = _technique()
        db.session.add(technique)
        rule = Rule(name="brute_force_ssh", rule_type="threshold", condition={},
                    mitre_techniques=[technique])
        db.session.add(rule)
        event = Event(
            timestamp=datetime.utcnow(), event_type="authentication_failure", category="authentication",
            source_type="ssh", source_ip="10.0.0.1", raw_message="x",
        )
        db.session.add(event)
        db.session.flush()
        alert = Alert(event_id=event.id, rule_id=rule.id, rule_name=rule.name,
                       severity="critical", description="x")
        db.session.add(alert)
        db.session.flush()

        mitre_enrichment.enrich_alert(alert)
        db.session.commit()

        assert [t.technique_id for t in alert.mitre_techniques] == ["T1110"]
        assert alert.to_dict()["mitre"] == [{"technique_id": "T1110", "name": "Brute Force",
                                              "tactic": "Credential Access"}]


def test_unmapped_rule_produces_empty_mitre_list(app, db):
    with app.app_context():
        rule = Rule(name="http_error_burst", rule_type="threshold", condition={})
        db.session.add(rule)
        event = Event(
            timestamp=datetime.utcnow(), event_type="http_error", category="web",
            source_type="nginx", source_ip="10.0.0.1", raw_message="x",
        )
        db.session.add(event)
        db.session.flush()
        alert = Alert(event_id=event.id, rule_id=rule.id, rule_name=rule.name,
                       severity="warning", description="x")
        db.session.add(alert)
        db.session.flush()

        mitre_enrichment.enrich_alert(alert)
        db.session.commit()

        assert alert.mitre_techniques == []
        assert alert.to_dict()["mitre"] == []


def test_rule_less_alert_enrichment_is_a_noop(app, db):
    with app.app_context():
        event = Event(
            timestamp=datetime.utcnow(), event_type="authentication_success", category="authentication",
            source_type="ssh", source_ip="10.0.0.9", raw_message="x",
        )
        db.session.add(event)
        db.session.flush()
        alert = Alert(event_id=event.id, rule_name="off_hours_login", severity="info", description="x")
        db.session.add(alert)
        db.session.flush()

        result = mitre_enrichment.enrich_alert(alert)
        db.session.commit()

        assert result == []
        assert alert.to_dict()["mitre"] == []


def test_seeded_brute_force_rule_produces_mitre_technique_on_alert(app, db):
    """End-to-end through the real detection pipeline: a rule with a MITRE
    mapping fires, and the resulting alert carries T1110."""
    with app.app_context():
        technique = _technique()
        db.session.add(technique)
        db.session.add(Rule(
            name="brute_force_ssh", rule_type="threshold",
            condition={"event_type": "authentication_failure", "count": 5, "window_seconds": 60,
                       "group_by": "source_ip"},
            severity="critical", mitre_techniques=[technique],
        ))
        for i in range(6):
            db.session.add(Event(
                timestamp=datetime.utcnow(), event_type="authentication_failure", category="authentication",
                source_type="ssh", source_ip="203.0.113.5", raw_message="x",
            ))
        db.session.commit()

        run_detection_job()

        alert = Alert.query.filter_by(rule_name="brute_force_ssh").first()
        assert alert is not None
        assert [t.technique_id for t in alert.mitre_techniques] == ["T1110"]
