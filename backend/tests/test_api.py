from datetime import datetime

from app.models import Event, Alert
from app.models.mitre import MitreTechnique
from app.models.ioc import IOC, IOCMatch


def test_register_and_login(client, db):
    resp = client.post("/api/auth/register", json={"email": "a@example.com", "password": "password123"})
    assert resp.status_code == 201
    assert "token" in resp.get_json()

    resp = client.post("/api/auth/login", json={"email": "a@example.com", "password": "password123"})
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_protected_routes_require_auth(client, db):
    assert client.get("/api/logs").status_code == 401
    assert client.get("/api/alerts").status_code == 401
    assert client.get("/api/stats/summary").status_code == 401
    assert client.get("/api/rules").status_code == 401


def _seed_event(db, **overrides):
    defaults = dict(
        timestamp=datetime.utcnow(),
        event_type="authentication_failure",
        category="authentication",
        source_type="ssh",
        source_ip="192.168.1.50",
        username="root",
        hostname="server",
        action="login",
        outcome="failure",
        severity="medium",
        raw_message="Failed password for root from 192.168.1.50 port 1000 ssh2",
    )
    defaults.update(overrides)
    event = Event(**defaults)
    db.session.add(event)
    db.session.commit()
    return event


def test_stats_summary_reflects_events(client, db, auth_headers):
    _seed_event(db)
    _seed_event(db, event_type="http_request", category="web", source_type="nginx",
                severity="info", outcome="success", username=None,
                raw_message="203.0.113.5 request 200")

    resp = client.get("/api/stats/summary", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["total_events"] == 2
    assert body["events_by_category"]["authentication"] == 1
    assert body["events_by_category"]["web"] == 1


def test_stats_summary_detection_status_disabled_by_default(client, db, auth_headers):
    # TestConfig sets ENABLE_SCHEDULER = False -- the trust signal should
    # say so rather than guessing from job history that doesn't exist yet.
    resp = client.get("/api/stats/summary", headers=auth_headers)
    assert resp.get_json()["detection_status"] == {"state": "disabled", "last_run_at": None}


def test_stats_summary_detection_status_unknown_when_scheduler_enabled_but_no_run_yet(
    app, client, db, auth_headers
):
    app.config["ENABLE_SCHEDULER"] = True
    resp = client.get("/api/stats/summary", headers=auth_headers)
    assert resp.get_json()["detection_status"] == {"state": "unknown", "last_run_at": None}


def test_stats_summary_detection_status_healthy_after_recent_success(app, client, db, auth_headers):
    from app.services import job_status
    app.config["ENABLE_SCHEDULER"] = True
    job_status.record_run("anomaly_detection", "success")

    resp = client.get("/api/stats/summary", headers=auth_headers)
    body = resp.get_json()["detection_status"]
    assert body["state"] == "healthy"
    assert body["last_run_at"] is not None


def test_stats_summary_detection_status_failed_when_last_run_failed(app, client, db, auth_headers):
    from app.services import job_status
    app.config["ENABLE_SCHEDULER"] = True
    job_status.record_run("anomaly_detection", "failed")

    resp = client.get("/api/stats/summary", headers=auth_headers)
    assert resp.get_json()["detection_status"]["state"] == "failed"


def test_stats_summary_detection_status_stale_past_the_interval(app, client, db, auth_headers):
    from datetime import datetime, timedelta, timezone
    from app.services import job_status
    app.config["ENABLE_SCHEDULER"] = True
    app.config["DETECTION_INTERVAL_SECONDS"] = 30
    job_status.record_run("anomaly_detection", "success")
    # Backdate the recorded run past the 3x-interval staleness threshold.
    job_status._last_run["anomaly_detection"]["at"] = datetime.now(timezone.utc) - timedelta(seconds=200)

    resp = client.get("/api/stats/summary", headers=auth_headers)
    assert resp.get_json()["detection_status"]["state"] == "stale"


def test_stats_summary_events_by_country(client, db, auth_headers):
    _seed_event(db, source_ip="8.8.8.8")  # public -> United States
    _seed_event(db, source_ip="192.168.1.50")  # private -> Unknown / Private

    resp = client.get("/api/stats/summary", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()["events_by_country"]
    assert body["United States"] == 1
    assert body["Unknown / Private"] == 1


def test_stats_timeseries(client, db, auth_headers):
    _seed_event(db)
    resp = client.get("/api/stats/timeseries?hours=24", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["hours"] == 24
    assert len(body["series"]) == 1
    assert body["series"][0]["total"] == 1


def test_stats_summary_mitre_technique_counts(client, db, auth_headers):
    event = _seed_event(db)
    technique = MitreTechnique(technique_id="T1110", name="Brute Force", tactic="Credential Access")
    db.session.add(technique)
    db.session.flush()
    alert = Alert(event_id=event.id, rule_name="brute_force_ssh", severity="critical",
                  description="test", status="open", mitre_techniques=[technique])
    db.session.add(alert)
    db.session.commit()

    resp = client.get("/api/stats/summary", headers=auth_headers)
    assert resp.status_code == 200
    counts = resp.get_json()["mitre_technique_counts"]
    assert counts == [{"technique_id": "T1110", "name": "Brute Force",
                        "tactic": "Credential Access", "count": 1}]


def test_stats_ioc_timeseries(client, db, auth_headers):
    event = _seed_event(db)
    ioc = IOC(indicator="1.2.3.4", indicator_type="ip", normalized_indicator="1.2.3.4")
    db.session.add(ioc)
    db.session.flush()
    match = IOCMatch(ioc_id=ioc.id, event_id=event.id, matched_field="source_ip",
                      matched_value="1.2.3.4")
    db.session.add(match)
    db.session.commit()

    resp = client.get("/api/stats/ioc-timeseries?hours=24", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["hours"] == 24
    assert len(body["series"]) == 1
    assert body["series"][0]["count"] == 1


def test_alerts_list_and_resolve(client, db, auth_headers):
    event = _seed_event(db)
    alert = Alert(event_id=event.id, rule_name="brute_force_ssh", severity="critical",
                  description="test", status="open")
    db.session.add(alert)
    db.session.commit()

    resp = client.get("/api/alerts?status=open", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["total"] == 1

    resp = client.patch(f"/api/alerts/{alert.id}", json={"status": "resolved"}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "resolved"

    resp = client.get("/api/alerts?status=open", headers=auth_headers)
    assert resp.get_json()["total"] == 0


def test_rules_crud(client, db, admin_auth_headers):
    # Rules management is admin-only under RBAC; analysts can still read (see
    # test_rbac.py for the full role matrix).
    resp = client.post("/api/rules", json={
        "name": "test_rule",
        "rule_type": "threshold",
        "condition": {"event_type": "authentication_failure", "count": 5, "window_seconds": 60},
    }, headers=admin_auth_headers)
    assert resp.status_code == 201
    rule_id = resp.get_json()["id"]

    resp = client.get("/api/rules", headers=admin_auth_headers)
    assert resp.status_code == 200
    assert len(resp.get_json()) == 1

    resp = client.patch(f"/api/rules/{rule_id}", json={"enabled": False}, headers=admin_auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["enabled"] is False

    resp = client.delete(f"/api/rules/{rule_id}", headers=admin_auth_headers)
    assert resp.status_code == 204


def test_get_single_log_event(client, db, auth_headers):
    event = _seed_event(db)
    resp = client.get(f"/api/logs/{event.id}", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["id"] == event.id
    assert body["event_type"] == "authentication_failure"
    assert body["source_type"] == "ssh"
