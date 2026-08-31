def test_metrics_endpoint_no_auth_required(client):
    resp = client.get("/api/metrics")
    assert resp.status_code == 200


def test_metrics_endpoint_exposes_expected_series(client):
    body = client.get("/api/metrics").get_data(as_text=True)
    for name in (
        "http_requests_total", "http_request_duration_seconds",
        "detection_job_runs_total", "detection_job_duration_seconds",
        "alerts_created_total", "playbook_executions_total",
    ):
        assert name in body


def test_http_requests_are_counted(client, db, auth_headers):
    client.get("/api/stats/summary", headers=auth_headers)
    body = client.get("/api/metrics").get_data(as_text=True)
    assert 'path="/api/stats/summary"' in body


def test_alert_creation_increments_alerts_created_total(client, db, auth_headers):
    from datetime import datetime
    from app.models import Event
    from app import db as _db

    with client.application.app_context():
        event = Event(
            timestamp=datetime.utcnow(), event_type="authentication_failure", category="authentication",
            source_type="ssh", source_ip="10.0.0.1", raw_message="x", severity="critical",
        )
        _db.session.add(event)
        _db.session.flush()

        from app.services.enrichment import enrich_and_correlate
        from app.models import Alert
        alert = Alert(event_id=event.id, rule_name="brute_force_ssh", severity="critical",
                      description="test", detection_source="rule")
        _db.session.add(alert)
        _db.session.flush()
        enrich_and_correlate(alert)
        _db.session.commit()

    body = client.get("/api/metrics").get_data(as_text=True)
    assert 'alerts_created_total{detection_source="rule",severity="critical"}' in body
