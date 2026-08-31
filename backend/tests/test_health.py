def test_liveness_ok(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_liveness_requires_no_auth(client):
    # No Authorization header at all -- health checks must be reachable by
    # a load balancer/orchestrator with no credentials.
    resp = client.get("/api/health")
    assert resp.status_code != 401


def test_readiness_ok(client, db):
    resp = client.get("/api/health/ready")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok", "database": "ok"}
