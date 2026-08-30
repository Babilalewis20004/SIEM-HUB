from datetime import datetime

from app.models import Event, Alert, Rule, User
from app.utils.auth import encode_token


def _seed_event(db):
    event = Event(
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
    db.session.add(event)
    db.session.commit()
    return event


# ---------- unauthenticated / forbidden ----------

def test_unauthenticated_requests_get_401(client, db):
    assert client.get("/api/logs").status_code == 401
    assert client.get("/api/alerts").status_code == 401
    assert client.get("/api/incidents").status_code == 401
    assert client.get("/api/users").status_code == 401
    assert client.post("/api/rules", json={}).status_code == 401


def test_viewer_can_read_but_not_mutate(client, db, viewer_auth_headers):
    event = _seed_event(db)
    alert = Alert(event_id=event.id, rule_name="brute_force_ssh", severity="critical",
                  description="test", status="open")
    db.session.add(alert)
    db.session.commit()

    # Reads are allowed.
    assert client.get("/api/logs", headers=viewer_auth_headers).status_code == 200
    assert client.get("/api/alerts", headers=viewer_auth_headers).status_code == 200
    assert client.get("/api/rules", headers=viewer_auth_headers).status_code == 200
    assert client.get("/api/incidents", headers=viewer_auth_headers).status_code == 200

    # Mutations are forbidden.
    assert client.post("/api/logs/upload", json={"lines": ["x"]},
                        headers=viewer_auth_headers).status_code == 403
    assert client.patch(f"/api/alerts/{alert.id}", json={"status": "acknowledged"},
                         headers=viewer_auth_headers).status_code == 403
    assert client.post("/api/rules", json={
        "name": "r", "rule_type": "threshold", "condition": {},
    }, headers=viewer_auth_headers).status_code == 403
    assert client.post("/api/alerts/run-detection", headers=viewer_auth_headers).status_code == 403
    assert client.post("/api/alerts/train-model", headers=viewer_auth_headers).status_code == 403
    assert client.get("/api/users", headers=viewer_auth_headers).status_code == 403


def test_analyst_can_operate_but_not_manage_users_or_rules(client, db, auth_headers):
    event = _seed_event(db)
    alert = Alert(event_id=event.id, rule_name="brute_force_ssh", severity="critical",
                  description="test", status="open")
    db.session.add(alert)
    db.session.commit()

    assert client.patch(f"/api/alerts/{alert.id}", json={"status": "acknowledged"},
                         headers=auth_headers).status_code == 200
    assert client.post("/api/alerts/run-detection", headers=auth_headers).status_code == 200

    # Analysts can read the user list (for incident assignment) but not manage it.
    assert client.get("/api/users", headers=auth_headers).status_code == 200

    assert client.post("/api/rules", json={
        "name": "r", "rule_type": "threshold", "condition": {},
    }, headers=auth_headers).status_code == 403
    assert client.post("/api/alerts/train-model", headers=auth_headers).status_code == 403


def test_admin_can_manage_rules_and_users(client, db, admin_auth_headers):
    resp = client.post("/api/rules", json={
        "name": "r1", "rule_type": "threshold",
        "condition": {"event_type": "authentication_failure", "count": 5, "window_seconds": 60},
    }, headers=admin_auth_headers)
    assert resp.status_code == 201

    resp = client.get("/api/users", headers=admin_auth_headers)
    assert resp.status_code == 200


# ---------- role/status protections ----------

def test_admin_cannot_change_own_role(client, db, admin_user, admin_auth_headers):
    resp = client.patch(f"/api/users/{admin_user}/role", json={"role": "viewer"},
                         headers=admin_auth_headers)
    assert resp.status_code == 403


def test_last_admin_cannot_be_demoted(client, db, admin_user, admin_auth_headers, user):
    # Promote `user` to admin so there are two admins; demoting either one
    # while the other remains active is fine.
    resp = client.patch(f"/api/users/{user}/role", json={"role": "admin"}, headers=admin_auth_headers)
    assert resp.status_code == 200

    second_admin_headers = {"Authorization": f"Bearer {encode_token(User.query.get(user))}"}
    resp = client.patch(f"/api/users/{admin_user}/role", json={"role": "viewer"},
                         headers=second_admin_headers)
    assert resp.status_code == 200

    # Only one admin (`user`) remains. Demoting them now would zero out
    # admins entirely; since only an admin can call this endpoint, the only
    # way to attempt it is `user` acting on themselves, which the separate
    # self-role-change guard blocks first (see test_admin_cannot_change_own_role).
    resp = client.patch(f"/api/users/{user}/role", json={"role": "viewer"},
                         headers=second_admin_headers)
    assert resp.status_code == 403


def test_last_admin_cannot_be_disabled(client, db, admin_user, admin_auth_headers):
    resp = client.patch(f"/api/users/{admin_user}/status", json={"is_active": False},
                         headers=admin_auth_headers)
    assert resp.status_code == 403  # also blocked as "cannot disable yourself"


def test_admin_cannot_disable_last_admin_via_other_account(client, db, admin_user, admin_auth_headers, user):
    resp = client.patch(f"/api/users/{user}/role", json={"role": "admin"}, headers=admin_auth_headers)
    assert resp.status_code == 200
    second_admin_headers = {"Authorization": f"Bearer {encode_token(User.query.get(user))}"}

    resp = client.patch(f"/api/users/{admin_user}/status", json={"is_active": False},
                         headers=second_admin_headers)
    assert resp.status_code == 200

    # Only `user` remains active-admin; disabling them now is a self-action,
    # blocked by the self-disable guard (403) before the last-admin count
    # guard would even apply.
    resp = client.patch(f"/api/users/{user}/status", json={"is_active": False},
                         headers=second_admin_headers)
    assert resp.status_code == 403


def test_invalid_role_rejected(client, db, admin_auth_headers, user):
    resp = client.patch(f"/api/users/{user}/role", json={"role": "superuser"},
                         headers=admin_auth_headers)
    assert resp.status_code == 400


# ---------- disabled users ----------

def test_disabled_user_cannot_login(client, db, admin_auth_headers, user):
    client.patch(f"/api/users/{user}/status", json={"is_active": False}, headers=admin_auth_headers)
    resp = client.post("/api/auth/login", json={"email": "analyst@example.com", "password": "password123"})
    assert resp.status_code == 403


def test_disabled_users_existing_token_is_rejected(client, db, admin_auth_headers, user, auth_headers):
    # Token was minted while the user was still active.
    assert client.get("/api/alerts", headers=auth_headers).status_code == 200
    client.patch(f"/api/users/{user}/status", json={"is_active": False}, headers=admin_auth_headers)
    assert client.get("/api/alerts", headers=auth_headers).status_code == 403


# ---------- mass assignment ----------

def test_register_ignores_client_supplied_role(client, db):
    resp = client.post("/api/auth/register", json={
        "email": "hacker@example.com", "password": "password123", "role": "admin", "is_admin": True,
    })
    assert resp.status_code == 201
    # First-ever user still becomes admin regardless of what was requested;
    # what matters is that a SECOND registration can't claim admin this way.
    resp2 = client.post("/api/auth/register", json={
        "email": "hacker2@example.com", "password": "password123", "role": "admin",
    })
    assert resp2.status_code == 201
    assert resp2.get_json()["user"]["role"] == "viewer"


def test_update_user_ignores_role_and_status_fields(client, db, admin_auth_headers, user):
    resp = client.patch(f"/api/users/{user}", json={
        "email": "still-analyst@example.com", "role": "admin", "is_active": False,
    }, headers=admin_auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["email"] == "still-analyst@example.com"
    assert body["role"] == "analyst"  # unaffected by the smuggled field
    assert body["is_active"] is True
