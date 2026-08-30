from datetime import datetime

from app.models import Incident


def _create_incident(client, headers, **overrides):
    payload = {"title": "Manual incident", "severity": "high", "priority": "high"}
    payload.update(overrides)
    resp = client.post("/api/incidents", json=payload, headers=headers)
    return resp


def test_create_and_get_incident(client, db, auth_headers):
    resp = _create_incident(client, auth_headers)
    assert resp.status_code == 201
    incident_id = resp.get_json()["id"]

    resp = client.get(f"/api/incidents/{incident_id}", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["title"] == "Manual incident"
    assert body["status"] == "open"
    assert body["alerts"] == []
    assert body["notes"] == []


def test_viewer_can_read_but_not_create_incident(client, db, viewer_auth_headers):
    resp = _create_incident(client, viewer_auth_headers)
    assert resp.status_code == 403

    resp = client.get("/api/incidents", headers=viewer_auth_headers)
    assert resp.status_code == 200


def test_update_incident_whitelists_fields(client, db, auth_headers):
    incident_id = _create_incident(client, auth_headers).get_json()["id"]

    resp = client.patch(f"/api/incidents/{incident_id}", json={
        "description": "updated", "status": "closed", "assigned_to": "someone-else",
    }, headers=auth_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["description"] == "updated"
    assert body["status"] == "open"        # status changes must go through /status
    assert body["assigned_to"] is None      # assignment must go through /assign


def test_filtering_by_status_and_severity(client, db, auth_headers):
    a = _create_incident(client, auth_headers, title="A", severity="high").get_json()["id"]
    b = _create_incident(client, auth_headers, title="B", severity="low").get_json()["id"]
    client.post(f"/api/incidents/{a}/status", json={"status": "investigating"}, headers=auth_headers)

    resp = client.get("/api/incidents?status=investigating", headers=auth_headers)
    ids = [i["id"] for i in resp.get_json()["items"]]
    assert ids == [a]

    resp = client.get("/api/incidents?severity=low", headers=auth_headers)
    ids = [i["id"] for i in resp.get_json()["items"]]
    assert ids == [b]


def test_assign_incident_rejects_disabled_user(client, db, auth_headers, admin_auth_headers, viewer_user):
    incident_id = _create_incident(client, auth_headers).get_json()["id"]
    client.patch(f"/api/users/{viewer_user}/status", json={"is_active": False}, headers=admin_auth_headers)

    resp = client.post(f"/api/incidents/{incident_id}/assign", json={"assigned_to": viewer_user},
                        headers=auth_headers)
    assert resp.status_code == 400


def test_assign_incident_success(client, db, auth_headers, viewer_user):
    incident_id = _create_incident(client, auth_headers).get_json()["id"]
    resp = client.post(f"/api/incidents/{incident_id}/assign", json={"assigned_to": viewer_user},
                        headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["assigned_to"] == viewer_user


def test_viewer_cannot_assign_or_resolve(client, db, auth_headers, viewer_auth_headers, viewer_user):
    incident_id = _create_incident(client, auth_headers).get_json()["id"]

    assert client.post(f"/api/incidents/{incident_id}/assign", json={"assigned_to": viewer_user},
                        headers=viewer_auth_headers).status_code == 403
    assert client.post(f"/api/incidents/{incident_id}/status", json={"status": "investigating"},
                        headers=viewer_auth_headers).status_code == 403
    assert client.post(f"/api/incidents/{incident_id}/notes", json={"content": "note"},
                        headers=viewer_auth_headers).status_code == 403


def test_status_state_machine_happy_path(client, db, auth_headers):
    incident_id = _create_incident(client, auth_headers).get_json()["id"]

    for status in ["investigating", "contained", "resolved", "closed"]:
        resp = client.post(f"/api/incidents/{incident_id}/status", json={"status": status},
                            headers=auth_headers)
        assert resp.status_code == 200, f"transition to {status} failed: {resp.get_json()}"
        assert resp.get_json()["status"] == status

    body = client.get(f"/api/incidents/{incident_id}", headers=auth_headers).get_json()
    assert body["resolved_at"] is not None
    assert body["resolved_by"] is not None


def test_invalid_transition_rejected(client, db, auth_headers):
    incident_id = _create_incident(client, auth_headers).get_json()["id"]
    # open -> resolved is not a direct allowed transition.
    resp = client.post(f"/api/incidents/{incident_id}/status", json={"status": "resolved"},
                        headers=auth_headers)
    assert resp.status_code == 400


def test_closed_incident_requires_explicit_reopen(client, db, auth_headers):
    incident_id = _create_incident(client, auth_headers).get_json()["id"]
    for status in ["investigating", "contained", "resolved", "closed"]:
        client.post(f"/api/incidents/{incident_id}/status", json={"status": status}, headers=auth_headers)

    resp = client.post(f"/api/incidents/{incident_id}/status", json={"status": "investigating"},
                        headers=auth_headers)
    assert resp.status_code == 400

    resp = client.post(f"/api/incidents/{incident_id}/status",
                        json={"status": "investigating", "reopen": True}, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "investigating"


def test_notes_require_auth_and_record_author(client, db, auth_headers, user):
    incident_id = _create_incident(client, auth_headers).get_json()["id"]

    resp = client.post(f"/api/incidents/{incident_id}/notes", json={"content": "investigating this"},
                        headers=auth_headers)
    assert resp.status_code == 201
    assert resp.get_json()["author_id"] == user

    resp = client.post(f"/api/incidents/{incident_id}/notes", json={"content": "second note"})
    assert resp.status_code == 401

    body = client.get(f"/api/incidents/{incident_id}", headers=auth_headers).get_json()
    assert len(body["notes"]) == 1
    assert body["notes"][0]["content"] == "investigating this"
