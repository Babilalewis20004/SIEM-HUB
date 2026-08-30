"""
Security-focused tests for the playbook subsystem (Part V): privilege
escalation, IDOR/authorization-bypass attempts, and rejecting anything that
tries to smuggle arbitrary code execution through a playbook definition.
"""
import pytest

from app.models import Incident
from app.playbooks.models import Playbook, PlaybookExecution
from app.playbooks import engine as playbook_engine


@pytest.fixture
def sync_playbooks(monkeypatch):
    """Runs playbook executions inline instead of on a real background
    thread -- see test_playbook_approvals.py's docstring for why."""
    monkeypatch.setattr(playbook_engine, "start_execution_async",
                         lambda app, execution_id: playbook_engine.run(app, execution_id))


def _make_incident(db):
    incident = Incident(title="Security test incident", severity="high", status="open")
    db.session.add(incident)
    db.session.commit()
    return incident


# ---- privilege escalation -------------------------------------------------

def test_viewer_cannot_execute_playbook(client, db, viewer_auth_headers):
    pb = Playbook(name="viewer-test-pb", trigger_type="manual",
                  steps=[{"action": "notify_analyst", "parameters": {}}])
    db.session.add(pb)
    db.session.commit()

    resp = client.post(f"/api/playbooks/{pb.id}/execute", json={}, headers=viewer_auth_headers)
    assert resp.status_code == 403


def test_viewer_cannot_manage_playbooks(client, db, viewer_auth_headers):
    resp = client.post("/api/playbooks", json={
        "name": "viewer-created", "steps": [{"action": "notify_analyst", "parameters": {}}],
    }, headers=viewer_auth_headers)
    assert resp.status_code == 403


def test_analyst_cannot_manage_playbooks(client, db, auth_headers):
    """Analyst can execute (PLAYBOOKS_EXECUTE) but not author/edit/delete
    playbook definitions (PLAYBOOKS_MANAGE is admin-only)."""
    resp = client.post("/api/playbooks", json={
        "name": "analyst-created", "steps": [{"action": "notify_analyst", "parameters": {}}],
    }, headers=auth_headers)
    assert resp.status_code == 403


def test_analyst_cannot_approve_or_reject(client, db, auth_headers):
    pb = Playbook(name="approve-test-pb", trigger_type="manual",
                  steps=[{"action": "block_ip", "parameters": {"ip": "1.2.3.4"}}])
    db.session.add(pb)
    db.session.flush()  # populate pb.id before referencing it below
    execution = PlaybookExecution(playbook_id=pb.id, status="awaiting_approval", mode="manual")
    db.session.add(execution)
    db.session.commit()

    assert client.post(f"/api/playbook-executions/{execution.id}/approve",
                        headers=auth_headers).status_code == 403
    assert client.post(f"/api/playbook-executions/{execution.id}/reject",
                        headers=auth_headers).status_code == 403


# ---- IDOR / state-machine abuse -------------------------------------------

def test_cannot_approve_execution_with_no_pending_approval(client, db, admin_auth_headers):
    pb = Playbook(name="no-approval-pb", trigger_type="manual",
                  steps=[{"action": "notify_analyst", "parameters": {}}])
    db.session.add(pb)
    db.session.flush()  # populate pb.id before referencing it below
    execution = PlaybookExecution(playbook_id=pb.id, status="completed", mode="manual")
    db.session.add(execution)
    db.session.commit()

    resp = client.post(f"/api/playbook-executions/{execution.id}/approve", headers=admin_auth_headers)
    assert resp.status_code == 409


def test_approve_unknown_execution_id_is_404_not_500(client, db, admin_auth_headers):
    resp = client.post("/api/playbook-executions/does-not-exist/approve", headers=admin_auth_headers)
    assert resp.status_code == 404


# ---- arbitrary action / code execution ------------------------------------

def test_unregistered_action_rejected_at_creation(client, db, admin_auth_headers):
    resp = client.post("/api/playbooks", json={
        "name": "malicious-pb",
        "steps": [{"action": "os.system", "parameters": {"command": "rm -rf /"}}],
    }, headers=admin_auth_headers)
    assert resp.status_code == 400
    assert Playbook.query.filter_by(name="malicious-pb").first() is None


def test_python_builtin_lookup_rejected_at_creation(client, db, admin_auth_headers):
    resp = client.post("/api/playbooks", json={
        "name": "malicious-pb-2",
        "steps": [{"action": "__import__", "parameters": {"name": "os"}}],
    }, headers=admin_auth_headers)
    assert resp.status_code == 400
    assert Playbook.query.filter_by(name="malicious-pb-2").first() is None


def test_condition_with_disallowed_operator_rejected(client, db, admin_auth_headers):
    resp = client.post("/api/playbooks", json={
        "name": "bad-condition-pb",
        "steps": [{
            "action": "add_incident_tag", "parameters": {"tag": "x"},
            "condition": {"field": "severity", "op": "__import__('os').system", "value": "high"},
        }],
    }, headers=admin_auth_headers)
    assert resp.status_code == 400
    assert Playbook.query.filter_by(name="bad-condition-pb").first() is None


def test_missing_required_parameters_rejected(client, db, admin_auth_headers):
    resp = client.post("/api/playbooks", json={
        "name": "missing-params-pb",
        "steps": [{"action": "block_ip", "parameters": {}}],
    }, headers=admin_auth_headers)
    assert resp.status_code == 400


def test_arbitrary_extra_fields_in_parameters_are_inert_data(db, admin_auth_headers, client, sync_playbooks):
    """Parameters an action doesn't recognise are just ignored, never
    interpreted -- e.g. a stray 'eval' key alongside a valid tag."""
    incident = _make_incident(db)
    resp = client.post("/api/playbooks", json={
        "name": "extra-params-pb", "trigger_type": "manual",
        "steps": [{"action": "add_incident_tag",
                   "parameters": {"tag": "safe-tag", "eval": "__import__('os').system('id')"}}],
    }, headers=admin_auth_headers)
    assert resp.status_code == 201
    pb_id = resp.get_json()["id"]

    exec_resp = client.post(f"/api/playbooks/{pb_id}/execute", json={"incident_id": incident.id},
                             headers=admin_auth_headers)
    assert exec_resp.status_code == 202
    execution_id = exec_resp.get_json()["id"]

    assert PlaybookExecution.query.get(execution_id).status == "completed"
    assert "safe-tag" in Incident.query.get(incident.id).tags
