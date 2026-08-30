"""
Playbook execution API: manual execution, approval/rejection/cancellation,
and the separation-of-duties rule (Part J.27, Part 40's approval/rejection
scenarios).

execute_playbook() (app/routes/playbooks.py) hands off to
engine.start_execution_async(), which in production spawns a real
background thread (see app/playbooks/engine.py) so a slow action never
blocks the web worker. Testing through that real thread means polling a
different thread's writes with a bounded timeout, which is inherently
racy against pytest's per-test in-memory SQLite teardown. Since these
tests are about the ROUTE logic (RBAC, separation of duties, state
transitions) and not about threading itself, the `sync_playbooks` fixture
patches start_execution_async to run inline instead -- same route, same
engine, no thread, no race. test_manual_execution_actually_uses_a_background_thread
at the bottom is the one test that deliberately exercises the real thread,
to prove the wiring itself works.
"""
import time

import pytest

from app.models import Incident, User
from app.playbooks.models import Playbook, PlaybookExecution
from app.playbooks import engine as playbook_engine
from app.utils.auth import encode_token


@pytest.fixture
def sync_playbooks(monkeypatch):
    monkeypatch.setattr(playbook_engine, "start_execution_async",
                         lambda app, execution_id: playbook_engine.run(app, execution_id))


def _wait_until(db, predicate, timeout=3.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        db.session.expire_all()
        if predicate():
            # A small grace period: the predicate can turn true a moment
            # before the background thread's `with app.app_context():`
            # actually unwinds (which runs Flask-SQLAlchemy's teardown).
            # Without this, that teardown can still be in flight when the
            # test function returns and pytest starts tearing down its own
            # app/db fixtures, racing on the shared `db` extension object.
            time.sleep(0.1)
            return True
        time.sleep(interval)
    db.session.expire_all()
    return predicate()


def _make_incident(db):
    incident = Incident(title="Approval test incident", severity="high", status="open")
    db.session.add(incident)
    db.session.commit()
    return incident


def _low_risk_playbook(db):
    pb = Playbook(name="low-risk-pb", trigger_type="manual",
                  steps=[{"action": "add_incident_tag", "parameters": {"tag": "t"}}])
    db.session.add(pb)
    db.session.commit()
    return pb


def _high_risk_playbook(db):
    pb = Playbook(name="high-risk-pb", trigger_type="manual",
                  steps=[{"action": "block_ip", "parameters": {"ip": "203.0.113.9"}}])
    db.session.add(pb)
    db.session.commit()
    return pb


def _second_admin_headers(db):
    u = User(email="admin2@example.com", role="admin")
    u.set_password("password123")
    db.session.add(u)
    db.session.commit()
    return {"Authorization": f"Bearer {encode_token(u)}"}, u.id


def test_execute_low_risk_playbook_completes(client, db, auth_headers, sync_playbooks):
    incident = _make_incident(db)
    pb = _low_risk_playbook(db)

    resp = client.post(f"/api/playbooks/{pb.id}/execute", json={"incident_id": incident.id},
                        headers=auth_headers)
    assert resp.status_code == 202
    execution_id = resp.get_json()["id"]
    assert PlaybookExecution.query.get(execution_id).status == "completed"


def test_execute_disabled_playbook_rejected(client, db, auth_headers):
    pb = Playbook(name="disabled-pb", trigger_type="manual", enabled=False,
                  steps=[{"action": "notify_analyst", "parameters": {}}])
    db.session.add(pb)
    db.session.commit()

    resp = client.post(f"/api/playbooks/{pb.id}/execute", json={}, headers=auth_headers)
    assert resp.status_code == 409


def test_high_risk_execute_reaches_awaiting_approval(client, db, auth_headers, sync_playbooks):
    incident = _make_incident(db)
    pb = _high_risk_playbook(db)

    resp = client.post(f"/api/playbooks/{pb.id}/execute", json={"incident_id": incident.id},
                        headers=auth_headers)
    execution_id = resp.get_json()["id"]
    assert PlaybookExecution.query.get(execution_id).status == "awaiting_approval"


def test_analyst_cannot_approve(client, db, auth_headers, sync_playbooks):
    incident = _make_incident(db)
    pb = _high_risk_playbook(db)
    resp = client.post(f"/api/playbooks/{pb.id}/execute", json={"incident_id": incident.id}, headers=auth_headers)
    execution_id = resp.get_json()["id"]

    approve = client.post(f"/api/playbook-executions/{execution_id}/approve", headers=auth_headers)
    assert approve.status_code == 403


def test_requester_cannot_approve_own_request(client, db, admin_auth_headers, sync_playbooks):
    incident = _make_incident(db)
    pb = _high_risk_playbook(db)
    resp = client.post(f"/api/playbooks/{pb.id}/execute", json={"incident_id": incident.id},
                        headers=admin_auth_headers)
    execution_id = resp.get_json()["id"]

    # Same admin who triggered it tries to approve -- separation of duties.
    approve = client.post(f"/api/playbook-executions/{execution_id}/approve", headers=admin_auth_headers)
    assert approve.status_code == 403


def test_different_admin_can_approve_and_it_completes(client, db, admin_auth_headers, sync_playbooks):
    incident = _make_incident(db)
    pb = _high_risk_playbook(db)
    resp = client.post(f"/api/playbooks/{pb.id}/execute", json={"incident_id": incident.id},
                        headers=admin_auth_headers)
    execution_id = resp.get_json()["id"]

    other_admin_headers, _ = _second_admin_headers(db)
    approve = client.post(f"/api/playbook-executions/{execution_id}/approve", headers=other_admin_headers)
    assert approve.status_code == 200
    assert PlaybookExecution.query.get(execution_id).status == "completed"


def test_reject_fails_execution_without_running_action(client, db, admin_auth_headers, sync_playbooks):
    incident = _make_incident(db)
    pb = _high_risk_playbook(db)
    resp = client.post(f"/api/playbooks/{pb.id}/execute", json={"incident_id": incident.id},
                        headers=admin_auth_headers)
    execution_id = resp.get_json()["id"]

    other_admin_headers, _ = _second_admin_headers(db)
    reject = client.post(f"/api/playbook-executions/{execution_id}/reject",
                          json={"reason": "not warranted"}, headers=other_admin_headers)
    assert reject.status_code == 200
    assert PlaybookExecution.query.get(execution_id).status == "failed"


def test_cancel_pending_execution(client, db, auth_headers, monkeypatch):
    """No sync_playbooks here -- we want the execution to still be
    genuinely pending (not already finished) when cancel is called. A real
    background thread with no artificial delay would race the cancel
    request non-deterministically (and, being backed by SQLite's
    single-shared-connection :memory: StaticPool in tests, unsafely), so
    engine.run() is given a small head start delay to make the ordering
    deterministic: cancel always reaches the row first."""
    original_run = playbook_engine.run

    def _delayed_run(app, execution_id):
        time.sleep(0.3)
        original_run(app, execution_id)

    monkeypatch.setattr(playbook_engine, "run", _delayed_run)

    incident = _make_incident(db)
    pb = _low_risk_playbook(db)
    resp = client.post(f"/api/playbooks/{pb.id}/execute", json={"incident_id": incident.id}, headers=auth_headers)
    execution_id = resp.get_json()["id"]

    cancel = client.post(f"/api/playbook-executions/{execution_id}/cancel", headers=auth_headers)
    assert cancel.status_code == 200
    assert PlaybookExecution.query.get(execution_id).status == "cancelled"

    # The delayed background thread still fires after its sleep -- it sees
    # status="cancelled" and returns immediately without executing any step
    # (see engine.run()'s cancellation check). Let it actually finish before
    # the test (and its in-memory DB) tears down, so it can't race the next
    # test's fresh app/engine.
    time.sleep(0.4)
    assert PlaybookExecution.query.get(execution_id).status == "cancelled"


def test_cannot_cancel_someone_elses_execution(client, db, admin_auth_headers, sync_playbooks):
    incident = _make_incident(db)
    pb = _high_risk_playbook(db)
    resp = client.post(f"/api/playbooks/{pb.id}/execute", json={"incident_id": incident.id},
                        headers=admin_auth_headers)
    execution_id = resp.get_json()["id"]

    # A non-owner, non-admin tries to cancel -- only the owner or an admin may.
    analyst = User(email="analyst2@example.com", role="analyst")
    analyst.set_password("password123")
    db.session.add(analyst)
    db.session.commit()
    analyst_headers = {"Authorization": f"Bearer {encode_token(analyst)}"}

    cancel = client.post(f"/api/playbook-executions/{execution_id}/cancel", headers=analyst_headers)
    assert cancel.status_code == 403


def test_manual_execution_actually_uses_a_background_thread(app, client, db, auth_headers):
    """No sync_playbooks -- this is the one test that deliberately exercises
    the real engine.start_execution_async() path end-to-end, to prove the
    production wiring (not just the route logic) works."""
    incident = _make_incident(db)
    pb = _low_risk_playbook(db)

    resp = client.post(f"/api/playbooks/{pb.id}/execute", json={"incident_id": incident.id},
                        headers=auth_headers)
    assert resp.status_code == 202
    execution_id = resp.get_json()["id"]

    with app.app_context():
        done = _wait_until(db, lambda: PlaybookExecution.query.get(execution_id).status == "completed")
        assert done
