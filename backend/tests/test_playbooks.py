"""
Playbook engine tests: validation, dry-run/manual execution, condition
evaluation, and idempotency (Part 38/40/41). Executions are run via
engine.run() directly (not the background thread) so tests stay
deterministic -- but engine.run() always opens its OWN nested app context
(required for its real caller, a bare background thread with no context at
all), which gives it a separate scoped SQLAlchemy session from the test's.
_run() below expires the test's session afterward so assertions see what
engine.run() actually committed instead of a stale pre-run identity-mapped
object -- a test-harness-only concern, not a production one (production
never re-reads through the *calling* session).
"""
from app.models import Incident, Alert, Event, Rule
from app.playbooks.models import Playbook, PlaybookExecution, PlaybookApproval, PlaybookActionLog
from app.playbooks import engine
from app.playbooks.validators import validate_playbook_definition
from app.playbooks.registry import get_action


def _run(app, db, execution_id):
    engine.run(app, execution_id)
    db.session.expire_all()


def _make_incident(db, severity="high"):
    incident = Incident(title="Test incident", severity=severity, status="open")
    db.session.add(incident)
    db.session.commit()
    return incident


def _make_playbook(db, steps, trigger_type="manual", trigger_condition=None, name="test-playbook"):
    pb = Playbook(name=name, trigger_type=trigger_type, trigger_condition=trigger_condition or {}, steps=steps)
    db.session.add(pb)
    db.session.commit()
    return pb


def _make_execution(db, playbook, incident=None, alert=None, triggered_by=None, mode="manual"):
    ex = PlaybookExecution(
        playbook_id=playbook.id, incident_id=incident.id if incident else None,
        alert_id=alert.id if alert else None, triggered_by=triggered_by, status="pending", mode=mode,
    )
    db.session.add(ex)
    db.session.commit()
    return ex


# ---- validators -------------------------------------------------------

def test_validator_rejects_unknown_action():
    errors = validate_playbook_definition({
        "name": "bad", "steps": [{"action": "os.system", "parameters": {"command": "rm -rf /"}}],
    })
    assert any("unknown action" in e for e in errors)


def test_validator_rejects_missing_required_parameter():
    errors = validate_playbook_definition({
        "name": "bad", "steps": [{"action": "block_ip", "parameters": {}}],
    })
    assert any("missing required parameter" in e for e in errors)


def test_validator_accepts_well_formed_definition():
    errors = validate_playbook_definition({
        "name": "good", "trigger_type": "manual",
        "steps": [{"action": "add_incident_tag", "parameters": {"tag": "test"}}],
    })
    assert errors == []


def test_registry_has_no_dynamic_lookup_for_unregistered_names():
    assert get_action("os.system") is None
    assert get_action("__import__") is None


# ---- engine: local actions ---------------------------------------------

def test_low_risk_playbook_completes_and_mutates_incident(app, db):
    with app.app_context():
        incident = _make_incident(db)
        pb = _make_playbook(db, steps=[
            {"action": "add_incident_tag", "parameters": {"tag": "brute-force"}},
            {"action": "create_case_note", "parameters": {"content": "Automated note."}},
        ])
        execution = _make_execution(db, pb, incident=incident)

        _run(app, db, execution.id)

        execution = PlaybookExecution.query.get(execution.id)
        incident = Incident.query.get(incident.id)
        assert execution.status == "completed"
        assert "brute-force" in incident.tags
        assert len(incident.notes) == 1
        assert incident.notes[0].author_id is None  # no human actor -> system note


def test_condition_false_skips_step(app, db):
    with app.app_context():
        incident = _make_incident(db, severity="low")
        pb = _make_playbook(db, steps=[
            {"action": "add_incident_tag", "parameters": {"tag": "should-not-apply"},
             "condition": {"field": "severity", "op": ">=", "value": "high"}},
        ])
        execution = _make_execution(db, pb, incident=incident)

        _run(app, db, execution.id)

        execution = PlaybookExecution.query.get(execution.id)
        incident = Incident.query.get(incident.id)
        assert execution.status == "completed"
        assert incident.tags in (None, [])


# ---- engine: approval gate ----------------------------------------------

def test_high_risk_step_pauses_for_approval(app, db):
    with app.app_context():
        incident = _make_incident(db)
        pb = _make_playbook(db, steps=[
            {"action": "add_incident_tag", "parameters": {"tag": "malicious-ioc"}},
            {"action": "block_ip", "parameters": {"ip": "203.0.113.9"}},
        ])
        execution = _make_execution(db, pb, incident=incident)

        _run(app, db, execution.id)

        execution = PlaybookExecution.query.get(execution.id)
        assert execution.status == "awaiting_approval"
        approval = PlaybookApproval.query.filter_by(execution_id=execution.id).first()
        assert approval is not None
        assert approval.status == "pending"
        assert approval.risk_level == "high"
        # First (low-risk) step already ran even though the second is paused.
        incident = Incident.query.get(incident.id)
        assert "malicious-ioc" in incident.tags
        # block_ip itself must NOT have executed yet.
        assert PlaybookActionLog.query.filter_by(execution_id=execution.id, action="block_ip").count() == 0


def test_step_cannot_opt_out_of_approval_for_high_risk_action(app, db):
    """A playbook step setting approval_required: false on a HIGH-risk
    action must not bypass the server-side approval floor (Part J)."""
    with app.app_context():
        incident = _make_incident(db)
        pb = _make_playbook(db, steps=[
            {"action": "block_ip", "parameters": {"ip": "203.0.113.9"}, "approval_required": False},
        ])
        execution = _make_execution(db, pb, incident=incident)

        _run(app, db, execution.id)

        execution = PlaybookExecution.query.get(execution.id)
        assert execution.status == "awaiting_approval"


def test_approved_execution_resumes_and_completes(app, db):
    with app.app_context():
        incident = _make_incident(db)
        pb = _make_playbook(db, steps=[{"action": "block_ip", "parameters": {"ip": "203.0.113.9"}}])
        execution = _make_execution(db, pb, incident=incident)
        _run(app, db, execution.id)

        approval = PlaybookApproval.query.filter_by(execution_id=execution.id).first()
        approval.status = "approved"
        execution = PlaybookExecution.query.get(execution.id)
        execution.status = "running"
        db.session.commit()

        _run(app, db, execution.id)

        execution = PlaybookExecution.query.get(execution.id)
        assert execution.status == "completed"
        log = PlaybookActionLog.query.filter_by(execution_id=execution.id, action="block_ip").first()
        assert log.status == "completed"
        assert log.result["mode"] == "dry_run"  # MockResponseProvider -- never a real network call


def test_rejected_approval_fails_the_execution_without_running_the_action(app, db):
    with app.app_context():
        incident = _make_incident(db)
        pb = _make_playbook(db, steps=[{"action": "block_ip", "parameters": {"ip": "203.0.113.9"}}])
        execution = _make_execution(db, pb, incident=incident)
        _run(app, db, execution.id)

        approval = PlaybookApproval.query.filter_by(execution_id=execution.id).first()
        approval.status = "rejected"
        approval.reason = "not warranted"
        db.session.commit()

        _run(app, db, execution.id)

        execution = PlaybookExecution.query.get(execution.id)
        assert execution.status == "failed"
        assert "rejected" in execution.error
        assert PlaybookActionLog.query.filter_by(execution_id=execution.id, action="block_ip").count() == 0


# ---- idempotency ---------------------------------------------------------

def test_duplicate_trigger_against_same_incident_is_not_re_executed(app, db):
    """Simulates Part 32/41: the same playbook fired twice for the same
    incident (e.g. a burst of correlated alerts) must not repeat a
    dangerous action twice."""
    with app.app_context():
        incident = _make_incident(db)
        pb = _make_playbook(db, steps=[{"action": "add_incident_tag", "parameters": {"tag": "dup-test"}}])

        first = _make_execution(db, pb, incident=incident)
        _run(app, db, first.id)
        assert PlaybookExecution.query.get(first.id).status == "completed"

        second = _make_execution(db, pb, incident=incident)
        _run(app, db, second.id)

        assert PlaybookExecution.query.get(second.id).status == "completed"
        # Only ever one PlaybookActionLog row for this (scope, action, target) --
        # the DB unique constraint is the backstop, the pre-check is the fast path.
        logs = PlaybookActionLog.query.filter_by(action="add_incident_tag", scope_key=incident.id).all()
        assert len(logs) == 1
        assert logs[0].status == "completed"


def test_action_failure_fails_the_execution_and_records_the_error(app, db):
    with app.app_context():
        incident = _make_incident(db)
        # create_case_note requires content indirectly via sanitize_text
        # falling back to a default -- use an action with a hard failure
        # mode instead: disable_detection_rule on a rule that doesn't exist.
        pb = _make_playbook(db, steps=[
            {"action": "disable_detection_rule", "parameters": {"rule_name": "does-not-exist"}},
        ])
        execution = _make_execution(db, pb, incident=incident)

        _run(app, db, execution.id)

        execution = PlaybookExecution.query.get(execution.id)
        assert execution.status == "failed"
        log = PlaybookActionLog.query.filter_by(execution_id=execution.id).first()
        assert log.status == "failed"
        assert log.error
