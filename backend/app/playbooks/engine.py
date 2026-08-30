"""
Playbook execution engine. A run is started on a background thread
(socketio.start_background_task, from either a manual "execute" API call or
an automatic trigger in app/playbooks/triggers.py) so a slow action can
never block the web worker -- but that also means run()/_run_step() must
open their own app context and must never hand db.session-touching work to
a second thread (Flask-SQLAlchemy's session is thread-local; a second
thread would get a different, uncommitted session). Only the four
provider-backed "external" actions (which never touch db.session -- see
providers.py) run inside a ThreadPoolExecutor with a timeout; every local
action runs directly on the engine's own thread.

current_step_index is where a paused (awaiting_approval) run resumes from,
so approving a step never re-executes already-completed steps.
"""
import logging
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime

from flask import current_app
from sqlalchemy.exc import IntegrityError

from app import db
from app.events import bus
from app.models import Alert, Incident
from app.services.audit import log_action
from app.playbooks.actions import ActionContext
from app.playbooks.models import PlaybookExecution, PlaybookApproval, PlaybookActionLog
from app.playbooks.registry import get_action

logger = logging.getLogger(__name__)

DEFAULT_ACTION_TIMEOUT_SECONDS = 10
SEVERITY_RANK = {"info": 0, "low": 1, "warning": 2, "medium": 2, "high": 3, "critical": 4}
_TEMPLATE_RE = re.compile(r"\{\{(\w+)\}\}")


def build_context(alert: Alert = None, incident: Incident = None) -> dict:
    """Small, flat dict describing the trigger, used for both condition
    evaluation and {{template}} parameter substitution. Steps only ever see
    these primitives, never the raw ORM objects."""
    event = alert.event if alert else None
    return {
        "alert_id": alert.id if alert else None,
        "incident_id": incident.id if incident else (alert.incident_id if alert else None),
        "severity": (alert.severity if alert else (incident.severity if incident else None)) or "",
        "ioc_match": bool(alert.ioc_matches) if alert else False,
        "mitre_technique": alert.mitre_technique if alert else None,
        "rule_name": alert.rule_name if alert else None,
        "source_ip": event.source_ip if event else None,
        "hostname": event.hostname if event else None,
        "username": event.username if event else None,
    }


def _evaluate_condition(condition, context: dict) -> bool:
    """Fixed operator set, never eval()'d -- see Part 29's "declarative,
    validated" requirement. `severity` is compared by rank so ">=" / "<="
    are meaningful; every other field is compared by equality/membership."""
    if not condition:
        return True
    field = condition.get("field")
    op = condition.get("op", "==")
    actual, expected = context.get(field), condition.get("value")

    if field == "severity":
        actual = SEVERITY_RANK.get(str(actual or "").lower(), -1)
        expected = SEVERITY_RANK.get(str(expected or "").lower(), -1)

    ops = {
        "==": lambda a, b: a == b, "!=": lambda a, b: a != b,
        ">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b,
        ">": lambda a, b: a > b, "<": lambda a, b: a < b,
        "in": lambda a, b: a in (b or []),
    }
    return ops.get(op, ops["=="])(actual, expected)


def matches_trigger(playbook, context: dict) -> bool:
    """AND-of-equalities trigger match (Part 30/31 examples), plus a narrow
    ">=high" / "<=medium" shorthand for severity -- a fixed prefix parse,
    not a general expression language."""
    condition = playbook.trigger_condition or {}
    for field, expected in condition.items():
        if field == "severity" and isinstance(expected, str) and expected[:2] in (">=", "<="):
            if not _evaluate_condition({"field": field, "op": expected[:2], "value": expected[2:]}, context):
                return False
        elif isinstance(expected, list):
            if context.get(field) not in expected:
                return False
        elif context.get(field) != expected:
            return False
    return True


def _resolve_parameters(parameters: dict, context: dict) -> dict:
    def _sub(value):
        if isinstance(value, str):
            return _TEMPLATE_RE.sub(lambda m: str(context.get(m.group(1)) or ""), value)
        return value
    return {k: _sub(v) for k, v in (parameters or {}).items()}


def _target_for(action_name: str, parameters: dict):
    """The value that makes a step's *effect* unique for idempotency -- e.g.
    re-blocking the same IP for the same incident is a duplicate, blocking a
    different IP is not. None means "never deduplicated" (safe to repeat:
    notes, notifications, ack/resolve, rule toggles)."""
    field = {"block_ip": "ip", "disable_user": "user_id", "isolate_host": "host",
              "add_incident_tag": "tag", "create_ioc": "indicator"}.get(action_name)
    if field:
        return parameters.get(field)
    if action_name == "kill_process":
        return f"{parameters.get('host')}:{parameters.get('process')}"
    return None


def start_execution_async(app, execution_id: str):
    from app import socketio
    socketio.start_background_task(run, app, execution_id)


def run(app, execution_id: str):
    with app.app_context():
        execution = PlaybookExecution.query.get(execution_id)
        if execution is None:
            logger.error("playbook execution %s vanished before it could run", execution_id)
            return

        playbook = execution.playbook
        if playbook is None:
            # playbook_id is NOT NULL and delete_playbook() refuses to delete
            # a playbook with execution history, so this should be
            # unreachable in production -- treat it the same as a vanished
            # execution rather than crashing the background thread.
            logger.error("playbook execution %s has no resolvable playbook", execution_id)
            return

        if execution.status == "cancelled":
            # A cancel request (only allowed while status is pending or
            # awaiting_approval -- see cancel_execution in
            # app/routes/playbooks.py) landed before this background thread
            # got to run at all. Respect it instead of barreling ahead and
            # overwriting "cancelled" with "completed"/"failed" once done.
            return

        context = build_context(execution.alert, execution.incident)
        steps = playbook.steps or []

        if execution.status == "pending":
            execution.status = "running"
            db.session.commit()
            bus.publish("playbook.started", {
                "execution_id": execution.id, "playbook_id": playbook.id,
                "playbook_name": playbook.name, "incident_id": execution.incident_id,
                "alert_id": execution.alert_id,
            })

        idx = execution.current_step_index
        while idx < len(steps):
            outcome = _run_step(execution, playbook, idx, steps[idx], context)
            if outcome in ("paused", "failed"):
                return
            idx += 1
            execution.current_step_index = idx
            db.session.commit()

        execution.status = "completed"
        execution.completed_at = datetime.utcnow()
        db.session.commit()
        bus.publish("playbook.completed", {
            "execution_id": execution.id, "playbook_id": playbook.id, "playbook_name": playbook.name,
        })


def _fail_execution(execution, playbook, message: str):
    execution.status = "failed"
    execution.error = message
    execution.completed_at = datetime.utcnow()
    db.session.commit()
    bus.publish("playbook.failed", {
        "execution_id": execution.id, "playbook_id": playbook.id, "playbook_name": playbook.name,
        "error": message,
    })


def _skip_duplicate(execution, idx, action_name):
    """Audit-only record of a skipped duplicate -- never a PlaybookActionLog
    row, since that table's uq_playbook_action_scope constraint means only
    one row can ever exist per (scope_key, action, target)."""
    log_action(None, "playbook.action_skipped_duplicate", "playbook_execution", execution.id,
               {"step_index": idx, "action": action_name})
    db.session.commit()
    bus.publish("playbook.action_completed", {
        "execution_id": execution.id, "step_index": idx, "action": action_name, "status": "skipped_duplicate",
    })


def _run_step(execution, playbook, idx: int, step: dict, context: dict) -> str:
    """Returns "ok", "paused" (awaiting approval), or "failed"."""
    action_name = step.get("action")
    spec = get_action(action_name)
    if spec is None:
        _fail_execution(execution, playbook, f"Unknown action {action_name!r} (not in registry).")
        return "failed"

    if not _evaluate_condition(step.get("condition"), context):
        return "ok"  # condition false -> step skipped silently, nothing happened

    parameters = _resolve_parameters(step.get("parameters") or {}, context)
    target = _target_for(action_name, parameters)
    scope_key = execution.incident_id or execution.alert_id

    if scope_key and target:
        existing = PlaybookActionLog.query.filter_by(
            scope_key=scope_key, action=action_name, target=target,
        ).first()
        if existing is not None:
            _skip_duplicate(execution, idx, action_name)
            return "ok"

    # High/critical risk always requires approval -- a step can opt a lower-
    # risk action INTO approval (approval_required: true) but can never opt
    # a high/critical action OUT of it. This is the server-side floor Part J
    # requires; it does not trust the playbook definition alone.
    needs_approval = spec.risk_level in ("high", "critical") or bool(step.get("approval_required"))
    approval = PlaybookApproval.query.filter_by(execution_id=execution.id, step_index=idx).first()

    if needs_approval:
        if approval is None:
            approval = PlaybookApproval(
                execution_id=execution.id, step_index=idx, action=action_name, parameters=parameters,
                risk_level=spec.risk_level, requested_by=execution.triggered_by,
            )
            db.session.add(approval)
            execution.status = "awaiting_approval"
            execution.current_step_index = idx
            db.session.commit()
            bus.publish("playbook.approval_required", {
                "execution_id": execution.id, "approval_id": approval.id, "step_index": idx,
                "action": action_name, "risk_level": spec.risk_level, "incident_id": execution.incident_id,
            })
            return "paused"
        if approval.status == "pending":
            return "paused"
        if approval.status == "rejected":
            _fail_execution(execution, playbook,
                             f"Step {idx} ({action_name}) was rejected: {approval.reason or 'no reason given'}")
            return "failed"
        # approval.status == "approved" -> fall through and execute

    log_entry = PlaybookActionLog(
        execution_id=execution.id, step_index=idx, action=action_name, parameters=parameters,
        scope_key=scope_key, target=target, risk_level=spec.risk_level, status="running",
    )
    db.session.add(log_entry)
    try:
        db.session.commit()
    except IntegrityError:
        # Lost a race against a concurrent execution for the same
        # scope/action/target (e.g. two correlated alerts firing the same
        # playbook at once) -- the unique constraint is the authoritative
        # backstop behind the pre-check above.
        db.session.rollback()
        _skip_duplicate(execution, idx, action_name)
        return "ok"

    bus.publish("playbook.action_started", {
        "execution_id": execution.id, "step_index": idx, "action": action_name, "risk_level": spec.risk_level,
    })

    actor_id = (approval.approved_by if (approval and approval.status == "approved") else None) or execution.triggered_by
    ctx = ActionContext(actor_id=actor_id, incident=execution.incident, alert=execution.alert)
    timeout = current_app.config.get("PLAYBOOK_ACTION_TIMEOUT_SECONDS", DEFAULT_ACTION_TIMEOUT_SECONDS)

    try:
        if spec.external:
            # Never touches db.session -- safe to run off-thread with a timeout.
            with ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(spec.fn, ctx, parameters).result(timeout=timeout)
        else:
            result = spec.fn(ctx, parameters)
        log_entry.status = "completed"
        log_entry.result = result
        log_entry.completed_at = datetime.utcnow()
        db.session.commit()
        bus.publish("playbook.action_completed", {
            "execution_id": execution.id, "step_index": idx, "action": action_name, "status": "completed",
        })
        return "ok"
    except FutureTimeoutError:
        error = f"{action_name} timed out after {timeout}s."
    except Exception as e:
        db.session.rollback()
        error = str(e)

    log_entry = PlaybookActionLog.query.get(log_entry.id)  # re-fetch: rollback() above expired it
    log_entry.status = "failed"
    log_entry.error = error
    log_entry.completed_at = datetime.utcnow()
    db.session.commit()
    bus.publish("playbook.action_failed", {
        "execution_id": execution.id, "step_index": idx, "action": action_name, "error": error,
    })
    _fail_execution(execution, playbook, f"Step {idx} ({action_name}) failed: {error}")
    return "failed"
