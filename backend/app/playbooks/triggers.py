"""
Wires alert/incident lifecycle events (published on app/events/bus.py by
app/services/enrichment.py, correlation.py, and app/routes/incidents.py) to
matching enabled playbooks. This is the only module that turns a bus event
into a new PlaybookExecution -- detection/correlation code never knows
playbooks exist.

Runs synchronously on the publisher's thread/app-context (matching
playbooks -> creating the PlaybookExecution row is fast, plain ORM), then
hands off to engine.start_execution_async for the actual (potentially slow)
run.
"""
import logging

from flask import current_app

from app import db
from app.events import bus
from app.models import Alert, Incident
from app.playbooks import engine
from app.playbooks.models import Playbook

logger = logging.getLogger(__name__)


def register_triggers():
    bus.subscribe("alert.created", _on_alert_created)
    bus.subscribe("incident.created", _on_incident_created)
    bus.subscribe("incident.status_changed", _on_incident_status_changed)


def _fire(trigger_type: str, alert, incident):
    context = engine.build_context(alert, incident)
    playbooks = Playbook.query.filter_by(enabled=True, trigger_type=trigger_type).all()
    if not playbooks:
        return
    app = current_app._get_current_object()

    for playbook in playbooks:
        if not engine.matches_trigger(playbook, context):
            continue
        from app.playbooks.models import PlaybookExecution
        execution = PlaybookExecution(
            playbook_id=playbook.id,
            incident_id=incident.id if incident else (alert.incident_id if alert else None),
            alert_id=alert.id if alert else None,
            triggered_by=None,  # automatic trigger, not a person
            status="pending",
            mode="automatic",
        )
        db.session.add(execution)
        db.session.commit()
        logger.info("Playbook %r auto-triggered by %s (execution %s)", playbook.name, trigger_type, execution.id)
        engine.start_execution_async(app, execution.id)


def _on_alert_created(envelope):
    alert = Alert.query.get(envelope["data"].get("id"))
    if alert is not None:
        _fire("alert", alert, None)


def _on_incident_created(envelope):
    incident = Incident.query.get(envelope["data"].get("incident_id"))
    if incident is not None:
        _fire("incident", None, incident)


def _on_incident_status_changed(envelope):
    incident = Incident.query.get(envelope["data"].get("incident_id"))
    if incident is not None:
        _fire("incident", None, incident)
