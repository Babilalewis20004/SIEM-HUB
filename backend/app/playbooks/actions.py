"""
Built-in playbook action functions. Every function has signature
`fn(ctx: ActionContext, parameters: dict) -> dict` and returns a small
JSON-serialisable result dict (stored on PlaybookActionLog.result). Raise
ValueError for a parameter/state problem that should fail the step (caught
by app/playbooks/engine.py, which records it and fails the execution) --
never let an action silently no-op on bad input.

`block_ip` / `disable_user` / `kill_process` / `isolate_host` are the only
actions that reach outside this app's own database, and they only ever go
through providers.default_provider (currently MockResponseProvider) -- see
docs/ARCHITECTURE.md's response-provider section for why no real external
call is wired up yet.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app import db
from app.models import Incident, IncidentNote, Alert, Rule
from app.models.ioc import IOC, INDICATOR_TYPES, THREAT_LEVELS
from app.services.ioc_normalization import validate_indicator, sanitize_text
from app.playbooks.providers import default_provider


@dataclass
class ActionContext:
    actor_id: str | None       # PlaybookExecution.triggered_by, or the approver for a gated step
    incident: Incident | None
    alert: Alert | None


def _require_incident(ctx: ActionContext) -> Incident:
    if ctx.incident is None:
        raise ValueError("This action requires an incident in the trigger context.")
    return ctx.incident


def _require_alert(ctx: ActionContext) -> Alert:
    if ctx.alert is None:
        raise ValueError("This action requires an alert in the trigger context.")
    return ctx.alert


# ---- Safe, built-in actions (Part 21) --------------------------------------

def create_case_note(ctx: ActionContext, parameters: dict) -> dict:
    incident = _require_incident(ctx)
    content = sanitize_text(parameters.get("content")) or "Automated playbook note."
    note = IncidentNote(incident_id=incident.id, author_id=ctx.actor_id, content=content)
    db.session.add(note)
    db.session.flush()
    return {"note_id": note.id, "content": content}


def add_incident_tag(ctx: ActionContext, parameters: dict) -> dict:
    incident = _require_incident(ctx)
    tag = (parameters.get("tag") or "").strip().lower()
    if not tag:
        raise ValueError("add_incident_tag requires a non-empty 'tag' parameter.")
    tags = list(incident.tags or [])
    if tag not in tags:
        tags.append(tag)
        incident.tags = tags
        db.session.add(incident)
    return {"tags": tags}


def acknowledge_alert(ctx: ActionContext, parameters: dict) -> dict:
    alert = _require_alert(ctx)
    alert.status = "acknowledged"
    alert.acknowledged_at = datetime.utcnow()
    alert.acknowledged_by_id = ctx.actor_id
    db.session.add(alert)
    return {"alert_id": alert.id, "status": alert.status}


def resolve_alert(ctx: ActionContext, parameters: dict) -> dict:
    alert = _require_alert(ctx)
    alert.status = "resolved"
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by_id = ctx.actor_id
    db.session.add(alert)
    return {"alert_id": alert.id, "status": alert.status}


def notify_analyst(ctx: ActionContext, parameters: dict) -> dict:
    """No email/SMS infrastructure exists in this app -- the notification IS
    the playbook.action_completed WebSocket event this action's execution
    already broadcasts (see engine.py), which surfaces in the SOC dashboard's
    Playbook Activity panel. This function just records the message."""
    message = sanitize_text(parameters.get("message")) or "Analyst attention requested by playbook."
    return {"notified": True, "message": message}


def create_ioc(ctx: ActionContext, parameters: dict) -> dict:
    indicator_type = (parameters.get("indicator_type") or "").strip().lower()
    indicator = parameters.get("indicator")
    if not indicator or indicator_type not in INDICATOR_TYPES:
        raise ValueError(f"create_ioc requires 'indicator' and a valid 'indicator_type' ({', '.join(INDICATOR_TYPES)}).")

    ok, normalized_or_error = validate_indicator(indicator_type, indicator)
    if not ok:
        raise ValueError(normalized_or_error)

    existing = IOC.query.filter_by(indicator_type=indicator_type, normalized_indicator=normalized_or_error).first()
    if existing:
        return {"ioc_id": existing.id, "created": False, "reason": "already exists"}

    threat_level = (parameters.get("threat_level") or "unknown").strip().lower()
    if threat_level not in THREAT_LEVELS:
        threat_level = "unknown"

    ioc = IOC(
        indicator=str(indicator).strip(),
        indicator_type=indicator_type,
        normalized_indicator=normalized_or_error,
        threat_level=threat_level,
        confidence=int(parameters.get("confidence", 60)),
        source=sanitize_text(parameters.get("source")) or "playbook",
    )
    db.session.add(ioc)
    db.session.flush()
    return {"ioc_id": ioc.id, "created": True}


def disable_detection_rule(ctx: ActionContext, parameters: dict) -> dict:
    rule_id = parameters.get("rule_id")
    rule_name = parameters.get("rule_name")
    rule = Rule.query.get(rule_id) if rule_id else Rule.query.filter_by(name=rule_name).first()
    if not rule:
        raise ValueError("disable_detection_rule: no matching rule found.")
    rule.enabled = False
    db.session.add(rule)
    return {"rule_id": rule.id, "rule_name": rule.name, "enabled": False}


# ---- External actions -- always via a ResponseProvider (Part 22) ----------

def _provider_action(action_name: str, required: tuple, target_field: str):
    def _fn(ctx: ActionContext, parameters: dict) -> dict:
        missing = [p for p in required if not parameters.get(p)]
        if missing:
            raise ValueError(f"{action_name} is missing required parameter(s): {', '.join(missing)}")
        return default_provider.execute(action_name, parameters)
    _fn.__name__ = action_name
    return _fn


block_ip = _provider_action("block_ip", ("ip",), "ip")
disable_user = _provider_action("disable_user", ("user_id",), "user_id")
kill_process = _provider_action("kill_process", ("host", "process"), "host")
isolate_host = _provider_action("isolate_host", ("host",), "host")
