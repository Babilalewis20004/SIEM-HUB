"""
Incident business logic that doesn't belong inline in a route: the status
state machine and severity/priority helpers shared with the correlation
engine. CRUD itself stays in app/routes/incidents.py; this module is only
for rules that need to be consistent no matter which route triggers them.
"""
from datetime import datetime

from app.models.incident import STATUSES

# Allowed forward/lateral transitions. "closed" is intentionally absent as a
# source here — closing is a one-way door unless the caller explicitly asks
# to reopen (see transition_status below), so a silent closed -> X never
# happens by accident.
_ALLOWED_TRANSITIONS = {
    "open": {"investigating", "closed"},
    "investigating": {"contained", "resolved", "open"},
    "contained": {"resolved", "investigating"},
    "resolved": {"closed", "investigating"},
}


class InvalidTransition(Exception):
    pass


def transition_status(incident, new_status: str, reopen: bool = False, actor=None):
    """Apply a validated status transition, stamping resolved_at/resolved_by
    when the incident moves into "resolved". Raises InvalidTransition if the
    move isn't allowed."""
    if new_status not in STATUSES:
        raise InvalidTransition(f"Unknown status: {new_status!r}")

    current = incident.status
    if current == new_status:
        return incident

    if current == "closed":
        if not reopen:
            raise InvalidTransition(
                "Incident is closed; pass reopen=true to explicitly reopen it."
            )
        if new_status != "investigating":
            raise InvalidTransition("Reopening a closed incident always moves it to 'investigating'.")
    elif new_status not in _ALLOWED_TRANSITIONS.get(current, set()):
        raise InvalidTransition(f"Cannot move an incident from '{current}' to '{new_status}'.")

    incident.status = new_status
    if new_status == "resolved":
        incident.resolved_at = datetime.utcnow()
        incident.resolved_by = getattr(actor, "id", None)
    elif new_status in ("investigating", "open", "contained"):
        incident.resolved_at = None
        incident.resolved_by = None

    return incident


ALERT_SEVERITY_TO_INCIDENT_SEVERITY = {"critical": "critical", "warning": "medium", "info": "info"}
INCIDENT_SEVERITY_TO_PRIORITY = {
    "critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "low",
}


def severity_for_alert(alert_severity: str) -> str:
    return ALERT_SEVERITY_TO_INCIDENT_SEVERITY.get(alert_severity, "medium")


def priority_for_severity(incident_severity: str) -> str:
    return INCIDENT_SEVERITY_TO_PRIORITY.get(incident_severity, "medium")
