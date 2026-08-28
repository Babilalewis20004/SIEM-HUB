"""
Validation for normalised events before they're persisted. Never trust
fields extracted from a log line — this is the boundary where we decide
whether a normalised event is well-formed enough to store.
"""
import ipaddress
from datetime import datetime

from app.models.event import SEVERITY_LEVELS, OUTCOMES

MAX_RAW_MESSAGE_LENGTH = 8192  # guards against pathologically long lines bloating storage


class EventValidationError(ValueError):
    pass


def _valid_ip(value):
    if value in (None, ""):
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _valid_port(value):
    if value is None:
        return True
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535


def validate_event_data(data: dict) -> dict:
    """Validate + lightly coerce a normalised event dict. Raises EventValidationError."""
    if not data.get("event_type"):
        raise EventValidationError("event_type is required")
    if not data.get("category"):
        raise EventValidationError("category is required")
    if not data.get("raw_message"):
        raise EventValidationError("raw_message is required")

    ts = data.get("timestamp")
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except ValueError:
            raise EventValidationError(f"invalid timestamp: {ts!r}")
    if not isinstance(ts, datetime):
        raise EventValidationError("timestamp is required and must be a datetime")
    data["timestamp"] = ts

    severity = data.get("severity") or "info"
    if severity not in SEVERITY_LEVELS:
        raise EventValidationError(f"invalid severity: {severity!r}")
    data["severity"] = severity

    outcome = data.get("outcome")
    if outcome is not None and outcome not in OUTCOMES:
        raise EventValidationError(f"invalid outcome: {outcome!r}")

    if not _valid_ip(data.get("source_ip")):
        raise EventValidationError(f"invalid source_ip: {data.get('source_ip')!r}")
    if not _valid_ip(data.get("destination_ip")):
        raise EventValidationError(f"invalid destination_ip: {data.get('destination_ip')!r}")

    if not _valid_port(data.get("source_port")):
        raise EventValidationError(f"invalid source_port: {data.get('source_port')!r}")
    if not _valid_port(data.get("destination_port")):
        raise EventValidationError(f"invalid destination_port: {data.get('destination_port')!r}")

    if len(data["raw_message"]) > MAX_RAW_MESSAGE_LENGTH:
        data["raw_message"] = data["raw_message"][:MAX_RAW_MESSAGE_LENGTH]

    return data
