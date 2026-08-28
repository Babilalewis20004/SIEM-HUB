"""
Normalisation layer: converts parser-specific dicts into the common Event
schema (see app/models/event.py). Detection engines and the API only ever
deal with normalised Event data — they don't need to know which parser (or
log format) originally produced it.

    raw line -> parser.parse() -> parser-specific dict -> normalize_*() -> Event fields
"""
from datetime import datetime

from app.parsers import detect_and_parse

NORMALIZERS = {}


def normalizer_for(source_type):
    def register(fn):
        NORMALIZERS[source_type] = fn
        return fn
    return register


@normalizer_for("ssh")
def normalize_ssh(parsed: dict) -> dict:
    outcome = "success" if parsed["result"] == "accepted" else "failure"
    return {
        "event_type": "authentication_success" if outcome == "success" else "authentication_failure",
        "category": "authentication",
        "source_type": "ssh",
        "source_ip": parsed.get("source_ip"),
        "destination_ip": None,
        "source_port": parsed.get("source_port"),
        "destination_port": 22,
        "username": parsed.get("username"),
        "hostname": parsed.get("hostname"),
        "action": "login",
        "outcome": outcome,
        "severity": "info" if outcome == "success" else "medium",
        "timestamp": parsed.get("timestamp"),
        "raw_message": parsed["raw_message"],
        "parsed_fields": {"pid": parsed.get("pid"), "protocol": parsed.get("protocol")},
    }


@normalizer_for("nginx")
def normalize_nginx(parsed: dict) -> dict:
    status = parsed.get("status_code")
    is_error = status is not None and status >= 400
    if status is not None and status >= 500:
        severity = "high"
    elif is_error:
        severity = "low"
    else:
        severity = "info"

    return {
        "event_type": "http_error" if is_error else "http_request",
        "category": "web",
        "source_type": "nginx",
        "source_ip": parsed.get("source_ip"),
        "destination_ip": None,
        "source_port": None,
        "destination_port": 80,
        "username": None,
        "hostname": parsed.get("hostname"),
        "action": "request",
        "outcome": "failure" if is_error else "success",
        "severity": severity,
        "timestamp": parsed.get("timestamp"),
        "raw_message": parsed["raw_message"],
        "parsed_fields": {
            "method": parsed.get("method"),
            "path": parsed.get("path"),
            "status_code": status,
            "user_agent": parsed.get("user_agent"),
            "referer": parsed.get("referer"),
            "response_bytes": parsed.get("response_bytes"),
            "http_version": parsed.get("http_version"),
        },
    }


def _generic_event(line: str, source_hint: str, host: str) -> dict:
    """Fallback for lines no registered parser recognised — nothing gets dropped."""
    return {
        "event_type": "unparsed",
        "category": "application",
        "source_type": source_hint or "generic",
        "source_ip": None,
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "username": None,
        "hostname": host,
        "action": None,
        "outcome": "unknown",
        "severity": "info",
        "timestamp": datetime.utcnow(),
        "raw_message": line,
        "parsed_fields": {},
    }


def normalize_event(parsed_log) -> dict:
    """Normalise an already-parsed (source_type, parser_dict) pair into Event fields."""
    source_type, parsed = parsed_log
    normalizer = NORMALIZERS[source_type]
    return normalizer(parsed)


def normalize_line(raw_line: str, source_hint: str = "generic", host: str = None):
    """
    raw log line -> normalised Event field dict, or None for a blank line.
    Raises ValueError if a parser recognised the line's format but the line
    itself was malformed (caller should count that as a parse failure).
    """
    line = raw_line.strip() if raw_line else ""
    if not line:
        return None

    source_type, parsed = detect_and_parse(line, host=host)
    if source_type is None:
        return _generic_event(line, source_hint, host)

    return normalize_event((source_type, parsed))
