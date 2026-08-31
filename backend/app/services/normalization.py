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


@normalizer_for("apache")
def normalize_apache(parsed: dict) -> dict:
    # Same combined-log-format shape as Nginx; only source_type differs.
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
        "source_type": "apache",
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


@normalizer_for("firewall")
def normalize_firewall(parsed: dict) -> dict:
    outcome = parsed.get("outcome", "unknown")
    if outcome == "blocked":
        event_type, severity = "connection_blocked", "medium"
    elif outcome == "success":
        event_type, severity = "connection_allowed", "info"
    else:
        event_type, severity = "connection_logged", "low"

    return {
        "event_type": event_type,
        "category": "network",
        "source_type": "firewall",
        "source_ip": parsed.get("source_ip"),
        "destination_ip": parsed.get("destination_ip"),
        "source_port": parsed.get("source_port"),
        "destination_port": parsed.get("destination_port"),
        "username": None,
        "hostname": parsed.get("hostname"),
        "action": "connection",
        "outcome": outcome,
        "severity": severity,
        "timestamp": parsed.get("timestamp"),
        "raw_message": parsed["raw_message"],
        "parsed_fields": {
            "protocol": parsed.get("protocol"),
            "interface_in": parsed.get("interface_in"),
            "interface_out": parsed.get("interface_out"),
        },
    }


@normalizer_for("windows_security")
def normalize_windows_security(parsed: dict) -> dict:
    # Same event_type/category as SSH's authentication_failure/_success so
    # the existing brute-force threshold rule and MITRE T1110 mapping fire
    # identically regardless of whether the source_ip is hitting SSH or RDP.
    is_failure = parsed["event_id"] == 4625
    return {
        "event_type": "authentication_failure" if is_failure else "authentication_success",
        "category": "authentication",
        "source_type": "windows_security",
        "source_ip": parsed.get("source_ip"),
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "username": parsed.get("username"),
        "hostname": parsed.get("hostname"),
        "action": "login",
        "outcome": "failure" if is_failure else "success",
        "severity": "medium" if is_failure else "info",
        "timestamp": parsed.get("timestamp"),
        "raw_message": parsed["raw_message"],
        "parsed_fields": {
            "event_id": parsed.get("event_id"),
            "logon_type": parsed.get("logon_type"),
            "failure_reason": parsed.get("failure_reason"),
        },
    }


@normalizer_for("syslog")
def normalize_syslog(parsed: dict) -> dict:
    return {
        "event_type": "syslog_message",
        "category": "application",
        "source_type": "syslog",
        "source_ip": None,
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "username": None,
        "hostname": parsed.get("hostname"),
        "action": None,
        "outcome": "unknown",
        "severity": parsed.get("severity", "info"),
        "timestamp": parsed.get("timestamp"),
        "raw_message": parsed["raw_message"],
        "parsed_fields": {
            "tag": parsed.get("tag"),
            "pid": parsed.get("pid"),
            "facility": parsed.get("facility"),
            "severity_name": parsed.get("severity_name"),
            "message": parsed.get("message"),
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

    source_type, parsed = detect_and_parse(line, host=host, source_hint=source_hint)
    if source_type is None:
        return _generic_event(line, source_hint, host)

    return normalize_event((source_type, parsed))
