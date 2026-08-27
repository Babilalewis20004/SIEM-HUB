"""
Parsers turn raw log lines into normalized dicts:
{
    timestamp, source, host, source_ip, event_type, severity, raw_message, parsed_fields
}
Add more parsers as needed (Windows Event XML, JSON logs, etc.)
"""
import re
from datetime import datetime

# Example: 2026-08-20T03:14:11 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2
SSH_FAILED_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+sshd.*?"
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)

# Example: 203.0.113.5 - - [20/Aug/2026:03:14:11 +0000] "GET /admin HTTP/1.1" 404 512
NGINX_RE = re.compile(
    r'(?P<ip>[\d.]+) - - \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" '
    r"(?P<status>\d{3}) (?P<size>\d+)"
)


def parse_line(raw_line: str, source_hint: str = "generic", host: str = None):
    line = raw_line.strip()
    if not line:
        return None

    m = SSH_FAILED_RE.search(line)
    if m:
        return {
            "timestamp": _parse_ts(m.group("ts")),
            "source": "auth",
            "host": host,
            "source_ip": m.group("ip"),
            "event_type": "login_failed",
            "severity": "warning",
            "raw_message": line,
            "parsed_fields": {"user": m.group("user")},
        }

    m = NGINX_RE.search(line)
    if m:
        status = int(m.group("status"))
        severity = "critical" if status >= 500 else ("warning" if status >= 400 else "info")
        return {
            "timestamp": _parse_nginx_ts(m.group("ts")),
            "source": "nginx",
            "host": host,
            "source_ip": m.group("ip"),
            "event_type": "http_request",
            "severity": severity,
            "raw_message": line,
            "parsed_fields": {
                "method": m.group("method"),
                "path": m.group("path"),
                "status": status,
                "size": int(m.group("size")),
            },
        }

    # Fallback: store as generic/unparsed log so nothing is dropped
    return {
        "timestamp": datetime.utcnow(),
        "source": source_hint,
        "host": host,
        "source_ip": None,
        "event_type": "unparsed",
        "severity": "info",
        "raw_message": line,
        "parsed_fields": {},
    }


def _parse_ts(ts_str: str) -> datetime:
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return datetime.utcnow()


def _parse_nginx_ts(ts_str: str) -> datetime:
    # 20/Aug/2026:03:14:11 +0000
    try:
        return datetime.strptime(ts_str.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return datetime.utcnow()
