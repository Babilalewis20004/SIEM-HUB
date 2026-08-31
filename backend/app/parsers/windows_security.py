import json
import re
from datetime import datetime, timezone

from app.parsers.base import BaseParser

# Windows Security auth events, one JSON object per line -- the shape most
# forwarders (Winlogbeat, WEF collectors writing NDJSON) actually emit, since
# a raw multi-line EVTX/XML record doesn't fit this pipeline's one-line-per-
# event model. Only the two logon events needed for a brute-force/successful-
# login signal are handled today (4625 failed, 4624 succeeded); add another
# EventID the same way SSH only handles Failed/Accepted password -- extend
# EVENT_ID_RE and the branch in parse() together.
#
#   {"EventID": 4625, "TimeCreated": "2026-08-20T03:14:11Z", "Computer":
#    "WIN-DC01", "TargetUserName": "administrator", "IpAddress":
#    "203.0.113.5", "LogonType": 3, "FailureReason": "Unknown user name or
#    bad password"}
EVENT_ID_RE = re.compile(r'"EventID"\s*:\s*"?(4624|4625)"?')


class WindowsSecurityParser(BaseParser):
    source_type = "windows_security"

    def matches(self, line: str) -> bool:
        return bool(EVENT_ID_RE.search(line))

    def parse(self, line: str, host: str = None) -> dict:
        try:
            data = json.loads(line.strip())
        except (json.JSONDecodeError, ValueError):
            raise ValueError("invalid JSON for Windows Security event line")

        event_id = data.get("EventID")
        if str(event_id) not in ("4624", "4625"):
            raise ValueError(f"unsupported Windows EventID: {event_id!r}")

        ip = data.get("IpAddress")
        if ip in ("-", "", None):
            ip = None

        return {
            "event_id": int(event_id),
            "timestamp": _parse_timestamp(data.get("TimeCreated")),
            "hostname": data.get("Computer") or host,
            "username": data.get("TargetUserName"),
            "source_ip": ip,
            "logon_type": data.get("LogonType"),
            "failure_reason": data.get("FailureReason"),
            "raw_message": line,
        }


def _parse_timestamp(ts_str) -> datetime:
    # The rest of this app stores naive UTC datetimes (see Event.timestamp,
    # job_status.py's comment on the same tradeoff) -- convert TimeCreated's
    # tz-aware ISO 8601 down to naive UTC instead of leaving it tz-aware,
    # which would otherwise mix naive/aware values in the same DB column.
    if not ts_str:
        return datetime.utcnow()
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        return datetime.utcnow()
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt
