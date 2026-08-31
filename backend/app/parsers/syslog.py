import re
from datetime import datetime

from app.parsers.base import BaseParser

# Catch-all for RFC 3164 ("<PRI>Mon DD HH:MM:SS host tag[pid]: msg") and
# RFC 5424 ("<PRI>1 2003-10-11T22:14:15.003Z host app-name procid msgid - msg")
# syslog envelopes that no more specific parser (SSH, firewall, ...) claimed
# -- e.g. an sshd disconnect message, a cron/su/sudo line, anything else a
# syslog daemon forwarded. Registered last in PARSERS: it only ever sees
# lines every other parser already declined, so it can afford a broad
# heuristic without stealing lines a dedicated parser would have handled
# better. This still beats falling all the way through to `unparsed` --
# hostname/process/severity survive even when the payload itself is unknown.
PRI_RE = re.compile(r'^<(?P<pri>\d{1,3})>')

ENVELOPE_RE = re.compile(
    r'^(?:<\d{1,3}>)?'
    r'(?:(?P<version>\d)\s+)?'
    r'(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})?|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<tag>[\w.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<msg>.*)$'
)

_SEVERITY_NAMES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
# syslog severity (0-7, most to least severe) -> this app's 5-level scale
_SEVERITY_MAP = {
    0: "critical", 1: "critical", 2: "critical",
    3: "high",
    4: "medium",
    5: "low",
    6: "info", 7: "info",
}


class SyslogParser(BaseParser):
    source_type = "syslog"

    def matches(self, line: str) -> bool:
        return bool(ENVELOPE_RE.match(line))

    def parse(self, line: str, host: str = None) -> dict:
        m = ENVELOPE_RE.match(line)
        if not m:
            raise ValueError("unrecognised syslog envelope format")

        pri_match = PRI_RE.match(line)
        facility = severity_num = severity = None
        if pri_match:
            pri = int(pri_match.group("pri"))
            facility, severity_num = divmod(pri, 8)
            severity = _SEVERITY_MAP.get(severity_num, "info")

        return {
            "timestamp": _parse_timestamp(m.group("ts")),
            "hostname": host or m.group("host"),
            "tag": m.group("tag"),
            "pid": m.group("pid"),
            "facility": facility,
            "severity_num": severity_num,
            "severity_name": _SEVERITY_NAMES[severity_num] if severity_num is not None else None,
            "severity": severity or "info",
            "message": m.group("msg"),
            "raw_message": line,
        }


def _parse_timestamp(ts_str: str) -> datetime:
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        pass
    try:
        parsed = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        return parsed.replace(year=datetime.utcnow().year)
    except ValueError:
        return datetime.utcnow()
