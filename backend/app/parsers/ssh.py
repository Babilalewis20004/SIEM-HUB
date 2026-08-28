import re
from datetime import datetime

from app.parsers.base import BaseParser

# Matches both syslog-style ("Aug 28 10:31:15 server sshd[1234]: ...") and
# ISO ("2026-08-20T03:14:11 server sshd[1234]: ...") timestamps, IPv4 and
# IPv6 source addresses, and both failed/accepted auth attempts.
LINE_RE = re.compile(
    r"^(?P<ts>(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})|(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+sshd(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<result>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>[0-9a-fA-F:.]+)\s+port\s+(?P<port>\d+)(?:\s+(?P<proto>\S+))?"
)


class SSHParser(BaseParser):
    source_type = "ssh"

    def matches(self, line: str) -> bool:
        return "sshd" in line and ("Failed password" in line or "Accepted password" in line)

    def parse(self, line: str, host: str = None) -> dict:
        m = LINE_RE.search(line)
        if not m:
            raise ValueError("unrecognised SSH auth log format")

        return {
            "timestamp": _parse_timestamp(m.group("ts")),
            "hostname": host or m.group("host"),
            "pid": m.group("pid"),
            "result": m.group("result").lower(),  # "failed" | "accepted"
            "username": m.group("user"),
            "source_ip": m.group("ip"),
            "source_port": int(m.group("port")),
            "protocol": m.group("proto"),
            "raw_message": line,
        }


def _parse_timestamp(ts_str: str) -> datetime:
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        pass
    try:
        # Syslog timestamps have no year; assume current year.
        parsed = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        return parsed.replace(year=datetime.utcnow().year)
    except ValueError:
        return datetime.utcnow()
