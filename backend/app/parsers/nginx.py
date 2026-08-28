import re
from datetime import datetime

from app.parsers.base import BaseParser

# Combined/common log format:
# 203.0.113.5 - - [20/Aug/2026:03:14:11 +0000] "GET /admin HTTP/1.1" 404 512 "-" "Mozilla/5.0"
# The referer/user-agent suffix is optional (plain "common" format omits it).
LINE_RE = re.compile(
    r'^(?P<ip>[0-9a-fA-F:.]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/[\d.]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# Heuristic: looks like "... [timestamp] "REQUEST" so it's worth attempting
# a strict parse (and treating a strict-parse failure as malformed, not "not nginx").
LOOKS_LIKE_RE = re.compile(r'\[[^\]]+\]\s+"[A-Z]+\s')


class NginxParser(BaseParser):
    source_type = "nginx"

    def matches(self, line: str) -> bool:
        return bool(LOOKS_LIKE_RE.search(line))

    def parse(self, line: str, host: str = None) -> dict:
        m = LINE_RE.search(line)
        if not m:
            raise ValueError("unrecognised nginx access log format")

        size = m.group("size")
        return {
            "timestamp": _parse_timestamp(m.group("ts")),
            "hostname": host,
            "source_ip": m.group("ip"),
            "method": m.group("method"),
            "path": m.group("path"),
            "http_version": m.group("protocol"),
            "status_code": int(m.group("status")),
            "response_bytes": int(size) if size and size != "-" else 0,
            "referer": m.group("referer"),
            "user_agent": m.group("user_agent"),
            "raw_message": line,
        }


def _parse_timestamp(ts_str: str) -> datetime:
    # 20/Aug/2026:03:14:11 +0000
    try:
        return datetime.strptime(ts_str.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return datetime.utcnow()
