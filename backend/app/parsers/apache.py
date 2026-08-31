import re
from datetime import datetime

from app.parsers.base import BaseParser

# Apache's "combined" log format is byte-for-byte the same shape as Nginx's
# combined format (both trace back to the same NCSA convention), so a line's
# *content* alone can never prove which server produced it -- there is no
# distinguishing field. Auto-detection (no explicit source) falls through to
# NginxParser, which is registered first in PARSERS. Callers that know the
# source (e.g. an upload with source="apache") get correct tagging via the
# source_hint priority pass in app/parsers/__init__.py::detect_and_parse().
LINE_RE = re.compile(
    r'^(?P<ip>[0-9a-fA-F:.]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/[\d.]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

LOOKS_LIKE_RE = re.compile(r'\[[^\]]+\]\s+"[A-Z]+\s')


class ApacheParser(BaseParser):
    source_type = "apache"

    def matches(self, line: str) -> bool:
        return bool(LOOKS_LIKE_RE.search(line))

    def parse(self, line: str, host: str = None) -> dict:
        m = LINE_RE.search(line)
        if not m:
            raise ValueError("unrecognised apache access log format")

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
