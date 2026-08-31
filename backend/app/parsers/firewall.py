import re
from datetime import datetime

from app.parsers.base import BaseParser

# iptables/UFW LOG target lines, forwarded through syslog by the kernel, e.g.:
#   Aug 28 10:31:15 gateway kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT=
#   MAC=... SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=54321 DPT=22 ...
# The syslog envelope (timestamp/host/"kernel:") is optional in matches() --
# some forwarders strip it and hand us just the kernel message -- but SRC=/
# DST=/PROTO= (iptables' own key=value fields) must all be present.
PREFIX_RE = re.compile(
    r'^(?P<ts>(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})|(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+'
    r'(?P<host>\S+)\s+kernel:\s*(?:\[[\d.]+\]\s*)?(?P<rest>.*)$'
)
KV_RE = re.compile(r'\b([A-Z]+)=(\S*)')

_BLOCK_RE = re.compile(r'UFW BLOCK|UFW DENY|\bDROP\b|\bREJECT\b|\bDENY\b', re.IGNORECASE)
_ALLOW_RE = re.compile(r'UFW ALLOW|\bACCEPT\b', re.IGNORECASE)


class FirewallParser(BaseParser):
    source_type = "firewall"

    def matches(self, line: str) -> bool:
        return "SRC=" in line and "DST=" in line and "PROTO=" in line

    def parse(self, line: str, host: str = None) -> dict:
        prefix = PREFIX_RE.match(line)
        ts_str = prefix.group("ts") if prefix else None
        syslog_host = prefix.group("host") if prefix else None
        rest = prefix.group("rest") if prefix else line

        kv = dict(KV_RE.findall(rest))
        src_ip = kv.get("SRC")
        dst_ip = kv.get("DST")
        if not src_ip or not dst_ip:
            raise ValueError("unrecognised firewall log format (missing SRC/DST)")

        if _BLOCK_RE.search(line):
            outcome = "blocked"
        elif _ALLOW_RE.search(line):
            outcome = "success"
        else:
            outcome = "unknown"

        spt, dpt = kv.get("SPT"), kv.get("DPT")
        return {
            "timestamp": _parse_timestamp(ts_str) if ts_str else datetime.utcnow(),
            "hostname": host or syslog_host,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": int(spt) if spt and spt.isdigit() else None,
            "destination_port": int(dpt) if dpt and dpt.isdigit() else None,
            "protocol": kv.get("PROTO"),
            "interface_in": kv.get("IN") or None,
            "interface_out": kv.get("OUT") or None,
            "outcome": outcome,
            "raw_message": line,
        }


def _parse_timestamp(ts_str: str) -> datetime:
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        pass
    try:
        parsed = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        return parsed.replace(year=datetime.utcnow().year)
    except ValueError:
        return datetime.utcnow()
