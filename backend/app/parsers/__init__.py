"""
Parser registry + dispatch. Adding a new log format means writing a
BaseParser subclass and registering it here (plus a normalizer function in
app/services/normalization.py) — nothing else in the pipeline needs to change.
"""
from app.parsers.base import BaseParser
from app.parsers.ssh import SSHParser
from app.parsers.nginx import NginxParser
from app.parsers.apache import ApacheParser
from app.parsers.firewall import FirewallParser
from app.parsers.windows_security import WindowsSecurityParser
from app.parsers.syslog import SyslogParser

# Order matters: earlier parsers get first refusal. SyslogParser is broadest
# (matches any "<PRI>ts host tag[pid]: msg"-shaped line) and goes last so it
# only ever catches what a more specific parser already declined -- e.g. an
# sshd disconnect message SSHParser doesn't claim.
PARSERS = [
    SSHParser(), NginxParser(), ApacheParser(), FirewallParser(),
    WindowsSecurityParser(), SyslogParser(),
]


def detect_and_parse(line: str, host: str = None, source_hint: str = None):
    """
    Try each registered parser against the line.

    source_hint (e.g. an upload's explicit source="apache") is tried first
    against the matching parser, if one is registered for it -- this is the
    only way to correctly tag a line whose format is genuinely ambiguous
    between two parsers (Apache and Nginx both use the same combined log
    format; content alone can't tell them apart). Without a hint, or if the
    hinted parser doesn't recognise the line, falls through to normal
    first-match auto-detection.

    Returns (source_type, parsed_dict) if a parser recognised and successfully
    parsed the line, or (None, None) if no parser recognised the line at all
    (caller should fall back to a generic/unparsed event). Raises ValueError
    if a parser recognised the line's format but couldn't parse it (malformed).
    """
    if source_hint:
        for parser in PARSERS:
            if parser.source_type == source_hint and parser.matches(line):
                return parser.source_type, parser.parse(line, host=host)

    for parser in PARSERS:
        if parser.matches(line):
            return parser.source_type, parser.parse(line, host=host)
    return None, None


__all__ = [
    "BaseParser", "SSHParser", "NginxParser", "ApacheParser", "FirewallParser",
    "WindowsSecurityParser", "SyslogParser", "PARSERS", "detect_and_parse",
]
