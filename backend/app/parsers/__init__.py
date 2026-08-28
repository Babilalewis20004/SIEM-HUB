"""
Parser registry + dispatch. Adding a new log format means writing a
BaseParser subclass and registering it here (plus a normalizer function in
app/services/normalization.py) — nothing else in the pipeline needs to change.
"""
from app.parsers.base import BaseParser
from app.parsers.ssh import SSHParser
from app.parsers.nginx import NginxParser

PARSERS = [SSHParser(), NginxParser()]


def detect_and_parse(line: str, host: str = None):
    """
    Try each registered parser against the line.

    Returns (source_type, parsed_dict) if a parser recognised and successfully
    parsed the line, or (None, None) if no parser recognised the line at all
    (caller should fall back to a generic/unparsed event). Raises ValueError
    if a parser recognised the line's format but couldn't parse it (malformed).
    """
    for parser in PARSERS:
        if parser.matches(line):
            return parser.source_type, parser.parse(line, host=host)
    return None, None


__all__ = ["BaseParser", "SSHParser", "NginxParser", "PARSERS", "detect_and_parse"]
