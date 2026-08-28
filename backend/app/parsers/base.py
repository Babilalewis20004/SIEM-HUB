"""
Parser interface. A parser turns one raw log line into a parser-specific
dict (its own vocabulary — e.g. SSH's "user"/"result", Nginx's "status").
It knows nothing about the normalised Event schema; that translation is
app/services/normalization.py's job. This split is what lets a new log
format (Windows Event, Apache, syslog, firewall, cloud) be added by writing
one parser + one normalizer function, without touching detection code.
"""
from abc import ABC, abstractmethod


class BaseParser(ABC):
    source_type: str = "generic"

    @abstractmethod
    def matches(self, line: str) -> bool:
        """Cheap heuristic: does this line look like this parser's format?"""
        raise NotImplementedError

    @abstractmethod
    def parse(self, line: str, host: str = None) -> dict:
        """
        Extract fields from a line this parser claimed via matches(). Raise
        ValueError if the line turns out to be malformed so the caller can
        count it as a parse failure instead of silently dropping/misparsing it.
        """
        raise NotImplementedError
