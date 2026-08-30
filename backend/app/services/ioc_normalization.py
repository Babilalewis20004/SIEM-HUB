"""
IOC validation and normalisation. This is the single place that decides
whether a submitted indicator is well-formed and what its canonical
`normalized_indicator` value is -- app/models/ioc.py's uniqueness constraint
is (indicator_type, normalized_indicator), so every writer (manual create,
CSV/JSON import) must go through validate_indicator() here rather than
storing raw user input directly.

Never fetches, resolves, or executes an indicator -- string parsing only.

Matching rule (documented because it's not obvious): domain matching is
EXACT after normalisation. "evil.example.com" does NOT match an IOC stored
for "example.com" -- no implicit subdomain/parent-domain matching. If an
analyst wants both covered, both must be added as separate IOCs.
"""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from app.models.ioc import INDICATOR_TYPES

_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_HEX_RE = re.compile(r"^[0-9a-f]+$")


def normalize_ip(value: str):
    value = (value or "").strip()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(ip)  # canonical form (e.g. compresses IPv6)


def normalize_domain(value: str):
    value = (value or "").strip().lower()
    if not value:
        return None
    value = value.rstrip(".")  # trailing-dot FQDNs normalise the same as without
    # Minimal sanity check: at least one label, only hostname-legal characters.
    if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", value):
        return None
    return value


def normalize_url(value: str):
    value = (value or "").strip()
    if not value:
        return None
    try:
        parts = urlsplit(value if "://" in value else f"http://{value}")
    except ValueError:
        return None
    if not parts.hostname:
        return None
    scheme = (parts.scheme or "http").lower()
    netloc = parts.hostname.lower()
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    path = parts.path or ""
    normalized = urlunsplit((scheme, netloc, path, parts.query, ""))
    return normalized.rstrip("/") or normalized


def normalize_hash(value: str, indicator_type: str):
    value = (value or "").strip().lower()
    expected_len = _HASH_LENGTHS.get(indicator_type)
    if expected_len is None or len(value) != expected_len or not _HEX_RE.match(value):
        return None
    return value


_FORMULA_PREFIXES = ("=", "+", "-", "@")


def sanitize_text(value):
    """Neutralise CSV-formula-injection payloads (e.g. "=cmd|...") in
    free-text fields (description, source) that might later be exported to
    CSV and opened in a spreadsheet tool. Never affects normal text."""
    if not value:
        return value
    value = str(value)
    if value and value[0] in _FORMULA_PREFIXES:
        return "'" + value
    return value


def validate_indicator(indicator_type: str, value: str):
    """Returns (ok: bool, normalized_or_error: str)."""
    if indicator_type not in INDICATOR_TYPES:
        return False, f"Unsupported indicator_type: {indicator_type!r}"

    if indicator_type == "ip":
        normalized = normalize_ip(value)
    elif indicator_type == "domain":
        normalized = normalize_domain(value)
    elif indicator_type == "url":
        normalized = normalize_url(value)
    else:  # md5 | sha1 | sha256
        normalized = normalize_hash(value, indicator_type)

    if normalized is None:
        return False, f"Invalid {indicator_type} value: {value!r}"
    return True, normalized
