"""
IOC matching engine: checks an Event's indicator-bearing fields against the
active IOC table and records the evidence trail (IOCMatch) an analyst can
inspect later. This is an enrichment/correlation signal, not a detector --
it never creates Alerts on its own and never blocks ingestion.

Efficiency: matching is done with one bulk `IN (...)` query per indicator
type, not one query per indicator (see match_indicators / match_events),
per the batch-ingestion requirement in docs/ARCHITECTURE.md.
"""
import logging
from collections import defaultdict
from datetime import datetime

from app import db
from app.models.ioc import IOC, IOCMatch
from app.events import bus
from app.services.ioc_normalization import normalize_ip, normalize_domain, normalize_url

logger = logging.getLogger(__name__)

# (event field name, indicator_type, normalizer) -- extend here as parsers
# gain more indicator-bearing fields. Fields that don't exist on a given
# Event (or aren't populated by today's parsers) simply contribute nothing;
# this list is intentionally forward-compatible.
_DIRECT_FIELDS = (
    ("source_ip", "ip", normalize_ip),
    ("destination_ip", "ip", normalize_ip),
)
_PARSED_FIELDS = (
    ("domain", "domain", normalize_domain),
    ("url", "url", normalize_url),
)
_HASH_PARSED_FIELDS = ("md5", "sha1", "sha256")


def extract_indicators(event):
    """Return {(indicator_type, normalized_value): [(field_name, raw_value), ...]}."""
    found = defaultdict(list)

    for field, itype, normalizer in _DIRECT_FIELDS:
        raw = getattr(event, field, None)
        if not raw:
            continue
        normalized = normalizer(raw)
        if normalized:
            found[(itype, normalized)].append((field, raw))

    parsed = event.parsed_fields or {}
    for field, itype, normalizer in _PARSED_FIELDS:
        raw = parsed.get(field)
        if not raw:
            continue
        normalized = normalizer(raw)
        if normalized:
            found[(itype, normalized)].append((field, raw))

    for itype in _HASH_PARSED_FIELDS:
        raw = parsed.get(itype)
        if not raw:
            continue
        normalized = raw.strip().lower()
        if len(normalized) == len(raw.strip()):
            found[(itype, normalized)].append((itype, raw))

    return found


def match_indicators(indicator_keys):
    """indicator_keys: iterable of (indicator_type, normalized_value).
    Returns {(indicator_type, normalized_value): IOC} for active matches,
    using one bulk query per indicator_type rather than N queries."""
    if not indicator_keys:
        return {}

    now = datetime.utcnow()
    by_type = defaultdict(set)
    for itype, value in indicator_keys:
        by_type[itype].add(value)

    results = {}
    for itype, values in by_type.items():
        rows = IOC.query.filter(
            IOC.indicator_type == itype,
            IOC.normalized_indicator.in_(values),
            IOC.enabled.is_(True),
        ).all()
        for ioc in rows:
            if not ioc.is_active(now):
                continue
            results[(ioc.indicator_type, ioc.normalized_indicator)] = ioc
    return results


def match_events(events):
    """Batch entry point: dedupe indicators across many events, then do one
    bulk IOC lookup per type instead of N per-event lookups. Returns
    {event_id: {(indicator_type, normalized_value): IOC}}."""
    per_event = {}
    all_keys = set()
    for event in events:
        indicators = extract_indicators(event)
        per_event[event.id] = indicators
        all_keys.update(indicators.keys())

    matched = match_indicators(all_keys)

    return {
        event_id: {key: matched[key] for key in indicators if key in matched}
        for event_id, indicators in per_event.items()
    }


def enrich_alert_iocs(alert):
    """Match alert.event's indicators against the IOC table and persist
    IOCMatch rows tagged with both event_id and alert_id. Returns the list
    of IOCMatch rows created (possibly empty)."""
    event = alert.event
    if event is None:
        return []

    indicators = extract_indicators(event)
    matched = match_indicators(indicators.keys())
    if not matched:
        return []

    created = []
    for key, occurrences in indicators.items():
        ioc = matched.get(key)
        if ioc is None:
            continue
        field, raw_value = occurrences[0]
        match = IOCMatch(
            ioc_id=ioc.id,
            event_id=event.id,
            alert_id=alert.id,
            matched_field=field,
            matched_value=str(raw_value),
            confidence=ioc.confidence,
        )
        db.session.add(match)
        created.append(match)

        ioc.last_seen_at = datetime.utcnow()
        db.session.add(ioc)

        if ioc.threat_level in ("high", "critical"):
            bus.publish("ioc.match", {
                "alert_id": alert.id, "indicator": ioc.indicator, "indicator_type": ioc.indicator_type,
                "threat_level": ioc.threat_level, "confidence": ioc.confidence,
            })

    if created:
        db.session.flush()
    return created
