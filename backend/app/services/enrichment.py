"""
Single entry point tying detection to correlation:

    Alert created -> MITRE enrichment -> IOC matching -> Correlation

Detection engines (app/services/detection.py, app/services/ml_detection.py)
call enrich_and_correlate(alert) instead of calling
app/services/correlation.correlate_alert() directly. MITRE and IOC
enrichment are each independently best-effort: a bug or failure in either
must never lose the underlying detection alert, so both are wrapped here and
only logged on failure -- correlation always runs.
"""
import logging

from app.events import bus
from app.services import correlation, mitre_enrichment, ioc_matching
from app.services.metrics import alerts_created_total

logger = logging.getLogger(__name__)


def enrich_and_correlate(alert):
    alerts_created_total.labels(alert.detection_source or "unknown", alert.severity).inc()

    try:
        mitre_enrichment.enrich_alert(alert)
    except Exception:
        logger.exception("MITRE enrichment failed for alert %s; continuing without it.", alert.id)

    try:
        ioc_matching.enrich_alert_iocs(alert)
    except Exception:
        logger.exception("IOC enrichment failed for alert %s; continuing without it.", alert.id)

    incident = correlation.correlate_alert(alert)

    # Published last, once mitre/ioc/incident are all known, so listeners
    # (the WebSocket broadcaster, alert-triggered playbooks) see the
    # complete picture in one event rather than a partial alert followed by
    # separate enrichment events. Small hand-built payload only -- never the
    # raw Alert record (see Part W: WebSockets are for "something changed",
    # not "here is the whole row").
    bus.publish("alert.created", {
        "id": alert.id,
        "title": alert.title or alert.rule_name,
        "severity": alert.severity,
        "detection_source": alert.detection_source,
        "mitre": [t.technique_id for t in alert.mitre_techniques],
        "ioc_matches": len(alert.ioc_matches or []),
        "incident_id": incident.id if incident else None,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
    })

    return incident
