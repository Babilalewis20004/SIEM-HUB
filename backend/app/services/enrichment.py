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

from app.services import correlation, mitre_enrichment, ioc_matching

logger = logging.getLogger(__name__)


def enrich_and_correlate(alert):
    try:
        mitre_enrichment.enrich_alert(alert)
    except Exception:
        logger.exception("MITRE enrichment failed for alert %s; continuing without it.", alert.id)

    try:
        ioc_matching.enrich_alert_iocs(alert)
    except Exception:
        logger.exception("IOC enrichment failed for alert %s; continuing without it.", alert.id)

    return correlation.correlate_alert(alert)
