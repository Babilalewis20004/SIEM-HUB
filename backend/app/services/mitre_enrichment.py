"""
MITRE ATT&CK enrichment: given a freshly created Alert, attach the ATT&CK
techniques its detection rule maps to.

Detection (app/services/detection.py, app/services/ml_detection.py) answers
"this behaviour triggered a detection." This module answers a narrower
question: "does the rule that fired have a documented ATT&CK mapping?" It
never invents a mapping -- alerts from rule-less detections (ML, statistical
heuristics) simply get no techniques.

Called from app/services/enrichment.py, which guarantees a failure here can
never prevent the underlying Alert from being created/committed.
"""
import logging

from app import db

logger = logging.getLogger(__name__)


def enrich_alert(alert):
    """Copy `alert.rule.mitre_techniques` onto `alert.mitre_techniques`, as
    of right now -- a later edit to the rule's mapping won't retroactively
    change already-enriched alerts. No-op if the alert has no rule_id or the
    rule has no mapped techniques. Returns the list of MitreTechnique rows
    attached (possibly empty)."""
    if not alert.rule_id:
        return []

    from app.models import Rule
    rule = Rule.query.get(alert.rule_id)
    if rule is None or not rule.mitre_techniques:
        return []

    alert.mitre_techniques = list(rule.mitre_techniques)
    db.session.add(alert)
    return alert.mitre_techniques
