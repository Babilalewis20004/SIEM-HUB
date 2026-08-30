"""
Simple, explainable "overall risk" score for an enriched Alert.

This is deliberately NOT a substitute for alert.severity (the detection
engine's own judgement, set at creation time -- see app/services/detection.py
and app/services/ml_detection.py) or for an IOC's threat_level (the threat
intel feed's own judgement). Both stay untouched and are surfaced separately
so an analyst can see exactly what fed the number, per docs/ARCHITECTURE.md's
"don't let enrichment overwrite detection severity blindly" rule.

This is an *application* risk score -- a documented, transparent heuristic,
not a validated/scientific model. Weights: detection severity 60%, IOC
threat intelligence 40% (only when the alert has at least one IOC match;
otherwise the score is detection severity alone).
"""

_SEVERITY_SCORE = {"info": 10, "warning": 50, "critical": 100}
_THREAT_LEVEL_SCORE = {"unknown": 0, "low": 25, "medium": 50, "high": 75, "critical": 100}
_THREAT_LEVEL_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

DETECTION_WEIGHT = 0.6
IOC_WEIGHT = 0.4


def _bucket(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _highest_threat_level(ioc_matches):
    levels = [m.ioc.threat_level for m in ioc_matches if m.ioc is not None]
    if not levels:
        return None
    return max(levels, key=lambda lvl: _THREAT_LEVEL_RANK.get(lvl, 0))


def compute_overall_risk(alert) -> dict:
    detection_severity = alert.severity or "info"
    detection_score = _SEVERITY_SCORE.get(detection_severity, 10)

    ioc_matches = alert.ioc_matches or []
    ioc_threat_level = _highest_threat_level(ioc_matches)

    if ioc_threat_level is not None:
        ioc_score = _THREAT_LEVEL_SCORE.get(ioc_threat_level, 0)
        overall_score = DETECTION_WEIGHT * detection_score + IOC_WEIGHT * ioc_score
    else:
        overall_score = detection_score

    return {
        "detection_severity": detection_severity,
        "ioc_threat_level": ioc_threat_level,
        "overall_score": round(overall_score, 1),
        "overall_risk": _bucket(overall_score),
    }
