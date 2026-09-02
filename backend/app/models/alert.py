import uuid
from datetime import datetime

from app import db


def gen_uuid():
    return str(uuid.uuid4())


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)

    event_id = db.Column(db.String(36), db.ForeignKey("events.id"), nullable=True)
    rule_name = db.Column(db.String(128), nullable=False, index=True)
    rule_id = db.Column(db.String(36), db.ForeignKey("rules.id"), nullable=True)

    title = db.Column(db.String(255), nullable=True)
    severity = db.Column(db.String(16), default="warning", index=True)  # info | warning | critical
    description = db.Column(db.Text, nullable=False)

    # Which detection layer produced this alert: rule | statistical | ml
    detection_source = db.Column(db.String(16), nullable=True, index=True)
    confidence = db.Column(db.Float, nullable=True)
    anomaly_score = db.Column(db.Float, nullable=True)

    # Extra context, e.g. {"source_ip": "1.2.3.4", "count": 12}
    context = db.Column(db.JSON, default=dict)

    status = db.Column(db.String(16), default="open", index=True)  # open | acknowledged | resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    acknowledged_by_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)

    # Legacy flat MITRE mapping, captured at creation time (see
    # app/models/rule.py for the source-of-truth fields on rule-driven
    # alerts). Superseded by the mitre_techniques many-to-many relationship
    # below, populated by app/services/mitre_enrichment.py.
    mitre_tactic = db.Column(db.String(128), nullable=True)
    mitre_technique = db.Column(db.String(16), nullable=True)
    mitre_subtechnique = db.Column(db.String(16), nullable=True)

    incident_id = db.Column(db.String(36), db.ForeignKey("incidents.id"), nullable=True, index=True)

    mitre_techniques = db.relationship(
        "MitreTechnique", secondary="alert_mitre_techniques", lazy=True,
    )
    ioc_matches = db.relationship("IOCMatch", backref="alert", lazy=True)

    def to_dict(self, include_risk=True):
        from app.services.risk_scoring import compute_overall_risk

        event = self.event
        return {
            "id": self.id,
            "event_id": self.event_id,
            "rule_name": self.rule_name,
            "rule_id": self.rule_id,
            "title": self.title or self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "detection_source": self.detection_source,
            "confidence": self.confidence,
            "anomaly_score": self.anomaly_score,
            "context": self.context or {},
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "acknowledged_by_id": self.acknowledged_by_id,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by_id": self.resolved_by_id,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "mitre_subtechnique": self.mitre_subtechnique,
            "mitre": [t.to_summary_dict() for t in self.mitre_techniques],
            "ioc_matches": [m.to_summary_dict() for m in self.ioc_matches],
            "incident_id": self.incident_id,
            "event": event.to_dict() if event else None,
            "risk": compute_overall_risk(self) if include_risk else None,
        }
