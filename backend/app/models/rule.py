import uuid
from datetime import datetime

from app import db


def gen_uuid():
    return str(uuid.uuid4())


class Rule(db.Model):
    __tablename__ = "rules"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)

    name = db.Column(db.String(128), nullable=False, unique=True)
    rule_type = db.Column(db.String(32), nullable=False)  # "threshold" | "pattern" | "blocklist"

    # Flexible condition payload, e.g.
    # threshold: {"event_type": "login_failed", "count": 5, "window_seconds": 60, "group_by": "source_ip"}
    # pattern:   {"field": "raw_message", "regex": "DROP TABLE"}
    # blocklist: {"field": "source_ip", "values": ["1.2.3.4"]}
    condition = db.Column(db.JSON, nullable=False, default=dict)

    severity = db.Column(db.String(16), default="warning")
    enabled = db.Column(db.Boolean, default=True)

    # Legacy flat MITRE mapping (see app/models/alert.py for the denormalised
    # per-alert copy captured at detection time). Superseded by the
    # mitre_techniques many-to-many relationship below for new mappings, but
    # kept populated/readable for back-compat with existing rules/alerts.
    mitre_tactic = db.Column(db.String(128), nullable=True)
    mitre_technique = db.Column(db.String(16), nullable=True)      # e.g. "T1110"
    mitre_subtechnique = db.Column(db.String(16), nullable=True)   # e.g. "T1110.001"

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    mitre_techniques = db.relationship(
        "MitreTechnique", secondary="rule_mitre_techniques", lazy=True,
    )

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "rule_type": self.rule_type,
            "condition": self.condition or {},
            "severity": self.severity,
            "enabled": self.enabled,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "mitre_subtechnique": self.mitre_subtechnique,
            "mitre": [t.to_summary_dict() for t in self.mitre_techniques],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
