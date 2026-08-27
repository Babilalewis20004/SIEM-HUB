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

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "rule_type": self.rule_type,
            "condition": self.condition or {},
            "severity": self.severity,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
