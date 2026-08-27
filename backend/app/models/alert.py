import uuid
from datetime import datetime

from app import db


def gen_uuid():
    return str(uuid.uuid4())


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)

    log_id = db.Column(db.String(36), db.ForeignKey("logs.id"), nullable=True)
    rule_name = db.Column(db.String(128), nullable=False, index=True)

    severity = db.Column(db.String(16), default="warning", index=True)  # info | warning | critical
    description = db.Column(db.Text, nullable=False)

    # Extra context, e.g. {"source_ip": "1.2.3.4", "count": 12}
    context = db.Column(db.JSON, default=dict)

    status = db.Column(db.String(16), default="open", index=True)  # open | acknowledged | resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "log_id": self.log_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "context": self.context or {},
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }
