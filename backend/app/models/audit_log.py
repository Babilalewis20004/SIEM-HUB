"""
Append-only audit trail for security-sensitive administrative and
investigation actions (role changes, alert/incident lifecycle, rule and
ML-model changes). Never stores passwords, tokens, or secrets — see
app/services/audit.py::log_action for the single write path.
"""
import uuid
from datetime import datetime

from app import db


def gen_uuid():
    return str(uuid.uuid4())


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)

    actor_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)  # null = system
    action = db.Column(db.String(64), nullable=False, index=True)
    target_type = db.Column(db.String(32), nullable=False, index=True)
    target_id = db.Column(db.String(64), nullable=True, index=True)
    extra = db.Column(db.JSON, default=dict)
    ip_address = db.Column(db.String(45), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "actor_id": self.actor_id,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "metadata": self.extra or {},
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
