import uuid
from datetime import datetime

from app import db


def gen_uuid():
    return str(uuid.uuid4())


class Log(db.Model):
    __tablename__ = "logs"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)

    timestamp = db.Column(db.DateTime, nullable=False, index=True, default=datetime.utcnow)
    ingested_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    source = db.Column(db.String(64), nullable=False, index=True)   # e.g. "nginx", "auth", "windows"
    host = db.Column(db.String(128), index=True)
    source_ip = db.Column(db.String(45), index=True)                # IPv4/IPv6

    event_type = db.Column(db.String(64), index=True)               # e.g. "login_failed", "http_request"
    severity = db.Column(db.String(16), default="info", index=True) # info | warning | critical

    raw_message = db.Column(db.Text, nullable=False)
    parsed_fields = db.Column(db.JSON, default=dict)                # flexible structured fields

    alerts = db.relationship("Alert", backref="log", lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "ingested_at": self.ingested_at.isoformat() if self.ingested_at else None,
            "source": self.source,
            "host": self.host,
            "source_ip": self.source_ip,
            "event_type": self.event_type,
            "severity": self.severity,
            "raw_message": self.raw_message,
            "parsed_fields": self.parsed_fields or {},
        }
