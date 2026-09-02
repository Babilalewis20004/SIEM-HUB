"""
Normalised Security Event — the canonical record detection engines and the
API operate on. Raw logs go: parser -> normaliser -> Event. See
app/services/normalization.py for how parser-specific output becomes this
schema, and docs/ARCHITECTURE.md for the full pipeline.
"""
import uuid
from datetime import datetime

from app import db

SEVERITY_LEVELS = ("info", "low", "medium", "high", "critical")
OUTCOMES = ("success", "failure", "blocked", "denied", "unknown")


def gen_uuid():
    return str(uuid.uuid4())


class Event(db.Model):
    __tablename__ = "events"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)

    # When the security event actually occurred (vs. created_at, when we stored it).
    timestamp = db.Column(db.DateTime, nullable=False, index=True, default=datetime.utcnow)

    event_type = db.Column(db.String(64), nullable=False, index=True)   # e.g. authentication_failure
    category = db.Column(db.String(32), nullable=False, index=True)     # e.g. authentication, web
    source_type = db.Column(db.String(32), nullable=False, index=True)  # e.g. ssh, nginx, generic

    source_ip = db.Column(db.String(45), index=True)       # IPv4/IPv6
    destination_ip = db.Column(db.String(45), index=True)
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)

    username = db.Column(db.String(255), index=True)
    hostname = db.Column(db.String(128), index=True)

    action = db.Column(db.String(64))    # e.g. login, request, connect, execute
    outcome = db.Column(db.String(16), index=True)  # success | failure | blocked | denied | unknown

    severity = db.Column(db.String(16), default="info", index=True)  # info|low|medium|high|critical

    raw_message = db.Column(db.Text, nullable=False)
    parsed_fields = db.Column(db.JSON, default=dict)  # parser-specific data that doesn't fit above

    # Reserved for a future LogSource entity (e.g. "which ingestion feed/agent").
    # Nothing populates this yet; it's a placeholder column, not a live FK.
    source_id = db.Column(db.String(36), nullable=True, index=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # DB insertion time

    alerts = db.relationship("Alert", backref="event", lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        from app.services.geoip import lookup_country

        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "category": self.category,
            "source_type": self.source_type,
            "source_ip": self.source_ip,
            "source_geo": lookup_country(self.source_ip),
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "username": self.username,
            "hostname": self.hostname,
            "action": self.action,
            "outcome": self.outcome,
            "severity": self.severity,
            "raw_message": self.raw_message,
            "parsed_fields": self.parsed_fields or {},
            "source_id": self.source_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
