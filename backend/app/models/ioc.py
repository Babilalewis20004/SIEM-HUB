"""
Indicators of Compromise (IOCs) and threat-intelligence sources.

IOC is the normalised, deduplicated indicator table (see
app/services/ioc_normalization.py for how `normalized_indicator` is derived).
IOCMatch is the evidence trail: *why* an Event/Alert was enriched with a
given IOC, written by app/services/ioc_matching.py. ThreatIntelSource is a
lightweight registry of where IOCs come from -- IOC.source is a free-text
label so importing/matching never requires one to exist first (see
docs/ARCHITECTURE.md's threat-intel architecture section).
"""
import uuid
from datetime import datetime

from app import db

INDICATOR_TYPES = ("ip", "domain", "url", "md5", "sha1", "sha256")
THREAT_LEVELS = ("unknown", "low", "medium", "high", "critical")


def gen_uuid():
    return str(uuid.uuid4())


class IOC(db.Model):
    __tablename__ = "iocs"
    __table_args__ = (
        db.UniqueConstraint("indicator_type", "normalized_indicator", name="uq_ioc_type_normalized"),
    )

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)

    indicator = db.Column(db.String(512), nullable=False)             # as originally submitted
    indicator_type = db.Column(db.String(16), nullable=False, index=True)  # see INDICATOR_TYPES
    normalized_indicator = db.Column(db.String(512), nullable=False, index=True)

    threat_level = db.Column(db.String(16), default="unknown", index=True)  # see THREAT_LEVELS
    confidence = db.Column(db.Integer, default=50)  # 0-100

    source = db.Column(db.String(128), nullable=True)  # free-text label, e.g. "internal", "AbuseIPDB"
    description = db.Column(db.Text, nullable=True)

    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True, index=True)

    enabled = db.Column(db.Boolean, default=True, index=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # No delete cascade: IOCMatch rows are historical investigation evidence
    # (see app/routes/iocs.py's delete_ioc, which refuses to delete an IOC
    # that has match history -- disable it instead).
    matches = db.relationship("IOCMatch", backref="ioc", lazy=True)

    def is_active(self, now=None):
        now = now or datetime.utcnow()
        if not self.enabled:
            return False
        if self.expires_at is not None and self.expires_at <= now:
            return False
        return True

    def to_dict(self):
        return {
            "id": self.id,
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "normalized_indicator": self.normalized_indicator,
            "threat_level": self.threat_level,
            "confidence": self.confidence,
            "source": self.source,
            "description": self.description,
            "first_seen_at": self.first_seen_at.isoformat() if self.first_seen_at else None,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class IOCMatch(db.Model):
    __tablename__ = "ioc_matches"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)

    ioc_id = db.Column(db.String(36), db.ForeignKey("iocs.id"), nullable=False, index=True)
    event_id = db.Column(db.String(36), db.ForeignKey("events.id"), nullable=True, index=True)
    alert_id = db.Column(db.String(36), db.ForeignKey("alerts.id"), nullable=True, index=True)

    matched_field = db.Column(db.String(32), nullable=False)   # e.g. "source_ip", "destination_ip", "domain"
    matched_value = db.Column(db.String(512), nullable=False)
    confidence = db.Column(db.Integer, nullable=True)  # IOC.confidence at match time

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self, include_ioc=True):
        data = {
            "id": self.id,
            "ioc_id": self.ioc_id,
            "event_id": self.event_id,
            "alert_id": self.alert_id,
            "matched_field": self.matched_field,
            "matched_value": self.matched_value,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_ioc and self.ioc is not None:
            data["ioc"] = self.ioc.to_dict()
        return data

    def to_summary_dict(self):
        """Compact shape embedded in Alert payloads."""
        ioc = self.ioc
        return {
            "indicator": ioc.indicator if ioc else self.matched_value,
            "indicator_type": ioc.indicator_type if ioc else None,
            "threat_level": ioc.threat_level if ioc else None,
            "confidence": self.confidence,
            "source": ioc.source if ioc else None,
            "matched_field": self.matched_field,
        }


class ThreatIntelSource(db.Model):
    __tablename__ = "threat_intel_sources"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)

    name = db.Column(db.String(128), nullable=False, unique=True)
    source_type = db.Column(db.String(32), nullable=False, default="custom")  # local_import|abuseipdb|otx|misp|custom
    url = db.Column(db.String(255), nullable=True)
    enabled = db.Column(db.Boolean, default=True)
    last_updated_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "source_type": self.source_type,
            "url": self.url,
            "enabled": self.enabled,
            "last_updated_at": self.last_updated_at.isoformat() if self.last_updated_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
