"""
Incident — a first-class investigation grouping one or more related Alerts,
produced by app/services/correlation.py or created manually by an analyst/
admin. See docs/ARCHITECTURE.md for the full Event -> Alert -> Incident
pipeline and the incident status state machine.
"""
import uuid
from datetime import datetime

from app import db

SEVERITY_LEVELS = ("info", "low", "medium", "high", "critical")
PRIORITY_LEVELS = ("low", "medium", "high", "critical")
STATUSES = ("open", "investigating", "contained", "resolved", "closed")


def gen_uuid():
    return str(uuid.uuid4())


class Incident(db.Model):
    __tablename__ = "incidents"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)

    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)

    severity = db.Column(db.String(16), default="medium", index=True)   # see SEVERITY_LEVELS
    status = db.Column(db.String(16), default="open", index=True)       # see STATUSES
    priority = db.Column(db.String(16), default="medium", index=True)   # see PRIORITY_LEVELS

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    first_seen_at = db.Column(db.DateTime, nullable=True)
    last_seen_at = db.Column(db.DateTime, nullable=True, index=True)

    assigned_to = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
    created_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)  # null = system/correlation
    resolved_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)

    # Free-form labels, e.g. added by a playbook's add_incident_tag action
    # or a human. Simple JSON list -- matches the Event.parsed_fields /
    # Rule.condition JSON-column convention rather than a many-to-many table,
    # since tags here don't need cross-incident reuse/filtering yet.
    tags = db.Column(db.JSON, default=list)

    alerts = db.relationship("Alert", backref="incident", lazy=True)
    notes = db.relationship(
        "IncidentNote", backref="incident", lazy=True,
        order_by="IncidentNote.created_at", cascade="all, delete-orphan",
    )

    def enrichment_summary(self):
        """Aggregated MITRE + IOC context across every alert on this
        incident, deduplicated -- an analyst-facing rollup, not raw feed
        data (see docs/ARCHITECTURE.md's enrichment section)."""
        techniques = {}
        iocs = {}
        for alert in self.alerts:
            for t in alert.mitre_techniques:
                techniques[t.technique_id] = t.to_summary_dict()
            for m in alert.ioc_matches:
                if m.ioc is None:
                    continue
                iocs[m.ioc.id] = {
                    "indicator": m.ioc.indicator,
                    "indicator_type": m.ioc.indicator_type,
                    "threat_level": m.ioc.threat_level,
                }
        return {
            "mitre_techniques": list(techniques.values()),
            "ioc_matches": list(iocs.values()),
        }

    def to_dict(self, include_alerts=True, include_notes=False):
        data = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "priority": self.priority,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "first_seen_at": self.first_seen_at.isoformat() if self.first_seen_at else None,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "assigned_to": self.assigned_to,
            "created_by": self.created_by,
            "resolved_by": self.resolved_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "tags": self.tags or [],
            "alert_count": len(self.alerts),
            "enrichment_summary": self.enrichment_summary(),
        }
        if include_alerts:
            data["alerts"] = [a.to_dict() for a in self.alerts]
        if include_notes:
            data["notes"] = [n.to_dict() for n in self.notes]
        return data


class IncidentNote(db.Model):
    __tablename__ = "incident_notes"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    incident_id = db.Column(db.String(36), db.ForeignKey("incidents.id"), nullable=False, index=True)
    # Nullable: a playbook's create_case_note action has no human author when
    # it runs unattended (an automatic alert/incident trigger, not a person
    # clicking "execute") -- null means "system/playbook", same convention
    # AuditLog.actor_id already uses for system actions.
    author_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)

    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "author_id": self.author_id,
            "content": self.content,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
