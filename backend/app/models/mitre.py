"""
MITRE ATT&CK technique catalogue and the rule/alert mapping tables.

`Rule` and `Alert` (see app/models/rule.py, app/models/alert.py) already carry
flat mitre_tactic/mitre_technique/mitre_subtechnique columns copied at
detection time -- those stay as-is for backward compatibility. This module
adds a small catalogue (so technique IDs resolve to names/tactics) and
many-to-many mapping tables so a single rule (and the alerts it produces) can
reference multiple techniques, per docs/ARCHITECTURE.md's enrichment design.

Alert <-> technique rows are written by app/services/mitre_enrichment.py at
enrichment time, copied from the rule's mapping as it existed *then* -- not
read live off the rule -- so editing a rule's mapping later never rewrites
the ATT&CK context already recorded on old alerts.
"""
import uuid
from datetime import datetime

from app import db


def gen_uuid():
    return str(uuid.uuid4())


rule_mitre_techniques = db.Table(
    "rule_mitre_techniques",
    db.Column("rule_id", db.String(36), db.ForeignKey("rules.id"), primary_key=True),
    db.Column("technique_id", db.String(36), db.ForeignKey("mitre_techniques.id"), primary_key=True),
)

alert_mitre_techniques = db.Table(
    "alert_mitre_techniques",
    db.Column("alert_id", db.String(36), db.ForeignKey("alerts.id"), primary_key=True),
    db.Column("technique_id", db.String(36), db.ForeignKey("mitre_techniques.id"), primary_key=True),
)


class MitreTechnique(db.Model):
    __tablename__ = "mitre_techniques"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)

    technique_id = db.Column(db.String(16), nullable=False, unique=True, index=True)  # e.g. "T1110"
    name = db.Column(db.String(255), nullable=False)
    tactic = db.Column(db.String(128), nullable=False, index=True)  # e.g. "Credential Access"
    description = db.Column(db.Text, nullable=True)

    # Self-referential: subtechniques (e.g. T1110.001) point at their parent (T1110).
    parent_technique_id = db.Column(db.String(36), db.ForeignKey("mitre_techniques.id"), nullable=True)
    subtechniques = db.relationship(
        "MitreTechnique", backref=db.backref("parent_technique", remote_side=[id]), lazy=True
    )

    url = db.Column(db.String(255), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "description": self.description,
            "parent_technique_id": self.parent_technique_id,
            "url": self.url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def to_summary_dict(self):
        """Compact shape embedded in Alert/Incident payloads."""
        return {"technique_id": self.technique_id, "name": self.name, "tactic": self.tactic}
