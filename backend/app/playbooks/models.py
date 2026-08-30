"""
Playbook data model. See app/playbooks/engine.py for execution, registry.py
for the action allowlist, and docs/ARCHITECTURE.md's playbook section for
the full design rationale.

A Playbook's `steps` field is a validated, declarative list (never code --
see validators.py):

    [{"action": "add_incident_tag", "parameters": {"tag": "brute-force"}},
     {"action": "block_ip", "parameters": {"ip": "{{source_ip}}"}}]

`{{source_ip}}` etc. are resolved from the trigger context (the alert/event
that fired the playbook) at execution time, in engine.py -- never evaluated
as code.
"""
import uuid
from datetime import datetime

from app import db

TRIGGER_TYPES = ("manual", "alert", "incident")
RISK_LEVELS = ("low", "medium", "high", "critical")
EXECUTION_STATUSES = ("pending", "awaiting_approval", "running", "completed", "failed", "cancelled")
EXECUTION_MODES = ("dry_run", "manual", "approved", "automatic")
APPROVAL_STATUSES = ("pending", "approved", "rejected", "expired")
ACTION_LOG_STATUSES = ("pending", "running", "completed", "failed", "skipped_duplicate", "awaiting_approval")

# High/critical risk actions never auto-run; see registry.py's per-action
# requires_approval flag, which this is the policy backing.
AUTO_APPROVE_RISK_LEVELS = ("low", "medium")


def gen_uuid():
    return str(uuid.uuid4())


class Playbook(db.Model):
    __tablename__ = "playbooks"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)

    name = db.Column(db.String(128), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    version = db.Column(db.Integer, nullable=False, default=1)
    enabled = db.Column(db.Boolean, nullable=False, default=True)

    trigger_type = db.Column(db.String(16), nullable=False, default="manual")  # see TRIGGER_TYPES
    # Declarative match condition evaluated against the triggering alert/incident,
    # e.g. {"rule_name": "brute_force_ssh"} or {"severity": ">=high"}. See
    # engine.py's condition evaluator -- never eval()'d.
    trigger_condition = db.Column(db.JSON, nullable=True, default=dict)

    steps = db.Column(db.JSON, nullable=False, default=list)

    created_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "enabled": self.enabled,
            "trigger_type": self.trigger_type,
            "trigger_condition": self.trigger_condition or {},
            "steps": self.steps or [],
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class PlaybookExecution(db.Model):
    __tablename__ = "playbook_executions"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)

    playbook_id = db.Column(db.String(36), db.ForeignKey("playbooks.id"), nullable=False, index=True)
    incident_id = db.Column(db.String(36), db.ForeignKey("incidents.id"), nullable=True, index=True)
    alert_id = db.Column(db.String(36), db.ForeignKey("alerts.id"), nullable=True, index=True)

    # Null triggered_by means an automatic alert/incident trigger fired this,
    # not a person -- used for approval separation-of-duties (a system-
    # triggered execution has no requester to conflict with an approver).
    triggered_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)

    status = db.Column(db.String(20), nullable=False, default="pending", index=True)  # EXECUTION_STATUSES
    mode = db.Column(db.String(16), nullable=False, default="manual")  # EXECUTION_MODES

    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    error = db.Column(db.Text, nullable=True)

    # Index into `playbook.steps` of the step currently pending approval /
    # about to resume -- lets the engine continue mid-playbook after approval
    # instead of restarting (which would re-run already-completed steps).
    current_step_index = db.Column(db.Integer, nullable=False, default=0)

    playbook = db.relationship("Playbook")
    incident = db.relationship("Incident")
    alert = db.relationship("Alert")
    action_logs = db.relationship(
        "PlaybookActionLog", backref="execution", lazy=True,
        order_by="PlaybookActionLog.step_index", cascade="all, delete-orphan",
    )
    approvals = db.relationship(
        "PlaybookApproval", backref="execution", lazy=True,
        order_by="PlaybookApproval.requested_at", cascade="all, delete-orphan",
    )

    def to_dict(self, include_logs=True, include_approvals=True):
        data = {
            "id": self.id,
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook.name if self.playbook else None,
            "incident_id": self.incident_id,
            "alert_id": self.alert_id,
            "triggered_by": self.triggered_by,
            "status": self.status,
            "mode": self.mode,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
            "current_step_index": self.current_step_index,
        }
        if include_logs:
            data["action_logs"] = [a.to_dict() for a in self.action_logs]
        # Approvals are at most one-per-step and cheap, unlike action_logs
        # (which can be long for a many-step playbook) -- included by
        # default even in list views so the approval queue UI doesn't need
        # a second request per execution.
        if include_approvals:
            data["approvals"] = [a.to_dict() for a in self.approvals]
        return data


class PlaybookApproval(db.Model):
    __tablename__ = "playbook_approvals"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    execution_id = db.Column(db.String(36), db.ForeignKey("playbook_executions.id"), nullable=False, index=True)
    step_index = db.Column(db.Integer, nullable=False)

    action = db.Column(db.String(64), nullable=False)
    parameters = db.Column(db.JSON, default=dict)
    risk_level = db.Column(db.String(16), nullable=False)  # RISK_LEVELS

    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    requested_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)

    approved_at = db.Column(db.DateTime, nullable=True)
    approved_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
    rejected_at = db.Column(db.DateTime, nullable=True)
    rejected_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
    reason = db.Column(db.Text, nullable=True)

    status = db.Column(db.String(16), nullable=False, default="pending", index=True)  # APPROVAL_STATUSES

    def to_dict(self):
        return {
            "id": self.id,
            "execution_id": self.execution_id,
            "step_index": self.step_index,
            "action": self.action,
            "parameters": self.parameters or {},
            "risk_level": self.risk_level,
            "requested_at": self.requested_at.isoformat() if self.requested_at else None,
            "requested_by": self.requested_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "approved_by": self.approved_by,
            "rejected_at": self.rejected_at.isoformat() if self.rejected_at else None,
            "rejected_by": self.rejected_by,
            "reason": self.reason,
            "status": self.status,
        }


class PlaybookActionLog(db.Model):
    """One row per step attempt. `scope_key` + `action` + `target` carries a
    unique constraint so a playbook re-triggered many times against the same
    incident/alert (e.g. by a burst of correlated alerts) cannot execute the
    same dangerous action twice -- see app/playbooks/engine.py's idempotency
    check, which queries for an existing row before inserting a new one and
    treats the DB UniqueViolation as the authoritative race-safe backstop."""
    __tablename__ = "playbook_action_logs"
    __table_args__ = (
        db.UniqueConstraint("scope_key", "action", "target", name="uq_playbook_action_scope"),
    )

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    execution_id = db.Column(db.String(36), db.ForeignKey("playbook_executions.id"), nullable=False, index=True)
    step_index = db.Column(db.Integer, nullable=False)

    action = db.Column(db.String(64), nullable=False)
    parameters = db.Column(db.JSON, default=dict)
    # incident_id (preferred) or alert_id -- the scope idempotency is checked
    # within. Nullable target means the action has no natural dedup key
    # (e.g. notify_analyst) and is never deduplicated.
    scope_key = db.Column(db.String(36), nullable=True)
    target = db.Column(db.String(255), nullable=True)

    risk_level = db.Column(db.String(16), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")  # ACTION_LOG_STATUSES

    result = db.Column(db.JSON, nullable=True)
    error = db.Column(db.Text, nullable=True)

    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "execution_id": self.execution_id,
            "step_index": self.step_index,
            "action": self.action,
            "parameters": self.parameters or {},
            "target": self.target,
            "risk_level": self.risk_level,
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
