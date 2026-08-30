"""
Single write path for the audit trail. Call this from routes right after a
security-sensitive mutation succeeds — never logs passwords, tokens, or
other secrets, only actor/action/target/metadata.
"""
from flask import request

from app import db
from app.models import AuditLog


def log_action(actor, action: str, target_type: str, target_id=None, metadata=None):
    entry = AuditLog(
        actor_id=getattr(actor, "id", None),
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        extra=metadata or {},
        ip_address=request.remote_addr,
    )
    db.session.add(entry)
    return entry
