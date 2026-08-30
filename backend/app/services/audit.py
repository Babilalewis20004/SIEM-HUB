"""
Single write path for the audit trail. Call this from routes right after a
security-sensitive mutation succeeds, or from background work (the
playbook engine, WebSocket connect/disconnect handlers) that has no
client IP to record — never logs passwords, tokens, or other secrets,
only actor/action/target/metadata.
"""
from flask import request, has_request_context

from app import db
from app.models import AuditLog


def log_action(actor, action: str, target_type: str, target_id=None, metadata=None):
    entry = AuditLog(
        actor_id=getattr(actor, "id", None),
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        extra=metadata or {},
        # request.remote_addr requires an active HTTP request context, which
        # a route/WebSocket-handler invocation has (Flask-SocketIO pushes
        # one per event) but a bare background thread -- the playbook
        # engine's engine.run() -- does not. has_request_context() lets one
        # log_action() serve both without every caller having to know which
        # situation it's in.
        ip_address=request.remote_addr if has_request_context() else None,
    )
    db.session.add(entry)
    return entry
