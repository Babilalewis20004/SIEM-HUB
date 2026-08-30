"""
The only bridge between the internal event bus (app/events/bus.py) and
Socket.IO. Detection, correlation, incident routes, and the playbook engine
never import flask_socketio directly -- they call bus.publish(...) and this
module relays the envelope to connected clients, keeping the presentation
layer optional (see app/ws/handlers.py for connection auth/rooms).

Room routing: every authenticated connection joins "authenticated" (see
app/ws/handlers.py) regardless of role, since alerts/incidents/playbooks are
visible to every role that already has *_READ permission over REST. A small
allowlist of admin-only event types is instead confined to "role:admin" --
these are operational/user-management events a viewer or analyst should
never see, per the milestone's WebSocket-authorization requirement.
"""
import logging

logger = logging.getLogger(__name__)

ADMIN_ONLY_EVENTS = {
    "user.role_changed",
    "user.disabled",
    "system.configuration_changed",
}

# Every event type this app emits over WebSocket. Kept as an explicit list
# (rather than "subscribe to whatever gets published") so it's obvious from
# reading this file alone what a frontend client can expect to receive.
BROADCAST_EVENT_TYPES = [
    "alert.created", "alert.updated",
    "incident.created", "incident.updated", "incident.assigned",
    "incident.status_changed", "incident.note_added",
    "ioc.match",
    "playbook.started", "playbook.completed", "playbook.failed", "playbook.cancelled",
    "playbook.approval_required",
    "playbook.action_started", "playbook.action_completed", "playbook.action_failed",
    "user.role_changed", "user.disabled",
]

def init_app(socketio_instance):
    """Subscribe the broadcaster to the event bus. create_app() calls
    bus.reset() before this on every invocation (create_app can run more
    than once per process, e.g. once per test) so each app instance starts
    from a clean subscriber list instead of accumulating handlers that
    close over a torn-down socketio_instance from a previous app."""
    from app.events import bus

    def _relay(event_type):
        def _handler(envelope):
            room = "role:admin" if event_type in ADMIN_ONLY_EVENTS else "authenticated"
            socketio_instance.emit(event_type, envelope, room=room)
        return _handler

    for event_type in BROADCAST_EVENT_TYPES:
        bus.subscribe(event_type, _relay(event_type))
