"""
In-process event bus decoupling detection/correlation/incidents/playbooks
from the WebSocket layer (see app/events/broadcaster.py, the only other
module that imports flask_socketio). There is no Redis/Celery in this
project (single Flask process, SQLite) so a synchronous in-memory
publish/subscribe registry is enough -- if this app is ever split across
multiple worker processes, Flask-SocketIO's `message_queue=` (Redis-backed)
is the documented upgrade path, not a rewrite of this module.

Handlers run synchronously, in subscription order, on the publisher's
thread. A handler that raises is logged and swallowed so one broken
subscriber (e.g. a playbook trigger) can never take down the publisher
(e.g. the detection job) -- mirrors the try/except discipline already used
in app/services/enrichment.py.
"""
import logging
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

_subscribers = defaultdict(list)


def subscribe(event_type: str, handler):
    """Register `handler(envelope)` to run whenever `event_type` is published."""
    _subscribers[event_type].append(handler)


def reset():
    """Test-only: clear all subscriptions (avoids duplicate handlers when
    create_app() runs more than once per process, e.g. once per test)."""
    _subscribers.clear()


def make_envelope(event_type: str, data: dict) -> dict:
    return {
        "event_type": event_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "data": data,
    }


def publish(event_type: str, data: dict):
    """Build the envelope and synchronously notify every subscriber. Never
    raises -- a subscriber failure is logged, not propagated to the caller
    (detection/correlation/incident code must never fail because a
    real-time broadcast or playbook trigger blew up)."""
    envelope = make_envelope(event_type, data)
    for handler in list(_subscribers.get(event_type, ())):
        try:
            handler(envelope)
        except Exception:
            logger.exception("Event handler for %r failed", event_type)
    return envelope
