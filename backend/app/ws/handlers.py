"""
Authenticated WebSocket connection handling. This is the only real-time
entry point that knows about Socket.IO's connect/disconnect lifecycle --
everything else (detection, correlation, playbooks) only ever talks to
app/events/bus.py.

A connection is authenticated exactly like a REST request: the same
user_from_token() (app/utils/auth.py) that validates JWTs, checks the user
still exists, and rejects a disabled account. There is no unauthenticated
channel and no fallback -- a missing/invalid/expired token or a disabled
user gets the connection refused before it ever joins a room, so no
privileged data can reach it even momentarily.
"""
import logging

from flask import request
from flask_socketio import join_room

from app import db
from app.services.audit import log_action
from app.utils.auth import AuthError, user_from_token

logger = logging.getLogger(__name__)

# sid -> {"user_id", "role"} for the lifetime of a connection, so disconnect
# can audit who left without re-decoding a token.
_connections = {}


def register_handlers(socketio):
    @socketio.on("connect")
    def handle_connect(auth):
        token = (auth or {}).get("token")
        try:
            user = user_from_token(token)
        except AuthError as e:
            logger.info("WebSocket connection rejected: %s", e.message)
            log_action(None, "websocket.rejected", "websocket", None, {"reason": e.message,
                                                                         "ip": request.remote_addr})
            db.session.commit()
            return False  # refuses the connection (Flask-SocketIO contract)

        join_room("authenticated")
        join_room(f"role:{user.role}")
        join_room(f"user:{user.id}")
        _connections[request.sid] = {"user_id": user.id, "role": user.role}

        log_action(user, "websocket.authenticated", "user", user.id, {"ip": request.remote_addr})
        db.session.commit()

    @socketio.on("disconnect")
    def handle_disconnect():
        info = _connections.pop(request.sid, None)
        if info:
            log_action(None, "websocket.disconnected", "user", info["user_id"])
            db.session.commit()
