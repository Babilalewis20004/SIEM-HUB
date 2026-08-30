"""
WebSocket authentication, RBAC, and real-time delivery tests. Uses
Flask-SocketIO's test_client, which drives the same connect/disconnect
handlers (app/ws/handlers.py) as a real browser connection without opening
a socket.
"""
from datetime import datetime, timedelta

import jwt as pyjwt

from app import socketio
from app.models import AuditLog, Event, Rule
from app.models.mitre import MitreTechnique
from app.services.detection import run_detection_job


def _token_from(auth_headers):
    return auth_headers["Authorization"].split(" ", 1)[1]


def test_valid_token_connects_and_is_audited(app, db, auth_headers):
    with app.app_context():
        client = socketio.test_client(app, auth={"token": _token_from(auth_headers)})
        assert client.is_connected()
        assert AuditLog.query.filter_by(action="websocket.authenticated").first() is not None
        client.disconnect()


def test_missing_token_is_rejected(app, db):
    with app.app_context():
        client = socketio.test_client(app, auth={})
        assert not client.is_connected()
        assert AuditLog.query.filter_by(action="websocket.rejected").first() is not None


def test_invalid_token_is_rejected(app, db):
    with app.app_context():
        client = socketio.test_client(app, auth={"token": "not-a-real-token"})
        assert not client.is_connected()


def test_expired_token_is_rejected(app, db, user):
    with app.app_context():
        payload = {
            "sub": user, "email": "analyst@example.com", "role": "analyst",
            "iat": datetime.utcnow() - timedelta(hours=2),
            "exp": datetime.utcnow() - timedelta(hours=1),
        }
        expired = pyjwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm="HS256")
        client = socketio.test_client(app, auth={"token": expired})
        assert not client.is_connected()


def test_disabled_user_is_rejected(app, db, user, auth_headers):
    with app.app_context():
        from app.models import User
        User.query.get(user).is_active = False
        db.session.commit()

        client = socketio.test_client(app, auth={"token": _token_from(auth_headers)})
        assert not client.is_connected()


def test_admin_only_event_not_delivered_to_analyst(app, db, auth_headers, admin_auth_headers):
    with app.app_context():
        analyst_client = socketio.test_client(app, auth={"token": _token_from(auth_headers)})
        admin_client = socketio.test_client(app, auth={"token": _token_from(admin_auth_headers)})
        analyst_client.get_received()
        admin_client.get_received()

        from app.events import bus
        bus.publish("user.role_changed", {"user_id": "x", "from": "viewer", "to": "analyst"})

        analyst_events = [e["name"] for e in analyst_client.get_received()]
        admin_events = [e["name"] for e in admin_client.get_received()]

        assert "user.role_changed" not in analyst_events
        assert "user.role_changed" in admin_events


def test_alert_and_incident_created_delivered_over_websocket(app, db, auth_headers):
    """Full pipeline: detection -> alert -> enrichment -> correlation ->
    event bus -> WebSocket broadcaster -> connected client, per Part 39."""
    with app.app_context():
        client = socketio.test_client(app, auth={"token": _token_from(auth_headers)})
        client.get_received()

        db.session.add(MitreTechnique(technique_id="T1110", name="Brute Force", tactic="Credential Access"))
        db.session.add(Rule(
            name="brute_force_ssh", rule_type="threshold",
            condition={"event_type": "authentication_failure", "count": 5, "window_seconds": 60,
                       "group_by": "source_ip"},
            severity="critical",
        ))
        now = datetime.utcnow()
        for i in range(6):
            db.session.add(Event(
                timestamp=now - timedelta(seconds=i * 5), event_type="authentication_failure",
                category="authentication", source_type="ssh", source_ip="198.51.100.7",
                username="admin", hostname="web01", action="login", outcome="failure",
                severity="medium", raw_message="sshd: failed password",
            ))
        db.session.commit()

        run_detection_job()

        received = client.get_received()
        names = [e["name"] for e in received]
        assert "alert.created" in names
        assert "incident.created" in names

        alert_event = next(e for e in received if e["name"] == "alert.created")
        payload = alert_event["args"][0]
        assert payload["event_type"] == "alert.created"
        assert payload["data"]["severity"] == "critical"
        assert payload["data"]["incident_id"] is not None
