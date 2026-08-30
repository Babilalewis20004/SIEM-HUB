"""
Regression test for a real bug found during live end-to-end testing of the
playbook engine: log_action() used to unconditionally read
request.remote_addr, which requires an active Flask *request* context.
Every existing caller at the time (routes, WebSocket connect/disconnect
handlers -- Flask-SocketIO pushes a request context per event) had one, but
app/playbooks/engine.py's background thread (a bare thread started via
socketio.start_background_task, only ever given an *app* context) does not.
The result in production was silent: log_action() raised, the exception
propagated out of the thread uncaught, and the PlaybookExecution row was
left stuck at status="running" forever with no logged error.

pytest-flask's autouse `_push_request_context` fixture pushes a request
context onto the *main test thread* for every test, which is exactly why
the existing test suite never caught this -- calling log_action() directly
from a test body always had a (fake, but present) request context. A real
background thread does not inherit that pushed context (Werkzeug's context
locals are thread-local), so running the assertion there reproduces the
actual bug.
"""
import threading

from app.services.audit import log_action
from app.models import AuditLog


def test_log_action_does_not_require_a_request_context(app, db):
    errors = []

    def _target():
        with app.app_context():
            try:
                entry = log_action(None, "test.background_action", "test", None)
                db.session.commit()
                if entry.ip_address is not None:
                    errors.append(f"expected ip_address=None outside a request, got {entry.ip_address!r}")
            except Exception as e:
                errors.append(repr(e))

    thread = threading.Thread(target=_target)
    thread.start()
    thread.join(timeout=5)

    assert not thread.is_alive(), "log_action() hung instead of raising or returning"
    assert not errors, errors

    with app.app_context():
        entry = AuditLog.query.filter_by(action="test.background_action").first()
        assert entry is not None
        assert entry.ip_address is None
