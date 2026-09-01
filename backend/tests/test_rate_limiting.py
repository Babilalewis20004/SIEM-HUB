"""
Flask-Limiter is applied per-route (login, register, log upload) rather than
globally -- see app/__init__.py's limiter wiring and config.py's RATELIMIT_*
settings. These tests use their own create_app() calls (not the shared `app`
fixture) so each test gets its own low, deterministic limit instead of
waiting out the real (much higher) default of "10 per minute" etc.
"""
from app import create_app, db as _db
from app.models import User
from app.utils.auth import encode_token
from tests.conftest import TestConfig


class _StrictConfig(TestConfig):
    RATELIMIT_LOGIN = "3 per minute"
    RATELIMIT_REGISTER = "2 per minute"
    RATELIMIT_UPLOAD = "2 per minute"
    RATELIMIT_REFRESH = "2 per minute"


def _client_for(config_class):
    app = create_app(config_class)
    return app, app.test_client()


def test_login_returns_429_after_threshold():
    app, client = _client_for(_StrictConfig)
    payload = {"email": "nouser@example.com", "password": "wrong-password"}

    for _ in range(3):
        resp = client.post("/api/auth/login", json=payload)
        assert resp.status_code == 401  # bad credentials, but under the limit

    resp = client.post("/api/auth/login", json=payload)
    assert resp.status_code == 429
    assert resp.get_json()["error"] == "rate_limit_exceeded"


def test_register_returns_429_after_threshold():
    app, client = _client_for(_StrictConfig)

    for i in range(2):
        resp = client.post(
            "/api/auth/register",
            json={"email": f"user{i}@example.com", "password": "password123"},
        )
        assert resp.status_code == 201

    resp = client.post(
        "/api/auth/register",
        json={"email": "one-too-many@example.com", "password": "password123"},
    )
    assert resp.status_code == 429


def test_upload_returns_429_after_threshold():
    app, client = _client_for(_StrictConfig)
    with app.app_context():
        u = User(email="analyst@example.com", role="analyst")
        u.set_password("password123")
        _db.session.add(u)
        _db.session.commit()
        headers = {"Authorization": f"Bearer {encode_token(u)}"}

    for _ in range(2):
        resp = client.post(
            "/api/logs/upload", json={"source": "generic", "lines": ["hello world"]}, headers=headers,
        )
        assert resp.status_code == 201

    resp = client.post(
        "/api/logs/upload", json={"source": "generic", "lines": ["hello again"]}, headers=headers,
    )
    assert resp.status_code == 429


def test_rate_limiting_can_be_disabled_via_config():
    class _DisabledConfig(_StrictConfig):
        RATELIMIT_ENABLED = False

    app, client = _client_for(_DisabledConfig)
    payload = {"email": "nouser@example.com", "password": "wrong-password"}

    for _ in range(5):
        resp = client.post("/api/auth/login", json=payload)
        assert resp.status_code == 401  # never 429, regardless of attempt count


def test_refresh_returns_429_after_threshold():
    app, client = _client_for(_StrictConfig)
    client.post(
        "/api/auth/register", json={"email": "refresh@example.com", "password": "password123"},
    )
    client.post(
        "/api/auth/login", json={"email": "refresh@example.com", "password": "password123"},
    )

    for _ in range(2):
        resp = client.post("/api/auth/refresh")
        assert resp.status_code == 200

    resp = client.post("/api/auth/refresh")
    assert resp.status_code == 429


def test_rate_limit_is_per_app_not_shared_across_tests():
    # Guards against limiter.reset() being removed/broken in create_app():
    # without it, in-memory counters from the tests above (same process,
    # same Limiter singleton) would leak into this one and fail it too.
    app, client = _client_for(_StrictConfig)
    payload = {"email": "nouser@example.com", "password": "wrong-password"}

    for _ in range(3):
        resp = client.post("/api/auth/login", json=payload)
        assert resp.status_code == 401
