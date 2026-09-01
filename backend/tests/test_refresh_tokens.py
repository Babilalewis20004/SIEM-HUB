from datetime import datetime, timedelta

from app.models import User
from app.models.refresh_token import RefreshToken
from app.utils.auth import issue_refresh_token

REFRESH_COOKIE_PATH = "/api/auth"


def _register_and_login(client, email="refresh@example.com"):
    client.post("/api/auth/register", json={"email": email, "password": "password123"})
    return client.post("/api/auth/login", json={"email": email, "password": "password123"})


def test_login_sets_httponly_refresh_cookie(client, db):
    _register_and_login(client)

    cookie = client.get_cookie("refresh_token", path=REFRESH_COOKIE_PATH)
    assert cookie is not None
    assert cookie.http_only is True
    assert cookie.path == REFRESH_COOKIE_PATH
    assert cookie.same_site == "Strict"


def test_refresh_returns_new_access_token_and_rotates_cookie(client, db):
    _register_and_login(client)
    old_cookie_value = client.get_cookie("refresh_token", path=REFRESH_COOKIE_PATH).value

    resp = client.post("/api/auth/refresh")
    assert resp.status_code == 200
    assert resp.get_json()["token"]

    # The refresh token is single-use: it must rotate even though the access
    # token payload (iat/exp are second-granularity) can legitimately come
    # back byte-identical when login and refresh land in the same second.
    new_cookie_value = client.get_cookie("refresh_token", path=REFRESH_COOKIE_PATH).value
    assert new_cookie_value != old_cookie_value


def test_refresh_rejects_missing_cookie(client, db):
    resp = client.post("/api/auth/refresh")
    assert resp.status_code == 401


def test_refresh_rejects_expired_token(app, client, db):
    with app.app_context():
        user = User(email="expired@example.com", role="viewer")
        user.set_password("password123")
        db.session.add(user)
        db.session.commit()
        raw_token = issue_refresh_token(user)
        row = RefreshToken.query.filter_by(user_id=user.id).one()
        row.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()

    client.set_cookie("refresh_token", raw_token, path=REFRESH_COOKIE_PATH)
    resp = client.post("/api/auth/refresh")
    assert resp.status_code == 401


def test_refresh_reuse_of_rotated_token_revokes_all_sessions(app, client, db):
    _register_and_login(client, email="reuse@example.com")
    old_cookie_value = client.get_cookie("refresh_token", path=REFRESH_COOKIE_PATH).value

    # Rotate once -- old_cookie_value is now revoked, a new one takes its place.
    first_refresh = client.post("/api/auth/refresh")
    assert first_refresh.status_code == 200

    # Replay the already-rotated-out token, as a copied/stolen token would.
    client.set_cookie("refresh_token", old_cookie_value, path=REFRESH_COOKIE_PATH)
    reuse_resp = client.post("/api/auth/refresh")
    assert reuse_resp.status_code == 401

    with app.app_context():
        user = User.query.filter_by(email="reuse@example.com").one()
        rows = RefreshToken.query.filter_by(user_id=user.id).all()
        assert len(rows) >= 2
        assert all(row.revoked_at is not None for row in rows)


def test_logout_revokes_token_and_clears_cookie(client, db):
    _register_and_login(client, email="logout@example.com")

    resp = client.post("/api/auth/logout")
    assert resp.status_code == 204

    assert client.get_cookie("refresh_token", path=REFRESH_COOKIE_PATH) is None

    refresh_resp = client.post("/api/auth/refresh")
    assert refresh_resp.status_code == 401
