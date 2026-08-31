import pytest
from sqlalchemy.orm import Query


def _boom(self):
    raise RuntimeError("boom")


def test_unhandled_exception_returns_json_500(client, db, auth_headers, monkeypatch):
    monkeypatch.setattr(Query, "count", _boom)

    resp = client.get("/api/stats/summary", headers=auth_headers)

    assert resp.status_code == 500
    assert resp.get_json() == {"error": "internal_server_error"}


def test_unhandled_exception_reraises_in_debug_mode(app, db, auth_headers, monkeypatch):
    monkeypatch.setattr(Query, "count", _boom)
    app.debug = True
    client = app.test_client()

    with pytest.raises(RuntimeError, match="boom"):
        client.get("/api/stats/summary", headers=auth_headers)


def test_404_is_not_swallowed_by_error_handler(client):
    resp = client.get("/api/this-route-does-not-exist")
    assert resp.status_code == 404
