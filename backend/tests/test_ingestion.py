import io

from app.models import Event


def test_upload_valid_lines(client, db, auth_headers):
    lines = [
        "Aug 28 10:31:15 server sshd[1234]: Failed password for root from 192.168.1.50 port 52344 ssh2",
        '203.0.113.5 - - [20/Aug/2026:03:14:11 +0000] "GET /index HTTP/1.1" 200 512',
    ]
    resp = client.post("/api/logs/upload", json={"lines": lines}, headers=auth_headers)
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["total_lines"] == 2
    assert data["parsed"] == 2
    assert data["normalised"] == 2
    assert data["failed"] == 0
    assert data["stored"] == 2
    assert data["ingested"] == 2
    assert Event.query.count() == 2


def test_upload_mixed_valid_and_invalid_lines(client, db, auth_headers):
    lines = [
        "Aug 28 10:31:15 server sshd[1234]: Failed password for root from 192.168.1.50 port 52344 ssh2",
        "Aug 28 10:31:15 server sshd[1234]: Failed password for root",  # malformed ssh line
        '203.0.113.5 - - [20/Aug/2026:03:14:11 +0000] "GET /admin HTTP/1.1" NOTASTATUS 512',  # malformed nginx
        "",  # blank, ignored, not counted
        "systemd: unrelated system message",  # falls back to generic, still stored
    ]
    resp = client.post("/api/logs/upload", json={"lines": lines}, headers=auth_headers)
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["total_lines"] == 4  # blank line excluded
    assert data["failed"] == 2
    assert data["stored"] == 2
    assert Event.query.count() == 2


def test_upload_empty_file(client, db, auth_headers):
    resp = client.post("/api/logs/upload", json={"lines": []}, headers=auth_headers)
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["stored"] == 0
    assert Event.query.count() == 0


def test_upload_unsupported_body(client, db, auth_headers):
    resp = client.post("/api/logs/upload", data="not json, not a file", headers=auth_headers)
    assert resp.status_code == 400


def test_upload_via_file_field(client, db, auth_headers):
    content = "Aug 28 10:31:15 server sshd[1234]: Accepted password for alice from 10.0.0.5 port 4444 ssh2\n"
    data = {"file": (io.BytesIO(content.encode()), "auth.log")}
    resp = client.post(
        "/api/logs/upload", data=data, headers=auth_headers, content_type="multipart/form-data"
    )
    assert resp.status_code == 201
    assert resp.get_json()["stored"] == 1


def test_upload_large_input_all_processed(client, db, auth_headers):
    lines = [
        f'203.0.113.{i % 250} - - [20/Aug/2026:03:14:11 +0000] "GET /p HTTP/1.1" 200 100'
        for i in range(500)
    ]
    resp = client.post("/api/logs/upload", json={"lines": lines}, headers=auth_headers)
    assert resp.status_code == 201
    assert resp.get_json()["stored"] == 500
    assert Event.query.count() == 500


def test_malformed_json_body_returns_400(client, db, auth_headers):
    resp = client.post(
        "/api/logs/upload",
        data="{not valid json",
        headers={**auth_headers, "Content-Type": "application/json"},
    )
    assert resp.status_code == 400


def test_lines_must_be_a_list(client, db, auth_headers):
    resp = client.post("/api/logs/upload", json={"lines": "not a list"}, headers=auth_headers)
    assert resp.status_code == 400


def test_upload_requires_auth(client, db):
    resp = client.post("/api/logs/upload", json={"lines": ["x"]})
    assert resp.status_code == 401


def test_list_logs_filters_by_category_and_source_ip(client, db, auth_headers):
    lines = [
        "Aug 28 10:31:15 server sshd[1234]: Failed password for root from 192.168.1.50 port 52344 ssh2",
        '203.0.113.5 - - [20/Aug/2026:03:14:11 +0000] "GET /index HTTP/1.1" 200 512',
    ]
    client.post("/api/logs/upload", json={"lines": lines}, headers=auth_headers)

    resp = client.get("/api/logs?category=authentication", headers=auth_headers)
    body = resp.get_json()
    assert body["total"] == 1
    assert body["items"][0]["source_ip"] == "192.168.1.50"

    resp = client.get("/api/logs?source_ip=203.0.113.5", headers=auth_headers)
    body = resp.get_json()
    assert body["total"] == 1
    assert body["items"][0]["event_type"] == "http_request"
