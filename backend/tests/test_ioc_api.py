from app.models.ioc import IOC


def _create_payload(indicator="185.10.10.10", indicator_type="ip", **overrides):
    payload = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "threat_level": "high",
        "confidence": 92,
        "source": "internal",
    }
    payload.update(overrides)
    return payload


# ---------- RBAC ----------

def test_all_roles_can_read_iocs(client, db, admin_auth_headers, auth_headers, viewer_auth_headers):
    for headers in (admin_auth_headers, auth_headers, viewer_auth_headers):
        assert client.get("/api/iocs", headers=headers).status_code == 200


def test_only_admin_can_create_ioc(client, db, admin_auth_headers, auth_headers, viewer_auth_headers):
    assert client.post("/api/iocs", json=_create_payload(), headers=auth_headers).status_code == 403
    assert client.post("/api/iocs", json=_create_payload(), headers=viewer_auth_headers).status_code == 403
    resp = client.post("/api/iocs", json=_create_payload(), headers=admin_auth_headers)
    assert resp.status_code == 201


def test_only_admin_can_import(client, db, admin_auth_headers, auth_headers):
    body = {"iocs": [_create_payload()]}
    assert client.post("/api/iocs/import", json=body, headers=auth_headers).status_code == 403
    resp = client.post("/api/iocs/import", json=body, headers=admin_auth_headers)
    assert resp.status_code == 200


# ---------- CRUD ----------

def test_create_ioc(client, db, admin_auth_headers):
    resp = client.post("/api/iocs", json=_create_payload(), headers=admin_auth_headers)
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["indicator_type"] == "ip"
    assert data["normalized_indicator"] == "185.10.10.10"
    assert data["threat_level"] == "high"


def test_create_duplicate_ioc_conflicts(client, db, admin_auth_headers):
    client.post("/api/iocs", json=_create_payload(), headers=admin_auth_headers)
    resp = client.post("/api/iocs", json=_create_payload(), headers=admin_auth_headers)
    assert resp.status_code == 409


def test_create_invalid_indicator_rejected(client, db, admin_auth_headers):
    resp = client.post("/api/iocs", json=_create_payload(indicator="not-an-ip"), headers=admin_auth_headers)
    assert resp.status_code == 400


def test_update_ioc(client, db, admin_auth_headers):
    ioc_id = client.post("/api/iocs", json=_create_payload(), headers=admin_auth_headers).get_json()["id"]
    resp = client.patch(f"/api/iocs/{ioc_id}", json={"threat_level": "critical"}, headers=admin_auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["threat_level"] == "critical"


def test_enable_disable_lifecycle(client, db, admin_auth_headers):
    ioc_id = client.post("/api/iocs", json=_create_payload(), headers=admin_auth_headers).get_json()["id"]

    resp = client.post(f"/api/iocs/{ioc_id}/disable", headers=admin_auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["enabled"] is False

    resp = client.post(f"/api/iocs/{ioc_id}/enable", headers=admin_auth_headers)
    assert resp.status_code == 200
    assert resp.get_json()["enabled"] is True


def test_delete_ioc_without_matches(client, db, admin_auth_headers):
    ioc_id = client.post("/api/iocs", json=_create_payload(), headers=admin_auth_headers).get_json()["id"]
    resp = client.delete(f"/api/iocs/{ioc_id}", headers=admin_auth_headers)
    assert resp.status_code == 204
    assert IOC.query.get(ioc_id) is None


# ---------- Import ----------

def test_import_json_reports_counts(client, db, admin_auth_headers):
    body = {"iocs": [
        _create_payload("185.10.10.10", "ip"),
        _create_payload("malicious-example.com", "domain", confidence=85),
        {"indicator": "not-an-ip", "indicator_type": "ip"},  # malformed row
    ]}
    resp = client.post("/api/iocs/import", json=body, headers=admin_auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 3
    assert data["imported"] == 2
    assert data["skipped"] == 1
    assert data["errors"] == 1


def test_import_upsert_updates_existing(client, db, admin_auth_headers):
    body = {"iocs": [_create_payload(confidence=50)]}
    client.post("/api/iocs/import", json=body, headers=admin_auth_headers)

    body2 = {"iocs": [_create_payload(confidence=99)]}
    resp = client.post("/api/iocs/import", json=body2, headers=admin_auth_headers)
    data = resp.get_json()
    assert data["updated"] == 1
    assert data["imported"] == 0

    ioc = IOC.query.filter_by(normalized_indicator="185.10.10.10").first()
    assert ioc.confidence == 99


def test_import_csv_text(client, db, admin_auth_headers):
    csv_body = "indicator,indicator_type,threat_level,confidence,source\n" \
               "185.10.10.10,ip,high,90,internal\n" \
               "malicious-example.com,domain,high,85,internal\n"
    resp = client.post("/api/iocs/import", data=csv_body, headers=admin_auth_headers,
                        content_type="text/csv")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["imported"] == 2


# ---------- Filters ----------

def test_list_filters_by_type_and_threat_level(client, db, admin_auth_headers):
    client.post("/api/iocs", json=_create_payload("185.10.10.10", "ip", threat_level="high"),
                headers=admin_auth_headers)
    client.post("/api/iocs", json=_create_payload("evil.example.com", "domain", threat_level="medium"),
                headers=admin_auth_headers)

    resp = client.get("/api/iocs?type=ip", headers=admin_auth_headers)
    items = resp.get_json()["items"]
    assert len(items) == 1
    assert items[0]["indicator_type"] == "ip"

    resp = client.get("/api/iocs?threat_level=medium", headers=admin_auth_headers)
    items = resp.get_json()["items"]
    assert len(items) == 1
    assert items[0]["threat_level"] == "medium"
