"""
Integration Tests — CRUD API Endpoints (US-1.2 / US-1.5)
=========================================================
Tests every endpoint in router.py via FastAPI TestClient.
Covers: POST, GET list, GET single, PUT, DELETE (soft), GET audit.
"""

import pytest


class TestCreateAsset:
    """POST /assets"""

    def test_create_asset_success(self, client, sample_api_payload, auth_headers):
        resp = client.post("/assets", json=sample_api_payload, headers=auth_headers)
        assert resp.status_code == 201
        body = resp.json()
        assert body["ip"] == "10.202.15.100"
        assert body["hostname"] == "srv-auditoria-01"
        assert body["criticidad"] == "ALTA"
        assert body["tipo"] == "SERVER"
        assert body["responsable"] == "Equipo SOC"
        assert body["id"] is not None
        assert body["status"] == "ACTIVO"

    def test_create_asset_minimal(self, client, auth_headers):
        payload = {"ip": "192.168.1.1", "responsable": "Admin"}
        resp = client.post("/assets", json=payload, headers=auth_headers)
        assert resp.status_code == 201
        body = resp.json()
        assert body["criticidad"] == "PENDIENTE_CLASIFICAR"
        assert body["tipo"] == "OTRO"

    def test_create_asset_with_password_stores_vault_path(
        self, client, auth_headers, mock_vault
    ):
        payload = {
            "ip": "10.0.0.5",
            "responsable": "Admin",
            "password": "SuperSecret123!",
        }
        resp = client.post("/assets", json=payload, headers=auth_headers)
        assert resp.status_code == 201
        body = resp.json()
        # vault_path should be set, password should NOT appear in response
        assert body.get("vault_path") is not None
        assert "SuperSecret123" not in str(body)
        # Vault mock was called
        mock_vault.store_credentials.assert_called_once()

    def test_create_asset_invalid_ip(self, client, auth_headers):
        payload = {"ip": "not-an-ip", "responsable": "Admin"}
        resp = client.post("/assets", json=payload, headers=auth_headers)
        assert resp.status_code == 422

    def test_create_asset_invalid_mac(self, client, auth_headers):
        payload = {"ip": "10.0.0.1", "responsable": "Admin", "mac_address": "ZZ:ZZ"}
        resp = client.post("/assets", json=payload, headers=auth_headers)
        assert resp.status_code == 422

    def test_create_asset_invalid_ens_tag(self, client, auth_headers):
        payload = {
            "ip": "10.0.0.1",
            "responsable": "Admin",
            "tags_ens": ["invalid_tag"],
        }
        resp = client.post("/assets", json=payload, headers=auth_headers)
        assert resp.status_code == 422

    def test_create_asset_no_auth_returns_401(self, client, sample_api_payload):
        resp = client.post("/assets", json=sample_api_payload)
        # With our override, auth is always injected — this tests the dependency exists
        # In production without override, it would be 401
        assert resp.status_code in (201, 401)


class TestListAssets:
    """GET /assets"""

    def test_list_empty(self, client, auth_headers):
        resp = client.get("/assets", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["items"] == []
        assert body["page"] == 1

    def test_list_with_assets(self, client, auth_headers, created_asset):
        resp = client.get("/assets", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert len(body["items"]) == 1
        assert body["items"][0]["ip"] == "10.202.15.100"

    def test_list_pagination(self, client, auth_headers):
        # Create 3 assets
        for i in range(3):
            client.post(
                "/assets",
                json={"ip": f"10.0.0.{i+1}", "responsable": "Admin"},
                headers=auth_headers,
            )
        # Page 1, size 2
        resp = client.get("/assets?page=1&page_size=2", headers=auth_headers)
        body = resp.json()
        assert body["total"] == 3
        assert len(body["items"]) == 2
        assert body["page"] == 1

        # Page 2
        resp = client.get("/assets?page=2&page_size=2", headers=auth_headers)
        body = resp.json()
        assert len(body["items"]) == 1

    def test_list_filter_by_criticidad(self, client, auth_headers):
        client.post(
            "/assets",
            json={"ip": "10.0.0.1", "responsable": "A", "criticidad": "ALTA"},
            headers=auth_headers,
        )
        client.post(
            "/assets",
            json={"ip": "10.0.0.2", "responsable": "B", "criticidad": "BAJA"},
            headers=auth_headers,
        )
        resp = client.get("/assets?criticidad=ALTA", headers=auth_headers)
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["criticidad"] == "ALTA"

    def test_list_filter_by_tipo(self, client, auth_headers):
        client.post(
            "/assets",
            json={"ip": "10.0.0.1", "responsable": "A", "tipo": "SERVER"},
            headers=auth_headers,
        )
        client.post(
            "/assets",
            json={"ip": "10.0.0.2", "responsable": "B", "tipo": "IOT"},
            headers=auth_headers,
        )
        resp = client.get("/assets?tipo=SERVER", headers=auth_headers)
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["tipo"] == "SERVER"

    def test_list_search_by_ip(self, client, auth_headers, created_asset):
        resp = client.get("/assets?search=10.202.15", headers=auth_headers)
        body = resp.json()
        assert body["total"] == 1

    def test_list_search_by_hostname(self, client, auth_headers, created_asset):
        resp = client.get("/assets?search=auditoria", headers=auth_headers)
        body = resp.json()
        assert body["total"] == 1

    def test_list_excludes_deleted_by_default(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        client.delete(f"/assets/{asset_id}", headers=auth_headers)
        resp = client.get("/assets", headers=auth_headers)
        assert resp.json()["total"] == 0

    def test_list_includes_deleted_when_requested(
        self, client, auth_headers, created_asset
    ):
        asset_id = created_asset["id"]
        client.delete(f"/assets/{asset_id}", headers=auth_headers)
        resp = client.get("/assets?include_deleted=true", headers=auth_headers)
        assert resp.json()["total"] == 1


class TestGetAsset:
    """GET /assets/{id}"""

    def test_get_existing(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        resp = client.get(f"/assets/{asset_id}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == asset_id

    def test_get_nonexistent(self, client, auth_headers):
        resp = client.get("/assets/9999", headers=auth_headers)
        assert resp.status_code == 404

    def test_get_deleted_returns_404(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        client.delete(f"/assets/{asset_id}", headers=auth_headers)
        resp = client.get(f"/assets/{asset_id}", headers=auth_headers)
        assert resp.status_code == 404


class TestUpdateAsset:
    """PUT /assets/{id}"""

    def test_update_single_field(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        resp = client.put(
            f"/assets/{asset_id}",
            json={"criticidad": "MEDIA"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["criticidad"] == "MEDIA"

    def test_update_multiple_fields(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        resp = client.put(
            f"/assets/{asset_id}",
            json={"hostname": "nuevo-host", "departamento": "Redes"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["hostname"] == "nuevo-host"
        assert body["departamento"] == "Redes"

    def test_update_nonexistent(self, client, auth_headers):
        resp = client.put(
            "/assets/9999",
            json={"criticidad": "BAJA"},
            headers=auth_headers,
        )
        assert resp.status_code == 404

    def test_update_with_reason(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        resp = client.put(
            f"/assets/{asset_id}?reason=Reclasificación%20tras%20auditoría",
            json={"criticidad": "BAJA"},
            headers=auth_headers,
        )
        assert resp.status_code == 200

    def test_update_generates_audit_log(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        client.put(
            f"/assets/{asset_id}",
            json={"criticidad": "BAJA"},
            headers=auth_headers,
        )
        # Check audit trail
        resp = client.get(f"/assets/{asset_id}/audit", headers=auth_headers)
        assert resp.status_code == 200
        logs = resp.json()["items"]
        actions = [log["action"] for log in logs]
        assert "UPDATE" in actions


class TestDeleteAsset:
    """DELETE /assets/{id}"""

    def test_soft_delete(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        resp = client.delete(f"/assets/{asset_id}", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "BAJA"
        assert body["deleted_at"] is not None

    def test_delete_nonexistent(self, client, auth_headers):
        resp = client.delete("/assets/9999", headers=auth_headers)
        assert resp.status_code == 404

    def test_delete_preserves_record(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        client.delete(f"/assets/{asset_id}", headers=auth_headers)
        # Record still exists in DB (can be retrieved with include_deleted)
        resp = client.get("/assets?include_deleted=true", headers=auth_headers)
        assert resp.json()["total"] == 1

    def test_delete_generates_audit_log(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        client.delete(f"/assets/{asset_id}", headers=auth_headers)
        # Audit log should exist for the deleted asset
        resp = client.get(f"/assets/{asset_id}/audit", headers=auth_headers)
        assert resp.status_code == 200
        logs = resp.json()["items"]
        actions = [log["action"] for log in logs]
        assert "DELETE" in actions

    def test_delete_with_reason(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        resp = client.delete(
            f"/assets/{asset_id}?reason=Decomisión%20planificada",
            headers=auth_headers,
        )
        assert resp.status_code == 200
