"""
Integration Tests — Audit Log (US-1.5)
=======================================
Validates that every CRUD operation generates an immutable
audit trail, as required by ENS Alto [op.exp.5].
"""

import pytest


class TestAuditLog:
    """GET /assets/{id}/audit"""

    def test_create_generates_audit_entry(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        resp = client.get(f"/assets/{asset_id}/audit", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] >= 1
        # At least one entry for the CREATE action (or CREDENTIAL_ACCESS)
        actions = [item["action"] for item in body["items"]]
        assert any(a in actions for a in ["CREATE", "CREDENTIAL_ACCESS"])

    def test_update_generates_audit_entry_with_changes(
        self, client, auth_headers, created_asset
    ):
        asset_id = created_asset["id"]
        client.put(
            f"/assets/{asset_id}",
            json={"criticidad": "BAJA"},
            headers=auth_headers,
        )
        resp = client.get(f"/assets/{asset_id}/audit", headers=auth_headers)
        body = resp.json()
        update_logs = [i for i in body["items"] if i["action"] == "UPDATE"]
        assert len(update_logs) >= 1

    def test_delete_generates_audit_entry(
        self, client, auth_headers, created_asset
    ):
        asset_id = created_asset["id"]
        client.delete(f"/assets/{asset_id}", headers=auth_headers)
        resp = client.get(f"/assets/{asset_id}/audit", headers=auth_headers)
        body = resp.json()
        delete_logs = [i for i in body["items"] if i["action"] == "DELETE"]
        assert len(delete_logs) == 1

    def test_audit_records_user_id(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        resp = client.get(f"/assets/{asset_id}/audit", headers=auth_headers)
        body = resp.json()
        for item in body["items"]:
            assert item["user_id"] is not None
            assert item["user_id"] != ""

    def test_audit_records_timestamp(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        resp = client.get(f"/assets/{asset_id}/audit", headers=auth_headers)
        body = resp.json()
        for item in body["items"]:
            assert item["timestamp"] is not None

    def test_audit_limit_parameter(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        # Generate more audit entries
        for i in range(5):
            client.put(
                f"/assets/{asset_id}",
                json={"hostname": f"host-{i}"},
                headers=auth_headers,
            )
        resp = client.get(
            f"/assets/{asset_id}/audit?limit=2", headers=auth_headers
        )
        body = resp.json()
        assert len(body["items"]) <= 2
        assert body["total"] >= 5  # total count is still correct

    def test_audit_for_nonexistent_asset(self, client, auth_headers):
        resp = client.get("/assets/9999/audit", headers=auth_headers)
        assert resp.status_code == 404

    def test_audit_for_deleted_asset_still_works(
        self, client, auth_headers, created_asset
    ):
        """ENS requires audit trail even for deleted assets."""
        asset_id = created_asset["id"]
        client.delete(f"/assets/{asset_id}", headers=auth_headers)
        # Audit endpoint should still work (include_deleted=True internally)
        resp = client.get(f"/assets/{asset_id}/audit", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] >= 1
