"""
Integration Tests — Ficha Única (US-1.7)
=========================================
Validates the /assets/{id}/ficha endpoint returns the
consolidated asset card consumed by M2/M3/M4.
"""

import pytest


class TestFichaUnica:
    """GET /assets/{id}/ficha"""

    def test_ficha_returns_full_card(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        resp = client.get(f"/assets/{asset_id}/ficha", headers=auth_headers)
        assert resp.status_code == 200
        ficha = resp.json()

        # Core identity fields (Bloque M1)
        assert ficha["id"] == asset_id
        assert ficha["ip"] == "10.202.15.100"
        assert ficha["hostname"] == "srv-auditoria-01"
        assert ficha["criticidad"] == "ALTA"
        assert ficha["tipo"] == "SERVER"
        assert ficha["status"] == "ACTIVO"
        assert ficha["responsable"] == "Equipo SOC"

    def test_ficha_includes_ens_tags(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        resp = client.get(f"/assets/{asset_id}/ficha", headers=auth_headers)
        ficha = resp.json()
        assert "op.exp.1" in ficha["tags_ens"]
        assert "op.acc.6" in ficha["tags_ens"]

    def test_ficha_has_metadata_fields(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        resp = client.get(f"/assets/{asset_id}/ficha", headers=auth_headers)
        ficha = resp.json()
        assert "ficha_generated_at" in ficha
        assert ficha["ficha_version"] == "1.0"

    def test_ficha_m2_m3_fields_null_initially(
        self, client, auth_headers, created_asset
    ):
        """M2 and M3 data should be None until those hitos populate them."""
        asset_id = created_asset["id"]
        resp = client.get(f"/assets/{asset_id}/ficha", headers=auth_headers)
        ficha = resp.json()
        assert ficha["superficie"] is None
        assert ficha["vulnerabilidades"] is None

    def test_ficha_nonexistent_asset(self, client, auth_headers):
        resp = client.get("/assets/9999/ficha", headers=auth_headers)
        assert resp.status_code == 404

    def test_ficha_deleted_asset_not_found(self, client, auth_headers, created_asset):
        asset_id = created_asset["id"]
        client.delete(f"/assets/{asset_id}", headers=auth_headers)
        resp = client.get(f"/assets/{asset_id}/ficha", headers=auth_headers)
        assert resp.status_code == 404
