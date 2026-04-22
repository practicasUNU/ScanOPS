"""
Tests para External Sync — US-1.6
===================================
Cubre: sync_from_external(), _map_snipeit_to_asset(),
       _mock_assets(), POST /assets/sync/external
"""
import pytest
from unittest.mock import patch, AsyncMock


# ─── Tests de endpoint ────────────────────────────────────

class TestSyncEndpoint:
    def test_sync_creates_new_assets(self, client, auth_headers):
        """Primera sync con mock debe crear 2 activos."""
        resp = client.post("/assets/sync/external", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["synced"] == 2
        assert body["total_rows"] == 2

    def test_sync_skips_existing(self, client, auth_headers):
        """Segunda sync no debe crear duplicados."""
        client.post("/assets/sync/external", headers=auth_headers)
        resp = client.post("/assets/sync/external", headers=auth_headers)
        body = resp.json()
        assert body["synced"] == 0
        assert body["skipped"] == 2

    def test_sync_result_has_all_fields(self, client, auth_headers):
        resp = client.post("/assets/sync/external", headers=auth_headers)
        body = resp.json()
        assert "synced" in body
        assert "skipped" in body
        assert "total_rows" in body


# ─── Tests unitarios de mapeo ─────────────────────────────

class TestMapSnipeIT:
    def test_maps_snipeit_fields(self):
        from services.asset_manager.services.external_sync import (
            _map_snipeit_to_asset,
        )

        row = {
            "ip_address": "10.50.50.1",
            "name": "switch-core-01",
            "assigned_to": {"name": "NetOps"},
        }
        mapped = _map_snipeit_to_asset(row)
        assert mapped["ip"] == "10.50.50.1"
        assert mapped["hostname"] == "switch-core-01"
        assert mapped["responsable"] == "NetOps"
        assert mapped["criticidad"] == "PENDIENTE_CLASIFICAR"

    def test_maps_fallback_fields(self):
        from services.asset_manager.services.external_sync import (
            _map_snipeit_to_asset,
        )

        row = {"ip": "10.1.1.1", "hostname": "test", "responsable": "Admin"}
        mapped = _map_snipeit_to_asset(row)
        assert mapped["ip"] == "10.1.1.1"
        assert mapped["hostname"] == "test"
        assert mapped["responsable"] == "Admin"

    def test_maps_empty_assigned_to(self):
        from services.asset_manager.services.external_sync import (
            _map_snipeit_to_asset,
        )

        row = {"ip_address": "10.2.2.2", "name": "test", "assigned_to": "none"}
        mapped = _map_snipeit_to_asset(row)
        # Cuando assigned_to no es dict, cae al fallback de row.get("responsable", "Pendiente")
        # Como no hay key "responsable" en row, devuelve "Pendiente"
        assert mapped["responsable"] == "Pendiente"

    def test_mock_assets_returns_data(self):
        from services.asset_manager.services.external_sync import _mock_assets

        data = _mock_assets()
        assert len(data) == 2
        assert data[0]["ip"] == "10.202.15.50"
        assert data[1]["ip"] == "10.202.15.60"


# ─── Tests con Snipe-IT configurado (mock HTTP) ──────────

class TestSyncWithSnipeIT:
    @pytest.mark.asyncio
    @patch(
        "services.asset_manager.services.external_sync._fetch_snipeit_assets",
        new_callable=AsyncMock,
    )
    async def test_sync_from_snipeit_api(self, mock_fetch, test_db, mock_vault):
        mock_fetch.return_value = [
            {"ip": "10.60.60.1", "hostname": "from-snipeit", "responsable": "IT"},
        ]
        from services.asset_manager.services.external_sync import (
            sync_from_external,
        )

        result = await sync_from_external(test_db)
        assert result["synced"] == 1

    @pytest.mark.asyncio
    @patch(
        "services.asset_manager.services.external_sync._fetch_snipeit_assets",
        new_callable=AsyncMock,
    )
    async def test_sync_skips_empty_ip(self, mock_fetch, test_db, mock_vault):
        mock_fetch.return_value = [
            {"ip": "", "hostname": "no-ip", "responsable": "X"},
        ]
        from services.asset_manager.services.external_sync import (
            sync_from_external,
        )

        result = await sync_from_external(test_db)
        assert result["synced"] == 0
        assert result["skipped"] == 1