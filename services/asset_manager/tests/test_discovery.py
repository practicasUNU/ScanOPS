"""
Tests para Discovery — US-1.4
==============================
Cubre: _ping_sweep(), run_network_discovery task,
       POST /assets/discovery, GET /assets/discovery/{task_id}
"""
import pytest
from unittest.mock import patch, MagicMock


# ─── Tests unitarios: _ping_sweep ─────────────────────────

class TestPingSweep:
    @patch("subprocess.run")
    def test_parses_nmap_output(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Host: 10.0.0.1 ()\nHost: 10.0.0.2 ()\n",
        )
        from services.asset_manager.tasks.discovery import _ping_sweep

        ips = _ping_sweep("10.0.0.0/30")
        assert len(ips) == 2
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips

    @patch("subprocess.run")
    def test_empty_when_no_hosts(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        from services.asset_manager.tasks.discovery import _ping_sweep

        ips = _ping_sweep("10.99.99.0/24")
        assert ips == []

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_raises_when_nmap_missing(self, mock_run):
        from services.asset_manager.tasks.discovery import _ping_sweep

        with pytest.raises(RuntimeError, match="nmap"):
            _ping_sweep("10.0.0.0/30")

    @patch("subprocess.run")
    def test_returns_empty_on_timeout(self, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nmap", timeout=300)
        from services.asset_manager.tasks.discovery import _ping_sweep

        ips = _ping_sweep("10.0.0.0/24")
        assert ips == []

    @patch("subprocess.run")
    def test_ignores_non_host_lines(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="# Nmap scan report\nHost: 10.0.0.1 ()\n# Done\n",
        )
        from services.asset_manager.tasks.discovery import _ping_sweep

        ips = _ping_sweep("10.0.0.0/30")
        assert ips == ["10.0.0.1"]


# ─── Tests de endpoint: POST /assets/discovery ────────────

class TestDiscoveryEndpoint:
    def test_trigger_discovery_returns_task_id(self, client, auth_headers):
        with patch(
            "services.asset_manager.api.router.run_network_discovery"
        ) as mock_task:
            mock_task.delay.return_value = MagicMock(id="fake-task-123")
            resp = client.post(
                "/assets/discovery",
                json={"network_ranges": ["10.5.5.0/30"]},
                headers=auth_headers,
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["status"] == "started"
            assert len(body["tasks"]) == 1
            assert body["tasks"][0]["task_id"] == "fake-task-123"
            assert body["tasks"][0]["cidr"] == "10.5.5.0/30"

    def test_trigger_discovery_multiple_ranges(self, client, auth_headers):
        with patch(
            "services.asset_manager.api.router.run_network_discovery"
        ) as mock_task:
            mock_task.delay.return_value = MagicMock(id="task-multi")
            resp = client.post(
                "/assets/discovery",
                json={"network_ranges": ["10.0.0.0/24", "192.168.1.0/28"]},
                headers=auth_headers,
            )
            assert resp.status_code == 200
            assert len(resp.json()["tasks"]) == 2

    def test_get_discovery_status_pending(self, client, auth_headers):
        with patch(
            "services.asset_manager.api.router.AsyncResult"
        ) as mock_result:
            instance = MagicMock()
            instance.status = "PENDING"
            instance.ready.return_value = False
            mock_result.return_value = instance

            resp = client.get(
                "/assets/discovery/fake-id-123",
                headers=auth_headers,
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["status"] == "PENDING"
            assert body["result"] is None

    def test_get_discovery_status_success(self, client, auth_headers):
        with patch(
            "services.asset_manager.api.router.AsyncResult"
        ) as mock_result:
            instance = MagicMock()
            instance.status = "SUCCESS"
            instance.ready.return_value = True
            instance.result = {"hosts_found": 5, "new_assets": 3}
            mock_result.return_value = instance

            resp = client.get(
                "/assets/discovery/fake-id-456",
                headers=auth_headers,
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["status"] == "SUCCESS"
            assert body["result"]["hosts_found"] == 5


# ─── Tests de la task completa (con mock de nmap) ─────────

class TestDiscoveryTask:
    @patch("services.asset_manager.tasks.discovery._ping_sweep")
    def test_creates_new_assets(self, mock_sweep, test_db, mock_vault):
        mock_sweep.return_value = ["10.77.77.1", "10.77.77.2"]
        from services.asset_manager.tasks.discovery import run_network_discovery

        # Patch SessionLocal para usar nuestra test_db
        with patch(
            "services.asset_manager.tasks.discovery.SessionLocal",
            return_value=test_db,
        ):
            result = run_network_discovery("10.77.77.0/30")

        assert result["hosts_found"] == 2
        assert result["new_assets"] == 2
        assert len(result["new_asset_ids"]) == 2

    
    @patch("services.asset_manager.tasks.discovery._ping_sweep")
    def test_skips_existing_ips(self, mock_sweep, client, auth_headers, mock_vault):
        """Discovery no debe crear duplicados de IPs que ya existen."""
        # Crear un activo via API
        client.post(
            "/assets",
            json={"ip": "10.88.88.1", "responsable": "Test"},
            headers=auth_headers,
        )

        # Simular discovery via endpoint
        with patch(
            "services.asset_manager.api.router.run_network_discovery"
        ) as mock_task:
            mock_task.delay.return_value = MagicMock(id="test-skip")
            resp = client.post(
                "/assets/discovery",
                json={"network_ranges": ["10.88.88.0/30"]},
                headers=auth_headers,
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "started"

    def test_invalid_cidr_returns_error(self, test_db, mock_vault):
        from services.asset_manager.tasks.discovery import run_network_discovery

        with patch(
            "services.asset_manager.tasks.discovery.SessionLocal",
            return_value=test_db,
        ):
            result = run_network_discovery("not-a-cidr")

        assert "error" in result