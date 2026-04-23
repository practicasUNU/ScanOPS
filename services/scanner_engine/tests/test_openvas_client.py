import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from services.scanner_engine.clients.openvas_client import OpenVASClient

@pytest.fixture
def openvas_client():
    with patch("services.scanner_engine.clients.openvas_client.settings") as mock_settings:
        mock_settings.openvas_host = "test_host"
        mock_settings.openvas_port = 9390
        mock_settings.openvas_user = "admin"
        mock_settings.openvas_pass = "admin"
        return OpenVASClient()

@pytest.mark.asyncio
async def test_create_target_success(openvas_client):
    """Verificar creación de target con mock de GMP."""
    mock_gmp = MagicMock()
    mock_gmp.create_target.return_value = {"id": "target_uuid_123"}
    mock_gmp.is_connected.return_value = True
    
    with patch.object(openvas_client, "_get_gmp", return_value=mock_gmp):
        target_id = await openvas_client.create_target(["10.0.0.1"], "TestTarget")
        assert target_id == "target_uuid_123"
        mock_gmp.create_target.assert_called_once()

@pytest.mark.asyncio
async def test_scan_asset_full_flow(openvas_client):
    """Test del flujo completo de escaneo (Target -> Task -> Start -> Wait -> Report)."""
    # Mocks de los métodos internos para no depender de la conexión real
    with patch.object(openvas_client, "create_target", new_callable=AsyncMock) as m_tgt, \
         patch.object(openvas_client, "create_task", new_callable=AsyncMock) as m_tsk, \
         patch.object(openvas_client, "start_task", new_callable=AsyncMock) as m_start, \
         patch.object(openvas_client, "wait_for_task_completion", new_callable=AsyncMock) as m_wait, \
         patch.object(openvas_client, "get_report_findings", new_callable=AsyncMock) as m_report, \
         patch.object(openvas_client, "disconnect", new_callable=AsyncMock):
        
        m_tgt.return_value = "tgt_1"
        m_tsk.return_value = "tsk_1"
        m_start.return_value = "rpt_1"
        m_wait.return_value = True
        m_report.return_value = [MagicMock(title="Vuln 1")]
        
        findings = await openvas_client.scan_asset(1, "1.1.1.1", "Asset1")
        
        assert len(findings) == 1
        assert findings[0].title == "Vuln 1"
        m_wait.assert_awaited_once()

@pytest.mark.asyncio
async def test_openvas_connection_error(openvas_client):
    """Verificar manejo de errores de conexión."""
    with patch("services.scanner_engine.clients.openvas_client.TlsConnection", side_effect=Exception("Conn Failed")):
        with pytest.raises(ConnectionError):
            await openvas_client._get_gmp()
