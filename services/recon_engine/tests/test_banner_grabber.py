import pytest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from services.recon_engine.services.banner_grabber import grab_banner, grab_all_banners

@pytest.mark.asyncio
async def test_grab_banner_ssh_success():
    """Test exitoso capturando banner de SSH."""
    mock_reader = AsyncMock()
    mock_reader.read.return_value = b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\n"
    mock_writer = MagicMock()
    
    with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
        result = await grab_banner("127.0.0.1", 22)
        
        assert result["port"] == 22
        assert result["service"] == "ssh"
        assert "OpenSSH_7.4p1" in result["version"]
        assert "SSH-2.0" in result["raw_banner"]

@pytest.mark.asyncio
async def test_grab_banner_http_success():
    """Test exitoso capturando banner de HTTP."""
    mock_reader = AsyncMock()
    # Simulamos respuesta HTTP con header Server
    mock_reader.read.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx/1.14.1\r\n\r\n"
    mock_writer = MagicMock()
    
    with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
        result = await grab_banner("127.0.0.1", 80)
        
        assert result["service"] == "http"
        assert result["version"] == "nginx/1.14.1"

@pytest.mark.asyncio
async def test_grab_banner_timeout():
    """Verificar manejo de timeout."""
    with patch("asyncio.open_connection", side_effect=asyncio.TimeoutError):
        result = await grab_banner("127.0.0.1", 80)
        assert result["raw_banner"] == ""
        assert result["version"] is None

@pytest.mark.asyncio
async def test_grab_all_banners_parallel():
    """Verificar ejecución en paralelo de múltiples puertos."""
    mock_results = [
        {"port": 22, "service": "ssh", "version": "v1", "raw_banner": "b1"},
        {"port": 80, "service": "http", "version": "v2", "raw_banner": "b2"}
    ]
    
    with patch("services.recon_engine.services.banner_grabber.grab_banner", side_effect=mock_results):
        results = await grab_all_banners("127.0.0.1", [22, 80])
        
        assert len(results) == 2
        assert results[0]["port"] == 22
        assert results[1]["port"] == 80
