import pytest
from unittest.mock import patch, MagicMock
from services.recon_engine.services.dns_whois import get_dns_info, get_whois_info, get_domain_recon

@pytest.mark.asyncio
async def test_get_dns_info_success():
    """Test de consulta DNS con mocks de dnspython."""
    mock_answer = [MagicMock(address="1.1.1.1")]
    
    with patch("dns.resolver.resolve", return_value=mock_answer):
        # Forzamos HAS_DNS a True para el test
        with patch("services.recon_engine.services.dns_whois.HAS_DNS", True):
            result = await get_dns_info("google.com")
            assert "A" in result
            assert len(result["A"]) > 0

@pytest.mark.asyncio
async def test_get_whois_info_success():
    """Test de consulta WHOIS con mock de python-whois."""
    mock_whois = MagicMock()
    mock_whois.registrar = "Google LLC"
    mock_whois.creation_date = "1997-09-15"
    mock_whois.name_servers = ["ns1.google.com", "ns2.google.com"]
    
    with patch("whois.whois", return_value=mock_whois):
        with patch("services.recon_engine.services.dns_whois.HAS_WHOIS", True):
            result = await get_whois_info("google.com")
            assert result["registrar"] == "Google LLC"
            assert "ns1.google.com" in result["name_servers"]

@pytest.mark.asyncio
async def test_get_domain_recon_integration():
    """Test de la función orquestadora de DNS/WHOIS."""
    with patch("services.recon_engine.services.dns_whois.get_dns_info", return_value={"A": ["1.2.3.4"]}), \
         patch("services.recon_engine.services.dns_whois.get_whois_info", return_value={"registrar": "Test"}):
        
        result = await get_domain_recon("example.com")
        
        assert result["domain"] == "example.com"
        assert result["dns_records"]["A"] == ["1.2.3.4"]
        assert result["whois_info"]["registrar"] == "Test"

@pytest.mark.asyncio
async def test_dns_whois_error_handling():
    """Verificar que los errores no rompen la ejecución."""
    with patch("dns.resolver.resolve", side_effect=Exception("DNS Error")):
        with patch("whois.whois", side_effect=Exception("WHOIS Error")):
            result = await get_domain_recon("fail.com")
            # Debe retornar estructura vacía pero no fallar
            assert result["domain"] == "fail.com"
            assert result["whois_info"]["registrar"] is None
