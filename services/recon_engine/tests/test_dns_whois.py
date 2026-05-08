import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from services.recon_engine.services.dns_whois import (
    get_dns_info, get_whois_info, get_domain_recon,
)

@pytest.mark.asyncio
async def test_get_dns_info_success():
    """Test de consulta DNS con mocks de dnspython."""
    mock_answer = [MagicMock(address="1.1.1.1")]

    with patch("dns.resolver.resolve", return_value=mock_answer):
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
    mock_whois.status = "active"
    mock_whois.expiration_date = None
    mock_whois.asn = None

    with patch("whois.whois", return_value=mock_whois):
        with patch("services.recon_engine.services.dns_whois.HAS_WHOIS", True):
            result = await get_whois_info("google.com")
            assert result["registrar"] == "Google LLC"
            assert "ns1.google.com" in result["name_servers"]

@pytest.mark.asyncio
async def test_get_domain_recon_integration():
    """Test de la función orquestadora de DNS/WHOIS."""
    with patch("services.recon_engine.services.dns_whois.get_dns_info",
               return_value={"A": ["1.2.3.4"], "spf_record": None}), \
         patch("services.recon_engine.services.dns_whois.get_whois_info",
               return_value={"registrar": "Test"}), \
         patch("services.recon_engine.services.dns_whois._get_dmarc_record",
               new_callable=AsyncMock, return_value=None):

        result = await get_domain_recon("example.com")

        assert result["domain"] == "example.com"
        assert result["dns_records"]["A"] == ["1.2.3.4"]
        assert result["whois_info"]["registrar"] == "Test"

@pytest.mark.asyncio
async def test_dns_whois_error_handling():
    """Verificar que los errores no rompen la ejecución."""
    with patch("dns.resolver.resolve", side_effect=Exception("DNS Error")), \
         patch("whois.whois", side_effect=Exception("WHOIS Error")), \
         patch("services.recon_engine.services.dns_whois.HAS_DNS", True), \
         patch("services.recon_engine.services.dns_whois.HAS_WHOIS", True):

        result = await get_domain_recon("fail.com")
        assert result["domain"] == "fail.com"
        assert result["whois_info"]["registrar"] is None


# ── Nuevos tests Capacidades 2 y 3 ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_spf_detected():
    """Dominio con TXT 'v=spf1...' → spf_record no es None."""
    def mock_resolve(domain, rtype):
        if rtype == "TXT":
            m = MagicMock()
            m.__str__ = MagicMock(return_value="v=spf1 include:_spf.google.com ~all")
            return [m]
        import dns.resolver
        raise dns.resolver.NoAnswer()

    with patch("services.recon_engine.services.dns_whois.HAS_DNS", True), \
         patch("dns.resolver.resolve", side_effect=mock_resolve):
        result = await get_dns_info("example.com")

    assert result["spf_record"] is not None
    assert result["spf_record"].startswith("v=spf1")

@pytest.mark.asyncio
async def test_dmarc_detected():
    """Mock _dmarc resolver TXT → dmarc_record no es None en get_domain_recon."""
    def mock_resolve(domain, rtype):
        if domain.startswith("_dmarc") and rtype == "TXT":
            m = MagicMock()
            m.__str__ = MagicMock(return_value="v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
            return [m]
        import dns.resolver
        raise dns.resolver.NoAnswer()

    with patch("services.recon_engine.services.dns_whois.HAS_DNS", True), \
         patch("services.recon_engine.services.dns_whois.HAS_WHOIS", True), \
         patch("dns.resolver.resolve", side_effect=mock_resolve), \
         patch("whois.whois", side_effect=Exception("no whois")):
        recon = await get_domain_recon("example.com")

    assert recon["dmarc_record"] is not None
    assert "DMARC1" in recon["dmarc_record"]

@pytest.mark.asyncio
async def test_asn_populated():
    """whois con campo asn → asn y asn_description no son None."""
    mock_w = MagicMock()
    mock_w.registrar = "Google LLC"
    mock_w.creation_date = None
    mock_w.expiration_date = None
    mock_w.name_servers = []
    mock_w.status = None
    mock_w.asn = "AS15169"
    mock_w.asn_description = "GOOGLE, US"
    mock_w.country = "US"

    with patch("services.recon_engine.services.dns_whois.HAS_WHOIS", True), \
         patch("whois.whois", return_value=mock_w):
        result = await get_whois_info("google.com")

    assert result["asn"] == "AS15169"
    assert result["asn_description"] == "GOOGLE, US"
    assert result["country"] == "US"

@pytest.mark.asyncio
async def test_dns_failure_graceful():
    """dns.resolver lanzando excepción → retorna dict vacío sin crash."""
    with patch("services.recon_engine.services.dns_whois.HAS_DNS", True), \
         patch("dns.resolver.resolve", side_effect=Exception("network error")):
        result = await get_dns_info("fail.com")

    assert isinstance(result, dict)
    assert "A" in result
    assert result["A"] == []
    assert result["spf_record"] is None
