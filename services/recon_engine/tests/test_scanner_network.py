"""
Tests para scanner_network.py — M2 Recon Engine
=================================================
Valida que M2 reporte solo reconocimiento técnico y no vulnerabilidades.
"""

import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from services.recon_engine.services.scanner_network import parse_nmap_xml, perform_full_recon
from services.recon_engine.models.schemas import PortDiscovery, OSInformation
from services.recon_engine.models.recon import ReconBase, ReconSnapshot, ReconSubdomain


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def nmap_xml_output():
    """Simula un XML real de Nmap con puertos y SO."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -O -oX - 10.202.15.100" version="7.94" start="1714381847">
<host>
    <status state="up" reason="echo-reply" reason_ttl="63"/>
    <address addr="10.202.15.100" addrtype="ipv4"/>
    <address addr="E0:D5:5E:50:27:39" addrtype="mac" vendor="Giga-byte Technology"/>
    <hostnames><hostname name="unuware-server" type="user"/></hostnames>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack" reason_ttl="63"/>
            <service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="Ubuntu 3ubuntu13.15" method="probed" conf="10"/>
        </port>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack" reason_ttl="63"/>
            <service name="http" product="Apache httpd" version="2.4.58" method="probed" conf="10"/>
        </port>
    </ports>
    <os>
        <osmatch name="Linux 5.0 - 5.4" accuracy="100" line="68011">
            <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="100">
                <cpe>cpe:/o:linux:linux_kernel:5</cpe>
            </osclass>
        </osmatch>
    </os>
    <times srtt="980" rttvar="5000" to="100000"/>
</host>
<runstats><finished time="1714381860" timestr="Mon Apr 29 10:31:00 2024" summary="Nmap done" elapsed="13.37" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""


@pytest.fixture
def nmap_xml_filtered():
    """XML de Nmap con un puerto filtered para test de firewall detection."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host>
    <status state="up"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
        <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" method="probed" conf="10"/>
        </port>
        <port protocol="tcp" portid="443">
            <state state="filtered"/>
            <service name="https"/>
        </port>
    </ports>
</host>
<runstats><finished elapsed="5.0"/></runstats>
</nmaprun>
"""


@pytest.fixture
def nmap_xml_with_443():
    """XML de Nmap con puerto 443 abierto para test de ssl_active."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host>
    <status state="up"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
        <port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https" method="probed" conf="10"/>
        </port>
    </ports>
</host>
<runstats><finished elapsed="3.0"/></runstats>
</nmaprun>
"""


def _make_db():
    engine = create_engine("sqlite:///:memory:")
    ReconBase.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


# ── Tests existentes (sin regresiones) ────────────────────────────────────────

def test_parse_nmap_xml_recon_only(nmap_xml_output):
    """Verifica que el parseo extraiga puertos y SO sin severidades."""
    ports, os_info, host_info, filtered_count = parse_nmap_xml(nmap_xml_output)

    assert len(ports) == 2
    ssh_port = next(p for p in ports if p.port == 22)
    assert ssh_port.service == "ssh"
    assert ssh_port.version == "OpenSSH 9.6p1 Ubuntu 3ubuntu13.15"
    assert ssh_port.confidence == 0.9
    assert not hasattr(ssh_port, "severity")

    assert os_info is not None
    assert os_info.detected_family == "Linux"
    assert "Linux 5.0" in os_info.detected_version
    assert os_info.confidence == 1.0

    assert host_info.mac_address == "E0:D5:5E:50:27:39"
    assert host_info.vendor == "Giga-byte Technology"
    assert host_info.latency_ms == 0.98

    assert filtered_count == 0


def test_parse_nmap_xml_empty():
    """Verifica manejo de salida vacía."""
    ports, os_info, host_info, filtered_count = parse_nmap_xml("")
    assert len(ports) == 0
    assert os_info is None
    assert host_info is None
    assert filtered_count == 0


@pytest.mark.asyncio
async def test_full_recon_orchestration(nmap_xml_output):
    """Prueba el flujo completo de perform_full_recon con IP target."""
    db = _make_db()
    snapshot_id = "test-snapshot-123"
    target = "10.202.15.100"

    with patch("services.recon_engine.services.scanner_network._run_tool",
               new_callable=AsyncMock) as mock_tool, \
         patch("services.recon_engine.services.scanner_network.grab_all_banners",
               new_callable=AsyncMock, return_value=[]), \
         patch("services.recon_engine.services.scanner_network.get_asn_info",
               new_callable=AsyncMock,
               return_value={"asn": None, "asn_description": None, "country": None}):

        mock_tool.return_value = (nmap_xml_output, "", 0)
        result = await perform_full_recon(snapshot_id, target, db)

        assert result.snapshot_id == snapshot_id
        assert result.status == "completed"
        assert result.summary.total_ports_open == 2
        assert len(result.reconnaissance.ports_discovered) == 2
        assert result.reconnaissance.os_information.detected_family == "Linux"

        snap_db = db.query(ReconSnapshot).filter_by(cycle_id=snapshot_id).first()
        assert snap_db is not None
        assert snap_db.status == "completed"

    db.close()


# ── Nuevos tests Capacidad 4 ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_domain_recon_integrated(nmap_xml_output):
    """target hostname → domain_recon not None en ReconData."""
    db = _make_db()
    domain_recon_dict = {
        "domain": "example.com",
        "dns_records": {"A": ["1.2.3.4"], "MX": [], "TXT": [], "NS": [], "CNAME": []},
        "spf_record": None,
        "dmarc_record": None,
        "whois_info": {"registrar": "Test", "creation_date": None, "expiration_date": None,
                       "name_servers": [], "status": None, "asn": None,
                       "asn_description": None, "country": None},
        "scanned_at": "2026-01-01T00:00:00",
    }

    with patch("services.recon_engine.services.scanner_network._run_tool",
               new_callable=AsyncMock, return_value=(nmap_xml_output, "", 0)), \
         patch("services.recon_engine.services.scanner_network.get_domain_recon",
               new_callable=AsyncMock, return_value=domain_recon_dict), \
         patch("services.recon_engine.services.scanner_network.grab_all_banners",
               new_callable=AsyncMock, return_value=[]):

        result = await perform_full_recon("snap-domain-001", "example.com", db)

    assert result.reconnaissance.domain_recon is not None
    assert result.reconnaissance.domain_recon.domain == "example.com"
    db.close()


@pytest.mark.asyncio
async def test_ip_target_no_domain_recon(nmap_xml_output):
    """Target IP pura → domain_recon is None."""
    db = _make_db()

    with patch("services.recon_engine.services.scanner_network._run_tool",
               new_callable=AsyncMock, return_value=(nmap_xml_output, "", 0)), \
         patch("services.recon_engine.services.scanner_network.grab_all_banners",
               new_callable=AsyncMock, return_value=[]), \
         patch("services.recon_engine.services.scanner_network.get_asn_info",
               new_callable=AsyncMock,
               return_value={"asn": None, "asn_description": None, "country": None}):

        result = await perform_full_recon("snap-ip-002", "192.168.1.1", db)

    assert result.reconnaissance.domain_recon is None
    db.close()


@pytest.mark.asyncio
async def test_ssl_active_flag(nmap_xml_with_443):
    """Puerto 443 en ports → summary.ssl_active == True."""
    db = _make_db()

    with patch("services.recon_engine.services.scanner_network._run_tool",
               new_callable=AsyncMock, return_value=(nmap_xml_with_443, "", 0)), \
         patch("services.recon_engine.services.scanner_network.grab_all_banners",
               new_callable=AsyncMock, return_value=[]), \
         patch("services.recon_engine.services.scanner_network.get_asn_info",
               new_callable=AsyncMock,
               return_value={"asn": None, "asn_description": None, "country": None}):

        result = await perform_full_recon("snap-ssl-003", "1.2.3.4", db)

    assert result.summary.ssl_active is True
    db.close()


@pytest.mark.asyncio
async def test_subdomains_in_response(nmap_xml_output):
    """ReconSubdomain en BD → subdomains[] poblado en ReconData."""
    db = _make_db()

    # Pre-crear snapshot con el cycle_id que usará perform_full_recon
    snap = ReconSnapshot(
        cycle_id="snap-sub-004",
        target="10.0.0.1",
        status="running",
        started_at=datetime.utcnow(),
    )
    db.add(snap)
    db.commit()
    db.refresh(snap)

    sub = ReconSubdomain(snapshot_id=snap.id, subdomain="api.example.com", source="subfinder")
    db.add(sub)
    db.commit()

    with patch("services.recon_engine.services.scanner_network._run_tool",
               new_callable=AsyncMock, return_value=(nmap_xml_output, "", 0)), \
         patch("services.recon_engine.services.scanner_network.grab_all_banners",
               new_callable=AsyncMock, return_value=[]), \
         patch("services.recon_engine.services.scanner_network.get_asn_info",
               new_callable=AsyncMock,
               return_value={"asn": None, "asn_description": None, "country": None}):

        result = await perform_full_recon("snap-sub-004", "10.0.0.1", db)

    assert len(result.reconnaissance.subdomains) == 1
    assert result.reconnaissance.subdomains[0].subdomain == "api.example.com"
    assert result.summary.total_subdomains == 1
    db.close()


@pytest.mark.asyncio
async def test_firewall_detected_flag(nmap_xml_filtered):
    """Puerto filtered en XML de nmap → summary.firewall_detected == True."""
    db = _make_db()

    # Verificar parse_nmap_xml también detecta filtered_count
    ports, _, _, filtered_count = parse_nmap_xml(nmap_xml_filtered)
    assert filtered_count == 1
    assert len(ports) == 1  # solo el puerto open (80)

    with patch("services.recon_engine.services.scanner_network._run_tool",
               new_callable=AsyncMock, return_value=(nmap_xml_filtered, "", 0)), \
         patch("services.recon_engine.services.scanner_network.grab_all_banners",
               new_callable=AsyncMock, return_value=[]), \
         patch("services.recon_engine.services.scanner_network.get_asn_info",
               new_callable=AsyncMock,
               return_value={"asn": None, "asn_description": None, "country": None}):

        result = await perform_full_recon("snap-fw-005", "1.2.3.4", db)

    assert result.summary.firewall_detected is True
    assert result.summary.total_ports_filtered == 1
    db.close()
