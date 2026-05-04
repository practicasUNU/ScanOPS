"""
Tests para scanner_network.py refactorizado — M2 Recon Engine
=============================================================
Valida que M2 reporte solo reconocimiento técnico y no vulnerabilidades.
"""

import pytest
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock, AsyncMock
from services.recon_engine.services.scanner_network import parse_nmap_xml
from services.recon_engine.models.schemas import PortDiscovery, OSInformation

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
<runstats><finished time="1714381860" timestr="Mon Apr 29 10:31:00 2024" summary="Nmap done at Mon Apr 29 10:31:00 2024; 1 IP address (1 host up) scanned in 13.37 seconds" elapsed="13.37" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""

def test_parse_nmap_xml_recon_only(nmap_xml_output):
    """Verifica que el parseo extraiga puertos y SO sin severidades."""
    ports, os_info, host_info = parse_nmap_xml(nmap_xml_output)
    
    # 1. Validar puertos
    assert len(ports) == 2
    ssh_port = next(p for p in ports if p.port == 22)
    assert ssh_port.service == "ssh"
    assert ssh_port.version == "OpenSSH 9.6p1 Ubuntu 3ubuntu13.15"
    assert ssh_port.confidence == 0.9
    # IMPORTANTE: No debe haber campo 'severity' ni 'vulnerability'
    assert not hasattr(ssh_port, 'severity')
    
    # 2. Validar SO
    assert os_info is not None
    assert os_info.detected_family == "Linux"
    assert "Linux 5.0" in os_info.detected_version
    assert os_info.confidence == 1.0
    
    # 3. Validar Host Info
    assert host_info.mac_address == "E0:D5:5E:50:27:39"
    assert host_info.vendor == "Giga-byte Technology"
    assert host_info.latency_ms == 0.98

def test_parse_nmap_xml_empty():
    """Verifica manejo de salida vacía."""
    ports, os_info, host_info = parse_nmap_xml("")
    assert len(ports) == 0
    assert os_info is None
    assert host_info is None

@pytest.mark.asyncio
async def test_full_recon_orchestration(nmap_xml_output):
    """Prueba el flujo completo de perform_full_recon."""
    from services.recon_engine.services.scanner_network import perform_full_recon
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from services.recon_engine.models.recon import ReconBase
    
    # Setup DB temporal
    engine = create_engine("sqlite:///:memory:")
    ReconBase.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    
    snapshot_id = "test-snapshot-123"
    target = "10.202.15.100"
    
    with patch('services.recon_engine.services.scanner_network._run_tool', new_callable=AsyncMock) as mock_tool:
        mock_tool.return_value = (nmap_xml_output, "", 0)
        
        result = await perform_full_recon(snapshot_id, target, db)
        
        assert result.snapshot_id == snapshot_id
        assert result.status == "completed"
        assert result.summary.total_ports_open == 2
        assert len(result.reconnaissance.ports_discovered) == 2
        assert result.reconnaissance.os_information.detected_family == "Linux"
        
        # Verificar persistencia
        from services.recon_engine.models.recon import ReconSnapshot, PortDiscoveryDB
        snap_db = db.query(ReconSnapshot).filter_by(snapshot_id=snapshot_id).first()
        assert snap_db is not None
        assert snap_db.reconnaissance_data["ports_discovered"][0]["port"] == 22
        
        ports_db = db.query(PortDiscoveryDB).filter_by(snapshot_id=snapshot_id).all()
        assert len(ports_db) == 2
        
    db.close()
