"""
Tests for Scanner Network with Database Persistence
==================================================
Integration tests for scanner_network with database operations.
"""

import pytest
import asyncio
import os
import sys
from unittest.mock import patch, AsyncMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from models.recon import Base, ReconSnapshot, ReconFinding, ReconSubdomain
from modules.scanner_network import scan, persist_findings_to_db


@pytest.fixture
def test_db():
    """Create in-memory test database."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


class TestScannerNetworkIntegration:
    """Integration tests for scanner_network with database."""

    @pytest.mark.asyncio
    async def test_scan_creates_snapshot_and_findings(self, test_db):
        """Test that scan creates snapshot and persists findings."""
        # Mock the external tools
        with patch('modules.scanner_network.run_masscan', new_callable=AsyncMock) as mock_masscan, \
             patch('modules.scanner_network.run_subfinder', new_callable=AsyncMock) as mock_subfinder, \
             patch('modules.scanner_network.run_nmap', new_callable=AsyncMock) as mock_nmap:

            # Mock outputs
            mock_masscan.return_value = "Discovered open port 22/tcp on 10.202.15.100\nDiscovered open port 80/tcp on 10.202.15.100"
            mock_subfinder.return_value = "subdomain.example.com\napi.example.com"
            mock_nmap.return_value = """
Nmap scan report for 10.202.15.100
22/tcp open  ssh     OpenSSH 8.2p1
80/tcp open  http    Apache httpd 2.4.41
"""

            # Mock database session in scanner_network
            with patch('modules.scanner_network.SessionLocal', return_value=test_db), \
                 patch('modules.scanner_network.create_tables'):

                # Run scan
                result = await scan("2026-W17")

                # Verify result structure
                assert "cycle_id" in result
                assert result["cycle_id"] == "2026-W17"
                assert "surface_changes" in result
                assert "hallazgos" in result

                # Verify database state
                snapshots = test_db.query(ReconSnapshot).all()
                assert len(snapshots) == 1
                snapshot = snapshots[0]
                assert snapshot.cycle_id == "2026-W17"
                assert snapshot.status == "completed"
                assert snapshot.finished_at is not None

                # Verify findings
                findings = test_db.query(ReconFinding).filter(ReconFinding.snapshot_id == snapshot.id).all()
                assert len(findings) > 0

                # Check for specific findings
                ssh_finding = next((f for f in findings if f.port == "22/tcp"), None)
                assert ssh_finding is not None
                assert ssh_finding.service == "ssh"
                assert ssh_finding.state == "open"

                http_finding = next((f for f in findings if f.port == "80/tcp"), None)
                assert http_finding is not None
                assert http_finding.service == "http"

                # Verify subdomains
                subdomains = test_db.query(ReconSubdomain).filter(ReconSubdomain.snapshot_id == snapshot.id).all()
                assert len(subdomains) == 2
                subdomain_names = {sd.subdomain for sd in subdomains}
                assert "subdomain.example.com" in subdomain_names
                assert "api.example.com" in subdomain_names

    @pytest.mark.asyncio
    async def test_persist_findings_to_db(self, test_db):
        """Test the persist_findings_to_db function directly."""
        # Create snapshot
        snapshot = ReconSnapshot(cycle_id="2026-W17", target="10.202.15.0/24", status="running")
        test_db.add(snapshot)
        test_db.commit()

        # Mock hallazgos data
        hallazgos = [
            {
                "host": "10.202.15.100",
                "puerto": "22/tcp",
                "servicio": "ssh",
                "estado": "open",
                "severidad": "INFO"
            },
            {
                "host": "10.202.15.100",
                "puerto": "80/tcp",
                "servicio": "http",
                "estado": "open",
                "severidad": "INFO"
            }
        ]

        # Mock masscan hosts
        masscan_hosts = {
            "10.202.15.100": {"22/tcp", "80/tcp", "443/tcp"}  # 443 not in hallazgos
        }

        # Mock subfinder domains
        subfinder_domains = ["test.example.com"]

        # Persist findings
        await persist_findings_to_db(snapshot.id, hallazgos, masscan_hosts, subfinder_domains, test_db)

        # Verify findings
        findings = test_db.query(ReconFinding).filter(ReconFinding.snapshot_id == snapshot.id).all()

        # Should have findings from hallazgos + extra from masscan
        assert len(findings) >= 3  # At least 22, 80 from hallazgos, 443 from masscan

        # Check specific findings
        ports = {f.port for f in findings if f.port}
        assert "22/tcp" in ports
        assert "80/tcp" in ports
        assert "443/tcp" in ports

        # Verify subdomains
        subdomains = test_db.query(ReconSubdomain).filter(ReconSubdomain.snapshot_id == snapshot.id).all()
        assert len(subdomains) == 1
        assert subdomains[0].subdomain == "test.example.com"

    def test_scan_handles_database_error(self, test_db):
        """Test that scan handles database errors gracefully."""
        # Mock database failure
        with patch('modules.scanner_network.SessionLocal', side_effect=Exception("DB Error")), \
             patch('modules.scanner_network.create_tables'):

            with pytest.raises(Exception):
                asyncio.run(scan("2026-W17"))