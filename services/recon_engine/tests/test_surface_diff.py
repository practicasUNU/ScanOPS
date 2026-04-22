"""
Tests for Surface Diff functionality
===================================
Unit and integration tests for surface comparison logic.
"""

import pytest
import os
import sys
from unittest.mock import Mock

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from services.recon_engine.models.recon import Base, ReconSnapshot, ReconFinding, ReconSubdomain
from services.recon_engine.services.surface_diff import (
    compare_snapshots, get_previous_snapshot_id,
    classify_change_severity, get_findings_set
)


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


class TestSurfaceDiff:
    """Unit tests for surface diff logic."""

    def test_detecta_nuevo_puerto(self, test_db):
        """Test detection of new open port."""
        # Create snapshots
        current_snapshot = ReconSnapshot(cycle_id="2026-W17", target="10.202.15.0/24", status="completed")
        previous_snapshot = ReconSnapshot(cycle_id="2026-W16", target="10.202.15.0/24", status="completed")
        test_db.add_all([current_snapshot, previous_snapshot])
        test_db.commit()

        # Add findings
        previous_finding = ReconFinding(
            snapshot_id=previous_snapshot.id,
            host="10.0.0.1",
            port="22/tcp",
            state="open",
            source="nmap"
        )
        current_findings = [
            ReconFinding(
                snapshot_id=current_snapshot.id,
                host="10.0.0.1",
                port="22/tcp",
                state="open",
                source="nmap"
            ),
            ReconFinding(
                snapshot_id=current_snapshot.id,
                host="10.0.0.1",
                port="8080/tcp",
                state="open",
                source="nmap"
            )
        ]
        test_db.add(previous_finding)
        test_db.add_all(current_findings)
        test_db.commit()

        # Compare
        changes = compare_snapshots(current_snapshot.id, previous_snapshot.id, test_db)

        assert changes["has_changes"] is True
        assert len(changes["new_ports"]) == 1
        assert changes["new_ports"][0]["port"] == "8080/tcp"
        assert changes["summary"]["new_ports"] == 1
        assert changes["summary"]["total_changes"] == 1

    def test_detecta_puerto_cerrado(self, test_db):
        """Test detection of closed port."""
        # Create snapshots
        current_snapshot = ReconSnapshot(cycle_id="2026-W17", target="10.202.15.0/24", status="completed")
        previous_snapshot = ReconSnapshot(cycle_id="2026-W16", target="10.202.15.0/24", status="completed")
        test_db.add_all([current_snapshot, previous_snapshot])
        test_db.commit()

        # Add findings - only previous has the port
        previous_finding = ReconFinding(
            snapshot_id=previous_snapshot.id,
            host="10.0.0.1",
            port="8080/tcp",
            state="open",
            source="nmap"
        )
        current_finding = ReconFinding(
            snapshot_id=current_snapshot.id,
            host="10.0.0.1",
            port="22/tcp",
            state="open",
            source="nmap"
        )
        test_db.add(previous_finding)
        test_db.add(current_finding)
        test_db.commit()

        # Compare
        changes = compare_snapshots(current_snapshot.id, previous_snapshot.id, test_db)

        assert changes["has_changes"] is True
        assert len(changes["closed_ports"]) == 1
        assert changes["closed_ports"][0]["port"] == "8080/tcp"
        assert changes["summary"]["closed_ports"] == 1

    def test_detecta_cambio_servicio(self, test_db):
        """Test detection of service change."""
        # Create snapshots
        current_snapshot = ReconSnapshot(cycle_id="2026-W17", target="10.202.15.0/24", status="completed")
        previous_snapshot = ReconSnapshot(cycle_id="2026-W16", target="10.202.15.0/24", status="completed")
        test_db.add_all([current_snapshot, previous_snapshot])
        test_db.commit()

        # Add findings with different services
        previous_finding = ReconFinding(
            snapshot_id=previous_snapshot.id,
            host="10.0.0.1",
            port="80/tcp",
            service="http",
            state="open",
            source="nmap"
        )
        current_finding = ReconFinding(
            snapshot_id=current_snapshot.id,
            host="10.0.0.1",
            port="80/tcp",
            service="nginx",
            state="open",
            source="nmap"
        )
        test_db.add(previous_finding)
        test_db.add(current_finding)
        test_db.commit()

        # Compare
        changes = compare_snapshots(current_snapshot.id, previous_snapshot.id, test_db)

        assert changes["has_changes"] is True
        assert len(changes["service_changes"]) == 1
        assert changes["service_changes"][0]["old_service"] == "http"
        assert changes["service_changes"][0]["new_service"] == "nginx"
        assert changes["summary"]["service_changes"] == 1

    def test_detecta_nuevo_host(self, test_db):
        """Test detection of new host."""
        # Create snapshots
        current_snapshot = ReconSnapshot(cycle_id="2026-W17", target="10.202.15.0/24", status="completed")
        previous_snapshot = ReconSnapshot(cycle_id="2026-W16", target="10.202.15.0/24", status="completed")
        test_db.add_all([current_snapshot, previous_snapshot])
        test_db.commit()

        # Add findings - current has an extra host
        previous_finding = ReconFinding(
            snapshot_id=previous_snapshot.id,
            host="10.0.0.1",
            source="discovery"
        )
        current_findings = [
            ReconFinding(
                snapshot_id=current_snapshot.id,
                host="10.0.0.1",
                source="discovery"
            ),
            ReconFinding(
                snapshot_id=current_snapshot.id,
                host="10.0.0.2",
                source="discovery"
            )
        ]
        test_db.add(previous_finding)
        test_db.add_all(current_findings)
        test_db.commit()

        # Compare
        changes = compare_snapshots(current_snapshot.id, previous_snapshot.id, test_db)

        assert changes["has_changes"] is True
        assert len(changes["new_hosts"]) == 1
        assert changes["new_hosts"][0]["host"] == "10.0.0.2"
        assert changes["summary"]["new_hosts"] == 1

    def test_primer_ciclo_sin_anterior(self, test_db):
        """Test first cycle with no previous snapshot."""
        # Create current snapshot only
        current_snapshot = ReconSnapshot(cycle_id="2026-W17", target="10.202.15.0/24", status="completed")
        test_db.add(current_snapshot)
        test_db.commit()

        # Add findings
        current_finding = ReconFinding(
            snapshot_id=current_snapshot.id,
            host="10.0.0.1",
            port="22/tcp",
            state="open",
            source="nmap"
        )
        test_db.add(current_finding)
        test_db.commit()

        # Compare (no previous)
        changes = compare_snapshots(current_snapshot.id, None, test_db)

        assert changes["is_baseline"] is True
        assert changes["has_changes"] is False

    def test_ciclos_identicos_sin_cambios(self, test_db):
        """Test identical cycles with no changes."""
        # Create snapshots
        current_snapshot = ReconSnapshot(cycle_id="2026-W17", target="10.202.15.0/24", status="completed")
        previous_snapshot = ReconSnapshot(cycle_id="2026-W16", target="10.202.15.0/24", status="completed")
        test_db.add_all([current_snapshot, previous_snapshot])
        test_db.commit()

        # Add identical findings
        findings_data = [
            {"host": "10.0.0.1", "port": "22/tcp", "state": "open", "service": "ssh"},
            {"host": "10.0.0.1", "port": "80/tcp", "state": "open", "service": "http"}
        ]

        for data in findings_data:
            prev_finding = ReconFinding(snapshot_id=previous_snapshot.id, **data)
            curr_finding = ReconFinding(snapshot_id=current_snapshot.id, **data)
            test_db.add(prev_finding)
            test_db.add(curr_finding)

        test_db.commit()

        # Compare
        changes = compare_snapshots(current_snapshot.id, previous_snapshot.id, test_db)

        assert changes["has_changes"] is False
        assert changes["summary"]["total_changes"] == 0

    def test_clasificacion_severidad(self):
        """Test severity classification."""
        # Test new port on critical asset
        severity = classify_change_severity("new_port", "10.202.15.100", state="open")  # Alta criticidad
        assert severity == "CRITICA"

        # Test new port on low criticality asset
        severity = classify_change_severity("new_port", "unknown.host", state="open")
        assert severity == "ALTA"

        # Test new host
        severity = classify_change_severity("new_host", "10.0.0.1")
        assert severity == "CRITICA"

        # Test service change
        severity = classify_change_severity("service_change", "10.0.0.1")
        assert severity == "MEDIA"

        # Test closed port (security improvement)
        severity = classify_change_severity("closed_port", "10.0.0.1")
        assert severity == "INFO"


class TestIntegration:
    """Integration tests with full database operations."""

    def test_snapshot_creation_and_comparison(self, test_db):
        """Test full snapshot creation and comparison workflow."""
        # Create two snapshots
        snapshot1 = ReconSnapshot(cycle_id="2026-W16", target="10.202.15.0/24", status="completed")
        snapshot2 = ReconSnapshot(cycle_id="2026-W17", target="10.202.15.0/24", status="completed")
        test_db.add_all([snapshot1, snapshot2])
        test_db.commit()

        # Add findings for snapshot1
        findings1 = [
            ReconFinding(snapshot_id=snapshot1.id, host="10.0.0.1", port="22/tcp", state="open", service="ssh"),
            ReconFinding(snapshot_id=snapshot1.id, host="10.0.0.1", port="80/tcp", state="open", service="http"),
        ]

        # Add findings for snapshot2 (with changes)
        findings2 = [
            ReconFinding(snapshot_id=snapshot2.id, host="10.0.0.1", port="22/tcp", state="open", service="ssh"),
            ReconFinding(snapshot_id=snapshot2.id, host="10.0.0.1", port="80/tcp", state="open", service="http"),
            ReconFinding(snapshot_id=snapshot2.id, host="10.0.0.1", port="443/tcp", state="open", service="https"),  # New port
            ReconFinding(snapshot_id=snapshot2.id, host="10.0.0.2", source="discovery"),  # New host
        ]

        test_db.add_all(findings1 + findings2)
        test_db.commit()

        # Test get_previous_snapshot_id
        prev_id = get_previous_snapshot_id("2026-W17", test_db)
        assert prev_id == snapshot1.id

        # Test comparison
        changes = compare_snapshots(snapshot2.id, snapshot1.id, test_db)

        assert changes["has_changes"] is True
        assert changes["summary"]["new_ports"] == 1
        assert changes["summary"]["new_hosts"] == 1
        assert changes["summary"]["total_changes"] == 2

        # Verify details
        assert len(changes["details"]) == 2
        change_types = {detail["type"] for detail in changes["details"]}
        assert "new_port" in change_types
        assert "new_host" in change_types