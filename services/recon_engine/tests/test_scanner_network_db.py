"""
Tests de persistencia DB para M2 Recon Engine
=============================================
Valida que el nuevo schema ReconSnapshot (JSON) persista correctamente.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from services.recon_engine.models.recon import ReconBase, ReconSnapshot, PortDiscoveryDB

@pytest.fixture
def db_session():
    """Sesión de base de datos en memoria para tests."""
    engine = create_engine("sqlite:///:memory:")
    ReconBase.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_persist_recon_snapshot_with_json(db_session):
    """Prueba que el campo reconnaissance_data persiste y se recupera bien."""
    snapshot_id = "snap-test-json"
    recon_data = {
        "ports_discovered": [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache"}
        ],
        "os_information": {"detected_family": "Linux", "detected_version": "5.4", "cpe": "cpe:/o:linux", "confidence": 0.9}
    }
    
    snapshot = ReconSnapshot(
        snapshot_id=snapshot_id,
        target="10.1.1.1",
        status="completed",
        reconnaissance_data=recon_data
    )
    db_session.add(snapshot)
    db_session.commit()
    
    # Recuperar
    saved = db_session.query(ReconSnapshot).filter_by(snapshot_id=snapshot_id).first()
    assert saved.reconnaissance_data["ports_discovered"][0]["port"] == 80
    assert saved.reconnaissance_data["os_information"]["detected_family"] == "Linux"

def test_persist_individual_ports(db_session):
    """Prueba que los puertos se guardan en su propia tabla para indexación."""
    snapshot_id = "snap-test-ports"
    port1 = PortDiscoveryDB(snapshot_id=snapshot_id, port=22, service="ssh", state="open")
    port2 = PortDiscoveryDB(snapshot_id=snapshot_id, port=443, service="https", state="open")
    
    db_session.add(port1)
    db_session.add(port2)
    db_session.commit()
    
    ports = db_session.query(PortDiscoveryDB).filter_by(snapshot_id=snapshot_id).all()
    assert len(ports) == 2
    assert {p.port for p in ports} == {22, 443}