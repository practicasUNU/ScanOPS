import pytest
import io
import json
from unittest.mock import MagicMock, patch
from services.scanner_engine.services.export_results import (
    export_to_json,
    export_to_csv,
    export_to_pdf
)
from services.scanner_engine.models.vulnerability import VulnFinding

@pytest.fixture
def mock_db():
    db = MagicMock()
    # Simulamos un hallazgo en la BD
    finding = VulnFinding(
        id=1,
        asset_id=10,
        scan_id="scan_1",
        vulnerability_id="CVE-2024-1234",
        title="Test Vulnerability",
        severity="HIGH",
        description="This is a test",
        scanner_name="Nuclei",
        remediation_status="open"
    )
    db.query.return_value.filter.return_value.all.return_value = [finding]
    # Caso para cuando se filtra por scan_id
    db.query.return_value.filter.return_value.filter.return_value.all.return_value = [finding]
    return db

def test_export_to_json_format(mock_db):
    """Verificar que la exportación JSON es válida y contiene los campos."""
    result = export_to_json(mock_db, 10)
    data = json.loads(result)
    
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["title"] == "Test Vulnerability"
    assert data[0]["severity"] == "HIGH"

def test_export_to_csv_content(mock_db):
    """Verificar que el CSV tiene los headers y datos correctos."""
    output_io = export_to_csv(mock_db, 10)
    content = output_io.getvalue()
    
    assert "Vulnerability,Severity,CVE/ID,Scanner,Description,Status" in content
    assert "Test Vulnerability,HIGH,CVE-2024-1234,Nuclei" in content

def test_export_to_pdf_generation(mock_db):
    """Verificar que se genera un stream de bytes para el PDF."""
    # Como reportlab genera binario, verificamos que no falle y retorne un buffer con datos
    pdf_buffer = export_to_pdf(mock_db, 10)
    
    assert isinstance(pdf_buffer, io.BytesIO)
    content = pdf_buffer.getvalue()
    assert len(content) > 0
    # Los PDFs empiezan con %PDF
    assert content.startswith(b"%PDF")

def test_export_empty_results(mock_db):
    """Verificar comportamiento con resultados vacíos."""
    mock_db.query.return_value.filter.return_value.all.return_value = []
    
    json_result = export_to_json(mock_db, 10)
    assert json_result == "[]"
    
    csv_result = export_to_csv(mock_db, 10).getvalue()
    # Solo los headers
    assert len(csv_result.strip().split("\n")) == 1
