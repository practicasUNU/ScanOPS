# services/ai_reasoning/tests/test_report_generator.py

import pytest
from services.ai_reasoning.report_generator import ReportGenerator

class TestReportGeneratorUnit:
    """Tests unitarios"""
    
    @pytest.fixture
    def generator(self):
        return ReportGenerator()
    
    @pytest.fixture
    def sample_findings(self):
        return [
            {
                "finding_id": "f1",
                "title": "SQL Injection",
                "description": "Direct DB access",
                "severity": "CRITICAL",
                "cvss": 9.2,
                "cwe": "CWE-89",
                "risk_level": "CRITICAL",
                "priority_score": 8.5,
                "ens_articles": ["Art. 5.1.6", "Art. 5.2.1"]
            },
            {
                "finding_id": "f2",
                "title": "XSS",
                "description": "Unescaped output",
                "severity": "HIGH",
                "cvss": 7.5,
                "cwe": "CWE-79",
                "risk_level": "HIGH",
                "priority_score": 6.8,
                "ens_articles": ["Art. 5.1.6", "Art. 6.1.1"]
            },
        ]
    
    def test_generate_html(self, generator, sample_findings):
        """Test: Generar HTML"""
        html = generator.generate_html(
            sample_findings,
            "scan_test_001",
            "2024-04-24T10:30:00Z"
        )
        
        assert "scan_test_001" in html
        assert "SQL Injection" in html
        assert "Executive Summary" in html
    
    def test_html_contains_findings(self, generator, sample_findings):
        """Test: HTML contiene hallazgos"""
        html = generator.generate_html(sample_findings, "scan_1", "2024-04-24T10:30:00Z")
        
        assert "SQL Injection" in html
        assert "XSS" in html
        assert "CRITICAL" in html
    
    def test_html_contains_risk_levels(self, generator, sample_findings):
        """Test: HTML contiene niveles de riesgo"""
        html = generator.generate_html(sample_findings, "scan_1", "2024-04-24T10:30:00Z")
        
        assert "CRITICAL" in html
        assert "HIGH" in html
    
    def test_html_contains_ens_articles(self, generator, sample_findings):
        """Test: HTML contiene artículos RD 311"""
        html = generator.generate_html(sample_findings, "scan_1", "2024-04-24T10:30:00Z")
        
        assert "Art. 5.1.6" in html
        assert "Art. 5.2.1" in html
    
    def test_summarize_ens_articles(self, generator, sample_findings):
        """Test: Resumir artículos ENS"""
        summary = generator._summarize_ens_articles(sample_findings)
        
        assert summary["Art. 5.1.6"] == 2  # Aparece en 2 hallazgos
        assert summary["Art. 5.2.1"] == 1
        assert summary["Art. 6.1.1"] == 1
    
    def test_save_html(self, generator, sample_findings, tmp_path):
        """Test: Guardar HTML a archivo"""
        html = generator.generate_html(sample_findings, "scan_1", "2024-04-24T10:30:00Z")
        
        filepath = tmp_path / "report.html"
        result = generator.save_html(html, str(filepath))
        
        assert result is True
        assert filepath.exists()
    
    def test_html_summary_stats(self, generator, sample_findings):
        """Test: Estadísticas en resumen"""
        html = generator.generate_html(sample_findings, "scan_1", "2024-04-24T10:30:00Z")
        
        assert "Total Findings:" in html
        assert "2" in html
        assert "CRITICAL: 1" in html
        assert "HIGH: 1" in html


class TestReportGeneratorIntegration:
    """Tests E2E"""
    
    @pytest.mark.integration
    def test_generate_full_report(self, tmp_path):
        """Test: Generar informe completo"""
        generator = ReportGenerator()
        
        findings = [
            {
                "finding_id": "f1",
                "title": "SQL Injection",
                "description": "Test",
                "cvss": 9.0,
                "cwe": "CWE-89",
                "risk_level": "CRITICAL",
                "priority_score": 8.5,
                "ens_articles": ["Art. 5.1.6"]
            }
        ]
        
        html = generator.generate_html(findings, "scan_001", "2024-04-24T10:30:00Z")
        html_path = tmp_path / "report.html"
        
        result = generator.save_html(html, str(html_path))
        
        assert result is True
        assert html_path.exists()
        assert len(html) > 1000  # Debe tener contenido significativo

    @pytest.mark.asyncio
    async def test_generate_preliminary_report_ai(self):
        """Test: Generación de informe ejecutivo con IA"""
        from unittest.mock import AsyncMock, patch
        from services.ai_reasoning.report_generator import ReportGenerator
        
        rg = ReportGenerator()
        hallazgos = [
            {
                "cve": "CVE-2021-44228",
                "hostname": "prod-web-01",
                "prioridad_real": 9.5,
                "accion_recomendada": "explotar_inmediato",
                "medida_principal": "mp.info.3"
            }
        ]
        activos = [{"hostname": "prod-web-01"}]
        
        with patch("services.ai_reasoning.report_generator.ollama") as mock_ollama:
            mock_ollama.analyze = AsyncMock(return_value="INFORME EJECUTIVO: Todo bajo control.")
            
            report = await rg.generate_preliminary_report(hallazgos, activos, "2024-04-25", "2024-04-27")
            
            assert "INFORME EJECUTIVO" in report
            mock_ollama.analyze.assert_called_once()
