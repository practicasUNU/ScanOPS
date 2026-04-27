# services/ai_reasoning/tests/test_rag_engine.py

import pytest
from unittest.mock import AsyncMock, MagicMock
from services.ai_reasoning.rag_engine import RAGEngine
from services.ai_reasoning.models import ENSMappingResult

class TestRAGEngineUnit:
    """Tests unitarios"""
    
    @pytest.fixture
    def rag_engine(self):
        mock_ollama = MagicMock()
        mock_ollama.is_available = AsyncMock(return_value=False)
        return RAGEngine(ollama_client=mock_ollama)
    
    @pytest.mark.asyncio
    async def test_map_by_cwe_sql_injection(self, rag_engine):
        """Test: SQL Injection mapea a Art. 5.1.6"""
        finding = {
            "finding_id": "f1",
            "title": "SQL Injection",
            "cwe": "CWE-89"
        }
        result = await rag_engine.map_to_ens(finding)
        
        assert "Art. 5.1.6" in result["ens_articles"]
        assert "Art. 5.2.1" in result["ens_articles"]
    
    @pytest.mark.asyncio
    async def test_map_by_cwe_xss(self, rag_engine):
        """Test: XSS mapea a Art. 5.1.6 y 6.1.1"""
        finding = {
            "finding_id": "f2",
            "title": "XSS",
            "cwe": "CWE-79"
        }
        result = await rag_engine.map_to_ens(finding)
        
        assert "Art. 5.1.6" in result["ens_articles"]
        assert "Art. 6.1.1" in result["ens_articles"]
    
    @pytest.mark.asyncio
    async def test_map_by_cwe_unknown(self, rag_engine):
        """Test: CWE desconocido retorna []"""
        finding = {
            "finding_id": "f3",
            "title": "Unknown",
            "cwe": "CWE-9999"
        }
        result = await rag_engine.map_to_ens(finding)
        
        assert result["ens_articles"] == [] or len(result["ens_articles"]) == 0
    
    @pytest.mark.asyncio
    async def test_map_with_ai_available(self, rag_engine):
        """Test: Mapeo con IA cuando Ollama disponible"""
        finding = {
            "finding_id": "f4",
            "title": "SQL Injection",
            "description": "Direct DB access",
            "severity": "HIGH",
            "cvss": 8.5,
            "cwe": "CWE-89"
        }
        
        rag_engine.ollama_client.is_available = AsyncMock(return_value=True)
        rag_engine.ollama_client.analyze = AsyncMock(
            return_value="Art. 5.1.6, Art. 6.2.1"
        )
        
        result = await rag_engine.map_to_ens(finding)
        
        assert len(result["ens_articles"]) > 0
        assert "ai_analysis" in result["mapped_by"]
    
    @pytest.mark.asyncio
    async def test_map_with_ai_unavailable(self, rag_engine):
        """Test: Fallback a CWE cuando Ollama no disponible"""
        finding = {
            "finding_id": "f5",
            "title": "SQL Injection",
            "cwe": "CWE-89"
        }
        
        rag_engine.ollama_client.is_available = AsyncMock(return_value=False)
        
        result = await rag_engine.map_to_ens(finding)
        
        assert "cwe_mapping" in result["mapped_by"]
        assert "ai_analysis" not in result["mapped_by"]
    
    def test_risk_level_critical(self, rag_engine):
        """Test: CVSS >= 9.0 = CRITICAL"""
        finding = {"cvss": 9.2}
        result = rag_engine._calculate_risk_level(finding, [])
        assert result == "CRITICAL"
    
    def test_risk_level_high(self, rag_engine):
        """Test: 7.0 <= CVSS < 9.0 = HIGH"""
        finding = {"cvss": 8.0}
        result = rag_engine._calculate_risk_level(finding, [])
        assert result == "HIGH"
    
    @pytest.mark.asyncio
    async def test_map_batch(self, rag_engine):
        """Test: Mapear batch de hallazgos"""
        findings = [
            {"finding_id": "f1", "title": "SQL", "cwe": "CWE-89"},
            {"finding_id": "f2", "title": "XSS", "cwe": "CWE-79"},
        ]
        
        rag_engine.ollama_client.is_available = AsyncMock(return_value=False)
        
        results = await rag_engine.map_batch(findings)
        
        assert len(results) == 2
        assert results[0]["finding_id"] == "f1"
        assert results[1]["finding_id"] == "f2"


class TestRAGEngineIntegration:
    """Tests E2E"""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_map_with_real_ollama(self):
        """Test: Mapeo con Ollama real"""
        from services.ai_reasoning.ollama_client import ollama
        
        if not await ollama.is_available():
            pytest.skip("Ollama not available")
        
        rag_engine = RAGEngine(ollama_client=ollama)
        
        finding = {
            "finding_id": "test_f1",
            "title": "SQL Injection",
            "description": "Parameter without validation",
            "severity": "HIGH",
            "cvss": 8.5,
            "cwe": "CWE-89"
        }
        
        result = await rag_engine.map_to_ens(finding)
        
        assert len(result["ens_articles"]) > 0
        assert result["compliance_status"] in ["COMPLIANT", "NOT_COMPLIANT", "UNKNOWN"]
        assert result["risk_level"] == "HIGH"
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_map_batch_realistic(self):
        """Test: Batch realista con Ollama"""
        from services.ai_reasoning.ollama_client import ollama
        
        if not await ollama.is_available():
            pytest.skip("Ollama not available")
        
        rag_engine = RAGEngine(ollama_client=ollama)
        
        findings = [
            {
                "finding_id": "f1", "title": "SQL Injection",
                "description": "Direct SQL in query", "cvss": 9.0, "cwe": "CWE-89"
            },
            {
                "finding_id": "f2", "title": "XSS",
                "description": "Unescaped output", "cvss": 7.5, "cwe": "CWE-79"
            },
        ]
        
        results = await rag_engine.map_batch(findings)
        
        assert len(results) == 2
        assert all(r["ens_articles"] for r in results)
