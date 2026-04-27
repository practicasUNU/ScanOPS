# services/ai_reasoning/tests/test_prioritizer.py

import pytest
from unittest.mock import AsyncMock, MagicMock
from services.ai_reasoning.prioritizer import Prioritizer
from services.ai_reasoning.models import Finding

class TestPrioritizerUnit:
    """Tests unitarios para Prioritizer"""
    
    @pytest.fixture
    def prioritizer(self):
        return Prioritizer()
    
    # TEST 1: Prioridad alta (Fórmula local)
    @pytest.mark.asyncio
    async def test_prioritize_local_high(self, prioritizer):
        """Test: Prioridad alta con lógica local (fallback)"""
        finding = Finding(
            scan_id="s1", asset_id=1, finding_id="f1",
            title="SQL", description="High risk",
            severity="CRITICAL", cvss=9.5, cwe="CWE-89",
            detected_at="2024-04-24T10:30:00Z", scanner="nuclei"
        )
        # Contexto: Activo crítico en Internet
        context = {"criticidad": "CRITICO", "exposure": "INTERNET"}
        
        result = await prioritizer.prioritize(finding, context)
        
        # Fórmula local: 1.0 (crit) * 9.5 (cvss) * 1.5 (exp) = 14.25
        assert result["prioridad_real"] == 14.25
        assert result["accion_recomendada"] == "explotar_inmediato"
    
    # TEST 2: Prioridad baja (Fórmula local)
    @pytest.mark.asyncio
    async def test_prioritize_local_low(self, prioritizer):
        """Test: Prioridad baja con lógica local"""
        finding = Finding(
            scan_id="s1", asset_id=1, finding_id="f2",
            title="Info", description="Low risk",
            severity="LOW", cvss=2.0, cwe="CWE-999",
            detected_at="2024-04-24T10:30:00Z", scanner="zap"
        )
        # Contexto: Activo bajo en red interna
        context = {"criticidad": "BAJO", "exposure": "INTERNAL"}
        
        result = await prioritizer.prioritize(finding, context)
        
        # Fórmula local: 0.2 (crit) * 2.0 (cvss) * 1.0 (exp) = 0.4
        assert result["prioridad_real"] == 0.4
        assert result["accion_recomendada"] == "descartar"

    # TEST 3: Prioridad con IA Experta
    @pytest.mark.asyncio
    async def test_prioritize_expert_ai(self):
        """Test: Priorización usando IA Experta"""
        mock_ollama = MagicMock()
        mock_ollama.is_available = AsyncMock(return_value=True)
        mock_ollama.analyze = AsyncMock(
            return_value='{"prioridad_real": 9.2, "cvss_ajustado": 8.5, "factor_exposicion": 1.2, "accion_recomendada": "explotar_inmediato", "justificacion": "Alta criticidad detectada"}'
        )
        
        p = Prioritizer(ollama_client=mock_ollama)
        finding = Finding(
            scan_id="s1", asset_id=1, finding_id="f3",
            title="SQL", description="Public", severity="HIGH", cvss=8.0,
            detected_at="2024-04-24T10:30:00Z", scanner="nuclei"
        )
        
        result = await p.prioritize(finding, {"criticidad": "ALTO"})
        
        assert result["prioridad_real"] == 9.2
        assert result["accion_recomendada"] == "explotar_inmediato"
    
    # TEST 4: Ranking ordenado
    @pytest.mark.asyncio
    async def test_rank_findings_ordered(self, prioritizer):
        """Test: Hallazgos ordenados por prioridad real"""
        findings = [
            Finding(scan_id="s1", asset_id=1, finding_id="f1", title="A",
                   description="Low", severity="LOW", cvss=2.0, cwe="CWE-200",
                   detected_at="2024-04-24T10:30:00Z", scanner="zap"),
            Finding(scan_id="s1", asset_id=1, finding_id="f2", title="B",
                   description="High", severity="HIGH", cvss=9.0, cwe="CWE-89",
                   detected_at="2024-04-24T10:30:00Z", scanner="nuclei"),
        ]
        # Forzamos contextos diferentes
        contexts = {
            "f1": {"criticidad": "BAJO", "exposure": "INTERNAL"},  # 0.4
            "f2": {"criticidad": "CRITICO", "exposure": "INTERNET"} # 13.5
        }
        
        results = await prioritizer.rank_findings(findings, contexts)
        
        assert results[0]["finding_id"] == "f2"
        assert results[0]["rank"] == 1
        assert results[1]["finding_id"] == "f1"
        assert results[1]["rank"] == 2


class TestPrioritizerIntegration:
    """Tests E2E"""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_prioritize_real_ollama(self):
        """Test: Priorización con Ollama real"""
        from services.ai_reasoning.ollama_client import ollama
        
        if not await ollama.is_available():
            pytest.skip("Ollama not available")
            
        p = Prioritizer(ollama_client=ollama)
        finding = Finding(
            scan_id="test",
            asset_id=999,
            finding_id="test_f_001",
            title="Remote Code Execution",
            description="Critical vulnerability in production server",
            severity="CRITICAL",
            cvss=10.0,
            cwe="CWE-94",
            detected_at="2024-04-24T10:30:00Z",
            scanner="nuclei"
        )
        
        context = {
            "hostname": "prod-db-01",
            "criticidad": "CRITICO",
            "exposure": "INTERNAL"
        }
        
        result = await p.prioritize(finding, context)
        
        assert "prioridad_real" in result
        assert "accion_recomendada" in result
        assert result["prioridad_real"] > 5.0
