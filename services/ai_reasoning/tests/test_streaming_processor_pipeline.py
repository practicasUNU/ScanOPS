# services/ai_reasoning/tests/test_streaming_processor_pipeline.py

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from services.ai_reasoning.streaming_processor import StreamingProcessor
from services.ai_reasoning.models import Finding, AIAnalysis, ProcessingResult, FilterResult

@pytest.fixture
def mock_ollama():
    mock = MagicMock()
    mock.is_available = AsyncMock(return_value=True)
    return mock

@pytest.fixture
def processor(mock_ollama):
    return StreamingProcessor(ollama_client=mock_ollama)

class TestStreamingProcessorPipeline:
    """Tests para el pipeline integrado de StreamingProcessor (US-4.2)"""

    @pytest.mark.asyncio
    async def test_process_finding_success(self, processor):
        """Test: Pipeline completo exitoso"""
        finding_data = {
            "scan_id": "scan_123",
            "asset_id": 1,
            "finding_id": "f_real",
            "title": "SQL Injection",
            "description": "Critical SQLi",
            "severity": "HIGH",
            "cvss": 9.0,
            "cwe": "CWE-89",
            "detected_at": "2024-04-24T10:30:00Z",
            "scanner": "nuclei",
            "asset_context": {"criticidad": "ALTO", "exposure": "INTERNET"}
        }

        # Mock Step 1: Filter
        mock_filter_res = FilterResult(
            finding_id="f_real", is_false_positive=False, 
            confidence=0.9, reason="Confirmed", filter_method="expert", status="passed"
        )
        
        # Mock Step 2: Prioritizer
        mock_prio_res = {
            "prioridad_real": 9.5,
            "accion_recomendada": "explotar_inmediato",
            "justificacion": "Alta criticidad"
        }

        # Mock Step 3: ENS Mapper
        mock_ens_res = {"medidas_ens": ["mp.info.3"], "medida_principal": "mp.info.3"}

        with patch("services.ai_reasoning.streaming_processor.FalsePositiveFilter.filter", AsyncMock(return_value=mock_filter_res)), \
             patch("services.ai_reasoning.streaming_processor.Prioritizer.prioritize", AsyncMock(return_value=mock_prio_res)), \
             patch("services.ai_reasoning.streaming_processor.map_to_ens", AsyncMock(return_value=mock_ens_res)), \
             patch("services.ai_reasoning.streaming_processor.celery_app.send_task") as mock_celery:

            result = await processor.process_finding(finding_data)

            assert result.status == "success"
            assert result.analysis.priority_score == 9.5
            assert result.analysis.recommended_action == "explotar_inmediato"
            assert "mp.info.3" in result.analysis.ens_articles
            mock_celery.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_finding_false_positive(self, processor):
        """Test: Pipeline se detiene si es falso positivo"""
        finding_data = {"finding_id": "f_fp", "cvss": 5.0, "title": "Test", "description": "Test", "severity": "MED", "detected_at": "2024", "scanner": "test", "asset_id": 1, "scan_id": "s1"}

        mock_filter_res = FilterResult(
            finding_id="f_fp", is_false_positive=True, 
            confidence=0.95, reason="False service", filter_method="rules", status="rejected"
        )

        with patch("services.ai_reasoning.streaming_processor.FalsePositiveFilter.filter", AsyncMock(return_value=mock_filter_res)), \
             patch("services.ai_reasoning.streaming_processor.Prioritizer.prioritize") as mock_prio:

            result = await processor.process_finding(finding_data)

            assert result.status == "false_positive"
            mock_prio.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_finding_low_priority_skip(self, processor):
        """Test: Pipeline se salta si la prioridad es 'descartar'"""
        finding_data = {"finding_id": "f_low", "cvss": 2.0, "title": "Test", "description": "Test", "severity": "LOW", "detected_at": "2024", "scanner": "test", "asset_id": 1, "scan_id": "s1"}

        mock_filter_res = FilterResult(finding_id="f_low", is_false_positive=False, confidence=0.8, reason="Real but low", filter_method="rules", status="passed")
        mock_prio_res = {"prioridad_real": 1.2, "accion_recomendada": "descartar", "justificacion": "Low risk asset"}

        with patch("services.ai_reasoning.streaming_processor.FalsePositiveFilter.filter", AsyncMock(return_value=mock_filter_res)), \
             patch("services.ai_reasoning.streaming_processor.Prioritizer.prioritize", AsyncMock(return_value=mock_prio_res)), \
             patch("services.ai_reasoning.streaming_processor.map_to_ens") as mock_ens:

            result = await processor.process_finding(finding_data)

            assert result.status == "skipped"
            mock_ens.assert_not_called()
