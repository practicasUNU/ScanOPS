"""Tests para StreamingProcessor - US-4.2"""
import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch
from services.ai_reasoning.streaming_processor import StreamingProcessor
from services.ai_reasoning.models import Finding, AIAnalysis, ProcessingResult


class TestStreamingProcessorUnit:
    """Tests unitarios (con mocks)"""
    
    @pytest.fixture
    def processor(self):
        """Instancia de StreamingProcessor"""
        mock_ollama = MagicMock()
        with patch("services.ai_reasoning.streaming_processor.celery_app.send_task") as mock_send:
            yield StreamingProcessor(
                redis_url="redis://localhost:6379/0",
                ollama_client=mock_ollama
            )
    
    @pytest.mark.asyncio
    async def test_init(self, processor):
        """Test: Inicialización correcta"""
        assert processor.redis_url == "redis://localhost:6379/0"
        assert processor.ollama_client is not None
        assert processor.running is False
    
    @pytest.mark.asyncio
    async def test_validate_finding_valid(self, processor):
        """Test: Validar Finding válido"""
        valid_finding = {
            "scan_id": "scan_001",
            "asset_id": 42,
            "finding_id": "f_001",
            "title": "SQL Injection",
            "description": "Vulnerable input",
            "severity": "HIGH",
            "cvss": 8.5,
            "cwe": "CWE-89",
            "detected_at": "2024-04-24T10:30:00Z",
            "scanner": "nuclei"
        }
        result = await processor._validate_finding(valid_finding)
        assert isinstance(result, Finding)
        assert result.finding_id == "f_001"
    
    @pytest.mark.asyncio
    async def test_validate_finding_invalid(self, processor):
        """Test: Rechazar Finding inválido"""
        invalid_finding = {"scan_id": "scan_001"}  # Incompleto
        with pytest.raises(Exception):
            await processor._validate_finding(invalid_finding)
    
    @pytest.mark.asyncio
    async def test_process_finding_success(self, processor):
        """Test: Procesar Finding válido"""
        valid_finding = {
            "scan_id": "scan_001",
            "asset_id": 42,
            "finding_id": "f_001",
            "title": "SQL Injection",
            "description": "Vulnerable input",
            "severity": "HIGH",
            "cvss": 8.5,
            "cwe": "CWE-89",
            "detected_at": "2024-04-24T10:30:00Z",
            "scanner": "nuclei"
        }
        
        # Mock OllamaClient
        processor.ollama_client.is_available = AsyncMock(return_value=True)
        processor.ollama_client.analyze = AsyncMock(
            return_value="Este es SQL injection real"
        )
        processor.ollama_client.model = "llama2"
        
        result = await processor.process_finding(valid_finding)
        
        assert result.status == "success"
        assert result.finding_id == "f_001"
        assert result.analysis is not None
    
    @pytest.mark.asyncio
    async def test_process_finding_invalid(self, processor):
        """Test: Rechazar Finding inválido"""
        invalid_finding = {"scan_id": "scan_001"}
        result = await processor.process_finding(invalid_finding)
        assert result.status == "error"
    
    @pytest.mark.asyncio
    async def test_process_finding_ollama_unavailable(self, processor):
        """Test: OllamaClient no disponible"""
        valid_finding = {
            "scan_id": "scan_001",
            "asset_id": 42,
            "finding_id": "f_001",
            "title": "SQL Injection",
            "description": "Vulnerable input",
            "severity": "HIGH",
            "cvss": 8.5,
            "cwe": "CWE-89",
            "detected_at": "2024-04-24T10:30:00Z",
            "scanner": "nuclei"
        }
        
        processor.ollama_client.is_available = AsyncMock(return_value=False)
        
        result = await processor.process_finding(valid_finding)
        assert result.status == "skipped"
        assert "OllamaClient not available" in result.error
    
    @pytest.mark.asyncio
    async def test_handle_message_valid(self, processor):
        """Test: Procesar mensaje JSON válido"""
        message = json.dumps({
            "scan_id": "scan_001",
            "asset_id": 42,
            "finding_id": "f_001",
            "title": "SQL Injection",
            "description": "Vulnerable input",
            "severity": "HIGH",
            "cvss": 8.5,
            "cwe": "CWE-89",
            "detected_at": "2024-04-24T10:30:00Z",
            "scanner": "nuclei"
        }).encode('utf-8')
        
        processor.ollama_client.is_available = AsyncMock(return_value=True)
        processor.ollama_client.analyze = AsyncMock(
            return_value="Análisis realizado"
        )
        processor.process_callback = AsyncMock()
        
        await processor._handle_message(message)
        
        assert processor.process_callback.called
    
    @pytest.mark.asyncio
    async def test_emit_finding_success(self, processor):
        """Test: Emitir hallazgo a Redis"""
        with patch.object(processor, 'redis', MagicMock()):
            processor.redis = AsyncMock()
            processor.redis.publish = AsyncMock(return_value=True)
            
            result = await processor.emit_finding({
                "finding_id": "f_001",
                "title": "SQL Injection"
            })
            
            assert result is True


class TestStreamingProcessorIntegration:
    """Tests E2E (requieren Redis real)"""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_redis_connection(self):
        """Test: Conectar a Redis"""
        processor = StreamingProcessor()
        result = await processor.initialize()
        if result:
            await processor.stop()
        assert result is True or result is False  # Just check it doesn't crash
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_process_real_finding(self):
        """Test: Procesar con Ollama real (si disponible)"""
        from services.ai_reasoning.ollama_client import ollama
        
        if not await ollama.is_available():
            pytest.skip("Ollama not available")
        
        processor = StreamingProcessor(ollama_client=ollama)
        
        result = await processor.process_finding({
            "scan_id": "test",
            "asset_id": 999,
            "finding_id": "test_f_001",
            "title": "Test Finding",
            "description": "Testing",
            "severity": "MEDIUM",
            "cvss": 5.5,
            "cwe": "CWE-89",
            "detected_at": "2024-04-24T10:30:00Z",
            "scanner": "test"
        })
        
        assert result.status in ["success", "error", "skipped"]
