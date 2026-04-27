# services/ai_reasoning/tests/test_ens_mapper.py

import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch
from services.ai_reasoning.ens_mapper import map_to_ens

class TestENSMapperUnit:
    """Tests unitarios para ENS Mapper"""
    
    @pytest.mark.asyncio
    async def test_map_to_ens_success(self):
        """Test: Mapeo exitoso con respuesta JSON válida"""
        finding = {
            "finding_id": "f_001",
            "cve": "CVE-2021-44228",
            "title": "Log4Shell",
            "description": "Remote Code Execution in Log4j"
        }
        asset = {
            "asset_id": 101,
            "hostname": "prod-web-01",
            "criticidad": "ALTO",
            "sensitive_data": True
        }
        
        # Mocks
        mock_response = {
            "medidas_ens": ["mp.info.3", "op.exp.2"],
            "medida_principal": "mp.info.3",
            "nivel_incumplimiento": "total",
            "descripcion_incumplimiento": "Exposición de logs con datos sensibles",
            "confianza_mapeo": "alta"
        }
        
        with patch("services.ai_reasoning.ens_mapper.ollama") as mock_ollama, \
             patch("services.ai_reasoning.ens_mapper.rag_engine") as mock_rag:
            
            mock_rag.get_ens_context = AsyncMock(return_value="Contexto de ejemplo ENS...")
            mock_ollama.analyze = AsyncMock(return_value=json.dumps(mock_response))
            
            result = await map_to_ens(finding, asset)
            
            assert result["finding_id"] == "f_001"
            assert result["asset_id"] == 101
            assert result["medida_principal"] == "mp.info.3"
            assert "mp.info.3" in result["medidas_ens"]
            assert result["nivel_incumplimiento"] == "total"

    @pytest.mark.asyncio
    async def test_map_to_ens_fallback_on_json_error(self):
        """Test: Fallback cuando el LLM devuelve basura"""
        finding = {"finding_id": "f_002"}
        asset = {"asset_id": 102}
        
        with patch("services.ai_reasoning.ens_mapper.ollama") as mock_ollama, \
             patch("services.ai_reasoning.ens_mapper.rag_engine") as mock_rag:
            
            mock_rag.get_ens_context = AsyncMock(return_value="")
            mock_ollama.analyze = AsyncMock(return_value="Esto no es JSON")
            
            result = await map_to_ens(finding, asset)
            
            assert result["medida_principal"] == "op.exp.2"
            assert result["confianza_mapeo"] == "baja"
            assert "parse_error" in result["descripcion_incumplimiento"]

    @pytest.mark.asyncio
    async def test_map_to_ens_retry_on_connection_error(self):
        """Test: Propagar error de conexión para reintento"""
        from services.ai_reasoning.ollama_client import OllamaConnectionError
        
        finding = {"finding_id": "f_003"}
        asset = {"asset_id": 103}
        
        with patch("services.ai_reasoning.ens_mapper.ollama") as mock_ollama:
            mock_ollama.analyze = AsyncMock(side_effect=OllamaConnectionError("Connection refused"))
            
            with pytest.raises(OllamaConnectionError):
                await map_to_ens(finding, asset)

class TestENSMapperIntegration:
    """Tests E2E"""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_map_to_ens_real_ollama(self):
        """Test: Mapeo real con Ollama"""
        from services.ai_reasoning.ollama_client import ollama
        
        if not await ollama.is_available():
            pytest.skip("Ollama not available")
            
        finding = {
            "finding_id": "test_rag_001",
            "cve": "CVE-2017-0144",
            "title": "EternalBlue",
            "description": "SMBv1 RCE"
        }
        asset = {
            "asset_id": 999,
            "hostname": "win-dc-01",
            "criticidad": "CRITICO",
            "sensitive_data": True
        }
        
        result = await map_to_ens(finding, asset)
        
        assert "medidas_ens" in result
        assert len(result["medidas_ens"]) > 0
        assert result["asset_id"] == 999
