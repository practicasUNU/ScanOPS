# services/ai_reasoning/tests/test_attack_vector.py

import pytest
import json
from unittest.mock import AsyncMock, patch
from services.ai_reasoning.attack_vector import suggest_attack_vector

class TestAttackVectorUnit:
    """Tests unitarios para Attack Vector Suggester"""
    
    @pytest.mark.asyncio
    async def test_suggest_attack_vector_success(self):
        """Test: Sugerencia exitosa"""
        ficha = {
            "asset_id": 1,
            "cve_id": "CVE-2017-0144",
            "hostname": "DC01",
            "target_ip": "192.168.1.10",
            "os": "Windows",
            "os_version": "2012 R2"
        }
        
        mock_response = {
            "msf_module": "exploit/windows/smb/ms17_010_eternalblue",
            "msf_payload": "windows/x64/meterpreter/reverse_tcp",
            "msf_options": {"RHOSTS": "192.168.1.10"},
            "attack_rationale": "Vulnerable service exposed",
            "risk_level": "medio",
            "estimated_service_impact": "ninguno",
            "confidence": "alto"
        }
        
        with patch("services.ai_reasoning.attack_vector.ollama") as mock_ollama:
            mock_ollama.analyze = AsyncMock(return_value=json.dumps(mock_response))
            
            result = await suggest_attack_vector(ficha)
            
            assert result["msf_module"] == "exploit/windows/smb/ms17_010_eternalblue"
            assert result["status"] == "pending_human_approval"
            assert result["requires_manual_review"] is False

    @pytest.mark.asyncio
    async def test_suggest_attack_vector_unknown_module(self):
        """Test: Módulo UNKNOWN requiere revisión manual"""
        ficha = {"asset_id": 2, "cve_id": "CVE-X"}
        
        mock_response = {
            "msf_module": "UNKNOWN",
            "confidence": "bajo"
        }
        
        with patch("services.ai_reasoning.attack_vector.ollama") as mock_ollama:
            mock_ollama.analyze = AsyncMock(return_value=json.dumps(mock_response))
            
            result = await suggest_attack_vector(ficha)
            
            assert result["msf_module"] == "UNKNOWN"
            assert result["requires_manual_review"] is True

    @pytest.mark.asyncio
    async def test_suggest_attack_vector_empty_module_raises_error(self):
        """Test: Módulo vacío lanza error"""
        ficha = {"asset_id": 3}
        
        with patch("services.ai_reasoning.attack_vector.ollama") as mock_ollama:
            mock_ollama.analyze = AsyncMock(return_value='{"msf_module": ""}')
            
            with pytest.raises(ValueError, match="El LLM devolvió un msf_module vacío o inválido"):
                await suggest_attack_vector(ficha)

class TestAttackVectorIntegration:
    """Tests E2E"""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_suggest_real_ollama(self):
        """Test: Sugerencia con Ollama real"""
        from services.ai_reasoning.ollama_client import ollama
        
        if not await ollama.is_available():
            pytest.skip("Ollama not available")
            
        ficha = {
            "asset_id": 999,
            "cve_id": "CVE-2017-0144",
            "hostname": "DC-PROD",
            "target_ip": "10.0.0.5",
            "os": "Windows",
            "os_version": "2016",
            "confirmed_cves": "CVE-2017-0144 (EternalBlue)"
        }
        
        result = await suggest_attack_vector(ficha)
        
        assert "msf_module" in result
        assert result["status"] == "pending_human_approval"
