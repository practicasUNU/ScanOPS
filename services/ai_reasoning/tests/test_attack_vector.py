# services/ai_reasoning/tests/test_attack_vector.py

import pytest
import json
from unittest.mock import AsyncMock, patch
from services.ai_reasoning.attack_vector import suggest_attack_vector
from services.ai_reasoning.pentestgpt_integration import AttackVectorAgent
from services.ai_reasoning.ollama_client import OllamaConnectionError

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


# ---------------------------------------------------------------------------
# TestAttackVectorAgent — US-4.7 pentestgpt_integration tests
# ---------------------------------------------------------------------------

SAMPLE_FICHA = {
    "os": "Ubuntu 22.04",
    "services": ["22/ssh", "80/http", "443/https"],
    "cves": ["CVE-2021-44228", "CVE-2022-0847"],
    "criticality": "CRITICA",
    "ens_measures": ["op.exp.2", "op.acc.1"],
}

VALID_LLM_RESPONSE = json.dumps({
    "msf_module": "exploit/multi/handler",
    "msf_payload": "linux/x64/meterpreter/reverse_tcp",
    "rationale": "SSH + Log4Shell combo permite RCE inicial.",
    "ens_article": "op.exp.2",
    "confidence": "alto",
})


class TestAttackVectorAgent:
    """Tests unitarios para AttackVectorAgent (US-4.7 — pentestgpt_integration)."""

    @pytest.mark.asyncio
    async def test_suggest_attack_vector_valid_response(self):
        """Successful LLM response returns all 5 required keys."""
        mock_client = AsyncMock()
        mock_client.analyze = AsyncMock(return_value=VALID_LLM_RESPONSE)
        agent = AttackVectorAgent(ollama_client=mock_client)
        result = await agent.suggest_attack_vector(SAMPLE_FICHA)
        assert all(k in result for k in ("msf_module", "msf_payload", "rationale", "ens_article", "confidence"))
        assert result["confidence"] == "alto"
        assert result["msf_module"] != "manual_review_required"

    @pytest.mark.asyncio
    async def test_suggest_attack_vector_invalid_json_returns_fallback(self):
        """Malformed JSON response returns fallback dict without raising."""
        mock_client = AsyncMock()
        mock_client.analyze = AsyncMock(return_value="not valid json {{{")
        agent = AttackVectorAgent(ollama_client=mock_client)
        result = await agent.suggest_attack_vector(SAMPLE_FICHA)
        assert result["msf_module"] == "manual_review_required"
        assert result["confidence"] == "bajo"

    @pytest.mark.asyncio
    async def test_suggest_attack_vector_ollama_unavailable_returns_fallback(self):
        """OllamaConnectionError returns fallback dict without raising."""
        mock_client = AsyncMock()
        mock_client.analyze = AsyncMock(side_effect=OllamaConnectionError())
        agent = AttackVectorAgent(ollama_client=mock_client)
        result = await agent.suggest_attack_vector(SAMPLE_FICHA)
        assert result["msf_module"] == "manual_review_required"

    @pytest.mark.asyncio
    async def test_suggest_attack_vector_prompt_contains_cves(self):
        """CVE IDs from ficha_unica appear verbatim in the prompt sent to the LLM."""
        mock_client = AsyncMock()
        captured: list[str] = []

        async def capture_analyze(prompt, **kwargs):
            captured.append(prompt)
            return VALID_LLM_RESPONSE

        mock_client.analyze = capture_analyze
        agent = AttackVectorAgent(ollama_client=mock_client)
        await agent.suggest_attack_vector(SAMPLE_FICHA)
        assert len(captured) == 1
        assert "CVE-2021-44228" in captured[0]

    @pytest.mark.asyncio
    async def test_suggest_attack_vector_missing_key_returns_fallback(self):
        """JSON missing 'msf_payload' triggers fallback (key validation)."""
        mock_client = AsyncMock()
        partial = json.dumps({
            "msf_module": "exploit/multi/handler",
            "rationale": "Some reason",
            "ens_article": "op.exp.2",
            "confidence": "alto",
            # "msf_payload" deliberately absent
        })
        mock_client.analyze = AsyncMock(return_value=partial)
        agent = AttackVectorAgent(ollama_client=mock_client)
        result = await agent.suggest_attack_vector(SAMPLE_FICHA)
        assert result["msf_module"] == "manual_review_required"
