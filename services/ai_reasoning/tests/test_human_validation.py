# services/ai_reasoning/tests/test_human_validation.py

import pytest
from services.ai_reasoning.human_validation import process_human_decision

class TestHumanValidation:
    """Tests para validación humana (US-4.8)"""
    
    @pytest.mark.asyncio
    async def test_process_decision_validated(self):
        """Test: Decisión validada correctamente"""
        result = await process_human_decision(
            asset_id="A01",
            finding_id="F01",
            decision="validada",
            corrected_module=None,
            operator_id="USR-001"
        )
        
        assert result["final_status"] == "approved"
        assert result["decision"] == "validada"
        assert result["operator_id"] == "USR-001"
        assert result["corrected_module"] is None
        assert "decided_at" in result

    @pytest.mark.asyncio
    async def test_process_decision_corrected(self):
        """Test: Decisión corregida con nuevo módulo"""
        result = await process_human_decision(
            asset_id="A02",
            finding_id="F02",
            decision="corregida",
            corrected_module="exploit/windows/http/new_exploit",
            operator_id="USR-002"
        )
        
        assert result["final_status"] == "approved_with_correction"
        assert result["corrected_module"] == "exploit/windows/http/new_exploit"

    @pytest.mark.asyncio
    async def test_process_decision_rejected(self):
        """Test: Decisión rechazada"""
        result = await process_human_decision(
            asset_id="A03",
            finding_id="F03",
            decision="rechazada",
            corrected_module=None,
            operator_id="USR-003"
        )
        
        assert result["final_status"] == "rejected"

    @pytest.mark.asyncio
    async def test_invalid_decision_raises_error(self):
        """Test: Decisión inválida lanza ValueError"""
        with pytest.raises(ValueError, match="Decisión inválida"):
            await process_human_decision("A04", "F04", "invalid", None, "OP")

    @pytest.mark.asyncio
    async def test_corrected_without_module_raises_error(self):
        """Test: Decisión corregida sin módulo lanza ValueError"""
        with pytest.raises(ValueError, match="debe proporcionarse un 'corrected_module'"):
            await process_human_decision("A05", "F05", "corregida", None, "OP")
