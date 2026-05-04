# services/ai_reasoning/tests/test_human_validation.py

import pytest
from unittest.mock import patch, MagicMock
from services.ai_reasoning.human_validation import process_human_decision

class TestHumanValidation:
    """Tests para validación humana (US-4.8)"""
    
    @pytest.mark.asyncio
    @patch("services.ai_reasoning.human_validation.psycopg2.connect")
    async def test_process_decision_validated(self, mock_connect):
        """Test: Decisión validada correctamente (Mocked DB)"""
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur
        mock_cur.fetchone.side_effect = [None, (1,)]

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
    @patch("services.ai_reasoning.human_validation.psycopg2.connect")
    async def test_process_decision_corrected(self, mock_connect):
        """Test: Decisión corregida con nuevo módulo (Mocked DB)"""
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur
        mock_cur.fetchone.side_effect = [None, (2,)]

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
    @patch("services.ai_reasoning.human_validation.psycopg2.connect")
    async def test_process_decision_rejected(self, mock_connect):
        """Test: Decisión rechazada (Mocked DB)"""
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur
        mock_cur.fetchone.side_effect = [None, (3,)]

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

    # --- NUEVOS TESTS SOLICITADOS ---

    @pytest.mark.asyncio
    @patch("services.ai_reasoning.human_validation.psycopg2.connect")
    async def test_process_decision_persists_approved(self, mock_connect):
        """Test: Verifica que una decisión validada persiste como approved"""
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur
        
        # Mock fetchone -> None (no existe registro previo), luego (99,) (id del INSERT)
        mock_cur.fetchone.side_effect = [None, (99,)]
        
        result = await process_human_decision(
            asset_id="A-01",
            finding_id="F-01",
            decision="validada",
            corrected_module=None,
            operator_id="admin"
        )
        
        assert result["final_status"] == "approved"
        assert result["approval_id"] == 99
        # Verificar que se llamó al INSERT
        called_queries = [call[0][0] for call in mock_cur.execute.call_args_list]
        assert any("INSERT INTO m4_approvals" in q for q in called_queries)

    @pytest.mark.asyncio
    @patch("services.ai_reasoning.human_validation.psycopg2.connect")
    async def test_process_decision_updates_existing(self, mock_connect):
        """Test: Verifica que si ya existe un registro se hace UPDATE"""
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur
        
        # Mock fetchone -> (42,) (registro ya existe)
        mock_cur.fetchone.return_value = (42,)
        
        result = await process_human_decision(
            asset_id="A-02",
            finding_id="F-02",
            decision="corregida",
            corrected_module="exploit/linux/ssh/test",
            operator_id="admin"
        )
        
        assert result["final_status"] == "approved_with_correction"
        assert result["approval_id"] == 42
        # Verificar que se llamó al UPDATE
        called_queries = [call[0][0] for call in mock_cur.execute.call_args_list]
        assert any("UPDATE m4_approvals" in q for q in called_queries)

    @pytest.mark.asyncio
    @patch("services.ai_reasoning.human_validation.psycopg2.connect")
    async def test_process_decision_rejected_persists(self, mock_connect):
        """Test: Verifica que una decisión rechazada también se persiste"""
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur
        mock_cur.fetchone.side_effect = [None, (101,)]
        
        result = await process_human_decision(
            asset_id="A-03",
            finding_id="F-03",
            decision="rechazada",
            corrected_module=None,
            operator_id="admin"
        )
        
        assert result["final_status"] == "rejected"
        assert result["approval_id"] == 101
        called_queries = [call[0][0] for call in mock_cur.execute.call_args_list]
        assert any("INSERT INTO m4_approvals" in q for q in called_queries)

    @pytest.mark.asyncio
    @patch("services.ai_reasoning.human_validation.psycopg2.connect")
    async def test_db_error_raises_runtime(self, mock_connect):
        """Test: Verifica que errores de DB lanzan RuntimeError"""
        mock_connect.side_effect = Exception("DB down")
        
        with pytest.raises(RuntimeError, match="No se pudo persistir la decisión en BD"):
            await process_human_decision("A", "F", "validada", None, "OP")
