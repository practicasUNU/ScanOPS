"""Tests para FalsePositiveFilter - US-4.3"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from services.ai_reasoning.false_positive_filter import FalsePositiveFilter
from services.ai_reasoning.models import Finding, FilterResult


class TestFalsePositiveFilterUnit:
    """Tests unitarios (con mocks)"""
    
    @pytest.fixture
    def filter(self):
        """Instancia de FalsePositiveFilter"""
        mock_ollama = MagicMock()
        return FalsePositiveFilter(ollama_client=mock_ollama)
    
    # TEST 1: Inicialización
    @pytest.mark.asyncio
    async def test_init(self, filter):
        """Test: Inicialización correcta"""
        assert filter.ollama_client is not None
        assert filter.rules is not None
    
    # TEST 2: Regla - Header security
    @pytest.mark.asyncio
    async def test_check_rules_security_header_real(self, filter):
        """Test: X-Frame-Options presente → REAL"""
        finding = Finding(
            scan_id="scan_001",
            asset_id=1,
            finding_id="f_001",
            title="X-Frame-Options Missing",
            description="X-Frame-Options header is set",
            severity="MEDIUM",
            cvss=6.5,
            cwe="CWE-1234",
            detected_at="2024-04-24T10:30:00Z",
            scanner="zap"
        )
        result = await filter._check_rules(finding)
        assert result is False  # No es FP (es real)
    
    # TEST 3: Regla - Test environment
    @pytest.mark.asyncio
    async def test_check_rules_test_env_fp(self, filter):
        """Test: Palabra 'test' en descripción → FALSO POSITIVO"""
        finding = Finding(
            scan_id="scan_001",
            asset_id=1,
            finding_id="f_002",
            title="SQL Injection Found",
            description="Found in test database",
            severity="HIGH",
            cvss=8.0,
            cwe="CWE-89",
            detected_at="2024-04-24T10:30:00Z",
            scanner="nuclei"
        )
        result = await filter._check_rules(finding)
        assert result is True  # Es FP
    
    # TEST 4: Regla - Low CVSS
    @pytest.mark.asyncio
    async def test_check_rules_low_cvss_fp(self, filter):
        """Test: CVSS < 2.0 → FALSO POSITIVO"""
        finding = Finding(
            scan_id="scan_001",
            asset_id=1,
            finding_id="f_003",
            title="Minor Issue",
            description="Very low severity",
            severity="LOW",
            cvss=1.5,
            cwe="CWE-200",
            detected_at="2024-04-24T10:30:00Z",
            scanner="nuclei"
        )
        result = await filter._check_rules(finding)
        # Regla dice cvss < 2.0 -> True
        assert result is True
    
    # TEST 5: Sin reglas aplicables
    @pytest.mark.asyncio
    async def test_check_rules_no_match(self, filter):
        """Test: Ninguna regla aplicable → None"""
        finding = Finding(
            scan_id="scan_001",
            asset_id=1,
            finding_id="f_004",
            title="SQL Injection",
            description="Generic SQL injection description",
            severity="HIGH",
            cvss=8.5,
            cwe="CWE-89",
            detected_at="2024-04-24T10:30:00Z",
            scanner="nuclei"
        )
        result = await filter._check_rules(finding)
        assert result is None  # No hay regla aplicable
    
    # TEST 6: Análisis con IA Experta - Real
    @pytest.mark.asyncio
    async def test_analyze_with_expert_ai_real(self, filter):
        """Test: Ollama dice que ES real (Expert logic)"""
        finding = Finding(
            scan_id="scan_001",
            asset_id=1,
            finding_id="f_005",
            title="SQL Injection",
            description="Parameter 'id' without validation",
            severity="HIGH",
            cvss=8.5,
            cwe="CWE-89",
            detected_at="2024-04-24T10:30:00Z",
            scanner="nuclei"
        )
        
        filter.ollama_client.is_available = AsyncMock(return_value=True)
        filter.ollama_client.analyze = AsyncMock(
            return_value='{"is_false_positive": false, "confidence": "alto", "reason": "Confirmado por contexto"}'
        )
        
        result = await filter._analyze_with_expert_ai(finding)
        assert result["is_false_positive"] is False
        assert result["confidence"] == "alto"
    
    # TEST 7: Análisis con IA Experta - Falso positivo
    @pytest.mark.asyncio
    async def test_analyze_with_expert_ai_fp(self, filter):
        """Test: Ollama dice que ES FP (Expert logic)"""
        finding = Finding(
            scan_id="scan_001",
            asset_id=1,
            finding_id="f_006",
            title="X-Frame-Options",
            description="X-Frame-Options header may be missing",
            severity="MEDIUM",
            cvss=6.5,
            cwe="CWE-1234",
            detected_at="2024-04-24T10:30:00Z",
            scanner="zap"
        )
        
        filter.ollama_client.is_available = AsyncMock(return_value=True)
        filter.ollama_client.analyze = AsyncMock(
            return_value='{"is_false_positive": true, "confidence": "alto", "reason": "Servicio no activo en el activo"}'
        )
        
        result = await filter._analyze_with_expert_ai(finding)
        assert result["is_false_positive"] is True
        assert result["confidence"] == "alto"
    
    # TEST 8: Confianza calculada (Rules)
    def test_calculate_confidence(self, filter):
        """Test: Calcular confianza para reglas"""
        finding = Finding(
            scan_id="scan_001",
            asset_id=1,
            finding_id="f_007",
            title="SQL Injection",
            description="confirmed SQL injection",
            severity="HIGH",
            cvss=9.5,
            cwe="CWE-89",
            detected_at="2024-04-24T10:30:00Z",
            scanner="nuclei"
        )
        
        confidence = filter._calculate_confidence(finding, method="rules")
        assert confidence == 0.95
    
    # TEST 9: Filter completo - Real con IA
    @pytest.mark.asyncio
    async def test_filter_real_expert_ai(self, filter):
        """Test: Filter decide que es REAL usando IA experta"""
        finding = Finding(
            scan_id="scan_001",
            asset_id=1,
            finding_id="f_008",
            title="SQL Injection",
            description="Parameter vulnerable",
            severity="HIGH",
            cvss=8.5,
            cwe="CWE-89",
            detected_at="2024-04-24T10:30:00Z",
            scanner="nuclei"
        )
        
        filter.ollama_client.is_available = AsyncMock(return_value=True)
        filter.ollama_client.analyze = AsyncMock(
            return_value='{"is_false_positive": false, "confidence": "alto", "reason": "Contexto validado"}'
        )
        
        result = await filter.filter(finding)
        
        assert isinstance(result, FilterResult)
        assert result.status == "passed"
        assert result.is_false_positive is False
        assert result.confidence == 0.95  # Mapeo de "alto"
    
    # TEST 10: Filter completo - Falso positivo con reglas
    @pytest.mark.asyncio
    async def test_filter_fp_rules(self, filter):
        """Test: Filter decide que es FALSO POSITIVO usando reglas"""
        finding = Finding(
            scan_id="scan_001",
            asset_id=1,
            finding_id="f_009",
            title="Issue in test",
            description="Found in test environment",
            severity="MEDIUM",
            cvss=2.5,
            cwe="CWE-200",
            detected_at="2024-04-24T10:30:00Z",
            scanner="nuclei"
        )
        
        # _check_rules retornará True -> FP
        result = await filter.filter(finding)
        
        assert isinstance(result, FilterResult)
        assert result.status == "rejected"
        assert result.is_false_positive is True


class TestFalsePositiveFilterIntegration:
    """Tests E2E (requieren Ollama real)"""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_filter_with_real_ollama(self):
        """Test: Filter con Ollama real"""
        from services.ai_reasoning.ollama_client import ollama
        
        if not await ollama.is_available():
            pytest.skip("Ollama not available")
        
        fp_filter = FalsePositiveFilter(ollama_client=ollama)
        
        finding = Finding(
            scan_id="test",
            asset_id=999,
            finding_id="test_f_001",
            title="SQL Injection",
            description="Testing SQL injection detection",
            severity="HIGH",
            cvss=8.0,
            cwe="CWE-89",
            detected_at="2024-04-24T10:30:00Z",
            scanner="test"
        )
        
        asset_context = {
            "os_family": "Linux",
            "services": [{"port": 80, "service": "http", "version": "Apache 2.4"}]
        }
        
        result = await fp_filter.filter(finding, asset_context=asset_context)
        
        assert result.status in ["passed", "rejected"]
        assert 0 <= result.confidence <= 1

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_filter_fp_no_service_ollama(self):
        """Test: Detectar FP cuando el servicio no existe (Expert Logic)"""
        from services.ai_reasoning.ollama_client import ollama
        
        if not await ollama.is_available():
            pytest.skip("Ollama not available")
            
        fp_filter = FalsePositiveFilter(ollama_client=ollama)
        
        finding = Finding(
            scan_id="test",
            asset_id=999,
            finding_id="test_f_004",
            title="EternalBlue (MS17-010)",
            description="Remote Code Execution in SMBv1",
            severity="CRITICAL",
            cvss=10.0,
            cwe="CWE-20",
            detected_at="2024-04-24T10:30:00Z",
            scanner="nuclei"
        )
        
        # El activo es Linux y NO tiene SMB
        asset_context = {
            "os_family": "Linux",
            "services": [{"port": 80, "service": "http"}]
        }
        
        result = await fp_filter.filter(finding, asset_context=asset_context)
        
        # Si el LLM no pudo procesar (modelo no instalado), el fallback es REAL (safe default ENS Alto)
        # En ese caso el test no puede validar el comportamiento inteligente del LLM
        if "Error en procesamiento" in result.reason:
            pytest.skip("Modelo LLM no disponible (404) - test requiere modelo instalado en Ollama")
        
        # El experto de IA debería decir que es FP
        assert result.is_false_positive is True
        assert result.status == "rejected"
        assert "no aparece" in result.reason.lower() or "linux" in result.reason.lower() or "smb" in result.reason.lower() or "expert" in result.filter_method
