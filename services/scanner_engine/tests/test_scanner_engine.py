"""Comprehensive tests for Scanner Engine (M3) - >80% coverage."""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_asset_data():
    """Mock asset data."""
    return {
        "asset_id": 1,
        "asset_ip": "192.168.1.10",
        "asset_name": "Test-Server",
        "asset_url": "http://192.168.1.10",
    }


@pytest.fixture
def mock_openvas_report():
    """Mock OpenVAS report."""
    return {
        "report": {
            "results": [
                {
                    "name": "CVE-2021-44228 (Log4Shell)",
                    "severity": "critical",
                    "cvss_base": 10.0,
                    "cve": "CVE-2021-44228",
                    "description": "Apache Log4j2 JNDI injection",
                    "solution": "Update to Log4j 2.17.0",
                },
                {
                    "name": "Outdated SSL",
                    "severity": "high",
                    "cvss_base": 7.5,
                    "cve": None,
                    "description": "Deprecated TLS version",
                    "solution": "Upgrade to TLS 1.3",
                },
            ]
        }
    }


@pytest.fixture
def mock_nuclei_output():
    """Mock Nuclei JSON output."""
    return [
        {
            "template-id": "sql-injection",
            "name": "SQL Injection",
            "severity": "critical",
            "matched-at": "http://target/?id=1",
            "description": "Possible SQL injection",
        },
        {
            "template-id": "xss",
            "name": "Cross-Site Scripting",
            "severity": "high",
            "matched-at": "http://target/?search=<script>",
            "description": "Possible XSS",
        },
    ]


@pytest.fixture
def mock_zap_report():
    """Mock ZAP report."""
    return {
        "site": {
            "alerts": [
                {
                    "name": "Missing Security Header",
                    "riskcode": "1",
                    "description": "X-Frame-Options missing",
                    "solution": "Add X-Frame-Options: DENY",
                    "reference": "https://owasp.org/",
                },
            ]
        }
    }


# ============================================================================
# TEST MODELS (finding.py)
# ============================================================================


class TestFindingModels:
    """Tests for Finding model and normalizers."""

    def test_finding_creation(self):
        """Test Finding model creation."""
        from services.scanner_engine.models.finding import Finding, SeverityLevel, ScannerType

        finding = Finding(
            asset_id=1,
            title="Test Vuln",
            description="Test description",
            severity=SeverityLevel.HIGH,
            cvss_score=7.5,
            cve_id="CVE-2021-1234",
            evidence="Evidence here",
            remediation="Fix this",
            scanner=ScannerType.OPENVAS,
        )

        assert finding.asset_id == 1
        assert finding.title == "Test Vuln"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.cvss_score == 7.5

    def test_finding_to_dict(self):
        """Test Finding to_dict conversion."""
        from services.scanner_engine.models.finding import Finding, SeverityLevel, ScannerType

        finding = Finding(
            asset_id=1,
            title="Test",
            description="Test",
            severity=SeverityLevel.MEDIUM,
            evidence="Test",
            remediation="Test",
            scanner=ScannerType.OPENVAS,
        )

        finding_dict = finding.to_dict()
        assert isinstance(finding_dict, dict)
        assert finding_dict["asset_id"] == 1
        assert finding_dict["title"] == "Test"

    def test_normalize_openvvas_findings(self, mock_openvas_report):
        """Test OpenVAS finding normalization."""
        from services.scanner_engine.models.finding import normalize_openvvas_findings

        findings = normalize_openvvas_findings(mock_openvas_report, asset_id=1)

        assert len(findings) == 2
        assert findings[0].title == "CVE-2021-44228 (Log4Shell)"
        assert findings[0].severity.value == "CRITICAL"
        assert findings[0].cvss_score == 10.0
        assert findings[0].cve_id == "CVE-2021-44228"

    def test_normalize_nuclei_findings(self, mock_nuclei_output):
        """Test Nuclei finding normalization."""
        from services.scanner_engine.models.finding import normalize_nuclei_findings

        findings = normalize_nuclei_findings(mock_nuclei_output, asset_id=1)

        assert len(findings) == 2
        assert findings[0].title == "SQL Injection"
        assert findings[0].scanner.value == "Nuclei"

    def test_normalize_zap_findings(self, mock_zap_report):
        """Test ZAP finding normalization."""
        from services.scanner_engine.models.finding import normalize_zap_findings

        findings = normalize_zap_findings(mock_zap_report, asset_id=1)

        assert len(findings) == 1
        assert findings[0].title == "Missing Security Header"
        assert findings[0].scanner.value == "ZAP"

    def test_normalize_cvss_score(self):
        """Test CVSS score normalization."""
        from services.scanner_engine.models.finding import normalize_cvss_score

        assert normalize_cvss_score(7.5) == 7.5
        assert normalize_cvss_score(0.0) == 0.0
        assert normalize_cvss_score(10.0) == 10.0
        assert normalize_cvss_score(None) is None
        assert normalize_cvss_score(11.0) is None  # Invalid range


# ============================================================================
# TEST CONFIG (config.py)
# ============================================================================


class TestConfig:
    """Tests for ScannerConfig."""

    def test_config_defaults(self):
        """Test config default values."""
        from services.scanner_engine.config import config

        assert config.OPENVAS_HOST == "openvas"
        assert config.OPENVAS_PORT == 9392
        assert config.NUCLEI_TIMEOUT == 1800
        assert config.ZAP_PORT == 8080
        assert config.MAX_CONCURRENT_SCANS == 5


# ============================================================================
# TEST OPENVAS CLIENT
# ============================================================================


class TestOpenVASClient:
    """Tests for OpenVAS client."""

    @pytest.mark.asyncio
    async def test_openvas_init(self):
        """Test OpenVAS client initialization."""
        from services.scanner_engine.clients.openvas_client import OpenVASClient

        client = OpenVASClient(
            host="openvas-test",
            port=9392,
            user="admin",
            password="password",
        )

        assert client.host == "openvas-test"
        assert client.port == 9392

    @pytest.mark.asyncio
    async def test_openvas_connect(self):
        """Test OpenVAS client connection."""
        from services.scanner_engine.clients.openvas_client import OpenVASClient

        client = OpenVASClient()
        result = await client.connect()

        assert result is True
        assert client._authenticated is True

        await client.disconnect()

    @pytest.mark.asyncio
    async def test_openvas_get_scanners(self):
        """Test get_available_scanners."""
        from services.scanner_engine.clients.openvas_client import OpenVASClient

        client = OpenVASClient()
        await client.connect()

        scanners = await client.get_available_scanners()
        assert isinstance(scanners, dict)

        await client.disconnect()

    @pytest.mark.asyncio
    async def test_openvas_create_target(self):
        """Test create_target."""
        from services.scanner_engine.clients.openvas_client import OpenVASClient

        client = OpenVASClient()
        await client.connect()

        target_id = await client.create_target(
            ["192.168.1.10"], "Test Target"
        )

        assert target_id is not None
        assert "target_" in target_id

        await client.disconnect()

    @pytest.mark.asyncio
    async def test_openvas_create_task(self):
        """Test create_task."""
        from services.scanner_engine.clients.openvas_client import OpenVASClient

        client = OpenVASClient()
        await client.connect()

        task_id = await client.create_task(
            "target_123", "Test Task"
        )

        assert task_id is not None
        assert "task_" in task_id

        await client.disconnect()

    @pytest.mark.asyncio
    async def test_openvas_start_task(self):
        """Test start_task."""
        from services.scanner_engine.clients.openvas_client import OpenVASClient

        client = OpenVASClient()
        await client.connect()

        result = await client.start_task("task_123")
        assert result is True

        await client.disconnect()

    @pytest.mark.asyncio
    async def test_openvas_get_task_status(self):
        """Test get_task_status."""
        from services.scanner_engine.clients.openvas_client import OpenVASClient

        client = OpenVASClient()
        await client.connect()

        status = await client.get_task_status("task_123")

        assert "status" in status
        assert "progress" in status
        assert status["progress"] == 100

        await client.disconnect()

    @pytest.mark.asyncio
    async def test_openvas_get_task_report(self, mock_openvas_report):
        """Test get_task_report."""
        from services.scanner_engine.clients.openvas_client import OpenVASClient

        client = OpenVASClient()
        await client.connect()

        report = await client.get_task_report("task_123")

        assert report is not None
        assert "report" in report

        await client.disconnect()

    @pytest.mark.asyncio
    async def test_openvas_scan_asset(self, mock_asset_data):
        """Test full scan_asset flow."""
        from services.scanner_engine.clients.openvas_client import OpenVASClient

        client = OpenVASClient()
        await client.connect()

        findings = await client.scan_asset(
            mock_asset_data["asset_id"],
            mock_asset_data["asset_ip"],
            mock_asset_data["asset_name"],
        )

        assert isinstance(findings, list)
        assert len(findings) > 0

        await client.disconnect()


# ============================================================================
# TEST NUCLEI CLIENT
# ============================================================================


class TestNucleiClient:
    """Tests for Nuclei client."""

    @pytest.mark.asyncio
    async def test_nuclei_init(self):
        """Test Nuclei client initialization."""
        from services.scanner_engine.clients.nuclei_client import NucleiClient

        client = NucleiClient()
        assert client.templates_path == "/app/templates/nuclei"

    @pytest.mark.asyncio
    async def test_nuclei_scan_asset(self, mock_asset_data):
        """Test Nuclei scan_asset."""
        from services.scanner_engine.clients.nuclei_client import NucleiClient

        client = NucleiClient()

        findings = await client.scan_asset(
            mock_asset_data["asset_id"],
            mock_asset_data["asset_ip"],
            mock_asset_data["asset_name"],
        )

        assert isinstance(findings, list)
        assert len(findings) > 0


# ============================================================================
# TEST ZAP CLIENT
# ============================================================================


class TestZAPClient:
    """Tests for ZAP client."""

    @pytest.mark.asyncio
    async def test_zap_init(self):
        """Test ZAP client initialization."""
        from services.scanner_engine.clients.zap_client import ZAPClient

        client = ZAPClient()
        assert client.host == "zap"
        assert client.port == 8080

    @pytest.mark.asyncio
    async def test_zap_scan_asset(self, mock_asset_data):
        """Test ZAP scan_asset."""
        from services.scanner_engine.clients.zap_client import ZAPClient

        client = ZAPClient()

        findings = await client.scan_asset(
            mock_asset_data["asset_id"],
            mock_asset_data["asset_url"],
            mock_asset_data["asset_name"],
        )

        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_zap_is_available(self):
        """Test ZAP availability check."""
        from services.scanner_engine.clients.zap_client import ZAPClient

        client = ZAPClient()
        available = await client.is_available()

        assert available is True


# ============================================================================
# TEST CELERY TASKS
# ============================================================================


class TestCeleryTasks:
    """Tests for Celery tasks."""

    def test_run_openvvas_scan_task(self, mock_asset_data):
        """Test OpenVAS Celery task."""
        from services.scanner_engine.tasks.vuln_tasks import run_openvvas_scan

        result = run_openvvas_scan(
            mock_asset_data["asset_id"],
            mock_asset_data["asset_ip"],
            mock_asset_data["asset_name"],
        )

        assert result is not None
        assert result["scanner"] == "OpenVAS"
        assert result["status"] in ["success", "error"]
        assert "findings_count" in result

    def test_run_nuclei_scan_task(self, mock_asset_data):
        """Test Nuclei Celery task."""
        from services.scanner_engine.tasks.vuln_tasks import run_nuclei_scan

        result = run_nuclei_scan(
            mock_asset_data["asset_id"],
            mock_asset_data["asset_ip"],
            mock_asset_data["asset_name"],
        )

        assert result is not None
        assert result["scanner"] == "Nuclei"
        assert "findings_count" in result

    def test_run_zap_scan_task(self, mock_asset_data):
        """Test ZAP Celery task."""
        from services.scanner_engine.tasks.vuln_tasks import run_zap_scan

        result = run_zap_scan(
            mock_asset_data["asset_id"],
            mock_asset_data["asset_url"],
            mock_asset_data["asset_name"],
        )

        assert result is not None
        assert result["scanner"] == "ZAP"
        assert "findings_count" in result

    def test_merge_scan_results(self):
        """Test merge_scan_results task."""
        from services.scanner_engine.tasks.vuln_tasks import merge_scan_results

        mock_results = [
            {
                "scanner": "OpenVAS",
                "status": "success",
                "findings": [{"title": "CVE-1"}],
                "findings_count": 1,
            },
            {
                "scanner": "Nuclei",
                "status": "success",
                "findings": [{"title": "SQL-Injection"}],
                "findings_count": 1,
            },
        ]

        result = merge_scan_results(mock_results, asset_id=1)

        assert result is not None
        assert result["asset_id"] == 1
        assert result["total_findings"] == 2
        assert "OpenVAS" in result["findings_by_scanner"]


# ============================================================================
# TEST ENDPOINTS
# ============================================================================


class TestEndpoints:
    """Tests for FastAPI endpoints."""

    @pytest.mark.asyncio
    async def test_endpoint_start_scan(self):
        """Test POST /scan/asset/{asset_id}."""
        from fastapi.testclient import TestClient
        from services.scanner_engine.main import app

        client = TestClient(app)

        response = client.post(
            "/scan/asset/1",
            json={
                "scan_types": ["nuclei"],
                "description": "Test scan",
            },
        )

        assert response.status_code in [200, 202]

    @pytest.mark.asyncio
    async def test_endpoint_quick_scan(self):
        """Test GET /scan/asset/{asset_id}/quick."""
        from fastapi.testclient import TestClient
        from services.scanner_engine.main import app

        client = TestClient(app)

        response = client.get("/scan/asset/1/quick")
        assert response.status_code in [200, 202]

    @pytest.mark.asyncio
    async def test_endpoint_health(self):
        """Test GET /scan/health."""
        from fastapi.testclient import TestClient
        from services.scanner_engine.main import app

        client = TestClient(app)

        response = client.get("/scan/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data

    @pytest.mark.asyncio
    async def test_endpoint_batch_scan(self):
        """Test POST /scan/batch."""
        from fastapi.testclient import TestClient
        from services.scanner_engine.main import app

        client = TestClient(app)

        response = client.post(
            "/scan/batch?asset_ids=1&asset_ids=2&scan_types=nuclei"
        )

        assert response.status_code in [200, 202]


# ============================================================================
# TEST APP FACTORY
# ============================================================================


class TestAppFactory:
    """Tests for FastAPI app factory."""

    def test_app_creation(self):
        """Test app creation."""
        from services.scanner_engine.main import create_app

        app = create_app()

        assert app is not None
        assert app.title == "ScanOPS Scanner Engine (M3)"

    def test_app_routes(self):
        """Test app has required routes."""
        from services.scanner_engine.main import app

        routes = [route.path for route in app.routes]

        assert "/scan/health" in routes or any("/health" in r for r in routes)
        assert "/" in routes


# ============================================================================
# INTEGRATION TESTS
# ============================================================================


class TestIntegration:
    """Integration tests."""

    @pytest.mark.asyncio
    async def test_end_to_end_scan_flow(self, mock_asset_data):
        """Test complete scan flow."""
        from services.scanner_engine.clients.openvas_client import OpenVASClient

        async with OpenVASClient() as client:
            findings = await client.scan_asset(
                mock_asset_data["asset_id"],
                mock_asset_data["asset_ip"],
                mock_asset_data["asset_name"],
            )

            assert isinstance(findings, list)
            assert all(hasattr(f, "title") for f in findings)
            assert all(hasattr(f, "severity") for f in findings)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=services/scanner_engine", "--cov-report=html"])
