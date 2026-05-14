"""Tests for services/orchestrator — cycle state, health checker, and API endpoints."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from zoneinfo import ZoneInfo

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

MADRID_TZ = ZoneInfo("Europe/Madrid")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _madrid_dt(year: int, month: int, day: int, hour: int = 10, minute: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, 0, tzinfo=MADRID_TZ)


def _patch_now(madrid_dt: datetime):
    """Patch datetime.now inside cycle_state so it returns the given Madrid datetime as UTC."""
    utc_dt = madrid_dt.astimezone(timezone.utc)
    return patch(
        "services.orchestrator.cycle_state.datetime",
        **{"now.return_value": utc_dt, "side_effect": None},
    )


# ---------------------------------------------------------------------------
# cycle_state unit tests
# ---------------------------------------------------------------------------

class TestGetCycleStatusPhase:
    # 2026-05-11 = Monday  -> phase 1
    # 2026-05-12 = Tuesday -> phase 2
    # 2026-05-13 = Wednesday -> phase 2
    # 2026-05-14 = Thursday -> phase 3
    # 2026-05-15 = Friday   -> phase 0 (idle)
    # 2026-05-16 = Saturday -> phase 4
    # 2026-05-17 = Sunday   -> phase 5

    @pytest.mark.parametrize("iso_date,expected_phase", [
        ("2026-05-11", 1),  # Monday
        ("2026-05-12", 2),  # Tuesday
        ("2026-05-13", 2),  # Wednesday
        ("2026-05-14", 3),  # Thursday
        ("2026-05-15", 0),  # Friday
        ("2026-05-16", 4),  # Saturday
        ("2026-05-17", 5),  # Sunday
    ])
    def test_current_phase_by_weekday(self, iso_date, expected_phase):
        from services.orchestrator.cycle_state import get_cycle_status

        year, month, day = map(int, iso_date.split("-"))
        madrid_dt = _madrid_dt(year, month, day)
        utc_dt = madrid_dt.astimezone(timezone.utc)

        with patch("services.orchestrator.cycle_state.datetime") as mock_dt:
            mock_dt.now.return_value = utc_dt
            result = get_cycle_status()

        assert result.current_phase == expected_phase

    def test_requires_human_approval_on_thursday(self):
        from services.orchestrator.cycle_state import get_cycle_status

        madrid_dt = _madrid_dt(2026, 5, 14)  # Thursday
        utc_dt = madrid_dt.astimezone(timezone.utc)

        with patch("services.orchestrator.cycle_state.datetime") as mock_dt:
            mock_dt.now.return_value = utc_dt
            result = get_cycle_status()

        assert result.requires_human_approval is True
        assert result.current_phase == 3

    @pytest.mark.parametrize("iso_date", [
        "2026-05-11",  # Monday
        "2026-05-12",  # Tuesday
        "2026-05-16",  # Saturday
        "2026-05-17",  # Sunday
    ])
    def test_requires_human_approval_false_on_non_thursday(self, iso_date):
        from services.orchestrator.cycle_state import get_cycle_status

        year, month, day = map(int, iso_date.split("-"))
        madrid_dt = _madrid_dt(year, month, day)
        utc_dt = madrid_dt.astimezone(timezone.utc)

        with patch("services.orchestrator.cycle_state.datetime") as mock_dt:
            mock_dt.now.return_value = utc_dt
            result = get_cycle_status()

        assert result.requires_human_approval is False

    def test_cycle_active_false_on_friday(self):
        from services.orchestrator.cycle_state import get_cycle_status

        madrid_dt = _madrid_dt(2026, 5, 15)  # Friday
        utc_dt = madrid_dt.astimezone(timezone.utc)

        with patch("services.orchestrator.cycle_state.datetime") as mock_dt:
            mock_dt.now.return_value = utc_dt
            result = get_cycle_status()

        assert result.cycle_active is False
        assert result.current_phase == 0

    def test_kill_switch_propagates(self):
        from services.orchestrator.cycle_state import get_cycle_status

        madrid_dt = _madrid_dt(2026, 5, 11)  # Monday
        utc_dt = madrid_dt.astimezone(timezone.utc)

        with patch("services.orchestrator.cycle_state.datetime") as mock_dt:
            mock_dt.now.return_value = utc_dt
            result = get_cycle_status(kill_switch_active=True)

        assert result.kill_switch_active is True

    def test_paused_propagates(self):
        from services.orchestrator.cycle_state import get_cycle_status

        madrid_dt = _madrid_dt(2026, 5, 11)  # Monday
        utc_dt = madrid_dt.astimezone(timezone.utc)

        with patch("services.orchestrator.cycle_state.datetime") as mock_dt:
            mock_dt.now.return_value = utc_dt
            result = get_cycle_status(paused=True)

        assert result.paused is True


class TestGetCycleStatusPhases:
    def test_always_five_phases(self):
        from services.orchestrator.cycle_state import get_cycle_status

        for iso_date in ["2026-05-11", "2026-05-12", "2026-05-14", "2026-05-15", "2026-05-16", "2026-05-17"]:
            year, month, day = map(int, iso_date.split("-"))
            utc_dt = _madrid_dt(year, month, day).astimezone(timezone.utc)

            with patch("services.orchestrator.cycle_state.datetime") as mock_dt:
                mock_dt.now.return_value = utc_dt
                result = get_cycle_status()

            assert len(result.phases) == 5, f"Expected 5 phases on {iso_date}"

    def test_phase_statuses_on_wednesday(self):
        from services.orchestrator.cycle_state import get_cycle_status

        utc_dt = _madrid_dt(2026, 5, 13).astimezone(timezone.utc)  # Wednesday, phase 2
        with patch("services.orchestrator.cycle_state.datetime") as mock_dt:
            mock_dt.now.return_value = utc_dt
            result = get_cycle_status()

        statuses = {p.phase_number: p.status for p in result.phases}
        assert statuses[1] == "completed"
        assert statuses[2] == "in_progress"
        assert statuses[3] == "pending"
        assert statuses[4] == "pending"
        assert statuses[5] == "pending"

    def test_phase_modules_present(self):
        from services.orchestrator.cycle_state import get_cycle_status

        utc_dt = _madrid_dt(2026, 5, 11).astimezone(timezone.utc)
        with patch("services.orchestrator.cycle_state.datetime") as mock_dt:
            mock_dt.now.return_value = utc_dt
            result = get_cycle_status()

        phase_modules = {p.phase_number: [m.id for m in p.modules] for p in result.phases}
        assert "M1" in phase_modules[1] and "M2" in phase_modules[1]
        assert "M3" in phase_modules[2] and "M8" in phase_modules[2]
        assert "M8" in phase_modules[3]
        assert "M4" in phase_modules[4]
        assert "M7" in phase_modules[5]


# ---------------------------------------------------------------------------
# health_checker unit tests
# ---------------------------------------------------------------------------

class TestCheckAllModules:
    @pytest.mark.asyncio
    async def test_returns_offline_when_unreachable(self):
        from services.orchestrator.health_checker import check_all_modules

        with patch("services.orchestrator.health_checker.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get.side_effect = Exception("Connection refused")
            mock_client_cls.return_value = mock_client

            result = await check_all_modules()

        assert all(v == "offline" for v in result.values())
        assert set(result.keys()) == {"M1", "M2", "M3", "M4", "M5", "M7", "M8"}

    @pytest.mark.asyncio
    async def test_returns_online_for_200(self):
        from services.orchestrator.health_checker import check_all_modules

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("services.orchestrator.health_checker.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = await check_all_modules()

        assert all(v == "online" for v in result.values())

    @pytest.mark.asyncio
    async def test_never_raises(self):
        from services.orchestrator.health_checker import check_all_modules

        with patch("services.orchestrator.health_checker.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get.side_effect = RuntimeError("unexpected")
            mock_client_cls.return_value = mock_client

            result = await check_all_modules()  # must not raise

        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# FastAPI endpoint tests
# ---------------------------------------------------------------------------

@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.asyncio
async def test_cycle_status_returns_200():
    from services.orchestrator.main import app

    utc_dt = _madrid_dt(2026, 5, 11).astimezone(timezone.utc)  # Monday

    with patch("services.orchestrator.cycle_state.datetime") as mock_dt, \
         patch("services.orchestrator.main.check_all_modules", new_callable=AsyncMock) as mock_health:
        mock_dt.now.return_value = utc_dt
        mock_health.return_value = {mid: "online" for mid in ["M1", "M2", "M3", "M4", "M5", "M7", "M8"]}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/orchestrator/cycle/status")

    assert response.status_code == 200
    data = response.json()
    assert "current_phase" in data
    assert "phases" in data
    assert len(data["phases"]) == 5
    assert "kill_switch_active" in data
    assert "paused" in data


@pytest.mark.asyncio
async def test_pause_toggles():
    import importlib
    import services.orchestrator.main as orchestrator_main

    # Reset state
    orchestrator_main._paused = False

    with patch("services.orchestrator.main.check_all_modules", new_callable=AsyncMock) as mock_health:
        mock_health.return_value = {}
        async with AsyncClient(transport=ASGITransport(app=orchestrator_main.app), base_url="http://test") as client:
            r1 = await client.post("/orchestrator/cycle/pause")
            assert r1.json()["paused"] is True

            r2 = await client.post("/orchestrator/cycle/pause")
            assert r2.json()["paused"] is False


@pytest.mark.asyncio
async def test_kill_switch_activate_deactivate():
    import services.orchestrator.main as orchestrator_main

    orchestrator_main._kill_switch_active = False

    async with AsyncClient(transport=ASGITransport(app=orchestrator_main.app), base_url="http://test") as client:
        r = await client.post("/orchestrator/cycle/kill-switch?totp_code=123456")
        assert r.status_code == 200
        assert r.json()["kill_switch_active"] is True

        r2 = await client.post("/orchestrator/cycle/kill-switch/deactivate")
        assert r2.json()["kill_switch_active"] is False


@pytest.mark.asyncio
async def test_kill_switch_invalid_totp():
    import services.orchestrator.main as orchestrator_main

    async with AsyncClient(transport=ASGITransport(app=orchestrator_main.app), base_url="http://test") as client:
        r = await client.post("/orchestrator/cycle/kill-switch?totp_code=abc")
        assert r.status_code == 400


@pytest.mark.asyncio
async def test_modules_health_endpoint():
    import services.orchestrator.main as orchestrator_main

    with patch("services.orchestrator.main.check_all_modules", new_callable=AsyncMock) as mock_health:
        mock_health.return_value = {"M1": "online", "M2": "offline"}
        async with AsyncClient(transport=ASGITransport(app=orchestrator_main.app), base_url="http://test") as client:
            r = await client.get("/orchestrator/modules/health")

    assert r.status_code == 200
    data = r.json()
    assert "modules" in data
    assert "timestamp" in data
    assert data["modules"]["M1"] == "online"
    assert data["modules"]["M2"] == "offline"
