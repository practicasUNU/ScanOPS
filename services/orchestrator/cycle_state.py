from datetime import datetime, timedelta, timezone
from typing import Optional
from zoneinfo import ZoneInfo

from pydantic import BaseModel

MADRID_TZ = ZoneInfo("Europe/Madrid")

# Weekday constants (datetime.weekday())
_MON, _TUE, _WED, _THU, _FRI, _SAT, _SUN = 0, 1, 2, 3, 4, 5, 6

# Phase schedule: phase_number -> (weekday, hour, minute)
_PHASE_SCHEDULE: dict[int, tuple[int, int, int]] = {
    1: (_MON, 2, 0),
    2: (_TUE, 0, 0),
    3: (_THU, 9, 0),
    4: (_SAT, 1, 0),
    5: (_SUN, 8, 0),
}

# Weekdays that map to each phase (for current_phase derivation)
_WEEKDAY_TO_PHASE: dict[int, int] = {
    _MON: 1,
    _TUE: 2,
    _WED: 2,
    _THU: 3,
    _FRI: 0,
    _SAT: 4,
    _SUN: 5,
}

_PHASE_DEFINITIONS = [
    {
        "phase_number": 1,
        "name": "Asset Discovery & Recon",
        "scheduled_day": "Monday",
        "scheduled_time": "02:00",
        "modules": [
            {"id": "M1", "name": "asset_manager", "port": 8001},
            {"id": "M2", "name": "recon_engine", "port": 8003},
        ],
    },
    {
        "phase_number": 2,
        "name": "Vulnerability Scanning & AI Analysis",
        "scheduled_day": "Tuesday",
        "scheduled_time": "00:00",
        "modules": [
            {"id": "M3", "name": "scanner_engine", "port": 8002},
            {"id": "M8", "name": "ai_reasoning", "port": 8005},
        ],
    },
    {
        "phase_number": 3,
        "name": "Human Approval Gate",
        "scheduled_day": "Thursday",
        "scheduled_time": "09:00",
        "modules": [
            {"id": "M8", "name": "ai_reasoning", "port": 8005},
        ],
    },
    {
        "phase_number": 4,
        "name": "Exploit Validation",
        "scheduled_day": "Saturday",
        "scheduled_time": "01:00",
        "modules": [
            {"id": "M4", "name": "exploit_engine", "port": 8004},
        ],
    },
    {
        "phase_number": 5,
        "name": "Reporting",
        "scheduled_day": "Sunday",
        "scheduled_time": "08:00",
        "modules": [
            {"id": "M7", "name": "reporting_engine", "port": 8007},
        ],
    },
]


class ModuleStatus(BaseModel):
    id: str
    name: str
    port: int
    status: str  # "completed" | "in_progress" | "pending" | "blocked"


class PhaseInfo(BaseModel):
    phase_number: int
    name: str
    scheduled_day: str
    scheduled_time: str
    status: str  # "completed" | "in_progress" | "pending"
    modules: list[ModuleStatus]


class CycleStatus(BaseModel):
    week_number: int
    year: int
    week_label: str
    current_phase: int  # 0 = idle
    current_phase_name: str
    cycle_active: bool
    requires_human_approval: bool
    kill_switch_active: bool
    paused: bool
    phases: list[PhaseInfo]
    next_phase_at: Optional[str]  # ISO datetime
    last_updated: str  # ISO datetime


def _phase_status(phase_number: int, current_phase: int) -> str:
    if current_phase == 0:
        return "pending"
    if phase_number < current_phase:
        return "completed"
    if phase_number == current_phase:
        return "in_progress"
    return "pending"


def _module_status(phase_number: int, current_phase: int, is_human_gate: bool) -> str:
    ps = _phase_status(phase_number, current_phase)
    if ps == "completed":
        return "completed"
    if ps == "in_progress":
        if is_human_gate:
            return "blocked"
        return "in_progress"
    return "pending"


def _next_phase_at(current_phase: int, now_madrid: datetime) -> Optional[str]:
    """Return ISO datetime of the next phase start, or None if on last phase."""
    next_phase = current_phase + 1 if current_phase > 0 else 1
    if next_phase > 5:
        return None

    weekday, hour, minute = _PHASE_SCHEDULE[next_phase]

    # Find the next occurrence of that weekday on or after today
    today_weekday = now_madrid.weekday()
    days_ahead = (weekday - today_weekday) % 7
    if days_ahead == 0 and (now_madrid.hour, now_madrid.minute) >= (hour, minute):
        days_ahead = 7

    target = now_madrid.replace(hour=hour, minute=minute, second=0, microsecond=0) + timedelta(days=days_ahead)
    return target.isoformat()


def get_cycle_status(kill_switch_active: bool = False, paused: bool = False) -> CycleStatus:
    """
    Derives current cycle state from the current day/time.
    Uses Europe/Madrid timezone.
    Returns CycleStatus with all phases and their statuses.
    """
    now_utc = datetime.now(timezone.utc)
    now_madrid = now_utc.astimezone(MADRID_TZ)

    iso_week = now_madrid.isocalendar()
    week_number = iso_week.week
    year = iso_week.year

    current_phase = _WEEKDAY_TO_PHASE[now_madrid.weekday()]
    cycle_active = current_phase != 0
    requires_human_approval = current_phase == 3

    phase_names = {p["phase_number"]: p["name"] for p in _PHASE_DEFINITIONS}
    current_phase_name = phase_names.get(current_phase, "Idle")

    phases: list[PhaseInfo] = []
    for defn in _PHASE_DEFINITIONS:
        pnum = defn["phase_number"]
        is_gate = pnum == 3
        ps = _phase_status(pnum, current_phase)
        modules = [
            ModuleStatus(
                id=m["id"],
                name=m["name"],
                port=m["port"],
                status=_module_status(pnum, current_phase, is_gate),
            )
            for m in defn["modules"]
        ]
        phases.append(
            PhaseInfo(
                phase_number=pnum,
                name=defn["name"],
                scheduled_day=defn["scheduled_day"],
                scheduled_time=defn["scheduled_time"],
                status=ps,
                modules=modules,
            )
        )

    next_at = _next_phase_at(current_phase, now_madrid)

    return CycleStatus(
        week_number=week_number,
        year=year,
        week_label=f"W{week_number:02d}-{year}",
        current_phase=current_phase,
        current_phase_name=current_phase_name,
        cycle_active=cycle_active,
        requires_human_approval=requires_human_approval,
        kill_switch_active=kill_switch_active,
        paused=paused,
        phases=phases,
        next_phase_at=next_at,
        last_updated=now_utc.isoformat(),
    )
