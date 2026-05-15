"""Tests for Celery Beat weekly cycle schedule.

Celery crontab day_of_week uses cron convention: 0=Sunday, 1=Monday, ..., 6=Saturday.
"""
import pytest
from celery.schedules import crontab
from shared.celery_app import app


def test_beat_schedule_has_5_phases():
    schedule = app.conf.beat_schedule
    phase_numbers = set()
    for name in schedule:
        if name.startswith('phase'):
            phase_numbers.add(int(name.split('-')[0].replace('phase', '')))
    assert phase_numbers == {1, 2, 3, 4, 5}


def test_beat_schedule_has_7_entries():
    assert len(app.conf.beat_schedule) == 7


def test_phase1_runs_monday():
    schedule = app.conf.beat_schedule
    task = schedule['phase1-asset-inventory-monday']
    assert isinstance(task['schedule'], crontab)
    assert task['schedule'].day_of_week == {1}  # Monday = 1 in cron (0=Sunday)
    assert 2 in task['schedule'].hour


def test_phase2_runs_tuesday():
    schedule = app.conf.beat_schedule
    task = schedule['phase2-vuln-scan-tuesday']
    assert isinstance(task['schedule'], crontab)
    assert task['schedule'].day_of_week == {2}  # Tuesday = 2 in cron


def test_phase3_runs_thursday():
    schedule = app.conf.beat_schedule
    task = schedule['phase3-human-approval-notification']
    assert isinstance(task['schedule'], crontab)
    assert task['schedule'].day_of_week == {4}  # Thursday = 4 in cron
    assert 9 in task['schedule'].hour


def test_phase4_runs_saturday():
    schedule = app.conf.beat_schedule
    task = schedule['phase4-exploit-execution-saturday']
    assert isinstance(task['schedule'], crontab)
    assert task['schedule'].day_of_week == {6}  # Saturday = 6 in cron
    assert 1 in task['schedule'].hour


def test_phase5_runs_sunday():
    schedule = app.conf.beat_schedule
    task = schedule['phase5-reporting-sunday']
    assert isinstance(task['schedule'], crontab)
    assert task['schedule'].day_of_week == {0}  # Sunday = 0 in cron
    assert 8 in task['schedule'].hour


def test_all_tasks_have_queues():
    schedule = app.conf.beat_schedule
    for name, task in schedule.items():
        assert 'options' in task, f"Task {name} missing options"
        assert 'queue' in task['options'], f"Task {name} missing queue"


def test_timezone_is_madrid():
    assert app.conf.timezone == 'Europe/Madrid'
