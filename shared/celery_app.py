"""
ScanOps Celery application — weekly automated security cycle.
ENS Alto: op.exp.2 (vulnerability management), op.exp.3 (configuration management)
"""
from celery import Celery
from celery.schedules import crontab
from shared.config import settings

app = Celery(
    "scanops",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "services.asset_manager.tasks.discovery",
        "services.recon_engine.tasks.scan_tasks",
        "services.scanner_engine.tasks.vuln_tasks",
        "services.ai_reasoning.tasks",
        "services.exploit_engine.tasks",
        "services.exploit_engine.alert_tasks",
        "services.reporting_engine.tasks",
    ]
)

app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Europe/Madrid',
    enable_utc=True,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=10,
    task_acks_late=True,
    task_time_limit=600,
    task_soft_time_limit=570,
    task_track_started=True,
    result_extended=True,

    # --- Weekly cycle Beat Schedule ---
    # ENS op.exp.2: periodic vulnerability analysis
    # ENS op.exp.3: automated configuration inventory
    # Celery crontab day_of_week uses cron convention: 0=Sunday, 1=Monday, …, 6=Saturday
    beat_schedule={

        # PHASE 1 — Monday 02:00 Madrid
        # M1: asset inventory sync
        'phase1-asset-inventory-monday': {
            'task': 'services.asset_manager.tasks.discovery.run_full_discovery',
            'schedule': crontab(hour=2, minute=0, day_of_week='monday'),
            'options': {'queue': 'discovery'},
        },
        # M2: full recon — starts 1h after M1 to allow asset inventory to complete
        'phase1-recon-monday': {
            'task': 'services.recon_engine.tasks.scan_tasks.run_recon_complete',
            'schedule': crontab(hour=3, minute=0, day_of_week='monday'),
            'options': {'queue': 'discovery'},
        },

        # PHASE 2 — Tuesday 00:00 Madrid
        # M3: vulnerability scan
        'phase2-vuln-scan-tuesday': {
            'task': 'services.scanner_engine.tasks.vuln_tasks.run_full_vulnerability_scan',
            'schedule': crontab(hour=0, minute=0, day_of_week='tuesday'),
            'options': {'queue': 'vulnerabilities'},
        },
        # M8: AI analysis — starts 4h after M3 to allow scan results to populate
        'phase2-ai-analysis-tuesday': {
            'task': 'services.ai_reasoning.tasks.run_full_ai_pipeline',
            'schedule': crontab(hour=4, minute=0, day_of_week='tuesday'),
            'options': {'queue': 'ai_reasoning'},
        },

        # PHASE 3 — Thursday 09:00 Madrid
        # Human approval gate — notifies security officer that M4 queue is ready
        'phase3-human-approval-notification': {
            'task': 'services.ai_reasoning.tasks.notify_human_approval_required',
            'schedule': crontab(hour=9, minute=0, day_of_week='thursday'),
            'options': {'queue': 'ai_reasoning'},
        },

        # PHASE 4 — Saturday 01:00 Madrid
        # M4: exploit execution (only pre-approved requests)
        'phase4-exploit-execution-saturday': {
            'task': 'services.exploit_engine.tasks.run_approved_exploits',
            'schedule': crontab(hour=1, minute=0, day_of_week='saturday'),
            'options': {'queue': 'exploitation'},
        },

        # ── Alertas pre-ataque (Viernes noche → Sábado madrugada) ──
        'alert-preattack-5h': {
            'task': 'services.exploit_engine.alert_tasks.alert_preattack_5h',
            'schedule': crontab(hour=20, minute=0, day_of_week='friday'),
            'options': {'queue': 'exploitation'},
        },
        'alert-preattack-4h': {
            'task': 'services.exploit_engine.alert_tasks.alert_preattack_4h',
            'schedule': crontab(hour=21, minute=0, day_of_week='friday'),
            'options': {'queue': 'exploitation'},
        },
        'alert-preattack-3h': {
            'task': 'services.exploit_engine.alert_tasks.alert_preattack_3h',
            'schedule': crontab(hour=22, minute=0, day_of_week='friday'),
            'options': {'queue': 'exploitation'},
        },
        'alert-preattack-2h': {
            'task': 'services.exploit_engine.alert_tasks.alert_preattack_2h',
            'schedule': crontab(hour=23, minute=0, day_of_week='friday'),
            'options': {'queue': 'exploitation'},
        },
        'alert-preattack-1h': {
            'task': 'services.exploit_engine.alert_tasks.alert_preattack_1h',
            'schedule': crontab(hour=0, minute=0, day_of_week='saturday'),
            'options': {'queue': 'exploitation'},
        },
        'alert-preattack-30m': {
            'task': 'services.exploit_engine.alert_tasks.alert_preattack_30m',
            'schedule': crontab(hour=0, minute=30, day_of_week='saturday'),
            'options': {'queue': 'exploitation'},
        },
        'alert-preattack-10m': {
            'task': 'services.exploit_engine.alert_tasks.alert_preattack_10m',
            'schedule': crontab(hour=0, minute=50, day_of_week='saturday'),
            'options': {'queue': 'exploitation'},
        },
        'alert-preattack-5m': {
            'task': 'services.exploit_engine.alert_tasks.alert_preattack_5m',
            'schedule': crontab(hour=0, minute=55, day_of_week='saturday'),
            'options': {'queue': 'exploitation'},
        },

        # PHASE 5 — Sunday 08:00 Madrid
        # M7: generate full audit report ZIP
        'phase5-reporting-sunday': {
            'task': 'services.reporting_engine.tasks.generate_weekly_report',
            'schedule': crontab(hour=8, minute=0, day_of_week='sunday'),
            'options': {'queue': 'reporting'},
        },
    },

    # --- Task queues ---
    task_queues={
        'discovery':       {'routing_key': 'discovery'},
        'vulnerabilities': {'routing_key': 'vulnerabilities'},
        'heavy_scans':     {'routing_key': 'heavy_scans'},
        'ai_reasoning':    {'routing_key': 'ai_reasoning'},
        'exploitation':    {'routing_key': 'exploitation'},
        'reporting':       {'routing_key': 'reporting'},
        'celery':          {'routing_key': 'celery'},
    },

    # --- Task routing ---
    task_routes={
        'services.asset_manager.tasks.discovery.*':   {'queue': 'discovery'},
        'services.recon_engine.tasks.scan_tasks.*':   {'queue': 'discovery'},
        'services.scanner_engine.tasks.vuln_tasks.*': {'queue': 'vulnerabilities'},
        'services.ai_reasoning.tasks.*':              {'queue': 'ai_reasoning'},
        'services.exploit_engine.tasks.*':            {'queue': 'exploitation'},
        'services.reporting_engine.tasks.*':          {'queue': 'reporting'},
        'scanner.openvas.scan_asset':                 {'queue': 'heavy_scans'},
    },
)
