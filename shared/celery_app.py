from celery import Celery
from shared.config import settings

# Asegúrate de que en tu .env o settings, redis_url sea:
# redis://localhost:6380/0

# shared/celery_app.py
app = Celery(
    "scanops",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "services.asset_manager.tasks.discovery",
        "services.recon_engine.tasks.scan_tasks",
        "services.scanner_engine.tasks.vuln_tasks" # Nueva línea
    ]
)

app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Europe/Madrid', # Ajustado a tu zona
    enable_utc=True,
    # ESTO CUMPLE LA US-2.7 (Programación automática)
    beat_schedule={
        'recon-lunes-madrugada': {
            'task': 'services.recon_engine.tasks.scan_tasks.run_recon_complete',
            'schedule': 604800.0, # Una vez a la semana (o usa crontab)
        },
    },
    # US-3.4: Definición de colas para paralelismo
    task_queues = {
        'discovery': {'routing_key': 'discovery'},
        'vulnerabilities': {'routing_key': 'vulnerabilities'},
        'heavy_scans': {'routing_key': 'heavy_scans'}, # Para OpenVAS
    },
    # Mapeo de tareas a colas
    task_routes = {
        'tasks.run_network_discovery': {'queue': 'discovery'},
        'tasks.run_nuclei_vulnerability_scan': {'queue': 'vulnerabilities'},
        'run_recon_complete': {'queue': 'discovery'},
    }
)