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
        "services.scanner_engine.tasks.vuln_tasks",
        "services.ai_reasoning.tasks"
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
    task_time_limit=300,        
    task_soft_time_limit=270,   
    
    # 👇 AÑADE ESTAS DOS LÍNEAS 👇
    task_track_started=True,    # Obliga a Celery a cambiar el estado a 'STARTED'
    result_extended=True,       # Guarda metadatos extra para que FastAPI no se líe
    # 👆 ---------------------- 👆

    # ESTO CUMPLE LA US-2.7 (Programación automática)
    beat_schedule={
        'recon-lunes-madrugada': {
            'task': 'services.recon_engine.tasks.scan_tasks.run_recon_complete',
            'schedule': 604800.0, 
        },
    },
    # US-3.4: Definición de colas para paralelismo
    task_queues = {
        'discovery': {'routing_key': 'discovery'},
        'vulnerabilities': {'routing_key': 'vulnerabilities'},
        'heavy_scans': {'routing_key': 'heavy_scans'}, 
    },
    # Mapeo de tareas a colas
    task_routes = {
        'tasks.run_network_discovery': {'queue': 'discovery'},
        'tasks.run_nuclei_vulnerability_scan': {'queue': 'vulnerabilities'},
        'tasks.run_nikto_vulnerability_scan': {'queue': 'vulnerabilities'},
        'run_recon_complete': {'queue': 'discovery'},
        'scanner.openvas.scan_asset': {'queue': 'heavy_scans'},
    }
)