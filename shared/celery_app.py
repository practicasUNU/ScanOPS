from celery import Celery
from shared.config import settings

# Asegúrate de que en tu .env o settings, redis_url sea:
# redis://localhost:6380/0

app = Celery(
    "scanops",
    broker=settings.redis_url,
    backend=settings.redis_url,
    # AÑADIMOS la ruta de las tasks del M2 aquí:
    include=[
        "services.asset_manager.tasks.discovery", 
        "services.recon_engine.tasks.scan_tasks"
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
)