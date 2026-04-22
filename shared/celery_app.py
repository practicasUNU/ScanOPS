from celery import Celery
from shared.config import settings

app = Celery(
    "scanops",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["services.asset_manager.tasks.discovery"]
)

app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)