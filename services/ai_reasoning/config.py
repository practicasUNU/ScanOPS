import os
from datetime import timedelta

# Redis
REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_FINDINGS_CHANNEL: str = os.getenv("REDIS_FINDINGS_CHANNEL", "findings:scan:*")
REDIS_TIMEOUT: float = float(os.getenv("REDIS_TIMEOUT", "30.0"))

# Streaming Processor
STREAMING_PROCESSOR_ENABLED: bool = os.getenv("STREAMING_PROCESSOR_ENABLED", "true") == "true"
STREAMING_BATCH_SIZE: int = int(os.getenv("STREAMING_BATCH_SIZE", "10"))
STREAMING_TIMEOUT: float = float(os.getenv("STREAMING_TIMEOUT", "300.0"))
STREAMING_RETRY_ATTEMPTS: int = int(os.getenv("STREAMING_RETRY_ATTEMPTS", "3"))
STREAMING_RETRY_DELAY = timedelta(seconds=int(os.getenv("STREAMING_RETRY_DELAY", "60")))
