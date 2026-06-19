import asyncio

import httpx

import os

SERVICE_URLS: dict[str, str] = {
    "M1": os.getenv("M1_URL", "http://m1:8001") + "/health",
    "M2": os.getenv("M2_URL", "http://m2:8003") + "/health",
    "M3": os.getenv("M3_URL", "http://scanner-engine:8002") + "/health",
    "M4": os.getenv("M4_URL", "http://m4:8004") + "/health",
    "M5": os.getenv("M5_URL", "http://m5:8006") + "/health",
    "M7": os.getenv("M7_URL", "http://m7:8000") + "/health",
    "M8": os.getenv("M8_URL", "http://m8:8005") + "/health",
}


async def _ping(client: httpx.AsyncClient, module_id: str, url: str) -> tuple[str, str]:
    try:
        response = await client.get(url, timeout=2.0)
        status = "online" if response.status_code < 500 else "offline"
    except Exception:
        status = "offline"
    return module_id, status


async def check_all_modules() -> dict[str, str]:
    """
    Pings all module /health endpoints concurrently.
    Returns dict: {"M1": "online"|"offline", ...}
    Timeout per request: 2 seconds.
    Never raises — always returns dict even if all fail.
    """
    async with httpx.AsyncClient() as client:
        tasks = [_ping(client, mid, url) for mid, url in SERVICE_URLS.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    health: dict[str, str] = {}
    for i, result in enumerate(results):
        module_id = list(SERVICE_URLS.keys())[i]
        if isinstance(result, Exception):
            health[module_id] = "offline"
        else:
            health[module_id] = result[1]
    return health
