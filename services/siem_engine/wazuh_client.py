"""Wazuh API client helper reutilizable para todos los módulos de M5."""
import os
import httpx

WAZUH_API = os.getenv("WAZUH_API_URL", "https://wazuh-manager:55000")
_WAZUH_USER = os.getenv("WAZUH_USER", "wazuh")
_WAZUH_PASS = os.getenv("WAZUH_PASSWORD", "wazuh")


def new_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=False, timeout=30.0)


async def get_token(client: httpx.AsyncClient) -> str:
    resp = await client.get(
        f"{WAZUH_API}/security/user/authenticate",
        auth=(_WAZUH_USER, _WAZUH_PASS),
    )
    resp.raise_for_status()
    return resp.json()["data"]["token"]


async def wazuh_get(path: str) -> dict:
    async with new_client() as c:
        token = await get_token(c)
        resp = await c.get(
            f"{WAZUH_API}{path}",
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        return resp.json()


async def wazuh_post(path: str, body: dict) -> dict:
    async with new_client() as c:
        token = await get_token(c)
        resp = await c.post(
            f"{WAZUH_API}{path}",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        return resp.json()
