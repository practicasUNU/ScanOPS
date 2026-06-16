"""
vhost Fuzzer — M2 Recon Engine Service
Fuzzing de virtual hosts con filtrado por baseline Content-Length para
eliminar falsos positivos (misma respuesta que el host por defecto).
Intenta usar ffuf si está disponible; fallback a Python puro con aiohttp.
ENS: op.exp.2 (descubrimiento de superficie de ataque)
"""
import asyncio
import json
import os
import re
import tempfile
from typing import List, Optional

from shared.scan_logger import ScanLogger

logger = ScanLogger("vhost_fuzzer")

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

_WORDLIST_PATHS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt",
    "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt",
]

_BUILTIN_VHOSTS = [
    "www", "admin", "api", "app", "dev", "staging", "test", "mail", "webmail",
    "smtp", "pop", "imap", "ftp", "ssh", "vpn", "portal", "dashboard",
    "internal", "intranet", "gitlab", "github", "jenkins", "ci", "cd",
    "monitoring", "metrics", "grafana", "prometheus", "kibana", "elastic",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "backup", "static", "cdn", "assets", "media", "upload", "files",
    "docs", "documentation", "status", "health", "ops", "devops",
    "sysadmin", "helpdesk", "support", "crm", "erp", "hr", "finance",
    "shop", "store", "checkout", "payment", "auth", "login", "sso",
    "ldap", "ad", "exchange", "sharepoint", "office", "wiki",
    "confluence", "jira", "beta", "alpha", "preview", "uat", "qa",
    "sandbox", "demo", "old", "legacy", "v1", "v2", "api2", "apidev",
    "git", "svn", "repo", "registry", "docker", "k8s", "kubernetes",
    "traefik", "nginx", "haproxy", "lb", "proxy",
]

_MAX_VHOSTS = 100
_BASELINE_DIFF_THRESHOLD = 50  # bytes — diferencia mínima para considerar vhost distinto


def _load_wordlist() -> List[str]:
    for path in _WORDLIST_PATHS:
        if os.path.isfile(path):
            try:
                with open(path, "r", errors="ignore") as f:
                    names = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
                    return names[:1000]
            except Exception:
                pass
    return list(_BUILTIN_VHOSTS)


async def _ffuf_available() -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            "ffuf", "-version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0
    except FileNotFoundError:
        return False


async def _ffuf_vhost_fuzz(target: str, port: int, scheme: str, vhosts: List[str]) -> List[str]:
    wl_fd, wl_path = tempfile.mkstemp(suffix=".txt")
    out_fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(wl_fd)
    os.close(out_fd)

    try:
        with open(wl_path, "w") as f:
            for vhost in vhosts:
                f.write(vhost + "\n")

        url = f"{scheme}://{target}:{port}/"
        cmd = [
            "ffuf",
            "-u", url,
            "-H", f"Host: FUZZ.{target}",
            "-w", wl_path,
            "-o", out_path,
            "-of", "json",
            "-mc", "200,201,301,302,401,403",
            "-t", "20",
            "-timeout", "5",
            "-rate", "50",
            "-s",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=90)

        with open(out_path, "r", errors="ignore") as f:
            raw = f.read().strip()
        if not raw:
            return []
        data = json.loads(raw)
        discovered = []
        for result in data.get("results", []):
            name = result.get("input", {}).get("FUZZ", "")
            if name:
                discovered.append(f"{name}.{target}")
        return discovered

    except asyncio.TimeoutError:
        logger.warning("VHOST_FFUF_TIMEOUT", target=target)
        return []
    except Exception as e:
        logger.debug("VHOST_FFUF_ERROR", target=target, error=str(e))
        return []
    finally:
        for path in (wl_path, out_path):
            try:
                os.unlink(path)
            except Exception:
                pass


async def _python_vhost_fuzz(target: str, port: int, scheme: str, vhosts: List[str]) -> List[str]:
    """
    Fallback puro Python usando aiohttp.
    Baseline: primer request con nombre de host inexistente.
    Solo marca como descubierto si la respuesta difiere del baseline en
    más de _BASELINE_DIFF_THRESHOLD bytes.
    """
    import aiohttp

    url = f"{scheme}://{target}:{port}/"
    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    timeout_cfg = aiohttp.ClientTimeout(total=5, connect=3)
    discovered = []

    async with aiohttp.ClientSession(connector=connector, timeout=timeout_cfg) as session:
        # Baseline — host inexistente para obtener longitud de respuesta por defecto
        baseline_len: int = -1
        try:
            async with session.get(
                url,
                headers={
                    "Host": f"nonexistent-baseline-fuzz.{target}",
                    "User-Agent": "Mozilla/5.0 (compatible; ScanOPS-vhost-fuzzer/1.0)",
                },
                allow_redirects=False,
                ssl=False,
            ) as resp:
                body = await resp.read()
                baseline_len = len(body)
                logger.info("VHOST_BASELINE", target=target, port=port, baseline_bytes=baseline_len)
        except Exception:
            logger.debug("VHOST_BASELINE_FAILED", target=target, port=port)

        async def _probe(vhost_name: str) -> Optional[str]:
            host_header = f"{vhost_name}.{target}"
            try:
                async with session.get(
                    url,
                    headers={
                        "Host": host_header,
                        "User-Agent": "Mozilla/5.0 (compatible; ScanOPS-vhost-fuzzer/1.0)",
                    },
                    allow_redirects=False,
                    ssl=False,
                ) as resp:
                    body = await resp.read()
                    cl = len(body)
                    diff = abs(cl - baseline_len) if baseline_len >= 0 else cl
                    if diff > _BASELINE_DIFF_THRESHOLD and resp.status in (200, 201, 301, 302, 401, 403):
                        return host_header
            except Exception:
                pass
            return None

        batch_size = 20
        for i in range(0, len(vhosts), batch_size):
            batch = vhosts[i:i + batch_size]
            results = await asyncio.gather(*[_probe(v) for v in batch], return_exceptions=True)
            for r in results:
                if isinstance(r, str):
                    discovered.append(r)

    return discovered


async def fuzz_vhosts(target: str, web_ports: Optional[List[int]] = None) -> List[str]:
    """
    Punto de entrada principal.
    Solo opera sobre hostname/dominio — las IPs puras no tienen vhosts con nombre.
    Devuelve lista de FQDNs descubiertos (ej: 'admin.example.com').
    """
    if not target or _IP_RE.match(target):
        return []

    if not web_ports:
        web_ports = [80]

    wordlist = _load_wordlist()
    use_ffuf = await _ffuf_available()
    all_discovered: List[str] = []

    for port in web_ports[:2]:  # Máximo 2 puertos para no alargar M2
        scheme = "https" if port in (443, 8443) else "http"
        logger.info(
            "VHOST_FUZZ_START",
            target=target,
            port=port,
            wordlist_size=len(wordlist),
            engine="ffuf" if use_ffuf else "python",
        )

        if use_ffuf:
            found = await _ffuf_vhost_fuzz(target, port, scheme, wordlist)
        else:
            found = await _python_vhost_fuzz(target, port, scheme, wordlist)

        logger.info("VHOST_FUZZ_DONE", target=target, port=port, found=len(found))

        for vh in found:
            if vh not in all_discovered:
                all_discovered.append(vh)

    return all_discovered[:_MAX_VHOSTS]
