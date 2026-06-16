"""
Threat Intelligence Clients — M3.1 FASE 3
==========================================
Sync HTTP clients for VirusTotal, CrowdSec CTI and AlienVault OTX.
Circuit breakers via pybreaker (optional — degrades gracefully if absent).
VT free tier is rate-limited to 4 req/min; a thread-safe bucket enforces this.

Sources:
  VirusTotal v3  — IP/domain/file reputation (30-day TTL)
  CrowdSec CTI v2 — IP reputation + attack behaviors (12-hour TTL)
  AlienVault OTX — Threat pulses for IP/domain/file (7-day TTL)
"""
from __future__ import annotations

import os
import threading
import time
from typing import Dict, Optional

import requests

try:
    import pybreaker
    _HAS_PYBREAKER = True
except ImportError:  # pybreaker not installed — circuit breakers disabled
    _HAS_PYBREAKER = False

from shared.scan_logger import ScanLogger

logger = ScanLogger("threat_intel_client")

# ── Config from env ────────────────────────────────────────────────────────────

VT_API_KEY        = os.getenv("VIRUSTOTAL_API_KEY", "")
CROWDSEC_API_KEY  = os.getenv("CROWDSEC_API_KEY", "")
OTX_API_KEY       = os.getenv("OTX_API_KEY", "")

VT_TTL_DAYS        = int(os.getenv("EDR_THREAT_INTEL_TTL_VT_DAYS", "30"))
CROWDSEC_TTL_HOURS = int(os.getenv("EDR_THREAT_INTEL_TTL_CROWDSEC_HOURS", "12"))
OTX_TTL_DAYS       = int(os.getenv("EDR_THREAT_INTEL_TTL_OTX_DAYS", "7"))

_CB_FAIL_MAX      = int(os.getenv("EDR_CIRCUIT_BREAKER_FAIL_MAX", "5"))
_CB_RESET_TIMEOUT = int(os.getenv("EDR_CIRCUIT_BREAKER_RESET_TIMEOUT", "60"))


# ── Circuit breaker factory ────────────────────────────────────────────────────

def _make_breaker(name: str):
    if _HAS_PYBREAKER:
        return pybreaker.CircuitBreaker(
            fail_max=_CB_FAIL_MAX,
            reset_timeout=_CB_RESET_TIMEOUT,
            name=name,
        )
    return None


_vt_cb       = _make_breaker("virustotal")
_crowdsec_cb = _make_breaker("crowdsec")
_otx_cb      = _make_breaker("otx")


# ── VT rate limiter — 4 req / 60 s ────────────────────────────────────────────

class _VTRateLimiter:
    """Thread-safe sliding-window limiter: at most MAX_PER_MIN calls per 60 s."""
    _lock = threading.Lock()
    _timestamps: list[float] = []
    MAX_PER_MIN = 4

    @classmethod
    def acquire(cls) -> None:
        with cls._lock:
            now = time.monotonic()
            cls._timestamps = [t for t in cls._timestamps if now - t < 60.0]
            if len(cls._timestamps) >= cls.MAX_PER_MIN:
                wait = 60.0 - (now - cls._timestamps[0]) + 0.1
                if wait > 0:
                    time.sleep(wait)
                cls._timestamps = cls._timestamps[1:]
            cls._timestamps.append(time.monotonic())


# ── VirusTotal v3 ──────────────────────────────────────────────────────────────

class VirusTotalClient:
    _BASE = "https://www.virustotal.com/api/v3"

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        return self._call(f"{self._BASE}/ip_addresses/{ip}")

    def lookup_domain(self, domain: str) -> Optional[Dict]:
        return self._call(f"{self._BASE}/domains/{domain}")

    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        return self._call(f"{self._BASE}/files/{file_hash}")

    def _call(self, url: str) -> Optional[Dict]:
        if not VT_API_KEY:
            return None

        def _do() -> Optional[Dict]:
            _VTRateLimiter.acquire()
            resp = requests.get(
                url,
                headers={"x-apikey": VT_API_KEY},
                timeout=15,
            )
            if resp.status_code == 200:
                return self._parse(resp.json())
            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                logger.warning("VT_RATE_LIMITED", url=url)
                return None
            logger.warning("VT_HTTP_ERROR", status=resp.status_code)
            resp.raise_for_status()
            return None

        try:
            if _vt_cb:
                return _vt_cb.call(_do)
            return _do()
        except Exception as exc:
            logger.warning("VT_CALL_FAILED", url=url, error=str(exc))
            return None

    @staticmethod
    def _parse(raw: Dict) -> Optional[Dict]:
        try:
            stats = raw["data"]["attributes"].get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
        except (KeyError, TypeError):
            return None


# ── CrowdSec CTI v2 ────────────────────────────────────────────────────────────

class CrowdSecClient:
    _BASE = "https://cti.api.crowdsec.net/v2"

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        if not CROWDSEC_API_KEY:
            return None

        url = f"{self._BASE}/smoke/{ip}"

        def _do() -> Optional[Dict]:
            resp = requests.get(
                url,
                headers={"x-api-key": CROWDSEC_API_KEY},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "reputation":     data.get("reputation", "unknown"),
                    "behaviors":      [b.get("label", "") for b in data.get("behaviors", [])],
                    "attack_details": data.get("attack_details", []),
                }
            if resp.status_code == 404:
                return {"reputation": "unknown", "behaviors": []}
            logger.warning("CROWDSEC_HTTP_ERROR", status=resp.status_code)
            resp.raise_for_status()
            return None

        try:
            if _crowdsec_cb:
                return _crowdsec_cb.call(_do)
            return _do()
        except Exception as exc:
            logger.warning("CROWDSEC_CALL_FAILED", ip=ip, error=str(exc))
            return None


# ── AlienVault OTX ────────────────────────────────────────────────────────────

class OTXClient:
    _BASE = "https://otx.alienvault.com/api/v1"

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        return self._call(f"{self._BASE}/indicators/IPv4/{ip}/general")

    def lookup_domain(self, domain: str) -> Optional[Dict]:
        return self._call(f"{self._BASE}/indicators/domain/{domain}/general")

    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        return self._call(f"{self._BASE}/indicators/file/{file_hash}/general")

    def _call(self, url: str) -> Optional[Dict]:
        if not OTX_API_KEY:
            return None

        def _do() -> Optional[Dict]:
            resp = requests.get(
                url,
                headers={"X-OTX-API-KEY": OTX_API_KEY},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                pulse_info = data.get("pulse_info", {})
                return {
                    "pulse_count": pulse_info.get("count", 0),
                    "reputation":  data.get("reputation", 0),
                    "type_title":  data.get("type_title", ""),
                }
            if resp.status_code == 404:
                return {"pulse_count": 0, "reputation": 0}
            logger.warning("OTX_HTTP_ERROR", status=resp.status_code)
            resp.raise_for_status()
            return None

        try:
            if _otx_cb:
                return _otx_cb.call(_do)
            return _do()
        except Exception as exc:
            logger.warning("OTX_CALL_FAILED", url=url, error=str(exc))
            return None
