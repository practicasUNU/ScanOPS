"""
IOC Extractor — M3.1 FASE 3
Extract Indicators of Compromise from behavioral finding indicators.
Handles IPv4, public domains and file hashes (MD5/SHA1/SHA256).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Set

# IPv4 — strict octet boundaries
_RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# Domains: common TLDs including typical C2/malware-favoured registrars
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:'
    r'com|net|org|io|info|biz|co|uk|de|fr|es|ru|cn|'
    r'tk|ga|ml|cf|gq|pw|xyz|top|site|online|click|download|duckdns'
    r')\b',
    re.IGNORECASE,
)

# MD5 (32), SHA1 (40), SHA256 (64) — full hex word
_RE_HASH = re.compile(r'\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b')

# RFC-1918 + loopback + link-local — never query threat intel for these
_PRIVATE_PREFIXES = (
    '10.', '127.', '0.', '169.254.',
    '192.168.',
    '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.',
    '172.24.', '172.25.', '172.26.', '172.27.',
    '172.28.', '172.29.', '172.30.', '172.31.',
)

_EXCLUDED_DOMAINS = frozenset({'localhost', 'localdomain', 'local', 'internal'})


@dataclass(frozen=True)
class IOC:
    value:    str
    ioc_type: str   # 'ip' | 'domain' | 'hash'


def extract_iocs(indicators: dict | None) -> List[IOC]:
    """
    Parse IOCs out of a behavioral finding's indicators dict.
    Inspects: indicators.cmdline, indicators.matched (list).
    Returns deduplicated list ordered: IPs → domains → hashes.
    """
    if not indicators:
        return []

    text_parts: List[str] = []
    if isinstance(indicators.get("cmdline"), str):
        text_parts.append(indicators["cmdline"])
    if isinstance(indicators.get("matched"), list):
        text_parts.extend(str(m) for m in indicators["matched"])

    combined = " ".join(text_parts)
    if not combined.strip():
        return []

    found_ips:     Set[str] = set()
    found_domains: Set[str] = set()
    found_hashes:  Set[str] = set()

    for ip in _RE_IPV4.findall(combined):
        if not any(ip.startswith(p) for p in _PRIVATE_PREFIXES):
            found_ips.add(ip)

    for domain in _RE_DOMAIN.findall(combined):
        dl = domain.lower()
        if dl not in _EXCLUDED_DOMAINS:
            found_domains.add(dl)

    for h in _RE_HASH.findall(combined):
        found_hashes.add(h.lower())

    result: List[IOC] = []
    result.extend(IOC(value=ip, ioc_type='ip')     for ip in sorted(found_ips))
    result.extend(IOC(value=d,  ioc_type='domain') for d  in sorted(found_domains))
    result.extend(IOC(value=h,  ioc_type='hash')   for h  in sorted(found_hashes))
    return result
