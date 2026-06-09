"""
WhatWeb Client - Technology Fingerprinting - Scanner Engine M3
Identifica CMS, frameworks, servidores web y versiones para enriquecer el contexto de M8.
"""

import subprocess
import json
import os
from typing import List, Dict

from shared.scan_logger import ScanLogger

logger = ScanLogger("whatweb_client")

MEDIUM_SEVERITY_PLUGINS = {
    "WordPress", "Joomla", "Drupal", "Laravel", "Django", "Rails",
    "jQuery", "PHP", "Apache", "nginx",
}


def _extract_version(plugin_data) -> str | None:
    if isinstance(plugin_data, list):
        for entry in plugin_data:
            if isinstance(entry, dict):
                v = entry.get("version") or entry.get("string")
                if v:
                    return str(v)
    if isinstance(plugin_data, dict):
        return plugin_data.get("version") or plugin_data.get("string")
    return None


def _assign_severity(plugin_name: str, version) -> str:
    if plugin_name in MEDIUM_SEVERITY_PLUGINS and version:
        return "MEDIUM"
    return "INFO"


def run_whatweb_scan(asset_id: int, target_url: str) -> List[Dict]:
    logger.info("WHATWEB_START", target=target_url)
    output_file = f"/tmp/whatweb_output_{os.getpid()}.json"

    try:
        cmd = [
            "whatweb",
            f"--log-json={output_file}",
            "--aggression=3",
            "--quiet",
            "--no-errors",
            target_url,
        ]

        subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        findings = []
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                raw = f.read().strip()
            if not raw:
                logger.warning("WHATWEB_EMPTY_OUTPUT", target=target_url)
                return []

            parsed_entries = []
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed_entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

            if not parsed_entries:
                try:
                    fallback = json.loads(raw)
                    if isinstance(fallback, list):
                        parsed_entries = fallback
                    elif isinstance(fallback, dict):
                        parsed_entries = [fallback]
                except json.JSONDecodeError:
                    logger.warning("WHATWEB_NO_PARSEABLE_OUTPUT", target=target_url)
                    return []

            for entry in parsed_entries:
                target = entry.get("target", target_url)
                plugins = entry.get("plugins", {})
                for plugin_name, plugin_data in plugins.items():
                    version = _extract_version(plugin_data)
                    severity = _assign_severity(plugin_name, version)
                    title = f"Technology Detected: {plugin_name}"
                    if version:
                        title += f" {version}"
                    findings.append({
                        "title": title,
                        "severity": severity,
                        "description": "Technology fingerprint detected on target. Useful for M8 reasoning context.",
                        "cve_id": None,
                        "evidence": {"plugin": plugin_name, "version": version, "target": target},
                        "remediation": "Hide version disclosure in HTTP headers and meta tags if not necessary.",
                        "ens_measure": "op.exp.2",
                        "scanner": "whatweb",
                    })

        logger.info("WHATWEB_FINISH", target=target_url, count=len(findings))
        return findings

    except subprocess.TimeoutExpired:
        logger.error("WHATWEB_TIMEOUT", target=target_url)
        return []
    except FileNotFoundError:
        logger.error("WHATWEB_NOT_FOUND", target=target_url)
        return []
    except Exception as e:
        logger.error("WHATWEB_ERROR", target=target_url, error=str(e))
        return []
    finally:
        if os.path.exists(output_file):
            os.remove(output_file)
