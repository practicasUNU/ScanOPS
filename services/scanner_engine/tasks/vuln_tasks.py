"""
Celery tasks for vulnerability scanning orchestration — M3.
Flujo orquestado: OpenVAS + Nuclei + ZAP con merge de resultados y stats.
"""

import asyncio
import logging
import time
from typing import Dict, List, Any
from datetime import datetime, timezone
from celery import group, chord
from sqlalchemy.dialects.postgresql import insert as pg_insert
from celery.exceptions import SoftTimeLimitExceeded

from shared.celery_app import app
from shared.database import SessionLocal
from shared.scan_logger import ScanLogger
from services.scanner_engine.models.vulnerability import VulnFinding
from services.scanner_engine.services.nuclei_wrapper import run_nuclei_scan as execute_nuclei_binary
from services.scanner_engine.clients.nmap_client import run_nmap_scan, extract_http_ports
from services.scanner_engine.clients.ffuf_client import run_ffuf_scan
from services.scanner_engine.clients.whatweb_client import run_whatweb_scan
from services.scanner_engine.clients.testssl_client import run_testssl_scan

logger = ScanLogger("scanner_tasks")

# --- TAREA: NUCLEI (US-3.2) ---
@app.task(name="tasks.run_nuclei_vulnerability_scan", queue="vulnerabilities")
def run_nuclei_task(asset_id: int, ip: str, hostname: str = None) -> List[Dict]:
    """Ejecuta Nuclei y devuelve hallazgos sin persistir (el orquestador persiste)."""
    logger.info("NUCLEI_TASK_START", asset_id=asset_id, target=ip)
    try:
        findings = execute_nuclei_binary(ip, hostname)
        return [{"scanner": "Nuclei", **f} for f in findings]
    except Exception as e:
        logger.error("NUCLEI_TASK_ERROR", error=str(e))
        return []

@app.task(name="tasks.run_nmap_vulnerability_scan", queue="vulnerabilities")
def run_nmap_task(asset_id: int, ip: str) -> List[Dict]:
    """Ejecuta Nmap NSE y devuelve hallazgos sin persistir."""
    logger.info("NMAP_TASK_START", asset_id=asset_id, target=ip)
    try:
        findings = run_nmap_scan(asset_id, ip)
        return findings
    except Exception as e:
        logger.error("NMAP_TASK_ERROR", error=str(e))
        return []

# --- TAREA: OPENVAS (US-3.1) ---
@app.task(name="scanner.openvas.scan_asset", queue="heavy_scans",
          time_limit=1800, soft_time_limit=1750)
def run_openvas_scan(asset_id: int, asset_ip: str, asset_name: str) -> List[Dict]:
    """Ejecuta OpenVAS real y devuelve hallazgos normalizados."""
    logger.info("OPENVAS_TASK_START", ip=asset_ip)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        from services.scanner_engine.clients.openvas_client import get_openvas_client
        client = loop.run_until_complete(get_openvas_client())
        findings = loop.run_until_complete(client.scan_asset(asset_id, asset_ip, asset_name))
        return [{"scanner": "OpenVAS", **f.to_dict()} for f in findings]
    except SoftTimeLimitExceeded:
        logger.error("OPENVAS_TASK_TIMEOUT", ip=asset_ip)
        return []
    except Exception as e:
        logger.error("OPENVAS_TASK_ERROR", error=str(e))
        return []
    finally:
        loop.close()


@app.task(name="tasks.run_nikto_vulnerability_scan", queue="vulnerabilities")
def run_nikto_task(asset_id: int, ip: str, port: int = 80) -> List[Dict]:
    from services.scanner_engine.clients.nikto_client import run_nikto_scan
    scheme = "https" if port == 443 else "http"
    target_url = f"{scheme}://{ip}:{port}"
    logger.info("NIKTO_TASK_START", target=target_url)
    try:
        findings = run_nikto_scan(asset_id, target_url)
        tagged = []
        for f in findings:
            evidence = dict(f.get("evidence", {}))
            evidence["port"] = str(port)
            evidence["target"] = target_url
            desc = f.get("description", "")
            tagged.append({
                **f,
                "scanner": "Nikto",
                "evidence": evidence,
                "description": f"[Port {port}] {desc}" if f":{port}" not in desc else desc,
            })
        return tagged
    except Exception as e:
        logger.error("NIKTO_TASK_ERROR", error=str(e))
        return []

# --- TAREA: FFUF (endpoint fuzzing) ---
@app.task(name="tasks.run_ffuf_scan", queue="vulnerabilities")
def run_ffuf_task(asset_id: int, ip: str, port: int = 80) -> List[Dict]:
    scheme = "https" if port == 443 else "http"
    target_url = f"{scheme}://{ip}:{port}"
    logger.info("FFUF_TASK_START", asset_id=asset_id, target=target_url)
    try:
        findings = run_ffuf_scan(asset_id, target_url)
        tagged = []
        for f in findings:
            evidence = dict(f.get("evidence", {}))
            evidence["port"] = str(port)
            evidence["target"] = target_url
            desc = f.get("description", "")
            tagged.append({
                **f,
                "scanner": "ffuf",
                "evidence": evidence,
                "description": f"[Port {port}] {desc}" if f":{port}" not in desc else desc,
            })
        return tagged
    except Exception as e:
        logger.error("FFUF_TASK_ERROR", error=str(e))
        return []

# --- TAREA: WHATWEB (technology fingerprinting) ---
@app.task(name="tasks.run_whatweb_scan", queue="vulnerabilities")
def run_whatweb_task(asset_id: int, ip: str) -> List[Dict]:
    logger.info("WHATWEB_TASK_START", asset_id=asset_id, target=ip)
    try:
        # Try HTTPS first (most modern servers), fall back to HTTP
        https_findings = run_whatweb_scan(asset_id, f"https://{ip}")
        if https_findings:
            return [{"scanner": "whatweb", **f} for f in https_findings]
        http_findings = run_whatweb_scan(asset_id, f"http://{ip}")
        return [{"scanner": "whatweb", **f} for f in http_findings]
    except Exception as e:
        logger.error("WHATWEB_TASK_ERROR", error=str(e))
        return []

# --- TAREA: TESTSSL (TLS/SSL deep analysis) ---
@app.task(name="tasks.run_testssl_scan", queue="vulnerabilities")
def run_testssl_task(asset_id: int, ip: str) -> List[Dict]:
    logger.info("TESTSSL_TASK_START", asset_id=asset_id, target=ip)
    try:
        # testssl always targets HTTPS; run_testssl_scan handles port extraction internally
        findings = run_testssl_scan(asset_id, f"https://{ip}")
        if not findings:
            logger.info("TESTSSL_NO_FINDINGS_ON_443", target=ip)
        return [{"scanner": "testssl", **f} for f in findings]
    except Exception as e:
        logger.error("TESTSSL_TASK_ERROR", error=str(e))
        return []

# --- CALLBACK: MERGE & PERSIST con deduplicación (US-3.4) ---
@app.task(name="tasks.merge_and_persist_results")
def merge_and_persist_results(results_list: List[List[Dict]], asset_id: int):
    """
    Recibe los resultados de todos los scanners, los une, persiste con upsert
    y genera stats. Deduplicación por (asset_id, vulnerability_id, scanner_name,
    affected_port) — evita duplicados entre runs sucesivos.
    """
    all_findings = [finding for sublist in results_list for finding in sublist]
    db = SessionLocal()
    scan_id = f"scan_multi_{int(time.time())}"
    stats = {"total": 0, "new": 0, "updated": 0,
             "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    try:
        for f in all_findings:
            severity = f.get("severity", "INFO").upper()
            raw_evidence = f.get("evidence", {})
            evidence = raw_evidence if isinstance(raw_evidence, dict) else {"raw": str(raw_evidence)}

            # Puerto: extraer de evidence si no viene en el finding directamente
            affected_port = f.get("affected_port") or f.get("port")
            if not affected_port:
                port_raw = evidence.get("port")
                try:
                    affected_port = int(port_raw) if port_raw else None
                except (ValueError, TypeError):
                    affected_port = None

            vulnerability_id = (f.get("cve_id") or f.get("vulnerability_id") or "VULN_GENERIC")[:32]
            scanner_name     = f.get("scanner", "Generic")[:32]

            stmt = pg_insert(VulnFinding).values(
                asset_id         = asset_id,
                scan_id          = scan_id,
                vulnerability_id = vulnerability_id,
                title            = f.get("title", "Unknown Vulnerability")[:255],
                severity         = severity[:16],
                description      = f.get("description", ""),
                scanner_name     = scanner_name,
                evidence         = evidence,
                created_by       = "system-orchestrator",
                cvss_v3_score    = f.get("cvss_score"),
                scanner_reference= (f.get("cve_id") or "")[:128],
                affected_port    = affected_port,
                last_verified_at = datetime.now(timezone.utc),
            ).on_conflict_do_update(
                index_elements   = ['asset_id', 'vulnerability_id',
                                    'scanner_name', 'affected_port'],
                set_=dict(
                    last_verified_at = datetime.now(timezone.utc),
                    evidence         = evidence,
                    description      = f.get("description", ""),
                    severity         = severity[:16],
                    scan_id          = scan_id,
                    updated_by       = "system-orchestrator",
                )
            )

            result = db.execute(stmt)
            stats["total"] += 1
            if result.inserted_primary_key and result.inserted_primary_key[0]:
                stats["new"] += 1
            else:
                stats["updated"] += 1
            if severity in stats:
                stats[severity] += 1

        db.commit()
        logger.info("SCAN_MERGE_COMPLETE", asset_id=asset_id,
                    total=stats["total"], new=stats["new"], updated=stats["updated"])
        return {"status": "completed", "asset_id": asset_id,
                "scan_id": scan_id, "stats": stats}
    except Exception as e:
        db.rollback()
        logger.error("MERGE_PERSIST_ERROR", error=str(e))
        return {"status": "error", "message": str(e)}
    finally:
        db.close()

@app.task(name="tasks.return_precomputed", queue="vulnerabilities")
def return_precomputed(findings: List[Dict]) -> List[Dict]:
    """Identity task — passes already-computed findings into a chord group."""
    return findings


# --- ORQUESTADOR PARALELO (US-3.4) ---
@app.task(name="services.scanner_engine.tasks.vuln_tasks.scan_asset_parallel")
def scan_asset_parallel(asset_id: int, asset_ip: str, asset_name: str, scan_types: List[str] = None):
    """
    Flujo en dos fases:
      Fase 1 — Nmap (bloqueante): descubre puertos y servicios.
      Fase 2 — Resto de scanners en paralelo. Nikto y ffuf se lanzan una vez
                por cada puerto HTTP descubierto por Nmap.
    """
    if not scan_types:
        scan_types = ["nuclei", "nmap", "nikto"]

    # --- Fase 1: Nmap ---
    nmap_findings = []
    if "openvas" in scan_types or "nmap" in scan_types:
        logger.info("NMAP_PHASE_START", asset_id=asset_id, target=asset_ip)
        try:
            nmap_findings = run_nmap_scan(asset_id, asset_ip)
        except Exception as e:
            logger.error("NMAP_PHASE_ERROR", error=str(e))

    http_ports = extract_http_ports(nmap_findings)
    logger.info("HTTP_PORTS_DISCOVERED", asset_id=asset_id, ports=http_ports)

    # --- Fase 2: resto de scanners ---
    tasks = []

    # Nmap findings ya obtenidos en fase 1 — se pasan como lista directa al chord
    # usando una tarea identity para que merge_and_persist_results los reciba igual
    # que los demás resultados del grupo.
    if nmap_findings:
        tasks.append(return_precomputed.s(nmap_findings))

    if "nuclei" in scan_types:
        tasks.append(run_nuclei_task.s(asset_id, asset_ip, asset_name))
    if "openvas" in scan_types:
        tasks.append(run_openvas_scan.s(asset_id, asset_ip, asset_name))

    # Nikto y ffuf: una tarea por puerto HTTP descubierto
    for port in http_ports:
        if "nikto" in scan_types:
            tasks.append(run_nikto_task.s(asset_id, asset_ip, port))
        if "ffuf" in scan_types:
            tasks.append(run_ffuf_task.s(asset_id, asset_ip, port))

    if "whatweb" in scan_types:
        tasks.append(run_whatweb_task.s(asset_id, asset_ip))
    if "testssl" in scan_types:
        tasks.append(run_testssl_task.s(asset_id, asset_ip))

    if not tasks:
        # Solo nmap se ejecutó, persistir sus findings directamente
        if nmap_findings:
            return merge_and_persist_results([nmap_findings], asset_id)
        return {"status": "no_scans_selected"}

    workflow = chord(group(tasks))(merge_and_persist_results.s(asset_id))
    logger.info("PARALLEL_SCAN_ORCHESTRATED", asset_id=asset_id, scanners=scan_types,
                http_ports=http_ports, hostname=asset_name)
    return {"status": "parallel_scans_initiated", "task_id": workflow.id}