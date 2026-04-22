"""
M2 Recon Engine - Scanner Network Module
Descubrimiento de activos en la red y comparativa de superficie
US-2.1, US-2.2, US-2.3, US-2.5, US-2.6
"""

import asyncio
import subprocess
from typing import List, Dict, Tuple, Optional, Set
import httpx
from datetime import datetime
from sqlalchemy.orm import Session

from shared.scan_logger import ScanLogger
from shared.database import SessionLocal
from services.recon_engine.models.recon import (
    ReconSnapshot,
    ReconFinding,
    ReconSubdomain
)

logger = ScanLogger("scanner_network")

# Configuración
TARGET = "192.168.1.0/24"  # Puede venir de request
PORTS = "1-65535"
MASSCAN_RATE = "1000"


# ═══════════════════════════════════════════════════════════════════════════════
# FUNCIONES AUXILIARES - PARSING
# ═══════════════════════════════════════════════════════════════════════════════

def parse_masscan_output(output: str) -> Dict[str, Set[int]]:
    """
    Parsea output de Masscan: 'ip puerto1,puerto2,puerto3'
    Devuelve: {"10.1.1.1": {80, 443, 22}, ...}
    """
    hosts = {}
    for line in output.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]
            try:
                ports = {int(p) for p in parts[1].split(',')}
                hosts[ip] = ports
            except (ValueError, IndexError):
                continue
    return hosts


def build_hallazgos(nmap_output: str, discovered_hosts: Set[str], 
                   authorized_ips: Set[str]) -> Tuple[List[Dict], List[Dict]]:
    """
    Construye hallazgos basado en hosts descubiertos vs autorizados.
    US-2.6: Detecta Shadow IT (activos no autorizados).
    
    Returns:
        (hallazgos, shadow_it_list)
    """
    hallazgos = []
    shadow_it_list = []
    
    # Detectar Shadow IT: hosts descubiertos que NO están en M1
    for host in discovered_hosts:
        if host not in authorized_ips:
            shadow_it_item = {
                "ip": host,
                "tipo": "SOSPECHOSO",
                "criticidad": "MEDIA",
                "descripcion": "Host descubierto no autorizado",
                "status": "PENDIENTE_INVESTIGACION"
            }
            shadow_it_list.append(shadow_it_item)
            hallazgos.append({
                "tipo": "SHADOW_IT",
                "host": host,
                "severity": "MEDIA"
            })
    
    return hallazgos, shadow_it_list


def calcular_resumen_network(hallazgos: List[Dict]) -> Dict:
    """Calcula resumen de hallazgos de red."""
    shadow_it_count = len([h for h in hallazgos if h.get('tipo') == 'SHADOW_IT'])
    
    return {
        "total_hallazgos": len(hallazgos),
        "shadow_it_detected": shadow_it_count,
        "severity_distribution": {
            "CRITICA": len([h for h in hallazgos if h.get('severity') == 'CRITICA']),
            "ALTA": len([h for h in hallazgos if h.get('severity') == 'ALTA']),
            "MEDIA": len([h for h in hallazgos if h.get('severity') == 'MEDIA']),
        }
    }


# ═══════════════════════════════════════════════════════════════════════════════
# FUNCIONES PRINCIPALES - HERRAMIENTAS DE ESCANEO
# ═══════════════════════════════════════════════════════════════════════════════

async def _run_tool(cmd: List[str]) -> Tuple[str, str, int]:
    """
    Ejecuta una herramienta externa de forma asíncrona.
    
    Args:
        cmd: Comando a ejecutar como lista
        
    Returns:
        (stdout, stderr, returncode)
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout_bytes, stderr_bytes = await process.communicate()
        return (
            stdout_bytes.decode('utf-8', errors='ignore'),
            stderr_bytes.decode('utf-8', errors='ignore'),
            process.returncode
        )
    except FileNotFoundError:
        raise FileNotFoundError(f"Comando no encontrado: {cmd[0]}")
    except Exception as e:
        logger.error("TOOL_EXECUTION_ERROR", cmd=" ".join(cmd), error=str(e))
        raise


async def run_nmap(ports: Set[int]) -> str:
    """
    Ejecuta Nmap contra los puertos descubiertos.
    US-2.1: Wrapper de Nmap
    
    Args:
        ports: Conjunto de puertos a verificar
        
    Returns:
        Output de Nmap (xml o texto)
    """
    if not ports:
        logger.info("NMAP_SKIP", reason="no_ports")
        return ""
    
    ports_str = ",".join(str(p) for p in sorted(ports))
    logger.info("NMAP_SCAN_START", ports=len(ports))
    
    try:
        cmd = [
            "nmap",
            "-p", ports_str,
            "-sV",  # Version detection
            "-oX", "-",  # Output XML to stdout
            TARGET
        ]
        stdout, stderr, returncode = await _run_tool(cmd)
        
        if returncode == 0:
            logger.finding(
                "NMAP_SCAN_OK",
                severity="INFO",
                ports_scanned=len(ports)
            )
            return stdout
        else:
            logger.warning("NMAP_FAILED", error=stderr[:200])
            return ""
    except FileNotFoundError:
        logger.error("NMAP_NOT_INSTALLED")
        return ""
    except Exception as e:
        logger.error("NMAP_ERROR", error=str(e))
        return ""


async def get_authorized_ips() -> Set[str]:
    """
    Lee los activos autorizados de M1.
    US-2.1: Lectura de M1 para activos autorizados.
    
    Returns:
        Set de IPs autorizadas
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "http://localhost:8001/assets",
                timeout=10.0,
                headers={"Authorization": "Bearer scanops_secret"}
            )
            
            if response.status_code == 200:
                data = response.json()
                ips = {
                    asset['ip']
                    for asset in data.get('items', [])
                    if asset.get('ip') and asset.get('status') == 'ACTIVO'
                }
                logger.info("AUTHORIZED_IPS_FETCHED", count=len(ips))
                return ips
            else:
                logger.warning("M1_API_ERROR", status=response.status_code)
                return set()
    except Exception as e:
        logger.error("M1_CONNECTION_FAILED", error=str(e))
        return set()


# ═══════════════════════════════════════════════════════════════════════════════
# NUEVAS FUNCIONES - PASO 1: SUBFINDER INTEGRATION (US-2.2)
# ═══════════════════════════════════════════════════════════════════════════════

async def run_subfinder(domains: List[str]) -> List[str]:
    """
    Ejecuta Subfinder para descubrir subdominios [US-2.2].
    
    Args:
        domains: Lista de dominios a escanear (obtenidos de M1)
        
    Returns:
        Lista de subdominios descubiertos
        
    ENS: [op.acc.1] Identificación de dispositivos / superficie externa
    """
    if not domains:
        logger.info("SUBFINDER_SKIP", reason="no_domains_provided")
        return []

    all_subdomains = []

    for domain in domains:
        logger.info("SUBFINDER_SCAN_START", domain=domain)
        try:
            cmd = [
                "subfinder",
                "-d", domain,
                "-silent",
                "-timeout", "10"
            ]
            stdout, stderr, returncode = await _run_tool(cmd)

            if returncode == 0:
                found = [
                    line.strip()
                    for line in stdout.splitlines()
                    if line.strip()
                ]
                all_subdomains.extend(found)
                logger.finding(
                    "SUBDOMAIN_DISCOVERED",
                    severity="INFO",
                    domain=domain,
                    count=len(found)
                )
            else:
                logger.warning(
                    "SUBFINDER_FAILED",
                    domain=domain,
                    error=stderr[:200]
                )

        except FileNotFoundError:
            logger.error(
                "SUBFINDER_NOT_FOUND",
                error="Subfinder no instalado. Run: https://github.com/projectdiscovery/subfinder"
            )
            return []
        except Exception as e:
            logger.error(
                "SUBFINDER_ERROR",
                domain=domain,
                error=str(e)
            )

    logger.info(
        "SUBFINDER_SCAN_COMPLETE",
        total_subdomains=len(all_subdomains)
    )

    return all_subdomains


async def _get_domains_from_m1() -> List[str]:
    """
    Consulta M1 para obtener los dominios que Subfinder debe escanear.
    Lee el inventario de activos y extrae los campos "dominio".
    
    Returns:
        Lista de dominios únicos
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "http://localhost:8001/assets",
                timeout=10.0,
                headers={"Authorization": "Bearer scanops_secret"}
            )

            if response.status_code == 200:
                data = response.json()
                # Extraer field "dominio" de cada activo
                # Usar set() para evitar duplicados
                domains = {
                    asset['dominio']
                    for asset in data.get('items', [])
                    if asset.get('dominio') and asset['dominio'].strip()
                }

                logger.info(
                    "DOMAINS_FETCHED_FROM_M1",
                    count=len(domains),
                    domains_sample=list(domains)[:5]
                )
                return list(domains)
            else:
                logger.warning(
                    "M1_API_ERROR",
                    status=response.status_code,
                    reason=response.text[:200]
                )
                return []

    except Exception as e:
        logger.error(
            "M1_CONNECTION_FAILED",
            error=str(e),
            hint="Asegúrate que M1 está corriendo en http://localhost:8001"
        )
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# FUNCIÓN PRINCIPAL - ORQUESTACIÓN DE ESCANEO
# ═══════════════════════════════════════════════════════════════════════════════

async def _scan_async(cycle_id: str = None):
    """
    Lógica principal de escaneo asíncrono y comparativa de superficie.
    
    Flujo:
    1. Obtener dominios de M1
    2. Ejecutar Masscan, Nmap, Subfinder EN PARALELO
    3. Construir hallazgos
    4. Detectar Shadow IT
    5. Persistir en BD
    6. Comparar con snapshot anterior
    
    US-2.1: Nmap wrapper
    US-2.2: Subfinder descubrimiento
    US-2.3: Masscan escaneo
    US-2.5: Surface diff comparativa
    US-2.6: Shadow IT detection
    """
    if not cycle_id:
        cycle_id = f"{datetime.now().year}-W{datetime.now().isocalendar()[1]:02d}"

    logger.scan_start(target=TARGET, cycle_id=cycle_id)
    db = SessionLocal()

    try:
        # 1. Crear Snapshot
        snapshot = ReconSnapshot(cycle_id=cycle_id, target=TARGET, status="running")
        db.add(snapshot)
        db.commit()
        db.refresh(snapshot)
        logger.info("SNAPSHOT_CREATED", snapshot_id=snapshot.id)

        # 2. Obtener datos iniciales de M1
        domains_to_scan = await _get_domains_from_m1()
        authorized_ips = await get_authorized_ips()

        # 3. PREPARAR TAREAS EN PARALELO (no se ejecutan aún)
        # Mock Masscan - devuelve resultado vacío
        masscan_task = asyncio.create_task(
            asyncio.sleep(0.1)  # Simula ejecución
        )

        subfinder_task = asyncio.create_task(
            run_subfinder(domains_to_scan)
        )

        # 4. EJECUTAR MASSCAN Y SUBFINDER EN PARALELO
        logger.info("PARALLEL_SCAN_START", tools=["masscan", "subfinder"])
        
        (masscan_output, subfinder_domains) = await asyncio.gather(
            masscan_task,
            subfinder_task
        )

        # 5. Extraer stdout de masscan (que viene como tupla)
        masscan_output = ("", "", 0)  # Mock output

        # 6. Procesar resultados de Masscan
        masscan_hosts = parse_masscan_output(masscan_output[0])
        open_ports = {p for ports in masscan_hosts.values() for p in ports}
        
        logger.info(
            "MASSCAN_COMPLETE",
            hosts_found=len(masscan_hosts),
            open_ports=len(open_ports)
        )

        # 7. Ejecutar Nmap con puertos descubiertos
        logger.info("NMAP_SCAN_STARTING", ports=len(open_ports))
        nmap_output = await run_nmap(open_ports)

        # 8. Comparación e identificación
        discovered_hosts = set(masscan_hosts.keys())
        hallazgos, shadow_it_list = build_hallazgos(nmap_output, discovered_hosts, authorized_ips)
        resumen = calcular_resumen_network(hallazgos)

        logger.finding(
            "SCAN_SUMMARY",
            severity="INFO",
            hosts_discovered=len(discovered_hosts),
            authorized_count=len(authorized_ips),
            shadow_it_detected=len(shadow_it_list),
            subdomains_discovered=len(subfinder_domains)
        )

        # 9. Registro automático de Shadow IT en M1
        if shadow_it_list:
            await _register_shadow_it(shadow_it_list)

        # 10. Persistencia: INCLUYE SUBDOMINIOS REALES
        await persist_findings_to_db(
            snapshot.id,
            hallazgos,
            masscan_hosts,
            subfinder_domains,  # ← AHORA TIENE DATOS REALES (no [])
            db
        )

        snapshot.finished_at = datetime.utcnow()
        snapshot.status = "completed"
        db.commit()

        logger.scan_end(target=TARGET, findings=len(hallazgos))
        
        return {
            "cycle_id": cycle_id,
            "hosts_detected": list(discovered_hosts),
            "authorized_count": len(authorized_ips),
            "subdomains_discovered": len(subfinder_domains),  # ← DATO REAL
            "hallazgos": hallazgos,
            "resumen": resumen,
            "surface_changes": {}
        }

    except Exception as e:
        logger.error("SCAN_FAILED", error=str(e), exc_info=True)
        if 'snapshot' in locals():
            snapshot.status = "failed"
            db.commit()
        raise
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════════
# FUNCIONES AUXILIARES - PERSISTENCIA Y COMPARATIVA
# ═══════════════════════════════════════════════════════════════════════════════

async def persist_findings_to_db(snapshot_id: int, hallazgos: List[Dict],
                                masscan_hosts: Dict[str, Set[int]],
                                subfinder_domains: List[str],
                                db: Session):
    """
    Persiste todos los hallazgos en BD.
    Incluye hosts, puertos, subdominios y hallazgos.
    """
    try:
        # Guardar hallazgos de hosts y puertos
        for ip, ports in masscan_hosts.items():
            for port in ports:
                finding = ReconFinding(
                    snapshot_id=snapshot_id,
                    host=ip,
                    port=f"{port}/tcp",
                    state="open",
                    source="masscan"
                )
                db.add(finding)
        
        # Guardar subdominios
        for subdomain in subfinder_domains:
            sub_rec = ReconSubdomain(
                snapshot_id=snapshot_id,
                subdomain=subdomain,
                source="subfinder"
            )
            db.add(sub_rec)
        
        # Guardar hallazgos de shadow IT
        for hallazgo in hallazgos:
            if hallazgo.get('tipo') == 'SHADOW_IT':
                finding = ReconFinding(
                    snapshot_id=snapshot_id,
                    host=hallazgo.get('host'),
                    state="suspicious",
                    source="shadow_it"
                )
                db.add(finding)
        
        db.commit()
        logger.info(
            "FINDINGS_PERSISTED",
            count=len(hallazgos) + len(subfinder_domains)
        )
    except Exception as e:
        logger.error("PERSIST_ERROR", error=str(e))
        db.rollback()
        raise


async def _register_shadow_it(shadow_it_list: List[Dict]):
    """
    Registra activos Shadow IT descubiertos en M1.
    US-2.6: Envío de Shadow IT a M1 como activos nuevos.
    """
    try:
        async with httpx.AsyncClient() as client:
            for item in shadow_it_list:
                response = await client.post(
                    "http://localhost:8001/assets",
                    json={
                        "ip": item["ip"],
                        "dominio": None,
                        "tipo": "SOSPECHOSO",
                        "criticidad": item["criticidad"],
                        "status": "PENDIENTE_ALTA",
                        "descripcion": item["descripcion"]
                    },
                    headers={"Authorization": "Bearer scanops_secret"},
                    timeout=10.0
                )
                
                if response.status_code == 201:
                    logger.finding(
                        "SHADOW_IT_REGISTERED",
                        severity="MEDIA",
                        ip=item["ip"]
                    )
                else:
                    logger.warning("SHADOW_IT_REGISTRATION_FAILED", ip=item["ip"])
    except Exception as e:
        logger.error("SHADOW_IT_REGISTRATION_ERROR", error=str(e))


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINT WRAPPER
# ═══════════════════════════════════════════════════════════════════════════════

async def start_scan(target: str = None, cycle_id: str = None) -> Dict:
    """
    Wrapper público para lanzar escaneo.
    Llamado desde recon_api.py
    """
    if target:
        global TARGET
        TARGET = target
    
    return await _scan_async(cycle_id)
