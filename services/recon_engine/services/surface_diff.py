"""
Surface Diff Service
===================
Compares surface snapshots to detect changes in network surface.
"""

import os
import sys
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict
from sqlalchemy.orm import Session

from ..models.recon import ReconFinding, ReconSubdomain, ReconSnapshot
from shared.scan_logger import ScanLogger

logger = ScanLogger("surface_diff")

# Mock inventory for severity classification (until M1 API is available)
MOCK_INVENTORY = {
    "10.202.15.100": {
        "activo": "Servidor de auditoría",
        "criticidad": "Alta",
        "responsable": "Equipo SOC"
    },
    "10.202.15.101": {
        "activo": "Switch de borde",
        "criticidad": "Media",
        "responsable": "Infraestructura"
    },
    "scanops.example.com": {
        "activo": "Portal ScanOPS",
        "criticidad": "Alta",
        "responsable": "Equipo SOC"
    }
}


def get_inventory_criticidad(host: str) -> str:
    """Get asset criticality from inventory."""
    if host in MOCK_INVENTORY:
        return MOCK_INVENTORY[host]["criticidad"]
    # Check for domain matches
    for asset, data in MOCK_INVENTORY.items():
        if asset.lower() == host.lower():
            return data["criticidad"]
    return "Baja"  # Default for unknown assets


def classify_change_severity(change_type: str, host: str, **kwargs) -> str:
    """
    Classify the severity of a surface change based on type and asset criticality.
    """
    criticidad = get_inventory_criticidad(host)

    if change_type == "new_port":
        if kwargs.get("state") == "open":
            return "CRITICA" if criticidad == "Alta" else "ALTA"
        return "MEDIA"

    elif change_type == "closed_port":
        return "INFO"  # Security improvement

    elif change_type == "new_host":
        return "CRITICA"  # Shadow IT

    elif change_type == "lost_host":
        return "MEDIA"  # Could be maintenance or incident

    elif change_type == "new_subdomain":
        return "ALTA"  # Expanded external surface

    elif change_type == "lost_subdomain":
        return "INFO"

    elif change_type == "service_change":
        return "MEDIA"  # Service/version change

    elif change_type == "state_change":
        if kwargs.get("old_state") == "filtered" and kwargs.get("new_state") == "open":
            return "ALTA"  # Firewall control lost
        elif kwargs.get("old_state") == "open" and kwargs.get("new_state") == "filtered":
            return "INFO"  # Security improvement
        return "MEDIA"

    return "INFO"


def get_findings_set(snapshot_id: int, db: Session) -> List[Dict]:
    """Get all findings for a snapshot as comparable dicts."""
    findings = db.query(ReconFinding).filter(ReconFinding.snapshot_id == snapshot_id).all()
    return [
        {
            "host": f.host,
            "port": f.port,
            "service": f.service,
            "version": f.version,
            "state": f.state,
            "source": f.source,
            "first_seen_snapshot_id": f.first_seen_snapshot_id
        }
        for f in findings
    ]


def get_subdomains_set(snapshot_id: int, db: Session) -> Set[str]:
    """Get all subdomains for a snapshot."""
    subdomains = db.query(ReconSubdomain).filter(ReconSubdomain.snapshot_id == snapshot_id).all()
    return {sd.subdomain for sd in subdomains}


def get_hosts_set(findings: List[Dict]) -> Set[str]:
    """Extract unique hosts from findings."""
    return {f["host"] for f in findings}


def get_port_tuples(findings: List[Dict]) -> Set[Tuple[str, str]]:
    """Get (host, port) tuples for comparison."""
    return {(f["host"], f["port"]) for f in findings if f["port"]}


def compare_snapshots(current_snapshot_id: int, previous_snapshot_id: Optional[int], db: Session) -> Dict:
    """
    Compare current snapshot with previous one to detect surface changes.
    """
    # Get current findings
    current_findings = get_findings_set(current_snapshot_id, db)
    current_hosts = get_hosts_set(current_findings)
    current_ports = get_port_tuples(current_findings)
    current_subdomains = get_subdomains_set(current_snapshot_id, db)

    changes = {
        "new_ports": [],
        "closed_ports": [],
        "new_hosts": [],
        "lost_hosts": [],
        "new_subdomains": [],
        "lost_subdomains": [],
        "service_changes": [],
        "state_changes": [],
        "details": []
    }

    if previous_snapshot_id is None:
        # First cycle - everything is "new" but we don't alert
        changes["is_baseline"] = True
        changes["has_changes"] = False
        return changes

    # Get previous findings
    previous_findings = get_findings_set(previous_snapshot_id, db)
    previous_hosts = get_hosts_set(previous_findings)
    previous_ports = get_port_tuples(previous_findings)
    previous_subdomains = get_subdomains_set(previous_snapshot_id, db)

    # Create lookup dicts for previous findings
    previous_findings_dict = {
        (f["host"], f["port"]): f for f in previous_findings if f["port"]
    }
    previous_subdomains_dict = {sd: True for sd in previous_subdomains}

    # Detect new and lost hosts
    new_hosts = current_hosts - previous_hosts
    lost_hosts = previous_hosts - current_hosts

    for host in sorted(new_hosts):
        severity = classify_change_severity("new_host", host)
        change_detail = {
            "type": "new_host",
            "host": host,
            "severity": severity,
            "description": f"Nuevo host detectado no en inventario",
            "medida_ens": "op.acc.7"
        }
        changes["new_hosts"].append({"host": host})
        changes["details"].append(change_detail)

    for host in sorted(lost_hosts):
        severity = classify_change_severity("lost_host", host)
        change_detail = {
            "type": "lost_host",
            "host": host,
            "severity": severity,
            "description": f"Host desaparecido de la red",
            "medida_ens": "op.mon.1"
        }
        changes["lost_hosts"].append({"host": host})
        changes["details"].append(change_detail)

    # Detect new and closed ports
    new_ports = current_ports - previous_ports
    closed_ports = previous_ports - current_ports

    for host, port in sorted(new_ports):
        current_finding = next(
            (f for f in current_findings if f["host"] == host and f["port"] == port),
            {}
        )
        severity = classify_change_severity("new_port", host, state=current_finding.get("state"))
        change_detail = {
            "type": "new_port",
            "host": host,
            "port": port,
            "service": current_finding.get("service"),
            "severity": severity,
            "description": f"Nuevo puerto {port} abierto en {host}",
            "medida_ens": "op.exp.2"
        }
        changes["new_ports"].append({
            "host": host,
            "port": port,
            "service": current_finding.get("service"),
            "state": current_finding.get("state")
        })
        changes["details"].append(change_detail)

    for host, port in sorted(closed_ports):
        severity = classify_change_severity("closed_port", host)
        change_detail = {
            "type": "closed_port",
            "host": host,
            "port": port,
            "severity": severity,
            "description": f"Puerto {port} cerrado en {host}",
            "medida_ens": "op.mon.1"
        }
        changes["closed_ports"].append({"host": host, "port": port})
        changes["details"].append(change_detail)

    # Detect service and state changes for common ports
    for host, port in current_ports & previous_ports:
        current_finding = next(
            (f for f in current_findings if f["host"] == host and f["port"] == port),
            {}
        )
        previous_finding = previous_findings_dict.get((host, port), {})

        # Service/version change
        if (current_finding.get("service") != previous_finding.get("service") or
            current_finding.get("version") != previous_finding.get("version")):
            severity = classify_change_severity("service_change", host)
            change_detail = {
                "type": "service_change",
                "host": host,
                "port": port,
                "service": current_finding.get("service"),
                "severity": severity,
                "description": f"Cambio de servicio en {host}:{port} de '{previous_finding.get('service')}' a '{current_finding.get('service')}'",
                "medida_ens": "op.mon.2"
            }
            changes["service_changes"].append({
                "host": host,
                "port": port,
                "old_service": previous_finding.get("service"),
                "new_service": current_finding.get("service"),
                "old_version": previous_finding.get("version"),
                "new_version": current_finding.get("version")
            })
            changes["details"].append(change_detail)

        # State change
        if current_finding.get("state") != previous_finding.get("state"):
            severity = classify_change_severity(
                "state_change", host,
                old_state=previous_finding.get("state"),
                new_state=current_finding.get("state")
            )
            change_detail = {
                "type": "state_change",
                "host": host,
                "port": port,
                "severity": severity,
                "description": f"Cambio de estado en {host}:{port} de '{previous_finding.get('state')}' a '{current_finding.get('state')}'",
                "medida_ens": "op.mon.3"
            }
            changes["state_changes"].append({
                "host": host,
                "port": port,
                "old_state": previous_finding.get("state"),
                "new_state": current_finding.get("state")
            })
            changes["details"].append(change_detail)

    # Detect new and lost subdomains
    new_subdomains = current_subdomains - previous_subdomains
    lost_subdomains = previous_subdomains - current_subdomains

    for subdomain in sorted(new_subdomains):
        severity = classify_change_severity("new_subdomain", subdomain)
        change_detail = {
            "type": "new_subdomain",
            "host": subdomain,
            "severity": severity,
            "description": f"Nuevo subdominio descubierto: {subdomain}",
            "medida_ens": "op.exp.3"
        }
        changes["new_subdomains"].append({"subdomain": subdomain})
        changes["details"].append(change_detail)

    for subdomain in sorted(lost_subdomains):
        severity = classify_change_severity("lost_subdomain", subdomain)
        change_detail = {
            "type": "lost_subdomain",
            "host": subdomain,
            "severity": severity,
            "description": f"Subdominio desaparecido: {subdomain}",
            "medida_ens": "op.mon.4"
        }
        changes["lost_subdomains"].append({"subdomain": subdomain})
        changes["details"].append(change_detail)

    # Calculate summary
    total_changes = len(changes["details"])
    max_severity = "INFO"
    if any(c["severity"] == "CRITICA" for c in changes["details"]):
        max_severity = "CRITICA"
    elif any(c["severity"] == "ALTA" for c in changes["details"]):
        max_severity = "ALTA"
    elif any(c["severity"] == "MEDIA" for c in changes["details"]):
        max_severity = "MEDIA"

    changes["summary"] = {
        "new_ports": len(changes["new_ports"]),
        "closed_ports": len(changes["closed_ports"]),
        "new_hosts": len(changes["new_hosts"]),
        "lost_hosts": len(changes["lost_hosts"]),
        "new_subdomains": len(changes["new_subdomains"]),
        "lost_subdomains": len(changes["lost_subdomains"]),
        "service_changes": len(changes["service_changes"]),
        "state_changes": len(changes["state_changes"]),
        "total_changes": total_changes,
        "max_severity": max_severity
    }

    changes["has_changes"] = total_changes > 0

    # Log changes
    for change in changes["details"]:
        logger.finding(
            f"SURFACE_CHANGE_{change['type'].upper()}",
            severity=change["severity"],
            host=change["host"],
            port=change.get("port"),
            description=change["description"]
        )

    return changes


def get_previous_snapshot_id(current_cycle_id: str, db: Session) -> Optional[int]:
    """
    Get the ID of the most recent completed snapshot before the current cycle.
    """
    # Parse cycle_id to get a comparable value (assuming format like "2026-W17")
    try:
        year, week = current_cycle_id.split("-W")
        current_value = int(year) * 100 + int(week)
    except (ValueError, IndexError):
        # Fallback: just get the most recent completed snapshot
        current_value = 0

    # Find previous completed snapshots
    previous_snapshots = (
        db.query(ReconSnapshot)
        .filter(ReconSnapshot.status == "completed")
        .order_by(ReconSnapshot.started_at.desc())
        .all()
    )

    for snapshot in previous_snapshots:
        if snapshot.cycle_id != current_cycle_id:
            try:
                year, week = snapshot.cycle_id.split("-W")
                prev_value = int(year) * 100 + int(week)
                if prev_value < current_value:
                    return snapshot.id
            except (ValueError, IndexError):
                # If can't parse, just return the most recent different cycle
                if snapshot.cycle_id != current_cycle_id:
                    return snapshot.id

    # Fallback: return the most recent completed snapshot if any
    if previous_snapshots and previous_snapshots[0].cycle_id != current_cycle_id:
        return previous_snapshots[0].id

    return None