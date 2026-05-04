import logging
import os
import psycopg2
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

DB_CONFIG = {
    "dsn": os.getenv("DATABASE_URL", "postgresql://scanops:scanops@postgres:5432/scanops")
}

async def process_human_decision(
    asset_id: str,
    finding_id: str,
    decision: str,
    corrected_module: Optional[str],
    operator_id: str
) -> Dict[str, Any]:
    """
    Implementa la validación humana obligatoria (US-4.8) para sugerencias de vectores de ataque.
    Persiste la decisión en la tabla m4_approvals para que el módulo M4 pueda ejecutarla.
    """

    # 1. Validar decisión
    valid_decisions = ["validada", "corregida", "rechazada"]
    if decision not in valid_decisions:
        raise ValueError(f"Decisión inválida: '{decision}'. Solo se acepta: {', '.join(valid_decisions)}")

    # 2. Validar módulo corregido
    if decision == "corregida" and (not corrected_module or not corrected_module.strip()):
        raise ValueError("Si la decisión es 'corregida', debe proporcionarse un 'corrected_module' no vacío.")

    # 3. Mapear decisión a status
    status_map = {
        "validada": "approved",
        "corregida": "approved_with_correction",
        "rechazada": "rejected"
    }
    final_status = status_map[decision]
    decided_at = datetime.utcnow()

    # 4. Persistir en m4_approvals
    # Si existe registro previo con finding_id → actualizar status
    # Si no existe → crear registro nuevo con status PENDING→final
    conn = None
    approval_id = None
    try:
        conn = psycopg2.connect(DB_CONFIG["dsn"])
        with conn:
            with conn.cursor() as cur:
                # Buscar si ya existe aprobación para este finding
                cur.execute(
                    "SELECT id FROM m4_approvals WHERE cve_id = %s AND target_ip = %s ORDER BY created_at DESC LIMIT 1",
                    (finding_id, asset_id)
                )
                row = cur.fetchone()

                if row:
                    # Actualizar registro existente
                    approval_id = row[0]
                    cur.execute(
                        """UPDATE m4_approvals
                           SET status = %s,
                               requester = %s,
                               updated_at = %s
                           WHERE id = %s""",
                        (final_status, operator_id, decided_at, approval_id)
                    )
                    logger.info(f"[ENS_EVIDENCE] approval_id={approval_id} updated to {final_status} by {operator_id}")
                else:
                    # Crear nuevo registro
                    cur.execute(
                        """INSERT INTO m4_approvals
                               (cve_id, target_ip, requester, status, created_at, updated_at)
                           VALUES (%s, %s, %s, %s, %s, %s)
                           RETURNING id""",
                        (finding_id, asset_id, operator_id, final_status, decided_at, decided_at)
                    )
                    approval_id = cur.fetchone()[0]
                    logger.info(f"[ENS_EVIDENCE] approval_id={approval_id} created with {final_status} by {operator_id}")

    except Exception as e:
        logger.error(f"Error persistiendo decisión humana en BD: {e}")
        raise RuntimeError(f"No se pudo persistir la decisión en BD: {e}")
    finally:
        if conn:
            conn.close()

    # 5. Retornar resultado de auditoría
    return {
        "approval_id": approval_id,
        "asset_id": asset_id,
        "finding_id": finding_id,
        "decision": decision,
        "final_status": final_status,
        "corrected_module": corrected_module if decision == "corregida" else None,
        "operator_id": operator_id,
        "decided_at": decided_at.isoformat(),
        "ens_evidence": f"op.pl.1 op.acc.5 op.exp.5 — decisión registrada"
    }
