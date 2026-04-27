# services/ai_reasoning/human_validation.py

import logging
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

async def process_human_decision(
    asset_id: str, 
    finding_id: str, 
    decision: str, 
    corrected_module: Optional[str], 
    operator_id: str
) -> Dict[str, Any]:
    """
    Implementa la validación humana obligatoria (US-4.8) para sugerencias de vectores de ataque.
    
    Este módulo es el human-in-the-loop que permite al Responsable de Seguridad revisar,
    corregir o rechazar las propuestas de la IA antes de que pasen al módulo de explotación (M4).
    El registro de estas decisiones constituye evidencia requerida para el cumplimiento de 
    normativas ENS (op.pl.1, op.acc.5, op.exp.5).
    
    Args:
        asset_id: ID del activo afectado.
        finding_id: ID de la vulnerabilidad/hallazgo.
        decision: Estado final ("validada", "corregida", "rechazada").
        corrected_module: Módulo MSF corregido (obligatorio si decision == "corregida").
        operator_id: ID del operador/usuario que firma la decisión.
        
    Returns:
        Dict con el resultado de la validación listo para persistir en PostgreSQL.
        
    Raises:
        ValueError: Si los parámetros de decisión o módulo corregido no son válidos.
    """
    
    # 1. Validar decisión
    valid_decisions = ["validada", "corregida", "rechazada"]
    if decision not in valid_decisions:
        raise ValueError(f"Decisión inválida: '{decision}'. Solo se acepta: {', '.join(valid_decisions)}")
        
    # 2. Validar módulo corregido
    if decision == "corregida" and (not corrected_module or not corrected_module.strip()):
        raise ValueError("Si la decisión es 'corregida', debe proporcionarse un 'corrected_module' no vacío.")
        
    # 3. Lógica de estados finales y transformación
    final_status = "pending_human_approval"
    
    if decision == "validada":
        final_status = "approved"
    elif decision == "corregida":
        final_status = "approved_with_correction"
    elif decision == "rechazada":
        final_status = "rejected"
        
    # 4. Preparar resultado de auditoría
    decided_at = datetime.utcnow().isoformat()
    
    result = {
        "asset_id": asset_id,
        "finding_id": finding_id,
        "decision": decision,
        "final_status": final_status,
        "operator_id": operator_id,
        "decided_at": decided_at,
        "corrected_module": corrected_module if decision == "corregida" else None
    }
    
    # 5. Logging estructurado - Evidencia ENS op.exp.5
    # Estas líneas de log son fundamentales para la trazabilidad de auditoría
    logger.info(
        f"ENS_EVIDENCE | HumanDecision | Operator: {operator_id} | Asset: {asset_id} | "
        f"Finding: {finding_id} | Decision: {decision} | Status: {final_status}"
    )
    
    # TODO: Implementar persistencia en PostgreSQL (Módulo M8 Database)
    # Se debe actualizar la tabla de sugerencias con la decisión del operador
    # query = \"\"\"
    #     UPDATE attack_vectors 
    #     SET status = %s, 
    #         msf_module = COALESCE(%s, msf_module), 
    #         decided_by = %s, 
    #         decided_at = %s 
    #     WHERE asset_id = %s AND finding_id = %s
    # \"\"\"
    
    return result
