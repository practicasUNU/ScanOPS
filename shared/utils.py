"""Shared utility functions across ScanOPS microservices."""

# ============================================================
# FUNCIONES PARA SCANNER_HEALTH
# ============================================================

def evaluar_metrica(nombre, valor_str, umbral_alerta=80, umbral_critico=90):
    valor = float(valor_str.rstrip('%').replace(',', '.'))
    if valor > umbral_critico:
        estado = "CRITICO"
        severidad = "CRITICA"
    elif valor > umbral_alerta:
        estado = "ALERTA"
        severidad = "ALTA"
    else:
        estado = "OK"
        severidad = "INFO"
    return {
        "nombre": nombre,
        "valor": valor_str,
        "umbral_alerta": f"{umbral_alerta}%",
        "umbral_critico": f"{umbral_critico}%",
        "estado": estado,
        "severidad": severidad
    }


def evaluar_servicio(nombre, estado_systemctl):
    severidad = "INFO" if estado_systemctl == "active" else "ALTA"
    return {
        "nombre": nombre,
        "estado": estado_systemctl,
        "severidad": severidad
    }


def calcular_estado_global(metricas, servicios):
    severidades = [m["severidad"] for m in metricas] + [s["severidad"] for s in servicios]
    if "CRITICA" in severidades:
        return "CRITICO"
    elif "ALTA" in severidades:
        return "ALERTA"
    return "OK"


def evaluar_root_bloqueado(passwd_status):
    locked = passwd_status.strip() == "L"
    return {
        "check": "root_bloqueado",
        "estado": "SEGURO" if locked else "RIESGO",
        "severidad": "INFO" if locked else "CRITICA",
        "medida_ens": "op.acc.6",
        "detalle": "Usuario root bloqueado correctamente" if locked else "El usuario root NO está bloqueado. Ejecutar: sudo passwd -l root",
        "remediacion": None if locked else "sudo passwd -l root"
    }


def evaluar_ufw(ufw_output):
    active = "Status: active" in ufw_output
    return {
        "check": "ufw_activo",
        "estado": "ACTIVO" if active else "INACTIVO",
        "severidad": "INFO" if active else "CRITICA",
        "medida_ens": "op.exp.4",
        "remediacion": None if active else "sudo ufw enable"
    }


def evaluar_ssh_root_login(sshd_config_value):
    seguro = sshd_config_value.strip().lower() == "no"
    return {
        "check": "ssh_root_login",
        "estado": "SEGURO" if seguro else "RIESGO",
        "severidad": "INFO" if seguro else "ALTA",
        "medida_ens": "op.acc.6"
    }


def evaluar_parches(count):
    return {
        "check": "parches_pendientes",
        "estado": f"{count} parches pendientes",
        "severidad": "ALTA" if count > 0 else "INFO",
        "medida_ens": "op.exp.2",
        "remediacion": "sudo apt update && sudo apt upgrade" if count > 0 else None
    }


def evaluar_cifrado_disco(lsblk_output):
    tiene_cifrado = "crypt" in lsblk_output
    estado = "ACTIVO" if tiene_cifrado else "AUSENTE"
    return {
        "check": "cifrado_disco",
        "estado": estado,
        "severidad": "INFO" if tiene_cifrado else "CRITICA",
        "medida_ens": "mp.si.2"
    }


def calcular_compliance(hallazgos):
    total = len(hallazgos)
    ok = sum(1 for h in hallazgos if h["severidad"] == "INFO")
    riesgo = total - ok
    return {
        "checks_total": total,
        "checks_ok": ok,
        "checks_riesgo": riesgo,
        "cumple_ens": riesgo == 0
    }


def parsear_puerto(linea):
    partes = linea.split()
    if len(partes) < 3:
        return None
    puerto_proto = partes[0]
    estado = partes[1]
    servicio = partes[2] if len(partes) > 2 else ""
    version = " ".join(partes[3:]) if len(partes) > 3 else ""

    if estado == "open":
        severidad = "INFO"
        estado_desc = "Abierto"
    elif estado == "filtered":
        severidad = "ALTA"
        estado_desc = "Filtrado"
    else:
        severidad = "INFO"
        estado_desc = estado

    medida_ens = {
        "22/tcp": "op.acc.1",
        "80/tcp": "op.exp.2",
        "443/tcp": "op.exp.2",
        "19999/tcp": "op.exp.4"
    }.get(puerto_proto, "op.exp.2")

    notas = {
        "22/tcp": "Servicio SSH accesible — verificar que solo acepta autenticación por clave",
        "80/tcp": "HTTP sin cifrar activo — verificar redirección a HTTPS",
        "443/tcp": "HTTPS activo con SSL",
        "19999/tcp": "Puerto filtrado por firewall — correcto"
    }
    nota = notas.get(puerto_proto, "")
    detalle = f"Servicio {servicio} {estado_desc} en {puerto_proto}."

    return {
        "puerto": puerto_proto,
        "servicio": servicio,
        "estado": estado_desc,
        "version": version,
        "severidad": severidad,
        "medida_ens": medida_ens,
        "nota": nota,
        "detalle": detalle
    }


def calcular_resumen_network(hallazgos):
    puertos_abiertos = sum(1 for h in hallazgos if h["estado"] == "Abierto")
    puertos_filtrados = sum(1 for h in hallazgos if h["estado"] == "Filtrado")
    ssl_activo = any(
        "ssl" in h["version"].lower() or h["puerto"] == "443/tcp"
        for h in hallazgos if h["estado"] == "Abierto"
    )
    firewall_detectado = puertos_filtrados > 0
    return {
        "puertos_abiertos": puertos_abiertos,
        "puertos_filtrados": puertos_filtrados,
        "ssl_activo": ssl_activo,
        "firewall_detectado": firewall_detectado
    }
