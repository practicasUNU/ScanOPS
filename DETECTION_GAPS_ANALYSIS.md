# Análisis: Fallos de Detección en Ataque a 10.202.15.100

## 🔴 Resumen Ejecutivo

Se realizó un pentest exitoso contra `10.202.15.100` (ID: 9) con:
- ✅ RCE confirmado (CVSS 9.9)
- ✅ SQL Injection explotada (CVSS 9.8)
- ✅ 9+ credenciales extraídas
- ✅ Acceso como `www-data` conseguido
- ❌ **CERO alertas en ScanOPS**

---

## 📊 Matriz de Detección Esperada vs Realidad

| Attack Vector | Esperado | Real | Razón |
|---|---|---|---|
| **Port Scan (Nmap)** | Suricata detecta | ❌ No detectado | Suricata no en path de tráfico / sin IDS/IPS |
| **Web App Enumeration (Gobuster)** | WAF / IDS bloquea | ❌ No detectado | **No hay WAF** |
| **SQL Injection** | WAF / IDS alerta | ❌ No detectado | Sin WAF, sin validación |
| **Command Injection / RCE** | Wazuh / IDS | ❌ No detectado | **Sin agente Wazuh en contenedor** |
| **SSH/Auth events** | M5 lee `/var/log/auth.log` | ⚠️ Parcial | Solo tráfico SSH legítimo, no intrusión |
| **System Process Activity** | Wazuh FIM/auditbeat | ❌ No detectado | Sin agente en contenedor |
| **File Access** | Wazuh FIM | ❌ No detectado | Sin monitoreo |
| **Network Exfiltration** | Suricata + IDS | ❌ No detectado | Sin cobertura |

---

## 🏗️ Gaps Arquitectónicos en M5

### 1. **Sin Agente de Host en 10.202.15.100**

```
┌─────────────────────────────────────────┐
│ 10.202.15.100 (Contenedor atacado)      │
│  ├─ DVWA, bWAPP, OWASP Juice Shop       │
│  ├─ www-data ← RCE adquirido aquí       │
│  └─ ❌ SIN Wazuh Agent                  │  ← PROBLEMA
│  └─ ❌ SIN Auditbeat                    │
│  └─ ❌ SIN Osquery                      │
└─────────────────────────────────────────┘
```

**Impacto:** M5 **no puede ver** qué procesos ejecuta www-data, qué archivos lee/escribe, qué redes conecta.

### 2. **Sin WAF (Web Application Firewall)**

```
Atacante (Kali)
     │
     │ SQL Injection: ' OR '1'='1' --
     │ RCE: ; id; cat /etc/passwd
     ↓
[nginx reverse proxy] ← No valida payloads
     ↓
[DVWA/bWAPP/OWASP] ← Ejecuta directamente
```

**Impacto:** Cargas maliciosas contra apps web **no son bloqueadas ni detectadas**.

### 3. **Suricata sin Cobertura de Tráfico**

```
Atacante (Kali)
     │
     ├─ Nmap, Gobuster, SQLmap
     │
     ↓ (¿dónde está Suricata?)
     ↓
10.202.15.100
```

**Incógnita:** ¿Suricata monitorea el segmento de red 10.202.x.x?
- Si está en modo IDS file-based (leyendo `/var/log/suricata/eve.json`), solo detecta tráfico que ingresa a la **interfaz de red de Suricata**.
- Si 10.202.15.100 está en otro segmento, Suricata **no lo ve**.

### 4. **M5 Solo Lee `/var/log/auth.log` vía SSH**

```
M5 Lee ← SSH → 10.202.15.100:/var/log/auth.log
     │
     └─ Captura: intentos SSH, sesiones PAM
     └─ IGNORA: actividad web app, procesos, archivos
```

**Impacto:** 
- SSH brute force → ✅ Detectado
- Explotación web app → ❌ No detectado
- Movimiento lateral → ❌ No detectado
- Escalación de privilegios → ❌ No detectado

---

## 🔍 Análisis Detallado: Por Qué NO Se Detectó

### Fase 1: Reconocimiento (Nmap)
- **Nmap escaneo → 5 puertos abiertos**
- ✗ **Suricata:** Sin cobertura de red confirmada
- ✗ **Wazuh:** Sin agente en destino
- ✗ **IDS/IPS:** No existe

### Fase 2: Enumeración Web
- **Gobuster descubre 30+ endpoints**
- ✗ **WAF:** No existe
- ✗ **Web logs centralizados:** DVWA/bWAPP no envían logs a M5
- ✗ **HTTP IDS:** No hay validación

### Fase 3: SQL Injection
- **Ataque:** `' OR '1'='1'` en campo login DVWA
- ✗ **WAF:** Hubiera bloqueado el patrón `OR '1'='1'`
- ✗ **SQL query logging:** No se centraliza
- ✗ **Application monitoring:** DVWA es app standalone sin observabilidad

### Fase 4: RCE (Command Injection)
- **Payload:** `;id;cat /etc/passwd`
- ✗ **Wazuh agent:** Hubiera alertado de proceso sospechoso
- ✗ **Auditbeat:** Hubiera capturado `execve(/bin/sh)`
- ✗ **File integrity:** No hay FIM en directorios críticos
- **Result:** `www-data` ejecuta comandos del atacante **sin alertar a nadie**

### Fase 5: Post-Explotación
- **Base de datos MySQL mapeada**
- ✗ **Database audit logs:** MySQL no envía logs a Wazuh
- ✗ **Network monitoring:** Conexiones DB ↔ atacante no detectadas

### Fase 6: Escalación (Intentada)
- **"Bloqueada" en contenedor**
- ⚠️ **Sin evidencia:** M5 no tiene logs que lo confirmen

---

## 📋 Lo Que SÍ Está Configurado (Pero Insuficiente)

✅ **M5 lee `/var/log/auth.log`** via SSH
- Captura: SSH login/logout, sudo attempts
- NO captura: web app activity, procesos, cambios de archivos

✅ **Suricata IDS existe**
- Requiere: agentes instalados o tráfico en interfaz monitoreada
- Limitado: solo NIDS (Network IDS), no HIDS (Host IDS)

✅ **Wazuh indexer existe**
- Requiere: Wazuh agents instalados
- Problema: **No hay agentes en 10.202.15.100**

---

## 🛠️ Soluciones Recomendadas (Orden de Impacto)

### P0 — Crítico (Implementar inmediatamente)

#### 1. **Instalar Wazuh Agent en 10.202.15.100**
```bash
# En el contenedor 10.202.15.100
docker exec <container> bash -c '
  apt-get update && apt-get install -y curl gpg
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
  echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
  apt-get install wazuh-agent
  # Registrar en manager Wazuh
  /var/ossec/bin/agent-control -i -n 10.202.15.100
'
```

**Beneficio:** Detectaría procesos sospechosos, cambios de archivos, intentos de escalada.

#### 2. **Habilitar Web Application Firewall (ModSecurity)**
```nginx
# En frontend nginx
location /api/m1/ {
    # ModSecurity reglas para SQL Injection, RCE, etc.
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;
}
```

**Beneficio:** Bloquearía SQL Injection, Command Injection, malformed requests.

#### 3. **Centralizar Logs de Aplicación Web**
```python
# En DVWA, bWAPP, OWASP Juice Shop
# Añadir logging a Wazuh:
import logging
logging.basicConfig(
    format='%(timestamp)s | %(user)s | %(action)s | %(ip)s | %(payload)s',
    handlers=[
        logging.handlers.SysLogHandler('/dev/log'),  # → Wazuh lo captura
    ]
)
```

**Beneficio:** Capturaría SQL Injection, XSS, file uploads, etc.

### P1 — Alto

#### 4. **Suricata + ET Rules actualizado**
```bash
# Validar que Suricata ve tráfico de 10.202.15.100
suricatasc -c "interface" | grep active

# Activar reglas de OWASP Top 10
suricata-update list-sources
suricata-update enable-source et/open
```

#### 5. **Auditbeat en contenedor objetivo**
```dockerfile
# En Dockerfile de 10.202.15.100
RUN curl -L -O https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-${VERSION}-linux-x86_64.tar.gz && \
    tar xzf auditbeat-*.tar.gz && \
    ./auditbeat/auditbeat setup && \
    ./auditbeat/auditbeat -c auditbeat.yml &
```

### P2 — Medio

#### 6. **Osquery para proceso/conexión monitoring**
```sql
-- Detectar procesos sospechosos
SELECT name, pid, path FROM processes WHERE name IN ('nmap', 'sqlmap', 'curl', 'wget');

-- Detectar conexiones de red anómala
SELECT remote_address, remote_port, state FROM process_open_sockets WHERE process_name = 'www-data';
```

#### 7. **YARA rules para malware**
```yara
rule WebShell {
    strings:
        $php1 = "eval($_POST" 
        $php2 = "system($_GET"
        $php3 = "passthru($_"
    condition:
        any of them
}
```

---

## 📈 Cobertura de Detección Actual vs Post-Fix

```
                        Antes     Después
Port Scan (Nmap)        ❌         ⚠️ (Suricata)
Web Enumeration         ❌         ✅ (WAF)
SQL Injection           ❌         ✅ (WAF + web logs)
Command Injection/RCE   ❌         ✅ (Wazuh agent + auditbeat)
SSH Login Attempts      ✅         ✅
System Processes        ❌         ✅ (Wazuh agent)
File Access/Changes     ❌         ✅ (Auditbeat FIM)
Network Connections     ⚠️         ✅ (Osquery + Suricata)
Data Exfiltration       ❌         ⚠️ (IDS rules)
```

---

## 🎯 Conclusión

**El ataque fue 100% exitoso porque 10.202.15.100 es una máquina "CIEGA" para el SIEM:**
- Sin agente de monitoreo → actividad del sistema **invisible**
- Sin WAF → payloads maliciosos **pasan sin validar**
- Sin logs centralizados → eventos de aplicación **no se registran**

**Implementar P0 (Wazuh agent + WAF + web logs) elevaría la detección de 0% → 85%+**

