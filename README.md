# ScanOps 🛡️

Plataforma de evaluación continua y auditoría de ciberseguridad para entornos críticos con foco en ENS Nivel Alto.

## Descripción

ScanOps es un framework modular de auditoría automatizada que combina escaneo de red, evaluación de salud de sistemas y hardening.
Permite ejecutar pruebas programadas, generar reportes integrados y detectar activos no autorizados dentro de inventarios.

## Características principales

- Escaneo de red con detección de puertos y servicios.
- Evaluación de salud de servidores remotos (CPU, RAM, disco, servicios).
- Comprobación de controles de hardening y cumplimiento ENS.
- Detección de Shadow IT basada en inventario simulado.
- Salida estructurada en JSON para orquestación y reporte maestro.

## Arquitectura del proyecto

- `scripts/main_orchestrator.py`: Orquestador principal que ejecuta módulos y consolida reportes.
- `src/modules/scanner_network.py`: Escaneo de red con `masscan`, `subfinder` y `nmap`.
- `src/modules/scanner_health.py`: Evaluación de métricas de servidor y servicios.
- `src/modules/scanner_hardening.py`: Auditoría de configuración y controles de seguridad.
- `src/utils.py`: Funciones compartidas de evaluación y resumen.
- `src/scan_logger.py`: Logging estructurado de eventos y métricas.

## Requisitos

- Python 3.11+ (compatible con 3.14 en el entorno actual).
- `paramiko` para conexiones SSH remotas.
- `pytest` para ejecutar pruebas.
- `masscan`, `subfinder` y `nmap` si desea usar el módulo de red completo.

## Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/practicasUNU/ScanOPS.git
   cd ScanOPS
   ```

2. Crea un entorno virtual:
   ```bash
   python -m venv .venv
   source .venv/Scripts/activate   # Windows
   source .venv/bin/activate       # Linux/macOS
   ```

3. Instala dependencias:
   ```bash
   python -m pip install --upgrade pip
   python -m pip install paramiko pytest
   ```

## Uso

### Ejecutar el orquestador

```bash
python scripts/main_orchestrator.py
```

Esto ejecuta los módulos de red, salud y hardening, y genera `output/master_audit_report.json`.

### Ejecutar un módulo individual

```bash
python src/modules/scanner_network.py
python src/modules/scanner_health.py
python src/modules/scanner_hardening.py
```

### Salida esperada

- `output/master_audit_report.json`: reporte maestro consolidado.
- `output/tmp_health.json`: salida del módulo de salud.
- `output/tmp_hardening.json`: salida del módulo de hardening.

> Nota: `scanner_network.py` ahora retorna el resultado directamente como JSON en stdout y no depende de un archivo temporal.

## Pruebas

Ejecuta:

```bash
pytest
```

o solo el conjunto de tests de red:

```bash
pytest tests/test_scanner_network.py
```

## Estructura de directorios

```text
ScanOPS/
├── api/
├── docs/
├── infra/
├── output/
├── scripts/
│   └── main_orchestrator.py
├── src/
│   ├── modules/
│   │   ├── scanner_hardening.py
│   │   ├── scanner_health.py
│   │   └── scanner_network.py
│   ├── scan_logger.py
│   └── utils.py
├── tests/
└── pyproject.toml
```

## Buenas prácticas

- Usa un entorno virtual para aislar dependencias.
- No subas credenciales ni contraseñas en texto plano.
- En `scanner_hardening.py`, reemplaza credenciales con un gestor seguro.

## Contribución

1. Crea una rama con un nombre descriptivo.
2. Abre un pull request con descripción y pruebas.
3. Asegura que `pytest` pase antes de solicitar revisión.

## Licencia

Indica aquí la licencia del proyecto si aplica. Si no hay licencia definida, se recomienda añadir una antes de distribuir el código.
