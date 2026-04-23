# Guía de Solución de Problemas (Troubleshooting) - ScanOPS

Esta guía contiene soluciones a los errores más comunes reportados durante la instalación y ejecución del sistema ScanOPS.

---

## 1. Error: "No module named 'psycopg2'"
Este error ocurre cuando el driver de PostgreSQL no está instalado o el sistema intenta buscar la versión de sistema en lugar del binario.

**Solución:**
Instala la versión binaria pre-compilada:
```bash
pip install psycopg2-binary
```
Si usas el script de instalación automática, esto se verifica automáticamente.

---

## 2. Error: "No module named 'gvm'"
Este error aparece al intentar importar el cliente de OpenVAS sin haber instalado las dependencias opcionales.

**Solución:**
Instala las herramientas de GVM (necesario solo si vas a realizar escaneos reales con OpenVAS):
```bash
pip install gvm-tools python-gvm
```
*Nota: Si estás en modo desarrollo/mock, puedes ignorar este error si los tests están configurados para saltar estas pruebas.*

---

## 3. Error: "Expected 'except' or 'finally' block" (SyntaxError)
Error de sintaxis común en bloques `try...except` donde falta el bloque de captura o el bloque está mal indentado.

**Solución:**
Revisar el archivo afectado (comúnmente `scan.py` o los clientes de scanners). Asegúrate de que cada `try` tenga su correspondiente `except`:
```python
try:
    # Código que puede fallar
    do_something()
except Exception as e:
    # Bloque obligatorio
    print(f"Error: {e}")
```

---

## 4. Error: "psycopg2.OperationalError: could not connect to server"
El sistema no puede contactar con la base de datos PostgreSQL.

**Solución:**
1. **Verificar PostgreSQL:** Asegúrate de que el servicio de Postgres esté corriendo.
   ```bash
   # En Linux
   sudo systemctl status postgresql
   # En Docker
   docker-compose ps
   ```
2. **Cambiar a SQLite (Solo para tests):** Si no tienes Postgres instalado localmente, puedes usar SQLite temporalmente en tu `.env`:
   ```env
   DATABASE_URL=sqlite:///./test.db
   ```

---

## 5. Error: "ModuleNotFoundError: No module named 'services.recon_engine'"
Ocurre cuando intentas ejecutar un script desde una subcarpeta y Python no reconoce la estructura del proyecto.

**Solución:**
Instala el proyecto en modo "editable". Esto permite que el directorio raíz se reconozca como un paquete de Python:
```bash
# Ejecutar desde la raíz del proyecto (donde está pyproject.toml)
pip install -e .
```
Esto creará los enlaces necesarios para que `import services...` funcione desde cualquier lugar.

---

## 6. Otros Errores de Dependencias
Si experimentas errores de "paquete no encontrado" generales:

**Solución:**
Asegúrate de haber instalado todos los requerimientos:
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```
