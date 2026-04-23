#!/bin/bash

echo "=== ScanOPS Installation Script (Unix) ==="

# 1. Verifica Python 3.8+
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 no está instalado."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "[ERROR] Python $REQUIRED_VERSION+ es requerido. Versión detectada: $PYTHON_VERSION"
    exit 1
fi
echo "Python detectado: $PYTHON_VERSION (OK)"

# 2. Crea virtualenv si no existe
if [ ! -d "venv" ]; then
    echo "Creando entorno virtual (venv)..."
    python3 -m venv venv
else
    echo "Entorno virtual ya existe."
fi

# Activar entorno virtual
echo "Activando entorno virtual..."
source venv/bin/activate

# Asegurar pip actualizado
pip install --upgrade pip

# 3. pip install -e .
echo "Instalando dependencias del núcleo (editable)..."
pip install -e .

# 4. pip install -r requirements-dev.txt (para tests)
if [ -f "requirements-dev.txt" ]; then
    echo "Instalando dependencias de desarrollo..."
    pip install -r requirements-dev.txt
else
    echo "[AVISO] requirements-dev.txt no encontrado."
fi

# 5. Verifica que psycopg2 se instaló
echo "Verificando instalación de psycopg2..."
if python -c "import psycopg2" &> /dev/null; then
    echo "psycopg2 importado con éxito"
else
    echo "[ERROR] psycopg2 no se instaló correctamente."
    echo "Intente ejecutar: pip install psycopg2-binary"
    exit 1
fi

# 6. Echo "✅ Instalación completada"
echo ""
echo "✅ Instalación completada correctamente."
echo "Para empezar, activa el entorno con: source venv/bin/activate"
echo ""
