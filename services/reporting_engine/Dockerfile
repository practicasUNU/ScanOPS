FROM python:3.11-slim

WORKDIR /app

# 1. Instalamos las librerías gráficas para WeasyPrint
RUN apt-get update && apt-get install -y \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libglib2.0-0 \
    shared-mime-info \
    fontconfig \
    && rm -rf /var/lib/apt/lists/*

# 2. Copiamos e instalamos dependencias de Python estándar
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 3. ── INYECCIÓN FORZADA DE SEGURIDAD PARA GOOGLE DRIVE ──
RUN pip install --no-cache-dir google-api-python-client google-auth-httplib2 google-auth-oauthlib

# 4. Copiamos el código
COPY . .

# Arrancamos FastAPI
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]