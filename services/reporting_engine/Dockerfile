FROM python:3.11-slim

WORKDIR /app

# Instalamos las librerías gráficas para WeasyPrint (Actualizadas para Debian Trixie/Bookworm)
RUN apt-get update && apt-get install -y \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libglib2.0-0 \
    shared-mime-info \
    fontconfig \
    && rm -rf /var/lib/apt/lists/*

# Copiamos e instalamos dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos el código
COPY . .

# Arrancamos FastAPI
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]