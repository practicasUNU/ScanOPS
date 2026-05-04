FROM python:3.11-slim

# Instalar dependencias del sistema y herramientas de compilación para NetExec
RUN apt-get update && apt-get install -y \
    nmap \
    hydra \
    git \
    gcc \
    python3-dev \
    libssl-dev \
    libffi-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Instalar NetExec desde GitHub
RUN pip install --no-cache-dir git+https://github.com/Pennyw0rth/NetExec

WORKDIR /app

# Copiar requerimientos e instalar
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar estructura de paquetes necesaria
COPY services/__init__.py /app/services/
COPY services/exploit_engine /app/services/exploit_engine
COPY shared /app/shared

EXPOSE 8004

# Comando para ejecutar la aplicación
CMD ["uvicorn", "services.exploit_engine.main:app", "--host", "0.0.0.0", "--port", "8004"]
