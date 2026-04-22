FROM python:3.11-slim

# 1. Instalar dependencias del sistema y Nmap
RUN apt-get update && apt-get install -y \
    nmap \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# 2. Instalar Nuclei (US-3.2)
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.1.8/nuclei_3.1.8_linux_amd64.zip \
    && unzip nuclei_3.1.8_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.1.8_linux_amd64.zip

# 3. Descargar plantillas de vulnerabilidades
RUN nuclei -update-templates

WORKDIR /app

# 4. Instalar dependencias de Python
COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY . .

EXPOSE 8001 8002

CMD ["uvicorn", "services.asset_manager.main:app", "--host", "0.0.0.0", "--port", "8001"]