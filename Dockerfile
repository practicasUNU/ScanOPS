FROM python:3.11-slim

# 1. Instalar Nmap (US-1.4) y dependencias para Nuclei 
RUN apt-get update && apt-get install -y \
    nmap \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# 2. Instalar Nuclei (US-3.2: Detección de Zero-days) [cite: 37, 41]
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.1.8/nuclei_3.1.8_linux_amd64.zip \
    && unzip nuclei_3.1.8_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.1.8_linux_amd64.zip

# 3. Descargar plantillas de vulnerabilidades (Mantenimiento US-3.2)
RUN nuclei -update-templates

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir . [cite: 182]

COPY . .

# Exponemos los puertos necesarios para el ecosistema
EXPOSE 8001 8002 

# Por defecto dejamos el de Asset Manager, pero el compose lo sobreescribe para M3
CMD ["uvicorn", "services.asset_manager.main:app", "--host", "0.0.0.0", "--port", "8001"]