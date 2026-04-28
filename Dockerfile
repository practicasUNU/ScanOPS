FROM python:3.11-slim

# 1. Instalar dependencias del sistema y Nmap
RUN apt-get update && apt-get install -y \
    nmap \
    wget \
    unzip \
    whois \
    && rm -rf /var/lib/apt/lists/*

# 2. Instalar Nuclei (US-3.2)
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.1.8/nuclei_3.1.8_linux_amd64.zip \
    && unzip nuclei_3.1.8_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.1.8_linux_amd64.zip

# 3. Instalar Subfinder (M2 - descubrimiento de subdominios)
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
    && unzip subfinder_2.6.6_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.6_linux_amd64.zip

# 4. Descargar plantillas de vulnerabilidades
RUN nuclei -update-templates

WORKDIR /app

# 4. Instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir .

EXPOSE 8001 8002

CMD ["uvicorn", "services.asset_manager.main:app", "--host", "0.0.0.0", "--port", "8001"]