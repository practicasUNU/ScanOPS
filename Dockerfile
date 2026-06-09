FROM python:3.11-slim

# 1. Instalar dependencias del sistema y Nmap
RUN apt-get update && apt-get install -y \
    nmap \
    wget \
    unzip \
    whois \
    git \
    perl \
    libnet-ssleay-perl \
    libjson-perl \
    libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

# 2. Instalar Nuclei (US-3.2)
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.1.8/nuclei_3.1.8_linux_amd64.zip \
    && unzip nuclei_3.1.8_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.1.8_linux_amd64.zip

# 2.5 Instalar Nikto (Reemplazo de ZAP) - Instalado desde fuente
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# 3. Instalar Subfinder (M2 - descubrimiento de subdominios)
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
    && unzip subfinder_2.6.6_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.6_linux_amd64.zip

# 3.5 Instalar ffuf (US-3.X — endpoint fuzzing)
RUN wget https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    && tar -xzf ffuf_2.1.0_linux_amd64.tar.gz \
    && mv ffuf /usr/local/bin/ \
    && rm -f ffuf_2.1.0_linux_amd64.tar.gz LICENSE README.md CHANGELOG.md

# 3.6 Instalar WhatWeb (fingerprinting de tecnologías web)
RUN apt-get update && apt-get install -y whatweb && rm -rf /var/lib/apt/lists/*

# 3.7 Instalar testssl.sh (análisis TLS/SSL — ENS mp.com.2)
RUN apt-get update && apt-get install -y dnsutils bsdmainutils && rm -rf /var/lib/apt/lists/* \
    && wget https://github.com/drwetter/testssl.sh/archive/refs/tags/v3.2.3.tar.gz \
    && tar -xzf v3.2.3.tar.gz \
    && mv testssl.sh-3.2.3/testssl.sh /usr/local/bin/testssl.sh \
    && chmod +x /usr/local/bin/testssl.sh \
    && rm -rf testssl.sh-3.2.3 v3.2.3.tar.gz

# 3.8 Wordlist embebida para ffuf
RUN mkdir -p /usr/share/wordlists \
    && printf 'admin\nlogin\nbackup\n.env\n.git/HEAD\nwp-admin\napi\napi/v1\napi/v2\nconsole\nphpmyadmin\nphpinfo.php\nconfig.php\n.htaccess\nrobots.txt\nsitemap.xml\nswagger.json\nopenapi.json\nactuator\nactuator/health\nactuator/env\nmanager/html\nserver-status\nserver-info\ntest\ndebug\nold\ntmp\nupload\nuploads\nfiles\nstatic/admin\nadmin/config\nbackup.zip\nbackup.sql\ndb.sql\nconfig.bak\nweb.config\ncrossdomain.xml\n' \
    > /usr/share/wordlists/ffuf_web.txt

# 4. Descargar plantillas de vulnerabilidades
RUN nuclei -update-templates

WORKDIR /app

# 5. Instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x run_migrations.sh
RUN pip install --no-cache-dir .

EXPOSE 8001 8002

CMD ["uvicorn", "services.asset_manager.main:app", "--host", "0.0.0.0", "--port", "8001"]