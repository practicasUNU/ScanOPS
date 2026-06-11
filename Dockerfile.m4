FROM python:3.11-slim

# Instalar dependencias del sistema y herramientas de compilación para NetExec
RUN apt-get update && apt-get install -y \
    nmap \
    hydra \
    sqlmap \
    sshpass \
    openssh-client \
    gobuster \
    wget \
    iputils-ping \
    git \
    gcc \
    python3-dev \
    libssl-dev \
    libffi-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Wordlist: intentar descomprimir rockyou, si no existe crear lista mínima
RUN mkdir -p /usr/share/wordlists && printf 'password\n123456\ntest123\nadmin\nroot\nadmin123\npassword123\nletmein\nqwerty\n111111\n' > /usr/share/wordlists/demo.txt
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gunzip /usr/share/wordlists/rockyou.txt.gz; \
    fi && \
    if [ ! -f /usr/share/wordlists/rockyou.txt ]; then \
        mkdir -p /usr/share/wordlists && \
        printf 'admin\npassword\n123456\nroot\ntoor\nletmein\nqwerty\n12345678\nadmin123\npassword1\ntest\nguest\nubuntu\nchangeme\nscanops\ntest123\nowaspbwa\n'  \
        > /usr/share/wordlists/rockyou.txt; \
    fi \
    && wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
       -O /usr/share/wordlists/common.txt \
    || echo "common.txt no descargado — usar docker cp"

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
