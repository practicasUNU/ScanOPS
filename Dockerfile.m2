FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --break-system-packages --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*
COPY services/recon_engine /app/services/recon_engine
COPY shared /app/shared
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 CMD python3 -c "import requests; requests.get('http://localhost:8003/health')" || exit 1
EXPOSE 8003
CMD ["python3", "-m", "uvicorn", "services.recon_engine.main:app", "--host", "0.0.0.0", "--port", "8003"]
