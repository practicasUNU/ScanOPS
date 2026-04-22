FROM python:3.11-slim

# Instalar nmap para discovery (US-1.4)
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY . .

EXPOSE 8001

CMD ["uvicorn", "services.asset_manager.main:app", "--host", "0.0.0.0", "--port", "8001"]