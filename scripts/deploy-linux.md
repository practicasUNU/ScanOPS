# ScanOPS Deployment Guide (Linux Server)

## Prerequisites

- Ubuntu 22.04 LTS or newer
- Docker + Docker Compose v2.0+
- Ollama installed on host (mistral:7b model downloaded)
- 16GB RAM, 4+ CPU cores
- Port 80/443 open to internet (if external access)

## Step 1: Setup Server & Dependencies

```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install Docker
sudo apt install -y docker.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker

# 3. Clone project
cd /opt
sudo git clone https://github.com/practicasUNU/ScanOPS.git
cd ScanOPS
sudo chown -R $USER:$USER .

# 4. Install Ollama (if not already installed)
curl -fsSL https://ollama.ai/install.sh | sh
# Pull model (runs in background if not already present)
ollama pull mistral:7b
```

## Step 2: Prepare Environment

```bash
# 1. Generate strong JWT secret
JWT_SECRET=$(openssl rand -hex 32)
echo "JWT_SECRET_KEY=$JWT_SECRET"  # Save this value

# 2. Copy env template
cp .env.production.example .env.production

# 3. Edit .env.production with real values
sudo nano .env.production

# Critical values to set:
# - DB_PASSWORD: Strong unique password
# - REDIS_PASSWORD: Strong unique password
# - JWT_SECRET_KEY: Generated above
# - PLATFORM_URL: Your domain (e.g., https://scanops.example.com)
# - OLLAMA_BASE_URL: http://localhost:11434 (for host Ollama)
```

## Step 3: SSL/TLS Certificates

### Option A: Self-signed (Internal Only)

```bash
mkdir -p certs

openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -nodes \
  -subj "/CN=scanops.example.com"

# Update nginx.conf to use certs/cert.pem and certs/key.pem
```

### Option B: Let's Encrypt (External)

```bash
sudo apt install -y certbot python3-certbot-nginx

sudo certbot certonly --standalone \
  -d scanops.example.com \
  -d www.scanops.example.com

# Certs will be in /etc/letsencrypt/live/scanops.example.com/
# Update nginx.conf paths accordingly
```

## Step 4: Update Nginx Config

Edit `nginx.conf` and update:

```nginx
server_name scanops.example.com;

listen 443 ssl http2;
ssl_certificate /etc/nginx/certs/cert.pem;
ssl_certificate_key /etc/nginx/certs/key.pem;

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}
```

## Step 5: Database Setup

```bash
# Load .env vars
export $(cat .env.production | xargs)

# Run migrations
docker compose -f docker-compose.yml -f docker-compose.production.yml run --rm m1 \
  alembic upgrade head

# Create initial admin user (if applicable)
docker compose -f docker-compose.yml -f docker-compose.production.yml exec m1 \
  python -m scripts.create_admin --email admin@scanops.com --password CHANGE_ME
```

## Step 6: Start Stack

```bash
# Load env
export $(cat .env.production | xargs)

# Start all services
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d

# Wait for healthchecks (2–3 min)
docker compose -f docker-compose.yml -f docker-compose.production.yml ps

# View logs
docker compose -f docker-compose.yml -f docker-compose.production.yml logs -f
```

## Step 7: Verify Deployment

```bash
# Test frontend
curl https://scanops.example.com/

# Test API
curl -k https://scanops.example.com/api/m1/health

# Test all services
for m in m1 m2 m3 m4 m5 m7 m8; do
  echo "Testing $m..."
  curl -k https://scanops.example.com/api/${m}/ 2>/dev/null | head -c 100
  echo ""
done

# Check Docker logs for errors
docker compose logs --tail=100
```

## Step 8: Monitoring & Maintenance

### Logs
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f m1

# Last 100 lines
docker compose logs --tail=100
```

### Backup Database
```bash
docker compose exec -T postgres pg_dump -U scanops scanops > backup-$(date +%Y%m%d-%H%M%S).sql
```

### Restore Database
```bash
docker compose exec -T postgres psql -U scanops scanops < backup-20240101-120000.sql
```

### Update Ollama Model
```bash
ollama pull mistral:7b
```

### Restart Services
```bash
# Restart one service
docker compose restart m1

# Restart all
docker compose restart

# Rebuild and restart (after code changes)
docker compose up -d --build
```

## Troubleshooting

### Nginx: "upstream timed out"
- Check if backend services are running: `docker compose ps`
- Check service logs: `docker compose logs m1`
- Increase proxy timeouts in nginx.conf if services are slow

### Ollama: "connection refused"
- Verify Ollama is running: `ollama list`
- Check if accessible: `curl http://localhost:11434/api/tags`
- Adjust OLLAMA_BASE_URL in .env if running on different host

### Database: "connection refused"
- Check postgres container: `docker compose ps postgres`
- View postgres logs: `docker compose logs postgres`
- Verify DATABASE_URL in .env is correct

### Certificate issues
- Verify cert paths in nginx.conf
- Check certs exist: `ls -la certs/`
- Renew Let's Encrypt: `sudo certbot renew`

## Systemd Service (Optional)

Create `/etc/systemd/system/scanops.service`:

```ini
[Unit]
Description=ScanOPS Cybersecurity Platform
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
WorkingDirectory=/opt/ScanOPS
ExecStart=/usr/bin/docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
ExecStop=/usr/bin/docker compose -f docker-compose.yml -f docker-compose.production.yml down
RemainAfterExit=yes
User=scanops

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable scanops
sudo systemctl start scanops
sudo systemctl status scanops
```

## Support

- Logs: `/opt/ScanOPS/logs/`
- Database: `psql postgresql://scanops:PASSWORD@localhost/scanops`
- Nginx config: `/opt/ScanOPS/nginx.conf`
- Environment: `/opt/ScanOPS/.env.production`
