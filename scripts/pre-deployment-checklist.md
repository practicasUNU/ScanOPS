# Pre-Deployment Checklist

Complete this before deploying to server.

## ✅ Code & Configuration

- [ ] **Frontend Dockerfile created** (`Dockerfile.frontend`)
  - [ ] Uses multi-stage build (Vite build + Nginx serve)
  - [ ] Copies nginx.conf into image

- [ ] **nginx.conf created** with reverse proxy rules
  - [ ] Routes `/api/*` to correct backend services
  - [ ] Serves frontend on `/`
  - [ ] Has healthcheck endpoint `/health`

- [ ] **docker-compose.yml updated** with nginx + frontend services
  - [ ] Frontend service builds from Dockerfile.frontend
  - [ ] Nginx service mounts nginx.conf and certs volumes
  - [ ] All services have internal network (no exposed ports except nginx)

- [ ] **docker-compose.production.yml created**
  - [ ] Inherits from main compose file
  - [ ] Removes port exposures (except nginx 80/443)
  - [ ] Sets restart policies to `always`
  - [ ] Uses environment variables from .env.production

- [ ] **.env.production.example created**
  - [ ] All secrets marked as `CHANGE_ME_*`
  - [ ] Includes database, Redis, JWT, OLLAMA, VAULT, SMTP configs
  - [ ] Has comments explaining each variable

## 🔧 Local Testing

- [ ] **Frontend builds locally**
  ```bash
  cd frontend && pnpm build
  ```

- [ ] **Dockerfile.frontend builds**
  ```bash
  docker build -f Dockerfile.frontend -t scanops-frontend:test .
  docker run -p 5000:80 scanops-frontend:test
  # Visit http://localhost:5000 → should load React UI
  ```

- [ ] **Orchestrator builds and starts in Docker** (Fase 2)
  ```bash
  docker compose build orchestrator
  docker compose up postgres redis orchestrator
  curl http://localhost:8009/health  # Should respond
  ```

- [ ] **Full stack boots on localhost**
  ```bash
  docker compose up -d
  # Wait 2–3 minutes for healthchecks
  docker compose ps  # All containers RUNNING
  ```

- [ ] **nginx routes work**
  ```bash
  curl http://localhost/health            # → 200
  curl http://localhost/api/m1/health     # → M1 responds
  curl http://localhost:5173              # → Frontend loads (dev) or 502 (expected if frontend not running dev mode)
  ```

## 🔐 Secrets & Security

- [ ] **No secrets in git**
  ```bash
  git log --all --source --full-history -S "PASSWORD\|SECRET\|TOKEN" | head
  # Should return nothing or only .env.example entries
  ```

- [ ] **JWT_SECRET_KEY generated** (unique per environment)
  ```bash
  openssl rand -hex 32
  ```

- [ ] **Database password is strong** (≥12 chars, mixed)
  ```bash
  openssl rand -base64 18
  ```

- [ ] **.env.production is gitignored**
  ```bash
  grep -q ".env.production" .gitignore && echo "OK" || echo "ADD TO .gitignore"
  ```

- [ ] **No test credentials in code**
  ```bash
  grep -r "admin:test123\|10\.202\.15\." services/ || echo "OK"
  ```

## 📦 Deliverables

- [ ] **Deploy script ready** (`scripts/deploy-linux.md`)
- [ ] **Troubleshooting doc ready** (in deploy-linux.md)
- [ ] **All 5 files in place**:
  1. `Dockerfile.frontend`
  2. `nginx.conf`
  3. `docker-compose.production.yml`
  4. `.env.production.example`
  5. `scripts/deploy-linux.md`

## 🚀 Server Readiness

- [ ] **Target server OS confirmed**: Ubuntu 22.04+
- [ ] **Docker installed on server**
- [ ] **SSH access configured**
- [ ] **Domain/IP for PLATFORM_URL decided**
- [ ] **SSL certificate plan** (Let's Encrypt or self-signed)
- [ ] **Ollama installed on host** with `mistral:7b` pulled
- [ ] **Firewall**: Port 80/443 open (if external), internal networks isolated
- [ ] **RAM/CPU**: 16GB RAM, 4+ cores available
- [ ] **Disk space**: 50GB+ (docker images + postgres data)

## 📝 Documentation

- [ ] **CLAUDE.md updated** with production deployment info
- [ ] **README.md** has quick-start for production
- [ ] **deploy-linux.md** is clear and tested (at least reviewed)

## 🧪 Integration Test Plan

After server deployment:

1. **Smoke test**
   ```bash
   curl https://scanops.example.com/
   curl https://scanops.example.com/api/m1/health
   ```

2. **Feature test** (at least one end-to-end flow)
   - Create asset in M1
   - Trigger scan via M2
   - Check results in database

3. **Load test** (optional, but recommended)
   ```bash
   ab -n 100 -c 10 https://scanops.example.com/
   ```

4. **Monitor logs** for errors
   ```bash
   docker compose logs --tail=500 | grep -i error
   ```

## ✨ Nice-to-Have (Not Blocking)

- [ ] Monitoring setup (Prometheus, Grafana, or equivalent)
- [ ] Log aggregation (ELK, Graylog, etc.)
- [ ] Backup cron job for PostgreSQL
- [ ] DNS health check setup
- [ ] Incident response runbook
- [ ] Disaster recovery plan

---

**Status**: `[ ] NOT READY` → Finish all ✅ items above before deployment

**Expected completion**: By end of Week 1
