# M3.1 EDR — Deployment Guide

## Prerequisites

- Docker Compose v2.20+
- Python 3.11 (inside container — no local Python needed)
- Node.js 20+ (for frontend build only)
- PostgreSQL 15 (provided by the compose stack)
- Redis 7 (provided by the compose stack)

---

## Environment Variables

Add to `scanner-engine` service in `docker-compose.yml` (or `.env`):

```env
# Threat intelligence APIs
VIRUSTOTAL_API_KEY=your-vt-key
CROWDSEC_API_KEY=your-cs-bouncer-key
OTX_API_KEY=your-otx-key

# IR execution safety
EDR_AUTO_REMEDIATE=false       # set to true only after validation
EDR_TI_TTL_HOURS=24           # threat intel cache TTL

# M8 integration
M8_SERVICE_URL=http://m8:8005
AI_REASONING_DB_URL=postgresql://scanops:scanops@postgres:5432/scanops

# JWT (shared with other services)
JWT_SECRET_KEY=scanops-secret-ens-alto-2026
```

---

## Database Migrations (Alembic)

EDR tables are added in migration `0007_edr_behavioral_tables.py`.

```bash
# Run from project root
docker compose exec scanner-engine alembic upgrade head
```

To verify:
```bash
docker compose exec scanner-engine alembic current
# Should show: 0007_edr_behavioral_tables (head)
```

To roll back if needed:
```bash
docker compose exec scanner-engine alembic downgrade 0006
```

---

## Fresh Install

```bash
# 1. Clone and configure
git clone https://github.com/unuware/scanops.git
cd scanops
cp .env.example .env
# edit .env with your API keys

# 2. Build and start
docker compose build scanner-engine celery-worker m8
docker compose up -d

# 3. Run migrations
docker compose exec scanner-engine alembic upgrade head

# 4. Build and deploy frontend
cd frontend
npm install
npm run build
docker compose cp dist/. frontend:/usr/share/nginx/html/
docker compose exec frontend nginx -s reload
cd ..

# 5. Verify
curl http://localhost:8002/health
# {"status": "ok", "edr": "ready"}
```

---

## Hot-Deploy (Development)

### Backend changes

```powershell
# From project root (Windows PowerShell)
docker compose cp services/scanner_engine/. scanner-engine:/app/services/scanner_engine/
docker compose cp services/scanner_engine/. celery-worker:/app/services/scanner_engine/
docker compose restart scanner-engine celery-worker
```

### AI reasoning changes (M8)

```powershell
docker compose cp services/ai_reasoning/. m8:/app/services/ai_reasoning/
docker compose cp services/ai_reasoning/. celery-worker:/app/services/ai_reasoning/
docker compose restart m8 celery-worker
```

### Frontend changes

```powershell
cd frontend
npm run build
docker compose cp dist/. frontend:/usr/share/nginx/html/
docker compose exec frontend nginx -s reload
cd ..
```

---

## Post-Deploy Checks

```bash
# 1. EDR health
curl http://localhost:8002/api/m3/edr/stats \
  -H "Authorization: Bearer <jwt>"
# Expect: 200 with stats object

# 2. Celery workers registered
docker compose exec celery-worker celery -A services.celery_app inspect registered
# Expect: behavioral_scan_task, enrich_findings_with_threat_intel listed

# 3. YARA rules loaded
docker compose exec scanner-engine python -c \
  "from services.scanner_engine.services.yara_scanner import _load_rules; print(_load_rules())"
# Expect: <yara.Rules object ...>

# 4. M8 EDR context builder
docker compose exec m8 python -c \
  "from services.ai_reasoning.edr_context_builder import build_edr_context_for_asset; print('ok')"
# Expect: ok

# 5. Database tables exist
docker compose exec postgres psql -U scanops -c \
  "\dt behavioral_findings"
# Expect: table listed
```

---

## YARA Rules

Rules are stored in `services/scanner_engine/rules/edr_rules.yar`. To add new rules:

1. Edit the `.yar` file
2. Hot-deploy scanner-engine (see above)
3. The singleton is reloaded on next scan request (no restart needed)

The YARA scanner degrades gracefully if `yara-python` is not installed — it returns empty hits rather than crashing.

---

## Scaling

### Multiple Celery workers

Behavioral scans are CPU-bound (YARA). For high volume, scale celery-worker:

```bash
docker compose up -d --scale celery-worker=3
```

Threat intel enrichment is I/O-bound (HTTP). The circuit breakers handle transient failures; the TTL cache prevents API quota exhaustion.

### Separate queues

The `enrich_findings_with_threat_intel` task is dispatched to the `threat_intel` queue. Configure a dedicated worker:

```bash
celery -A services.celery_app worker -Q threat_intel -c 8 -l INFO
```

---

## Monitoring

Key Celery task metrics to watch:

| Task | Expected p95 latency | Alert threshold |
|---|---|---|
| `behavioral_scan_task` | < 30s (1000 procs) | > 60s |
| `enrich_findings_with_threat_intel` | < 5s (cache hit) / < 30s (miss) | > 120s |
| `run_full_ai_pipeline` | < 5 min | > 15 min |

Flower dashboard (if enabled): `http://localhost:5555`
