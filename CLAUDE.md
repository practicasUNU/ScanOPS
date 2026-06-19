# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ScanOPS** is a modular, enterprise-grade cybersecurity auditing and assessment platform targeting **ENS Nivel Alto** (RD 311/2022) compliance. It combines network reconnaissance, vulnerability scanning, system hardening evaluation, and AI-powered analysis with automated reporting.

## Architecture: Microservices Stack

**Backend**: Python 3.8+, FastAPI, SQLAlchemy, PostgreSQL, Celery/Redis
- **M1 (Asset Manager)**: Port 8001 — asset inventory, metadata, CMDB
- **M2 (Scanner Engine)**: Port 8003 — network/vulnerability scanning orchestration
- **M3**: Port 8002 — additional scanning module
- **M4**: Port 8004 — exploitation/brute-force (Hydra, Gobuster) — **TOTP+PIN is exploitation limit for ENS evidence**
- **M5**: Port 8006 — specialized scanner
- **M7**: Port 8007 — reporting, PDF generation (httpx, PyJWT)
- **M8**: Port 8005 — secondary scanning/analysis
- **Orchestrator**: Port 8009 — task coordination
- **Celery Workers**: Async task processing (Redis-backed)

**Frontend** (React 18.3.1, Vite 6.x):
- `frontend/`: Main UI (TailwindCSS 4.1.12, Material UI, React Router 7.13.0)
- `scanops-dashboard/`: Secondary dashboard (Recharts)
- Dev server: localhost:5173

**Data & Messaging**:
- PostgreSQL 16 (`scanops` db)
- Redis 7 (Celery broker, alias `scanops-main-redis`)
- Alembic migrations in `alembic/`

**AI**: Ollama (Mistral:7b) at `host.docker.internal:11434` (local, for ENS mp.info.3 scope)

## Startup (Local Dev)

```bash
# 1. Full stack (from project root)
docker compose up -d

# 2. Orchestrator service
$env:JWT_SECRET_KEY = "scanops-secret-ens-alto-2026"
python -m uvicorn services.orchestrator.main:app --host 0.0.0.0 --port 8009 --reload

# 3. Frontend (in another terminal)
cd frontend
pnpm install  # or npm install
pnpm dev
```

Visit `http://localhost:5173` for the UI.

## Common Commands

### Docker
```bash
docker compose up -d                    # Start stack
docker compose up -d --build            # Rebuild + start
docker compose logs -f <service>        # Stream logs (e.g., m1, orchestrator)
docker compose down                     # Stop (keeps volumes)
docker compose down -v                  # Stop + DELETE volumes ⚠️ destructive
docker compose build <service>          # Rebuild one service
```

### Python/Backend
```bash
# Install (one-time)
pip install -r requirements.txt
pip install -e .                        # Dev mode

# Run tests
pytest                                  # All tests
pytest services/*/tests -v             # Service tests
pytest -m integration                   # Only integration tests (needs Docker)
pytest -k "test_name"                  # Single test

# Run migrations (required before first start)
alembic upgrade head

# Celery tasks (for debugging)
celery -A shared.celery_app inspect active
celery -A shared.celery_app flower      # UI at :5555
```

### Frontend
```bash
cd frontend
pnpm install
pnpm dev                                # Vite dev server
pnpm build && pnpm preview             # Production build + preview
```

## Project Structure (Simplified)

```
ScanOPS/
├── services/                    # Microservices (Python/FastAPI)
│   ├── asset_manager/          # M1: Asset management
│   ├── scanner_engine/         # M2: Scanning orchestration
│   ├── ai_reasoning/           # Ollama integration
│   ├── reporting_engine/       # Report generation
│   ├── exploit_engine/         # Exploit suggestions
│   └── orchestrator/           # M9: Task coordination
├── shared/                      # Shared code (Celery, auth, config)
├── frontend/                    # React UI (Vite)
├── scanops-dashboard/          # Secondary React dashboard
├── alembic/                    # Database migrations
├── tests/                      # Root tests
├── docker-compose.yml          # Local stack definition
├── Dockerfile*                 # Multi-service images
├── pyproject.toml             # Build config + pytest settings
├── requirements.txt           # Dependencies
└── README.md                  # General docs
```

## Critical Rules (Boilerplate)

- **Always `docker compose build` before `up --force-recreate`** — never just `docker restart` (Python changes don't hot-reload)
- **JWT_SECRET_KEY must be `scanops-secret-ens-alto-2026`** in all services (set in docker-compose.yml)
- **Redis alias `scanops-main-redis`** — do not confuse with other Redis instances
- **Never run `docker compose down -v`** in shared environments (destroys database)
- **Use PowerShell, not Git Bash** for commands on Windows
- **Ollama model: `mistral:7b`** — do not use variants
- **MSF is permanently removed** — do not add references

## Environment & Secrets

**Docker-compose vars**:
- DATABASE_URL: `postgresql://scanops:scanops@postgres:5432/scanops`
- REDIS_URL: `redis://scanops-main-redis:6379/0`
- OLLAMA_BASE_URL: `http://host.docker.internal:11434`
- JWT_SECRET_KEY: `scanops-secret-ens-alto-2026`

**Sensitive data**: 
- VAULT_ADDR / VAULT_TOKEN for credential storage (HashiCorp Vault, optional)
- TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID for notifications (optional)
- .env files should NOT be committed

See `services/ai_reasoning/.env.example` for service-specific templates.

## Test Targets (Local/Lab)

- **Internal**: 10.202.15.100 (credentials: admin:test123)
- **External**: pruebas.unuware.com / 82.223.9.162

## ENS Nivel Alto (RD 311/2022) — In Scope

Controls being validated:
- **op.acc.1, op.acc.6**: Access control & user management
- **op.exp.2, op.exp.4, op.exp.5**: Exploitation testing (Hydra/Gobuster; TOTP+PIN boundary)
- **mp.info.3, mp.info.4**: Information & config management (Ollama analysis)
- **mp.si.5**: Security incident response
- **op.cont.2**: Continuous monitoring

**Evidence generation**: Login session logging (`shared/auth.py`), SSH-based SIEM log collection (paramiko over SSH, not Wazuh/UDP).

## Current Status (Known Complete)

- Frontend H8: 100% (25/25 Playwright tests passing)
- M4 (Exploit): Hydra + Gobuster operational; TOTP+PIN is the exploitation boundary for ENS evidence
- M7 (Reporting): PDF generation operational
- Auth: Session logging implemented in `shared/auth.py` + `auth_router.py`

## Async & Celery

Tasks are queued to Redis and processed by `celery-worker` container. Task queues:
- `discovery` — asset discovery tasks
- `vulnerabilities` — scanning results processing
- `heavy_scans` — resource-intensive operations
- `scanner_tasks` — per-scanner orchestration
- `ai_reasoning` — LLM analysis
- `exploitation` — exploit/remediation suggestions
- `reporting` — report generation

Monitor with Celery Flower or CLI: `celery -A shared.celery_app inspect active`

## Debugging

**Service logs**:
```bash
docker compose logs -f m1                   # Asset Manager
docker compose logs -f orchestrator
docker compose logs -f celery-worker
```

**Database access**:
```bash
psql postgresql://scanops:scanops@localhost:5432/scanops
\dt                                        # List tables
\d asset_manager.assets                    # Describe table
```

**Test a single endpoint** (after `docker compose up -d`):
```bash
curl http://localhost:8001/health
curl http://localhost:8001/assets
```

## Common Workflows

### Add a new API endpoint
1. Create route in `services/{module}/api/routes.py` or similar
2. Use Pydantic schemas for validation
3. Query via SQLAlchemy ORM
4. Add test in `services/{module}/tests/test_api.py`
5. Run: `pytest services/{module}/tests/test_api.py -v`

### Add a database migration
1. Create new schema/table
2. Auto-generate: `alembic revision --autogenerate -m "description"`
3. Review `alembic/versions/*.py`
4. Apply: `alembic upgrade head`

### Queue an async task
1. Define in `shared/tasks.py` or service-specific task module
2. Decorate with `@shared.celery_app.task`
3. Call from endpoint: `task_name.delay(args)`
4. Monitor in Celery logs or Flower UI

## Contributing Checklist

- [ ] Branch name is descriptive
- [ ] All tests pass: `pytest`
- [ ] Test in Docker: `docker compose up -d && curl http://localhost:8001/health`
- [ ] Migrations applied: `alembic upgrade head`
- [ ] No secrets in diff (check `.env`, credentials)
- [ ] PR includes test evidence (screenshots/logs if UI change)
- [ ] No references to removed tools (e.g., MSF)