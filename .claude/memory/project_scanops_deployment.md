---
name: scanops_deployment_status
description: Production deployment blockers and next steps for ScanOPS server deployment
metadata:
  type: project
---

## Current State (Dev Environment)

- **OS**: Windows 11 + WSL2
- **Frontend**: Vite dev server (`pnpm dev` on localhost:5173)
- **Orchestrator**: Manual launch from PowerShell (`uvicorn services.orchestrator.main:app`)
- **Services M1–M8**: Fully dockerized (running in docker-compose.yml)
- **Ollama**: Local host (mistral:7b on host.docker.internal:11434)

## Deployment Blockers (5 Critical Issues)

**1. Frontend not in Docker**
- Currently: `pnpm dev` (Vite dev server, localhost:5173)
- Needed: Build static (pnpm build → dist/), serve via Nginx
- Missing: Dockerfile.frontend, no Nginx in docker-compose.yml

**2. Orchestrator untested in Docker**
- Currently: Manual launch to work around import path issues
- Dockerfile.orchestrator exists but never built/tested
- Must verify container builds & runs without manual intervention

**3. No reverse proxy / API routing**
- Currently: Services expose ports directly (M1:8001, M2:8003, ..., Orchestrator:8009)
- Needed: Nginx/Traefik to route /api/m1/* → M1, /api/m2/* → M2, etc.; serve frontend on /
- Missing: nginx.conf or Traefik config, Nginx service in compose

**4. Secrets hardcoded, no production .env**
- Currently: IPs (10.202.15.100, 10.202.15.199) & secrets in docker-compose.yml, test credentials visible
- Needed: .env.production with real server IPs, separate secrets management
- Risk: Credentials exposed in git history

**5. No HTTPS / certificate management**
- Currently: Dev-only HTTP on exposed ports
- Needed: HTTPS with real or self-signed certs, certificate renewal strategy

## Target Server Requirements

- **OS**: Ubuntu 22.04+ (Linux, not Windows)
- **Runtime**: Docker + Docker Compose v2
- **External service**: Ollama on host (not in container) with mistral:7b pre-downloaded
- **Hardware**: 16GB RAM minimum (8GB + services), 2+ CPU cores
- **Network**: Port 80/443 open if external access required

## Implementation Roadmap

### Phase 1 — Frontend Docker + Nginx (Week 1)
1. Create `Dockerfile.frontend` (multi-stage: build with Vite, serve with Nginx)
2. Create `nginx.conf` with reverse proxy rules
3. Add `frontend` and `nginx` services to docker-compose.yml
4. Test locally: `docker compose up frontend nginx`

### Phase 2 — Verify Orchestrator in Docker (Week 1)
1. Fix import paths in `services/orchestrator/main.py` (absolute vs. relative)
2. Build: `docker compose build orchestrator`
3. Test: `docker compose up orchestrator` (must start without manual uvicorn)
4. Verify /health endpoint responds

### Phase 3 — Production .env Structure (Week 1)
1. Create `.env.production` template with placeholders
2. Remove hardcoded secrets from docker-compose.yml
3. Use environment variable substitution in compose file
4. Document which vars must be set before deploy

### Phase 4 — HTTPS & Security (Week 2)
1. Self-signed cert generation script (for internal) or Let's Encrypt integration (for external)
2. Nginx cert mounting in docker-compose.yml
3. Redirect HTTP → HTTPS

### Phase 5 — Integration Test on Linux (Week 2)
1. Spin up Ubuntu 22.04 VM / cloud instance
2. Install Docker, pull repo, run `docker compose up -d`
3. Test all endpoints: GET /, GET /api/m1/health, etc.
4. Load test & monitor resources

## Why This Order?

- **Phase 1 + 2 first**: Frontend + Orchestrator are the only non-dockerized pieces; unblock the rest
- **Phase 3 in parallel**: .env refactoring can happen while Phase 1/2 are building
- **Phase 4 after 3**: HTTPS depends on certs, which depend on .env having real hostnames
- **Phase 5 validates all**: Real server test catches environment-specific issues (path volumes, port bindings, etc.)

## Known Risks

- **Import paths**: Orchestrator uses absolute imports; might fail in container. Test early (Phase 2).
- **Ollama external**: Can't run in Docker on Linux same way as WSL2 host.docker.internal; must bind-mount host socket or use network mode.
- **Database volume**: PostgreSQL data persists in docker-compose named volume `pgdata`; backup before deploy.
- **Hardcoded IPs in code**: grep for "10.202.15", "10.202.15.199" across services; may need parametrization.

## Estimated Effort

- **Frontend Dockerfile + Nginx**: 2–3 hours
- **Orchestrator Docker verification**: 1–2 hours
- **Production .env**: 1 hour
- **HTTPS setup**: 1–2 hours
- **Linux integration test**: 2–3 hours (including troubleshooting)
- **Total**: ~9–12 hours work

## Success Criteria

- [ ] `docker compose up -d` starts all 12+ services without manual intervention
- [ ] Frontend loads at `http://localhost/` (or https://localhost)
- [ ] API requests route via Nginx: `curl http://localhost/api/m1/health` → M1 responds
- [ ] All services pass healthchecks within 60s
- [ ] Load test: 100 concurrent requests, <1s latency at p95
- [ ] PostgreSQL & Redis volumes persist after `docker compose down` + `up`
