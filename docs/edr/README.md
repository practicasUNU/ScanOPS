# M3.1 — EDR (Endpoint Detection & Response)

## What it does

M3.1 adds real-time behavioral monitoring to ScanOPS. It SSHs into a scanned asset, collects the running process list, detects suspicious behaviors (C2 callbacks, reverse shells, privilege escalation, data exfiltration), extracts IOCs, and enriches them with threat intelligence from VirusTotal, CrowdSec, and AlienVault OTX.

All findings feed the M8 AI reasoning engine for kill-chain detection and drive the Incident Response queue — the only way to execute a remediation action is through a human-in-the-loop TOTP+PIN approval gate.

---

## Quick Start

### 1. Prerequisites

```bash
# Running containers (from project root)
docker compose ps
# Must see: scanner-engine, celery-worker, m8, postgres, redis
```

Required env vars in `scanner-engine`:
```
VIRUSTOTAL_API_KEY=...
CROWDSEC_API_KEY=...
OTX_API_KEY=...
EDR_AUTO_REMEDIATE=false  # always start in manual mode
```

### 2. Run a behavioral scan

```bash
curl -X POST http://localhost:8002/api/m3/edr/behavioral-scan \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": 42,
    "ssh_host": "10.0.1.5",
    "ssh_user": "root",
    "ssh_password": "changeme",
    "ssh_port": 22
  }'
```

Response: `{ "task_id": "...", "status": "queued" }`

### 3. Check findings

```bash
curl http://localhost:8002/api/m3/edr/behavioral-findings?asset_id=42 \
  -H "Authorization: Bearer <jwt>"
```

### 4. Request a remediation action

```bash
curl -X POST http://localhost:8002/api/m3/edr/request-response-action \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": 42,
    "action_type": "kill_process",
    "target_detail": "PID:1337",
    "requested_by": "analyst@company.com",
    "justification": "Active C2 callback on port 4444",
    "pin": "MySecurePin1!"
  }'
```

Response includes a **QR code** and **TOTP secret** for the approver. The requester and approver must be different people (separation of duties).

### 5. Approve the action

```bash
curl -X POST http://localhost:8002/api/m3/edr/approve-action/7 \
  -H "Authorization: Bearer <jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "totp_code": "123456",
    "pin": "MySecurePin1!",
    "approved_by": "ciso@company.com"
  }'
```

---

## Dashboard

Navigate to `http://localhost:3000/edr` (requires `security_officer` or `system_manager` role).

The Incident Response queue is at `http://localhost:3000/incident-response`.

---

## Run the tests

```bash
# Inside container
docker compose exec scanner-engine python -m pytest \
  services/scanner_engine/tests/test_edr_unit.py \
  services/scanner_engine/tests/test_edr_integration.py \
  services/scanner_engine/tests/test_edr_performance.py \
  services/scanner_engine/tests/test_edr_security.py \
  -v --tb=short
```

---

## Further reading

- [API Reference](API_REFERENCE.md)
- [Architecture](ARCHITECTURE.md)
- [Deployment](DEPLOYMENT.md)
- [Troubleshooting](TROUBLESHOOTING.md)
