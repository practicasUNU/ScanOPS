# M3.1 EDR — Troubleshooting

## Behavioral Scan Issues

### "SSH connection refused / timeout"

**Symptom**: `behavioral_scan_task` fails with `paramiko.ssh_exception.NoValidConnectionsError`.

**Causes and fixes**:
- Asset firewall blocks port 22: verify with `nmap -p 22 <host>`
- Wrong credentials: test manually with `ssh user@host` from inside the scanner-engine container
- SSH service not running on asset: check `systemctl status sshd` on target

```bash
# Test SSH from inside container
docker compose exec scanner-engine ssh -o StrictHostKeyChecking=no user@10.0.1.5
```

---

### "analyze_processes returned 0 anomalies" (false negative)

**Symptom**: Scan completes but no findings, even on a known-compromised host.

**Checks**:
1. Is `ps aux` returning full command lines? Some systems truncate at 64 chars.
   - Fix: Use `ps -eo pid,ppid,user,%cpu,%mem,comm,args --no-headers` (already in client)
2. Is the malicious process using obfuscation? Check if cmdline is base64-encoded.
   - The `OBFUSCATION` pattern detects `base64 -d` and `openssl enc` pipes.
3. YARA rules may not cover the specific variant.
   - Add a new rule to `services/scanner_engine/rules/edr_rules.yar`

---

### "YARA scanner not available"

**Symptom**: Logs show `YARA library not available — scanner disabled`.

**Fix**: Install yara-python in the container:
```bash
docker compose exec scanner-engine pip install yara-python
```

The scanner degrades gracefully (returns empty hits) if yara-python is absent — it does not crash.

---

## Threat Intel Issues

### "Circuit breaker OPEN for VirusTotal"

**Symptom**: Logs show `pybreaker.CircuitBreakerError` on VT calls; enrichment returns without VT data.

**When this happens**: After 5 consecutive VT API failures (rate limit, network error, invalid key).

**Reset**:
```bash
# Check circuit breaker state
docker compose exec celery-worker python -c "
from services.scanner_engine.services.threat_intel_service import _vt_circuit_breaker
print(_vt_circuit_breaker.current_state)
"
# If 'open', wait reset_timeout (300s) or restart worker to force reset
docker compose restart celery-worker
```

**Prevent**: Ensure `VIRUSTOTAL_API_KEY` is set. VT free tier: 4 req/min — the circuit breaker auto-throttles.

---

### "Threat intel cache always missing" (all requests hit APIs)

**Symptom**: Every enrichment task hits VT/CS/OTX even for the same IOC.

**Cause**: `EDR_TI_TTL_HOURS` is 0 or the cache table is being truncated.

**Fix**:
```bash
# Check TTL env var
docker compose exec scanner-engine env | grep TTL

# Check cache contents
docker compose exec postgres psql -U scanops -c \
  "SELECT ioc_value, expires_at FROM threat_intel_cache LIMIT 5;"
```

---

## Incident Response Issues

### "TOTP verification fails" (valid code rejected)

**Symptom**: `approve-action` returns 401 even with correct TOTP code.

**Causes**:
1. **Clock skew**: The container clock is more than 4 minutes off from the approver's device.
   - Check: `docker compose exec scanner-engine date` vs. `date` on approver machine
   - Fix: `docker compose exec scanner-engine ntpdate -u pool.ntp.org`
   - The `valid_window=8` in `pyotp.verify()` allows ±4 minutes (8 × 30s steps)
2. **TOTP secret rotated**: The `approval_token` in the DB was overwritten after the QR was shown.
   - This should not happen — never update `approval_token` after action creation.

---

### "PIN verification fails" (bcrypt error)

**Symptom**: `bcrypt.checkpw` raises `ValueError: Invalid salt`.

**Cause**: The stored `pin_hash` in `approval_token` JSON is corrupted or truncated.

**Fix**: The `approval_token` column is `VARCHAR(255)`. If the JSON is longer than 255 chars (rare), it gets silently truncated.

```sql
-- Check actual stored length
SELECT id, LENGTH(approval_token) FROM incident_response_logs WHERE id = 7;
```

If truncated, increase column size: `ALTER TABLE incident_response_logs ALTER COLUMN approval_token TYPE TEXT;`

---

### "Action stuck in pending"

**Symptom**: Action was approved but `status` never changes to `completed`.

**Cause**: `EDR_AUTO_REMEDIATE=false` (default). Approval only changes status to `approved`; execution requires either `EDR_AUTO_REMEDIATE=true` or a manual trigger.

**Fix (temporary)**:
```bash
# Manually execute via API
curl -X POST http://localhost:8002/api/m3/edr/execute-action/7 \
  -H "Authorization: Bearer <jwt>"
```

**Or enable auto-remediate**:
```bash
# docker-compose.yml → scanner-engine → environment
EDR_AUTO_REMEDIATE=true
docker compose up -d scanner-engine celery-worker
```

---

## M8 Integration Issues

### "EDR context unavailable for asset X"

**Symptom**: Logs in m8 container: `EDR context unavailable for asset 42: ...`

**Cause**: `build_edr_context_for_asset()` queries PostgreSQL. If the scanner-engine DB and M8 DB are different instances, M8 cannot see behavioral_findings.

**Fix**: Both services must use the same `AI_REASONING_DB_URL` / `DATABASE_URL` pointing to the same PostgreSQL instance.

```bash
# Verify M8 can see EDR data
docker compose exec m8 python -c "
from services.ai_reasoning.edr_context_builder import build_edr_context_for_asset
print(build_edr_context_for_asset(1))
"
```

---

### "EDR multiplier not applied in priority score"

**Symptom**: Assets with CRITICAL behavioral findings get the same priority as assets without EDR data.

**Check**: `prioritizer.py` applies the multiplier only when `asset_context["behavioral"]` is non-empty.

```bash
# Check what context M8 receives for an asset
docker compose exec m8 python -c "
from services.ai_reasoning.edr_context_builder import build_edr_context_for_asset
import json; print(json.dumps(build_edr_context_for_asset(42), indent=2))
"
# If output is {} or missing 'behavioral' key, no findings exist for that asset_id
```

---

## Log Patterns

| Log message | Location | Meaning |
|---|---|---|
| `Behavioral scan started for asset X` | celery-worker | Task received, SSH connecting |
| `analyze_processes: N anomalies detected` | celery-worker | Heuristic phase complete |
| `YARA: N rules loaded` | scanner-engine startup | YARA scanner initialized |
| `IOC extracted: ip=X.X.X.X` | celery-worker | IOC ready for TI lookup |
| `Cache hit for IOC X` | celery-worker | TI API call skipped |
| `EDR context unavailable for asset X` | m8 | Non-fatal; M8 scores without EDR boost |
| `EDR ×1.95: C2 activo (×1.5), YARA 2 regla(s) (×1.3)` | m8 | Multiplier applied to priority |
| `Kill chain detected for asset X: stage=EXPLOITATION` | m8 | High-priority alert |
| `Action 7 approved by ciso@company.com` | scanner-engine | IR audit trail entry |

---

## Running Tests Inside Container

```bash
# Copy latest test files
docker compose cp services/scanner_engine/tests/. scanner-engine:/app/services/scanner_engine/tests/

# Run all EDR tests
docker compose exec scanner-engine python -m pytest \
  services/scanner_engine/tests/test_edr_unit.py \
  services/scanner_engine/tests/test_edr_integration.py \
  services/scanner_engine/tests/test_edr_performance.py \
  services/scanner_engine/tests/test_edr_security.py \
  -v --tb=short 2>&1 | tee /tmp/edr_test_results.txt

# Unit tests only (fastest, no DB needed)
docker compose exec scanner-engine python -m pytest \
  services/scanner_engine/tests/test_edr_unit.py -v

# Performance test (requires ~30s)
docker compose exec scanner-engine python -m pytest \
  services/scanner_engine/tests/test_edr_performance.py \
  -v -s --timeout=120
```
