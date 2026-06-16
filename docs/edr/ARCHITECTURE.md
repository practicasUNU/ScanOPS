# M3.1 EDR — Architecture

## Component Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         ScanOPS                                  │
│                                                                  │
│  ┌─────────────┐    ┌──────────────────────────────────────────┐ │
│  │  Frontend   │    │         M3 Scanner-Engine :8002           │ │
│  │  React/TS   │◄───┤                                           │ │
│  │  /edr       │    │  ┌─────────────────────────────────────┐  │ │
│  │  /incident  │    │  │         EDR Router                   │  │ │
│  │  -response  │    │  │  POST /edr/behavioral-scan           │  │ │
│  └─────────────┘    │  │  GET  /edr/behavioral-findings       │  │ │
│                     │  │  POST /edr/request-response-action   │  │ │
│                     │  │  POST /edr/approve-action/{id}       │  │ │
│                     │  │  GET  /edr/stats                     │  │ │
│                     │  └──────────────┬──────────────────────┘  │ │
│                     │                 │                           │ │
│                     │  ┌──────────────▼──────────────────────┐  │ │
│                     │  │       Celery Worker                   │  │ │
│                     │  │  behavioral_scan_task                 │  │ │
│                     │  │  enrich_findings_with_threat_intel   │  │ │
│                     │  └──┬──────────┬──────────┬────────────┘  │ │
│                     │     │          │           │               │ │
│                     │  ┌──▼──┐  ┌───▼───┐  ┌───▼──────────┐   │ │
│                     │  │SSH  │  │ IOC   │  │ Threat Intel  │   │ │
│                     │  │     │  │Extract│  │  VT/CS/OTX    │   │ │
│                     │  │ ps  │  │       │  │  PyBreaker    │   │ │
│                     │  │ aux │  └───────┘  └──────────────┘   │ │
│                     │  └──┬──┘                                  │ │
│                     │     │                                      │ │
│                     │  ┌──▼────────────┐  ┌─────────────────┐  │ │
│                     │  │AnomalyDetector│  │  YARA Scanner   │  │ │
│                     │  │  Heuristic    │  │  rules/*.yar    │  │ │
│                     │  │  patterns     │  │  yara-python    │  │ │
│                     │  └──────────────┘  └─────────────────┘  │ │
│                     └──────────────────────────────────────────┘ │
│                                                                  │
│  ┌──────────────────┐    ┌──────────┐    ┌───────────────────┐  │
│  │   PostgreSQL     │    │  Redis   │    │  M8 AI Reasoning  │  │
│  │  behavioral_     │    │ (broker) │    │  :8005            │  │
│  │  findings        │    │          │    │  kill_chain_detect │  │
│  │  incident_       │    │          │    │  edr_context_     │  │
│  │  response_logs   │    │          │    │  builder          │  │
│  │  threat_intel_   │    │          │    │  prioritizer      │  │
│  │  cache           │    │          │    │  (EDR multipliers)│  │
│  └──────────────────┘    └──────────┘    └───────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### Behavioral Scan Pipeline

```
1. POST /edr/behavioral-scan
       │
       ▼
2. behavioral_scan_task (Celery)
       │
       ├── SSH connect → ps aux → parse ProcessInfo[]
       │
       ├── analyze_processes()
       │     ├── AnomalyDetector: regex heuristics per pattern type
       │     │     C2_CALLBACK, REVERSE_SHELL, DATA_EXFIL,
       │     │     PRIVILEGE_ESCALATION, OBFUSCATION
       │     └── YaraScanner: scan each cmdline against rules/
       │
       ├── merge_yara_with_anomalies()
       │     Correlate YARA hits with behavioral anomalies;
       │     boost confidence or create YARA_MATCH entries
       │
       └── INSERT INTO behavioral_findings RETURNING id
               │
               ▼
3. enrich_findings_with_threat_intel.delay(finding_id)
       │
       ├── extract_iocs(indicators)
       │     IPs (non-RFC-1918), domains (.tk/.xyz/.top),
       │     hashes (MD5/SHA1/SHA256)
       │
       ├── For each IOC:
       │     ├── Check ThreatIntelCache (TTL=24h)
       │     ├── Cache hit → skip API calls
       │     └── Cache miss → parallel: VT + CS + OTX
       │           consensus vote ≥ 3/5 → is_malicious=true
       │           UPDATE behavioral_findings SET severity
       │
       └── UPDATE threat_intel_cache
```

### M8 Integration Flow

```
run_full_ai_pipeline (Celery periodic or on-demand)
       │
       ├── get_assets_with_active_edr_findings()
       │
       └── For each asset: process_edr_enriched_asset_task(asset_id)
             │
             ├── build_edr_context_for_asset(asset_id)
             │     → { behavioral: {...}, threat_intel: {...} }
             │
             ├── _fetch_open_vulnerabilities(asset_id)
             │     → CVEs from scan_results table
             │
             ├── analyze_kill_chain(asset_context, vulns)
             │     LLM (claude-sonnet-4-6) → deterministic fallback
             │     Returns: { detected: bool, stage: str, confidence: float }
             │
             ├── _persist_kill_chain_result() → m8_results table
             │
             └── If kill chain detected:
                   enrich ficha_unica + dispatch suggest_attack_vector_task
```

### Incident Response Pipeline

```
POST /edr/request-response-action
       │  Generate TOTP secret + bcrypt PIN hash
       │  Store in approval_token JSON
       │  Return QR code to requester
       ▼
INSERT incident_response_logs (status=pending)
       │
       ▼ (out of band: approver scans QR)
POST /edr/approve-action/{id}
       │  Verify TOTP (valid_window=8 = ±4 minutes)
       │  Verify bcrypt PIN
       │  Only if status=="pending"
       ▼
UPDATE status=approved
       │
       └── If EDR_AUTO_REMEDIATE=true:
             execute_response_action_task (Celery)
             SSH → command based on action_type
             UPDATE status=completed, execution_output
```

---

## Database Schema (EDR tables)

```sql
behavioral_findings
  id SERIAL PRIMARY KEY
  asset_id INTEGER NOT NULL
  process_name VARCHAR(255)
  anomaly_type VARCHAR(100)       -- C2_CALLBACK, REVERSE_SHELL, ...
  severity VARCHAR(20)            -- INFO/LOW/MEDIUM/HIGH/CRITICAL
  confidence_score INTEGER        -- 0-100
  detection_method VARCHAR(100)   -- behavioral_heuristic, yara, combined
  indicators JSONB                -- { cmdline, pid, user, matched[] }
  mitre_attack_tactics JSONB      -- ["TA0011", ...]
  yara_hits INTEGER DEFAULT 0
  status VARCHAR(50) DEFAULT 'open'
  detected_at TIMESTAMP DEFAULT NOW()

threat_intel_cache
  id SERIAL PRIMARY KEY
  ioc_value VARCHAR(512) UNIQUE
  ioc_type VARCHAR(50)            -- ip, domain, hash, url
  is_malicious BOOLEAN
  confidence_score INTEGER
  vt_positives INTEGER
  vt_total INTEGER
  crowdsec_reputation VARCHAR(100)
  otx_pulse_count INTEGER
  tags JSONB
  expires_at TIMESTAMP            -- TTL=24h by default

incident_response_logs
  id SERIAL PRIMARY KEY
  asset_id INTEGER NOT NULL
  action_type VARCHAR(100)        -- kill_process, block_ip, ...
  target_detail VARCHAR(512)      -- PID:x, IP, file path, username
  requested_by VARCHAR(255)
  approved_by VARCHAR(255)
  justification TEXT
  status VARCHAR(50)              -- pending/approved/completed/failed/rejected
  approval_token VARCHAR(255)     -- JSON: { totp_secret, pin_hash }
  execution_output TEXT
  created_at TIMESTAMP DEFAULT NOW()
  executed_at TIMESTAMP
```

---

## EDR Priority Multipliers (M8 integration)

When M8 prioritizes an asset, it calls `_apply_edr_multiplier()`:

| Trigger | Multiplier | Cap |
|---|---|---|
| Active C2 + severity HIGH/CRITICAL | ×1.5 | |
| YARA hits > 0 | ×1.3 | |
| Malicious IP in TI cache | ×1.4 | |
| All combined | capped | ×2.0 |

A priority of 7.0 with C2 + YARA + malicious IP becomes `min(10.0, 7.0 × 2.0) = 10.0`.

---

## Security Design

| Control | Implementation |
|---|---|
| Human approval gate (ENS op.acc.5) | TOTP + bcrypt PIN, `status=pending→approved` |
| Separation of duties | `requested_by ≠ approved_by` enforced by convention |
| Audit trail (ENS mp.info.3) | Every state transition recorded with identity + timestamp |
| Replay attack prevention | `pyotp.TOTP.verify(valid_window=8)` — one-time per 30s window |
| Auto-remediate off by default | `EDR_AUTO_REMEDIATE=false` in docker-compose |
| API authentication | JWT Bearer on all EDR endpoints |
| Circuit breakers | `pybreaker` on VT/CS/OTX clients (fail_max=5) |
