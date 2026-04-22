# ScanOPS Surface Snapshot System

This document describes the implementation of the surface snapshot system for ScanOPS, which enables tracking changes in network surface over time.

## Overview

The surface snapshot system captures the complete state of network reconnaissance at the end of each M2 (Network Scanning) execution. Each cycle generates an immutable snapshot that can be compared with previous cycles to detect changes in the attack surface.

## Database Schema

### Tables

1. **recon_snapshots**
   - Stores metadata for each reconnaissance cycle
   - Fields: id, cycle_id, target, started_at, finished_at, status

2. **recon_findings**
   - Stores individual findings (ports, services) for each snapshot
   - Fields: id, snapshot_id, host, port, service, version, state, source, first_seen_snapshot_id

3. **recon_subdomains**
   - Stores discovered subdomains for each snapshot
   - Fields: id, snapshot_id, subdomain, source

## Key Components

### 1. Models (`src/models/recon.py`)
- SQLAlchemy ORM models for database tables
- Pydantic schemas for API validation and serialization
- Surface change schemas for comparison results

### 2. Surface Diff Service (`src/modules/surface_diff.py`)
- `compare_snapshots()`: Compares two snapshots and detects changes
- `classify_change_severity()`: Classifies severity based on change type and asset criticality
- Change types detected: new_ports, closed_ports, new_hosts, lost_hosts, service_changes, state_changes, new_subdomains, lost_subdomains

### 3. Database Configuration (`src/database.py`)
- SQLAlchemy engine and session management
- PostgreSQL connection configuration via `DATABASE_URL` environment variable

### 4. Modified Scanner Network (`src/modules/scanner_network.py`)
- Creates snapshot record at scan start
- Persists all findings and subdomains to database
- Compares with previous snapshot and includes surface_changes in output

### 5. REST API (`api/recon_api.py`)
- FastAPI endpoints for querying snapshots and changes
- Endpoints:
  - `GET /recon/cycles/{cycle_id}/changes` - Get surface changes for a cycle
  - `GET /recon/cycles/{cycle_id}/snapshot` - Get snapshot details
  - `GET /recon/cycles` - List all cycles
  - `GET /recon/snapshots/{snapshot_id}/findings` - Get findings for a snapshot
  - `GET /recon/snapshots/{snapshot_id}/subdomains` - Get subdomains for a snapshot

## Usage

### Running a Scan with Snapshots

```bash
# Run the main orchestrator (generates cycle_id automatically)
python scripts/main_orchestrator.py

# Or run scanner_network directly with specific cycle_id
python src/modules/scanner_network.py 2026-W17
```

### Running the API

```bash
python api/recon_api.py
```

### Database Setup

1. Create PostgreSQL database
2. Set `DATABASE_URL` environment variable
3. Run migrations:
   ```bash
   alembic upgrade head
   ```

## Output Format

The scanner_network module now includes a `surface_changes` section in its output:

```json
{
  "cycle_id": "2026-W17",
  "previous_cycle_id": 1,
  "surface_changes": {
    "has_changes": true,
    "summary": {
      "new_ports": 2,
      "closed_ports": 0,
      "new_hosts": 1,
      "service_changes": 1,
      "total_changes": 4,
      "max_severity": "CRITICA"
    },
    "details": [
      {
        "type": "new_port",
        "host": "10.202.15.100",
        "port": "8080/tcp",
        "service": "http-proxy",
        "severity": "CRITICA",
        "description": "Nuevo puerto abierto en servidor de criticidad Alta",
        "medida_ens": "op.exp.2"
      }
    ]
  }
}
```

## Severity Classification

Changes are classified by severity based on type and asset criticality:

- **CRITICA**: New ports/hosts on high-criticality assets, shadow IT detection
- **ALTA**: New ports on low-criticality assets, new subdomains
- **MEDIA**: Service changes, lost hosts
- **INFO**: Closed ports (security improvements), lost subdomains

## Testing

Run tests with pytest:

```bash
pytest tests/test_surface_diff.py -v
pytest tests/test_scanner_network_db.py -v
```

## Dependencies

- SQLAlchemy 2.0+
- Pydantic 2.0+
- FastAPI
- PostgreSQL
- Alembic (for migrations)

## Environment Variables

- `DATABASE_URL`: PostgreSQL connection string (default: postgresql://scanops:scanops@localhost:5432/scanops)

## Future Enhancements

1. Integration with M1 (Asset Inventory) API for real-time criticality updates
2. Dashboard integration for visualizing surface changes
3. AI-powered change analysis and prioritization
4. Alerting system for critical surface changes