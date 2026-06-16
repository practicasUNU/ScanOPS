"""add EDR tables: behavioral_findings, threat_intel_cache, incident_response_log

Revision ID: 011
Revises: 010
Create Date: 2026-06-16
"""
from alembic import op

revision = '011'
down_revision = '010'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        -- ── behavioral_findings ──────────────────────────────────────────────
        -- Stores anomalous processes and behavioral indicators detected on assets.
        CREATE TABLE IF NOT EXISTS behavioral_findings (
            id                    SERIAL PRIMARY KEY,
            asset_id              INTEGER      NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            scan_id               VARCHAR(64)  NOT NULL,
            pid                   INTEGER,
            process_name          VARCHAR(255),
            anomaly_type          VARCHAR(50)  NOT NULL,
            severity              VARCHAR(16)  NOT NULL DEFAULT 'MEDIUM'
                                      CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
            confidence_score      SMALLINT     NOT NULL DEFAULT 50
                                      CHECK (confidence_score BETWEEN 0 AND 100),
            detection_method      VARCHAR(50),
            indicators            JSON,
            mitre_attack_tactics  JSON,
            remediation_suggested TEXT,
            status                VARCHAR(20)  NOT NULL DEFAULT 'open'
                                      CHECK (status IN ('open','investigating','resolved','false_positive')),
            created_at            TIMESTAMP    NOT NULL DEFAULT NOW(),
            updated_at            TIMESTAMP             DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS ix_beh_findings_asset_id ON behavioral_findings (asset_id);
        CREATE INDEX IF NOT EXISTS ix_beh_findings_scan_id  ON behavioral_findings (scan_id);
        CREATE INDEX IF NOT EXISTS ix_beh_findings_severity ON behavioral_findings (severity);

        -- ── threat_intel_cache ───────────────────────────────────────────────
        -- Caches IOC lookups from VirusTotal, CrowdSec and AlienVault OTX.
        -- TTL varies per source: VT hits 30d, CrowdSec IPs 12h, OTX domains 7d.
        CREATE TABLE IF NOT EXISTS threat_intel_cache (
            id              SERIAL      PRIMARY KEY,
            ioc_value       VARCHAR(512) NOT NULL,
            ioc_type        VARCHAR(20)  NOT NULL
                                CHECK (ioc_type IN ('ip','domain','hash','url')),
            vt_result       JSON,
            crowdsec_result JSON,
            otx_result      JSON,
            is_malicious    BOOLEAN      NOT NULL DEFAULT FALSE,
            malicious_votes SMALLINT     NOT NULL DEFAULT 0,
            ttl_expires     TIMESTAMP    NOT NULL,
            created_at      TIMESTAMP    NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMP             DEFAULT NOW()
        );

        CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_intel_ioc     ON threat_intel_cache (ioc_value, ioc_type);
        CREATE INDEX        IF NOT EXISTS ix_threat_intel_ttl      ON threat_intel_cache (ttl_expires);
        CREATE INDEX        IF NOT EXISTS ix_threat_intel_malicious ON threat_intel_cache (is_malicious);

        -- ── incident_response_log ────────────────────────────────────────────
        -- Audit trail of every response action (kill/quarantine/block/isolate).
        -- ENS op.exp.4: all actions must be approved and logged.
        CREATE TABLE IF NOT EXISTS incident_response_log (
            id                    SERIAL       PRIMARY KEY,
            asset_id              INTEGER      NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            behavioral_finding_id INTEGER               REFERENCES behavioral_findings(id) ON DELETE SET NULL,
            action_type           VARCHAR(50)  NOT NULL
                                      CHECK (action_type IN (
                                          'quarantine_file',
                                          'kill_process',
                                          'block_ip',
                                          'isolate_host',
                                          'collect_forensics'
                                      )),
            target_detail         VARCHAR(512) NOT NULL,
            requested_by          VARCHAR(100) NOT NULL,
            approval_token        VARCHAR(255),
            approved_by           VARCHAR(100),
            approved_at           TIMESTAMP,
            executed_at           TIMESTAMP,
            status                VARCHAR(20)  NOT NULL DEFAULT 'pending'
                                      CHECK (status IN (
                                          'pending',
                                          'approved',
                                          'executing',
                                          'completed',
                                          'rejected',
                                          'failed'
                                      )),
            result_output         TEXT,
            rollback_capable      BOOLEAN      NOT NULL DEFAULT FALSE,
            execution_duration_ms INTEGER,
            created_at            TIMESTAMP    NOT NULL DEFAULT NOW(),
            updated_at            TIMESTAMP             DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS ix_ir_log_asset_id ON incident_response_log (asset_id);
        CREATE INDEX IF NOT EXISTS ix_ir_log_status   ON incident_response_log (status);
    """)


def downgrade():
    op.execute("""
        DROP TABLE IF EXISTS incident_response_log;
        DROP TABLE IF EXISTS threat_intel_cache;
        DROP TABLE IF EXISTS behavioral_findings;
    """)
