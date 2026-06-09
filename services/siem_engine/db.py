"""DB helpers for M5 SIEM Engine — psycopg2 directo, patrón M4."""
import os
import urllib.parse
import psycopg2
from psycopg2.extras import RealDictCursor


def get_db_config() -> dict:
    url = os.getenv("DATABASE_URL", "")
    if url:
        r = urllib.parse.urlparse(url)
        return {
            "host": r.hostname,
            "port": r.port or 5432,
            "database": r.path.lstrip("/"),
            "user": r.username,
            "password": r.password,
        }
    return {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": int(os.getenv("DB_PORT", "5432")),
        "database": os.getenv("DB_NAME", "scanops"),
        "user": os.getenv("DB_USER", "scanops"),
        "password": os.getenv("DB_PASSWORD", "scanops"),
    }


def get_conn():
    return psycopg2.connect(**get_db_config())


def create_siem_tables() -> None:
    ddl = """
    CREATE TABLE IF NOT EXISTS siem_agents (
        id SERIAL PRIMARY KEY,
        asset_id INTEGER,
        wazuh_agent_id VARCHAR(10),
        agent_name VARCHAR(255),
        agent_ip VARCHAR(45),
        status VARCHAR(50) DEFAULT 'pending',
        deployed_at TIMESTAMP DEFAULT NOW(),
        last_seen TIMESTAMP,
        fim_enabled BOOLEAN DEFAULT TRUE,
        process_monitoring BOOLEAN DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS siem_blocks (
        id SERIAL PRIMARY KEY,
        ip VARCHAR(45) NOT NULL,
        reason VARCHAR(255),
        severity VARCHAR(20),
        source VARCHAR(50),
        blocked_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP,
        active BOOLEAN DEFAULT TRUE,
        crowdsec_decision_id VARCHAR(100)
    );

    CREATE TABLE IF NOT EXISTS siem_emergency_scans (
        id SERIAL PRIMARY KEY,
        asset_id INTEGER,
        reason VARCHAR(255),
        triggered_by VARCHAR(255),
        m2_scan_id VARCHAR(100),
        m3_scan_id VARCHAR(100),
        status VARCHAR(50) DEFAULT 'triggered',
        triggered_at TIMESTAMP DEFAULT NOW()
    );
    
    CREATE TABLE IF NOT EXISTS siem_correlations (
        id SERIAL PRIMARY KEY,
        correlation_id VARCHAR(36) UNIQUE,
        threat_level VARCHAR(20),
        attack_pattern VARCHAR(255),
        confidence FLOAT,
        affected_ips JSONB,
        timeline JSONB,
        ai_reasoning TEXT,
        recommended_action TEXT,
        ens_measures JSONB,
        events_analyzed INTEGER,
        ai_used BOOLEAN DEFAULT TRUE,
        correlated_at TIMESTAMP DEFAULT NOW()
    );
    
    CREATE TABLE IF NOT EXISTS siem_lucia_notifications (
        id SERIAL PRIMARY KEY,
        notification_id VARCHAR(36) UNIQUE,
        payload JSONB,
        sent BOOLEAN DEFAULT FALSE,
        method VARCHAR(50),
        notified_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS siem_pipeline_events (
        id SERIAL PRIMARY KEY,
        event_type VARCHAR(50) NOT NULL,
        severity VARCHAR(20) DEFAULT 'HIGH',
        source VARCHAR(50) DEFAULT 'M4-Pipeline',
        target_ip VARCHAR(45),
        attacker_ip VARCHAR(45),
        description TEXT,
        details JSONB,
        mitigated BOOLEAN DEFAULT FALSE,
        timestamp TIMESTAMP DEFAULT NOW()
    );

    """
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(ddl)
    finally:
        conn.close()
