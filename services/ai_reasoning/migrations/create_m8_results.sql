CREATE TABLE IF NOT EXISTS m8_results (
    id              SERIAL PRIMARY KEY,
    asset_id        INTEGER NOT NULL,
    target_ip       VARCHAR(45),
    cve_id          VARCHAR(100),
    suggested_tool  VARCHAR(255),
    tool_params     TEXT,
    mitre_tactic    VARCHAR(255),
    risk_level      VARCHAR(20),
    attack_rationale TEXT,
    confidence      VARCHAR(20),
    status          VARCHAR(50) DEFAULT 'pending_human_approval',
    prompt_version  VARCHAR(50),
    approval_id     INTEGER,
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_m8_results_asset_id ON m8_results(asset_id);
CREATE INDEX IF NOT EXISTS ix_m8_results_created_at ON m8_results(created_at);
