-- ============================================
-- Vulnerability Scanner Database Schema
-- Status: FROZEN as of Day 1 — changes require a PR + team review
-- ============================================

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    ip_address TEXT,
    asset_type TEXT CHECK(asset_type IN ('domain', 'subdomain', 'ip')) DEFAULT 'subdomain',
    authorized BOOLEAN NOT NULL DEFAULT 0,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT CHECK(status IN ('active', 'inactive')) DEFAULT 'active',
    UNIQUE(domain)
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    status TEXT CHECK(status IN ('running', 'completed', 'failed')) DEFAULT 'running',
    notes TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    asset_id INTEGER NOT NULL,
    finding_type TEXT CHECK(finding_type IN ('open_port', 'cve', 'misconfig', 'weak_tls')) NOT NULL,
    port INTEGER,
    service TEXT,
    cve_id TEXT,
    cvss_score REAL,
    epss_score REAL,
    kev_flag BOOLEAN DEFAULT 0,
    risk_score REAL,
    severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')),
    description TEXT,
    status TEXT CHECK(status IN ('open', 'resolved', 'ignored')) DEFAULT 'open',
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES scan_runs(id),
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);

CREATE TABLE IF NOT EXISTS notifications_sent (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    channel TEXT CHECK(channel IN ('slack', 'discord', 'email', 'telegram')) NOT NULL,
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_assets_authorized ON assets(authorized);