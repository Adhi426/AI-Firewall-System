-- Reference schema for the AI Firewall System.
-- The backend creates these automatically via SQLAlchemy on first run
-- (backend/models.py); this file documents the same schema for anyone
-- who wants to inspect/seed the SQLite database directly, or port it to
-- another RDBMS.

CREATE TABLE IF NOT EXISTS logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     DATETIME NOT NULL,
    src_ip        TEXT,
    dst_ip        TEXT,
    src_port      INTEGER,
    dst_port      INTEGER,
    protocol      TEXT,
    features      TEXT,          -- JSON blob of the raw flow features
    label         TEXT,          -- 'benign' | 'malicious'
    confidence    REAL,
    verdict       TEXT,          -- 'ALLOW' | 'BLOCK'
    reason        TEXT
);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_src_ip ON logs(src_ip);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT UNIQUE NOT NULL,
    blocked_at  DATETIME NOT NULL,
    reason      TEXT,
    auto        BOOLEAN DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip);

CREATE TABLE IF NOT EXISTS rules (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type    TEXT NOT NULL,   -- 'allow_ip' | 'deny_ip' | 'threshold'
    value        TEXT NOT NULL,
    description  TEXT DEFAULT '',
    created_at   DATETIME NOT NULL
);
