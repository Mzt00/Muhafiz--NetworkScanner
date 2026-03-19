-- ============================================================
--  Muhafiz Community API Database Schema
--  SQLITE
--  No IPs, no MACs, no identifying information stored here.
-- ============================================================


CREATE TABLE IF NOT EXISTS submissions (
    uuid            TEXT    PRIMARY KEY,
    port            INTEGER NOT NULL,
    banner_snippet  TEXT    NOT NULL DEFAULT '',
    device_type     TEXT    NOT NULL DEFAULT 'unknown',
    manufacturer    TEXT    NOT NULL DEFAULT 'unknown',
    risk_score      INTEGER NOT NULL DEFAULT 5,
    shodan_match    INTEGER NOT NULL DEFAULT 0,
    client_version  TEXT    NOT NULL DEFAULT 'unknown',
    status          TEXT    NOT NULL DEFAULT 'pending',
    submitted_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    ip_hash         TEXT    NOT NULL DEFAULT ''
);


CREATE TABLE IF NOT EXISTS confidence_queue (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    port             INTEGER NOT NULL,
    banner_key       TEXT    NOT NULL,
    device_type      TEXT    NOT NULL DEFAULT 'unknown',
    manufacturer     TEXT    NOT NULL DEFAULT 'unknown',
    risk_score_avg   REAL    NOT NULL DEFAULT 5.0,
    submission_count INTEGER NOT NULL DEFAULT 1,
    first_seen       TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen        TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    status           TEXT    NOT NULL DEFAULT 'queued',
    UNIQUE(port, banner_key)
);


CREATE TABLE IF NOT EXISTS fingerprints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    port            INTEGER NOT NULL,
    banner_contains TEXT    NOT NULL,
    device_type     TEXT    NOT NULL DEFAULT 'unknown',
    manufacturer    TEXT    NOT NULL DEFAULT 'unknown',
    risk_base       INTEGER NOT NULL DEFAULT 5,
    notes           TEXT,
    source          TEXT    NOT NULL DEFAULT 'community',
    merged_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    merged_by       TEXT    NOT NULL DEFAULT 'auto',
    version_added   TEXT    NOT NULL DEFAULT '0.1.0'
);

CREATE TABLE IF NOT EXISTS github_issues (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    queue_id     INTEGER NOT NULL REFERENCES confidence_queue(id),
    issue_number INTEGER NOT NULL,
    issue_url    TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'open',
    opened_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    closed_at    TEXT
);

CREATE TABLE IF NOT EXISTS api_stats (
    id                     INTEGER PRIMARY KEY DEFAULT 1,
    total_submissions      INTEGER NOT NULL DEFAULT 0,
    total_merged           INTEGER NOT NULL DEFAULT 0,
    total_rejected         INTEGER NOT NULL DEFAULT 0,
    total_signatures       INTEGER NOT NULL DEFAULT 0,
    unique_devices_seen    INTEGER NOT NULL DEFAULT 0,
    last_updated           TEXT    NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO api_stats (id) VALUES (1);


CREATE TABLE IF NOT EXISTS rate_limits (
    ip_hash       TEXT    NOT NULL,
    window_start  TEXT    NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (ip_hash, window_start)
);


CREATE INDEX IF NOT EXISTS idx_submissions_status
    ON submissions(status);

CREATE INDEX IF NOT EXISTS idx_submissions_port
    ON submissions(port);

CREATE INDEX IF NOT EXISTS idx_queue_port_banner
    ON confidence_queue(port, banner_key);

CREATE INDEX IF NOT EXISTS idx_queue_status
    ON confidence_queue(status);

CREATE INDEX IF NOT EXISTS idx_fingerprints_port
    ON fingerprints(port);

CREATE INDEX IF NOT EXISTS idx_rate_limits_ip
    ON rate_limits(ip_hash, window_start);