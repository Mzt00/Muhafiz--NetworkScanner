-- ============================================================
--  Muhafiz Local Database Schema
--  SQLite — stored at muhafiz.db (never committed to GitHub)
--  All data stays on the user's machine.
-- ============================================================


CREATE TABLE IF NOT EXISTS scans (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TEXT    NOT NULL DEFAULT (datetime('now')),
    wan_ip_hash         TEXT    NOT NULL,
    subnet              TEXT    NOT NULL,
    device_count        INTEGER NOT NULL DEFAULT 0,
    exposed_port_count  INTEGER NOT NULL DEFAULT 0,
    correlation_count   INTEGER NOT NULL DEFAULT 0,
    upnp_leak_count     INTEGER NOT NULL DEFAULT 0,
    risk_score_avg      REAL    NOT NULL DEFAULT 0.0,
    duration_seconds    INTEGER NOT NULL DEFAULT 0
);


CREATE TABLE IF NOT EXISTS devices ( -- lan devices
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip           TEXT    NOT NULL,
    mac_prefix   TEXT    NOT NULL,
    hostname     TEXT,
    device_type  TEXT    NOT NULL DEFAULT 'unknown',
    manufacturer TEXT    NOT NULL DEFAULT 'unknown',
    risk_score   INTEGER NOT NULL DEFAULT 0,
    first_seen   TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen    TEXT    NOT NULL DEFAULT (datetime('now'))
);




CREATE TABLE IF NOT EXISTS ports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    port         INTEGER NOT NULL,
    protocol     TEXT    NOT NULL DEFAULT 'tcp',
    service      TEXT,
    banner       TEXT,
    device_type  TEXT    NOT NULL DEFAULT 'unknown',
    manufacturer TEXT    NOT NULL DEFAULT 'unknown'
);


CREATE TABLE IF NOT EXISTS correlations (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    device_id        INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    port             INTEGER NOT NULL,
    protocol         TEXT    NOT NULL DEFAULT 'tcp',
    service          TEXT,
    risk_score       INTEGER NOT NULL DEFAULT 0,
    severity         TEXT    NOT NULL DEFAULT 'LOW',
    reason           TEXT,
    cves             TEXT,
    shodan_last_seen TEXT,
    resolved         INTEGER NOT NULL DEFAULT 0,
    resolved_at      TEXT
);


CREATE TABLE IF NOT EXISTS upnp_leaks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    internal_ip   TEXT    NOT NULL,
    internal_port INTEGER NOT NULL,
    external_port INTEGER NOT NULL,
    protocol      TEXT    NOT NULL DEFAULT 'TCP',
    description   TEXT,
    lease_duration INTEGER NOT NULL DEFAULT 0,
    confirmed     INTEGER NOT NULL DEFAULT 0,
    resolved      INTEGER NOT NULL DEFAULT 0,
    resolved_at   TEXT
);



CREATE TABLE IF NOT EXISTS exposed_ports (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    port             INTEGER NOT NULL,
    protocol         TEXT    NOT NULL DEFAULT 'tcp',
    service          TEXT,
    banner           TEXT,
    cves             TEXT,
    shodan_last_seen TEXT
);


--Exposed device registry
-- Tracks every device that has ever been found exposed.
-- Keyed by MAC prefix so the same physical device is
-- recognised across scans even if its IP changes (DHCP).

CREATE TABLE IF NOT EXISTS exposed_device_registry (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_prefix          TEXT    NOT NULL UNIQUE,  -- first 3 octets aa:bb:cc
    last_ip             TEXT    NOT NULL,          -- most recent internal IP
    hostname            TEXT,
    device_type         TEXT    NOT NULL DEFAULT 'unknown',
    manufacturer        TEXT    NOT NULL DEFAULT 'unknown',
    exposed_ports       TEXT    NOT NULL,          -- JSON array of port numbers
    highest_risk_score  INTEGER NOT NULL DEFAULT 0,
    exposure_count      INTEGER NOT NULL DEFAULT 0, -- how many scans found it exposed
    first_exposed       TEXT    NOT NULL DEFAULT (datetime('now')),
    last_exposed        TEXT    NOT NULL DEFAULT (datetime('now')),
    last_scan_id        INTEGER REFERENCES scans(id),
    is_new              INTEGER NOT NULL DEFAULT 1, -- 1 = new since last viewed
    resolved            INTEGER NOT NULL DEFAULT 0  -- 1 = user marked as fixed
);


--
-- Every time an exposed device is seen in a new scan,
-- log what changed so the user can see history over time.

CREATE TABLE IF NOT EXISTS registry_changelog (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_prefix      TEXT    NOT NULL,
    scan_id         INTEGER NOT NULL REFERENCES scans(id),
    event           TEXT    NOT NULL,  -- 'first_seen' / 'still_exposed' / 'new_port' / 'resolved'
    detail          TEXT,              -- human readable e.g. "New port 8080 detected"
    risk_score      INTEGER NOT NULL DEFAULT 0,
    recorded_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS contributions (
    uuid            TEXT PRIMARY KEY,
    port            INTEGER NOT NULL,
    banner_snippet  TEXT,
    device_type     TEXT,
    manufacturer    TEXT,
    risk_score      INTEGER,
    shodan_match    INTEGER NOT NULL DEFAULT 0,
    status          TEXT    NOT NULL DEFAULT 'queued',
    contributed_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS consent_preferences (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS consent_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    port        INTEGER NOT NULL,
    approved    INTEGER NOT NULL,
    recorded_at TEXT    NOT NULL DEFAULT (datetime('now'))
);


CREATE TABLE IF NOT EXISTS fingerprint_meta (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    version          TEXT    NOT NULL,
    total_signatures INTEGER NOT NULL DEFAULT 0,
    updated_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);


CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_devices_scan_id
    ON devices(scan_id);

CREATE INDEX IF NOT EXISTS idx_ports_device_id
    ON ports(device_id);

CREATE INDEX IF NOT EXISTS idx_correlations_scan_id
    ON correlations(scan_id);

CREATE INDEX IF NOT EXISTS idx_correlations_severity
    ON correlations(severity);

CREATE INDEX IF NOT EXISTS idx_upnp_scan_id
    ON upnp_leaks(scan_id);

CREATE INDEX IF NOT EXISTS idx_contributions_status
    ON contributions(status);

CREATE INDEX IF NOT EXISTS idx_scans_timestamp
    ON scans(timestamp);

CREATE INDEX IF NOT EXISTS idx_registry_mac
    ON exposed_device_registry(mac_prefix);

CREATE INDEX IF NOT EXISTS idx_registry_is_new
    ON exposed_device_registry(is_new);

CREATE INDEX IF NOT EXISTS idx_changelog_mac
    ON registry_changelog(mac_prefix);