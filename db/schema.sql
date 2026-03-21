-- ============================================================
--  Muhafiz Local Database Schema  LAN Architecture
--  SQLite  stored at muhafiz.db (never committed to GitHub)
-- ============================================================


-- ── Scan runs ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scans (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp             TEXT    NOT NULL DEFAULT (datetime('now')),
    subnet                TEXT    NOT NULL,
    wan_ip_partial        TEXT    NOT NULL DEFAULT '',  -- partial e.g. "203.x.x.x"
    device_count          INTEGER NOT NULL DEFAULT 0,
    mapping_count         INTEGER NOT NULL DEFAULT 0,
    exposure_finding_count INTEGER NOT NULL DEFAULT 0,
    device_finding_count  INTEGER NOT NULL DEFAULT 0,
    upnp_leak_count       INTEGER NOT NULL DEFAULT 0,
    confirmed_reachable   INTEGER NOT NULL DEFAULT 0,   -- count of confidence=100
    duration_seconds      INTEGER NOT NULL DEFAULT 0
);


-- ── Devices found on LAN ───────────────────────────────────

CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip            TEXT    NOT NULL,
    mac_prefix    TEXT    NOT NULL,   -- first 3 octets only
    hostname      TEXT,
    device_type   TEXT    NOT NULL DEFAULT 'unknown',
    manufacturer  TEXT    NOT NULL DEFAULT 'unknown',
    is_camera     INTEGER NOT NULL DEFAULT 0,
    onvif_model   TEXT    NOT NULL DEFAULT '',
    first_seen    TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen     TEXT    NOT NULL DEFAULT (datetime('now'))
);


-- ── Open ports per device ──────────────────────────────────

CREATE TABLE IF NOT EXISTS ports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    port          INTEGER NOT NULL,
    protocol      TEXT    NOT NULL DEFAULT 'tcp',
    service       TEXT,
    banner        TEXT,
    device_type   TEXT    NOT NULL DEFAULT 'unknown',
    manufacturer  TEXT    NOT NULL DEFAULT 'unknown'
);


-- ── Router port mappings ───────────────────────────────────

CREATE TABLE IF NOT EXISTS port_mappings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    internal_ip    TEXT    NOT NULL,
    internal_port  INTEGER NOT NULL,
    external_port  INTEGER NOT NULL,
    protocol       TEXT    NOT NULL DEFAULT 'TCP',
    description    TEXT,
    source         TEXT    NOT NULL DEFAULT 'upnp',  -- upnp / nat_pmp
    lease_duration INTEGER NOT NULL DEFAULT 0
);


-- ── Exposure findings ──────────────────────────────────────
-- Device matched to a confirmed router mapping

CREATE TABLE IF NOT EXISTS exposure_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    mapping_id      INTEGER NOT NULL REFERENCES port_mappings(id) ON DELETE CASCADE,
    risk_score      INTEGER NOT NULL DEFAULT 0,
    severity        TEXT    NOT NULL DEFAULT 'LOW',
    confidence      INTEGER NOT NULL DEFAULT 0,
    reachable       INTEGER NOT NULL DEFAULT 0,  -- 1 = external verification succeeded
    verification_banner TEXT,
    reasons         TEXT    NOT NULL DEFAULT '[]',      -- JSON array
    remediation     TEXT    NOT NULL DEFAULT '[]',      -- JSON array
    resolved        INTEGER NOT NULL DEFAULT 0,
    resolved_at     TEXT
);


-- ── Device risk findings ───────────────────────────────────
-- Devices with no mapping — internal risk only

CREATE TABLE IF NOT EXISTS device_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    device_id     INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    risk_score    INTEGER NOT NULL DEFAULT 0,
    severity      TEXT    NOT NULL DEFAULT 'LOW',
    confidence    INTEGER NOT NULL DEFAULT 0,
    reasons       TEXT    NOT NULL DEFAULT '[]',
    remediation   TEXT    NOT NULL DEFAULT '[]',
    resolved      INTEGER NOT NULL DEFAULT 0,
    resolved_at   TEXT
);


-- ── UPnP leaks ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS upnp_leaks (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    internal_ip    TEXT    NOT NULL,
    internal_port  INTEGER NOT NULL,
    external_port  INTEGER NOT NULL,
    protocol       TEXT    NOT NULL DEFAULT 'TCP',
    description    TEXT,
    lease_duration INTEGER NOT NULL DEFAULT 0,
    source         TEXT    NOT NULL DEFAULT 'upnp',
    resolved       INTEGER NOT NULL DEFAULT 0,
    resolved_at    TEXT
);


-- ── Device registry ────────────────────────────────────────
-- Tracks every device seen across scans by MAC prefix

CREATE TABLE IF NOT EXISTS device_registry (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_prefix          TEXT    NOT NULL UNIQUE,
    last_ip             TEXT    NOT NULL,
    hostname            TEXT,
    device_type         TEXT    NOT NULL DEFAULT 'unknown',
    manufacturer        TEXT    NOT NULL DEFAULT 'unknown',
    is_camera           INTEGER NOT NULL DEFAULT 0,
    open_ports          TEXT    NOT NULL DEFAULT '[]',   -- JSON array
    highest_risk_score  INTEGER NOT NULL DEFAULT 0,
    highest_confidence  INTEGER NOT NULL DEFAULT 0,
    scan_count          INTEGER NOT NULL DEFAULT 0,
    exposure_count      INTEGER NOT NULL DEFAULT 0,  -- scans where mapping found
    first_seen          TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen           TEXT    NOT NULL DEFAULT (datetime('now')),
    last_scan_id        INTEGER REFERENCES scans(id),
    is_new              INTEGER NOT NULL DEFAULT 1,
    resolved            INTEGER NOT NULL DEFAULT 0
);


-- ── Registry changelog ─────────────────────────────────────

CREATE TABLE IF NOT EXISTS registry_changelog (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_prefix  TEXT    NOT NULL,
    scan_id     INTEGER NOT NULL,
    event       TEXT    NOT NULL,
    detail      TEXT,
    risk_score  INTEGER NOT NULL DEFAULT 0,
    confidence  INTEGER NOT NULL DEFAULT 0,
    recorded_at TEXT    NOT NULL DEFAULT (datetime('now'))
);


-- ── Community contributions ────────────────────────────────

CREATE TABLE IF NOT EXISTS contributions (
    uuid            TEXT PRIMARY KEY,
    port            INTEGER NOT NULL,
    banner_snippet  TEXT,
    device_type     TEXT,
    manufacturer    TEXT,
    risk_score      INTEGER,
    status          TEXT    NOT NULL DEFAULT 'queued',
    contributed_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);


-- ── Consent preferences ────────────────────────────────────

CREATE TABLE IF NOT EXISTS consent_preferences (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);


-- ── Consent log ────────────────────────────────────────────

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


CREATE INDEX IF NOT EXISTS idx_devices_scan          ON devices(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_device          ON ports(device_id);
CREATE INDEX IF NOT EXISTS idx_mappings_scan         ON port_mappings(scan_id);
CREATE INDEX IF NOT EXISTS idx_exposure_scan         ON exposure_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_exposure_severity     ON exposure_findings(severity);
CREATE INDEX IF NOT EXISTS idx_exposure_confidence   ON exposure_findings(confidence);
CREATE INDEX IF NOT EXISTS idx_device_findings_scan  ON device_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_upnp_scan             ON upnp_leaks(scan_id);
CREATE INDEX IF NOT EXISTS idx_contributions_status  ON contributions(status);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp       ON scans(timestamp);
CREATE INDEX IF NOT EXISTS idx_registry_mac          ON device_registry(mac_prefix);
CREATE INDEX IF NOT EXISTS idx_registry_is_new       ON device_registry(is_new);
CREATE INDEX IF NOT EXISTS idx_changelog_mac         ON registry_changelog(mac_prefix);