-- ============================================================
-- SQLite3 Schema for Display_Log
-- Derived from: Logs/Display_log.csv
-- Board: Raspberry Pi 4 / Raspbian OS
-- ============================================================

CREATE TABLE IF NOT EXISTS Display_Log (
    -- ── Primary Key / Metadata ──────────────────────────────
    id          INTEGER PRIMARY KEY AUTOINCREMENT,  -- auto-managed row id
    SrNO        INTEGER NOT NULL,                   -- original serial number from CSV
    Date        TEXT    NOT NULL,                   -- format: DD/MM/YYYY
    Time        TEXT    NOT NULL,                   -- format: HH:MM:SS

    -- ── Display Identity ────────────────────────────────────
    DuNo        INTEGER NOT NULL,                   -- Dispenser Unit number  (e.g. 99000000)
    dispSrNo    INTEGER NOT NULL,                   -- Display Serial Number  (e.g. 12000000)
    displayShaSign  TEXT NOT NULL,                  -- SHA-256 hex signature of the display firmware (0x...)

    -- ── Display-level Firmware & State ──────────────────────
    firmware    REAL    NOT NULL DEFAULT 0.0,       -- current firmware version (float)
    autoMode    INTEGER NOT NULL DEFAULT 0,         -- 0=manual, 1=auto
    onoff       INTEGER NOT NULL DEFAULT 0,         -- 0=off,    1=on

    -- ── Nozzle 1 ────────────────────────────────────────────
    Nozzle1_ID          INTEGER NOT NULL DEFAULT 0,
    Nozzle1_Amount      REAL    NOT NULL DEFAULT 0.0,
    Nozzle1_Volume      REAL    NOT NULL DEFAULT 0.0,
    Nozzle1_KFactor     INTEGER NOT NULL DEFAULT 1000,
    Nozzle1_Timestamp   TEXT    NOT NULL DEFAULT '0/0/0-0:0:0',  -- format: D/M/Y-H:M:S
    Nozzle1_TXN         INTEGER NOT NULL DEFAULT 0,              -- transaction count
    Nozzle1_FW          REAL    NOT NULL DEFAULT 0.0,            -- nozzle firmware version
    Nozzle1_SHA         TEXT    NOT NULL,                        -- SHA-256 hex of nozzle firmware

    -- ── Nozzle 2 ────────────────────────────────────────────
    Nozzle2_ID          INTEGER NOT NULL DEFAULT 0,
    Nozzle2_Amount      REAL    NOT NULL DEFAULT 0.0,
    Nozzle2_Volume      REAL    NOT NULL DEFAULT 0.0,
    Nozzle2_KFactor     INTEGER NOT NULL DEFAULT 1000,
    Nozzle2_Timestamp   TEXT    NOT NULL DEFAULT '0/0/0-0:0:0',
    Nozzle2_TXN         INTEGER NOT NULL DEFAULT 0,
    Nozzle2_FW          REAL    NOT NULL DEFAULT 0.0,
    Nozzle2_SHA         TEXT    NOT NULL,

    -- ── Nozzle 3 ────────────────────────────────────────────
    Nozzle3_ID          INTEGER NOT NULL DEFAULT 0,
    Nozzle3_Amount      REAL    NOT NULL DEFAULT 0.0,
    Nozzle3_Volume      REAL    NOT NULL DEFAULT 0.0,
    Nozzle3_KFactor     INTEGER NOT NULL DEFAULT 1000,
    Nozzle3_Timestamp   TEXT    NOT NULL DEFAULT '0/0/0-0:0:0',
    Nozzle3_TXN         INTEGER NOT NULL DEFAULT 0,
    Nozzle3_FW          REAL    NOT NULL DEFAULT 0.0,
    Nozzle3_SHA         TEXT    NOT NULL,

    -- ── Nozzle 4 ────────────────────────────────────────────
    Nozzle4_ID          INTEGER NOT NULL DEFAULT 0,
    Nozzle4_Amount      REAL    NOT NULL DEFAULT 0.0,
    Nozzle4_Volume      REAL    NOT NULL DEFAULT 0.0,
    Nozzle4_KFactor     INTEGER NOT NULL DEFAULT 1000,
    Nozzle4_Timestamp   TEXT    NOT NULL DEFAULT '0/0/0-0:0:0',
    Nozzle4_TXN         INTEGER NOT NULL DEFAULT 0,
    Nozzle4_FW          REAL    NOT NULL DEFAULT 0.0,
    Nozzle4_SHA         TEXT    NOT NULL,

    -- ── Timestamps ──────────────────────────────────────────
    created_at  TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- ── Indexes for common query patterns ───────────────────────
-- Query by dispenser/display unit
CREATE INDEX IF NOT EXISTS idx_display_log_DuNo     ON Display_Log(DuNo);
CREATE INDEX IF NOT EXISTS idx_display_log_dispSrNo ON Display_Log(dispSrNo);

-- Query by date (most common reporting need)
CREATE INDEX IF NOT EXISTS idx_display_log_Date     ON Display_Log(Date);

-- Query by firmware SHA to find boards running a specific firmware
CREATE INDEX IF NOT EXISTS idx_display_log_sha      ON Display_Log(displayShaSign);
