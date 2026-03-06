"""
utils/db_manager.py
-------------------
SQLite3 database manager for the Display_Log table.

Usage
-----
    from utils.db_manager import DisplayLogDB

    db = DisplayLogDB()          # opens/creates the DB in <project_root>/data/bootloader.db
    db.insert_record(row_dict)   # insert a single log entry
    db.import_csv("Logs/Display_log.csv")   # bulk-import the existing CSV

Columns map directly to Logs/Display_log.csv header:
    SrNO, Date, Time, DuNo, dispSrNo, displayShaSign,
    firmware, autoMode, onoff,
    Nozzle{1-4}_ID, Nozzle{1-4}_Amount, Nozzle{1-4}_Volume,
    Nozzle{1-4}_KFactor, Nozzle{1-4}_Timestamp, Nozzle{1-4}_TXN,
    Nozzle{1-4}_FW, Nozzle{1-4}_SHA
"""

import csv
import logging
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Path resolution ────────────────────────────────────────────────────────────
# Resolve to <project_root>/data/bootloader.db regardless of CWD
_HERE = Path(__file__).resolve().parent          # utils/
_PROJECT_ROOT = _HERE.parent                     # python_bootloader/
_DEFAULT_DB_PATH = _PROJECT_ROOT / "data" / "bootloader.db"

# SQL to create the table (mirrors scripts/create_display_log_table.sql)
_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS Display_Log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    SrNO                INTEGER NOT NULL,
    Date                TEXT    NOT NULL,
    Time                TEXT    NOT NULL,
    DuNo                INTEGER NOT NULL,
    dispSrNo            INTEGER NOT NULL,
    displayShaSign      TEXT    NOT NULL,
    firmware            REAL    NOT NULL DEFAULT 0.0,
    autoMode            INTEGER NOT NULL DEFAULT 0,
    onoff               INTEGER NOT NULL DEFAULT 0,
    Nozzle1_ID          INTEGER NOT NULL DEFAULT 0,
    Nozzle1_Amount      REAL    NOT NULL DEFAULT 0.0,
    Nozzle1_Volume      REAL    NOT NULL DEFAULT 0.0,
    Nozzle1_KFactor     INTEGER NOT NULL DEFAULT 1000,
    Nozzle1_Timestamp   TEXT    NOT NULL DEFAULT '0/0/0-0:0:0',
    Nozzle1_TXN         INTEGER NOT NULL DEFAULT 0,
    Nozzle1_FW          REAL    NOT NULL DEFAULT 0.0,
    Nozzle1_SHA         TEXT    NOT NULL,
    Nozzle2_ID          INTEGER NOT NULL DEFAULT 0,
    Nozzle2_Amount      REAL    NOT NULL DEFAULT 0.0,
    Nozzle2_Volume      REAL    NOT NULL DEFAULT 0.0,
    Nozzle2_KFactor     INTEGER NOT NULL DEFAULT 1000,
    Nozzle2_Timestamp   TEXT    NOT NULL DEFAULT '0/0/0-0:0:0',
    Nozzle2_TXN         INTEGER NOT NULL DEFAULT 0,
    Nozzle2_FW          REAL    NOT NULL DEFAULT 0.0,
    Nozzle2_SHA         TEXT    NOT NULL,
    Nozzle3_ID          INTEGER NOT NULL DEFAULT 0,
    Nozzle3_Amount      REAL    NOT NULL DEFAULT 0.0,
    Nozzle3_Volume      REAL    NOT NULL DEFAULT 0.0,
    Nozzle3_KFactor     INTEGER NOT NULL DEFAULT 1000,
    Nozzle3_Timestamp   TEXT    NOT NULL DEFAULT '0/0/0-0:0:0',
    Nozzle3_TXN         INTEGER NOT NULL DEFAULT 0,
    Nozzle3_FW          REAL    NOT NULL DEFAULT 0.0,
    Nozzle3_SHA         TEXT    NOT NULL,
    Nozzle4_ID          INTEGER NOT NULL DEFAULT 0,
    Nozzle4_Amount      REAL    NOT NULL DEFAULT 0.0,
    Nozzle4_Volume      REAL    NOT NULL DEFAULT 0.0,
    Nozzle4_KFactor     INTEGER NOT NULL DEFAULT 1000,
    Nozzle4_Timestamp   TEXT    NOT NULL DEFAULT '0/0/0-0:0:0',
    Nozzle4_TXN         INTEGER NOT NULL DEFAULT 0,
    Nozzle4_FW          REAL    NOT NULL DEFAULT 0.0,
    Nozzle4_SHA         TEXT    NOT NULL,
    created_at          TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);
"""

_CREATE_INDEXES_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_display_log_DuNo     ON Display_Log(DuNo);",
    "CREATE INDEX IF NOT EXISTS idx_display_log_dispSrNo ON Display_Log(dispSrNo);",
    "CREATE INDEX IF NOT EXISTS idx_display_log_Date     ON Display_Log(Date);",
    "CREATE INDEX IF NOT EXISTS idx_display_log_sha      ON Display_Log(displayShaSign);",
]

# All 40 data columns (excluding the auto id and created_at)
_COLUMNS = [
    "SrNO", "Date", "Time", "DuNo", "dispSrNo", "displayShaSign",
    "firmware", "autoMode", "onoff",
    "Nozzle1_ID", "Nozzle1_Amount", "Nozzle1_Volume", "Nozzle1_KFactor",
    "Nozzle1_Timestamp", "Nozzle1_TXN", "Nozzle1_FW", "Nozzle1_SHA",
    "Nozzle2_ID", "Nozzle2_Amount", "Nozzle2_Volume", "Nozzle2_KFactor",
    "Nozzle2_Timestamp", "Nozzle2_TXN", "Nozzle2_FW", "Nozzle2_SHA",
    "Nozzle3_ID", "Nozzle3_Amount", "Nozzle3_Volume", "Nozzle3_KFactor",
    "Nozzle3_Timestamp", "Nozzle3_TXN", "Nozzle3_FW", "Nozzle3_SHA",
    "Nozzle4_ID", "Nozzle4_Amount", "Nozzle4_Volume", "Nozzle4_KFactor",
    "Nozzle4_Timestamp", "Nozzle4_TXN", "Nozzle4_FW", "Nozzle4_SHA",
]

_INSERT_SQL = (
    f"INSERT INTO Display_Log ({', '.join(_COLUMNS)}) "
    f"VALUES ({', '.join(['?'] * len(_COLUMNS))})"
)


class DisplayLogDB:
    """Thin wrapper around the SQLite3 Display_Log table."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ── Connection management ──────────────────────────────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,    # safe for the single-threaded Tkinter UI
                isolation_level=None,       # autocommit for simple inserts
            )
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    # ── Schema initialisation ──────────────────────────────────────────────────

    def _init_db(self):
        conn = self._get_conn()
        conn.execute(_CREATE_TABLE_SQL)
        for idx_sql in _CREATE_INDEXES_SQL:
            conn.execute(idx_sql)
        logger.info("Display_Log table initialised at %s", self.db_path)

    # ── Insert helpers ─────────────────────────────────────────────────────────

    def insert_record(self, row: Dict[str, Any]) -> int:
        """
        Insert a single Display_Log record.

        Parameters
        ----------
        row : dict  – keys matching _COLUMNS (missing keys fall back to DEFAULT)

        Returns
        -------
        int – the rowid of the inserted row
        """
        values = tuple(row.get(col) for col in _COLUMNS)
        conn = self._get_conn()
        cur = conn.execute(_INSERT_SQL, values)
        logger.debug("Inserted Display_Log row id=%s", cur.lastrowid)
        return cur.lastrowid

    def insert_many(self, rows: List[Dict[str, Any]]) -> int:
        """Bulk-insert a list of row dicts. Returns number of rows inserted."""
        conn = self._get_conn()
        data = [tuple(row.get(col) for col in _COLUMNS) for row in rows]
        conn.execute("BEGIN")
        conn.executemany(_INSERT_SQL, data)
        conn.execute("COMMIT")
        logger.info("Bulk-inserted %d Display_Log rows", len(data))
        return len(data)

    # ── CSV import ─────────────────────────────────────────────────────────────

    def import_csv(self, csv_path: str, skip_duplicates: bool = True) -> int:
        """
        Import all rows from a Display_Log CSV file.

        Parameters
        ----------
        csv_path       : path to the .csv file
        skip_duplicates: if True, rows whose SrNO already exists are skipped

        Returns
        -------
        int – number of rows actually inserted
        """
        csv_path = Path(csv_path)
        if not csv_path.exists():
            raise FileNotFoundError(f"CSV not found: {csv_path}")

        rows = []
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for raw in reader:
                if not any(raw.values()):          # skip blank lines
                    continue
                row = _coerce_row(raw)
                if skip_duplicates and self._srno_exists(row["SrNO"]):
                    continue
                rows.append(row)

        if not rows:
            logger.info("No new rows to import from %s", csv_path)
            return 0

        return self.insert_many(rows)

    def _srno_exists(self, srno: int) -> bool:
        cur = self._get_conn().execute(
            "SELECT 1 FROM Display_Log WHERE SrNO=? LIMIT 1", (srno,)
        )
        return cur.fetchone() is not None

    # ── Query helpers ──────────────────────────────────────────────────────────

    def fetch_all(self) -> List[sqlite3.Row]:
        conn = self._get_conn()
        cur = conn.execute("SELECT * FROM Display_Log ORDER BY id")
        return cur.fetchall()

    def fetch_by_dispenser(self, du_no: int) -> List[sqlite3.Row]:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT * FROM Display_Log WHERE DuNo=? ORDER BY Date, Time", (du_no,)
        )
        return cur.fetchall()

    def fetch_by_date(self, date_str: str) -> List[sqlite3.Row]:
        """date_str in DD/MM/YYYY format as stored in the CSV."""
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT * FROM Display_Log WHERE Date=? ORDER BY Time", (date_str,)
        )
        return cur.fetchall()

    def fetch_by_sha(self, sha: str) -> List[sqlite3.Row]:
        """Find all records where the display firmware matches the given SHA."""
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT * FROM Display_Log WHERE displayShaSign=? ORDER BY Date, Time",
            (sha,),
        )
        return cur.fetchall()

    def row_count(self) -> int:
        cur = self._get_conn().execute("SELECT COUNT(*) FROM Display_Log")
        return cur.fetchone()[0]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _coerce_row(raw: Dict[str, str]) -> Dict[str, Any]:
    """
    Convert a raw CSV row (all strings) to the correct Python types
    that match the SQLite column affinities.
    """
    return {
        "SrNO":             int(raw["SrNO"]),
        "Date":             raw["Date"].strip(),
        "Time":             raw["Time"].strip(),
        "DuNo":             int(raw["DuNo"]),
        "dispSrNo":         int(raw["dispSrNo"]),
        "displayShaSign":   raw["displayShaSign"].strip(),
        "firmware":         float(raw["firmware"]),
        "autoMode":         int(raw["autoMode"]),
        "onoff":            int(raw["onoff"]),
        # Nozzle 1
        "Nozzle1_ID":       int(raw["Nozzle1_ID"]),
        "Nozzle1_Amount":   float(raw["Nozzle1_Amount"]),
        "Nozzle1_Volume":   float(raw["Nozzle1_Volume"]),
        "Nozzle1_KFactor":  int(raw["Nozzle1_KFactor"]),
        "Nozzle1_Timestamp":raw["Nozzle1_Timestamp"].strip(),
        "Nozzle1_TXN":      int(raw["Nozzle1_TXN"]),
        "Nozzle1_FW":       float(raw["Nozzle1_FW"]),
        "Nozzle1_SHA":      raw["Nozzle1_SHA"].strip(),
        # Nozzle 2
        "Nozzle2_ID":       int(raw["Nozzle2_ID"]),
        "Nozzle2_Amount":   float(raw["Nozzle2_Amount"]),
        "Nozzle2_Volume":   float(raw["Nozzle2_Volume"]),
        "Nozzle2_KFactor":  int(raw["Nozzle2_KFactor"]),
        "Nozzle2_Timestamp":raw["Nozzle2_Timestamp"].strip(),
        "Nozzle2_TXN":      int(raw["Nozzle2_TXN"]),
        "Nozzle2_FW":       float(raw["Nozzle2_FW"]),
        "Nozzle2_SHA":      raw["Nozzle2_SHA"].strip(),
        # Nozzle 3
        "Nozzle3_ID":       int(raw["Nozzle3_ID"]),
        "Nozzle3_Amount":   float(raw["Nozzle3_Amount"]),
        "Nozzle3_Volume":   float(raw["Nozzle3_Volume"]),
        "Nozzle3_KFactor":  int(raw["Nozzle3_KFactor"]),
        "Nozzle3_Timestamp":raw["Nozzle3_Timestamp"].strip(),
        "Nozzle3_TXN":      int(raw["Nozzle3_TXN"]),
        "Nozzle3_FW":       float(raw["Nozzle3_FW"]),
        "Nozzle3_SHA":      raw["Nozzle3_SHA"].strip(),
        # Nozzle 4
        "Nozzle4_ID":       int(raw["Nozzle4_ID"]),
        "Nozzle4_Amount":   float(raw["Nozzle4_Amount"]),
        "Nozzle4_Volume":   float(raw["Nozzle4_Volume"]),
        "Nozzle4_KFactor":  int(raw["Nozzle4_KFactor"]),
        "Nozzle4_Timestamp":raw["Nozzle4_Timestamp"].strip(),
        "Nozzle4_TXN":      int(raw["Nozzle4_TXN"]),
        "Nozzle4_FW":       float(raw["Nozzle4_FW"]),
        "Nozzle4_SHA":      raw["Nozzle4_SHA"].strip(),
    }


# ── Quick smoke-test / CLI import ──────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    db = DisplayLogDB()
    print(f"DB path : {db.db_path}")
    print(f"Rows before import: {db.row_count()}")

    if len(sys.argv) > 1:
        csv_file = sys.argv[1]
    else:
        csv_file = str(_PROJECT_ROOT / "Logs" / "Display_log.csv")

    inserted = db.import_csv(csv_file)
    print(f"Rows inserted: {inserted}")
    print(f"Total rows   : {db.row_count()}")
    db.close()
