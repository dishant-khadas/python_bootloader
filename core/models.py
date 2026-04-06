"""
core/models.py
--------------
Peewee ORM model definitions for the SQLite3 database.

DB location: ~/.czar-bootloader/bootloader.db  (persistent across reboots and rebuilds)

Tables
------
    DisplaySession  → mirrors Display_log.csv   (1 row per successful handshake)
    ProgrammingLog  → mirrors logs.csv          (1 row per firmware update attempt)
    NozzleLog       → nozzle sub-records        (4 rows per DisplaySession)

ProgrammingLog.display_session is a nullable FK:
    → Set when a handshake succeeded before the update (S-01, E-21, E-15 …)
    → NULL for auth/handshake failures (E-51, E-31, E-42 …)

Usage
-----
    from core.models import init_db, ProgrammingLog, DisplaySession, NozzleLog
    init_db()  # call once at app startup
"""

import datetime
from pathlib import Path

from peewee import (
    SqliteDatabase,
    Model,
    AutoField,
    IntegerField,
    CharField,
    FloatField,
    ForeignKeyField,
    DateTimeField,
)
from utils.path_utils import get_log_path

# ── DB path ────────────────────────────────────────────────────────────────────
# Use the same persistent user directory as the CSV logs (~/.czar-bootloader/)
# This survives PyInstaller rebuilds and app restarts.
_DB_PATH = Path(get_log_path("bootloader.db"))

db = SqliteDatabase(
    str(_DB_PATH),
    pragmas={
        "foreign_keys": 1,            # enforce FK constraints within NozzleLog
    },
)

class BaseModel(Model):
    class Meta:
        database = db



class DisplaySession(BaseModel):
    """One row per successful 512-byte handshake."""

    id             = AutoField()
    SrNO           = IntegerField()
    Date           = CharField()                      # DD/MM/YYYY
    Time           = CharField()                      # HH:MM:SS
    duNumber       = CharField()                      # unified name (was DuNo in CSV)
    displayNumber  = CharField()                      # unified name (was dispSrNo in CSV)
    displayShaSign = CharField()                      # 0x... SHA-256 of display firmware
    firmware       = FloatField(default=0.0)          # e.g. 11.13
    autoMode       = IntegerField(default=0)          # 0=manual, 1=auto
    onoff          = IntegerField(default=0)          # 0=off, 1=on
    created_at     = DateTimeField(default=datetime.datetime.now)

    class Meta:
        table_name = "Display_Session"


class ProgrammingLog(BaseModel):
    """
    One row per firmware update attempt (success or failure).
    display_session is NULL when no handshake happened (login fail, timeout).
    """

    id              = AutoField()
    SrNO            = IntegerField()
    Log_ID          = CharField()                     # e.g. 41999990_260213141012_1
    errorCode       = CharField(default="")           # e.g. 'E-51', 'E-31', 'S-01'
    display_session = ForeignKeyField(
                          DisplaySession,
                          null=True,
                          default=None,
                          backref="programming_logs",
                          on_delete="SET NULL",
                      )                               # NULL → no handshake for this attempt
    phoneNo       = CharField(default="")             # empty on login failure
    IP_Address    = CharField(default="")
    Date          = CharField()                       # DD-MM-YYYY
    Time          = CharField()                       # HH:MM:SS
    duNumber      = CharField(default="")             # empty if handshake never succeeded
    displayNumber = CharField(default="")             # empty if handshake never succeeded
    fileName      = CharField(default="")             # empty on handshake / auth failures
    result        = CharField()                       # 'Success' | 'Fail' | 'Failed'
    description   = CharField(default="")
    data_sent     = IntegerField(default=0)           # 0 = not synced to server yet
    created_at    = DateTimeField(default=datetime.datetime.now)

    class Meta:
        table_name = "Programming_Log"


class NozzleLog(BaseModel):
    """
    4 rows per DisplaySession — one for each nozzle.
    Hard FK to DisplaySession (safe because nozzles only exist WITH a session).
    """

    id            = AutoField()
    session       = ForeignKeyField(
                        DisplaySession,
                        backref="nozzles",
                        on_delete="CASCADE",
                    )
    nozzle_number = IntegerField()                    # 1 | 2 | 3 | 4
    nozzle_ID     = IntegerField(default=0)           # nozzle type identifier
    Amount        = FloatField(default=0.0)           # transaction amount
    Volume        = FloatField(default=0.0)           # volume dispensed
    KFactor       = IntegerField(default=1000)        # calibration factor
    Timestamp     = CharField(default="0/0/0-0:0:0") # last transaction timestamp
    TXN           = IntegerField(default=0)           # transaction count
    FW            = FloatField(default=0.0)           # nozzle firmware version
    SHA           = CharField(default="")             # 0x... SHA-256 of nozzle firmware

    class Meta:
        table_name = "Nozzle_Log"


# ── Initialisation ─────────────────────────────────────────────────────────────

def init_db() -> None:
    """
    Create tables if they don't exist. Call once at app startup.
    Safe to call multiple times (uses CREATE TABLE IF NOT EXISTS).
    """
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db.connect(reuse_if_open=True)
    db.create_tables([ProgrammingLog, DisplaySession, NozzleLog], safe=True)
