import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "captures.db"


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS captures (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            source_ip   TEXT,
            user_agent  TEXT,
            method      TEXT,
            path        TEXT,
            query       TEXT,
            body        TEXT,
            credentials TEXT
        )
    """)
    conn.commit()
    conn.close()
