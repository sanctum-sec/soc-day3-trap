import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "events.db"


def get_conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id    TEXT PRIMARY KEY,
            sensor_id   TEXT,
            timestamp   TEXT,
            source_ip   TEXT,
            source_port INTEGER,
            dest_port   INTEGER,
            method      TEXT,
            path        TEXT,
            headers     TEXT,
            body        TEXT,
            tags        TEXT,
            ioc_matches TEXT,
            published   INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            ip   TEXT PRIMARY KEY,
            data TEXT
        )
    """)
    conn.commit()
    conn.close()
