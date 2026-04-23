"""
Reads new captures from trap/captures.db every 5 s, converts to SOC Protocol
EventEnvelope, and POSTs to all configured peers.
"""
import json
import logging
import os
import time
import uuid
from pathlib import Path

import requests

import ioc_sync

BASE_DIR = Path(__file__).parent
STATE_FILE = BASE_DIR / "publisher_state.json"
LOG_FILE = BASE_DIR / "logs" / "security.log"
DB_PATH = BASE_DIR / "trap" / "captures.db"

# wic02/Scout expects an IOC envelope; wic03+wic04 get the standard telemetry envelope
TELEMETRY_PEERS = {
    "wic03": "http://wic03.sanctumsec.com:8000/ingest",
    "wic04": "http://wic04.sanctumsec.com:8000/telemetry",
}
SCOUT_URL = "http://wic02.sanctumsec.com:8000/observe"

SCHEMA_VERSION = "1.0"
PRODUCER = "wic01"
POLL_INTERVAL = 5

# ── logging ───────────────────────────────────────────────────────────────────

LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("publisher")

# ── state ─────────────────────────────────────────────────────────────────────

def load_cursor() -> int:
    try:
        return json.loads(STATE_FILE.read_text()).get("last_rowid", 0)
    except (FileNotFoundError, json.JSONDecodeError):
        return 0


def save_cursor(rowid: int) -> None:
    STATE_FILE.write_text(json.dumps({"last_rowid": rowid}))


# ── conversion ────────────────────────────────────────────────────────────────

_SEVERITY_MAP = {
    "/.env":          "high",
    "/wp-admin":      "medium",
    "/wp-login.php":  "medium",
    "/phpmyadmin":    "medium",
    "/pma":           "medium",
    "/login":         "medium",
    "/admin":         "medium",
    "/xmlrpc.php":    "low",
}


def _severity(path: str, credentials: str | None) -> str:
    if credentials:
        return "high"
    return _SEVERITY_MAP.get(path.rstrip("/"), "info")


def row_to_envelope(row) -> dict:
    rowid, ts, source_ip, user_agent, method, path, query, body, credentials = row

    is_known_bad, score = ioc_sync.lookup(source_ip)
    enrichment = {"is_known_bad": is_known_bad}
    if is_known_bad:
        enrichment["scout_reputation_score"] = score

    severity = _severity(path, credentials)
    if is_known_bad and severity in ("info", "low"):
        severity = "medium"

    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "event_type": "telemetry",
        "timestamp": ts,
        "producer": PRODUCER,
        "severity": severity,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "method": method,
        "path": path,
        "query": query,
        "body": body,
        "credentials": credentials,
        "data": {"enrichment": enrichment},
    }


# ── fetch new rows ────────────────────────────────────────────────────────────

def fetch_new_rows(last_rowid: int) -> list[tuple]:
    import sqlite3
    if not DB_PATH.exists():
        return []
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT rowid, ts, source_ip, user_agent, method, path, query, body, credentials "
        "FROM captures WHERE rowid > ? ORDER BY rowid ASC",
        (last_rowid,),
    ).fetchall()
    conn.close()
    return rows


# ── publish ───────────────────────────────────────────────────────────────────

def _post(peer: str, url: str, payload: dict, token: str) -> None:
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=5)
        if r.ok:
            log.info("published %s -> %s [%d]", payload.get("event_id", "?")[:8], peer, r.status_code)
        else:
            log.error("peer %s returned %d for event %s: %s",
                      peer, r.status_code, payload.get("event_id", "?")[:8], r.text[:200])
    except requests.RequestException as exc:
        log.error("peer %s unreachable for event %s: %s", peer, payload.get("event_id", "?")[:8], exc)


def _scout_payload(envelope: dict) -> dict:
    """Convert telemetry envelope to wic02 Scout IOC envelope format."""
    is_bad, score = ioc_sync.lookup(envelope["source_ip"])
    return {
        "event_id":         envelope["event_id"],
        "timestamp":        envelope["timestamp"],
        "source":           PRODUCER,
        "ioc_value":        envelope["source_ip"],
        "ioc_type":         "ip",
        "tags":             (["credential_capture"] if envelope.get("credentials") else [])
                            + (["known_bad"] if is_bad else []),
        "reputation_score": int(score) if score is not None else (80 if is_bad else 0),
    }


def publish(envelope: dict, token: str) -> None:
    # Standard telemetry to wic03 / wic04
    for peer, url in TELEMETRY_PEERS.items():
        _post(peer, url, envelope, token)
    # IOC observable to wic02 Scout
    _post("wic02", SCOUT_URL, _scout_payload(envelope), token)


# ── main loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    token = os.environ.get("SOC_PROTOCOL_TOKEN", "")
    if not token:
        log.warning("SOC_PROTOCOL_TOKEN not set — requests will have an empty bearer token")

    ioc_sync.start(token)

    log.info("publisher started (poll every %ds)", POLL_INTERVAL)
    cursor = load_cursor()
    log.info("resuming from rowid %d", cursor)

    while True:
        try:
            rows = fetch_new_rows(cursor)
            for row in rows:
                envelope = row_to_envelope(row)
                publish(envelope, token)
                cursor = row[0]
                save_cursor(cursor)
            if rows:
                log.info("processed %d new capture(s), cursor now at %d", len(rows), cursor)
        except Exception as exc:
            log.error("publisher loop error: %s", exc)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
