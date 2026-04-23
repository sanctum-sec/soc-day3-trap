"""
Background thread that fetches bad-IP list from wic02 every 60 s.
Import this module and call start(token) once; use lookup(ip) anywhere.
"""
import logging
import threading
import time
from typing import Optional

import requests

log = logging.getLogger("ioc_sync")

IOC_URL = "http://wic02.sanctumsec.com:8000/ioc/bad-ips"
INTERVAL = 60

# {ip: score_or_None}  — replaced atomically on each successful fetch
_cache: dict[str, Optional[float]] = {}
_lock = threading.Lock()


# ── response normaliser ───────────────────────────────────────────────────────

def _parse(data) -> dict[str, Optional[float]]:
    """
    Accept any reasonable shape the feed might return:
      - ["1.2.3.4", ...]
      - [{"ip": "1.2.3.4", "score": 85}, ...]
      - {"1.2.3.4": 85, ...}
      - {"1.2.3.4": {"score": 85, ...}, ...}
    """
    result: dict[str, Optional[float]] = {}
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                result[item] = None
            elif isinstance(item, dict):
                ip = item.get("ip") or item.get("address") or item.get("indicator")
                raw_score = (
                    item.get("score")
                    or item.get("reputation_score")
                    or item.get("reputation")
                    or item.get("risk_score")
                )
                if ip:
                    result[str(ip)] = float(raw_score) if raw_score is not None else None
    elif isinstance(data, dict):
        for ip, val in data.items():
            if isinstance(val, (int, float)):
                result[str(ip)] = float(val)
            elif isinstance(val, dict):
                raw = val.get("score") or val.get("reputation_score") or val.get("reputation")
                result[str(ip)] = float(raw) if raw is not None else None
            else:
                result[str(ip)] = None
    return result


# ── fetch / loop ──────────────────────────────────────────────────────────────

def _fetch(token: str) -> None:
    try:
        r = requests.get(
            IOC_URL,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if r.ok:
            parsed = _parse(r.json())
            with _lock:
                _cache.clear()
                _cache.update(parsed)
            log.info("ioc_sync: refreshed — %d bad IPs in cache", len(_cache))
        else:
            log.warning("ioc_sync: feed returned %d", r.status_code)
    except Exception as exc:
        log.warning("ioc_sync: fetch error: %s", exc)


def _loop(token: str) -> None:
    while True:
        _fetch(token)
        time.sleep(INTERVAL)


# ── public API ────────────────────────────────────────────────────────────────

def start(token: str) -> None:
    """Spawn background fetch thread. Safe to call multiple times (no-op after first)."""
    t = threading.Thread(target=_loop, args=(token,), daemon=True, name="ioc-sync")
    t.start()
    log.info("ioc_sync: started (interval=%ds, url=%s)", INTERVAL, IOC_URL)


def lookup(ip: str) -> tuple[bool, Optional[float]]:
    """Return (is_known_bad, scout_reputation_score). Score is None if feed omits it."""
    with _lock:
        if ip in _cache:
            return True, _cache[ip]
    return False, None
