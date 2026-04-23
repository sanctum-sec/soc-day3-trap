import json
import os
import re
import secrets
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

BASE_DIR = Path(__file__).parent.parent
CAPTURES_DB = BASE_DIR / "trap" / "captures.db"
SECURITY_LOG = BASE_DIR / "logs" / "security.log"

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
security = HTTPBasic()

PEERS = ["wic02", "wic03", "wic04"]

# ── auth ──────────────────────────────────────────────────────────────────────

def verify(credentials: HTTPBasicCredentials = Depends(security)):
    user = os.environ.get("ADMIN_USER", "admin")
    pw   = os.environ.get("ADMIN_PASS", "SocDay3-Admin!")
    ok = secrets.compare_digest(credentials.username, user) and \
         secrets.compare_digest(credentials.password, pw)
    if not ok:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})

# ── data helpers ──────────────────────────────────────────────────────────────

def _captures_conn():
    if not CAPTURES_DB.exists():
        return None
    conn = sqlite3.connect(CAPTURES_DB)
    conn.row_factory = sqlite3.Row
    return conn


def event_counts() -> dict:
    conn = _captures_conn()
    if not conn:
        return {"5m": 0, "1h": 0, "24h": 0}
    now = datetime.now(timezone.utc)
    def _count(minutes):
        cutoff = (now - timedelta(minutes=minutes)).isoformat()
        return conn.execute(
            "SELECT COUNT(*) FROM captures WHERE ts >= ?", (cutoff,)
        ).fetchone()[0]
    result = {"5m": _count(5), "1h": _count(60), "24h": _count(1440)}
    conn.close()
    return result


def last_captures(n: int = 20) -> list:
    conn = _captures_conn()
    if not conn:
        return []
    rows = conn.execute(
        "SELECT id, ts, source_ip, user_agent, method, path, credentials "
        "FROM captures ORDER BY id DESC LIMIT ?", (n,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def peer_status() -> dict[str, dict]:
    """Scan last 600 lines of security.log for most recent result per peer."""
    status = {p: {"state": "unknown", "ts": "", "detail": ""} for p in PEERS}
    if not SECURITY_LOG.exists():
        return status
    lines = SECURITY_LOG.read_text(errors="replace").splitlines()[-600:]
    # Walk newest-first so first match = most recent
    for line in reversed(lines):
        for peer in PEERS:
            if status[peer]["state"] != "unknown":
                continue
            if f"-> {peer} [" in line:
                code = re.search(rf"-> {peer} \[(\d+)\]", line)
                status[peer] = {
                    "state": "ok" if code and code.group(1).startswith("2") else "error",
                    "ts": line[:23],
                    "detail": f"HTTP {code.group(1)}" if code else "",
                }
            elif f"peer {peer} " in line and ("unreachable" in line or "returned" in line):
                status[peer] = {
                    "state": "error",
                    "ts": line[:23],
                    "detail": line[line.find(peer):][len(peer)+1:80],
                }
    return status


def security_log_grouped(n: int = 50) -> dict[str, list]:
    """Return last n parseable log entries grouped by event_type."""
    if not SECURITY_LOG.exists():
        return {}
    lines = SECURITY_LOG.read_text(errors="replace").splitlines()

    entries = []
    for line in reversed(lines):
        if len(entries) >= n:
            break
        line = line.strip()
        if not line:
            continue
        # JSON entry (portal / old honeypot)
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                entries.append({
                    "event_type": obj.get("event_type") or _classify_json(obj),
                    "ts":  obj.get("timestamp", "")[:19],
                    "ip":  obj.get("source_ip", ""),
                    "detail": f"{obj.get('method','')} {obj.get('path','')}",
                })
                continue
            except json.JSONDecodeError:
                pass
        # Structured text entry (publisher / ioc_sync)
        entries.append({
            "event_type": _classify_text(line),
            "ts": line[:23],
            "ip": "",
            "detail": line[24:120] if len(line) > 24 else line,
        })

    grouped: dict[str, list] = defaultdict(list)
    for e in entries:
        grouped[e["event_type"]].append(e)
    return dict(grouped)


def _classify_json(obj: dict) -> str:
    tags = obj.get("tags", [])
    if "credential_capture" in tags:
        return "credential_capture"
    if "sso_attempt" in tags:
        return "sso_attempt"
    return "http_probe"


def _classify_text(line: str) -> str:
    l = line.lower()
    if "published" in l:
        return "publish_success"
    if "unreachable" in l or "returned" in l:
        return "peer_error"
    if "ioc_sync" in l:
        return "ioc_sync"
    if "error" in l:
        return "error"
    return "info"


# ── HTML helpers ──────────────────────────────────────────────────────────────

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
       background: #0d1117; color: #c9d1d9; padding: 24px; }
h1  { color: #58a6ff; font-size: 18px; margin-bottom: 20px; }
h2  { color: #8b949e; font-size: 13px; text-transform: uppercase;
      letter-spacing: 1px; margin: 24px 0 10px; }
.tabs { display: flex; gap: 8px; margin-bottom: 24px; }
.tab  { padding: 7px 18px; border: 1px solid #30363d; border-radius: 6px;
        background: #161b22; color: #8b949e; cursor: pointer; font-size: 13px;
        text-decoration: none; }
.tab.active, .tab:hover { border-color: #58a6ff; color: #e6edf3; }
.stats { display: flex; gap: 14px; margin-bottom: 8px; }
.stat { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
        padding: 12px 20px; min-width: 100px; }
.stat .label { font-size: 11px; color: #8b949e; margin-bottom: 4px; }
.stat .value { font-size: 26px; font-weight: 600; color: #58a6ff; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th, td { padding: 6px 10px; text-align: left; border-bottom: 1px solid #21262d; }
th { color: #8b949e; font-weight: 600; background: #161b22; }
tr:hover td { background: #161b22; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px;
         font-size: 11px; font-weight: 600; }
.ok    { background: #1a4731; color: #3fb950; }
.error { background: #3d1c1c; color: #f85149; }
.unknown { background: #21262d; color: #8b949e; }
.cred  { background: #3d2b00; color: #e3b341; }
.group-header { background: #161b22; color: #8b949e; font-size: 11px;
                padding: 5px 10px; letter-spacing: 0.5px; border-left: 3px solid #30363d; }
.group-header.credential_capture { border-color: #e3b341; }
.group-header.peer_error         { border-color: #f85149; }
.group-header.publish_success    { border-color: #3fb950; }
.group-header.ioc_sync           { border-color: #58a6ff; }
pre { white-space: pre-wrap; word-break: break-all; max-width: 480px; }
"""

def _tab_buttons(active: str) -> str:
    tabs = {"ops": "Operational", "security": "Security"}
    out = '<div class="tabs">'
    for key, label in tabs.items():
        cls = "tab active" if key == active else "tab"
        out += f'<a class="{cls}" href="#" hx-get="/tabs/{key}" hx-target="#content" hx-swap="innerHTML">{label}</a>'
    return out + "</div>"


def shell() -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>wic01 — Admin</title>
<script src="https://unpkg.com/htmx.org@1.9.12/dist/htmx.min.js"></script>
<style>{CSS}</style>
</head><body>
<h1>🪤 wic01 — Admin Panel</h1>
{_tab_buttons("ops")}
<div id="content"
     hx-get="/tabs/ops"
     hx-trigger="load"
     hx-swap="innerHTML">
  <p style="color:#8b949e;font-size:13px">Loading…</p>
</div>
</body></html>"""


def _badge(state: str) -> str:
    return f'<span class="badge {state}">{state.upper()}</span>'


def ops_fragment() -> str:
    counts  = event_counts()
    rows    = last_captures(20)
    peers   = peer_status()

    # stats
    stats_html = "".join(
        f'<div class="stat"><div class="label">Last {k}</div>'
        f'<div class="value">{v}</div></div>'
        for k, v in counts.items()
    )

    # captures table
    cap_rows = ""
    for r in rows:
        cred_cell = f'<td class="badge cred">{r["credentials"][:40]}</td>' \
                    if r["credentials"] else "<td>—</td>"
        cap_rows += (
            f"<tr><td>{r['ts'][:19]}</td><td>{r['source_ip']}</td>"
            f"<td>{r['method']}</td><td>{r['path']}</td>{cred_cell}</tr>"
        )
    cap_table = f"""<table>
<tr><th>Timestamp</th><th>Source IP</th><th>Method</th><th>Path</th><th>Credentials</th></tr>
{cap_rows or '<tr><td colspan="5" style="color:#8b949e">No captures yet</td></tr>'}
</table>"""

    # peer table
    peer_rows = "".join(
        f"<tr><td>{p}</td><td>{_badge(d['state'])}</td>"
        f"<td style='color:#8b949e;font-size:11px'>{d['ts']}</td>"
        f"<td style='font-size:11px'>{d['detail']}</td></tr>"
        for p, d in peers.items()
    )
    peer_table = f"""<table>
<tr><th>Peer</th><th>Status</th><th>Last seen</th><th>Detail</th></tr>
{peer_rows}
</table>"""

    return f"""<div hx-get="/tabs/ops" hx-trigger="every 5s" hx-swap="outerHTML">
<h2>Event counts</h2>
<div class="stats">{stats_html}</div>
<h2>Last 20 captures</h2>
{cap_table}
<h2>Outbound delivery</h2>
{peer_table}
</div>"""


def security_fragment() -> str:
    grouped = security_log_grouped(50)
    if not grouped:
        return '<div hx-get="/tabs/security" hx-trigger="every 5s" hx-swap="outerHTML"><p style="color:#8b949e;font-size:13px">No log entries yet.</p></div>'

    body = ""
    type_order = ["credential_capture", "peer_error", "sso_attempt",
                  "http_probe", "publish_success", "ioc_sync", "error", "info"]
    keys = type_order + [k for k in grouped if k not in type_order]

    for key in keys:
        entries = grouped.get(key)
        if not entries:
            continue
        body += f'<tr class="group-header {key}"><td colspan="4">{key.upper()} ({len(entries)})</td></tr>'
        for e in entries[:15]:
            body += (
                f"<tr><td>{e['ts']}</td><td>{e['ip']}</td>"
                f"<td><pre>{e['detail'][:120]}</pre></td></tr>"
            )

    return f"""<div hx-get="/tabs/security" hx-trigger="every 5s" hx-swap="outerHTML">
<h2>Security log — last 50 entries grouped by type</h2>
<table>
<tr><th>Timestamp</th><th>IP</th><th>Detail</th></tr>
{body}
</table>
</div>"""


# ── routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index(_: None = Depends(verify)):
    return shell()


@app.get("/tabs/ops", response_class=HTMLResponse)
def tab_ops(_: None = Depends(verify)):
    return ops_fragment()


@app.get("/tabs/security", response_class=HTMLResponse)
def tab_security(_: None = Depends(verify)):
    return security_fragment()


@app.get("/admin", response_class=HTMLResponse)
def admin_alias(_: None = Depends(verify)):
    return shell()
