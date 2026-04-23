from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
import sqlite3
import uuid
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from db import get_conn

BASE_DIR = Path(__file__).parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

sec_logger = logging.getLogger("portal")
_h = logging.FileHandler(LOG_DIR / "security.log")
_h.setFormatter(logging.Formatter("%(message)s"))
sec_logger.addHandler(_h)
sec_logger.setLevel(logging.INFO)

app = FastAPI(docs_url=None, redoc_url=None)

HTML_LOGIN = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sanctum Corp — Employee Portal</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0a0e1a;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }
    .bg-grid {
      position: fixed; inset: 0; z-index: 0;
      background-image:
        linear-gradient(rgba(0,200,255,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,200,255,0.03) 1px, transparent 1px);
      background-size: 40px 40px;
    }
    .glow {
      position: fixed;
      width: 600px; height: 600px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(0,120,255,0.12) 0%, transparent 70%);
      top: -100px; left: -100px;
      pointer-events: none;
    }
    .glow2 {
      position: fixed;
      width: 400px; height: 400px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(0,220,180,0.08) 0%, transparent 70%);
      bottom: -50px; right: -50px;
      pointer-events: none;
    }
    .card {
      position: relative; z-index: 1;
      background: rgba(13, 18, 30, 0.9);
      border: 1px solid rgba(0,200,255,0.15);
      border-radius: 16px;
      padding: 48px 44px;
      width: 420px;
      box-shadow: 0 0 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.03);
      backdrop-filter: blur(20px);
    }
    .logo {
      display: flex; align-items: center; gap: 10px;
      margin-bottom: 32px;
    }
    .logo-icon {
      width: 36px; height: 36px;
      background: linear-gradient(135deg, #0078ff, #00dcb4);
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      font-size: 18px;
    }
    .logo-text { font-size: 18px; font-weight: 600; color: #e8eaf0; letter-spacing: -0.3px; }
    .logo-sub  { font-size: 11px; color: #4a5568; letter-spacing: 1.5px; text-transform: uppercase; }
    h1 { font-size: 22px; font-weight: 600; color: #e8eaf0; margin-bottom: 6px; }
    .subtitle { font-size: 13px; color: #4a5568; margin-bottom: 32px; }
    label { display: block; font-size: 12px; color: #6b7a99; margin-bottom: 6px; letter-spacing: 0.3px; }
    input[type=text], input[type=password] {
      width: 100%;
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 8px;
      padding: 11px 14px;
      color: #e8eaf0;
      font-size: 14px;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
      margin-bottom: 18px;
    }
    input:focus {
      border-color: rgba(0,200,255,0.4);
      box-shadow: 0 0 0 3px rgba(0,200,255,0.08);
    }
    .forgot { font-size: 12px; color: #0078ff; text-decoration: none; float: right; margin-top: -14px; margin-bottom: 22px; display: block; }
    .forgot:hover { color: #00dcb4; }
    button {
      width: 100%;
      background: linear-gradient(135deg, #0078ff, #0055cc);
      color: #fff;
      border: none;
      border-radius: 8px;
      padding: 12px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.2s, transform 0.1s;
      letter-spacing: 0.3px;
    }
    button:hover { opacity: 0.9; }
    button:active { transform: scale(0.99); }
    .divider { display: flex; align-items: center; gap: 12px; margin: 22px 0; }
    .divider hr { flex: 1; border: none; border-top: 1px solid rgba(255,255,255,0.06); }
    .divider span { font-size: 12px; color: #2d3748; }
    .sso {
      width: 100%;
      background: transparent;
      border: 1px solid rgba(255,255,255,0.08);
      color: #6b7a99;
      border-radius: 8px;
      padding: 11px;
      font-size: 13px;
      cursor: pointer;
      transition: border-color 0.2s, color 0.2s;
    }
    .sso:hover { border-color: rgba(0,200,255,0.3); color: #e8eaf0; }
    .footer { margin-top: 28px; font-size: 11px; color: #2d3748; text-align: center; }
    .badge {
      display: inline-flex; align-items: center; gap: 5px;
      background: rgba(0,200,255,0.06);
      border: 1px solid rgba(0,200,255,0.12);
      border-radius: 20px;
      padding: 3px 10px;
      font-size: 11px; color: #4a90a4;
      margin-bottom: 28px;
    }
    .dot { width: 6px; height: 6px; background: #00dcb4; border-radius: 50%; animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
    .error { color: #ff5a6a; font-size: 12px; margin-bottom: 14px; padding: 8px 12px; background: rgba(255,90,106,0.08); border-radius: 6px; border: 1px solid rgba(255,90,106,0.2); }
  </style>
</head>
<body>
  <div class="bg-grid"></div>
  <div class="glow"></div>
  <div class="glow2"></div>
  <div class="card">
    <div class="logo">
      <div class="logo-icon">🔐</div>
      <div>
        <div class="logo-text">Sanctum Corp</div>
        <div class="logo-sub">Secure Access</div>
      </div>
    </div>
    <div class="badge"><div class="dot"></div> Systems operational</div>
    <h1>Welcome back</h1>
    <p class="subtitle">Sign in to your employee account</p>
    {error_block}
    <form method="POST" action="/login">
      <label>Corporate email</label>
      <input type="text" name="username" placeholder="you@sanctumcorp.com" autocomplete="off">
      <label>Password</label>
      <input type="password" name="password" placeholder="••••••••••">
      <a href="/reset" class="forgot">Forgot password?</a>
      <button type="submit">Sign in →</button>
    </form>
    <div class="divider"><hr><span>or</span><hr></div>
    <button class="sso" onclick="window.location='/sso'">🏢 &nbsp; Continue with SSO</button>
    <div class="footer">© 2026 Sanctum Corp · <a href="/privacy" style="color:#2d3748">Privacy</a> · <a href="/terms" style="color:#2d3748">Terms</a></div>
  </div>
</body>
</html>"""

HTML_LOADING = """<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Sanctum Corp — Authenticating...</title>
  <meta http-equiv="refresh" content="3;url=/dashboard">
  <style>
    * { margin:0; padding:0; box-sizing:border-box }
    body { background:#0a0e1a; display:flex; align-items:center; justify-content:center; min-height:100vh; font-family:-apple-system,sans-serif; color:#e8eaf0; }
    .wrap { text-align:center }
    .spinner { width:40px; height:40px; border:2px solid rgba(0,200,255,0.1); border-top-color:#0078ff; border-radius:50%; animation:spin 0.8s linear infinite; margin:0 auto 20px; }
    @keyframes spin { to { transform:rotate(360deg) } }
    p { color:#4a5568; font-size:14px }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="spinner"></div>
    <p>Verifying credentials...</p>
  </div>
</body>
</html>"""

HTML_DASHBOARD = """<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Sanctum Corp — Portal</title>
  <meta http-equiv="refresh" content="2;url=/login?err=session">
  <style>
    * { margin:0; padding:0; box-sizing:border-box }
    body { background:#0a0e1a; display:flex; align-items:center; justify-content:center; min-height:100vh; font-family:-apple-system,sans-serif; color:#e8eaf0; }
    .wrap { text-align:center }
    p { color:#4a5568; font-size:14px; margin-top:10px }
    span { font-size:36px }
  </style>
</head>
<body>
  <div class="wrap">
    <span>🔒</span>
    <p>Session expired. Redirecting...</p>
  </div>
</body>
</html>"""


def log_event(request: Request, path: str, extra: dict = None):
    event = {
        "event_id": str(uuid.uuid4()),
        "sensor_id": "wic01-portal",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": request.client.host if request.client else "unknown",
        "source_port": request.client.port if request.client else 0,
        "destination_port": 80,
        "method": request.method,
        "path": path,
        "headers": dict(request.headers),
        "body": "",
        "tags": ["portal"],
        "ioc_matches": [],
    }
    if extra:
        event.update(extra)

    conn = get_conn()
    conn.execute(
        "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            event["event_id"], event["sensor_id"], event["timestamp"],
            event["source_ip"], event["source_port"], event["destination_port"],
            event["method"], event["path"],
            json.dumps(event["headers"]), event.get("body", ""),
            json.dumps(event["tags"]), json.dumps(event["ioc_matches"]),
            0,
        ),
    )
    conn.commit()
    conn.close()
    sec_logger.info(json.dumps({k: v for k, v in event.items() if k != "headers"}))


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    log_event(request, "/")
    return RedirectResponse("/login")


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request, err: str = ""):
    log_event(request, "/login")
    error_block = ""
    if err == "session":
        error_block = '<div class="error">⚠ Your session has expired. Please sign in again.</div>'
    elif err == "invalid":
        error_block = '<div class="error">⚠ Invalid credentials. Please try again.</div>'
    return HTML_LOGIN.replace("{error_block}", error_block)


@app.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, username: str = Form(""), password: str = Form("")):
    log_event(request, "/login", {
        "body": json.dumps({"username": username, "password": password}),
        "tags": ["portal", "credential_capture"],
    })
    return HTMLResponse(HTML_LOADING)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    log_event(request, "/dashboard")
    return HTMLResponse(HTML_DASHBOARD)


@app.get("/sso", response_class=HTMLResponse)
async def sso(request: Request):
    log_event(request, "/sso", {"tags": ["portal", "sso_attempt"]})
    return RedirectResponse("/login?err=session")



@app.api_route("/ingest", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def block_ingest(request: Request):
    log_event(request, "/ingest")
    from fastapi.responses import JSONResponse
    return JSONResponse(
        {"detail": "Invalid or missing bearer token"},
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.api_route("/{path:path}", methods=["GET", "POST"])
async def catch_all(request: Request, path: str):
    log_event(request, f"/{path}")
    return RedirectResponse("/login")
