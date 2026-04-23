import json
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from .db import init_db, get_conn

init_db()

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# ── helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_creds(body: str, content_type: str) -> Optional[str]:
    """Pull anything that looks like credentials out of the request body."""
    cred_keys = {"username", "user", "email", "login", "password", "pass", "pwd", "secret", "token"}
    try:
        if "application/json" in content_type:
            data = json.loads(body)
            found = {k: v for k, v in data.items() if k.lower() in cred_keys}
            return json.dumps(found) if found else None
        if "application/x-www-form-urlencoded" in content_type or "multipart" in content_type:
            data = dict(urllib.parse.parse_qsl(body))
            found = {k: v for k, v in data.items() if k.lower() in cred_keys}
            return json.dumps(found) if found else None
    except Exception:
        pass
    return None


async def _capture(request: Request) -> None:
    raw = await request.body()
    body = raw.decode("utf-8", errors="replace")[:8192]
    ct = request.headers.get("content-type", "")
    creds = _extract_creds(body, ct)

    conn = get_conn()
    conn.execute(
        """INSERT INTO captures
           (ts, source_ip, user_agent, method, path, query, body, credentials)
           VALUES (?,?,?,?,?,?,?,?)""",
        (
            _now(),
            request.client.host if request.client else "unknown",
            request.headers.get("user-agent", ""),
            request.method,
            request.url.path,
            str(request.query_params),
            body,
            creds,
        ),
    )
    conn.commit()
    conn.close()


# ── /login ────────────────────────────────────────────────────────────────────

@app.api_route("/login", methods=["GET", "POST"])
async def fake_login(request: Request):
    await _capture(request)
    if request.method == "GET":
        return HTMLResponse("""<!DOCTYPE html><html><head><title>Login</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;padding-top:80px;background:#f5f5f5}
.box{background:#fff;padding:32px;border-radius:4px;box-shadow:0 1px 4px rgba(0,0,0,.2);width:320px}
h2{margin:0 0 20px}input{width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box;border:1px solid #ccc;border-radius:3px}
button{width:100%;padding:9px;background:#0066cc;color:#fff;border:none;border-radius:3px;cursor:pointer}
.err{color:red;font-size:13px;margin-bottom:10px}</style></head>
<body><div class="box"><h2>Sign in</h2>
<form method="POST">
<input name="username" placeholder="Username"><input type="password" name="password" placeholder="Password">
<button>Sign in</button></form></div></body></html>""", status_code=200)
    return HTMLResponse("""<!DOCTYPE html><html><head><title>Login</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;padding-top:80px;background:#f5f5f5}
.box{background:#fff;padding:32px;border-radius:4px;box-shadow:0 1px 4px rgba(0,0,0,.2);width:320px}
h2{margin:0 0 20px}input{width:100%;padding:8px;margin-bottom:12px;box-sizing:border-box;border:1px solid #ccc;border-radius:3px}
button{width:100%;padding:9px;background:#0066cc;color:#fff;border:none;border-radius:3px;cursor:pointer}
.err{color:red;font-size:13px;margin-bottom:10px}</style></head>
<body><div class="box"><h2>Sign in</h2>
<p class="err">Invalid username or password.</p>
<form method="POST">
<input name="username" placeholder="Username"><input type="password" name="password" placeholder="Password">
<button>Sign in</button></form></div></body></html>""", status_code=401)


# ── /admin ────────────────────────────────────────────────────────────────────

@app.api_route("/admin", methods=["GET", "POST"])
@app.api_route("/admin/{rest:path}", methods=["GET", "POST"])
async def fake_admin(request: Request, rest: str = ""):
    await _capture(request)
    return Response(
        content="Unauthorized",
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="Admin Panel"'},
        media_type="text/plain",
    )


# ── /wp-admin ─────────────────────────────────────────────────────────────────

@app.api_route("/wp-admin", methods=["GET", "POST"])
@app.api_route("/wp-admin/{rest:path}", methods=["GET", "POST"])
async def fake_wp_admin(request: Request, rest: str = ""):
    await _capture(request)
    show_error = request.method == "POST"
    error_block = '<p id="login_error">ERROR: Invalid username. <a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>' if show_error else ""
    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Log In &#8212; WordPress</title>
<style>
body{{background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}}
#login{{width:320px;margin:80px auto 0;padding:0}}
#login h1 a{{display:block;text-align:center;outline:none;margin-bottom:25px;font-size:20px;color:#3c434a;text-decoration:none}}
.login form{{background:#fff;border:1px solid #c3c4c7;box-shadow:0 1px 3px rgba(0,0,0,.04);padding:26px 24px}}
.login label{{display:block;font-size:14px;font-weight:600;margin-bottom:4px;color:#3c434a}}
.login input[type=text],.login input[type=password]{{width:100%;box-sizing:border-box;padding:6px 8px;font-size:16px;border:1px solid #8c8f94;border-radius:3px;margin-bottom:16px}}
.login .button-primary{{background:#2271b1;color:#fff;border:none;padding:8px 12px;font-size:14px;cursor:pointer;width:100%;border-radius:3px}}
#login_error{{background:#fff;border-left:4px solid #d63638;padding:12px;margin-bottom:16px;font-size:13px;color:#3c434a}}
</style></head>
<body id="login-page"><div id="login">
<h1><a>WordPress</a></h1>
{error_block}
<form name="loginform" method="post">
<label>Username or Email Address<input type="text" name="log" size="20" autocomplete="username"></label>
<label>Password<input type="password" name="pwd" size="20" autocomplete="current-password"></label>
<input type="submit" name="wp-submit" class="button-primary" value="Log In">
</form></div></body></html>"""
    return HTMLResponse(html, status_code=401 if show_error else 200)


@app.api_route("/wp-login.php", methods=["GET", "POST"])
async def fake_wp_login(request: Request):
    return await fake_wp_admin(request)


# ── /phpmyadmin ───────────────────────────────────────────────────────────────

@app.api_route("/phpmyadmin", methods=["GET", "POST"])
@app.api_route("/phpmyadmin/{rest:path}", methods=["GET", "POST"])
@app.api_route("/pma", methods=["GET", "POST"])
@app.api_route("/pma/{rest:path}", methods=["GET", "POST"])
async def fake_pma(request: Request, rest: str = ""):
    await _capture(request)
    show_error = request.method == "POST"
    msg = '<div class="error">Access denied!</div>' if show_error else ""
    html = f"""<!DOCTYPE html><html><head><title>phpMyAdmin</title>
<style>
body{{font-family:sans-serif;background:#fff;margin:0}}
#pma_header{{background:#f5f5f5;border-bottom:1px solid #ccc;padding:8px 16px;font-size:18px;font-weight:bold;color:#555}}
.login-form{{width:340px;margin:60px auto;padding:24px;border:1px solid #ccc;background:#fafafa;border-radius:4px}}
.login-form h3{{margin:0 0 16px;font-size:15px;color:#333}}
.login-form input{{width:100%;padding:7px;box-sizing:border-box;margin-bottom:10px;border:1px solid #bbb;border-radius:3px;font-size:14px}}
.login-form button{{background:#4a6ee0;color:#fff;border:none;padding:8px;width:100%;cursor:pointer;border-radius:3px;font-size:14px}}
.error{{color:#c00;background:#fdd;border:1px solid #faa;padding:8px;margin-bottom:12px;border-radius:3px;font-size:13px}}
</style></head>
<body>
<div id="pma_header">phpMyAdmin</div>
<div class="login-form">
<h3>Welcome to phpMyAdmin</h3>
{msg}
<form method="POST">
<input name="pma_username" placeholder="Username" autocomplete="off">
<input type="password" name="pma_password" placeholder="Password">
<button type="submit">Go</button>
</form></div></body></html>"""
    return HTMLResponse(html, status_code=401 if show_error else 200)


# ── /.env ─────────────────────────────────────────────────────────────────────

@app.api_route("/.env", methods=["GET"])
async def fake_env(request: Request):
    await _capture(request)
    return PlainTextResponse("Forbidden", status_code=403)


# ── /xmlrpc.php ───────────────────────────────────────────────────────────────

@app.api_route("/xmlrpc.php", methods=["GET", "POST"])
async def fake_xmlrpc(request: Request):
    await _capture(request)
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member><name>faultCode</name><value><int>403</int></value></member>
        <member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>
      </struct>
    </value>
  </fault>
</methodResponse>"""
    return Response(content=xml, media_type="application/xml", status_code=200)



# ── block reserved system paths ──────────────────────────────────────────────

@app.api_route("/ingest", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.api_route("/health", methods=["GET"])
async def reserved(request: Request):
    await _capture(request)
    return JSONResponse({"detail": "Not authenticated"}, status_code=401)

# ── catch-all ─────────────────────────────────────────────────────────────────

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def catch_all(request: Request, path: str = ""):
    await _capture(request)
    return JSONResponse({"status": "ok"}, status_code=200)
