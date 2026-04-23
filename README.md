# Team 1 — Trap (Пастка)

> Production SOC tool delivered at **STEP UP 3! Women's Cyber Defense Workshop** (Kraków, 21–23 April 2026) — part of a 6-team live exercise that built a working Security Operations Center in one day.

## What the team built

Honeypot sensor network — catches attacker interactions on exposed HTTP ports, logs every session, and publishes `telemetry` events to the rest of the SOC.

## Deployed services

| Service | Role |
| --- | --- |
| `soc-app.service` | main ingest + event emitter on port 8000 |
| `soc-honeypot.service` | HTTP honeypot on port 8080 (trap.main:app) |
| `soc-admin.service` | admin dashboard on port 8001 |
| `soc-ioc-sync.service` | polls Scout's `/ioc/bad-ips` to enrich telemetry |
| `soc-publisher.service` | fans out telemetry to Analyst / Scout / Hunter |
| `soc-portal.service` | decoy login/SSO portal pages |

Ran in production on **`wic01.sanctumsec.com`**.

## Repo layout

| Path | What's there |
| --- | --- |
| `main.py` | FastAPI ingest + publish endpoints |
| `trap/` | honeypot app (`uvicorn trap.main:app`) |
| `publisher.py` | outbound telemetry fan-out with retry |
| `ioc_sync.py` | periodic IOC polling from Scout |
| `portal.py` | decoy login/SSO portal endpoints |
| `db.py` | SQLite storage for captures |
| `admin/` | port-8001 admin dashboard |
| `schemas/` | shared event-envelope Pydantic models |

## Running it locally

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
# Admin UI (if present) on port 8001 — see the team's service files
```

Required env vars (set in a local `.env` or `~/.soc_env`):

- `SOC_PROTOCOL_TOKEN` — shared bearer token used between peer SOC tools
- `ADMIN_USER` / `ADMIN_PASS` — admin page HTTP Basic credentials (if this team has an admin UI)

## Protocol implemented

This tool implements the contract defined in **[sanctum-sec/soc-protocol](https://github.com/sanctum-sec/soc-protocol)** — event envelope, bearer-token auth, MITRE ATT&CK tagging, per-port convention (8000 app / 8001 admin).

## Notes from the build day

- 6 systemd units working together — the team split the concerns cleanly
- IOC enrichment loop pulls from Scout every ~60s and tags known-bad source IPs

## Day 3 build plan (archival)

The original build plan that guided the team during the workshop is preserved here:

- 🇬🇧 [`PLAN.en.md`](PLAN.en.md)
- 🇺🇦 [`PLAN.uk.md`](PLAN.uk.md)

The plans include a cross-cutting AI-CTI goals section covering Modules 4–6 of the Day 3 curriculum (AI-augmented CTI, AI-enabled attack patterns, AI social engineering).
