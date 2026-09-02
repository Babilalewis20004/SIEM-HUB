# Deployment

The [Quick Start](../README.md#quick-start) `docker compose up` is tuned for
trying the app locally — SQLite, the Werkzeug dev server, self-signed/no
TLS, permissive cookie settings. This document is what actually changes to
run SIEM-HUB somewhere real. It's a guide, not a live deployment — nothing
described here is currently deployed anywhere.

## What changes for production

| Concern | Local (docker-compose.yml today) | Production |
|---|---|---|
| Database | SQLite file in a named volume | Postgres (`DATABASE_URL=postgresql://...`) |
| App server | Werkzeug dev server (`socketio.run()` in `run.py`) | gunicorn + eventlet worker |
| TLS | None (plain HTTP on :8080) | Terminated at a reverse proxy (nginx/Caddy/load balancer) |
| Secrets | Placeholder values in `.env` | Real, random `SECRET_KEY`/`JWT_SECRET_KEY`, injected via the platform's secret store, never committed |
| Refresh cookie | `REFRESH_COOKIE_SECURE=false` (HTTP dev) | `REFRESH_COOKIE_SECURE=true` (cookie requires HTTPS) |
| Rate limiting | In-memory (`RATELIMIT_STORAGE_URI=memory://`) | Redis (`RATELIMIT_STORAGE_URI=redis://...`) if running more than one worker |
| WebSocket fan-out | Single process, in-memory event bus | Redis-backed `message_queue=` if running more than one worker (see below) |
| CORS | `http://localhost:5173` | Your real frontend origin(s), nothing wider |

### 1. Database: switch to Postgres

Set `DATABASE_URL` to a real Postgres connection string
(`postgresql://user:pass@host:5432/siem`) instead of leaving it unset. The
schema is already managed by Flask-Migrate — `flask db upgrade` applies the
same migration history regardless of backend. No SQLite-specific code exists
in the app layer (see `docs/ARCHITECTURE.md`'s note on why `Alert.event_id`
required a full column rebuild — that was a SQLite constraint, already
worked around; Postgres wouldn't have needed it).

### 2. App server: gunicorn + eventlet

`run.py`'s `socketio.run()` is a development convenience. For production,
run behind gunicorn with an eventlet worker so Flask-SocketIO can serve real
WebSocket upgrades (the dev server's threading-mode limitation described in
`docs/ARCHITECTURE.md` goes away here):

```bash
pip install eventlet gunicorn
gunicorn --worker-class eventlet -w 1 "run:app" --bind 0.0.0.0:5000
```

**Stay at `-w 1`** unless `message_queue=` (below) is also configured —
each gunicorn worker otherwise has its own isolated in-process event bus and
Socket.IO instance, so a client connected to worker A never sees an alert
whose detection ran on worker B.

### 3. Multi-worker fan-out (only if you need more than one process)

Two single-process assumptions need a Redis backend once you scale past one
gunicorn worker:

- **WebSocket broadcast**: `socketio = SocketIO(app, message_queue="redis://<host>:6379/0")`
  in `app/__init__.py` — Flask-SocketIO's built-in, documented way to fan
  events out across processes. `app/events/bus.py`/`app/playbooks/` need no
  changes; they already only talk to the bus, never to `socketio` directly.
- **Rate limiting**: `RATELIMIT_STORAGE_URI=redis://<host>:6379/1` — otherwise
  each worker enforces its own separate limit, effectively multiplying the
  configured threshold by worker count.

### 4. TLS

Terminate TLS at a reverse proxy or load balancer in front of the app (the
shipped `frontend/nginx.conf` proxies `/api` and `/socket.io` to the backend
over plain HTTP inside the Docker network — put a TLS-terminating layer in
front of that nginx, e.g. a managed load balancer, or add a `listen 443 ssl`
server block with a real certificate). Once TLS is in place, set
`REFRESH_COOKIE_SECURE=true` — the refresh cookie is silently dropped by the
browser if this is true without HTTPS actually being in place, and is
sent-in-the-clear-readable-by-network risk if left false with HTTPS
available.

### 5. Secrets

Generate real values — never reuse the `.env.example` placeholders:

```bash
python -c "import secrets; print(secrets.token_hex(32))"   # run twice: SECRET_KEY, JWT_SECRET_KEY
```

Inject via your platform's secret manager (e.g. a cloud provider's secrets
service, Docker/Kubernetes secrets, or a `.env` file that is never
committed and is readable only by the deploying process) — not baked into
an image layer.

## A generic cloud-VM walkthrough

This works on any VPS/cloud VM (a DigitalOcean droplet, an AWS EC2
instance, a Linode, etc.) with Docker installed — it's the same
`docker-compose.yml` already in this repo, just with the production values
above:

1. Provision a VM, install Docker + Docker Compose, open ports 80/443 (and
   restrict 5000/9090/3000 to your own IP or a VPN — they don't need to be
   public).
2. Point a DNS record at the VM's IP.
3. Clone the repo, `cp backend/.env.example backend/.env`, then edit it:
   real `SECRET_KEY`/`JWT_SECRET_KEY`, `DATABASE_URL` pointed at a managed
   Postgres instance (or a Postgres container added to `docker-compose.yml`
   with a persistent volume), `REFRESH_COOKIE_SECURE=true`,
   `CORS_ORIGINS=https://your-domain`.
4. Put a TLS-terminating reverse proxy (e.g. Caddy, or nginx +
   certbot) in front of the stack's port 8080, proxying your domain to it.
5. `docker compose up --build -d`, then run migrations and seed only the
   detection rules/MITRE catalogue (skip `seed.py`'s demo admin
   user/sample traffic in a real deployment — register a real first admin
   account instead, since it's the one that gets `role: admin`
   automatically).
6. Point your monitoring at `GET /api/health` (liveness) and
   `GET /api/health/ready` (readiness, checks the DB) for uptime checks /
   orchestrator health probes.

## What this repo intentionally does not include

No IaC (Terraform/CloudFormation) or Kubernetes manifests are provided —
this is a single-VM-scale application by design (see
[`SECURITY.md`](SECURITY.md)'s "known, accepted trade-offs"), and adding
orchestration for a workload that doesn't need it would be premature
infrastructure for a portfolio project. The upgrade paths above (Postgres,
Redis, multi-worker gunicorn) are exactly the changes that would need to
happen first if that ever became necessary.
