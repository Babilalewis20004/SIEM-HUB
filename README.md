# SIEM-lite

A minimal Log Analyzer / SIEM built with Flask + React. Ingests logs,
normalises them into a common Event schema, runs rule-based + statistical +
ML anomaly detection, and visualizes alerts/trends on a dashboard. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full pipeline and the
`Log` → `Event` migration rationale.

## Quick Start

Everything runs in Docker — no Python, Node, or database setup needed on
your machine.

**Prerequisites:**
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes
  Docker Compose) installed and running
- Ports `8080`, `5000`, `9090`, and `3000` free on your machine
- ~5 minutes and about 2GB of disk space for images

**Steps:**

1. **Get the code:**
   ```bash
   git clone https://github.com/Babilalewis20004/SIEM-HUB.git
   cd SIEM-HUB/SIEM-APP
   ```

2. **Create the backend's environment file** (a template with safe demo
   defaults — no values need to be changed to try the app out):
   ```bash
   cp backend/.env.example backend/.env
   ```

3. **Build and start everything** (backend API, frontend, Prometheus,
   Grafana). First run takes a few minutes to download images and build;
   later runs are fast:
   ```bash
   docker compose up --build
   ```
   This runs in the foreground and streams logs from every service. Leave
   it running and open a **second terminal** in the same `SIEM-APP` folder
   for the next step. (Prefer one terminal? Run `docker compose up --build -d`
   instead to start in the background, then use `docker compose logs -f` if
   you want to watch the logs.)

4. **Seed sample data** (one-time, in the second terminal — creates a demo
   admin account, default detection rules, and ~3 hours of sample log
   traffic so the dashboard isn't empty):
   ```bash
   docker compose exec backend python seed.py
   ```

5. **Open the app:** go to **http://localhost:8080** in your browser and
   log in with:
   - **Email:** `admin@example.com`
   - **Password:** `changeme123`

   You should land on a dashboard with alerts, event volume charts, and
   MITRE ATT&CK detail already populated from the seeded data. Try the
   **Alerts**, **Log Explorer**, **Incidents**, and **Threat Intel** pages
   from the nav, or trigger a fresh detection pass with
   `POST http://localhost:5000/api/alerts/run-detection`.

6. **When you're done**, stop everything with `Ctrl+C` in the first
   terminal, then:
   ```bash
   docker compose down          # stop containers, keep the seeded data
   docker compose down -v       # stop containers AND delete the data (fresh start next time)
   ```

**Also available once the stack is up:**
- Backend API directly: http://localhost:5000 (e.g. `GET /api/health`)
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000

**If something doesn't come up:** run `docker compose ps` to check
container status, or `docker compose logs backend` (swap in `frontend`,
`prometheus`, etc.) to see what a specific service is doing. A common cause
of failure is one of the ports above already being used by something else
on your machine — stop that other process or edit the port mappings in
`docker-compose.yml`.

See [Running with Docker](#running-with-docker) below for more detail on
what the stack is doing, and the rest of this README for how the
application itself works.

## Structure

```
siem-lite/
├── backend/          Flask API
│   ├── app/
│   │   ├── models/       Event (canonical), Log (deprecated alias), Alert, Rule, User
│   │   ├── parsers/       base.py + ssh.py, nginx.py — format-specific extraction
│   │   ├── routes/       auth, logs, alerts, stats, rules blueprints
│   │   ├── services/
│   │   │   ├── normalization.py   parser output -> normalised Event fields
│   │   │   ├── validation.py      Event field validation before storage
│   │   │   ├── detection.py       rule-based + off-hours heuristic
│   │   │   └── ml_detection.py    Isolation Forest anomaly detection
│   │   └── ml_models/    persisted trained model (isolation_forest.joblib)
│   ├── migrations/    Flask-Migrate/Alembic schema history
│   ├── tests/          pytest suite (models, normalisation, ingestion, detection, ML, API)
│   ├── config.py
│   ├── run.py
│   ├── seed.py        Seeds a default admin user + default rules + sample events
│   └── requirements.txt
└── frontend/          React (Vite)
    └── src/
        ├── api/client.js     Axios wrapper for the backend (attaches JWT, handles 401s)
        ├── context/          AuthContext.jsx — login/register/logout state
        ├── pages/            Login, Dashboard, Alerts, Logs (Log Explorer + event detail)
        └── components/
```

## Auth

JWT-based, implemented in `app/utils/auth.py` + `app/routes/auth.py`.

- `POST /api/auth/register` — `{"email": "...", "password": "..."}` (min 8
  chars). The **first** user to register becomes `role: "admin"`, everyone
  after is `role: "viewer"` (least privilege) — an admin promotes trusted
  accounts to `analyst`/`admin` via `PATCH /api/users/<id>/role`. Role is
  enforced everywhere via a central permission registry
  (`app/auth/permissions.py`) — see `docs/ARCHITECTURE.md`'s RBAC section.
- `POST /api/auth/login` — returns `{"token": "...", "user": {...}}`
- `GET /api/auth/me` — returns the current user for a valid token
- Every other route (`/api/logs/*`, `/api/alerts/*`, `/api/stats/*`,
  `/api/rules/*`, etc.) requires `Authorization: Bearer <token>` — enforced
  via `before_request` on each blueprint in `app/__init__.py`, with
  per-route RBAC permission checks on top
- Tokens expire after `JWT_EXPIRATION_HOURS` (default 12) — no refresh-token
  flow; the frontend just sends the person back to the login screen on a 401
- Set `REQUIRE_AUTH=false` in `.env` to disable auth entirely for local
  testing (e.g. hitting the API directly with curl without a token)
- `/api/auth/login`, `/api/auth/register`, and `/api/logs/upload` are
  rate-limited per-IP (Flask-Limiter — see `RATELIMIT_*` in `config.py`; a
  429 with `{"error": "rate_limit_exceeded"}` means back off). Storage is
  in-memory, so it's single-process only; set `RATELIMIT_ENABLED=false` to
  disable for local testing.

`seed.py` creates a default account: **admin@example.com / changeme123** —
log in with that, then change the password or delete the account and
register your own. Don't ship this default in anything real.

The frontend (`AuthContext.jsx`) stores the token in `localStorage`, attaches
it to every API call via an axios interceptor, and redirects to `/login`
(really: renders the `Login` page in place) whenever a request comes back
401.

## Running with Docker

```bash
cp backend/.env.example backend/.env   # fill in real SECRET_KEY/JWT_SECRET_KEY if you don't have one yet
docker compose up --build
docker compose exec backend python seed.py   # first run only: admin user + sample data
```

- Frontend (nginx-served SPA, reverse-proxying `/api` and `/socket.io` to the
  backend): http://localhost:8080
- Backend API directly: http://localhost:5000
- Prometheus: http://localhost:9090 · Grafana: http://localhost:3000
- `siem.db` and the trained ML model persist in named volumes (`siem-db`,
  `ml-models`) across `docker compose down` (not `-v`)
- The backend container runs migrations (`flask db upgrade`) automatically
  on startup — see `backend/docker-entrypoint.sh`
- `observability/docker-compose.yml` is a separate, lighter stack (just
  Prometheus + Grafana, scraping a backend run directly on the host via
  `python run.py`) for when you don't want the full container stack

Schema is managed by Flask-Migrate (`flask db upgrade`/`flask db migrate`) —
`db.create_all()` is no longer called automatically on startup except for
ephemeral test databases (`AUTO_CREATE_DB=true`, set by the pytest config)
and a fresh Docker volume with no tables yet (`backend/docker-entrypoint.sh`
detects that case and bootstraps the schema from the current models instead
of running the migration chain, which assumes a pre-existing database).

Detection runs automatically every 30s via APScheduler (configurable in
`config.py`), or trigger manually: `POST /api/alerts/run-detection`.

### Running tests

Tests run against a local Python environment, not the Docker image (there's
no test stage in `backend/Dockerfile`):

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pytest
```

## How detection works

Both layers, in `app/services/detection.py`, read normalised `Event`
records only (`source_ip`, `event_type`, `category`, `outcome`,
`timestamp`) — neither has any SSH- or Nginx-specific logic. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full pipeline.

1. **Threshold rules** — stored in the `rules` table, editable via
   `/api/rules`. Example: 5+ `authentication_failure` events from the same
   `source_ip` within 60s → alert. Conditions can filter by `event_type`
   and/or `category`. Add your own via `POST /api/rules`:
   ```json
   {
     "name": "port_scan",
     "rule_type": "threshold",
     "condition": {"category": "web", "count": 30, "window_seconds": 30, "group_by": "source_ip"},
     "severity": "critical"
   }
   ```
2. **Off-hours heuristic** — built-in example flagging authentication
   activity between 00:00–05:00 server time. Swap in a real statistical
   baseline (rolling average per host) as a next step.

## ML anomaly detection (Isolation Forest)

Complements the rule-based engine by catching *unknown* unusual patterns
instead of only known-bad ones. Lives in `app/services/ml_detection.py`.

**Pipeline:**
1. Logs are bucketed by `(source_ip, 60s window)` — configurable via
   `ML_BUCKET_SECONDS`
2. Each bucket becomes a 10-feature vector: event count, distinct event
   types, failed logins, HTTP errors, unique paths/users touched, avg
   response size, off-hours flag, and critical+high / medium+low severity
   counts (`FEATURE_NAMES` in `ml_detection.py`) — computed from `Event`
   fields (`event_type`, `category`, `outcome`, `severity`, `parsed_fields`)
3. `train_model()` fits a `StandardScaler` + `IsolationForest` on historical
   buckets and persists both to `app/ml_models/isolation_forest.joblib`
4. `run_ml_detection_job()` scores recent completed buckets against the
   saved model; outliers become `Alert` rows with `rule_name:
   "ml_isolation_forest"` and the anomaly score + feature values in `context`

**Using it:**
- `python seed.py` seeds ~3 hours of baseline traffic and trains the model
  automatically, so the dashboard has something to score against on first run
- `POST /api/alerts/train-model` — (re)train on the last `ML_TRAINING_LOOKBACK_HOURS`
  of data (optionally pass `{"lookback_hours": N}`)
- `GET /api/alerts/ml-status` — check whether a model exists and when it was trained
- `POST /api/alerts/run-detection` — runs both the rule-based engine and ML
  scoring in one pass; also runs automatically every `DETECTION_INTERVAL_SECONDS`
  once a model exists
- The frontend Alerts page has a "Train Model" panel and tags ML-origin
  alerts with an `ML` badge + anomaly score

**Tuning notes:**
- `ML_CONTAMINATION` (default `0.05`) controls how sensitive the model is —
  lower it if you're seeing too many false positives on small/synthetic
  datasets, raise it if real attacks are being missed
- `ML_MIN_TRAINING_SAMPLES` (default `15`) is a low bar for demo purposes;
  a real deployment wants far more historical buckets before trusting the
  model
- Retraining also happens automatically every `ML_RETRAIN_INTERVAL_SECONDS`
  (default 6h) via APScheduler, on the same rolling
  `ML_TRAINING_LOOKBACK_HOURS` window the manual endpoint uses — set
  `ML_AUTO_RETRAIN_ENABLED=false` to go back to manual-only (the
  endpoint/button always still works either way)

## Ingesting logs

- `POST /api/logs/upload` — multipart file upload (`file` field), one log
  line per row, or JSON: `{"source": "nginx", "host": "web01", "lines": [...]}`
- Pipeline: parse → normalise → validate → store (see
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)). One malformed line never
  fails the whole batch; the response reports
  `{total_lines, parsed, normalised, failed, stored}`.
- Parsers currently understand SSH auth lines (failed + accepted, both
  syslog and ISO timestamps, IPv4/IPv6), Nginx/Apache combined/common access
  log format, Linux firewall (iptables/UFW) LOG lines, Windows Security
  logon events (4624/4625, one JSON object per line), and a generic syslog
  envelope (RFC 3164/5424) that recovers hostname/tag/severity from any
  syslog-wrapped line no more specific parser claims; anything left
  unmatched is stored as `event_type: "unparsed"` so nothing is dropped.
  Add a new format by writing a parser in `app/parsers/` + a normaliser in
  `app/services/normalization.py` — see `docs/ARCHITECTURE.md` for the
  extension pattern, including how `source_hint` (e.g. `source: "apache"`
  on upload) disambiguates formats that are byte-for-byte identical to
  another parser's.
- `GET /api/logs` supports filtering by `source_type`, `event_type`,
  `category`, `severity`, `source_ip`, `destination_ip`, `hostname`,
  `username`, `outcome`, `start`/`end`, and free-text `q`, plus
  `sort`/`order` (severity sorts by actual level, not alphabetically).
- `GET /api/logs/grouped?group_by=<field>` aggregates that same filtered
  set into per-value counts (with max severity and last-seen) — any field
  `GET /api/logs` can filter by. The Log Explorer's "Group by" view uses
  this; clicking a group row drills back into the raw filtered list.
