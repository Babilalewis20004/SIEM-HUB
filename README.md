# SIEM-lite

A minimal Log Analyzer / SIEM built with Flask + React. Ingests logs,
normalises them into a common Event schema, runs rule-based + statistical +
ML anomaly detection, and visualizes alerts/trends on a dashboard. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full pipeline and the
`Log` → `Event` migration rationale.

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

## Backend setup

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
flask db upgrade        # applies schema migrations (creates/updates events, alerts, etc.)
python seed.py           # creates admin user + default rules + sample events
python run.py             # runs on http://localhost:5000
```

Schema is managed by Flask-Migrate (`flask db upgrade`/`flask db migrate`) —
`db.create_all()` is no longer called automatically on startup except for
ephemeral test databases (`AUTO_CREATE_DB=true`, set by the pytest config).
If you're upgrading an existing pre-Event checkout, back up `siem.db`
first; the migration copies every `logs` row into `events` (same `id`s) and
does not drop any data.

Detection runs automatically every 30s via APScheduler (configurable in
`config.py`), or trigger manually: `POST /api/alerts/run-detection`.

### Running tests

```bash
cd backend
pytest
```

## Frontend setup

```bash
cd frontend
npm install
npm run dev             # runs on http://localhost:5173, proxies /api to :5000
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
  `username`, `outcome`, `start`/`end`, and free-text `q`.

## Next steps to extend

- Add more parsers (a cloud audit log, more Windows EventIDs beyond
  4624/4625) — see `docs/ARCHITECTURE.md` for the extension pattern
- Rate limiting, automatic periodic ML retraining, RBAC, and MITRE/IOC
  enrichment are already implemented — see `docs/ARCHITECTURE.md` and the
  Auth/ML sections above for how to tune or extend any of them
