# SIEM-lite

A minimal Log Analyzer / SIEM built with Flask + React. Ingests logs, runs
rule-based anomaly detection, and visualizes alerts/trends on a dashboard.

## Structure

```
siem-lite/
├── backend/          Flask API
│   ├── app/
│   │   ├── models/       Log, Alert, Rule, User (SQLAlchemy)
│   │   ├── routes/       auth, logs, alerts, stats, rules blueprints
│   │   ├── services/     detection.py (rule-based) + ml_detection.py (Isolation Forest)
│   │   ├── ml_models/    persisted trained model (isolation_forest.joblib)
│   │   └── utils/        auth.py (JWT) + parsers.py — log line parsers (SSH, nginx, generic)
│   ├── config.py
│   ├── run.py
│   ├── seed.py        Seeds a default admin user + default rules + sample logs
│   └── requirements.txt
└── frontend/          React (Vite)
    └── src/
        ├── api/client.js     Axios wrapper for the backend (attaches JWT, handles 401s)
        ├── context/          AuthContext.jsx — login/register/logout state
        ├── pages/            Login, Dashboard, Alerts, Logs
        └── components/
```

## Auth

JWT-based, implemented in `app/utils/auth.py` + `app/routes/auth.py`.

- `POST /api/auth/register` — `{"email": "...", "password": "..."}` (min 8
  chars). The **first** user to register becomes `role: "admin"`, everyone
  after is `role: "analyst"` (role isn't enforced anywhere yet — it's there
  for you to build permission checks on top of)
- `POST /api/auth/login` — returns `{"token": "...", "user": {...}}`
- `GET /api/auth/me` — returns the current user for a valid token
- Every other route (`/api/logs/*`, `/api/alerts/*`, `/api/stats/*`,
  `/api/rules/*`) requires `Authorization: Bearer <token>` — enforced via
  `before_request` on each blueprint in `app/__init__.py`
- Tokens expire after `JWT_EXPIRATION_HOURS` (default 12) — no refresh-token
  flow; the frontend just sends the person back to the login screen on a 401
- Set `REQUIRE_AUTH=false` in `.env` to disable auth entirely for local
  testing (e.g. hitting the API directly with curl without a token)

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
python seed.py        # creates admin user + default rules + sample data
python run.py          # runs on http://localhost:5000
```

Detection runs automatically every 30s via APScheduler (configurable in
`config.py`), or trigger manually: `POST /api/alerts/run-detection`.

## Frontend setup

```bash
cd frontend
npm install
npm run dev             # runs on http://localhost:5173, proxies /api to :5000
```

## How detection works

Two layers, both in `app/services/detection.py`:

1. **Threshold rules** — stored in the `rules` table, editable via
   `/api/rules`. Example: 5+ `login_failed` events from the same
   `source_ip` within 60s → alert. Add your own via `POST /api/rules`:
   ```json
   {
     "name": "port_scan",
     "rule_type": "threshold",
     "condition": {"event_type": "http_request", "count": 30, "window_seconds": 30, "group_by": "source_ip"},
     "severity": "critical"
   }
   ```
2. **Off-hours heuristic** — built-in example flagging login activity
   between 00:00–05:00 server time. Swap in a real statistical baseline
   (rolling average per host) as a next step.

## ML anomaly detection (Isolation Forest)

Complements the rule-based engine by catching *unknown* unusual patterns
instead of only known-bad ones. Lives in `app/services/ml_detection.py`.

**Pipeline:**
1. Logs are bucketed by `(source_ip, 60s window)` — configurable via
   `ML_BUCKET_SECONDS`
2. Each bucket becomes a 10-feature vector: event count, distinct event
   types, failed logins, HTTP errors, unique paths/users touched, avg
   response size, off-hours flag, critical/warning counts
   (`FEATURE_NAMES` in `ml_detection.py`)
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
- Retraining is manual by design here (via the endpoint/button) — wire it
  into the APScheduler in `app/__init__.py` for automatic periodic retrains

## Ingesting logs

- `POST /api/logs/upload` — multipart file upload (`file` field), one log
  line per row, or JSON: `{"source": "nginx", "host": "web01", "lines": [...]}`
- Parsers currently understand SSH failed-login lines and nginx access log
  format; unmatched lines are stored as `event_type: "unparsed"` so nothing
  is dropped. Add more patterns in `app/utils/parsers.py`.

## Next steps to extend

- Swap SQLite for Postgres in production (`DATABASE_URL`)
- Add a real syslog listener (UDP/TCP) for live ingestion instead of file upload
- WebSocket push for real-time alert updates instead of polling
- Automatic periodic retraining of the Isolation Forest (see ML tuning notes above)
- Richer ML features: per-host baselines instead of global, rolling
  time-of-day baselines, sequence-based features (e.g. request ordering)
- Enforce `role` (admin vs analyst) on sensitive routes — e.g. only admins
  can create/delete detection rules; right now any authenticated user can
- Refresh tokens / shorter-lived access tokens for a production deployment
- Rate limiting on `/api/auth/login` to slow down credential stuffing
