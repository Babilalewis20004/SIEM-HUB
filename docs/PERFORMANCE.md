# Performance

Real numbers from a real run, not estimates — captured against the actual
`docker compose` stack (nginx → Flask dev server, SQLite, single process)
on one developer laptop. **This is not a production capacity claim.** It's
a demonstration that the detection → correlation → API pipeline holds up
under concurrent load, and an honest look at where it bends first — see
[`DEPLOYMENT.md`](DEPLOYMENT.md) for exactly what changes (Postgres,
gunicorn+eventlet, multi-worker) before this would mean anything at
production scale.

## Methodology

`backend/tests/load/locustfile.py` (Locust, not part of CI/pytest — a
standalone tool) simulates analysts hitting the same endpoints a real
dashboard session calls, weighted toward reads the way real SOC usage is
(many analysts watching, comparatively few log sources actively pushing):

| Endpoint | Weight | What it represents |
|---|---:|---|
| `GET /api/alerts` | 10 | Alerts table, polled/viewed constantly |
| `GET /api/stats/summary` | 8 | Dashboard tiles + charts |
| `GET /api/logs?category=...` | 6 | Log Explorer, filtered |
| `GET /api/incidents` | 3 | Incidents list |
| `POST /api/logs/upload` | 1 | Occasional ingestion |

All simulated users share **one** pre-fetched auth token rather than each
calling `/api/auth/login` — see the run log below for why that specific
choice matters.

```bash
cd backend
pip install -r tests/load/requirements.txt
locust -f tests/load/locustfile.py --host http://localhost:8080 \
  --headless -u 20 -r 5 -t 60s
```

## Run 1: what happens if 20 users *do* each log in independently

The first run had every simulated user call `/api/auth/login` on start, at
20 users ramped over 4 seconds — i.e., 20 login attempts from one IP in a
few seconds. Result: **50.9% failure rate**, entirely
`429 Too Many Requests` on login (`RATELIMIT_LOGIN`, 10/minute) cascading
into `401`s on every downstream request from a user who never got a token.

This is not a bug — it's [`SECURITY.md`](SECURITY.md)'s login rate limit
doing exactly what it's for. It's also not representative of real usage
(analysts don't all authenticate simultaneously from one address), so the
methodology above uses one shared token. Left in here deliberately: a load
test that only reports the happy path would have missed a real, correct
piece of the system's behavior.

## Run 2: read-path throughput (shared token, 20 concurrent users, 60s)

```
Type     Name                    # reqs   # fails |   Avg    Min    Max   Med |  req/s
------------------------------------------------------------------------------------------
GET      /api/alerts                259    0.00%  |   372     42   2065   200 |   4.41
GET      /api/incidents              89    0.00%  |   313     30   1710   190 |   1.51
POST     /api/logs/upload            22    0.00%  |    69     16    519    39 |   0.37
GET      /api/logs?filtered         193    0.00%  |    96     10    935    41 |   3.28
GET      /api/stats/summary         213    0.00%  |   149     18   1178    70 |   3.62
------------------------------------------------------------------------------------------
Aggregated                          776    0.00%  |   227     10   2065    98 |  13.20
```

**Zero failed requests** across 776 requests once the login burst was
removed from the picture — every request the API actually received under
load, it answered correctly.

| Metric | Value |
|---|---:|
| Aggregate throughput | ~13.2 req/s sustained |
| Aggregate p50 latency | 98 ms |
| Aggregate p95 latency | 910 ms |
| Aggregate p99 latency | 1300 ms |
| Error rate | 0.00% |

**`GET /api/alerts` is the slowest endpoint** (372 ms average, up to
2.1s at the tail) — expected, since each alert response embeds its full
`Event`, MITRE mapping, IOC matches, and computed risk score inline (a
deliberate API design choice — see `ARCHITECTURE.md` — so the frontend
never needs N+1 follow-up calls to render one alert row). That
completeness has a real serialization cost under concurrent load, and is
the first place to look if this needed to scale further (e.g. pagination
tuning, or trimming embedded fields from the list view specifically and
keeping them on the detail view).

## Where the numbers would move first in production

Per [`DEPLOYMENT.md`](DEPLOYMENT.md): SQLite is a single writer (log
ingestion and every read compete for the same file lock under real
concurrent load — Postgres removes that entirely), and the Werkzeug dev
server used here is single-threaded per request in a way gunicorn+eventlet
is not. Both are exactly the two swaps `DEPLOYMENT.md` already documents,
not new findings from this test — this test's job was to confirm the
pipeline is correct under load, not to benchmark infrastructure it was
never meant to run on.
