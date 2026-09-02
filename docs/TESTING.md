# Testing

## Backend

```bash
cd backend
python3 -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
pytest --cov=app --cov-report=term-missing
```

**Real output from this run**, captured this session against `backend/`
directly (not the Docker image — there's no test stage in
`backend/Dockerfile`):

```
243 passed in 140.62s (0:02:20)
TOTAL   3125 statements   406 missed   87% coverage
```

| Area | Coverage |
|---|---:|
| Models, permissions, event bus, playbook models, health, metrics, correlation, ML detection | 96–100% |
| Auth, RBAC authorization, ingestion routes, incident routes | 84–93% |
| Playbook engine, validators, triggers, action registry | 58–85% (background-thread paths — see note below) |
| `app/routes/audit.py` (read-only audit log listing) | 33% |

What pytest covers: models, log normalization, ingestion (multi-format
parsing), rule-based + ML detection, RBAC/permissions, refresh-token
rotation and reuse detection, MITRE/IOC enrichment, correlation scoring,
the incident state machine, the playbook engine (including approval gates
and idempotency), and every API route's auth/permission enforcement.

**The lower playbook-engine numbers are not neglect — they're partly
structural.** `app/playbooks/engine.py::run()` executes on a real
background thread (`socketio.start_background_task`), and a real bug was
only ever caught by testing that thread directly rather than through the
normal `pytest-flask` request-context fixture (see
[`ARCHITECTURE.md`](ARCHITECTURE.md)'s "Real-time SOC operations +
playbooks" section for the full story — briefly, `log_action()` reading
`request.remote_addr` unconditionally crashed silently on that thread in a
way the autouse test fixture's request context masked). The lesson that
came out of it stands: a green pytest run does not by itself prove a
background-thread code path is correct — anything on
`socketio.start_background_task`/APScheduler touching `request`/`session`
needs either an explicit context guard or a real-thread regression test
(`tests/test_audit.py` has one), not just suite coverage.

## Frontend

**No automated test suite exists yet** — `frontend/package.json` has no
test runner configured. This is a real, current gap, not an oversight
being glossed over. Everything demonstrated in
[`SCENARIOS.md`](SCENARIOS.md) and the [screenshots](screenshots/) was
manually/live-verified end-to-end (real login, real Docker stack, real
detections streaming over the WebSocket) rather than covered by an
automated frontend suite. Adding one (Vitest + React Testing Library
would fit this stack) is the natural next step here.

## What's verified live vs. by pytest

A few real bugs in this project were only ever caught by manually running
the actual stack, not by the pytest suite — documented in
[`ARCHITECTURE.md`](ARCHITECTURE.md) as a deliberate practice, not an
afterthought: the audit-logging-on-a-background-thread bug above, a
WebSocket cookie-path bug (a refresh cookie scoped to `/api/auth/refresh`
that silently never reached `/api/auth/logout`), and two Docker-networking
bugs (`socketio.run()` defaulting to `127.0.0.1`, and `flask db upgrade`
assuming a pre-existing database) that only surfaced running
`docker compose up` against a genuinely empty volume — a clean
`docker compose build` gave no signal about either. `pytest` proves the
logic is correct in isolation; running the real stack is what this project
treats as the actual acceptance test for anything touching background
threads, cookies, or container networking.
