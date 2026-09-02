# Security

This document summarizes SIEM-HUB's own security posture — authentication,
authorization, transport/config hardening, and the CI gates that enforce all
of it on every push. For pipeline internals (parsing, detection,
correlation) see [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Authentication

JWT access tokens + a rotating, server-side refresh session:

- **Access token**: short-lived (`ACCESS_TOKEN_EXPIRATION_MINUTES`, default
  **15 minutes**), PyJWT-signed, sent as `Authorization: Bearer <token>`.
  The backing `User` row is re-fetched on every request, so disabling an
  account invalidates its still-unexpired token immediately — no separate
  revocation list needed.
- **Refresh token**: long-lived (`REFRESH_TOKEN_EXPIRATION_DAYS`, default
  **7 days**), stored server-side **hashed** (SHA-256 — the raw value is
  never persisted), delivered to the browser only as an **HttpOnly,
  SameSite=Strict** cookie scoped to `/api/auth` (`Secure` in production —
  `REFRESH_COOKIE_SECURE`). Because it's HttpOnly, JavaScript — including an
  XSS payload — can never read it; `document.cookie` never exposes it
  (verified live, see [`ARCHITECTURE.md`](ARCHITECTURE.md)).
- **Rotation + reuse detection**: every refresh consumes the token and
  issues a new one (single-use). Presenting an already-rotated token — only
  possible if a token was copied/replayed — revokes **every** other active
  session for that user, on the assumption that a used-up token being
  presented again means it leaked.
- **Logout** (`POST /api/auth/logout`) does a real server-side revoke, not
  just a client-side token drop.
- First registered user becomes `admin` automatically; everyone after
  starts as `viewer` (least privilege) and is promoted explicitly.

## Authorization (RBAC)

Three roles — `admin`, `analyst`, `viewer` — mapped to permissions in one
place, `app/auth/permissions.py`, and enforced via `@require_permission(...)`
on every route. No handler ever branches on `user.role` directly.

| Capability | admin | analyst | viewer |
|---|:---:|:---:|:---:|
| Read events/alerts/incidents/rules/MITRE/IOCs/playbooks | ✅ | ✅ | ✅ |
| Upload logs, acknowledge/resolve alerts, update/assign/resolve incidents | ✅ | ✅ | ❌ |
| Run detection, execute (or request) playbooks | ✅ | ✅ | ❌ |
| Manage users, rules, IOCs, playbook definitions | ✅ | ❌ | ❌ |
| Train ML model, read audit log, approve high-risk playbook steps | ✅ | ❌ | ❌ |

Additional guardrails in `app/routes/users.py`:
- A user can never change their own role (no self-escalation).
- The last active admin can't be demoted or disabled (no lockout).
- Role/status changes only happen through their own dedicated, whitelisted
  endpoints — never a generic `PATCH /users/<id>` body (no mass assignment).

**Separation of duties on high-risk automation**: a playbook step whose
action is `high`/`critical` risk always requires approval — a playbook
author cannot opt a high-risk action out of that gate by setting
`approval_required: false` server-side. The person who triggered a playbook
run can never approve their own request.

Every security-sensitive mutation (role/status change, alert
acknowledge/resolve, incident lifecycle, rule change, ML training, IOC
change, playbook approval) is written to an append-only `AuditLog` via one
code path (`app/services/audit.py::log_action`) — actor, action, target,
metadata only, **never** passwords, tokens, or secrets.

## Playbook automation is sandboxed by design

`app/playbooks/registry.py` is the *only* place an action name resolves to
code — a static, closed dict. There is no `importlib`/`getattr(module,
user_input)` anywhere in the playbook engine, so a step can never invoke
arbitrary code, only a name the registry already knows with parameters that
action already declared it needs. The four external-effect actions
(`block_ip`, `disable_user`, `kill_process`, `isolate_host`) currently run
through a `MockResponseProvider` that records "would have done X" and never
reaches a real network device, OS, or account — see
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the `ResponseProvider` interface a
real integration would implement.

## Rate limiting

Flask-Limiter, per-IP, in-memory (single-process — see
[`DEPLOYMENT.md`](DEPLOYMENT.md) for the Redis-backed multi-worker note):

| Route | Default limit |
|---|---|
| `POST /api/auth/login` | 10/minute |
| `POST /api/auth/register` | 5/minute |
| `POST /api/auth/refresh` | 30/minute |
| `POST /api/logs/upload` | 60/minute |

## Transport & browser hardening

Both the frontend's production nginx config (`frontend/nginx.conf`) and its
Vite dev/preview server apply the same headers: `Content-Security-Policy`
(script-src/style-src/connect-src all scoped to `'self'`, no inline
scripts), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Cross-Origin-Opener-Policy`/`Cross-Origin-Embedder-Policy`, and a
`Permissions-Policy` disabling geolocation/camera/microphone. nginx also
allow-lists the `Host` header (rejects anything but the deployed hostname
with `444`) and only forwards a WebSocket `Upgrade` when the client asked
for exactly `websocket` — both close off HTTP request-smuggling/host-header
tricks a naive reverse-proxy config would allow through. All inbound
requests pass through Werkzeug's `ProxyFix` so rate limiting and audit
logging see the real client IP, not the proxy's.

## Secrets

- `backend/.env` is git-ignored; `backend/.env.example` ships only
  placeholder values (`change-me-in-production`) that must be replaced with
  real, random secrets before any non-local deployment.
- `SECRET_KEY` and `JWT_SECRET_KEY` are read from the environment
  (`config.py`), never hard-coded.
- **gitleaks** scans every push/PR for anything that looks like a
  credential anyway, as a backstop against an `.env` file being committed
  by mistake.

## CI security gates (`.github/workflows/security.yml`)

Every push and PR to `main`, plus a weekly scheduled run (to catch newly
disclosed CVEs in already-committed dependencies), all **blocking**:

| Check | Tool | Catches |
|---|---|---|
| Secret scanning | gitleaks | Committed credentials/API keys |
| Backend SAST | bandit | Common Python security anti-patterns |
| Backend dependency audit | pip-audit | Known CVEs in pinned Python packages |
| Frontend dependency audit | npm audit (`--audit-level=high`) | Known CVEs in npm packages |
| Static analysis | CodeQL (Python + JavaScript) | Data-flow vulnerabilities (injection, taint) |
| Static analysis | Semgrep (`security-audit`, `owasp-top-ten`, `flask`, `react` rulesets) | OWASP Top 10 patterns |
| Filesystem/config/dependency scan | Trivy | Vulnerable dependencies, IaC misconfig, embedded secrets |
| Dynamic scan | OWASP ZAP baseline | Live HTTP response header/config issues against a running backend |

A handful of specific, individually-justified rule exclusions are
documented inline in `security.yml`/`.zap/rules.tsv` (e.g. a Django-specific
Semgrep rule that doesn't apply to this Flask app, and two nginx rules that
flag the exact pattern this app's `map` directives already use to
*mitigate* the issue they're checking for) — each with a comment explaining
why, not a blanket suppression.

## Known, accepted trade-offs

These are deliberate design decisions for a single-process demo/portfolio
deployment, documented rather than hidden — see
[`ARCHITECTURE.md`](ARCHITECTURE.md) and [`DEPLOYMENT.md`](DEPLOYMENT.md)
for the upgrade path for each:

- **SQLite, single writer** — fine at this scale; Postgres is the
  documented swap for concurrent-write production load.
- **Flask-SocketIO threading async mode** — chosen over eventlet/gevent to
  avoid process-wide monkey-patching; the documented upgrade for
  multi-worker deployments is `message_queue=` backed by Redis.
- **In-memory rate-limit storage** — per-process; a multi-worker deployment
  needs `RATELIMIT_STORAGE_URI` pointed at Redis.
- **Mock response providers** — `block_ip`/`disable_user`/`kill_process`/
  `isolate_host` never touch a real system today; the `ResponseProvider`
  interface exists specifically so a real integration is a new
  implementation, not a rewrite of the playbook engine.
