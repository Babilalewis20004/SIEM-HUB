# Architecture: the normalised Event pipeline

## Why normalisation exists

Before this change, `Log` was a single semi-normalised record shape used
directly by the API, the rule engine, and the ML feature extractor — every
consumer had to know parser-specific details (e.g. "nginx status lives in
`parsed_fields['status']`", "SSH's failure field is `event_type ==
'login_failed'`"). Adding a new log source meant touching detection code,
not just adding a parser.

The fix is a strict pipeline with one normalised shape in the middle:

```text
Raw Log Line
      |
      v
   Parser            (app/parsers/*.py)      -- format-specific extraction
      |
      v
Parser-specific dict                          -- SSH's or Nginx's own vocabulary
      |
      v
  Normaliser         (app/services/normalization.py)
      |
      v
Normalised Security Event                     -- app/models/event.py
      |
      v
   Validation         (app/services/validation.py)
      |
      v
  Event (stored)
      |
      v
 Detection Engines     (rule-based + statistical + Isolation Forest)
      |
      v
    Alert              (app/models/alert.py, references Event via event_id)
```

Detection engines, the ML feature extractor, and the API only ever read
`Event` fields. None of them import from `app/parsers/` or know which
parser produced a given event. Adding a new log source (Windows Event,
Apache, syslog, a firewall, a cloud audit log) means:

1. Write a `BaseParser` subclass in `app/parsers/` (format-specific extraction).
2. Write a `normalize_<source>()` function in `app/services/normalization.py`
   that maps the parser's dict into `Event` fields, registered via
   `@normalizer_for("<source_type>")`.
3. Register the parser in `app/parsers/__init__.py`'s `PARSERS` list.

Nothing else changes — no detection code, no ML code, no API routes.

## The Event schema

| Field              | Purpose                                                        |
|---------------------|------------------------------------------------------------------|
| `id`                | UUID primary key                                                |
| `timestamp`         | When the security event actually occurred                       |
| `event_type`        | Specific classification, e.g. `authentication_failure`          |
| `category`          | High-level security category, e.g. `authentication`, `web`      |
| `source_type`       | Origin/log format, e.g. `ssh`, `nginx`, `generic`                |
| `source_ip`         | Originating IP, where available                                 |
| `destination_ip`    | Destination IP, where available                                 |
| `source_port`       | Source port, where available                                    |
| `destination_port`  | Destination port, where available                               |
| `username`          | Associated user, where available                                |
| `hostname`          | Associated host                                                 |
| `action`            | What happened, e.g. `login`, `request`                          |
| `outcome`           | Result: `success`, `failure`, `blocked`, `denied`, `unknown`     |
| `severity`          | Normalised severity: `info`, `low`, `medium`, `high`, `critical` |
| `raw_message`       | Original, unmodified log line                                   |
| `parsed_fields`     | Parser-specific metadata that doesn't belong in the common schema (JSON) |
| `source_id`         | Reserved for a future `LogSource` entity (unused today)         |
| `created_at`        | When the row was inserted (vs. `timestamp`, when it happened)   |

## Decision: `Log` → `Event`, not `Log` → `LogSource`

The pre-existing `Log` model already represented individual parsed log
records (it had `source`, `host`, `source_ip`, `event_type`, `severity`,
`raw_message`, `parsed_fields` — essentially a smaller version of `Event`).
It was not standing in for a log *source* (a feed/connection/agent), so
turning it into `LogSource` would have been a fiction. Instead:

- `Log` was migrated field-for-field into `Event` (see migration
  `4514e8321aca_add_normalised_event_schema.py`) — every row keeps its
  original `id`, so anything that referenced a log by id still resolves.
- `app/models/log.py` now just re-exports `Event` as `Log`
  (`from app.models.event import Event as Log`) so any code still doing
  `from app.models import Log` keeps working. New code should use `Event`.
- `Alert.log_id` was renamed to `Alert.event_id` (data copied across, not
  just renamed, since SQLite requires a table rebuild for either operation).
  `Alert.log_id` survives as a read-only property and a deprecated key in
  `Alert.to_dict()` for anything still reading it.
- `source_id` is a placeholder column for a future `LogSource` entity (e.g.
  "which ingestion feed/agent submitted this"), added now so it doesn't
  require another migration later — nothing populates it yet.

## Ingestion pipeline

`POST /api/logs/upload` (`app/routes/logs.py`) implements:

```text
upload -> detect format -> parse -> normalise -> validate -> store Event
```

One malformed line never fails the whole batch — each line is parsed and
validated independently, and the response reports per-line statistics:

```json
{"total_lines": 1000, "parsed": 972, "normalised": 965, "failed": 28, "stored": 965}
```

- `total_lines` — non-blank lines submitted
- `parsed` — a parser recognised the line's format and extracted fields
  (or no parser recognised it, so it becomes a generic/`unparsed` event —
  nothing is silently dropped just because it's unfamiliar)
- `normalised` — the normalised event passed validation
  (`app/services/validation.py`: required fields present, severity/outcome
  in the controlled vocabulary, IPs and ports well-formed, timestamp valid)
- `failed` — a parser recognised the line's *format* but couldn't parse it
  (malformed), or normalisation produced an invalid event
- `stored` — rows actually committed to the `events` table

## Detection engines

Both `app/services/detection.py` (threshold rules + off-hours heuristic)
and `app/services/ml_detection.py` (Isolation Forest feature engineering)
query `Event` exclusively — `source_ip`, `event_type`, `category`,
`outcome`, `severity`, `parsed_fields`, `timestamp`. Neither has any
SSH- or Nginx-specific logic; a brute-force rule watching
`authentication_failure` events would fire identically whether those events
came from SSH, a future Windows Event Log parser, or anything else that
normalises into `category: "authentication"`.

# Architecture: RBAC + Detection Correlation / Incident model

## RBAC pipeline

```text
User (role: admin | analyst | viewer)
        |
        v
Authentication            app/utils/auth.py — PyJWT, re-fetches the User row
                           on every request (so a disabled account's existing
                           token stops working immediately, no revocation list
                           needed)
        |
        v
Authorization              app/auth/authorization.py — @require_permission(...)
                           on every route; never `if user.role == "admin"`
                           scattered through handlers
        |
        v
Permission                 app/auth/permissions.py — ROLE_PERMISSIONS is the
                           single source of truth mapping each role to a set
                           of permission strings (events.read, alerts.resolve,
                           incidents.assign, rules.delete, ml.train, ...)
        |
        v
API resource                the route body, which only runs once permission
                           has already been confirmed
```

Unauthenticated requests get `401`; authenticated-but-under-permissioned
requests get `403`. The frontend (`frontend/src/context/PermissionContext.jsx`,
built on the same role→permission map) mirrors this to hide/disable controls,
but it is UX only — the Flask API is the sole enforcement point.

User administration (`app/routes/users.py`) additionally guards against:
privilege escalation (a user can never change their own role), locking the
system (the last active admin can't be demoted or disabled), and mass
assignment (role/status changes only ever happen through their own
dedicated, whitelisted endpoints — never via a generic `PATCH /users/<id>`
body).

## Detection → Alert → Correlation → Incident pipeline

```text
Event
  |
  v
Detection            app/services/detection.py (rules, off-hours heuristic)
                      app/services/ml_detection.py (Isolation Forest)
  |
  v
Alert                 app/models/alert.py — detection_source records which
                       layer produced it (rule | statistical | ml); MITRE
                       tactic/technique/subtechnique are copied from the
                       Rule (if any) at creation time
  |
  v
Alert deduplication    unchanged: still per-rule/heuristic, keyed on
                       Alert.context JSON (see detection.py/ml_detection.py)
  |
  v
Correlation Engine     app/services/correlation.py — deterministic, scored,
                       never ML. Called once, right after each Alert is
                       flushed, from the same three call sites that create
                       Alerts (never from a route).
  |
  +-- existing Incident (score >= CORRELATION_SCORE_THRESHOLD) -> attach
  |
  +-- new Incident (otherwise)
  |
  v
Incident               app/models/incident.py — investigation workflow with
                       a status state machine (app/services/incidents.py)
```

Detection, correlation, and the incident workflow are kept as separate
services on purpose (Part N of the milestone spec): detection only ever
produces Alerts, correlation only ever groups Alerts into Incidents, and the
Incident API/state machine is the only thing that models an investigation.

### Correlation scoring

For a new alert's Event compared against each existing alert already in a
candidate Incident (open/investigating/contained only — resolved/closed
incidents are never auto-reopened by a stray matching alert):

| Match                          | Score |
|--------------------------------|------:|
| same `source_ip`               |   +40 |
| same `hostname`                |   +30 |
| same `username`                |   +20 |
| same `category`                |   +10 |
| within `CORRELATION_TIME_WINDOW_MINUTES` (default 15) | +20 |

The best-scoring candidate incident is reused if its score clears
`CORRELATION_SCORE_THRESHOLD` (default 50); otherwise a new Incident is
created. The reasoning is stored on the alert itself
(`alert.context["correlation"]`) so an analyst can see exactly why two
alerts were grouped — no black-box scoring. This is also what prevents
"alert storms" from becoming incident storms: repeated alerts sharing a
source IP/category within the window keep landing in the same incident
instead of each spawning a new one, on top of the pre-existing per-rule
deduplication that already collapses hundreds of raw events into one alert.

### Incident status state machine

```text
open -> investigating -> contained -> resolved -> closed
                 ^______________|         |
                                 (also resolved -> investigating)

closed -> investigating   only via an explicit reopen=true flag on
                           POST /incidents/<id>/status — a silent
                           closed -> anything transition is rejected
```

## Data relationships

```text
User
 |
 +-- Incident.assigned_to / created_by / resolved_by
 +-- IncidentNote.author_id
 +-- AuditLog.actor_id

Event
 |
 +-- Alert.event_id  (one event, many alerts)

Alert
 |
 +-- Alert.incident_id  (one incident, many alerts; one alert, at most one incident)
 +-- Alert.rule_id      (nullable — off-hours/ML alerts have no backing Rule row)

Incident
 |
 +-- alerts       (backref from Alert.incident_id)
 +-- notes        (IncidentNote, cascade-deleted with the incident)
```

Security-sensitive actions (role/status changes, alert acknowledge/resolve,
incident create/assign/status-change/note, rule changes, ML training) are
recorded in `AuditLog` (`app/models/audit_log.py`) via the single write path
`app/services/audit.py::log_action` — actor, action, target, and metadata
only; never passwords, tokens, or other secrets.

# Architecture: MITRE ATT&CK Enrichment + IOC / Threat Intel Correlation

## Enrichment pipeline

```text
Event
 |
 v
Detection (app/services/detection.py, ml_detection.py)
 |
 v
Alert created (flushed, alert.id populated)
 |
 v
app/services/enrichment.py::enrich_and_correlate(alert)
 |
 +--> MITRE enrichment (app/services/mitre_enrichment.py)   -- best-effort
 +--> IOC matching     (app/services/ioc_matching.py)       -- best-effort
 |
 v
Correlation (app/services/correlation.py, unchanged core logic + one new
             "shared IOC" signal)
 |
 v
Incident
```

MITRE enrichment and IOC matching are each wrapped in their own try/except
inside `enrich_and_correlate` — a bug or outage in either can never prevent
the underlying Alert from being created/committed, and correlation always
runs regardless. This is the practical meaning of "enrichment is a
dependency, not a single point of failure" for this project.

**Detection** decides "this behaviour is suspicious" (unchanged).
**MITRE enrichment** decides "does the rule that fired have a documented
ATT&CK mapping" — it copies technique(s) already mapped to the rule; it
never invents a mapping. **IOC matching** decides "does this event's
IP/domain/URL/hash appear in the IOC table" — it's a lookup, not a fetch;
IOCs are never resolved or executed. **Correlation** is unchanged in scope
(same alert -> incident grouping decision), just gains one more signal.

## MITRE catalogue + mapping

`MitreTechnique` (`app/models/mitre.py`) is a small internal catalogue —
only techniques an actual detection maps to are seeded (see `seed.py`), not
the full ATT&CK matrix. `Rule.mitre_techniques` and `Alert.mitre_techniques`
are many-to-many relationships (`rule_mitre_techniques` /
`alert_mitre_techniques` join tables) so a single rule can map to multiple
techniques. The alert-side mapping is copied at enrichment time rather than
read live off the rule, so editing a rule's mapping later never rewrites the
ATT&CK context already recorded on old alerts — the same rationale as the
pre-existing flat `mitre_tactic`/`mitre_technique`/`mitre_subtechnique`
columns on both models, which stay in place for backward compatibility.

Current mapping: `brute_force_ssh` -> `T1110` (Brute Force / Credential
Access). No other existing detection (`http_error_burst`, the off-hours
heuristic, the ML Isolation Forest) has a mapping — none of them are a
clean, justified match for a single ATT&CK technique, and a rule-less alert
(ML/statistical) always enriches to `mitre: []`.

## IOC / threat intelligence

`IOC` (`app/models/ioc.py`) is the normalised, deduplicated indicator table
— uniqueness is `(indicator_type, normalized_indicator)`, enforced by a DB
constraint. `app/services/ioc_normalization.py` is the only place that
decides what "normalized" means per type (IP via `ipaddress`, domain
lower-cased/trailing-dot-stripped, URL scheme+host lower-cased via
`urllib.parse`, hashes lower-cased/length-validated) — every writer (manual
create, CSV/JSON import) goes through it. Domain matching is **exact only**:
a subdomain never matches its parent domain's IOC.

`app/services/ioc_matching.py` extracts candidate indicators from an
Event's `source_ip`/`destination_ip` (always) and `parsed_fields`
domain/url/hash keys (opportunistically — today's SSH/Nginx parsers don't
populate these, so this is forward-compatible, not currently exercised) and
does one bulk `IN (...)` query per indicator type — never one query per
indicator. `IOCMatch` is the evidence trail (which field, which value,
against which IOC, at what confidence) written for both the `Event` and the
`Alert` it's attached to. An IOC's `enabled`/`expires_at` gate future
matches but never delete past `IOCMatch` rows — history is preserved even
after an IOC is disabled, expires, or (if it has no match history) deleted.
`ThreatIntelSource` is a lightweight source registry only; `IOC.source` is a
free-text label so local CSV/JSON import (`POST /api/iocs/import`) never
requires one to exist first, and the matching engine never hard-codes a
provider.

## Risk scoring

`app/services/risk_scoring.py::compute_overall_risk(alert)` combines
`alert.severity` (60%) and the highest `threat_level` among the alert's IOC
matches (40%, only when at least one match exists) into an `overall_risk`
label. This is an explicitly documented, transparent application heuristic
— not a validated model — and it never overwrites `alert.severity` or an
IOC's own `threat_level`; both stay visible alongside it in the API
response's `risk` object.

## Correlation: the new IOC signal

`app/services/correlation.py` gains one additional scored signal on top of
the existing source-IP/hostname/username/category/time-window ones (see
"Correlation scoring" above): if the new alert and a candidate alert share
at least one matched `ioc_id`, that's worth +35 points toward the existing
`CORRELATION_SCORE_THRESHOLD`. It does not replace or lower the bar for the
existing signals, and does not automatically merge every alert that happens
to share an IOC — it's one more input to the same scored, explainable
decision.

## RBAC

Two new permissions: `mitre.read` (all three roles — same tier as
`rules.read`) and `iocs.read`/`iocs.manage` (`iocs.manage` — create, update,
delete, import, enable, disable — is admin-only; analyst and viewer get
`iocs.read`). IOC/MITRE mutations are audited the same way as everything
else — `ioc.created`, `ioc.updated`, `ioc.enabled`, `ioc.disabled`,
`ioc.deleted`, `ioc.imported`, `rule.mitre_mapping_changed`.

# Real-time SOC operations + playbooks

## Why this exists

Every prior milestone was request/response: an analyst had to reload a page
to see a new alert, and there was no automated response beyond detection
itself. This milestone adds two things on top of the unchanged detection ->
enrichment -> correlation -> incident pipeline:

1. **Real-time push** — connected analysts see new alerts/incidents and
   playbook progress without polling (the existing 15s React Query poll
   stays as a fallback, not a replacement).
2. **Playbooks** — declarative, validated automation that can react to an
   alert/incident and run a fixed set of registered actions, with
   high-risk actions gated behind human approval.

No Redis, no Celery, no Kafka: this is still a single Flask process on
SQLite (see the WebSocket section below for exactly why that's sufficient
here, and the specific upgrade path if it stops being sufficient).

## Event bus -> WebSocket architecture

```text
Detection / Correlation / Incident routes / Playbook engine
                    |
                    v
       app/events/bus.py (publish/subscribe, in-process, synchronous)
                    |
                    v
     app/events/broadcaster.py (the only module that imports flask_socketio
                                 outside of app/ws/handlers.py)
                    |
                    v
              socketio.emit(event_type, envelope, room=...)
                    |
                    v
         React RealtimeContext -> useRealtime(eventType, handler)
```

`app/events/bus.py` is a plain module-level `dict[event_type] -> [handlers]`
— no Redis. Detection/correlation/playbook code never imports
`flask_socketio`; it calls `bus.publish(event_type, data)` and moves on.
A subscriber's exception is caught and logged, never propagated — a broken
WebSocket broadcast or playbook trigger can't take down detection. Every
publish is wrapped in a small envelope (`{event_type, timestamp, data}`);
`data` is always a hand-built dict of a few primitive fields, never a raw
`model.to_dict()` — WebSocket messages mean "something changed," REST
remains the source of the full record (Part W's rule).

`create_app()` calls `bus.reset()` before wiring the broadcaster and the
playbook triggers (`app/playbooks/triggers.py`) every time it runs — it can
run more than once per process (once per pytest test), and without
resetting first, a second app instance's handlers would pile up alongside
the first's now-torn-down `socketio`/`app` references.

**WebSocket auth**: `app/ws/handlers.py`'s `connect` handler validates the
JWT passed in Socket.IO's `auth` payload via
`app.utils.auth.user_from_token()` — the exact same check
(`decode_token` -> `User.query.get` -> `is_active`) the REST path's
`get_current_user()` uses, factored out so both enforce identical rules. A
missing/invalid/expired token or a disabled user gets the connection
refused (`return False` from the handler) before it ever joins a room — no
privileged data reaches a socket that failed auth, even momentarily.
Every connect/reject is audited (`websocket.authenticated` /
`websocket.rejected`) through the same `log_action()` every other
security-sensitive mutation uses.

**Rooms**: every authenticated connection joins `"authenticated"`
(everything visible over REST to any role with `*_READ` gets broadcast
here) plus `role:<role>` and `user:<id>` for future narrower targeting.
`app/events/broadcaster.py`'s `ADMIN_ONLY_EVENTS` set
(`user.role_changed`, `user.disabled`, `system.configuration_changed`)
broadcasts to `role:admin` only — WebSocket authentication alone is not
treated as sufficient authorization for these.

**Why threading async mode, not eventlet/gevent**: this app already runs
Flask-APScheduler on background threads in the same process; eventlet/
gevent would monkey-patch the entire process (sockets, threading, SSL) for
no benefit here and has materially flakier Windows support. If this app
is ever deployed behind multiple worker processes (gunicorn `-w N`),
Flask-SocketIO's `message_queue=` (Redis-backed pub/sub across workers) is
the documented upgrade path — a config change, not a rewrite of
`app/events/bus.py` or `app/playbooks/`.

**Known limitation**: Werkzeug's built-in development server (used by
`socketio.run()` for local dev) does not properly complete a raw WebSocket
transport *upgrade* under threading mode — the upgrade attempt logs a
500/`ConnectionError` in `simple_websocket`'s Werkzeug integration.
Socket.IO's transport-negotiation design means this is invisible to a
user: `socket.io-client` (browser or Node) falls back to and stays
reliably on HTTP long-polling, which carries every event correctly — this
was verified live by connecting a real client, forcing polling-only
transport, and confirming `alert.created`/`incident.updated`/every
`playbook.*` event arrived during a real detection run. A production
deployment behind gunicorn+eventlet (or gevent) would support the true
WebSocket upgrade; this is a dev-server-only rough edge, not a design flaw.

## Playbook engine

```text
Alert / Incident created
         |
         v
app/playbooks/triggers.py     -- subscribes to alert.created / incident.created /
                                  incident.status_changed on the bus, matches
                                  enabled Playbooks by trigger_type + trigger_condition
         |
         v
   PlaybookExecution created (status=pending) + committed
         |
         v
app/playbooks/engine.start_execution_async()  -- socketio.start_background_task
         |
         v
app/playbooks/engine.run()    -- opens its OWN app context (the calling thread
                                  has none); walks playbook.steps in order
         |
    for each step:
         |
         +-- condition false?           -> skip silently
         +-- already logged for this   -> audit-only "skipped_duplicate",
         |   (scope, action, target)?      never re-executes (idempotency)
         +-- risk high/critical, or    -> PlaybookApproval row created,
         |   step opts in explicitly?     execution parks at awaiting_approval
         +-- otherwise                 -> action runs, PlaybookActionLog written
```

**Action registry** (`app/playbooks/registry.py`) is the *only* place a
step's `action` string resolves to code — a static
`dict[name] -> ActionSpec(fn, required_parameters, risk_level,
requires_approval, external)`. `app/playbooks/validators.py` rejects any
step naming an action not in this dict, or missing a required parameter,
before a Playbook is ever stored. There is no `importlib`/`getattr(module,
user_input)` anywhere in this package — an attacker (or a careless
playbook author) cannot smuggle arbitrary code through a step, only a
name this file already knows and a parameter dict the target action
already declared it needs.

**Approval floor is server-side, not playbook-side**: `engine._run_step()`
computes `needs_approval = spec.risk_level in ("high", "critical") or
step.get("approval_required")` — a step can opt a low-risk action *into*
approval, but can never opt a high/critical action *out* of it by setting
`approval_required: false`. Separation of duties (a person can never
approve their own request) is enforced in the approve/reject routes
(`app/routes/playbooks.py`), not just by RBAC — `PLAYBOOKS_APPROVE` says
"you may approve," the route additionally checks
`execution.triggered_by != current_user.id`. An automatic (alert/incident)
trigger has `triggered_by = None`, so there's no requester to conflict
with.

**Idempotency**: `playbook_action_logs` has a DB unique constraint on
`(scope_key, action, target)` — `scope_key` is the incident/alert id,
`target` is whichever single parameter makes an action's *effect* unique
(the IP for `block_ip`, the tag for `add_incident_tag`, etc.; actions with
no natural dedup key, like `notify_analyst`, are never deduplicated). The
engine pre-checks for an existing row before running a step (fast path)
and catches the `IntegrityError` if two executions race to insert the same
triple simultaneously (the DB constraint is the authoritative backstop,
not the pre-check). **Known limitation**: because the constraint doesn't
distinguish `status`, a *failed* attempt permanently occupies that triple
— a genuinely failed high-risk action is not auto-retried by design (a
SIEM silently retrying `block_ip` after a failure is its own hazard); a
fresh manual investigation or a new incident tag/note is the intended
path, not blind retry.

**Response providers**: `block_ip` / `disable_user` / `kill_process` /
`isolate_host` are the only actions with `external=True` in the registry
— they never touch `db.session` (so it's safe to run them off the
engine's own thread) and go through `app/playbooks/providers.py`'s
`ResponseProvider` interface, currently only `MockResponseProvider`, which
records a structured "would have done X" result and never reaches a real
network device, OS, or user record. `engine._run_step()` wraps only these
four in a `ThreadPoolExecutor(...).result(timeout=...)` — every other
(local, DB-touching) action runs directly on the engine's own thread/
session, since handing a Flask-SQLAlchemy-session-touching call to a
second thread would hand it a *different*, uncommitted session.

**A real bug this surfaced**: `app/services/audit.py`'s `log_action()`
originally read `request.remote_addr` unconditionally. Every caller that
existed before this milestone (routes, and `app/ws/handlers.py`'s
connect/disconnect handlers — Flask-SocketIO pushes a request context per
event) had one. `engine.run()`'s background thread does not — only an app
context. The result in production was silent: the exception propagated
out of the bare background thread, uncaught, leaving the
`PlaybookExecution` stuck at `status="running"` forever with no logged
error. `pytest-flask`'s autouse `_push_request_context` fixture pushes a
request context onto the *main test thread* for every test, which is
exactly why the pre-existing test suite never caught this — the fix
(`ip_address=request.remote_addr if has_request_context() else None`) and
a regression test that reproduces the bug from a real background thread
(bypassing that autouse fixture) are in `tests/test_audit.py`. This is the
canonical reason this milestone's manual/live verification (Part Z) is not
optional: it found a bug the unit test suite structurally could not.

## RBAC (playbooks)

Four new permissions: `playbooks.read` (all roles), `playbooks.manage`
(create/edit/delete playbook definitions — admin only),
`playbooks.execute` (run a low-risk playbook, or request a high-risk one —
admin + analyst), `playbooks.approve` (admin only, subject to the
separation-of-duties check above). `PLAYBOOKS_MANAGE` and
`PLAYBOOKS_EXECUTE` are deliberately separate so a policy change to one
can never silently grant the other.

## Default playbooks

Seeded by `seed.py` (same idempotent "insert if the name doesn't already
exist" pattern as its rules/MITRE/IOC seeding): *SSH Brute Force Response*
(alert-triggered on `rule_name == brute_force_ssh`; tag + note + notify,
no external action), *Malicious IOC Investigation* (alert-triggered on
`ioc_match == true`; tag + note + notify + a `block_ip` step that always
parks for approval), *Critical Incident Notification*
(incident-triggered on `severity == critical`; notify + note).
