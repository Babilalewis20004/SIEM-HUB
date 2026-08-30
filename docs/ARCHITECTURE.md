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
