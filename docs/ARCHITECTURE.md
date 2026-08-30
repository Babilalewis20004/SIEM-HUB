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
