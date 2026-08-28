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
