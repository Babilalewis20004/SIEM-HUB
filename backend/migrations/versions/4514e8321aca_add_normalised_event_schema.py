"""add normalised event schema

Migrates the app from the old, semi-normalised `Log` model to the fully
normalised `Event` schema (see app/models/event.py and
docs/ARCHITECTURE.md). `Log` already represented individual parsed log
records, so this is a field-preserving transform rather than a new concept:

    logs.source        -> events.source_type
    logs.host           -> events.hostname
    logs.event_type      -> events.event_type + events.category (split out)
    logs.severity (3-lvl) -> events.severity (5-lvl, recomputed where derivable)
    logs.parsed_fields    -> events.parsed_fields (re-keyed per parser) + events.username
    logs.ingested_at       -> events.created_at
    (new)                   -> events.action, events.outcome, events.destination_port

No row is dropped: every `logs` row becomes exactly one `events` row with the
same `id`, so anything that referenced a log by id (e.g. alerts.log_id) keeps
resolving. `alerts.log_id` is renamed to `alerts.event_id` (data copied,
not just renamed, since SQLite requires a table rebuild either way).

Revision ID: 4514e8321aca
Revises:
Create Date: 2026-08-28 18:23:36.161189

"""
import json
from datetime import datetime

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column

# revision identifiers, used by Alembic.
revision = '4514e8321aca'
down_revision = None
branch_labels = None
depends_on = None


events_table = table(
    'events',
    column('id', sa.String),
    column('timestamp', sa.DateTime),
    column('event_type', sa.String),
    column('category', sa.String),
    column('source_type', sa.String),
    column('source_ip', sa.String),
    column('destination_ip', sa.String),
    column('source_port', sa.Integer),
    column('destination_port', sa.Integer),
    column('username', sa.String),
    column('hostname', sa.String),
    column('action', sa.String),
    column('outcome', sa.String),
    column('severity', sa.String),
    column('raw_message', sa.Text),
    column('parsed_fields', sa.JSON),
    column('source_id', sa.String),
    column('created_at', sa.DateTime),
)

logs_table = table(
    'logs',
    column('id', sa.String),
    column('timestamp', sa.DateTime),
    column('ingested_at', sa.DateTime),
    column('source', sa.String),
    column('host', sa.String),
    column('source_ip', sa.String),
    column('event_type', sa.String),
    column('severity', sa.String),
    column('raw_message', sa.Text),
    column('parsed_fields', sa.JSON),
)


def _parse_dt(value):
    if value is None:
        return datetime.utcnow()
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return datetime.utcnow()


def _parse_json(value):
    if value in (None, ""):
        return {}
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return {}


def _log_to_event(row: dict) -> dict:
    """Best-effort field mapping from an old `logs` row to the new `events` shape."""
    old_event_type = row["event_type"] or "unparsed"
    old_severity = row["severity"] or "info"
    parsed = _parse_json(row["parsed_fields"])
    source = row["source"] or "generic"

    if old_event_type == "login_failed":
        category, action, outcome = "authentication", "login", "failure"
        event_type = "authentication_failure"
    elif old_event_type == "login_success":
        category, action, outcome = "authentication", "login", "success"
        event_type = "authentication_success"
    elif old_event_type == "http_request":
        status = parsed.get("status")
        is_error = isinstance(status, int) and status >= 400
        category, action = "web", "request"
        outcome = "failure" if is_error else "success"
        event_type = "http_error" if is_error else "http_request"
    else:
        category = "authentication" if source == "auth" else ("web" if source == "nginx" else "application")
        action, outcome = None, "unknown"
        event_type = old_event_type

    if category == "web":
        status = parsed.get("status")
        if isinstance(status, int) and status >= 500:
            severity = "high"
        elif isinstance(status, int) and status >= 400:
            severity = "low"
        else:
            severity = "info"
        new_parsed_fields = {
            "method": parsed.get("method"),
            "path": parsed.get("path"),
            "status_code": parsed.get("status"),
            "response_bytes": parsed.get("size"),
        }
        destination_port = 80
        username = None
    elif category == "authentication":
        severity = "medium" if outcome == "failure" else "info"
        new_parsed_fields = {"pid": None, "protocol": None}
        destination_port = 22
        username = parsed.get("user")
    else:
        severity = {"info": "info", "warning": "medium", "critical": "critical"}.get(old_severity, "info")
        new_parsed_fields = parsed
        destination_port = None
        username = parsed.get("user")

    return {
        "id": row["id"],
        "timestamp": _parse_dt(row["timestamp"]),
        "event_type": event_type,
        "category": category,
        "source_type": source,
        "source_ip": row["source_ip"],
        "destination_ip": None,
        "source_port": None,
        "destination_port": destination_port,
        "username": username,
        "hostname": row["host"],
        "action": action,
        "outcome": outcome,
        "severity": severity,
        "raw_message": row["raw_message"],
        "parsed_fields": new_parsed_fields,
        "source_id": None,
        "created_at": _parse_dt(row["ingested_at"]),
    }


def upgrade():
    bind = op.get_bind()

    # 1. Create the new normalised `events` table.
    op.create_table(
        'events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('category', sa.String(length=32), nullable=False),
        sa.Column('source_type', sa.String(length=32), nullable=False),
        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('destination_ip', sa.String(length=45), nullable=True),
        sa.Column('source_port', sa.Integer(), nullable=True),
        sa.Column('destination_port', sa.Integer(), nullable=True),
        sa.Column('username', sa.String(length=255), nullable=True),
        sa.Column('hostname', sa.String(length=128), nullable=True),
        sa.Column('action', sa.String(length=64), nullable=True),
        sa.Column('outcome', sa.String(length=16), nullable=True),
        sa.Column('severity', sa.String(length=16), nullable=True),
        sa.Column('raw_message', sa.Text(), nullable=False),
        sa.Column('parsed_fields', sa.JSON(), nullable=True),
        sa.Column('source_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_events_timestamp'), ['timestamp'], unique=False)
        batch_op.create_index(batch_op.f('ix_events_event_type'), ['event_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_events_category'), ['category'], unique=False)
        batch_op.create_index(batch_op.f('ix_events_source_type'), ['source_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_events_source_ip'), ['source_ip'], unique=False)
        batch_op.create_index(batch_op.f('ix_events_destination_ip'), ['destination_ip'], unique=False)
        batch_op.create_index(batch_op.f('ix_events_username'), ['username'], unique=False)
        batch_op.create_index(batch_op.f('ix_events_hostname'), ['hostname'], unique=False)
        batch_op.create_index(batch_op.f('ix_events_outcome'), ['outcome'], unique=False)
        batch_op.create_index(batch_op.f('ix_events_severity'), ['severity'], unique=False)
        batch_op.create_index(batch_op.f('ix_events_source_id'), ['source_id'], unique=False)

    # 2. Copy every `logs` row into `events` (same id, mapped fields). Nothing is deleted yet.
    rows = bind.execute(sa.select(logs_table)).mappings().all()
    if rows:
        op.bulk_insert(events_table, [_log_to_event(dict(r)) for r in rows])

    # 3. Point alerts at events instead of logs. Two batch passes: the first
    # adds event_id (so both columns briefly coexist and we can copy data
    # between them); the second drops log_id once event_id is populated.
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('event_id', sa.String(length=36), nullable=True))

    bind.execute(sa.text("UPDATE alerts SET event_id = log_id"))

    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.create_foreign_key('fk_alerts_event_id_events', 'events', ['event_id'], ['id'])
        batch_op.drop_column('log_id')

    # 4. Drop the old logs table now every row lives in events.
    with op.batch_alter_table('logs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_logs_event_type'))
        batch_op.drop_index(batch_op.f('ix_logs_host'))
        batch_op.drop_index(batch_op.f('ix_logs_severity'))
        batch_op.drop_index(batch_op.f('ix_logs_source'))
        batch_op.drop_index(batch_op.f('ix_logs_source_ip'))
        batch_op.drop_index(batch_op.f('ix_logs_timestamp'))
    op.drop_table('logs')


def _event_to_log(row: dict) -> dict:
    """Best-effort reverse mapping for downgrade(). Not lossless: event_type
    values that didn't exist pre-Event (e.g. authentication_success) pass
    through as-is rather than being invented backwards."""
    parsed = row["parsed_fields"] or {}
    if row["category"] == "web":
        old_parsed = {
            "method": parsed.get("method"),
            "path": parsed.get("path"),
            "status": parsed.get("status_code"),
            "size": parsed.get("response_bytes"),
        }
    elif row["category"] == "authentication":
        old_parsed = {"user": row["username"]}
    else:
        old_parsed = parsed

    reverse_event_type = {
        "authentication_failure": "login_failed",
        "authentication_success": "login_success",
        "http_request": "http_request",
        "http_error": "http_request",
    }.get(row["event_type"], row["event_type"])

    severity_map = {"critical": "critical", "high": "critical", "medium": "warning", "low": "warning", "info": "info"}

    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "ingested_at": row["created_at"] or row["timestamp"],
        "source": row["source_type"],
        "host": row["hostname"],
        "source_ip": row["source_ip"],
        "event_type": reverse_event_type,
        "severity": severity_map.get(row["severity"], "info"),
        "raw_message": row["raw_message"],
        "parsed_fields": old_parsed,
    }


def downgrade():
    bind = op.get_bind()

    op.create_table(
        'logs',
        sa.Column('id', sa.VARCHAR(length=36), nullable=False),
        sa.Column('timestamp', sa.DATETIME(), nullable=False),
        sa.Column('ingested_at', sa.DATETIME(), nullable=False),
        sa.Column('source', sa.VARCHAR(length=64), nullable=False),
        sa.Column('host', sa.VARCHAR(length=128), nullable=True),
        sa.Column('source_ip', sa.VARCHAR(length=45), nullable=True),
        sa.Column('event_type', sa.VARCHAR(length=64), nullable=True),
        sa.Column('severity', sa.VARCHAR(length=16), nullable=True),
        sa.Column('raw_message', sa.TEXT(), nullable=False),
        sa.Column('parsed_fields', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('logs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_logs_timestamp'), ['timestamp'], unique=False)
        batch_op.create_index(batch_op.f('ix_logs_source_ip'), ['source_ip'], unique=False)
        batch_op.create_index(batch_op.f('ix_logs_source'), ['source'], unique=False)
        batch_op.create_index(batch_op.f('ix_logs_severity'), ['severity'], unique=False)
        batch_op.create_index(batch_op.f('ix_logs_host'), ['host'], unique=False)
        batch_op.create_index(batch_op.f('ix_logs_event_type'), ['event_type'], unique=False)

    rows = bind.execute(sa.select(events_table)).mappings().all()
    if rows:
        op.bulk_insert(logs_table, [_event_to_log(dict(r)) for r in rows])

    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('log_id', sa.VARCHAR(length=36), nullable=True))

    bind.execute(sa.text("UPDATE alerts SET log_id = event_id"))

    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.create_foreign_key('fk_alerts_log_id_logs', 'logs', ['log_id'], ['id'])
        batch_op.drop_column('event_id')

    with op.batch_alter_table('events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_events_source_id'))
        batch_op.drop_index(batch_op.f('ix_events_severity'))
        batch_op.drop_index(batch_op.f('ix_events_outcome'))
        batch_op.drop_index(batch_op.f('ix_events_hostname'))
        batch_op.drop_index(batch_op.f('ix_events_username'))
        batch_op.drop_index(batch_op.f('ix_events_destination_ip'))
        batch_op.drop_index(batch_op.f('ix_events_source_ip'))
        batch_op.drop_index(batch_op.f('ix_events_source_type'))
        batch_op.drop_index(batch_op.f('ix_events_category'))
        batch_op.drop_index(batch_op.f('ix_events_event_type'))
        batch_op.drop_index(batch_op.f('ix_events_timestamp'))
    op.drop_table('events')
