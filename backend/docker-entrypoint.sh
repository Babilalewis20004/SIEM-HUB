#!/bin/sh
set -e

# migrations/versions/4514e8321aca_*.py (the base migration) transforms a
# pre-existing `logs` table into the new `events` schema -- it never creates
# `alerts`/`users`/`rules`/etc. itself, since it was written to migrate an
# already-populated pre-Event dev database, not to bootstrap one from
# nothing. A brand new volume (first `docker compose up`) has no tables at
# all, so `flask db upgrade` would fail looking for a `logs` table that was
# never there. Detect that case and create the schema from the current
# models instead (the same AUTO_CREATE_DB path tests already use -- see
# config.py), then stamp the migration history as up to date so any
# *future* `flask db upgrade` (new migrations added later) applies cleanly
# on top. A database that already has tables (a real prior install) always
# goes through the normal migration path unchanged.
STATE=$(python -c "
import sqlalchemy as sa
from config import Config
engine = sa.create_engine(Config.SQLALCHEMY_DATABASE_URI)
print('empty' if not sa.inspect(engine).get_table_names() else 'existing')
")

if [ "$STATE" = "empty" ]; then
    echo "Fresh database -- creating schema from current models..."
    python -c "
from app import create_app, db
app = create_app()
with app.app_context():
    db.create_all()
"
    flask db stamp head
else
    echo "Applying database migrations..."
    flask db upgrade
fi

echo "Starting SIEM-HUB backend..."
exec python run.py
