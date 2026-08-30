"""add playbook engine tables, incident tags, and nullable incident_notes.author_id

Purely additive except for two small, backward-compatible relaxations on
existing tables:
  - incidents.tags: new nullable JSON column, existing rows read as [].
  - incident_notes.author_id: NOT NULL -> nullable, so a playbook's
    create_case_note action can write a note with no human author (an
    automatic alert/incident trigger, not a person). Existing rows are
    unaffected (SQLite recreates the table via batch mode; no data changes).

No existing detection/alert/IOC/MITRE/audit table is touched otherwise. See
docs/ARCHITECTURE.md's "Real-Time SOC Operations + Playbooks" section for
the full design (event bus, WebSocket gateway, playbook engine, approval
gates, response providers).

Revision ID: d8e3f6a1b4c7
Revises: c4d8a1f60e2b
Create Date: 2026-08-30 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = 'd8e3f6a1b4c7'
down_revision = 'c4d8a1f60e2b'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('tags', sa.JSON(), nullable=True))

    with op.batch_alter_table('incident_notes', schema=None) as batch_op:
        batch_op.alter_column('author_id', existing_type=sa.String(length=36), nullable=True)

    op.create_table(
        'playbooks',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('trigger_type', sa.String(length=16), nullable=False),
        sa.Column('trigger_condition', sa.JSON(), nullable=True),
        sa.Column('steps', sa.JSON(), nullable=False),
        sa.Column('created_by', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )

    op.create_table(
        'playbook_executions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('playbook_id', sa.String(length=36), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=True),
        sa.Column('alert_id', sa.String(length=36), nullable=True),
        sa.Column('triggered_by', sa.String(length=36), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('mode', sa.String(length=16), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('current_step_index', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['playbook_id'], ['playbooks.id']),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id']),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id']),
        sa.ForeignKeyConstraint(['triggered_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('playbook_executions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_playbook_executions_playbook_id'), ['playbook_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_playbook_executions_incident_id'), ['incident_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_playbook_executions_alert_id'), ['alert_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_playbook_executions_status'), ['status'], unique=False)

    op.create_table(
        'playbook_approvals',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('execution_id', sa.String(length=36), nullable=False),
        sa.Column('step_index', sa.Integer(), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('parameters', sa.JSON(), nullable=True),
        sa.Column('risk_level', sa.String(length=16), nullable=False),
        sa.Column('requested_at', sa.DateTime(), nullable=True),
        sa.Column('requested_by', sa.String(length=36), nullable=True),
        sa.Column('approved_at', sa.DateTime(), nullable=True),
        sa.Column('approved_by', sa.String(length=36), nullable=True),
        sa.Column('rejected_at', sa.DateTime(), nullable=True),
        sa.Column('rejected_by', sa.String(length=36), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.ForeignKeyConstraint(['execution_id'], ['playbook_executions.id']),
        sa.ForeignKeyConstraint(['requested_by'], ['users.id']),
        sa.ForeignKeyConstraint(['approved_by'], ['users.id']),
        sa.ForeignKeyConstraint(['rejected_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('playbook_approvals', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_playbook_approvals_execution_id'), ['execution_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_playbook_approvals_status'), ['status'], unique=False)

    op.create_table(
        'playbook_action_logs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('execution_id', sa.String(length=36), nullable=False),
        sa.Column('step_index', sa.Integer(), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('parameters', sa.JSON(), nullable=True),
        sa.Column('scope_key', sa.String(length=36), nullable=True),
        sa.Column('target', sa.String(length=255), nullable=True),
        sa.Column('risk_level', sa.String(length=16), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('result', sa.JSON(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['execution_id'], ['playbook_executions.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('scope_key', 'action', 'target', name='uq_playbook_action_scope'),
    )
    with op.batch_alter_table('playbook_action_logs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_playbook_action_logs_execution_id'), ['execution_id'], unique=False)


def downgrade():
    with op.batch_alter_table('playbook_action_logs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_playbook_action_logs_execution_id'))
    op.drop_table('playbook_action_logs')

    with op.batch_alter_table('playbook_approvals', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_playbook_approvals_status'))
        batch_op.drop_index(batch_op.f('ix_playbook_approvals_execution_id'))
    op.drop_table('playbook_approvals')

    with op.batch_alter_table('playbook_executions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_playbook_executions_status'))
        batch_op.drop_index(batch_op.f('ix_playbook_executions_alert_id'))
        batch_op.drop_index(batch_op.f('ix_playbook_executions_incident_id'))
        batch_op.drop_index(batch_op.f('ix_playbook_executions_playbook_id'))
    op.drop_table('playbook_executions')

    op.drop_table('playbooks')

    with op.batch_alter_table('incident_notes', schema=None) as batch_op:
        batch_op.alter_column('author_id', existing_type=sa.String(length=36), nullable=False)

    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.drop_column('tags')
