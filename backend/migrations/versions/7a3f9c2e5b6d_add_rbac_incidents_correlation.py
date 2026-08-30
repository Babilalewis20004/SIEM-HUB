"""add RBAC (viewer role, user status), incidents, incident notes, audit log,
and alert/rule enrichment (MITRE metadata, detection_source, incident link)

This is purely additive: no existing table is dropped, no existing column is
removed, and every new column is nullable or has a safe default so existing
users/alerts/rules/events rows keep working unchanged. Pre-existing alerts
get incident_id = NULL (left unassigned — no retroactive correlation run).
See docs/ARCHITECTURE.md for the full RBAC + correlation/incident design.

Revision ID: 7a3f9c2e5b6d
Revises: 4514e8321aca
Create Date: 2026-08-29 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '7a3f9c2e5b6d'
down_revision = '4514e8321aca'
branch_labels = None
depends_on = None


def upgrade():
    # 1. New tables (incidents first: alerts.incident_id and incident_notes
    # both reference it).
    op.create_table(
        'incidents',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=16), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.Column('priority', sa.String(length=16), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(), nullable=True),
        sa.Column('assigned_to', sa.String(length=36), nullable=True),
        sa.Column('created_by', sa.String(length=36), nullable=True),
        sa.Column('resolved_by', sa.String(length=36), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['assigned_to'], ['users.id']),
        sa.ForeignKeyConstraint(['created_by'], ['users.id']),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_incidents_severity'), ['severity'], unique=False)
        batch_op.create_index(batch_op.f('ix_incidents_status'), ['status'], unique=False)
        batch_op.create_index(batch_op.f('ix_incidents_priority'), ['priority'], unique=False)
        batch_op.create_index(batch_op.f('ix_incidents_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_incidents_last_seen_at'), ['last_seen_at'], unique=False)

    op.create_table(
        'incident_notes',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=False),
        sa.Column('author_id', sa.String(length=36), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id']),
        sa.ForeignKeyConstraint(['author_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('incident_notes', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_incident_notes_incident_id'), ['incident_id'], unique=False)

    op.create_table(
        'audit_log',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('actor_id', sa.String(length=36), nullable=True),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('target_type', sa.String(length=32), nullable=False),
        sa.Column('target_id', sa.String(length=64), nullable=True),
        sa.Column('extra', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('audit_log', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_audit_log_action'), ['action'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_log_target_type'), ['target_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_log_target_id'), ['target_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_audit_log_created_at'), ['created_at'], unique=False)

    # 2. users: soft-disable support. Existing rows default to active.
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()))

    # 3. rules: MITRE ATT&CK mapping.
    with op.batch_alter_table('rules', schema=None) as batch_op:
        batch_op.add_column(sa.Column('mitre_tactic', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('mitre_technique', sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column('mitre_subtechnique', sa.String(length=16), nullable=True))

    # 4. alerts: rule FK, richer lifecycle metadata, MITRE copy, incident link.
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('rule_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('title', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('detection_source', sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column('confidence', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('anomaly_score', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('acknowledged_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('acknowledged_by_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('resolved_by_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('mitre_tactic', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('mitre_technique', sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column('mitre_subtechnique', sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column('incident_id', sa.String(length=36), nullable=True))
        batch_op.create_index(batch_op.f('ix_alerts_detection_source'), ['detection_source'], unique=False)
        batch_op.create_index(batch_op.f('ix_alerts_incident_id'), ['incident_id'], unique=False)
        batch_op.create_foreign_key('fk_alerts_rule_id_rules', 'rules', ['rule_id'], ['id'])
        batch_op.create_foreign_key('fk_alerts_ack_by_users', 'users', ['acknowledged_by_id'], ['id'])
        batch_op.create_foreign_key('fk_alerts_resolved_by_users', 'users', ['resolved_by_id'], ['id'])
        batch_op.create_foreign_key('fk_alerts_incident_id_incidents', 'incidents', ['incident_id'], ['id'])


def downgrade():
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.drop_constraint('fk_alerts_incident_id_incidents', type_='foreignkey')
        batch_op.drop_constraint('fk_alerts_resolved_by_users', type_='foreignkey')
        batch_op.drop_constraint('fk_alerts_ack_by_users', type_='foreignkey')
        batch_op.drop_constraint('fk_alerts_rule_id_rules', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_alerts_incident_id'))
        batch_op.drop_index(batch_op.f('ix_alerts_detection_source'))
        batch_op.drop_column('incident_id')
        batch_op.drop_column('mitre_subtechnique')
        batch_op.drop_column('mitre_technique')
        batch_op.drop_column('mitre_tactic')
        batch_op.drop_column('resolved_by_id')
        batch_op.drop_column('acknowledged_by_id')
        batch_op.drop_column('acknowledged_at')
        batch_op.drop_column('anomaly_score')
        batch_op.drop_column('confidence')
        batch_op.drop_column('detection_source')
        batch_op.drop_column('title')
        batch_op.drop_column('rule_id')

    with op.batch_alter_table('rules', schema=None) as batch_op:
        batch_op.drop_column('mitre_subtechnique')
        batch_op.drop_column('mitre_technique')
        batch_op.drop_column('mitre_tactic')

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('is_active')

    op.drop_table('audit_log')
    op.drop_table('incident_notes')
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_incidents_last_seen_at'))
        batch_op.drop_index(batch_op.f('ix_incidents_created_at'))
        batch_op.drop_index(batch_op.f('ix_incidents_priority'))
        batch_op.drop_index(batch_op.f('ix_incidents_status'))
        batch_op.drop_index(batch_op.f('ix_incidents_severity'))
    op.drop_table('incidents')
