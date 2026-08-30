"""add IOC / threat intelligence tables (iocs, ioc_matches, threat_intel_sources)

Purely additive: three new tables, no existing table/column touched. IOC
uniqueness is enforced at the DB level via a composite unique constraint on
(indicator_type, normalized_indicator) -- see app/services/ioc_normalization.py
for how normalized_indicator is derived. See docs/ARCHITECTURE.md.

Revision ID: c4d8a1f60e2b
Revises: 9b1e4f7a2c3d
Create Date: 2026-08-30 00:05:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = 'c4d8a1f60e2b'
down_revision = '9b1e4f7a2c3d'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'iocs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('indicator', sa.String(length=512), nullable=False),
        sa.Column('indicator_type', sa.String(length=16), nullable=False),
        sa.Column('normalized_indicator', sa.String(length=512), nullable=False),
        sa.Column('threat_level', sa.String(length=16), nullable=True),
        sa.Column('confidence', sa.Integer(), nullable=True),
        sa.Column('source', sa.String(length=128), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('indicator_type', 'normalized_indicator', name='uq_ioc_type_normalized'),
    )
    with op.batch_alter_table('iocs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_iocs_indicator_type'), ['indicator_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_iocs_normalized_indicator'), ['normalized_indicator'], unique=False)
        batch_op.create_index(batch_op.f('ix_iocs_threat_level'), ['threat_level'], unique=False)
        batch_op.create_index(batch_op.f('ix_iocs_expires_at'), ['expires_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_iocs_enabled'), ['enabled'], unique=False)

    op.create_table(
        'ioc_matches',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('ioc_id', sa.String(length=36), nullable=False),
        sa.Column('event_id', sa.String(length=36), nullable=True),
        sa.Column('alert_id', sa.String(length=36), nullable=True),
        sa.Column('matched_field', sa.String(length=32), nullable=False),
        sa.Column('matched_value', sa.String(length=512), nullable=False),
        sa.Column('confidence', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['ioc_id'], ['iocs.id']),
        sa.ForeignKeyConstraint(['event_id'], ['events.id']),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('ioc_matches', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_ioc_matches_ioc_id'), ['ioc_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_ioc_matches_event_id'), ['event_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_ioc_matches_alert_id'), ['alert_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_ioc_matches_created_at'), ['created_at'], unique=False)

    op.create_table(
        'threat_intel_sources',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('source_type', sa.String(length=32), nullable=False),
        sa.Column('url', sa.String(length=255), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('last_updated_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )


def downgrade():
    op.drop_table('threat_intel_sources')
    with op.batch_alter_table('ioc_matches', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_ioc_matches_created_at'))
        batch_op.drop_index(batch_op.f('ix_ioc_matches_alert_id'))
        batch_op.drop_index(batch_op.f('ix_ioc_matches_event_id'))
        batch_op.drop_index(batch_op.f('ix_ioc_matches_ioc_id'))
    op.drop_table('ioc_matches')
    with op.batch_alter_table('iocs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_iocs_enabled'))
        batch_op.drop_index(batch_op.f('ix_iocs_expires_at'))
        batch_op.drop_index(batch_op.f('ix_iocs_threat_level'))
        batch_op.drop_index(batch_op.f('ix_iocs_normalized_indicator'))
        batch_op.drop_index(batch_op.f('ix_iocs_indicator_type'))
    op.drop_table('iocs')
