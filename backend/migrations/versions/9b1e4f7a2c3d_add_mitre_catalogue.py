"""add MITRE ATT&CK technique catalogue and rule/alert mapping tables

Purely additive: three new tables (mitre_techniques, rule_mitre_techniques,
alert_mitre_techniques). No existing table/column is touched -- the
pre-existing flat Rule.mitre_tactic/technique/subtechnique and
Alert.mitre_tactic/technique/subtechnique columns are unaffected and stay
readable. See docs/ARCHITECTURE.md for the enrichment design.

Revision ID: 9b1e4f7a2c3d
Revises: 7a3f9c2e5b6d
Create Date: 2026-08-30 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '9b1e4f7a2c3d'
down_revision = '7a3f9c2e5b6d'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'mitre_techniques',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('technique_id', sa.String(length=16), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('tactic', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('parent_technique_id', sa.String(length=36), nullable=True),
        sa.Column('url', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['parent_technique_id'], ['mitre_techniques.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('mitre_techniques', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_mitre_techniques_technique_id'), ['technique_id'], unique=True)
        batch_op.create_index(batch_op.f('ix_mitre_techniques_tactic'), ['tactic'], unique=False)

    op.create_table(
        'rule_mitre_techniques',
        sa.Column('rule_id', sa.String(length=36), nullable=False),
        sa.Column('technique_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['rule_id'], ['rules.id']),
        sa.ForeignKeyConstraint(['technique_id'], ['mitre_techniques.id']),
        sa.PrimaryKeyConstraint('rule_id', 'technique_id'),
    )

    op.create_table(
        'alert_mitre_techniques',
        sa.Column('alert_id', sa.String(length=36), nullable=False),
        sa.Column('technique_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id']),
        sa.ForeignKeyConstraint(['technique_id'], ['mitre_techniques.id']),
        sa.PrimaryKeyConstraint('alert_id', 'technique_id'),
    )


def downgrade():
    op.drop_table('alert_mitre_techniques')
    op.drop_table('rule_mitre_techniques')
    with op.batch_alter_table('mitre_techniques', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_mitre_techniques_tactic'))
        batch_op.drop_index(batch_op.f('ix_mitre_techniques_technique_id'))
    op.drop_table('mitre_techniques')
