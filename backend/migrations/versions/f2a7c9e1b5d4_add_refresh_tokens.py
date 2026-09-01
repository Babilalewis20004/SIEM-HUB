"""add refresh_tokens table

Purely additive -- backs the new server-side refresh-token session (see
app/models/refresh_token.py and app/utils/auth.py) with a hashed, rotating,
revocable token store. No existing table is touched. See the "secure JWT
architecture" refresh-token milestone for the full design: short-lived JWT
access tokens, long-lived refresh tokens delivered only as an HttpOnly
cookie, single-use rotation, and reuse-detection revocation.

Revision ID: f2a7c9e1b5d4
Revises: d8e3f6a1b4c7
Create Date: 2026-09-01 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = 'f2a7c9e1b5d4'
down_revision = 'd8e3f6a1b4c7'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'refresh_tokens',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('replaced_by_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['replaced_by_id'], ['refresh_tokens.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash'),
    )
    with op.batch_alter_table('refresh_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_refresh_tokens_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_refresh_tokens_token_hash'), ['token_hash'], unique=False)


def downgrade():
    with op.batch_alter_table('refresh_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_refresh_tokens_token_hash'))
        batch_op.drop_index(batch_op.f('ix_refresh_tokens_user_id'))
    op.drop_table('refresh_tokens')
