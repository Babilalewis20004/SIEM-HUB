from datetime import datetime

from app import db
from app.models.user import gen_uuid


class RefreshToken(db.Model):
    """A hashed, server-side refresh-token session backing a short-lived JWT
    access token (see app/utils/auth.py). Only the SHA-256 hash of the raw
    token is ever stored -- same principle as password hashing -- so a DB
    read alone can never yield a usable token.

    Rotation: each successful use revokes this row and issues a fresh one
    (replaced_by_id links them), making every refresh token single-use.
    Presenting an already-revoked token again means it was copied/replayed,
    so app/utils/auth.py::rotate_refresh_token responds by revoking every
    other active token for the user.
    """

    __tablename__ = "refresh_tokens"

    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    replaced_by_id = db.Column(db.String(36), db.ForeignKey("refresh_tokens.id"), nullable=True)

    @property
    def is_valid(self) -> bool:
        return self.revoked_at is None and self.expires_at > datetime.utcnow()
