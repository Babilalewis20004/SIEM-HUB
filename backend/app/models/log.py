"""
Deprecated alias. `Log` used to be the raw-ish log record model; it has been
migrated into `Event` (app/models/event.py), the normalised security event
schema. Kept only so `from app.models import Log` still resolves for any
external/legacy code — new code should use Event directly.
"""
from app.models.event import Event as Log

__all__ = ["Log"]
