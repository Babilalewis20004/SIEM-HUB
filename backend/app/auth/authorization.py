"""
Route-level authorization decorators. These assume `g.current_user` has
already been set by app.utils.auth's require_auth/require_auth_before_request
(authentication) — this module only ever answers "is this already-identified
user allowed to do this", never "who is this user".
"""
from functools import wraps

from flask import g, jsonify

from app.auth.permissions import role_has_permission


def require_permission(*permissions):
    """Allow the request if the current user's role has ANY of the given
    permissions. Use multiple require_permission calls (stacked decorators)
    if a route genuinely needs ALL of several permissions at once."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if user is None:
                return jsonify({"error": "Authentication required."}), 401
            if not any(role_has_permission(user.role, p) for p in permissions):
                return jsonify({"error": "Forbidden: insufficient permissions."}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator
