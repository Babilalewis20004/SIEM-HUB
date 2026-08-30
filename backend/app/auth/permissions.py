"""
Central permission registry for RBAC. Roles map to permission sets here and
nowhere else — routes call require_permission(...) (see authorization.py)
instead of ever checking `user.role` directly, so this file is the single
place the admin/analyst/viewer matrix is defined.
"""

ROLES = ("admin", "analyst", "viewer")

# users.read is deliberately granted to analyst as well as admin (not just
# users.manage) so the incident-assignment dropdown can list assignable
# users without giving analysts any ability to change roles/status.
USERS_READ = "users.read"
USERS_MANAGE = "users.manage"

EVENTS_READ = "events.read"
LOGS_UPLOAD = "logs.upload"

ALERTS_READ = "alerts.read"
ALERTS_ACKNOWLEDGE = "alerts.acknowledge"
ALERTS_RESOLVE = "alerts.resolve"

INCIDENTS_READ = "incidents.read"
INCIDENTS_UPDATE = "incidents.update"
INCIDENTS_ASSIGN = "incidents.assign"
INCIDENTS_RESOLVE = "incidents.resolve"

RULES_READ = "rules.read"
RULES_CREATE = "rules.create"
RULES_UPDATE = "rules.update"
RULES_DELETE = "rules.delete"

ML_TRAIN = "ml.train"
DETECTION_RUN = "detection.run"
AUDIT_READ = "audit.read"

MITRE_READ = "mitre.read"
IOCS_READ = "iocs.read"
IOCS_MANAGE = "iocs.manage"  # create/update/delete/import/enable/disable

_ADMIN_PERMISSIONS = {
    USERS_READ, USERS_MANAGE,
    EVENTS_READ, LOGS_UPLOAD,
    ALERTS_READ, ALERTS_ACKNOWLEDGE, ALERTS_RESOLVE,
    INCIDENTS_READ, INCIDENTS_UPDATE, INCIDENTS_ASSIGN, INCIDENTS_RESOLVE,
    RULES_READ, RULES_CREATE, RULES_UPDATE, RULES_DELETE,
    ML_TRAIN, DETECTION_RUN, AUDIT_READ,
    MITRE_READ, IOCS_READ, IOCS_MANAGE,
}

_ANALYST_PERMISSIONS = {
    USERS_READ,
    EVENTS_READ, LOGS_UPLOAD,
    ALERTS_READ, ALERTS_ACKNOWLEDGE, ALERTS_RESOLVE,
    INCIDENTS_READ, INCIDENTS_UPDATE, INCIDENTS_ASSIGN, INCIDENTS_RESOLVE,
    RULES_READ,
    DETECTION_RUN,
    MITRE_READ, IOCS_READ,
}

_VIEWER_PERMISSIONS = {
    EVENTS_READ,
    ALERTS_READ,
    INCIDENTS_READ,
    RULES_READ,
    MITRE_READ, IOCS_READ,
}

ROLE_PERMISSIONS = {
    "admin": _ADMIN_PERMISSIONS,
    "analyst": _ANALYST_PERMISSIONS,
    "viewer": _VIEWER_PERMISSIONS,
}


def permissions_for_role(role: str) -> set:
    return ROLE_PERMISSIONS.get(role, set())


def role_has_permission(role: str, permission: str) -> bool:
    return permission in permissions_for_role(role)
