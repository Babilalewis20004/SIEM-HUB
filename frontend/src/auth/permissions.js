// Client-side mirror of backend/app/auth/permissions.py's ROLE_PERMISSIONS.
// This is UX only (hides/disables buttons the API would reject anyway) —
// the Flask API is the authoritative enforcement point, not this file.

const ADMIN_PERMISSIONS = new Set([
  "users.read", "users.manage",
  "events.read", "logs.upload",
  "alerts.read", "alerts.acknowledge", "alerts.resolve",
  "incidents.read", "incidents.update", "incidents.assign", "incidents.resolve",
  "rules.read", "rules.create", "rules.update", "rules.delete",
  "ml.train", "detection.run", "audit.read",
]);

const ANALYST_PERMISSIONS = new Set([
  "users.read",
  "events.read", "logs.upload",
  "alerts.read", "alerts.acknowledge", "alerts.resolve",
  "incidents.read", "incidents.update", "incidents.assign", "incidents.resolve",
  "rules.read",
  "detection.run",
]);

const VIEWER_PERMISSIONS = new Set([
  "events.read",
  "alerts.read",
  "incidents.read",
  "rules.read",
]);

const ROLE_PERMISSIONS = {
  admin: ADMIN_PERMISSIONS,
  analyst: ANALYST_PERMISSIONS,
  viewer: VIEWER_PERMISSIONS,
};

export function roleCan(role, permission) {
  return ROLE_PERMISSIONS[role]?.has(permission) ?? false;
}
