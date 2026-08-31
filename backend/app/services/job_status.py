"""
In-memory last-run tracking for scheduled jobs -- backs the dashboard's
"is detection running" trust signal (see /stats/summary's
detection_status), not a general observability store (that's
app/utils/job_logging.py + Prometheus; see docs/ARCHITECTURE.md's
Observability section). Deliberately not persisted: a fresh process
hasn't proven a job has run yet, so reading "unknown" until the next
scheduled tick is the correct behavior, not a gap to fill.
"""
import threading
from datetime import datetime, timezone

_lock = threading.Lock()
_last_run = {}  # job_name -> {"at": datetime (tz-aware UTC), "outcome": "success" | "failed"}


def record_run(job_name, outcome):
    # Timezone-aware, unlike the naive datetime.utcnow() used elsewhere in
    # this codebase's models: this timestamp feeds a client-side "Xs ago"
    # countdown (DetectionStatus.jsx), and a naive isoformat() string (no
    # offset) gets parsed as *local* time by JS's Date constructor --
    # inflating or shrinking every delta by the browser's UTC offset.
    with _lock:
        _last_run[job_name] = {"at": datetime.now(timezone.utc), "outcome": outcome}


def all_last_runs():
    with _lock:
        return dict(_last_run)


def reset():
    """Clears state between create_app() calls -- a plain module-level dict
    otherwise leaks across app instances in the same process (e.g. once per
    test), the same reason app/events/bus.py has its own reset()."""
    with _lock:
        _last_run.clear()
