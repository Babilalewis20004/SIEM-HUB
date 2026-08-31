"""
Start/end/duration/outcome logging for background work that has no other
supervisor -- a scheduled detection pass, a playbook run on its own thread.
APScheduler logs a job's own exception via `apscheduler.executors.default`,
but gives no start/duration signal for a successful run, and a playbook
execution (a bare `socketio.start_background_task`) has no equivalent at
all -- an uncaught exception there just dies on the thread with nothing but
Python's default `threading.excepthook` to notice.
"""
import logging
import time
from contextlib import contextmanager

logger = logging.getLogger("siem.jobs")


@contextmanager
def logged_job(job_name):
    start = time.monotonic()
    logger.info("job started", extra={"job": job_name})
    try:
        yield
    except Exception:
        logger.exception(
            "job failed",
            extra={"job": job_name, "duration_seconds": round(time.monotonic() - start, 3)},
        )
        raise
    else:
        logger.info(
            "job completed",
            extra={"job": job_name, "duration_seconds": round(time.monotonic() - start, 3)},
        )
