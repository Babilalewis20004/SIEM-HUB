"""
JSON logging setup. Routes every logger -- Flask's own, Werkzeug's request
log, and every module-level `logging.getLogger(__name__)` already scattered
through app/services and app/playbooks -- through one JSON handler on the
root logger, so a log aggregator gets one consistent shape instead of
Python's default plain-text lines. No dependency: stdlib `logging` +
`json` only.
"""
import json
import logging
from datetime import datetime, timezone

# Every attribute a bare LogRecord carries -- anything beyond this set on a
# given record came from a `logger.info(..., extra={...})` call and should
# be surfaced as its own JSON field (e.g. job name, duration_seconds).
_RESERVED_ATTRS = frozenset(vars(logging.LogRecord("", 0, "", 0, "", (), None)).keys())


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        payload.update(
            {k: v for k, v in record.__dict__.items() if k not in _RESERVED_ATTRS}
        )
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        # default=str: a log call must never itself raise because some
        # `extra` value (a datetime, a model instance) isn't JSON-serializable.
        return json.dumps(payload, default=str)


_HANDLER_NAME = "siem-json"


def configure_logging(app):
    root = logging.getLogger()

    # Drop only a handler we previously attached (by name) rather than
    # replacing root.handlers wholesale: create_app() can run more than once
    # per process (e.g. once per test), so this stays idempotent, but a
    # blanket `root.handlers = [...]` would also rip out any handler another
    # party attached to root -- notably pytest's own log-capture handler,
    # which caplog-based tests depend on.
    root.handlers = [h for h in root.handlers if getattr(h, "name", None) != _HANDLER_NAME]

    handler = logging.StreamHandler()
    handler.name = _HANDLER_NAME
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(app.config.get("LOG_LEVEL", "INFO"))
