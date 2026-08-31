import json
import logging

from app.logging_config import JsonFormatter, configure_logging


def _make_record(**kwargs):
    defaults = dict(
        name="test.logger", level=logging.INFO, pathname=__file__, lineno=1,
        msg="hello %s", args=("world",), exc_info=None,
    )
    defaults.update(kwargs)
    return logging.LogRecord(**defaults)


def test_json_formatter_basic_fields():
    record = _make_record()
    payload = json.loads(JsonFormatter().format(record))

    assert payload["level"] == "INFO"
    assert payload["logger"] == "test.logger"
    assert payload["message"] == "hello world"
    assert "timestamp" in payload


def test_json_formatter_includes_extra_fields():
    record = _make_record()
    record.job = "anomaly_detection"
    record.duration_seconds = 1.5

    payload = json.loads(JsonFormatter().format(record))
    assert payload["job"] == "anomaly_detection"
    assert payload["duration_seconds"] == 1.5


def test_json_formatter_includes_exception():
    try:
        raise ValueError("boom")
    except ValueError:
        import sys
        record = _make_record(exc_info=sys.exc_info())

    payload = json.loads(JsonFormatter().format(record))
    assert "ValueError: boom" in payload["exception"]


def test_configure_logging_replaces_own_handler_idempotently(app):
    configure_logging(app)
    configure_logging(app)

    root = logging.getLogger()
    json_handlers = [h for h in root.handlers if isinstance(h.formatter, JsonFormatter)]
    assert len(json_handlers) == 1


def test_configure_logging_does_not_remove_other_handlers(app):
    sentinel = logging.NullHandler()
    sentinel.name = "not-ours"
    root = logging.getLogger()
    root.addHandler(sentinel)
    try:
        configure_logging(app)
        assert sentinel in root.handlers
    finally:
        root.removeHandler(sentinel)
