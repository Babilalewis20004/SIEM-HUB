import logging

import pytest

from app.utils.job_logging import logged_job


def test_logged_job_logs_start_and_completion(caplog):
    with caplog.at_level(logging.INFO, logger="siem.jobs"):
        with logged_job("test_job"):
            pass

    messages = [r.message for r in caplog.records]
    assert "job started" in messages
    assert "job completed" in messages
    completed = next(r for r in caplog.records if r.message == "job completed")
    assert completed.job == "test_job"
    assert isinstance(completed.duration_seconds, float)


def test_logged_job_logs_failure_and_reraises(caplog):
    with caplog.at_level(logging.INFO, logger="siem.jobs"):
        with pytest.raises(RuntimeError, match="boom"):
            with logged_job("test_job"):
                raise RuntimeError("boom")

    failed = next(r for r in caplog.records if r.message == "job failed")
    assert failed.job == "test_job"
    assert failed.levelname == "ERROR"
