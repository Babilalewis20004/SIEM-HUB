import os
import random
from datetime import datetime, timedelta

from app.models import Event, Alert
from app.services.ml_detection import (
    build_feature_vector,
    train_model,
    run_ml_detection_job,
    get_model_status,
    FEATURE_NAMES,
)


def _web_event(ts, source_ip, status=200):
    is_error = status >= 400
    return Event(
        timestamp=ts,
        event_type="http_error" if is_error else "http_request",
        category="web",
        source_type="nginx",
        source_ip=source_ip,
        destination_port=80,
        hostname="web01",
        action="request",
        outcome="failure" if is_error else "success",
        severity="high" if status >= 500 else ("low" if is_error else "info"),
        raw_message=f"{source_ip} request {status}",
        parsed_fields={"method": "GET", "path": "/x", "status_code": status, "response_bytes": 500},
    )


def test_build_feature_vector_from_events():
    now = datetime(2026, 8, 28, 14, 0, 0)
    events = [
        _web_event(now, "10.0.0.1", 200),
        _web_event(now, "10.0.0.1", 404),
        _web_event(now, "10.0.0.1", 500),
    ]
    vector = build_feature_vector(events)
    assert len(vector) == len(FEATURE_NAMES)
    total, distinct_types, failed_logins, http_errors = vector[0], vector[1], vector[2], vector[3]
    assert total == 3
    assert http_errors == 2
    assert failed_logins == 0


def _seed_baseline(db, hours=3, ips=("10.0.0.1", "10.0.0.2", "10.0.0.3")):
    # Needs real variance (not a constant 1-event-per-bucket) or Isolation
    # Forest has nothing to learn a boundary from — mirrors seed.py's approach.
    rng = random.Random(42)
    now = datetime.utcnow()
    for minute_offset in range(hours * 60, 0, -1):
        ts = now - timedelta(minutes=minute_offset)
        for ip in ips:
            for i in range(rng.randint(1, 4)):
                status = rng.choice([200, 200, 200, 200, 404])
                db.session.add(_web_event(ts + timedelta(seconds=i * 10), ip, status))
    db.session.commit()


def test_train_model_insufficient_data_returns_reason(app, db):
    with app.app_context():
        db.session.add(_web_event(datetime.utcnow(), "10.0.0.1"))
        db.session.commit()

        result = train_model()
        assert result["trained"] is False
        assert "reason" in result


def test_train_model_success_and_status(app, db, tmp_path):
    with app.app_context():
        app.config["ML_MODEL_PATH"] = str(tmp_path / "model.joblib")
        _seed_baseline(db)

        result = train_model()
        assert result["trained"] is True
        assert result["training_samples"] > 0

        status = get_model_status()
        assert status["trained"] is True
        assert status["feature_names"] == FEATURE_NAMES


def test_ml_detection_without_trained_model_noops(app, db, tmp_path):
    with app.app_context():
        app.config["ML_MODEL_PATH"] = str(tmp_path / "does-not-exist.joblib")
        result = run_ml_detection_job()
        assert result["scored"] == 0
        assert result["alerts_created"] == 0
        assert "reason" in result


def test_ml_detection_flags_anomalous_burst(app, db, tmp_path):
    with app.app_context():
        app.config["ML_MODEL_PATH"] = str(tmp_path / "model.joblib")
        app.config["ML_BUCKET_SECONDS"] = 60
        app.config["ML_SCORE_LOOKBACK_MINUTES"] = 240

        _seed_baseline(db)
        train_model()

        # A burst of failed events well outside the learned baseline shape.
        anomaly_bucket_start = datetime.utcnow() - timedelta(minutes=10)
        for i in range(40):
            db.session.add(_web_event(anomaly_bucket_start + timedelta(seconds=i), "203.0.113.99", 500))
        db.session.commit()

        result = run_ml_detection_job()
        assert result["scored"] > 0

        alerts = Alert.query.filter_by(rule_name="ml_isolation_forest").all()
        assert any(a.context.get("group_key") == "203.0.113.99" for a in alerts)


def test_ml_detection_dedups_repeated_runs(app, db, tmp_path):
    with app.app_context():
        app.config["ML_MODEL_PATH"] = str(tmp_path / "model.joblib")
        app.config["ML_BUCKET_SECONDS"] = 60
        app.config["ML_SCORE_LOOKBACK_MINUTES"] = 240

        _seed_baseline(db)
        train_model()

        anomaly_bucket_start = datetime.utcnow() - timedelta(minutes=10)
        for i in range(40):
            db.session.add(_web_event(anomaly_bucket_start + timedelta(seconds=i), "203.0.113.99", 500))
        db.session.commit()

        run_ml_detection_job()
        first_count = Alert.query.filter_by(rule_name="ml_isolation_forest").count()
        run_ml_detection_job()
        second_count = Alert.query.filter_by(rule_name="ml_isolation_forest").count()

        assert first_count > 0
        assert second_count == first_count
