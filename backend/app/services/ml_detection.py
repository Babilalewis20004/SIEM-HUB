"""
ML-based anomaly detection using scikit-learn's Isolation Forest.

Complements the rule-based engine in detection.py: rules catch known bad
patterns (5 failed logins in 60s), Isolation Forest catches *unknown*
unusual patterns by learning what "normal" traffic looks like per source_ip
and flagging feature vectors that don't fit that shape.

Feature engineering reads normalised `Event` records — the ML layer has no
idea whether a bucket's events came from SSH, Nginx, or any future parser.

Pipeline:
1. Bucket events into (source_ip, time_bucket) groups
2. Turn each bucket into a fixed-size numeric feature vector
3. train_model()  -> fits StandardScaler + IsolationForest on historical
   buckets, persists both to disk via joblib
4. run_ml_detection_job() -> scores recent (completed) buckets against the
   saved model; buckets flagged as outliers become Alerts

This is intentionally a from-scratch, dependency-light pipeline (no feature
store, no MLflow) so it's easy to read end-to-end for a portfolio project.
"""
import os
from collections import defaultdict
from datetime import datetime, timedelta
from statistics import mean

import joblib
import numpy as np
from flask import current_app
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app import db
from app.models import Event, Alert
from app.services import correlation

FEATURE_NAMES = [
    "total_events",
    "distinct_event_types",
    "failed_logins",
    "http_errors",
    "unique_paths",
    "unique_users",
    "avg_response_size",
    "is_off_hours",
    "critical_count",
    "warning_count",
]

RULE_NAME = "ml_isolation_forest"

# severity values (see app/models/event.py SEVERITY_LEVELS) rolled up into the
# two coarse buckets the feature vector has historically used.
_CRITICAL_SEVERITIES = ("critical", "high")
_WARNING_SEVERITIES = ("medium", "low")


# ---------- feature engineering ----------

def _bucket_start(ts: datetime, bucket_seconds: int) -> datetime:
    epoch = int(ts.timestamp())
    floored = epoch - (epoch % bucket_seconds)
    return datetime.utcfromtimestamp(floored)


def _group_events_by_bucket(events, bucket_seconds):
    buckets = defaultdict(list)
    for event in events:
        if not event.source_ip:
            continue
        key = (event.source_ip, _bucket_start(event.timestamp, bucket_seconds))
        buckets[key].append(event)
    return buckets


def build_feature_vector(events_in_bucket):
    total = len(events_in_bucket)
    event_types = {e.event_type for e in events_in_bucket}
    failed_logins = sum(1 for e in events_in_bucket if e.event_type == "authentication_failure")

    web_events = [e for e in events_in_bucket if e.category == "web"]
    http_errors = sum(1 for e in web_events if e.outcome == "failure")
    unique_paths = len({(e.parsed_fields or {}).get("path") for e in web_events if e.parsed_fields})
    sizes = [(e.parsed_fields or {}).get("response_bytes", 0) for e in web_events if e.parsed_fields]
    avg_size = mean(sizes) if sizes else 0

    login_events = [e for e in events_in_bucket if e.event_type == "authentication_failure"]
    unique_users = len({e.username for e in login_events if e.username})

    hour = events_in_bucket[0].timestamp.hour
    is_off_hours = 1 if 0 <= hour < 5 else 0

    critical_count = sum(1 for e in events_in_bucket if e.severity in _CRITICAL_SEVERITIES)
    warning_count = sum(1 for e in events_in_bucket if e.severity in _WARNING_SEVERITIES)

    return [
        total, len(event_types), failed_logins, http_errors,
        unique_paths, unique_users, avg_size, is_off_hours,
        critical_count, warning_count,
    ]


# ---------- model persistence ----------

def _model_path():
    return current_app.config["ML_MODEL_PATH"]


def _load_model():
    path = _model_path()
    if not os.path.exists(path):
        return None
    try:
        return joblib.load(path)
    except Exception:
        return None


def get_model_status():
    bundle = _load_model()
    if bundle is None:
        return {"trained": False}
    return {
        "trained": True,
        "trained_at": bundle["trained_at"].isoformat(),
        "training_samples": bundle["n_samples"],
        "feature_names": FEATURE_NAMES,
        "contamination": bundle.get("contamination"),
    }


# ---------- training ----------

def train_model(lookback_hours=None):
    lookback_hours = lookback_hours or current_app.config["ML_TRAINING_LOOKBACK_HOURS"]
    bucket_seconds = current_app.config["ML_BUCKET_SECONDS"]
    min_samples = current_app.config["ML_MIN_TRAINING_SAMPLES"]
    contamination = current_app.config["ML_CONTAMINATION"]

    since = datetime.utcnow() - timedelta(hours=lookback_hours)
    events = Event.query.filter(Event.timestamp >= since).all()
    buckets = _group_events_by_bucket(events, bucket_seconds)

    if len(buckets) < min_samples:
        return {
            "trained": False,
            "reason": (
                f"Not enough activity to train yet: found {len(buckets)} "
                f"(source_ip, {bucket_seconds}s) buckets, need at least {min_samples}. "
                "Ingest more logs (or lower ML_MIN_TRAINING_SAMPLES for a demo) and try again."
            ),
        }

    X = np.array([build_feature_vector(group) for group in buckets.values()])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=150,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X_scaled)

    bundle = {
        "model": model,
        "scaler": scaler,
        "trained_at": datetime.utcnow(),
        "n_samples": len(X),
        "contamination": contamination,
        "feature_names": FEATURE_NAMES,
    }

    os.makedirs(os.path.dirname(_model_path()), exist_ok=True)
    joblib.dump(bundle, _model_path())

    return {"trained": True, "training_samples": len(X), "buckets_used": len(buckets)}


# ---------- scoring ----------

def run_ml_detection_job():
    bundle = _load_model()
    if bundle is None:
        return {"scored": 0, "alerts_created": 0, "reason": "No trained model yet."}

    bucket_seconds = current_app.config["ML_BUCKET_SECONDS"]
    lookback_minutes = current_app.config["ML_SCORE_LOOKBACK_MINUTES"]

    since = datetime.utcnow() - timedelta(minutes=lookback_minutes)
    events = Event.query.filter(Event.timestamp >= since).all()
    buckets = _group_events_by_bucket(events, bucket_seconds)

    scored = 0
    created = 0
    now = datetime.utcnow()

    for (ip, bucket_start), group_events in buckets.items():
        # Skip the bucket that's still filling up — scoring it early invites false positives.
        if bucket_start + timedelta(seconds=bucket_seconds) > now:
            continue

        vector = np.array([build_feature_vector(group_events)])
        vector_scaled = bundle["scaler"].transform(vector)

        prediction = bundle["model"].predict(vector_scaled)[0]      # -1 = anomaly, 1 = normal
        score = float(bundle["model"].decision_function(vector_scaled)[0])  # lower = more anomalous
        scored += 1

        if prediction != -1:
            continue

        bucket_key = bucket_start.isoformat()
        existing = Alert.query.filter(
            Alert.rule_name == RULE_NAME,
            Alert.context["group_key"].as_string() == ip,
            Alert.context["bucket"].as_string() == bucket_key,
        ).first()
        if existing:
            continue

        severity = "critical" if score < -0.15 else "warning"
        alert = Alert(
            event_id=group_events[-1].id,
            rule_name=RULE_NAME,
            title="ML anomaly detected",
            severity=severity,
            description=(
                f"Isolation Forest flagged unusual activity from {ip}: "
                f"{len(group_events)} events in {bucket_seconds}s "
                f"(anomaly score {score:.3f}, lower = more anomalous)"
            ),
            detection_source="ml",
            anomaly_score=round(score, 4),
            context={
                "group_key": ip,
                "bucket": bucket_key,
                "anomaly_score": round(score, 4),
                "features": dict(zip(FEATURE_NAMES, build_feature_vector(group_events))),
            },
        )
        db.session.add(alert)
        db.session.flush()
        correlation.correlate_alert(alert)
        created += 1

    db.session.commit()
    return {"scored": scored, "alerts_created": created}
