import os

from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Load .env explicitly (and before Config reads os.environ below) so values
# are picked up consistently regardless of entry point (python run.py,
# flask run, gunicorn, pytest, ...). Flask's own app.run() also loads
# .env, but only after this module has already been imported and the
# Config class body below has already read os.environ.
load_dotenv(os.path.join(BASE_DIR, ".env"))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'siem.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:5173")

    # Observability
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

    # Schema is managed via `flask db upgrade` (Flask-Migrate) by default.
    # Only auto-create tables from the live models when there's no migration
    # history to apply to (e.g. test databases) — see app/__init__.py.
    AUTO_CREATE_DB = os.environ.get("AUTO_CREATE_DB", "false").lower() == "true"

    # Auth
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-jwt-secret-change-me")
    JWT_EXPIRATION_HOURS = int(os.environ.get("JWT_EXPIRATION_HOURS", "12"))
    REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "true").lower() != "false"

    # Detection tuning
    ENABLE_SCHEDULER = True
    DETECTION_INTERVAL_SECONDS = 30
    FAILED_LOGIN_THRESHOLD = 5          # failed logins
    FAILED_LOGIN_WINDOW_SECONDS = 60    # within this window -> alert
    OFF_HOURS_START = 0                 # 00:00
    OFF_HOURS_END = 5                   # 05:00 local server time

    MAX_CONTENT_LENGTH = 25 * 1024 * 1024  # 25MB upload limit

    # Rate limiting (Flask-Limiter). Storage is in-memory -- fine for this
    # single-process app (same constraint as the Socket.IO async_mode note
    # above); a multi-worker deployment would need RATELIMIT_STORAGE_URI
    # pointed at Redis instead. Limits are per-IP (default key_func).
    RATELIMIT_ENABLED = os.environ.get("RATELIMIT_ENABLED", "true").lower() != "false"
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_LOGIN = os.environ.get("RATELIMIT_LOGIN", "10 per minute")
    RATELIMIT_REGISTER = os.environ.get("RATELIMIT_REGISTER", "5 per minute")
    RATELIMIT_UPLOAD = os.environ.get("RATELIMIT_UPLOAD", "60 per minute")

    # ML anomaly detection (Isolation Forest) tuning
    ML_MODEL_PATH = os.path.join(BASE_DIR, "app", "ml_models", "isolation_forest.joblib")
    ML_BUCKET_SECONDS = 60               # feature vectors are built per source_ip per this window
    ML_TRAINING_LOOKBACK_HOURS = 168     # how far back to pull training data (7 days)
    ML_MIN_TRAINING_SAMPLES = 15         # minimum (ip, bucket) feature rows required to train
    ML_CONTAMINATION = 0.05              # expected proportion of anomalous buckets
    ML_SCORE_LOOKBACK_MINUTES = 15       # how far back to score on each detection pass
    ML_SCORING_ENABLED = True            # scheduler scores automatically once a model exists
    ML_AUTO_RETRAIN_ENABLED = os.environ.get("ML_AUTO_RETRAIN_ENABLED", "true").lower() != "false"
    ML_RETRAIN_INTERVAL_SECONDS = int(os.environ.get("ML_RETRAIN_INTERVAL_SECONDS", str(6 * 60 * 60)))  # every 6h

    # Alert correlation (app/services/correlation.py) tuning
    CORRELATION_TIME_WINDOW_MINUTES = 15   # alerts within this window of each other may correlate
    CORRELATION_SCORE_THRESHOLD = 50       # minimum score (see correlation.py SCORE_*) to attach to an incident
