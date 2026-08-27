from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_apscheduler import APScheduler
from config import Config

db = SQLAlchemy()
scheduler = APScheduler()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": app.config.get("CORS_ORIGINS", "*")}})

    # Blueprints
    from app.routes.auth import auth_bp
    from app.routes.logs import logs_bp
    from app.routes.alerts import alerts_bp
    from app.routes.stats import stats_bp
    from app.routes.rules import rules_bp
    from app.utils.auth import require_auth_before_request

    # Every route except /api/auth/* requires a valid JWT.
    # Must be attached before the blueprints are registered.
    if app.config.get("REQUIRE_AUTH", True):
        logs_bp.before_request(require_auth_before_request)
        alerts_bp.before_request(require_auth_before_request)
        stats_bp.before_request(require_auth_before_request)
        rules_bp.before_request(require_auth_before_request)

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(logs_bp, url_prefix="/api/logs")
    app.register_blueprint(alerts_bp, url_prefix="/api/alerts")
    app.register_blueprint(stats_bp, url_prefix="/api/stats")
    app.register_blueprint(rules_bp, url_prefix="/api/rules")

    # Background anomaly detection scheduler
    if not scheduler.running and app.config.get("ENABLE_SCHEDULER", True):
        scheduler.init_app(app)
        scheduler.start()

        from app.services.detection import run_detection_job
        from app.services.ml_detection import run_ml_detection_job

        @scheduler.task("interval", id="anomaly_detection", seconds=app.config.get("DETECTION_INTERVAL_SECONDS", 30))
        def scheduled_detection():
            with app.app_context():
                run_detection_job()

        if app.config.get("ML_SCORING_ENABLED", True):
            @scheduler.task("interval", id="ml_anomaly_detection", seconds=app.config.get("DETECTION_INTERVAL_SECONDS", 30))
            def scheduled_ml_detection():
                with app.app_context():
                    # No-ops gracefully (returns a "reason") until a model has been trained
                    run_ml_detection_job()

    with app.app_context():
        db.create_all()

    return app
