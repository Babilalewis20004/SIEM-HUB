from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_apscheduler import APScheduler
from config import Config

db = SQLAlchemy()
migrate = Migrate()
scheduler = APScheduler()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    CORS(app, resources={r"/api/*": {"origins": app.config.get("CORS_ORIGINS", "*")}})

    # Blueprints
    from app.routes.auth import auth_bp
    from app.routes.logs import logs_bp
    from app.routes.alerts import alerts_bp
    from app.routes.stats import stats_bp
    from app.routes.rules import rules_bp
    from app.routes.users import users_bp
    from app.routes.incidents import incidents_bp
    from app.routes.audit import audit_bp
    from app.utils.auth import require_auth_before_request

    # Every route except /api/auth/* requires a valid JWT. Registered on the
    # app (not the blueprint objects, which are module-level singletons and
    # would blow up on Blueprint.before_request() the second time create_app()
    # runs — e.g. once per test) and filtered by blueprint name instead.
    # Role/permission enforcement on top of this lives in app/auth/ and is
    # applied per-route via @require_permission, not here.
    protected_blueprints = {"logs", "alerts", "stats", "rules", "users", "incidents", "audit"}
    if app.config.get("REQUIRE_AUTH", True):
        @app.before_request
        def _enforce_auth():
            if request.blueprint in protected_blueprints:
                return require_auth_before_request()

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(logs_bp, url_prefix="/api/logs")
    app.register_blueprint(alerts_bp, url_prefix="/api/alerts")
    app.register_blueprint(stats_bp, url_prefix="/api/stats")
    app.register_blueprint(rules_bp, url_prefix="/api/rules")
    app.register_blueprint(users_bp, url_prefix="/api/users")
    app.register_blueprint(incidents_bp, url_prefix="/api/incidents")
    app.register_blueprint(audit_bp, url_prefix="/api/audit-log")

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

    # Schema is managed by Flask-Migrate (`flask db upgrade`) now that the
    # normalised Event schema exists — see docs/ARCHITECTURE.md. The one
    # exception is ephemeral test/in-memory databases, which have no
    # migration history to apply and just need the current model schema.
    if app.config.get("AUTO_CREATE_DB", False):
        with app.app_context():
            db.create_all()

    return app
