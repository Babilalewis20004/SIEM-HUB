from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_apscheduler import APScheduler
from flask_socketio import SocketIO
from config import Config

db = SQLAlchemy()
migrate = Migrate()
scheduler = APScheduler()
# threading async mode: this app is a single Flask process (no gunicorn/
# multiple workers, no Redis) already running APScheduler on background
# threads -- eventlet/gevent would monkey-patch the whole process for no
# benefit here and has flakier Windows support. If this ever moves behind
# multiple worker processes, Flask-SocketIO's message_queue= (Redis-backed)
# is the documented upgrade path, not a rewrite of this module.
# manage_session=False: this app has no Flask cookie-session (auth is JWT
# only, carried in the connect handshake's `auth` payload -- see
# app/ws/handlers.py), and Flask-SocketIO's session-management code path is
# incompatible with Flask 3.1's read-only RequestContext.session property.
socketio = SocketIO(async_mode="threading", manage_session=False)


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    CORS(app, resources={r"/api/*": {"origins": app.config.get("CORS_ORIGINS", "*")}})
    socketio.init_app(app, cors_allowed_origins=app.config.get("CORS_ORIGINS", "*"))

    # Blueprints
    from app.routes.auth import auth_bp
    from app.routes.logs import logs_bp
    from app.routes.alerts import alerts_bp
    from app.routes.stats import stats_bp
    from app.routes.rules import rules_bp
    from app.routes.users import users_bp
    from app.routes.incidents import incidents_bp
    from app.routes.audit import audit_bp
    from app.routes.iocs import iocs_bp
    from app.routes.mitre import mitre_bp
    from app.routes.playbooks import playbooks_bp, playbook_executions_bp
    from app.utils.auth import require_auth_before_request

    # Every route except /api/auth/* requires a valid JWT. Registered on the
    # app (not the blueprint objects, which are module-level singletons and
    # would blow up on Blueprint.before_request() the second time create_app()
    # runs — e.g. once per test) and filtered by blueprint name instead.
    # Role/permission enforcement on top of this lives in app/auth/ and is
    # applied per-route via @require_permission, not here.
    protected_blueprints = {
        "logs", "alerts", "stats", "rules", "users", "incidents", "audit", "iocs", "mitre",
        "playbooks", "playbook_executions",
    }
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
    app.register_blueprint(iocs_bp, url_prefix="/api/iocs")
    app.register_blueprint(mitre_bp, url_prefix="/api/mitre")
    app.register_blueprint(playbooks_bp, url_prefix="/api/playbooks")
    app.register_blueprint(playbook_executions_bp, url_prefix="/api/playbook-executions")

    # Real-time event bus wiring: bus.reset() first because create_app() can
    # run more than once per process (e.g. once per test), and the bus is a
    # plain module-level dict -- without resetting, a second app instance's
    # handlers would pile up alongside the first's (whose socketio_instance/
    # app have since been torn down).
    from app.events import bus, broadcaster
    from app.ws.handlers import register_handlers
    from app.playbooks.triggers import register_triggers

    bus.reset()
    broadcaster.init_app(socketio)
    register_triggers()
    register_handlers(socketio)

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
