import time

from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_apscheduler import APScheduler
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
from config import Config

from app.logging_config import configure_logging

db = SQLAlchemy()
migrate = Migrate()
scheduler = APScheduler()
# Per-IP by default (get_remote_address) -- applied selectively via
# @limiter.limit(...) on individual routes (auth, log upload), not globally.
limiter = Limiter(key_func=get_remote_address)
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
    configure_logging(app)

    db.init_app(app)
    migrate.init_app(app, db)
    # supports_credentials so the browser sends/accepts the refresh-token
    # cookie (app/routes/auth.py) -- requires an explicit origin below, not
    # "*", which CORS_ORIGINS already defaults to.
    CORS(app, resources={r"/api/*": {"origins": app.config.get("CORS_ORIGINS", "*")}}, supports_credentials=True)
    socketio.init_app(app, cors_allowed_origins=app.config.get("CORS_ORIGINS", "*"))
    limiter.init_app(app)
    # In-memory storage lives on the Limiter singleton, not per-app -- reset
    # it here for the same reason as bus.reset()/job_status.reset() below:
    # create_app() can run more than once per process (once per test).
    limiter.reset()

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
    from app.routes.health import health_bp
    from app.routes.metrics import metrics_bp
    from app.utils.auth import require_auth_before_request

    # HTTP metrics: registered before the auth gate below so the timer starts
    # (and every response, including 401s, gets counted) regardless of
    # whether a later before_request short-circuits the request. Labeled by
    # request.url_rule.rule (the route pattern, e.g. "/api/alerts/<id>")
    # rather than request.path, which would give every distinct alert/
    # incident/user id its own label series — unbounded cardinality is the
    # classic way to make a Prometheus instance fall over.
    from app.services.metrics import http_requests_total, http_request_duration_seconds

    @app.before_request
    def _metrics_start_timer():
        request._metrics_start = time.monotonic()

    @app.after_request
    def _metrics_record(response):
        path = request.url_rule.rule if request.url_rule else "unmatched"
        duration = time.monotonic() - request._metrics_start
        http_request_duration_seconds.labels(request.method, path).observe(duration)
        http_requests_total.labels(request.method, path, response.status_code).inc()
        return response

    # Baseline hardening headers -- this is a JSON API with no HTML templates
    # of its own, but the browser still applies these to error pages, the
    # /api/health response, etc., and their absence is what a DAST scan
    # (see .github/workflows/security.yml) flags first.
    @app.after_request
    def _security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # base-uri/form-action don't fall back to default-src per the CSP
        # spec, so 'none' there alone still leaves them unset.
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        # Pure JSON API -- nothing here is meant to be cached.
        response.headers["Cache-Control"] = "no-store"
        return response

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

    # Catch-all so an unhandled exception is always logged (with traceback)
    # and always returns valid JSON instead of leaking a stack trace to the
    # client — Flask calls a registered handler for Exception regardless of
    # debug mode, so without the app.debug branch below this would also
    # swallow Werkzeug's interactive debugger locally. HTTPException (404s,
    # the 401s from require_auth_before_request, etc.) is passed through
    # unchanged; those already have the right status code and shape.
    @app.errorhandler(429)
    def _handle_rate_limit_exceeded(exc):
        return jsonify({"error": "rate_limit_exceeded", "message": str(exc.description)}), 429

    @app.errorhandler(Exception)
    def _handle_unhandled_exception(exc):
        if isinstance(exc, HTTPException):
            return exc
        app.logger.exception("Unhandled exception on %s %s", request.method, request.path)
        if app.debug:
            raise exc
        return jsonify({"error": "internal_server_error"}), 500

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(health_bp, url_prefix="/api")
    app.register_blueprint(metrics_bp, url_prefix="/api")
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
    from app.services import job_status

    bus.reset()
    job_status.reset()
    broadcaster.init_app(socketio)
    register_triggers()
    register_handlers(socketio)

    # Background anomaly detection scheduler
    if not scheduler.running and app.config.get("ENABLE_SCHEDULER", True):
        scheduler.init_app(app)
        scheduler.start()

        from app.services.detection import run_detection_job
        from app.services.ml_detection import run_ml_detection_job
        from app.utils.job_logging import logged_job
        from app.services.metrics import detection_job_runs_total, detection_job_duration_seconds
        from app.services import job_status

        def _run_scheduled_job(job_name, job_fn):
            start = time.monotonic()
            outcome = "success"
            try:
                with logged_job(job_name):
                    with app.app_context():
                        job_fn()
            except Exception:
                outcome = "failed"
                raise
            finally:
                detection_job_duration_seconds.labels(job_name).observe(time.monotonic() - start)
                detection_job_runs_total.labels(job_name, outcome).inc()
                job_status.record_run(job_name, outcome)

        @scheduler.task("interval", id="anomaly_detection", seconds=app.config.get("DETECTION_INTERVAL_SECONDS", 30))
        def scheduled_detection():
            _run_scheduled_job("anomaly_detection", run_detection_job)

        if app.config.get("ML_SCORING_ENABLED", True):
            @scheduler.task("interval", id="ml_anomaly_detection", seconds=app.config.get("DETECTION_INTERVAL_SECONDS", 30))
            def scheduled_ml_detection():
                # No-ops gracefully (returns a "reason") until a model has been trained
                _run_scheduled_job("ml_anomaly_detection", run_ml_detection_job)

        if app.config.get("ML_AUTO_RETRAIN_ENABLED", True):
            from app.services.ml_detection import train_model as _train_ml_model

            # Retrains on a rolling ML_TRAINING_LOOKBACK_HOURS window, so the
            # model keeps adapting to gradually-shifting "normal" traffic
            # instead of staying frozen at whatever was trained at seed time.
            # A too-small dataset just re-reports {"trained": False, "reason":
            # ...} via _run_scheduled_job -- not an exception, so it never
            # trips the job-failure metric/log.
            @scheduler.task(
                "interval", id="ml_auto_retrain",
                seconds=app.config.get("ML_RETRAIN_INTERVAL_SECONDS", 6 * 60 * 60),
            )
            def scheduled_ml_retrain():
                _run_scheduled_job("ml_auto_retrain", _train_ml_model)

    # Schema is managed by Flask-Migrate (`flask db upgrade`) now that the
    # normalised Event schema exists — see docs/ARCHITECTURE.md. The one
    # exception is ephemeral test/in-memory databases, which have no
    # migration history to apply and just need the current model schema.
    if app.config.get("AUTO_CREATE_DB", False):
        with app.app_context():
            db.create_all()

    return app
