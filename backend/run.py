import os

from app import create_app, socketio

app = create_app()

if __name__ == "__main__":
    # Werkzeug's dev-server HTTP handler sets its own `Server` header below
    # the WSGI app (Flask's after_request never sees it), leaking exact
    # Werkzeug/Python versions -- flagged by the ZAP DAST scan (see
    # .github/workflows/security.yml). Scoped to this dev-only entrypoint;
    # a real WSGI server (gunicorn, etc.) sets its own and isn't affected.
    from werkzeug.serving import WSGIRequestHandler

    WSGIRequestHandler.server_version = "webserver"
    WSGIRequestHandler.sys_version = ""


    # socketio.run wraps Werkzeug's dev server with WebSocket support
    # (threading async mode -- see app/__init__.py). Using app.run() here
    # instead would silently serve REST fine but drop every WebSocket
    # connection.
    #
    # debug=True enables Werkzeug's reloader, which re-runs create_app() in
    # a forked child process -- roughly doubling startup time. Fine for local
    # dev; CI (which just needs the server up for a DAST scan) sets
    # FLASK_DEBUG=false to skip it.
    debug = os.environ.get("FLASK_DEBUG", "true").lower() != "false"
    # Defaults to loopback-only, matching Werkzeug's own default -- a bare
    # `python run.py` on a dev machine shouldn't be reachable from the LAN.
    # The Docker Compose stack sets HOST=0.0.0.0 (see docker-compose.yml)
    # since nginx/Prometheus reach this process as a sibling container, not
    # as localhost.
    host = os.environ.get("HOST", "127.0.0.1")
    # Outside debug mode, flask-socketio refuses to boot the Werkzeug dev
    # server (it's not meant for production) unless explicitly overridden.
    # Fine here: FLASK_DEBUG=false is only ever set for the ephemeral CI
    # instance backing the ZAP DAST scan, not a real deployment.
    socketio.run(app, host=host, debug=debug, port=5000, allow_unsafe_werkzeug=not debug)
