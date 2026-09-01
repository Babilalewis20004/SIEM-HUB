import os

from app import create_app, socketio

app = create_app()

if __name__ == "__main__":
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
    socketio.run(app, debug=debug, port=5000)
