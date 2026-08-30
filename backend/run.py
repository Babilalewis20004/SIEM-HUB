from app import create_app, socketio

app = create_app()

if __name__ == "__main__":
    # socketio.run wraps Werkzeug's dev server with WebSocket support
    # (threading async mode -- see app/__init__.py). Using app.run() here
    # instead would silently serve REST fine but drop every WebSocket
    # connection.
    socketio.run(app, debug=True, port=5000)
