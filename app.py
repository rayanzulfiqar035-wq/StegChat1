"""Application factory and development entry point for the secure chat server.

Step 1 only serves a placeholder page: accounts, models and chat arrive in later
steps. The factory is written so those steps can plug in blueprints without
touching the wiring here.
"""

from __future__ import annotations

import sys

from flask import Flask, render_template

from config import Config, ConfigError
from extensions import csrf, db, login_manager, socketio


def create_app(config_class: type[Config] = Config) -> Flask:
    """Build and configure the Flask application.

    Raises `ConfigError` when required configuration (notably `SECRET_KEY`) is
    missing, so the process fails closed instead of booting half-configured.
    """
    # SECURITY: fail fast on missing configuration before anything is served.
    config_class.validate()

    app = Flask(__name__)
    app.config.from_object(config_class)

    # SECURITY: never leave the interactive debugger enabled - it exposes an
    # arbitrary-code console and must not be switched on in this codebase.
    app.config["DEBUG"] = False
    app.config["TESTING"] = False

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    socketio.init_app(app)

    _register_login_stub()
    _register_routes(app)
    return app


def _register_login_stub() -> None:
    """TEMP: satisfy Flask-Login until the User model exists in Step 2.

    Flask-Login refuses to build a request context (and therefore any template)
    without a user loader. Step 1 has no accounts, so every request is anonymous.
    Step 2 registers the real loader that reads `User` from the database.
    """

    @login_manager.user_loader
    def _load_anonymous_user(_user_id: str) -> None:
        return None


def _register_routes(app: Flask) -> None:
    """Register the placeholder routes that exist in Step 1."""

    @app.get("/")
    def index() -> str:
        """Render the "server running" placeholder page."""
        return render_template("base.html")


def main() -> int:
    """Start the development server on the loopback interface only."""
    try:
        app = create_app()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1

    # SECURITY: bound to 127.0.0.1 so the development server is never reachable
    # from the local network.
    socketio.run(
        app,
        host="127.0.0.1",
        port=5000,
        allow_unsafe_werkzeug=True,
        debug=False,
        use_reloader=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
