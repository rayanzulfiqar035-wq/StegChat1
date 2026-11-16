"""Application factory and development entry point for the secure chat server.

Step 1 built the skeleton; Step 2 adds accounts (register, login, logout).
Later steps plug in additional blueprints and Socket.IO handlers without
touching this wiring.
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
    # SECURITY: restrict WebSocket connections to this origin only (§11).
    # Cross-origin WebSocket requests are rejected automatically.
    socketio.init_app(app, cors_allowed_origins="https://localhost:5000")

    # Register blueprints.
    from auth import auth_bp  # noqa: PLC0415 — deferred to avoid circular import
    app.register_blueprint(auth_bp)

    # Create all database tables (SQLite file lives under instance/).
    with app.app_context():
        db.create_all()

    _register_user_loader()
    _register_login_manager(app)
    _register_routes(app)
    return app


def _register_user_loader() -> None:
    """Register the Flask-Login user loader that reads `User` from the DB."""
    from models import User  # noqa: PLC0415

    @login_manager.user_loader
    def load_user(user_id: str) -> "User | None":
        # SECURITY: query by integer primary key only; never by username or
        # any user-supplied string to prevent injection via the session cookie.
        return db.session.get(User, int(user_id))


def _register_login_manager(app: Flask) -> None:
    """Configure Flask-Login behaviour for unauthenticated requests."""
    # Redirect unauthenticated users to /login with a neutral flash message.
    login_manager.login_view = "auth.login"  # type: ignore[assignment]
    # SECURITY: "strong" session protection regenerates the session on
    # IP or user-agent change, limiting session-fixation and hijacking risk.
    login_manager.session_protection = "strong"


def _register_routes(app: Flask) -> None:
    """Register top-level routes (placeholder index from Step 1)."""

    @app.get("/")
    def index() -> str:
        """Render the server-running placeholder page."""
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
