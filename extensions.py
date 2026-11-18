"""Flask extension instances, created unbound and attached in `create_app()`.

Keeping them here (instead of inside `app.py`) avoids circular imports once the
blueprints, models and Socket.IO handlers are added in later steps.
"""

from __future__ import annotations

from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlite3 import Connection as SQLiteConnection


@event.listens_for(Engine, "connect")
def enable_secure_delete(connection, record):
    """Overwrite deleted SQLite cells on every newly opened connection."""
    if isinstance(connection, SQLiteConnection):
        # SECURITY: this constant SQLite connection pragma is the sole SQL
        # exception; all application data access continues through the ORM.
        cursor = connection.cursor()
        try:
            cursor.execute("PRAGMA secure_delete = ON")
        finally:
            cursor.close()

db = SQLAlchemy()

# SECURITY: sessions are server-signed cookies handled by Flask-Login; no JWT and
# no client-readable session state.
login_manager = LoginManager()
login_manager.session_protection = "strong"

# SECURITY: CSRFProtect rejects state-changing requests that lack a valid token,
# which stops a third-party page from driving this app with the victim's cookie.
csrf = CSRFProtect()

# SECURITY: trust the actual connection address, not forwarded request headers.
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")

# Threading mode with simple-websocket: no eventlet/gevent monkey patching.
# SECURITY: restrict WebSocket origins to exact app HTTPS origins (§11).
socketio = SocketIO(
    async_mode="threading",
    cors_allowed_origins=["https://localhost:5000", "https://127.0.0.1:5000"],
    max_http_buffer_size=5_000_000,
)
