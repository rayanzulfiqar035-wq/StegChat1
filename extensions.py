"""Flask extension instances, created unbound and attached in `create_app()`.

Keeping them here (instead of inside `app.py`) avoids circular imports once the
blueprints, models and Socket.IO handlers are added in later steps.
"""

from __future__ import annotations

from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()

# SECURITY: sessions are server-signed cookies handled by Flask-Login; no JWT and
# no client-readable session state.
login_manager = LoginManager()
login_manager.session_protection = "strong"

# SECURITY: CSRFProtect rejects state-changing requests that lack a valid token,
# which stops a third-party page from driving this app with the victim's cookie.
csrf = CSRFProtect()

# Threading mode with simple-websocket: no eventlet/gevent monkey patching.
socketio = SocketIO(async_mode="threading")
