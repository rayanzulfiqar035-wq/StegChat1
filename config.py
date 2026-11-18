"""Application configuration loaded from the environment (`.env` in development).

Every value comes from a variable documented in `docs/PROJECT_MAIN.md` section 14.
No secret is ever hard-coded here: `SECRET_KEY` has no default and the app
refuses to start without it.
"""

from __future__ import annotations

import os
import math
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# Load `.env` from the project root unless the process environment already
# provides the variable (the real environment always wins).
load_dotenv(BASE_DIR / ".env", override=False)


class ConfigError(RuntimeError):
    """Raised when the configuration is missing a required value or is invalid."""


def _env_str(name: str, default: str) -> str:
    """Return a string setting, falling back to `default` when the variable is unset or empty."""
    value = os.environ.get(name, "").strip()
    return value or default


def _env_int(name: str, default: int) -> int:
    """Return a positive integer setting, raising `ConfigError` when it is not a valid number."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}.") from exc
    if value <= 0:
        raise ConfigError(f"{name} must be greater than zero, got {value}.")
    return value


def _env_flag(name: str, default: int) -> int:
    """Return a 0/1 flag setting, accepting `0`/`1` (and their word forms)."""
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return 1
    if raw in {"0", "false", "no", "off"}:
        return 0
    raise ConfigError(f"{name} must be 0 or 1, got {raw!r}.")


def _env_days(name: str, default: float) -> float:
    """Accept positive fractional days for short expiry acceptance checks."""
    try:
        value = float(os.environ.get(name, "").strip() or default)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a positive number of days.") from exc
    if not math.isfinite(value) or value <= 0:
        raise ConfigError(f"{name} must be a positive number of days.")
    return value


class Config:
    """Flask configuration object; every attribute is read by `create_app()`."""

    # SECURITY: the session signing key is mandatory and has no default, so a
    # misconfigured deployment fails closed instead of using a guessable key.
    SECRET_KEY = os.environ.get("SECRET_KEY", "").strip() or None

    DATABASE_URL = _env_str("DATABASE_URL", "sqlite:///chat.db")
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SSL_CERT = _env_str("SSL_CERT", "certs/localhost.pem")
    SSL_KEY = _env_str("SSL_KEY", "certs/localhost-key.pem")

    MESSAGE_TTL_DAYS = _env_days("MESSAGE_TTL_DAYS", 7)
    MAX_TEXT_BYTES = _env_int("MAX_TEXT_BYTES", 16384)
    MAX_STEGO_BYTES = _env_int("MAX_STEGO_BYTES", 3145728)
    MAX_PENDING_PER_PAIR = _env_int("MAX_PENDING_PER_PAIR", 100)

    SESSION_MINUTES = _env_int("SESSION_MINUTES", 30)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=SESSION_MINUTES)

    STEGO_LAB = bool(_env_flag("STEGO_LAB", 0))
    AUDIT_LOG_PATH = str(BASE_DIR / "logs" / "audit.log")
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_ENABLED = True
    SOCKET_RATE_LIMIT_ENABLED = True

    # SECURITY: the session cookie is never readable by JavaScript and is not
    # sent with cross-site requests (no CSRF-by-cookie-relay).
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # SECURITY: only send the session cookie over HTTPS connections.
    SESSION_COOKIE_SECURE = True
    # Cap incoming request bodies to slightly above the largest allowed envelope
    # (MAX_STEGO_BYTES = 3 MiB) to prevent memory exhaustion via oversized uploads.
    MAX_CONTENT_LENGTH = max(MAX_TEXT_BYTES, 4 * ((MAX_STEGO_BYTES + 2) // 3)) + 65536

    @classmethod
    def validate(cls) -> None:
        """Raise `ConfigError` with an actionable message if a required value is missing."""
        if not cls.SECRET_KEY:
            raise ConfigError(
                "SECRET_KEY is not set. Copy .env.example to .env and generate one with:\n"
                '  python -c "import secrets; print(secrets.token_hex(32))"'
            )
        if len(cls.SECRET_KEY) < 32:
            raise ConfigError(
                "SECRET_KEY is too short (minimum 32 characters). Generate a strong one with:\n"
                '  python -c "import secrets; print(secrets.token_hex(32))"'
            )

        cert_path = Path(cls.SSL_CERT)
        if not cert_path.is_absolute():
            cert_path = BASE_DIR / cert_path

        key_path = Path(cls.SSL_KEY)
        if not key_path.is_absolute():
            key_path = BASE_DIR / key_path

        if not cert_path.is_file() or not key_path.is_file():
            missing = []
            if not cert_path.is_file():
                missing.append(str(cert_path))
            if not key_path.is_file():
                missing.append(str(key_path))
            raise ConfigError(
                f"Missing SSL certificate file(s): {', '.join(missing)}.\n"
                "Generate them using mkcert:\n"
                "  mkcert -install\n"
                "  mkcert -cert-file certs/localhost.pem -key-file certs/localhost-key.pem localhost 127.0.0.1 ::1"
            )
