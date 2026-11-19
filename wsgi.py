"""Vercel WSGI entrypoint. Local development continues to use app.py."""

import os
from urllib.parse import urlsplit

from app import create_app
from config import Config, ConfigError


class VercelConfig(Config):
    REQUIRE_LOCAL_TLS = False  # Vercel terminates HTTPS before invoking WSGI.
    ENABLE_BACKGROUND_CLEANUP = False
    AUDIT_LOG_TO_STDOUT = True

    _origin = os.environ.get("APP_ORIGIN") or (
        "https://" + os.environ["VERCEL_URL"] if os.environ.get("VERCEL_URL") else ""
    )
    _parsed_origin = urlsplit(_origin)
    SOCKET_ALLOWED_ORIGINS = [_origin]
    CSP_CONNECT_SRC = f"'self' wss://{_parsed_origin.netloc}"

    @classmethod
    def validate(cls) -> None:
        super().validate()
        if not cls.DATABASE_URL.startswith("postgresql+psycopg://"):
            raise ConfigError("Vercel requires DATABASE_URL using postgresql+psycopg://.")
        if (cls._parsed_origin.scheme != "https" or not cls._parsed_origin.netloc
                or cls._parsed_origin.path or cls._parsed_origin.query
                or cls._parsed_origin.fragment):
            raise ConfigError("APP_ORIGIN must be an HTTPS origin, for example https://chat.example.com.")


app = create_app(VercelConfig)
