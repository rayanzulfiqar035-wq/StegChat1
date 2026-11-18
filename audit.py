"""Allowlisted security events, never request bodies or exception details."""
import ipaddress
import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import current_app, has_request_context, request

EVENTS = {"registration", "login_success", "login_failure", "logout", "keys_uploaded",
          "keys_reset", "rate_limit", "lockout", "message_rejected", "server_error", "request_rejected",
          "contact_requested", "contact_accepted", "contact_removed"}
REASONS = {"http", "socket", "csrf", "invalid payload", "unsupported version", "unsupported kind",
           "sender mismatch", "invalid recipient", "invalid timestamp", "invalid base64",
           "message too large", "invalid ephemeral key", "invalid iv", "invalid signature",
           "invalid ciphertext", "invalid PNG", "image too large", "recipient not found", "unauthorized", "queue_full", "storage unavailable", "contact not approved"}


def init_audit(app):
    """Bind one rotating UTF-8 log to this application instance."""
    path = Path(app.config["AUDIT_LOG_PATH"])
    path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.Logger("secure_chat.audit", level=logging.INFO)
    handler = RotatingFileHandler(path, maxBytes=1_048_576, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    app.extensions["audit_logger"] = logger


def audit_event(event, username=None, reason=None):
    """Write only fixed event/reason names and validated account/IP metadata."""
    if event not in EVENTS:
        return
    fields = [f"event={event}"]
    if reason is not None:
        fields.append(f"reason={reason if reason in REASONS else 'validation failed'}")
    # SECURITY: rejected messages record reason only, never envelope members.
    if event != "message_rejected":
        if username is not None:
            safe = username if isinstance(username, str) and re.fullmatch(r"[a-z0-9_]{3,32}", username) else "<invalid>"
            fields.append(f"username={safe}")
        if has_request_context():
            try:
                address = str(ipaddress.ip_address(request.remote_addr))
            except ValueError:
                address = "unknown"
            fields.append(f"ip={address}")
    current_app.extensions["audit_logger"].info(" ".join(fields))
