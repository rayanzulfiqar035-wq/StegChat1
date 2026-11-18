"""Socket.IO event handlers for real-time messaging.

Step 4 built the real-time transport; Step 6 replaces the temporary plaintext
relay with the encrypted message envelope (main spec §11 and §12). The server
validates the envelope shape and forwards it unchanged: it holds no key and
never decrypts anything.

Security:
- `connect` refuses unauthenticated connections.
- The sender is always taken from `current_user.username` (Flask session),
  never trusted from client payloads.
- Message payloads are never logged.
- Messages are emitted strictly to the recipient's room (`user:<id>`), never
  broadcasted.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from threading import RLock
from collections import deque
from time import monotonic
from typing import Any

from flask import current_app, request
from flask_login import current_user
from flask_socketio import emit, join_room
from sqlalchemy.exc import SQLAlchemyError

from extensions import db, socketio
from models import PendingMessage, User
from audit import audit_event

# In-memory tracking of active connections per user ID.
# Maps user_id -> set of active Socket.IO session IDs (sids).
_connected_users: dict[int, set[str]] = {}
_connections_lock = RLock()


def _send_rate_allowed(user_id):
    """Sliding-minute counter shared by this user's tabs and reconnects."""
    if not current_app.config["SOCKET_RATE_LIMIT_ENABLED"]:
        return True
    with _connections_lock:
        counters = current_app.extensions.setdefault("socket_send_rates", {})
        now = monotonic()
        # SECURITY: remove idle entries to keep the in-memory limiter bounded.
        for uid in list(counters):
            if counters[uid][-1] <= now - 60:
                del counters[uid]
        events = counters.setdefault(user_id, deque())
        while events and events[0] <= now - 60:
            events.popleft()
        if len(events) >= 30:
            return False
        events.append(now)
        return True


def reject_message(reason):
    """Audit a fixed rejection reason without recording envelope content."""
    audit_event("message_rejected", reason=reason)
    return {"ok": False, "error": reason}

# §12 envelope: version 1, text kind only until Step 9 adds `stego`.
_ENVELOPE_VERSION = 1
_TEXT_FIELDS = ("v", "kind", "sender", "recipient", "ts", "eph", "iv", "ct", "sig")
_TEXT_B64_FIELDS = ("eph", "iv", "ct", "sig")
_USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")
# §12: raw P-256 public point is 65 bytes (0x04 || X || Y); AES-GCM IV is 12.
_EPH_BYTES = 65
_IV_BYTES = 12


class EnvelopeError(ValueError):
    """Raised when an envelope fails validation; the message is safe to return."""


def _decode_b64(value: str) -> bytes:
    """Strictly decode standard base64 with padding (fails closed)."""
    if not value or len(value) % 4 != 0 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
        raise EnvelopeError("invalid base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EnvelopeError("invalid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise EnvelopeError("invalid base64")
    return decoded


def _validate_envelope(data: Any, sender: str) -> dict[str, Any]:
    """Validate a client envelope against main spec §12 and return a clean copy.

    SECURITY: only the documented fields are accepted (no extra members), every
    field is type-checked, the claimed sender must be the session user, and the
    size limit stops an oversized envelope from being relayed or buffered.
    """
    if not isinstance(data, dict):
        raise EnvelopeError("invalid payload")
    if set(data.keys()) != set(_TEXT_FIELDS):
        raise EnvelopeError("invalid payload")

    if type(data["v"]) is not int or data["v"] != _ENVELOPE_VERSION:
        raise EnvelopeError("unsupported version")
    if data["kind"] != "text":
        raise EnvelopeError("unsupported kind")

    # SECURITY: the server never trusts a client-supplied sender (§11).
    if not isinstance(data["sender"], str) or data["sender"] != sender:
        raise EnvelopeError("sender mismatch")

    recipient = data["recipient"]
    if not isinstance(recipient, str) or not _USERNAME_RE.fullmatch(recipient):
        raise EnvelopeError("invalid recipient")

    ts = data["ts"]
    if type(ts) is not int or not 0 < ts <= 9_007_199_254_740_991:
        raise EnvelopeError("invalid timestamp")

    for field in _TEXT_B64_FIELDS:
        if not isinstance(data[field], str):
            raise EnvelopeError("invalid payload")

    # SECURITY: bound the whole JSON envelope before allocating decoded fields.
    limit = int(current_app.config["MAX_TEXT_BYTES"])
    if any(len(data[field]) > limit for field in _TEXT_B64_FIELDS):
        raise EnvelopeError("message too large")
    if len(json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > limit:
        raise EnvelopeError("message too large")

    ephemeral = _decode_b64(data["eph"])
    if len(ephemeral) != _EPH_BYTES or ephemeral[0] != 0x04:
        raise EnvelopeError("invalid ephemeral key")
    if len(_decode_b64(data["iv"])) != _IV_BYTES:
        raise EnvelopeError("invalid iv")
    if len(_decode_b64(data["sig"])) != 64:
        raise EnvelopeError("invalid signature")
    ciphertext = _decode_b64(data["ct"])
    if len(ciphertext) < 16:
        raise EnvelopeError("invalid ciphertext")

    return {field: data[field] for field in _TEXT_FIELDS}


def handle_connect() -> bool | None:
    """Handle incoming WebSocket connection.

    SECURITY: refuse connection if the user is not authenticated via the
    session cookie.
    """
    if not current_user.is_authenticated:
        # Refuse connection
        return False

    with _connections_lock:
        user_id = current_user.id
        join_room(f"user:{user_id}")
        _connected_users.setdefault(user_id, set()).add(request.sid)
        queued = PendingMessage.query.filter_by(recipient_id=user_id).order_by(
            PendingMessage.created_at, PendingMessage.id).limit(200).all()
        for message in queued:
            emit("message", message.envelope(), to=request.sid)
    return None


def handle_disconnect(reason: str | None = None) -> None:
    """Clean up connection tracking when a client disconnects."""
    if current_user.is_authenticated:
        user_id = current_user.id
        with _connections_lock:
            sids = _connected_users.get(user_id)
            if sids:
                sids.discard(request.sid)
                if not sids:
                    _connected_users.pop(user_id, None)


def disconnect_user(user_id: int) -> None:
    """Close this account's open chat sockets when it logs out.

    SECURITY: Socket.IO holds a session snapshot; HTTP logout alone cannot
    revoke that snapshot. Disconnect all tabs/devices for this account.
    """
    with _connections_lock:
        for sid in tuple(_connected_users.pop(user_id, set())):
            socketio.server.disconnect(sid, namespace="/")


def handle_send_message(data: Any) -> dict[str, Any]:
    """Persist an encrypted envelope and relay it when the recipient is online.

    Payload: text envelope from main spec §12.
    Ack: {"ok": True, "id": <delivery id>} or {"ok": False, "error": <reason>}

    SECURITY: this handler contains no decryption path and no key material. It
    checks the shape of the envelope, then forwards the exact bytes it received
    so the recipient's signature check covers what was actually sent.
    """
    if not current_user.is_authenticated:
        return reject_message("unauthorized")

    if not _send_rate_allowed(current_user.id):
        audit_event("rate_limit", current_user.username, reason="socket")
        return {"ok": False, "error": "rate_limited"}

    try:
        envelope = _validate_envelope(data, current_user.username)
    except EnvelopeError as exc:
        return reject_message(str(exc))

    # Look up recipient by exact (already normalised) username.
    recipient = User.query.filter_by(username=envelope["recipient"]).first()
    if not recipient:
        return reject_message("recipient not found")

    # SECURITY: serialize relay with logout so revoked sockets cannot send or
    # receive after logout has completed.
    with _connections_lock:
        if request.sid not in _connected_users.get(current_user.id, set()):
            return reject_message("unauthorized")
        # SECURITY: count and insert under the same lock in this single-process
        # threading server, so simultaneous sends cannot bypass the pair cap.
        try:
            count = PendingMessage.query.filter_by(sender_id=current_user.id,
                                                  recipient_id=recipient.id).count()
            if count >= current_app.config["MAX_PENDING_PER_PAIR"]:
                return reject_message("queue_full")
            message = PendingMessage(sender_id=current_user.id, recipient_id=recipient.id,
                                     kind=envelope["kind"], ciphertext=envelope["ct"],
                                     iv=envelope["iv"], ephemeral_public_key=envelope["eph"],
                                     signature=envelope["sig"], client_ts=envelope["ts"])
            db.session.add(message)
            db.session.commit()
            delivery_id = message.id
        except SQLAlchemyError:
            # SECURITY: SQL exceptions can include ciphertext bind parameters.
            # Return a generic failure without printing the exception/payload.
            db.session.rollback()
            return reject_message("storage unavailable")
        if _connected_users.get(recipient.id):
            emit("message", {"id": delivery_id, **envelope}, to=f"user:{recipient.id}")

    return {"ok": True, "id": delivery_id}


def handle_ack_message(data: Any) -> dict[str, bool]:
    """Delete only deliveries owned by this authenticated recipient."""
    if (not current_user.is_authenticated or not isinstance(data, dict)
            or set(data) != {"id"} or type(data["id"]) is not int
            or not 0 < data["id"] <= 9_007_199_254_740_991):
        return {"ok": False}
    with _connections_lock:
        if request.sid not in _connected_users.get(current_user.id, set()):
            return {"ok": False}
        # SECURITY: ownership is part of the DELETE predicate, not client input.
        deleted = PendingMessage.query.filter_by(
            id=data["id"], recipient_id=current_user.id).delete()
        db.session.commit()
    return {"ok": bool(deleted)}


def register_handlers() -> None:
    """Bind handlers to each factory-created Socket.IO server."""
    with _connections_lock:
        _connected_users.clear()
    socketio.on_event("connect", handle_connect)
    socketio.on_event("disconnect", handle_disconnect)
    socketio.on_event("send_message", handle_send_message)
    socketio.on_event("ack_message", handle_ack_message)

    @socketio.on_error_default
    def handle_socket_error(error):
        """Prevent event exceptions from logging payloads or tracebacks."""
        db.session.rollback()
        audit_event("server_error")
        return {"ok": False, "error": "server error"}
