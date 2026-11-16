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
from typing import Any

from flask import current_app, request
from flask_login import current_user
from flask_socketio import emit, join_room

from extensions import socketio
from models import User

# In-memory tracking of active connections per user ID.
# Maps user_id -> set of active Socket.IO session IDs (sids).
_connected_users: dict[int, set[str]] = {}
_connections_lock = RLock()

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
    """Relay an encrypted, signed envelope to the recipient's room.

    Payload: text envelope from main spec §12.
    Ack: {"ok": True} or {"ok": False, "error": <short reason>}

    SECURITY: this handler contains no decryption path and no key material. It
    checks the shape of the envelope, then forwards the exact bytes it received
    so the recipient's signature check covers what was actually sent.
    """
    if not current_user.is_authenticated:
        return {"ok": False, "error": "unauthorized"}

    try:
        envelope = _validate_envelope(data, current_user.username)
    except EnvelopeError as exc:
        return {"ok": False, "error": str(exc)}

    # Look up recipient by exact (already normalised) username.
    recipient = User.query.filter_by(username=envelope["recipient"]).first()
    if not recipient:
        return {"ok": False, "error": "recipient not found"}

    # Offline recipients are refused until Step 7 adds the pending queue.
    # SECURITY: serialize relay with logout so revoked sockets cannot send or
    # receive after logout has completed.
    with _connections_lock:
        if request.sid not in _connected_users.get(current_user.id, set()):
            return {"ok": False, "error": "unauthorized"}
        if not _connected_users.get(recipient.id):
            return {"ok": False, "error": "recipient offline"}
        emit("message", envelope, to=f"user:{recipient.id}")

    return {"ok": True}


def register_handlers() -> None:
    """Bind handlers to each factory-created Socket.IO server."""
    with _connections_lock:
        _connected_users.clear()
    socketio.on_event("connect", handle_connect)
    socketio.on_event("disconnect", handle_disconnect)
    socketio.on_event("send_message", handle_send_message)
