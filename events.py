"""Socket.IO event handlers for real-time messaging.

Step 4 implements plain, unencrypted messaging to verify the real-time
transport before encryption is added in Steps 5-6.  All plaintext message
handling here is temporary and marked `# TEMP-PLAINTEXT`.

Security:
- `connect` refuses unauthenticated connections.
- The sender is always taken from `current_user.username` (Flask session),
  never trusted from client payloads.
- Message payloads are never logged.
- Messages are emitted strictly to the recipient's room (`user:<id>`), never
  broadcasted.
"""

from __future__ import annotations

from typing import Any

from flask import request
from flask_login import current_user
from flask_socketio import emit, join_room

from extensions import socketio
from models import User

# In-memory tracking of active connections per user ID.
# Maps user_id -> set of active Socket.IO session IDs (sids).
_connected_users: dict[int, set[str]] = {}


@socketio.on("connect")
def handle_connect() -> bool | None:
    """Handle incoming WebSocket connection.

    SECURITY: refuse connection if the user is not authenticated via the
    session cookie.
    """
    if not current_user.is_authenticated:
        # Refuse connection
        return False

    user_id = current_user.id
    room = f"user:{user_id}"
    join_room(room)

    _connected_users.setdefault(user_id, set()).add(request.sid)
    return None


@socketio.on("disconnect")
def handle_disconnect() -> None:
    """Clean up connection tracking when a client disconnects."""
    if current_user.is_authenticated:
        user_id = current_user.id
        sids = _connected_users.get(user_id)
        if sids:
            sids.discard(request.sid)
            if not sids:
                _connected_users.pop(user_id, None)


@socketio.on("send_message")
def handle_send_message(data: Any) -> dict[str, Any]:
    """Relay a message from the authenticated user to the recipient's room.

    Payload: {"recipient": str, "text": str}
    Ack: {"ok": True} or {"ok": False, "error": str}
    """
    if not current_user.is_authenticated:
        return {"ok": False, "error": "unauthorized"}

    if not isinstance(data, dict):
        return {"ok": False, "error": "invalid payload"}

    raw_recipient = data.get("recipient")
    raw_text = data.get("text")

    if not isinstance(raw_recipient, str) or not raw_recipient.strip():
        return {"ok": False, "error": "recipient required"}

    # SECURITY: enforce max text length (<= 2000 chars) and non-empty.
    if not isinstance(raw_text, str) or not raw_text.strip():
        return {"ok": False, "error": "message text cannot be empty"}

    if len(raw_text) > 2000:
        return {"ok": False, "error": "message text exceeds 2000 characters"}

    recipient_username = raw_recipient.strip().lower()

    # Look up recipient by exact username.
    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        return {"ok": False, "error": "recipient not found"}

    # In Step 4, messages to offline users are refused (Step 7 adds pending queue).
    recipient_sids = _connected_users.get(recipient.id)
    if not recipient_sids:
        return {"ok": False, "error": "recipient offline"}

    # SECURITY: use current_user.username from server session; never trust client sender.
    # SECURITY: do not log payload content.
    # TEMP-PLAINTEXT: send plain text payload; Step 6 replaces with encrypted envelope.
    emit(
        "message",
        {
            "sender": current_user.username,
            "text": raw_text,  # TEMP-PLAINTEXT
        },
        to=f"user:{recipient.id}",
    )

    return {"ok": True}
