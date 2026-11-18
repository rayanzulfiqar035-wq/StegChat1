"""Expiry of temporary ciphertext deliveries; no payloads are logged."""
from datetime import datetime, timedelta, timezone

from flask import current_app

from extensions import db, socketio
from models import PendingMessage


def delete_expired_messages() -> int:
    """Delete messages older than configured server-time TTL in app context."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=current_app.config["MESSAGE_TTL_DAYS"])
    # SECURITY: expiry is based on server receipt time, never a sender timestamp.
    deleted = PendingMessage.query.filter(PendingMessage.created_at < cutoff).delete()
    db.session.commit()
    return deleted


def start_cleanup_task(app):
    """Run expiry hourly; startup expiry is performed by the application factory."""
    def worker():
        while True:
            socketio.sleep(3600)
            with app.app_context():
                try:
                    delete_expired_messages()
                except Exception:
                    db.session.rollback()
                    # SECURITY: database exceptions can contain bound ciphertext;
                    # log a generic operational failure without exception details.
                    app.logger.error("Pending-message cleanup failed; will retry next hour")
    return socketio.start_background_task(worker)
