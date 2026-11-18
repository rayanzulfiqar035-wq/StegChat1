"""Step 7 queue persistence, ownership, expiry and connection regressions."""
from datetime import datetime, timedelta, timezone

import pytest

from test_step6 import account_hash, app, envelope, login, sockets  # shared fixtures
from cleanup import delete_expired_messages, start_cleanup_task
from config import Config, _env_days
from extensions import db, socketio
from models import PendingMessage


def test_offline_delivery_stored_then_acknowledged(app, envelope):
    alice = socketio.test_client(app, flask_test_client=login(app))
    result = alice.emit("send_message", envelope, callback=True)
    assert result["ok"]
    with app.app_context():
        row = db.session.get(PendingMessage, result["id"])
        assert row.ciphertext == envelope["ct"]
        assert row.signature == envelope["sig"]
        assert row.envelope() == {"id": result["id"], **envelope}
        assert "text" not in row.__table__.columns
    bob = socketio.test_client(app, flask_test_client=login(app, "bob"))
    assert bob.get_received()[0]["args"] == {"id": result["id"], **envelope}
    # Connect/forwarding alone must never delete the row.
    with app.app_context():
        assert PendingMessage.query.count() == 1
    assert bob.emit("ack_message", {"id": result["id"]}, callback=True) == {"ok": True}
    assert bob.emit("ack_message", {"id": result["id"]}, callback=True) == {"ok": False}
    with app.app_context():
        assert PendingMessage.query.count() == 0
    later = alice.emit("send_message", envelope, callback=True)
    assert later["id"] > result["id"]  # old ACK cannot delete a later delivery
    alice.disconnect(); bob.disconnect()


def test_ack_ownership_and_unknown_id_indistinguishable(app, sockets, envelope):
    _, _, alice, bob = sockets
    result = alice.emit("send_message", envelope, callback=True)
    attacker = socketio.test_client(app, flask_test_client=login(app, "offline"))
    for client in (alice, attacker):
        assert client.emit("ack_message", {"id": result["id"]}, callback=True) == {"ok": False}
        assert client.emit("ack_message", {"id": 999999}, callback=True) == {"ok": False}
    for payload in ({"id": True}, {"id": "1"}, {"id": -1}, {}, None, {"id": 1, "recipient_id": 2}):
        assert bob.emit("ack_message", payload, callback=True) == {"ok": False}
    with app.app_context():
        assert PendingMessage.query.count() == 1
    attacker.disconnect()


def test_queue_cap_101st_and_recipient_pair_independence(app, envelope):
    alice = socketio.test_client(app, flask_test_client=login(app))
    for _ in range(100):
        assert alice.emit("send_message", envelope, callback=True)["ok"]
    assert alice.emit("send_message", envelope, callback=True) == {"ok": False, "error": "queue_full"}
    assert alice.emit("send_message", {**envelope, "recipient": "offline"}, callback=True)["ok"]
    with app.app_context():
        assert PendingMessage.query.count() == 101
    alice.disconnect()


def test_storage_failure_returns_no_payload_and_does_not_relay(app, sockets, envelope, monkeypatch, capsys):
    from sqlalchemy.exc import SQLAlchemyError
    _, _, alice, bob = sockets
    def fail_commit():
        raise SQLAlchemyError("test ciphertext must never appear in logs")
    monkeypatch.setattr(db.session, "commit", fail_commit)
    assert alice.emit("send_message", envelope, callback=True) == {
        "ok": False, "error": "storage unavailable"}
    assert bob.get_received() == []
    with app.app_context():
        assert PendingMessage.query.count() == 0
    captured = capsys.readouterr()
    assert "test ciphertext" not in captured.out + captured.err


def test_reconnect_oldest_first_at_most_200(app, envelope):
    app.config["MAX_PENDING_PER_PAIR"] = 300
    alice = socketio.test_client(app, flask_test_client=login(app))
    ids = [alice.emit("send_message", envelope, callback=True)["id"] for _ in range(205)]
    bob_http = login(app, "bob")
    bob = socketio.test_client(app, flask_test_client=bob_http)
    assert [m["args"]["id"] for m in bob.get_received()] == ids[:200]
    bob.disconnect()
    bob = socketio.test_client(app, flask_test_client=bob_http)
    assert [m["args"]["id"] for m in bob.get_received()] == ids[:200]
    with app.app_context():
        assert PendingMessage.query.count() == 205
    alice.disconnect(); bob.disconnect()


def test_tiny_fractional_ttl_uses_server_creation_time(app, sockets, envelope, monkeypatch):
    _, _, alice, _ = sockets
    first = alice.emit("send_message", envelope, callback=True)["id"]
    second = alice.emit("send_message", envelope, callback=True)["id"]
    monkeypatch.setenv("MESSAGE_TTL_DAYS", "0.0007")
    app.config["MESSAGE_TTL_DAYS"] = _env_days("MESSAGE_TTL_DAYS", 7)
    with app.app_context():
        db.session.get(PendingMessage, first).created_at = datetime.now(timezone.utc) - timedelta(minutes=2)
        db.session.commit()
        assert delete_expired_messages() == 1
        assert db.session.get(PendingMessage, first) is None
        assert db.session.get(PendingMessage, second) is not None


def test_secure_delete_on_new_connections_and_startup_expiry(app, tmp_path):
    from app import create_app
    class DiskConfig(Config):
        TESTING = True
        SECRET_KEY = app.config["SECRET_KEY"]
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + str(tmp_path / "expiry.db")
    disk = create_app(DiskConfig)
    with disk.app_context():
        # PRAGMA is deliberately used only for SQLite connection configuration.
        with db.engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA secure_delete").scalar() == 1
        db.session.add(PendingMessage(sender_id=1, recipient_id=2, kind="text",
            ciphertext="ciphertext", iv="iv", ephemeral_public_key="public",
            signature="signature", client_ts=1,
            created_at=datetime.now(timezone.utc) - timedelta(days=8)))
        db.session.commit()
        db.engine.dispose()
        with db.engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA secure_delete").scalar() == 1
    disk = create_app(DiskConfig)
    with disk.app_context():
        assert PendingMessage.query.count() == 0
        db.session.remove(); db.engine.dispose()


def test_hourly_worker_scheduled_and_runs_cleanup(app, monkeypatch):
    callbacks, intervals, runs = [], [], []
    monkeypatch.setattr(socketio, "start_background_task", lambda fn: callbacks.append(fn))
    monkeypatch.setattr("cleanup.delete_expired_messages", lambda: runs.append(True))
    class StopWorker(Exception):
        pass
    def sleep(seconds):
        intervals.append(seconds)
        if len(intervals) == 2:
            raise StopWorker
    monkeypatch.setattr(socketio, "sleep", sleep)
    start_cleanup_task(app)
    with pytest.raises(StopWorker):
        callbacks[0]()
    assert intervals == [3600, 3600] and runs == [True]
