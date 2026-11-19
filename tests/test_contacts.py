"""Phonebook consent, direct socket bypass and offline delivery authorization."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import secrets

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import create_app
from config import Config
from extensions import db, socketio
from models import LoginAttempt, PhonebookContact, PendingMessage, User
from test_step6 import BASE, account_hash, app, csrf, envelope, login
from test_step10 import stego
from test_step8 import hardened


@pytest.fixture
def strangers(app):
    with app.app_context():
        PhonebookContact.query.delete()
        db.session.commit()
    return app


def contact_request(client, path="/api/contacts", method="POST", body=None, token=True):
    headers = {"Referer": BASE + "/chat"}
    if token:
        headers["X-CSRFToken"] = csrf(client)
    return client.open(path, method=method, base_url=BASE, json=body, headers=headers)


def connect_pair(app):
    alice, bob = login(app), login(app, "bob")
    assert contact_request(alice, body={"username": "BOB"}).status_code == 201
    assert contact_request(bob, "/api/contacts/alice/accept").status_code == 200
    return alice, bob


def messages(socket):
    return [event for event in socket.get_received() if event["name"] == "message"]


def disk_settings(tmp_path):
    class Settings(Config):
        TESTING = True
        RATELIMIT_ENABLED = False
        SOCKET_RATE_LIMIT_ENABLED = False
        SECRET_KEY = secrets.token_hex(32)
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + (tmp_path / "phonebook.db").as_posix()
        AUDIT_LOG_PATH = str(tmp_path / "audit.log")
    return Settings


@pytest.mark.parametrize("kind", ["text", "stego"])
def test_strangers_and_pending_requests_cannot_send_even_by_direct_socket(strangers, envelope, stego, kind):
    alice, bob = login(strangers), login(strangers, "bob")
    sender = socketio.test_client(strangers, flask_test_client=alice)
    recipient = socketio.test_client(strangers, flask_test_client=bob)
    payload = envelope if kind == "text" else stego
    try:
        for pending in (False, True):
            if pending:
                assert contact_request(alice, body={"username": "bob"}).status_code == 201
            assert sender.emit("send_message", payload, callback=True) == {
                "ok": False, "error": "contact not approved"}
            assert messages(recipient) == []
            with strangers.app_context():
                assert PendingMessage.query.count() == 0
    finally:
        sender.disconnect(); recipient.disconnect()


def test_only_recipient_can_accept_and_phonebooks_are_private(strangers, envelope):
    alice, bob, other = login(strangers), login(strangers, "bob"), login(strangers, "offline")
    assert contact_request(alice, body={"username": "bob"}).status_code == 201
    assert contact_request(alice, "/api/contacts/bob/accept").status_code == 403
    assert contact_request(other, "/api/contacts/alice/accept").status_code == 404
    # A crossed request is not acceptance.
    assert contact_request(bob, body={"username": "alice"}).status_code == 409
    assert bob.get("/api/contacts", base_url=BASE).json == {
        "contacts": [{"username": "alice", "status": "incoming"}]}
    assert other.get("/api/contacts", base_url=BASE).json == {"contacts": []}
    assert contact_request(bob, "/api/contacts/alice/accept").status_code == 200
    assert alice.get("/api/contacts", base_url=BASE).json == {
        "contacts": [{"username": "bob", "status": "accepted"}]}
    a = socketio.test_client(strangers, flask_test_client=alice)
    b = socketio.test_client(strangers, flask_test_client=bob)
    try:
        assert a.emit("send_message", envelope, callback=True)["ok"]
        assert len(messages(b)) == 1
        reverse = {**envelope, "sender": "bob", "recipient": "alice"}
        assert b.emit("send_message", reverse, callback=True)["ok"]
        assert len(messages(a)) == 1
    finally:
        a.disconnect(); b.disconnect()


def test_removal_blocks_existing_sockets_and_queued_replay(strangers, envelope):
    alice, bob = connect_pair(strangers)
    a = socketio.test_client(strangers, flask_test_client=alice)
    queued = a.emit("send_message", envelope, callback=True)
    assert queued["ok"]
    b = socketio.test_client(strangers, flask_test_client=bob)
    assert len(messages(b)) == 1
    assert contact_request(bob, "/api/contacts/alice", "DELETE").status_code == 200
    assert a.emit("send_message", envelope, callback=True)["error"] == "contact not approved"
    b.disconnect()
    b = socketio.test_client(strangers, flask_test_client=bob)
    assert messages(b) == []
    with strangers.app_context():
        assert db.session.get(PendingMessage, queued["id"]) is not None
    # The recipient can still explicitly dismiss a formerly delivered row.
    assert b.emit("ack_message", {"id": queued["id"]}, callback=True) == {"ok": True}
    a.disconnect(); b.disconnect()


@pytest.mark.parametrize("path,method", [
    ("/api/contacts", "GET"), ("/api/contacts", "POST"),
    ("/api/contacts/bob/accept", "POST"), ("/api/contacts/bob", "DELETE"),
])
def test_contact_api_requires_login(strangers, path, method):
    client = strangers.test_client()
    assert contact_request(client, path, method, {"username": "bob"}).status_code == 401


@pytest.mark.parametrize("path,method", [
    ("/api/contacts", "POST"), ("/api/contacts/bob/accept", "POST"),
    ("/api/contacts/bob", "DELETE"),
])
def test_contact_writes_require_csrf(strangers, path, method):
    assert contact_request(login(strangers), path, method, {"username": "bob"}, token=False).status_code == 400
    with strangers.app_context():
        assert PhonebookContact.query.count() == 0


@pytest.mark.parametrize("body,status", [
    ({"username": "alice"}, 400), ({"username": "missing"}, 404),
    ({"username": "bob", "accepted": True}, 400), ({"username": {}}, 404),
    ({"username": "bob/../alice"}, 404), ({}, 400), ([], 400),
])
def test_no_self_contact_invalid_requests_or_client_granted_approval(strangers, body, status):
    assert contact_request(login(strangers), body=body).status_code == status
    with strangers.app_context():
        assert PhonebookContact.query.count() == 0


def test_decline_and_cancel_do_not_create_contacts(strangers):
    alice, bob = login(strangers), login(strangers, "bob")
    for actor, target in ((bob, "alice"), (alice, "bob")):
        assert contact_request(alice, body={"username": "bob"}).status_code == 201
        assert contact_request(actor, "/api/contacts/" + target, "DELETE").status_code == 200
        assert contact_request(bob, "/api/contacts/alice/accept").status_code == 404


def test_database_enforces_one_canonical_pair(strangers):
    connect_pair(strangers)
    with strangers.app_context():
        row = PhonebookContact.query.one()
        db.session.add(PhonebookContact(user_a_id=row.user_b_id, user_b_id=row.user_a_id,
                                       requested_by_id=row.user_a_id, accepted=True))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_simultaneous_crossed_requests_do_not_auto_accept(account_hash, tmp_path):
    # Separate file-backed connections match production; an in-memory SQLite
    # fixture shares one connection and is unsuitable for concurrent requests.
    application = create_app(disk_settings(tmp_path))
    with application.app_context():
        db.session.add_all(User(username=name, password_hash=account_hash) for name in ("alice", "bob"))
        db.session.commit()
    alice, bob = login(application), login(application, "bob")
    requests = [(alice, "bob", csrf(alice)), (bob, "alice", csrf(bob))]
    gate = Barrier(2)
    def submit(pair):
        client, peer, token = pair
        gate.wait(timeout=5)
        return client.post("/api/contacts", base_url=BASE, json={"username": peer},
                           headers={"Referer": BASE + "/chat", "X-CSRFToken": token}).status_code
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sorted(pool.map(submit, requests)) == [201, 409]
        with application.app_context():
            assert PhonebookContact.query.count() == 1
            assert PhonebookContact.query.one().accepted is False
    finally:
        with application.app_context():
            db.session.remove(); db.engine.dispose()
        for handler in application.extensions["audit_logger"].handlers:
            handler.close()


def test_unapproved_queue_rows_cannot_starve_an_approved_delivery(strangers, envelope):
    _, bob = connect_pair(strangers)
    with strangers.app_context():
        ids = {user.username: user.id for user in User.query.all()}
        for sender in ["offline"] * 200 + ["alice"]:
            db.session.add(PendingMessage(sender_id=ids[sender], recipient_id=ids["bob"],
                kind="text", ciphertext=envelope["ct"], iv=envelope["iv"],
                ephemeral_public_key=envelope["eph"], signature=envelope["sig"], client_ts=envelope["ts"]))
        db.session.commit()
    socket = socketio.test_client(strangers, flask_test_client=bob)
    try:
        delivered = messages(socket)
        assert len(delivered) == 1 and delivered[0]["args"]["sender"] == "alice"
        with strangers.app_context():
            assert PendingMessage.query.count() == 201
    finally:
        socket.disconnect()


def test_phonebook_write_rate_limit_is_shared_across_operations(hardened):
    client = login(hardened)
    for _ in range(30):
        assert contact_request(client, body={"username": "bob"}).status_code == 409
    assert contact_request(client, "/api/contacts/bob", "DELETE").status_code == 429


def test_additive_startup_preserves_existing_accounts_and_pending_rows(account_hash, tmp_path, envelope):
    settings = disk_settings(tmp_path)
    old_engine = create_engine(settings.SQLALCHEMY_DATABASE_URI)
    db.metadata.create_all(old_engine, tables=[User.__table__, PendingMessage.__table__, LoginAttempt.__table__])
    assert not inspect(old_engine).has_table("phonebook_contacts")
    with Session(old_engine) as session:
        alice = User(username="alice", password_hash=account_hash)
        bob = User(username="bob", password_hash=account_hash)
        session.add_all([alice, bob]); session.commit()
        session.add(PendingMessage(sender_id=alice.id, recipient_id=bob.id, kind="text",
            ciphertext=envelope["ct"], iv=envelope["iv"], ephemeral_public_key=envelope["eph"],
            signature=envelope["sig"], client_ts=envelope["ts"]))
        session.commit()
    old_engine.dispose()
    application = create_app(settings)
    try:
        with application.app_context():
            assert User.query.count() == 2 and PendingMessage.query.count() == 1
            assert User.query.filter_by(username="alice").one().password_hash == account_hash
            assert PhonebookContact.query.count() == 0
        client = socketio.test_client(application, flask_test_client=login(application, "bob"))
        assert messages(client) == []  # Existing senders are not silently approved.
        client.disconnect()
    finally:
        with application.app_context():
            db.session.remove(); db.engine.dispose()
        for handler in application.extensions["audit_logger"].handlers:
            handler.close()
