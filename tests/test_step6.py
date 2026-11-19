"""Regression checks for the Step 6 relay and its account/key prerequisites."""
import base64
import json
import re
import secrets
from itertools import combinations

import pytest

from app import create_app
from auth import _ph
from config import Config
from extensions import db, socketio
from models import PhonebookContact, User

BASE = "https://localhost:5000"
PASSWORD = "test-only-account-password"
B64 = lambda value: base64.b64encode(value).decode("ascii")


@pytest.fixture(scope="module")
def account_hash():
    return _ph.hash(PASSWORD)


def approve_fixture_contacts():
    """Existing relay/security regressions run between approved test contacts."""
    users = User.query.order_by(User.id).all()
    for first, second in combinations(users, 2):
        db.session.add(PhonebookContact(user_a_id=first.id, user_b_id=second.id,
                                       requested_by_id=first.id, accepted=True))
    db.session.commit()


@pytest.fixture
def app(account_hash, monkeypatch, tmp_path):
    class TestConfig(Config):
        TESTING = True
        RATELIMIT_ENABLED = False
        SOCKET_RATE_LIMIT_ENABLED = False
        AUDIT_LOG_PATH = str(tmp_path / "audit.log")
        SECRET_KEY = secrets.token_hex(32)
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"

    application = create_app(TestConfig)
    application.config["TESTING"] = True
    monkeypatch.setattr("api._write_audit_log", lambda *args: None)
    with application.app_context():
        db.session.add_all(User(username=name, password_hash=account_hash)
                           for name in ("alice", "bob", "offline"))
        db.session.commit()
        approve_fixture_contacts()
    yield application
    with application.app_context():
        db.session.remove()
        db.engine.dispose()


def csrf(client):
    response = client.get("/", base_url=BASE, follow_redirects=True)
    return re.search(r'<meta name="csrf-token" content="([^"]+)"', response.text)[1]


def login(app, username="alice"):
    client = app.test_client()
    response = client.post("/login", base_url=BASE,
                           headers={"Referer": BASE + "/login"},
                           data={"username": username, "password": PASSWORD,
                                 "csrf_token": csrf(client)})
    assert response.status_code == 302
    return client


def keys_request(client, payload, method="POST", token=True):
    headers = {"Referer": BASE + "/chat"}
    if token:
        headers["X-CSRFToken"] = csrf(client)
    return client.open("/api/keys", method=method, base_url=BASE,
                       json=payload, headers=headers)


@pytest.fixture
def envelope():
    return {"v": 1, "kind": "text", "sender": "alice", "recipient": "bob",
            "ts": 1794852000000, "eph": B64(b"\x04" + bytes(64)),
            "iv": B64(bytes(12)), "ct": B64(bytes(32)), "sig": B64(bytes(64))}


@pytest.fixture
def sockets(app):
    alice_http, bob_http = login(app), login(app, "bob")
    alice = socketio.test_client(app, flask_test_client=alice_http)
    bob = socketio.test_client(app, flask_test_client=bob_http)
    yield alice_http, bob_http, alice, bob
    for client in (alice, bob):
        if client.is_connected():
            client.disconnect()


def test_relay_only_to_recipient_and_unchanged(sockets, envelope):
    _, _, alice, bob = sockets
    result = alice.emit("send_message", envelope, callback=True)
    assert result["ok"] is True and isinstance(result["id"], int)
    messages = bob.get_received()
    assert len(messages) == 1
    assert messages[0]["name"] == "message"
    assert messages[0]["args"] == {"id": result["id"], **envelope}
    assert alice.get_received() == []


@pytest.mark.parametrize("changes", [
    {"v": True}, {"v": 1.0}, {"v": "1"}, {"kind": "stego"},
    {"sender": "bob"}, {"recipient": "unknown"},
    {"recipient": "bob/../alice"}, {"ts": True}, {"ts": 1.5},
    {"ts": 2**53}, {"ts": 0}, {"eph": B64(bytes(65))},
    {"eph": B64(bytes(64))}, {"iv": "!!!!"}, {"iv": B64(bytes(11))},
    {"sig": B64(b"x")}, {"sig": B64(bytes(50000))},
    {"ct": B64(b"x")}, {"ct": B64(bytes(16384))},
    {"text": "plaintext must not be relayed"}, {"recipient_id": 2},
])
def test_reject_malformed_or_unavailable_envelopes(sockets, envelope, changes):
    _, _, alice, bob = sockets
    result = alice.emit("send_message", {**envelope, **changes}, callback=True)
    assert result["ok"] is False
    assert bob.get_received() == []


def test_exact_envelope_size_boundary(app, sockets, envelope):
    _, _, alice, bob = sockets
    size = len(json.dumps(envelope, separators=(",", ":")).encode("utf-8"))
    app.config["MAX_TEXT_BYTES"] = size - 1
    assert alice.emit("send_message", envelope, callback=True)["ok"] is False
    app.config["MAX_TEXT_BYTES"] = size
    assert alice.emit("send_message", envelope, callback=True)["ok"] is True
    assert len(bob.get_received()) == 1


def test_missing_field_and_wrong_payload(sockets, envelope):
    _, _, alice, bob = sockets
    del envelope["sig"]
    for payload in (envelope, [], None, "plaintext"):
        assert alice.emit("send_message", payload, callback=True)["ok"] is False
    assert bob.get_received() == []


def test_unauthenticated_socket_and_foreign_origin(app):
    client = app.test_client()
    assert not socketio.test_client(app, flask_test_client=client).is_connected()
    response = client.get("/socket.io/?EIO=4&transport=polling", base_url=BASE,
                          headers={"Origin": "https://untrusted.example"})
    assert response.status_code == 400


def test_logout_disconnects_sockets(sockets):
    alice_http, _, alice, bob = sockets
    assert alice_http.get("/logout", base_url=BASE).status_code == 405
    assert alice_http.post("/logout", base_url=BASE).status_code == 400
    assert alice.is_connected()
    response = alice_http.post("/logout", base_url=BASE,
                              headers={"Referer": BASE + "/chat"},
                              data={"csrf_token": csrf(alice_http)})
    assert response.status_code == 302
    assert not alice.is_connected()
    assert bob.is_connected()
    assert alice_http.get("/api/me", base_url=BASE).status_code == 401


def test_api_auth_and_csrf_errors_are_json(app):
    response = app.test_client().get("/api/me", base_url=BASE)
    assert response.status_code == 401 and response.json["error"]
    client = login(app)
    response = keys_request(client, {}, token=False)
    assert response.status_code == 400 and response.json["error"]
    assert client.get("/api/missing", base_url=BASE).status_code == 404
    assert client.get("/api/missing", base_url=BASE).is_json


@pytest.fixture
def public_keys():
    # Structurally valid public P-256 generator coordinates; no private value.
    jwk = {"kty": "EC", "crv": "P-256",
           "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
           "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}
    return {"ecdh_jwk": jwk.copy(), "ecdsa_jwk": jwk.copy()}


@pytest.mark.parametrize("mutation", [
    {"d": "private-value"}, {"ext": True}, {"crv": "P-384"},
    {"x": "!" * 4 + "A" * 43}, {"x": "+" + "A" * 42},
    {"x": "A" * 43 + "=!!!!"}, {"x": "A" * 42 + "B"}, {"x": "abc"},
])
def test_reject_private_or_malformed_public_keys(app, public_keys, mutation):
    public_keys["ecdh_jwk"].update(mutation)
    assert keys_request(login(app), public_keys).status_code == 400


def test_public_key_lifecycle(app, public_keys):
    client = login(app)
    assert keys_request(client, public_keys).status_code == 201
    assert keys_request(client, public_keys).status_code == 409
    assert keys_request(client, public_keys, "PUT").status_code == 200
    assert client.get("/api/me", base_url=BASE).json == {"username": "alice", "has_keys": True}
    result = client.get("/api/users/alice/keys", base_url=BASE).json
    assert result == {"username": "alice", **public_keys}
    assert client.get("/api/users/bob/keys", base_url=BASE).status_code == 404
    with app.app_context():
        user = User.query.filter_by(username="alice").one()
        assert set(json.loads(user.ecdh_public_jwk)) == {"kty", "crv", "x", "y"}


def test_account_regressions_and_cookie_flags(app):
    client = app.test_client()
    assert client.get("/chat", base_url=BASE).status_code == 302
    errors = []
    for username in ("alice", "unknown"):
        response = client.post("/login", base_url=BASE,
                               headers={"Referer": BASE + "/login"},
                               data={"username": username, "password": "wrong", "csrf_token": csrf(client)})
        errors.append("Invalid username or password." in response.text)
    assert all(errors)
    for username, password, expected in (("ALICE", PASSWORD, "already taken"),
                                         ("newuser", "12345", "at least 12")):
        response = client.post("/register", base_url=BASE,
                               headers={"Referer": BASE + "/register"},
                               data={"username": username, "password": password,
                                     "confirm": password, "csrf_token": csrf(client)})
        assert expected in response.text
    client = login(app)
    response = client.get("/chat", base_url=BASE)
    assert response.status_code == 200
    cookies = response.headers.getlist("Set-Cookie")
    assert any(h.startswith("session=") and all(flag in h for flag in
               ("Secure", "HttpOnly", "SameSite=Lax")) for h in cookies)
