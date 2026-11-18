"""Step 8 acceptance and adversarial security regressions, limits enabled."""
from datetime import datetime, timedelta, timezone
import secrets

import pytest
from flask import abort

from app import create_app
from auth import _ph
from config import Config
from extensions import db, socketio
from models import LoginAttempt, PendingMessage, User
from test_step6 import BASE, PASSWORD, csrf, envelope, public_keys


@pytest.fixture
def hardened(tmp_path):
    class Settings(Config):
        TESTING = True
        SECRET_KEY = secrets.token_hex(32)
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
        AUDIT_LOG_PATH = str(tmp_path / "audit.log")
    app = create_app(Settings)
    with app.app_context():
        hashed = _ph.hash(PASSWORD)
        db.session.add_all(User(username=n, password_hash=hashed) for n in ("alice", "bob"))
        db.session.commit()
    @app.get("/forced-error")
    @app.get("/api/forced-error")
    def fail():
        raise RuntimeError("SECRET_EXCEPTION_SENTINEL")
    @app.get("/error/<int:code>")
    def error(code):
        abort(code, description="SECRET_EXCEPTION_SENTINEL")
    yield app
    with app.app_context():
        db.session.remove(); db.engine.dispose()
    for handler in app.extensions["audit_logger"].handlers:
        handler.close()


def attempt(client, password=PASSWORD, username="alice", ip="127.0.0.1", path="/login"):
    token = csrf(client)
    return client.post(path, base_url=BASE, headers={"Referer": BASE + path},
                       environ_overrides={"REMOTE_ADDR": ip},
                       data={"username": username, "password": password,
                             "confirm": password, "csrf_token": token})


def signed_in(app, username="alice"):
    client = app.test_client()
    assert attempt(client, username=username).status_code == 302
    return client


def key_request(client, method, payload, token=True):
    headers = {"Referer": BASE + "/chat"}
    if token:
        headers["X-CSRFToken"] = csrf(client)
    return client.open("/api/keys", method=method, base_url=BASE, json=payload, headers=headers)


def test_headers_https_and_cookies(hardened):
    client = signed_in(hardened)
    response = client.get("/chat", base_url=BASE)
    policy = response.headers["Content-Security-Policy"]
    for directive in ("default-src 'self'", "script-src 'self'", "style-src 'self'",
                      "img-src 'self' blob: data:", "frame-ancestors 'none'",
                      "base-uri 'self'", "form-action 'self'",
                      "connect-src 'self' wss://localhost:5000 wss://127.0.0.1:5000"):
        assert directive in policy
    assert "unsafe-" not in policy and "*" not in policy
    assert response.headers["Strict-Transport-Security"] == "max-age=3600"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "strict-origin"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert client.get("/", base_url="http://localhost:5000").status_code in (301, 302)
    session = next(c for c in response.headers.getlist("Set-Cookie") if c.startswith("session="))
    assert all(flag in session for flag in ("Secure", "HttpOnly", "SameSite=Lax"))


def test_sixth_login_limited_even_with_changed_username(hardened):
    client = hardened.test_client()
    for index in range(5):
        assert attempt(client, "wrong", username=f"unknown{index}").status_code == 200
    assert attempt(client, "wrong", username="different").status_code == 429
    # GETs neither consume nor inherit the credential-submission limit.
    assert client.get("/login", base_url=BASE).status_code == 200


def test_lockout_full_fifteen_minutes_and_no_extension(hardened, monkeypatch):
    client = hardened.test_client()
    start = datetime(2026, 11, 19, 10, tzinfo=timezone.utc)
    current = [start]
    monkeypatch.setattr("auth._utc_now", lambda: current[0])
    for index in range(5):
        current[0] = start + timedelta(minutes=index * 3)
        assert "Invalid username or password." in attempt(client, "wrong", ip=f"127.0.0.{index+1}").text
    current[0] = start + timedelta(minutes=20)  # oldest failure outside rolling window
    assert "Invalid username or password." in attempt(client, ip="127.0.0.6").text
    with hardened.app_context():
        assert LoginAttempt.query.count() == 5
    assert "event=lockout" in open(hardened.config["AUDIT_LOG_PATH"], encoding="utf-8").read()
    current[0] = start + timedelta(minutes=27, seconds=1)
    assert attempt(client, ip="127.0.0.7").status_code == 302


def test_register_limit(hardened):
    client = hardened.test_client()
    for _ in range(10):
        assert attempt(client, "short", username="newuser", path="/register").status_code == 200
    assert attempt(client, "short", username="other", path="/register").status_code == 429


def test_directory_limit_shared_across_usernames(hardened):
    client = signed_in(hardened)
    for index in range(30):
        assert client.get(f"/api/users/missing{index}/keys", base_url=BASE).status_code == 404
    response = client.get("/api/users/bob/keys", base_url=BASE)
    assert response.status_code == 429 and response.json == {"error": "Too many requests"}


def test_key_upload_and_reset_share_limit(hardened, public_keys):
    client = signed_in(hardened)
    for index in range(10):
        assert key_request(client, "POST" if index == 0 else "PUT", public_keys).status_code in (200, 201)
    assert key_request(client, "PUT", public_keys).status_code == 429


@pytest.mark.parametrize("method", ["POST", "PUT"])
def test_fetch_csrf_enforced(hardened, public_keys, method):
    assert key_request(signed_in(hardened), method, public_keys, token=False).status_code == 400


def test_socket_31st_counted_across_tabs_and_reconnects(hardened, envelope, monkeypatch):
    client = signed_in(hardened)
    first = socketio.test_client(hardened, flask_test_client=client)
    second = socketio.test_client(hardened, flask_test_client=client)
    now = [100.0]
    monkeypatch.setattr("events.monotonic", lambda: now[0])
    for index in range(30):
        assert (first if index % 2 else second).emit("send_message", envelope, callback=True)["ok"]
    assert first.emit("send_message", envelope, callback=True) == {"ok": False, "error": "rate_limited"}
    first.disconnect()
    first = socketio.test_client(hardened, flask_test_client=client)
    assert first.emit("send_message", envelope, callback=True)["error"] == "rate_limited"
    now[0] += 60
    assert first.emit("send_message", envelope, callback=True)["ok"]
    first.disconnect(); second.disconnect()


def test_audit_events_without_secret_or_content(hardened, public_keys, envelope):
    client = hardened.test_client()
    assert attempt(client, username="newuser", path="/register").status_code == 302
    assert attempt(client, "wrong-test-password").status_code == 200
    assert attempt(client).status_code == 302
    assert key_request(client, "POST", public_keys).status_code == 201
    assert key_request(client, "PUT", public_keys).status_code == 200
    socket = socketio.test_client(hardened, flask_test_client=client)
    assert not socket.emit("send_message", {**envelope, "text": "SECRET_MESSAGE_TEXT"}, callback=True)["ok"]
    for _ in range(30):
        socket.emit("send_message", envelope, callback=True)
    response = client.post("/logout", base_url=BASE, headers={"Referer": BASE + "/chat"}, data={"csrf_token": csrf(client)})
    assert response.status_code == 302
    text = open(hardened.config["AUDIT_LOG_PATH"], encoding="utf-8").read()
    for event in ("registration", "login_failure", "login_success", "keys_uploaded", "keys_reset", "logout", "rate_limit", "message_rejected"):
        assert f"event={event}" in text
    for secret in (PASSWORD, "wrong-test-password", "SECRET_MESSAGE_TEXT", envelope["ct"], public_keys["ecdh_jwk"]["x"], "$argon2id$"):
        assert secret not in text
    rejected = next(line for line in text.splitlines() if "event=message_rejected" in line)
    assert "username=" not in rejected and "ip=" not in rejected


@pytest.mark.parametrize("code", [400, 403, 404, 429, 500])
def test_errors_are_generic(hardened, code):
    response = hardened.test_client().get(f"/error/{code}", base_url=BASE)
    assert response.status_code == code
    assert "SECRET_EXCEPTION_SENTINEL" not in response.text
    assert "Traceback" not in response.text


def test_exception_generic_in_html_json_and_logs(hardened):
    for path in ("/forced-error", "/api/forced-error"):
        response = hardened.test_client().get(path, base_url=BASE)
        assert response.status_code == 500 and "SECRET_EXCEPTION_SENTINEL" not in response.text
    assert response.json == {"error": "Internal server error"}
    text = open(hardened.config["AUDIT_LOG_PATH"], encoding="utf-8").read()
    assert "event=server_error" in text and "SECRET_EXCEPTION_SENTINEL" not in text


def test_socket_exception_does_not_log_event_payload(hardened, envelope, monkeypatch, capsys):
    socket = socketio.test_client(hardened, flask_test_client=signed_in(hardened))
    def fail(*args):
        raise RuntimeError("SECRET_SOCKET_EXCEPTION")
    monkeypatch.setattr("events._validate_envelope", fail)
    assert socket.emit("send_message", envelope, callback=True) == {"ok": False, "error": "server error"}
    socket.disconnect()
    text = open(hardened.config["AUDIT_LOG_PATH"], encoding="utf-8").read()
    captured = capsys.readouterr()
    assert "SECRET_SOCKET_EXCEPTION" not in text + captured.out + captured.err
    assert envelope["ct"] not in text + captured.out + captured.err
