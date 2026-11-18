"""Raw PNG relay/persistence validation, queue ownership and stego limits."""
import base64
import pytest

from test_step6 import account_hash, app, envelope, login, sockets
from test_step8 import hardened
from extensions import db, socketio
from models import PendingMessage

PNG = bytes((137,80,78,71,13,10,26,10))


@pytest.fixture
def stego(envelope):
    return {k: v for k, v in {**envelope, "kind": "stego", "img": base64.b64encode(PNG + bytes(56)).decode()}.items() if k not in ("iv", "ct")}


def test_offline_stego_preserved_exactly_and_owned_ack(app, stego):
    alice = socketio.test_client(app, flask_test_client=login(app))
    result = alice.emit("send_message", stego, callback=True)
    assert result["ok"]
    with app.app_context():
        row = db.session.get(PendingMessage, result["id"])
        assert row.iv is None and row.kind == "stego" and row.ciphertext == stego["img"]
        assert row.envelope() == {"id": result["id"], **stego}
    assert alice.emit("ack_message", {"id": result["id"]}, callback=True) == {"ok": False}
    bob = socketio.test_client(app, flask_test_client=login(app, "bob"))
    assert bob.get_received()[0]["args"] == {"id": result["id"], **stego}
    assert bob.emit("ack_message", {"id": result["id"]}, callback=True) == {"ok": True}
    with app.app_context():
        assert PendingMessage.query.count() == 0
    alice.disconnect(); bob.disconnect()


def test_exact_decoded_png_limit_and_no_pixel_processing(app, sockets, stego):
    _, _, alice, bob = sockets
    app.config["MAX_STEGO_BYTES"] = 64
    assert alice.emit("send_message", stego, callback=True)["ok"]
    assert bob.get_received()[0]["args"]["img"] == stego["img"]
    # Not a decodable PNG: magic/size validation is deliberately the only image
    # inspection on the server. Browser signature and PNG checks remain required.
    oversize = {**stego, "img": base64.b64encode(PNG + bytes(57)).decode()}
    assert alice.emit("send_message", oversize, callback=True) == {"ok": False, "error": "image too large"}
    assert bob.get_received() == []
    assert socketio.server.eio.max_http_buffer_size >= 5_000_000


@pytest.mark.parametrize("change", [
    {"img": "!!!!"}, {"img": 42}, {"img": base64.b64encode(b"JPEG NOT PNG").decode()},
    {"eph": "abcd"}, {"sig": "abcd"}, {"iv": "extra"}, {"ct": "extra"},
    {"sender": "bob"}, {"ts": True}, {"recipient": "unknown"},
])
def test_invalid_stego_not_stored_or_relayed(app, sockets, stego, change):
    _, _, alice, bob = sockets
    assert not alice.emit("send_message", {**stego, **change}, callback=True)["ok"]
    assert bob.get_received() == []
    with app.app_context():
        assert PendingMessage.query.count() == 0


def test_queue_cap_shared_between_text_and_stego(app, sockets, envelope, stego):
    _, _, alice, _ = sockets
    app.config["MAX_PENDING_PER_PAIR"] = 2
    assert alice.emit("send_message", envelope, callback=True)["ok"]
    assert alice.emit("send_message", stego, callback=True)["ok"]
    assert alice.emit("send_message", stego, callback=True)["error"] == "queue_full"


def test_rejected_stego_audit_has_reason_only(app, sockets, stego):
    _, _, alice, _ = sockets
    assert not alice.emit("send_message", {**stego, "recipient": "unknown"}, callback=True)["ok"]
    with open(app.config["AUDIT_LOG_PATH"], encoding="utf-8") as log:
        text = log.read()
    assert "event=message_rejected reason=recipient not found" in text
    assert all(stego[field] not in text for field in ("img", "eph", "sig"))


def test_five_stego_per_minute_across_reconnects_with_text_still_available(hardened, stego, envelope, monkeypatch):
    client = login(hardened)
    alice = socketio.test_client(hardened, flask_test_client=client)
    now = [100.0]
    monkeypatch.setattr("events.monotonic", lambda: now[0])
    for _ in range(5):
        assert alice.emit("send_message", stego, callback=True)["ok"]
    assert alice.emit("send_message", stego, callback=True)["error"] == "rate_limited"
    assert alice.emit("send_message", envelope, callback=True)["ok"]
    alice.disconnect()
    alice = socketio.test_client(hardened, flask_test_client=client)
    assert alice.emit("send_message", stego, callback=True)["error"] == "rate_limited"
    now[0] += 60
    assert alice.emit("send_message", stego, callback=True)["ok"]
    alice.disconnect()
