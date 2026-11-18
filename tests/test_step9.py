"""The lab must be opt-in and authenticated, retaining Step 8 headers."""
import pytest
from app import create_app
from config import Config
from extensions import db
from models import User
from test_step6 import account_hash, BASE, login


@pytest.mark.parametrize("enabled", [False, True])
def test_lab_flag_login_and_csp(enabled, account_hash, tmp_path):
    class Settings(Config):
        TESTING = True
        STEGO_LAB = enabled
        RATELIMIT_ENABLED = False
        AUDIT_LOG_PATH = str(tmp_path / "audit.log")
        SECRET_KEY = "test-only-secret-" * 4
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    app = create_app(Settings)
    anonymous = app.test_client().get("/stego-lab", base_url=BASE)
    assert anonymous.status_code == (302 if enabled else 404)
    with app.app_context():
        db.session.add(User(username="alice", password_hash=account_hash)); db.session.commit()
    client = login(app)
    response = client.get("/stego-lab", base_url=BASE)
    assert response.status_code == (200 if enabled else 404)
    if enabled:
        assert "Steganography lab" in response.text
        assert "stego_lab.js" in response.text
        assert "'unsafe-inline'" not in response.headers["Content-Security-Policy"]
        assert "socket.io.min.js" not in response.text
        assert 'type="module"' in response.text
    with app.app_context():
        db.session.remove(); db.engine.dispose()
    for handler in app.extensions["audit_logger"].handlers:
        handler.close()
