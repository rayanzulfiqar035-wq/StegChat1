"""Step 11 coverage gaps; existing Step 6-10 tests cover the other defenses."""
import re

import pytest
from sqlalchemy import inspect

from auth import _ph
from extensions import db
from models import User
from test_step6 import BASE, PASSWORD, account_hash, app, csrf, login


def test_registration_stores_only_verifiable_argon2id(app):
    client = app.test_client()
    response = client.post(
        "/register", base_url=BASE, headers={"Referer": BASE + "/register"},
        data={"username": "New_User", "password": PASSWORD, "confirm": PASSWORD,
              "csrf_token": csrf(client)})
    assert response.status_code == 302 and response.location.endswith("/login")
    with app.app_context():
        user = User.query.filter_by(username="new_user").one()
        assert user.password_hash.startswith("$argon2id$")
        assert user.password_hash != PASSWORD
        assert _ph.verify(user.password_hash, PASSWORD)
        assert user.ecdh_public_jwk is None and user.ecdsa_public_jwk is None
    assert login(app, "new_user").get("/chat", base_url=BASE).status_code == 200


@pytest.mark.parametrize("path,method", [
    ("/api/me", "GET"), ("/api/users/alice/keys", "GET"),
    ("/api/keys", "POST"), ("/api/keys", "PUT"),
])
def test_all_api_operations_require_login_even_with_valid_csrf(app, path, method):
    client = app.test_client()
    response = client.open(path, method=method, base_url=BASE, json={},
                           headers={"Referer": BASE + "/", "X-CSRFToken": csrf(client)})
    assert response.status_code == 401 and response.is_json
    with app.app_context():
        assert all(user.ecdh_public_jwk is None for user in User.query.all())


def test_unknown_key_lookup_returns_404(app):
    response = login(app).get("/api/users/does_not_exist/keys", base_url=BASE)
    assert response.status_code == 404 and response.is_json


@pytest.mark.parametrize("path", ["/register", "/login", "/logout"])
def test_html_post_forms_require_csrf(app, path):
    client = login(app) if path == "/logout" else app.test_client()
    response = client.post(path, base_url=BASE, headers={"Referer": BASE + path},
                           data={"username": "uncreated", "password": PASSWORD,
                                 "confirm": PASSWORD})
    assert response.status_code == 400
    if path == "/logout":
        assert client.get("/api/me", base_url=BASE).status_code == 200
    with app.app_context():
        assert User.query.filter_by(username="uncreated").first() is None


def test_every_database_table_excludes_plaintext_and_private_key_columns(app):
    # SECURITY: inspect the actual temporary DB, including tables outside ORM metadata.
    forbidden = ("plaintext", "cleartext", "messagetext", "messagebody",
                 "privatekey", "privatejwk", "secretkey")
    with app.app_context():
        schema = inspect(db.engine)
        tables = schema.get_table_names()
        assert {"users", "pending_messages", "login_attempts"} <= set(tables)
        for table in tables:
            for column in schema.get_columns(table):
                normalized = re.sub(r"[^a-z0-9]", "", column["name"].lower())
                assert not any(name in normalized for name in forbidden), (
                    f"Forbidden sensitive column: {table}.{column['name']}")
